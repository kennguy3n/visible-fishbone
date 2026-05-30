//! Bounded in-memory spool with oldest-dropped-first eviction.
//!
//! The egress path holds a `BoundedSpool<T>` per direction
//! (telemetry, audit, …). When the network is healthy the spool
//! is empty most of the time — events drop in and are flushed
//! out within milliseconds. When the network drops, the spool
//! fills up to its bound and then evicts the oldest item every
//! time a new one is pushed.
//!
//! Rationale for oldest-dropped-first (vs newest-dropped-on-push):
//!
//! * The most recent observation is the one operators care about
//!   in a post-incident review — "what is the agent seeing
//!   *now*". Throwing it away because the queue is full hides
//!   the most-relevant signal.
//! * Older events are still in the local PCAP ring (sng-telemetry
//!   layers that on top) for forensic re-hydration if needed.
//!
//! Disk-backed spool with WAL-style guarantees lives in
//! `sng-telemetry` (PR 5). The in-memory bound here is a hard
//! upper limit on resident memory regardless of how aggressive
//! the producer is.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Cumulative spool statistics. All counters are monotonic and
/// safe to read from any thread. Cloning the snapshot is cheap
/// (it's just `u64`s).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SpoolStats {
    /// Items currently in the spool (snapshot, not monotonic).
    pub len: u64,
    /// Total items pushed into the spool since construction.
    pub pushed: u64,
    /// Items evicted to make room for a new push (oldest-drop).
    pub evicted: u64,
    /// Items dequeued by the drain path.
    pub drained: u64,
}

/// Bounded FIFO spool. The producer side calls [`push`] and gets
/// back whether an oldest item had to be evicted; the consumer
/// side calls [`drain`] or [`pop_front`] to flush bytes onto the
/// wire.
///
/// The spool is `Send + Sync` via the inner `parking_lot::Mutex`,
/// so a single instance can be shared between a producer task
/// (the local subsystems pushing events) and a consumer task
/// (the egress flusher).
#[derive(Debug)]
pub struct BoundedSpool<T> {
    inner: parking_lot::Mutex<VecDeque<T>>,
    capacity: usize,
    pushed: AtomicU64,
    evicted: AtomicU64,
    drained: AtomicU64,
}

/// Return value from [`BoundedSpool::push`].
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Item was accepted without evicting.
    Accepted,
    /// Item was accepted and the oldest entry was evicted to
    /// make room.
    AcceptedWithEviction,
}

impl<T> BoundedSpool<T> {
    /// Construct a spool with the given bound. `capacity` of
    /// zero is permitted and means "every push evicts itself
    /// immediately" — equivalent to dropping every event but
    /// useful for `--telemetry=off` test deployments.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: parking_lot::Mutex::new(VecDeque::with_capacity(capacity.max(1))),
            capacity,
            pushed: AtomicU64::new(0),
            evicted: AtomicU64::new(0),
            drained: AtomicU64::new(0),
        }
    }

    /// Push an item. If the spool is at capacity, the oldest
    /// item is evicted and the new item is appended. Returns the
    /// outcome so the caller can pin a metric counter.
    pub fn push(&self, item: T) -> PushOutcome {
        self.pushed.fetch_add(1, Ordering::Relaxed);
        if self.capacity == 0 {
            // Capacity zero is a no-op spool — counted as an
            // eviction so dashboards still surface the drop.
            self.evicted.fetch_add(1, Ordering::Relaxed);
            return PushOutcome::AcceptedWithEviction;
        }
        let mut guard = self.inner.lock();
        let mut evicted = false;
        while guard.len() >= self.capacity {
            // `pop_front` is O(1) on `VecDeque`.
            let _ = guard.pop_front();
            evicted = true;
        }
        guard.push_back(item);
        if evicted {
            self.evicted.fetch_add(1, Ordering::Relaxed);
            PushOutcome::AcceptedWithEviction
        } else {
            PushOutcome::Accepted
        }
    }

    /// Pop the oldest item, if any.
    pub fn pop_front(&self) -> Option<T> {
        let mut guard = self.inner.lock();
        let popped = guard.pop_front();
        if popped.is_some() {
            self.drained.fetch_add(1, Ordering::Relaxed);
        }
        popped
    }

    /// Push an item back onto the *front* of the spool, preserving
    /// FIFO ordering for re-spooled batches (e.g. after a transient
    /// flush failure). If the spool is at capacity, the **newest**
    /// item at the back is evicted to make room — the opposite of
    /// [`push`], because the caller is asserting that the item they
    /// are re-spooling is the oldest live batch and must keep its
    /// position. If capacity is zero the item is dropped (and an
    /// eviction is counted) for symmetry with [`push`].
    pub fn push_front(&self, item: T) -> PushOutcome {
        self.pushed.fetch_add(1, Ordering::Relaxed);
        if self.capacity == 0 {
            self.evicted.fetch_add(1, Ordering::Relaxed);
            return PushOutcome::AcceptedWithEviction;
        }
        let mut guard = self.inner.lock();
        let mut evicted = false;
        while guard.len() >= self.capacity {
            // The re-spooled item is the *oldest*, so to make
            // room we evict from the back (the newest items).
            let _ = guard.pop_back();
            evicted = true;
        }
        guard.push_front(item);
        if evicted {
            self.evicted.fetch_add(1, Ordering::Relaxed);
            PushOutcome::AcceptedWithEviction
        } else {
            PushOutcome::Accepted
        }
    }

    /// Drain up to `max` items into a fresh `Vec`. The caller
    /// can pass `usize::MAX` to drain everything; a bounded
    /// drain is the canonical "flush one batch" call. Returns
    /// the items in oldest-to-newest order.
    pub fn drain(&self, max: usize) -> Vec<T> {
        let mut guard = self.inner.lock();
        let take = guard.len().min(max);
        let drained: Vec<T> = guard.drain(..take).collect();
        if !drained.is_empty() {
            self.drained
                .fetch_add(drained.len() as u64, Ordering::Relaxed);
        }
        drained
    }

    /// Current length (snapshot, not monotonic).
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Whether the spool currently holds no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Configured capacity (returned for observability).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Snapshot of cumulative spool stats. Returned by value so
    /// the caller can compare against an earlier snapshot
    /// without holding any locks.
    #[must_use]
    pub fn stats(&self) -> SpoolStats {
        SpoolStats {
            len: self.len() as u64,
            pushed: self.pushed.load(Ordering::Relaxed),
            evicted: self.evicted.load(Ordering::Relaxed),
            drained: self.drained.load(Ordering::Relaxed),
        }
    }

    /// Wrap the spool in an `Arc` so producer + consumer tasks
    /// can share it.
    #[must_use]
    pub fn shared(self) -> Arc<Self> {
        Arc::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_until_full_then_evicts_oldest() {
        let spool: BoundedSpool<u32> = BoundedSpool::new(3);
        assert_eq!(spool.push(1), PushOutcome::Accepted);
        assert_eq!(spool.push(2), PushOutcome::Accepted);
        assert_eq!(spool.push(3), PushOutcome::Accepted);
        assert_eq!(spool.push(4), PushOutcome::AcceptedWithEviction);
        // After the eviction the spool holds [2, 3, 4].
        let drained = spool.drain(usize::MAX);
        assert_eq!(drained, vec![2, 3, 4]);
    }

    #[test]
    fn drain_returns_oldest_first() {
        let spool: BoundedSpool<&'static str> = BoundedSpool::new(4);
        spool.push("a");
        spool.push("b");
        spool.push("c");
        let drained = spool.drain(2);
        assert_eq!(drained, vec!["a", "b"]);
        assert_eq!(spool.len(), 1);
        assert_eq!(spool.pop_front(), Some("c"));
        assert_eq!(spool.pop_front(), None);
    }

    #[test]
    fn stats_track_lifecycle() {
        let spool: BoundedSpool<u32> = BoundedSpool::new(2);
        spool.push(1);
        spool.push(2);
        spool.push(3); // evicts 1
        let drained = spool.drain(usize::MAX);
        assert_eq!(drained, vec![2, 3]);
        let stats = spool.stats();
        assert_eq!(stats.pushed, 3);
        assert_eq!(stats.evicted, 1);
        assert_eq!(stats.drained, 2);
        assert_eq!(stats.len, 0);
    }

    #[test]
    fn push_front_preserves_fifo_on_respool() {
        let spool: BoundedSpool<u32> = BoundedSpool::new(4);
        spool.push(2);
        spool.push(3);
        // Caller pops 1 off, fails to flush it, and re-spools.
        spool.push_front(1);
        let drained = spool.drain(usize::MAX);
        assert_eq!(drained, vec![1, 2, 3]);
    }

    #[test]
    fn push_front_at_capacity_evicts_newest() {
        let spool: BoundedSpool<u32> = BoundedSpool::new(2);
        spool.push(2);
        spool.push(3);
        // At capacity. `push_front(1)` must evict the newest
        // (3 at the back), not the oldest, so the re-spooled
        // batch retains its leading position.
        let outcome = spool.push_front(1);
        assert_eq!(outcome, PushOutcome::AcceptedWithEviction);
        let drained = spool.drain(usize::MAX);
        assert_eq!(drained, vec![1, 2]);
    }

    #[test]
    fn zero_capacity_drops_immediately() {
        let spool: BoundedSpool<u32> = BoundedSpool::new(0);
        assert_eq!(spool.push(1), PushOutcome::AcceptedWithEviction);
        assert!(spool.is_empty());
        assert_eq!(spool.stats().evicted, 1);
    }
}

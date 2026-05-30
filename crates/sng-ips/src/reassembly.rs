//! TCP segment reassembly buffer.
//!
//! Signatures are written against application-layer payloads
//! that may span multiple TCP segments — a SQLi rule that
//! looks for `' OR '1'='1` will miss its target if the
//! attacker splits the string across two packets. The IPS
//! engine therefore maintains a per-flow reassembly buffer
//! that joins consecutive in-order segments, runs the
//! signature scan on the joined payload, and slides the
//! window forward as the scan consumes bytes.
//!
//! ### Scope
//!
//! This buffer is **stream-relative**, not octet-perfect.
//! The IPS does not need to reconstruct the byte-for-byte
//! TCP stream the way Suricata does (which would require
//! tracking sequence numbers, retransmits, out-of-order
//! gaps, and PAWS). Instead it operates on the in-order
//! payload stream as observed by the producer (the
//! firewall's `observe_packet` path already discards
//! retransmits at conntrack time; the IPS sees what
//! lookup_or_create returns). This trades perfect fidelity
//! for hot-path simplicity — the worst case is a missed
//! match on a flow where the attacker triggered the
//! detection logic precisely on a retransmit boundary, an
//! edge case Suricata itself struggles with.
//!
//! ### Sliding window
//!
//! The buffer keeps the last
//! [`ReassemblyConfig::window_bytes`] of in-order payload
//! per direction. Each `append` truncates the older bytes
//! so the buffer stays bounded; the operator tunes the
//! window via [`ReassemblyConfig`].
//!
//! ### Directionality
//!
//! TCP is bidirectional — the IPS scans request and
//! response payloads independently because exploit
//! payloads look different in each direction (request
//! carries the attack, response carries leaked data).
//! [`ReassemblyBuffer`] tracks both via
//! [`Direction::Originator`] / [`Direction::Responder`]
//! and exposes the assembled payload per direction.

use lru::LruCache;
use parking_lot::Mutex;
use std::num::NonZeroUsize;
use std::sync::Arc;

/// Direction of a payload within a flow.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Originator → responder (the side that sent the SYN).
    Originator,
    /// Responder → originator (the side that sent the
    /// SYN+ACK).
    Responder,
}

/// Configuration for a single flow's reassembly buffer.
#[derive(Clone, Copy, Debug)]
pub struct ReassemblyConfig {
    /// Sliding-window length per direction. Bigger windows
    /// catch attacks that span more segments at the cost of
    /// memory per flow. Default = 64 KiB which holds the
    /// typical HTTP request + headers + first chunk of
    /// body. Operators with TLS-resumption sniffing tune
    /// down (TLS record framing limits useful window to ~16
    /// KiB after the ClientHello).
    pub window_bytes: usize,
}

impl Default for ReassemblyConfig {
    fn default() -> Self {
        Self {
            window_bytes: 64 * 1024,
        }
    }
}

/// Per-flow reassembly buffer holding the most recent
/// `window_bytes` of in-order payload per direction.
#[derive(Debug)]
pub struct ReassemblyBuffer {
    cfg: ReassemblyConfig,
    state: Mutex<BufferState>,
}

#[derive(Debug, Default)]
struct BufferState {
    originator: Vec<u8>,
    responder: Vec<u8>,
    bytes_dropped_to_window: u64,
}

impl ReassemblyBuffer {
    /// Construct a buffer with the given configuration.
    #[must_use]
    pub fn new(cfg: ReassemblyConfig) -> Self {
        Self {
            cfg,
            state: Mutex::new(BufferState::default()),
        }
    }

    /// Append `payload` to the in-order stream for
    /// `direction`. The buffer truncates the head of the
    /// per-direction byte vector if the resulting length
    /// would exceed `window_bytes` — older bytes are
    /// silently dropped and accounted toward
    /// [`ReassemblyBuffer::bytes_dropped_to_window`].
    ///
    /// Returns the number of bytes dropped by **this**
    /// call (the per-call delta, not the cumulative
    /// counter). The IPS service uses this to surface
    /// window pressure on a counter without round-tripping
    /// through [`Self::bytes_dropped_to_window`].
    pub fn append(&self, direction: Direction, payload: &[u8]) -> usize {
        if payload.is_empty() {
            return 0;
        }
        let mut s = self.state.lock();
        let buf = match direction {
            Direction::Originator => &mut s.originator,
            Direction::Responder => &mut s.responder,
        };
        // Truncate first if the incoming payload alone is
        // larger than the window — the buffer stores only
        // the trailing window-bytes of the payload.
        if payload.len() >= self.cfg.window_bytes {
            let keep_from = payload.len() - self.cfg.window_bytes;
            let dropped_from_buf = buf.len();
            let dropped_from_payload = keep_from;
            let dropped = dropped_from_buf.saturating_add(dropped_from_payload);
            s.bytes_dropped_to_window = s.bytes_dropped_to_window.saturating_add(dropped as u64);
            let buf = match direction {
                Direction::Originator => &mut s.originator,
                Direction::Responder => &mut s.responder,
            };
            buf.clear();
            buf.extend_from_slice(&payload[keep_from..]);
            return dropped;
        }
        buf.extend_from_slice(payload);
        if buf.len() > self.cfg.window_bytes {
            let drop = buf.len() - self.cfg.window_bytes;
            s.bytes_dropped_to_window = s.bytes_dropped_to_window.saturating_add(drop as u64);
            let buf = match direction {
                Direction::Originator => &mut s.originator,
                Direction::Responder => &mut s.responder,
            };
            buf.drain(..drop);
            return drop;
        }
        0
    }

    /// Call `f` with a borrow of the in-order payload for
    /// `direction`. The borrow is held under the buffer's
    /// internal lock so callers must not block / await
    /// inside the closure. Returns whatever `f` returns.
    pub fn with_payload<F, R>(&self, direction: Direction, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let s = self.state.lock();
        let bytes: &[u8] = match direction {
            Direction::Originator => &s.originator,
            Direction::Responder => &s.responder,
        };
        f(bytes)
    }

    /// Drop the in-order payload up to (but not including)
    /// the given offset. Used by the IPS service after a
    /// scan completes to slide the window past already-
    /// scanned bytes, leaving the unscanned tail intact for
    /// the next scan.
    pub fn consume(&self, direction: Direction, n: usize) {
        if n == 0 {
            return;
        }
        let mut s = self.state.lock();
        let buf = match direction {
            Direction::Originator => &mut s.originator,
            Direction::Responder => &mut s.responder,
        };
        let drop = n.min(buf.len());
        buf.drain(..drop);
    }

    /// Cumulative number of payload bytes the buffer
    /// dropped because they fell off the trailing edge of
    /// the sliding window. Returned by the IPS stats
    /// snapshot so operators can detect when windows are
    /// undersized.
    #[must_use]
    pub fn bytes_dropped_to_window(&self) -> u64 {
        self.state.lock().bytes_dropped_to_window
    }

    /// Bytes currently held for the given direction.
    #[must_use]
    pub fn len(&self, direction: Direction) -> usize {
        let s = self.state.lock();
        match direction {
            Direction::Originator => s.originator.len(),
            Direction::Responder => s.responder.len(),
        }
    }

    /// True if the buffer is empty in both directions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        let s = self.state.lock();
        s.originator.is_empty() && s.responder.is_empty()
    }

    /// Drop all buffered bytes in both directions. Used
    /// when the flow closes.
    pub fn clear(&self) {
        let mut s = self.state.lock();
        s.originator.clear();
        s.responder.clear();
    }

    /// Configuration this buffer was constructed with.
    #[must_use]
    pub fn config(&self) -> ReassemblyConfig {
        self.cfg
    }
}

/// Flow-keyed table of reassembly buffers. The IPS service
/// looks up a buffer per flow as packets arrive; the table
/// is bounded by [`ReassemblyTable::capacity`] and evicts
/// the **least-recently-touched** buffer when full.
///
/// Internally backed by an [`lru::LruCache`] so both insert
/// and eviction are O(1) — important under flow-creation
/// bursts (port scans, SYN floods, opportunistic crawlers)
/// where a linear-scan-for-min eviction would dominate
/// lock-hold time.
#[derive(Debug)]
pub struct ReassemblyTable {
    capacity: NonZeroUsize,
    cfg: ReassemblyConfig,
    /// `LruCache` is not internally synchronised; we keep
    /// it behind a `parking_lot::Mutex` and release the
    /// guard as soon as the per-flow buffer Arc is cloned
    /// out. The scan-and-append path runs entirely outside
    /// this lock.
    inner: Mutex<LruCache<u64, Arc<ReassemblyBuffer>>>,
}

impl ReassemblyTable {
    /// Construct a new table. Capacity is clamped to a
    /// minimum of 1 — a zero-capacity table is degenerate
    /// (it would evict the just-inserted entry on the next
    /// insert) and would crash `LruCache::new` outright.
    #[must_use]
    pub fn new(capacity: usize, cfg: ReassemblyConfig) -> Self {
        // `capacity.max(1)` is always `>= 1`, so the
        // NonZeroUsize construction is infallible. The
        // fallback is a const NonZeroUsize so the
        // unwrap-style call sites stay out of the
        // `expect_used` lint.
        const ONE: NonZeroUsize = NonZeroUsize::new(1).expect("compile-time: 1 is non-zero");
        let capacity = NonZeroUsize::new(capacity.max(1)).unwrap_or(ONE);
        Self {
            capacity,
            cfg,
            inner: Mutex::new(LruCache::new(capacity)),
        }
    }

    /// Get-or-create the per-flow buffer. The returned
    /// [`Arc<ReassemblyBuffer>`] outlives the table lock,
    /// so the caller can run scans against the buffer
    /// without blocking other flows.
    ///
    /// `LruCache::get_or_insert` bumps the flow to the
    /// most-recently-used position, so the next eviction
    /// picks a flow that has actually been idle.
    pub fn get_or_create(&self, flow_id: u64) -> Arc<ReassemblyBuffer> {
        let mut inner = self.inner.lock();
        let buf = inner.get_or_insert(flow_id, || Arc::new(ReassemblyBuffer::new(self.cfg)));
        Arc::clone(buf)
    }

    /// Run `f` against the buffer for the given flow,
    /// creating one if absent. Convenience wrapper over
    /// [`Self::get_or_create`].
    pub fn with_flow<F, R>(&self, flow_id: u64, f: F) -> R
    where
        F: FnOnce(&ReassemblyBuffer) -> R,
    {
        let buf = self.get_or_create(flow_id);
        f(&buf)
    }

    /// Drop the buffer for the given flow. Called when the
    /// flow closes (conntrack sweep / TCP FIN / RST).
    pub fn drop_flow(&self, flow_id: u64) {
        let mut inner = self.inner.lock();
        inner.pop(&flow_id);
    }

    /// Number of flows currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// True if no flows are currently held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Configured capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity.get()
    }

    /// Configuration each buffer is constructed with.
    #[must_use]
    pub fn config(&self) -> ReassemblyConfig {
        self.cfg
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn small_cfg() -> ReassemblyConfig {
        ReassemblyConfig { window_bytes: 16 }
    }

    #[test]
    fn append_concatenates_bytes_in_order() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"AAAA");
        b.append(Direction::Originator, b"BBBB");
        b.with_payload(Direction::Originator, |bytes| {
            assert_eq!(bytes, b"AAAABBBB");
        });
    }

    #[test]
    fn append_directionality_is_independent() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"REQ ");
        b.append(Direction::Responder, b"RSP ");
        b.with_payload(Direction::Originator, |bytes| assert_eq!(bytes, b"REQ "));
        b.with_payload(Direction::Responder, |bytes| assert_eq!(bytes, b"RSP "));
    }

    #[test]
    fn window_drops_oldest_bytes_when_exceeded() {
        let b = ReassemblyBuffer::new(ReassemblyConfig { window_bytes: 8 });
        b.append(Direction::Originator, b"AAAA");
        b.append(Direction::Originator, b"BBBB");
        b.append(Direction::Originator, b"CCCC");
        // 12 bytes appended; window = 8 → tail "BBBBCCCC".
        b.with_payload(Direction::Originator, |bytes| {
            assert_eq!(bytes, b"BBBBCCCC");
        });
        assert_eq!(b.bytes_dropped_to_window(), 4);
    }

    #[test]
    fn append_larger_than_window_keeps_only_tail() {
        let b = ReassemblyBuffer::new(ReassemblyConfig { window_bytes: 8 });
        b.append(Direction::Originator, b"abcdefghijklmnop");
        b.with_payload(Direction::Originator, |bytes| {
            assert_eq!(bytes, b"ijklmnop");
        });
        assert_eq!(b.bytes_dropped_to_window(), 8);
    }

    #[test]
    fn append_after_oversized_continues_appending() {
        let b = ReassemblyBuffer::new(ReassemblyConfig { window_bytes: 8 });
        b.append(Direction::Originator, b"abcdefghijklmnop");
        b.append(Direction::Originator, b"X");
        b.with_payload(Direction::Originator, |bytes| {
            assert_eq!(bytes, b"jklmnopX");
        });
    }

    #[test]
    fn consume_drops_head_bytes() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"AAAABBBB");
        b.consume(Direction::Originator, 4);
        b.with_payload(Direction::Originator, |bytes| assert_eq!(bytes, b"BBBB"));
    }

    #[test]
    fn consume_more_than_held_drops_all() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"AAAA");
        b.consume(Direction::Originator, 16);
        b.with_payload(Direction::Originator, |bytes| assert_eq!(bytes, b""));
    }

    #[test]
    fn empty_append_is_noop() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"");
        assert!(b.is_empty());
    }

    #[test]
    fn clear_drops_both_directions() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"AAAA");
        b.append(Direction::Responder, b"BBBB");
        b.clear();
        assert!(b.is_empty());
    }

    #[test]
    fn len_reports_per_direction() {
        let b = ReassemblyBuffer::new(small_cfg());
        b.append(Direction::Originator, b"AAAA");
        b.append(Direction::Responder, b"BBBBBB");
        assert_eq!(b.len(Direction::Originator), 4);
        assert_eq!(b.len(Direction::Responder), 6);
    }

    #[test]
    fn table_with_flow_creates_and_appends() {
        let t = ReassemblyTable::new(8, small_cfg());
        t.with_flow(42, |b| b.append(Direction::Originator, b"AAAA"));
        t.with_flow(42, |b| {
            b.with_payload(Direction::Originator, |bytes| {
                assert_eq!(bytes, b"AAAA");
            });
        });
    }

    #[test]
    fn table_evicts_lru_at_capacity() {
        let t = ReassemblyTable::new(2, small_cfg());
        t.with_flow(1, |b| b.append(Direction::Originator, b"A"));
        t.with_flow(2, |b| b.append(Direction::Originator, b"B"));
        // Touch flow 1 so 2 becomes least-recent.
        t.with_flow(1, |_| {});
        // Insert flow 3 → forces eviction of flow 2.
        t.with_flow(3, |b| b.append(Direction::Originator, b"C"));
        assert_eq!(t.len(), 2);
        // Flow 2 is gone; flow 1 and 3 remain.
        t.with_flow(1, |b| {
            b.with_payload(Direction::Originator, |bytes| assert_eq!(bytes, b"A"));
        });
    }

    #[test]
    fn table_drop_flow_removes_buffer() {
        let t = ReassemblyTable::new(4, small_cfg());
        t.with_flow(1, |b| b.append(Direction::Originator, b"AAAA"));
        assert_eq!(t.len(), 1);
        t.drop_flow(1);
        assert!(t.is_empty());
    }
}

//! Monotonic per-stream sequence number tracker.
//!
//! Every batch the agent emits to the control plane carries a
//! sequence number that monotonically increases per stream.
//! When the control plane acks a batch, it echoes the
//! highest-contiguous sequence it has durably accepted. The
//! agent compares that against its high-water mark:
//!
//! * acked == highest — the agent advances its high-water mark
//!   and frees the spool prefix up to that sequence.
//! * acked >  highest — the server has acked something the agent
//!   never sent. Either a server bug or a replay; fail closed.
//! * acked <  highest — the server has acked a sequence below
//!   the high-water mark. This is the regression case; fail
//!   closed.
//!
//! The fail-closed behaviour is intentional: silently accepting
//! a regressed ack would let an attacker who can replay old acks
//! convince the agent that "newer" batches were durably
//! accepted, suppressing legitimate retries.

use parking_lot::Mutex;

/// Regression report. Returned by [`SequenceTracker::record_ack`]
/// when the server-reported high-water mark is inconsistent with
/// what the agent has on file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceRegression {
    /// Stream identifier — surfaced so an orchestrator can scope
    /// its reconnect to the offending stream rather than tear
    /// the whole connection down.
    pub stream: String,
    /// Highest sequence the agent had emitted on this stream
    /// before the offending ack.
    pub highest_emitted: u64,
    /// Sequence the server reported in the offending ack.
    pub observed: u64,
    /// Reason classification.
    pub kind: RegressionKind,
}

/// Whether the regression was an out-of-band high ack (server
/// acked a sequence the agent never emitted) or a regressed low
/// ack (server acked a sequence below the high-water mark).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionKind {
    /// Server acked a sequence above any the agent has emitted.
    /// Either a server bug or a replay against an old client
    /// session.
    AheadOfEmitted,
    /// Server acked a sequence below the agent's current
    /// high-water mark — the replay attack the fail-closed
    /// posture exists to detect.
    BelowHighWater,
}

/// Per-stream sequence-number generator + ack tracker. The
/// generator allocates fresh sequences for outgoing batches via
/// [`SequenceTracker::next_seq`]; the ack tracker validates
/// server-reported high-water marks via
/// [`SequenceTracker::record_ack`].
#[derive(Debug)]
pub struct SequenceTracker {
    stream: String,
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Next sequence to emit.
    next: u64,
    /// The most recently emitted sequence. `None` until
    /// `next_seq` has been called at least once. Tracked
    /// explicitly (instead of derived from `next - 1`) so the
    /// `u64::MAX` saturation boundary in `next_seq` does not
    /// make `record_ack` reject a legitimate ack of
    /// `u64::MAX` as `AheadOfEmitted`. Also lets us distinguish
    /// "agent has emitted seq 0 and the server is acking it"
    /// (legitimate when start_seq=0) from "agent has emitted
    /// nothing and the server is spuriously acking seq 0".
    last_emitted: Option<u64>,
    /// Highest sequence the server has durably acked.
    acked_high_water: Option<u64>,
}

impl SequenceTracker {
    /// Construct a fresh tracker. `stream` is surfaced in any
    /// [`SequenceRegression`] this tracker emits.
    ///
    /// `start_seq` is the first sequence number to emit; for a
    /// freshly enrolled agent that is `1`. For an agent
    /// resuming an existing stream from a persisted high-water
    /// mark, pass the persisted "next sequence" value.
    #[must_use]
    pub fn new(stream: impl Into<String>, start_seq: u64) -> Self {
        Self {
            stream: stream.into(),
            inner: Mutex::new(Inner {
                next: start_seq,
                last_emitted: None,
                acked_high_water: None,
            }),
        }
    }

    /// The stream identifier this tracker is scoped to.
    #[must_use]
    pub fn stream(&self) -> &str {
        &self.stream
    }

    /// Allocate the next sequence number. The returned value is
    /// `last_emitted + 1`. Atomic with respect to concurrent
    /// `next_seq` calls.
    ///
    /// **Saturation contract**: the internal counter uses
    /// `saturating_add`, so `next_seq` is guaranteed never to
    /// panic but on overflow it will return `u64::MAX`
    /// indefinitely instead of wrapping to 0. The agent emits
    /// per-stream sequences, so at one batch per microsecond
    /// (orders of magnitude beyond what any deployment will
    /// produce) it would take ~584,942 years to reach the
    /// saturation point — this branch exists solely to keep the
    /// arithmetic infallible. If saturation ever became
    /// reachable in practice the right response would be to
    /// migrate the stream to a fresh sequence space (new
    /// stream id), not to wrap.
    pub fn next_seq(&self) -> u64 {
        let mut guard = self.inner.lock();
        let seq = guard.next;
        guard.next = guard.next.saturating_add(1);
        guard.last_emitted = Some(seq);
        seq
    }

    /// The next sequence that will be returned by `next_seq`,
    /// without allocating it. Surfaced for observability /
    /// resumption-checkpoint serialisation.
    pub fn peek_next_seq(&self) -> u64 {
        self.inner.lock().next
    }

    /// The current high-water mark — the highest sequence the
    /// server has durably acked.
    pub fn high_water(&self) -> Option<u64> {
        self.inner.lock().acked_high_water
    }

    /// Record a server-reported high-water mark.
    ///
    /// On success, returns the previous high-water mark (`None`
    /// on the first ack of this session).
    ///
    /// On a regression — either `observed > highest_emitted` or
    /// `observed < high_water` — returns a
    /// [`SequenceRegression`] so the orchestrator can fail
    /// closed.
    pub fn record_ack(&self, observed: u64) -> Result<Option<u64>, SequenceRegression> {
        let mut guard = self.inner.lock();
        // If nothing has been emitted yet, the server cannot
        // legitimately ack any sequence — including 0, which is a
        // valid sequence number when `start_seq == 0`. Reject up
        // front so a server bug or a replay against a freshly
        // constructed tracker can't quietly install a high-water
        // mark.
        //
        // We use `last_emitted` (not `next - 1`) so that the
        // `u64::MAX` saturation boundary in `next_seq` is
        // handled exactly: after emitting `u64::MAX`,
        // `last_emitted == Some(u64::MAX)` and an ack of
        // `u64::MAX` is accepted, while `next - 1 == u64::MAX - 1`
        // would have rejected it as `AheadOfEmitted`.
        let Some(highest_emitted) = guard.last_emitted else {
            return Err(SequenceRegression {
                stream: self.stream.clone(),
                highest_emitted: guard.next.saturating_sub(1),
                observed,
                kind: RegressionKind::AheadOfEmitted,
            });
        };
        if observed > highest_emitted {
            return Err(SequenceRegression {
                stream: self.stream.clone(),
                highest_emitted,
                observed,
                kind: RegressionKind::AheadOfEmitted,
            });
        }
        if let Some(prev) = guard.acked_high_water {
            if observed < prev {
                return Err(SequenceRegression {
                    stream: self.stream.clone(),
                    highest_emitted,
                    observed,
                    kind: RegressionKind::BelowHighWater,
                });
            }
        }
        let prev = guard.acked_high_water.replace(observed);
        Ok(prev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_seq_is_monotonic() {
        let t = SequenceTracker::new("telemetry", 1);
        assert_eq!(t.next_seq(), 1);
        assert_eq!(t.next_seq(), 2);
        assert_eq!(t.next_seq(), 3);
        assert_eq!(t.peek_next_seq(), 4);
    }

    #[test]
    fn record_ack_advances_high_water() {
        let t = SequenceTracker::new("telemetry", 1);
        for _ in 0..5 {
            let _ = t.next_seq();
        }
        // Sequences emitted: 1..=5. Server acks 3.
        let prev = t.record_ack(3).expect("ack accepted");
        assert_eq!(prev, None);
        // Server later acks 5.
        let prev = t.record_ack(5).expect("ack accepted");
        assert_eq!(prev, Some(3));
        // An ack equal to high water is fine (idempotent).
        let prev = t.record_ack(5).expect("ack accepted");
        assert_eq!(prev, Some(5));
        assert_eq!(t.high_water(), Some(5));
    }

    #[test]
    fn ack_ahead_of_emitted_is_rejected() {
        let t = SequenceTracker::new("telemetry", 1);
        // No sequences emitted yet — highest_emitted = 0.
        let err = t.record_ack(7).expect_err("ack ahead must regress");
        assert_eq!(err.kind, RegressionKind::AheadOfEmitted);
        assert_eq!(err.highest_emitted, 0);
        assert_eq!(err.observed, 7);
    }

    #[test]
    fn spurious_ack_before_any_emit_is_rejected() {
        // Server acks seq 0 (or any seq) before the agent has
        // emitted anything. The previous implementation silently
        // accepted ack(0) here because `highest_emitted` underflows
        // to 0 and `0 > 0` is false. With the emitted_any guard,
        // the tracker now rejects unconditionally.
        let t = SequenceTracker::new("telemetry", 1);
        let err = t.record_ack(0).expect_err("ack before emit must regress");
        assert_eq!(err.kind, RegressionKind::AheadOfEmitted);
        assert_eq!(err.observed, 0);
        // Same defence with start_seq=0 — the server cannot ack
        // sequence 0 until the agent has actually emitted it.
        let t0 = SequenceTracker::new("telemetry", 0);
        let err0 = t0.record_ack(0).expect_err("ack before emit must regress");
        assert_eq!(err0.kind, RegressionKind::AheadOfEmitted);
    }

    #[test]
    fn ack_zero_after_emit_is_accepted() {
        // After the agent emits seq 0 (start_seq=0), an ack of 0 is
        // legitimate and must be recorded as the high-water mark.
        let t = SequenceTracker::new("telemetry", 0);
        assert_eq!(t.next_seq(), 0);
        let prev = t.record_ack(0).expect("ack of emitted seq 0");
        assert_eq!(prev, None);
        assert_eq!(t.high_water(), Some(0));
    }

    #[test]
    fn ack_below_high_water_is_rejected() {
        let t = SequenceTracker::new("telemetry", 1);
        for _ in 0..5 {
            let _ = t.next_seq();
        }
        let _ = t.record_ack(4).expect("ack accepted");
        let err = t.record_ack(2).expect_err("ack regression");
        assert_eq!(err.kind, RegressionKind::BelowHighWater);
        assert_eq!(err.stream, "telemetry");
        assert_eq!(err.observed, 2);
    }

    #[test]
    fn ack_of_u64_max_is_accepted_after_saturating_emit() {
        // Regression for the Devin Review off-by-one at the
        // u64::MAX saturation boundary. The earlier implementation
        // computed `highest_emitted = guard.next.saturating_sub(1)`,
        // so after `next_seq` emitted `u64::MAX` the next call kept
        // `next` at `u64::MAX` (saturating_add no-op) and
        // `highest_emitted` was reported as `u64::MAX - 1`, which
        // made a legitimate ack of `u64::MAX` look like an
        // `AheadOfEmitted` regression.
        //
        // The fix tracks `last_emitted` explicitly. We can't loop
        // 2^64 times to reach saturation, so we seed `next` to
        // `u64::MAX` via `start_seq` and exercise the saturating
        // path directly: the first call returns `u64::MAX`, the
        // second also returns `u64::MAX` (saturation), and an ack
        // of `u64::MAX` must be accepted.
        let t = SequenceTracker::new("telemetry", u64::MAX);
        assert_eq!(t.next_seq(), u64::MAX);
        assert_eq!(t.next_seq(), u64::MAX, "next_seq saturates at u64::MAX");
        let prev = t
            .record_ack(u64::MAX)
            .expect("ack of saturated seq is accepted");
        assert_eq!(prev, None);
        assert_eq!(t.high_water(), Some(u64::MAX));
        // And an ack ABOVE u64::MAX is mathematically impossible, but
        // an idempotent re-ack at the boundary must still succeed.
        let prev = t
            .record_ack(u64::MAX)
            .expect("idempotent re-ack at boundary");
        assert_eq!(prev, Some(u64::MAX));
    }

    #[test]
    fn resumes_from_persisted_start_seq() {
        let t = SequenceTracker::new("telemetry", 1000);
        assert_eq!(t.next_seq(), 1000);
        assert_eq!(t.next_seq(), 1001);
        // Ack from before the resume must be rejected as a
        // regression — the server should never know about
        // sequences below the persisted start.
        let _ = t.record_ack(1000).expect("first valid ack");
        let err = t.record_ack(500).expect_err("must regress");
        assert_eq!(err.kind, RegressionKind::BelowHighWater);
    }
}

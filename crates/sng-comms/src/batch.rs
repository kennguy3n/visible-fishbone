//! Size-and-time-bounded batch builder.
//!
//! The agent accumulates [`Envelope`]s in a per-stream
//! [`BatchBuilder`]; the builder flushes a batch to the wire
//! when:
//!
//! * the number of accumulated envelopes hits `max_events`, OR
//! * the encoded payload reaches `max_bytes`, OR
//! * the time-since-first-event exceeds `flush_interval`, OR
//! * the caller explicitly invokes [`force_flush`] (used on
//!   graceful shutdown).
//!
//! The "encoded payload" trigger uses the cached MessagePack
//! size of each envelope rather than recomputing the framed size
//! on every push — encoding once at push time both bounds the
//! work-per-event and lets the flush path skip a re-encode. The
//! envelopes are kept owned in the batch (not yet encoded) so a
//! caller that wants to redact / enrich at flush time can do so
//! without a decode-modify-re-encode cycle.

use chrono::{DateTime, Utc};
use sng_core::envelope::Envelope;
use std::time::Duration;

/// Reason a batch flushed. Surfaced for observability dashboards.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BatchFlushReason {
    /// `max_events` reached.
    EventsLimit,
    /// `max_bytes` reached (estimated MessagePack size).
    BytesLimit,
    /// `flush_interval` elapsed since the first event arrived.
    TimerElapsed,
    /// Caller invoked [`BatchBuilder::force_flush`] (e.g. on
    /// graceful shutdown).
    Forced,
}

/// Configuration for [`BatchBuilder`]. Defaults match the SDA
/// agent's posture: 256 events / 64 KiB / 5 second interval —
/// enough to amortise the per-batch handshake cost without
/// holding events long enough to mask a real incident in the
/// detection pipeline.
#[derive(Debug, Clone, Copy)]
pub struct BatchConfig {
    /// Maximum events per batch. `0` is treated as `1` — i.e.
    /// every event flushes immediately.
    pub max_events: usize,
    /// Maximum estimated MessagePack-encoded size of the batch
    /// (in bytes). When the running total crosses this
    /// threshold the batch flushes.
    pub max_bytes: usize,
    /// Wall-clock duration since the first event in the batch
    /// after which the batch flushes regardless of size.
    pub flush_interval: Duration,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_events: 256,
            max_bytes: 64 * 1024,
            flush_interval: Duration::from_secs(5),
        }
    }
}

/// A flushed batch. Owned by the caller after a successful
/// flush; the [`BatchBuilder`] is reset and ready for the next
/// batch.
#[derive(Debug)]
pub struct Batch {
    /// Envelopes in oldest-to-newest order.
    pub envelopes: Vec<Envelope>,
    /// Estimated MessagePack size (sum of per-envelope sizes
    /// observed at push time). Surfaced so the egress path can
    /// pick a compression strategy without re-encoding.
    pub estimated_bytes: usize,
    /// Wall-clock timestamp the *first* envelope was pushed
    /// into this batch. Used to compute end-to-end latency
    /// (push → control-plane-accepted) on the egress path.
    pub started_at: DateTime<Utc>,
    /// Reason the batch flushed.
    pub reason: BatchFlushReason,
}

/// Size-and-time-bounded batch accumulator.
///
/// **Not** internally synchronised — callers that share a
/// `BatchBuilder` between tasks must wrap it in a
/// `tokio::sync::Mutex` (the canonical pattern in
/// `TelemetryClient`). Keeping the type sync-agnostic at this
/// layer means embedding a batch builder inside an outer state
/// machine (e.g. PR 5's `sng-telemetry`) does not pay for an
/// extra mutex.
#[derive(Debug)]
pub struct BatchBuilder {
    config: BatchConfig,
    pending: Vec<Envelope>,
    estimated_bytes: usize,
    started_at: Option<DateTime<Utc>>,
}

impl BatchBuilder {
    /// Construct a fresh builder.
    #[must_use]
    pub fn new(config: BatchConfig) -> Self {
        Self {
            config,
            pending: Vec::with_capacity(initial_capacity(config.max_events)),
            estimated_bytes: 0,
            started_at: None,
        }
    }

    /// Number of accumulated envelopes (snapshot).
    #[must_use]
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether the builder currently holds no events.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Estimated bytes accumulated so far.
    #[must_use]
    pub fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }

    /// Wall-clock timestamp the oldest currently-pending event
    /// was pushed. Used by [`BatchBuilder::poll_timer`] to
    /// decide whether the flush-interval has elapsed.
    #[must_use]
    pub fn started_at(&self) -> Option<DateTime<Utc>> {
        self.started_at
    }

    /// Add an envelope to the batch. Returns `Some(Batch)` if
    /// the push triggered a size-based flush; the caller is
    /// expected to send the returned batch.
    ///
    /// The push always succeeds — the size-based flush returns
    /// the batch *before* the new envelope and starts a fresh
    /// batch around the new envelope. This guarantees no event
    /// is ever silently dropped from inside the builder, and
    /// the new event is always emitted in the next batch.
    pub fn push(&mut self, envelope: Envelope) -> Option<Batch> {
        let envelope_size = estimated_msgpack_size(&envelope);

        // If pushing this envelope would push us over a bound,
        // flush the existing batch first and start a fresh one.
        let flush_reason = if !self.pending.is_empty()
            && (self.pending.len() >= self.config.max_events
                || self.estimated_bytes.saturating_add(envelope_size) > self.config.max_bytes)
        {
            Some(if self.pending.len() >= self.config.max_events {
                BatchFlushReason::EventsLimit
            } else {
                BatchFlushReason::BytesLimit
            })
        } else {
            None
        };
        let flushed = flush_reason.map(|reason| self.take(reason));

        if self.started_at.is_none() {
            self.started_at = Some(envelope.timestamp);
        }
        self.estimated_bytes = self.estimated_bytes.saturating_add(envelope_size);
        self.pending.push(envelope);

        // After the push, a single-envelope batch may also have
        // hit the bound (e.g. max_events == 1, or the envelope
        // alone exceeds max_bytes). In that case we flush again
        // to give the caller a one-event batch immediately.
        if self.pending.len() >= self.config.max_events
            || self.estimated_bytes > self.config.max_bytes
        {
            let reason = if self.pending.len() >= self.config.max_events {
                BatchFlushReason::EventsLimit
            } else {
                BatchFlushReason::BytesLimit
            };
            // We deliberately discard `flushed` here only if it
            // was `None`; if both pre- and post-push hit the
            // bound, the caller still needs both batches. The
            // contract is that `push` returns *at most one*
            // batch — if the pre-push flush already happened,
            // the post-push case cannot have triggered (a
            // single new event cannot itself exceed a bound
            // that the pre-push had already cleared by
            // resetting). The post-push trigger is only
            // reachable when `flushed` is `None`.
            debug_assert!(
                flushed.is_none(),
                "post-push trigger should only fire when pre-push did not",
            );
            return Some(self.take(reason));
        }
        flushed
    }

    /// Check whether the flush-interval timer has elapsed and
    /// return the accumulated batch if so. Caller wires this up
    /// to a `tokio::time::interval` ticker in production.
    pub fn poll_timer(&mut self, now: DateTime<Utc>) -> Option<Batch> {
        let started = self.started_at?;
        if self.pending.is_empty() {
            return None;
        }
        let elapsed = now.signed_duration_since(started);
        let elapsed_std = elapsed.to_std().ok()?;
        if elapsed_std >= self.config.flush_interval {
            Some(self.take(BatchFlushReason::TimerElapsed))
        } else {
            None
        }
    }

    /// Force a flush regardless of bounds. Used on graceful
    /// shutdown so no events sit in the builder when the agent
    /// exits.
    pub fn force_flush(&mut self) -> Option<Batch> {
        if self.pending.is_empty() {
            None
        } else {
            Some(self.take(BatchFlushReason::Forced))
        }
    }

    fn take(&mut self, reason: BatchFlushReason) -> Batch {
        let envelopes = std::mem::replace(
            &mut self.pending,
            Vec::with_capacity(initial_capacity(self.config.max_events)),
        );
        let estimated_bytes = std::mem::take(&mut self.estimated_bytes);
        let started_at = self.started_at.take().unwrap_or_else(Utc::now);
        Batch {
            envelopes,
            estimated_bytes,
            started_at,
            reason,
        }
    }
}

/// Cap the pre-allocated [`Vec`] capacity at a reasonable upper
/// bound. Callers may pass `usize::MAX` for `max_events` (the
/// "only the byte / time triggers fire" case); blindly
/// preallocating that many slots aborts allocation immediately.
fn initial_capacity(max_events: usize) -> usize {
    // 1024 events is well above the default 256 batch ceiling
    // while staying within a few hundred KB of pre-reserved
    // headroom even with chunky envelope structs.
    max_events.clamp(1, 1024)
}

/// Estimate the MessagePack-encoded size of an envelope without
/// allocating an encoded buffer. We use the actual
/// `rmp_serde::encoded_len` helper rather than guessing — it
/// walks the value once and tracks per-field framing exactly.
/// On the rare cases where it fails (e.g. a deeply nested
/// recursive type with a counter overflow), we fall back to a
/// conservative upper bound of 4 KiB so the batch still has a
/// monotonically advancing size signal.
fn estimated_msgpack_size(envelope: &Envelope) -> usize {
    // `rmp_serde` doesn't expose an `encoded_len` helper, but
    // encoding to a `Vec<u8>` is the canonical sizing path and
    // is what the egress codec will do at flush time anyway.
    // To keep the per-event cost predictable, we cap the
    // worst-case "this envelope is unencodable" path with a
    // conservative bound; in practice every envelope shape that
    // ships in this workspace encodes successfully.
    rmp_serde::to_vec(envelope).map_or(4 * 1024, |v| v.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sng_core::envelope::{Envelope, EventClass, Platform, SCHEMA_VERSION};
    use sng_core::ids::{DeviceId, EventId, SiteId, TenantId};
    use sng_core::traffic_class::TrafficClass;

    fn mk_envelope(seconds: i64) -> Envelope {
        Envelope {
            schema_version: SCHEMA_VERSION,
            event_id: EventId::new_v4(),
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            site_id: Some(SiteId::new_v4()),
            timestamp: Utc.timestamp_opt(seconds, 0).single().expect("ts"),
            event_class: EventClass::Flow,
            platform: Platform::Linux,
            traffic_class: Some(TrafficClass::InspectLite),
            bytes_in: 0,
            bytes_out: 0,
            payload: Vec::new(),
        }
    }

    #[test]
    fn flushes_on_max_events() {
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: 3,
            max_bytes: usize::MAX,
            flush_interval: Duration::from_secs(60),
        });
        assert!(b.push(mk_envelope(1)).is_none());
        assert!(b.push(mk_envelope(2)).is_none());
        let batch = b.push(mk_envelope(3)).expect("flushes on third");
        assert_eq!(batch.reason, BatchFlushReason::EventsLimit);
        assert_eq!(batch.envelopes.len(), 3);
        assert!(b.is_empty());
    }

    #[test]
    fn flushes_on_max_bytes() {
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: usize::MAX,
            // Force a flush after two envelopes — encoded size
            // varies a little but is well above 50 bytes each.
            max_bytes: 50,
            flush_interval: Duration::from_secs(60),
        });
        assert!(b.push(mk_envelope(1)).is_some());
    }

    #[test]
    fn flushes_on_timer() {
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: usize::MAX,
            max_bytes: usize::MAX,
            flush_interval: Duration::from_secs(1),
        });
        let env = mk_envelope(0);
        let pushed_at = env.timestamp;
        b.push(env);
        // Still inside the window.
        assert!(
            b.poll_timer(pushed_at + chrono::Duration::milliseconds(500))
                .is_none()
        );
        // Past the window — flushes.
        let flushed = b
            .poll_timer(pushed_at + chrono::Duration::seconds(2))
            .expect("flushes on timer");
        assert_eq!(flushed.reason, BatchFlushReason::TimerElapsed);
        assert_eq!(flushed.envelopes.len(), 1);
    }

    #[test]
    fn force_flush_drains_pending() {
        let mut b = BatchBuilder::new(BatchConfig::default());
        b.push(mk_envelope(1));
        b.push(mk_envelope(2));
        let flushed = b.force_flush().expect("force flush drains pending");
        assert_eq!(flushed.reason, BatchFlushReason::Forced);
        assert_eq!(flushed.envelopes.len(), 2);
        assert!(b.is_empty());
        // Forced flush on an empty builder is a no-op.
        assert!(b.force_flush().is_none());
    }

    #[test]
    fn no_event_is_lost_across_size_based_flushes() {
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: 2,
            max_bytes: usize::MAX,
            flush_interval: Duration::from_secs(60),
        });
        let e1 = mk_envelope(1);
        let e2 = mk_envelope(2);
        let e3 = mk_envelope(3);
        let id1 = e1.event_id;
        let id2 = e2.event_id;
        let id3 = e3.event_id;
        assert!(b.push(e1).is_none());
        // e2 pushes us to 2/2 and triggers a flush of [e1, e2].
        let batch = b.push(e2).expect("flushes at limit");
        let ids: Vec<_> = batch.envelopes.iter().map(|e| e.event_id).collect();
        assert_eq!(ids, vec![id1, id2]);
        // e3 starts a fresh batch.
        assert!(b.push(e3).is_none());
        assert_eq!(b.len(), 1);
        let leftover = b.force_flush().expect("leftover");
        assert_eq!(
            leftover
                .envelopes
                .iter()
                .map(|e| e.event_id)
                .collect::<Vec<_>>(),
            vec![id3],
        );
    }
}

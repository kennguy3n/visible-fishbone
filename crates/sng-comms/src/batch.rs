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
//! The "encoded payload" trigger uses the **actual** MessagePack
//! size of each envelope, not an estimate: we encode each
//! envelope to bytes once at push time (so the size bound is
//! exact, not approximate) and cache the bytes alongside the
//! envelope inside the batch. The egress path then concatenates
//! the cached per-envelope bytes under a single MessagePack
//! array header rather than re-encoding the whole batch — the
//! encode pass at push time *is* the only encode pass.
//!
//! Callers that need to redact / enrich an envelope must do so
//! before calling [`BatchBuilder::push`]; the canonical place
//! for late enrichment is `TelemetryClient::submit`, which
//! applies the `EnrichmentContext` before forwarding to the
//! builder.

use chrono::{DateTime, Utc};
use sng_core::envelope::Envelope;
use std::time::Duration;
use tracing::warn;

/// One envelope plus its MessagePack bytes, captured at
/// [`BatchBuilder::push`] time.
///
/// The cached `encoded` bytes are exactly what the production
/// codec (`rmp_serde::to_vec_named`) produces for a single
/// envelope. The batch flush path concatenates these bytes under
/// a MessagePack array header — `array_header(N) ++ encoded[0]
/// ++ … ++ encoded[N-1]` is byte-for-byte the same as
/// `rmp_serde::to_vec_named(&[envelope_0, …, envelope_N-1])`.
#[derive(Debug, Clone)]
pub struct EncodedEnvelope {
    /// The structured envelope. Preserved for observability,
    /// metrics, and tests that want to inspect individual
    /// fields after a batch flushes.
    pub envelope: Envelope,
    /// Per-envelope MessagePack-encoded bytes. Concatenating
    /// these under a single MessagePack array header is
    /// equivalent to encoding the whole `Vec<Envelope>` in one
    /// shot — this is the property that lets us avoid the
    /// previous double-encode (size estimate at push + full
    /// re-encode at flush).
    pub encoded: Vec<u8>,
}

impl EncodedEnvelope {
    /// Encode an envelope and pair it with its bytes.
    ///
    /// Returns `Err` if `rmp_serde::to_vec_named` fails — in
    /// practice this is unreachable (all `Envelope` field types
    /// are trivially serializable), but surfacing the error
    /// prevents a silent-empty-bytes outcome that would produce
    /// a corrupt MessagePack array: the array header would claim
    /// N items but only N−1 items' worth of bytes would follow.
    /// Callers (i.e. `BatchBuilder::push`) log-and-drop on error
    /// so the wire format stays valid at the cost of one
    /// dropped envelope.
    pub fn encode(envelope: Envelope) -> Result<Self, rmp_serde::encode::Error> {
        // `to_vec_named` matches `TelemetryClient::encode_batch`
        // exactly — named maps using `#[serde(rename = "…")]`
        // short tags. The Go control plane decodes with
        // `vmihailenco/msgpack/v5`, which expects named maps.
        let encoded = rmp_serde::to_vec_named(&envelope)?;
        Ok(Self { envelope, encoded })
    }

    /// Encoded byte length. Constant-time accessor used by the
    /// builder's bounds-checking.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        self.encoded.len()
    }
}

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
    /// Maximum events per batch. The builder enforces a minimum
    /// of `1` at construction time via [`BatchConfig::normalize`]
    /// — a caller-supplied `0` becomes `1`, i.e. every event
    /// flushes immediately. The normalisation is structural so a
    /// future refactor of the post-push bounds check (`>=`
    /// vs `>`) cannot silently regress to "never flush on event
    /// count" when the operator sets `max_events = 0`.
    pub max_events: usize,
    /// Maximum estimated MessagePack-encoded size of the batch
    /// (in bytes). When the running total crosses this
    /// threshold the batch flushes. Normalised to a minimum of
    /// `1` for the same reason as `max_events`.
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

impl BatchConfig {
    /// Coerce caller-supplied values into the closed set the
    /// builder's invariants assume. Both `max_events` and
    /// `max_bytes` are clamped to a minimum of `1`: zero would
    /// mean "never flush on this dimension", which is an
    /// ambiguous footgun — the field is documented as a *cap*,
    /// so the only consistent interpretation of `0` is "flush
    /// every event".
    ///
    /// Called by [`BatchBuilder::new`]; callers constructing a
    /// `BatchConfig` by hand can call this themselves to keep
    /// the value they store identical to what the builder will
    /// actually use.
    #[must_use]
    pub fn normalize(self) -> Self {
        Self {
            max_events: self.max_events.max(1),
            max_bytes: self.max_bytes.max(1),
            flush_interval: self.flush_interval,
        }
    }
}

/// A flushed batch. Owned by the caller after a successful
/// flush; the [`BatchBuilder`] is reset and ready for the next
/// batch.
#[derive(Debug)]
pub struct Batch {
    /// Envelopes in oldest-to-newest order, paired with their
    /// MessagePack-encoded bytes. The egress path concatenates
    /// the encoded bytes under a single array header rather
    /// than re-encoding the structured envelopes.
    pub envelopes: Vec<EncodedEnvelope>,
    /// Exact MessagePack size of the per-envelope payloads,
    /// summed at push time. Does **not** include the array
    /// header (≤5 bytes) the egress codec writes around the
    /// payloads. Surfaced so the egress path can pick a
    /// compression strategy without re-walking the envelopes.
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
    pending: Vec<EncodedEnvelope>,
    estimated_bytes: usize,
    started_at: Option<DateTime<Utc>>,
}

impl BatchBuilder {
    /// Construct a fresh builder.
    ///
    /// The supplied config is run through
    /// [`BatchConfig::normalize`] so the builder's own
    /// `max_events` / `max_bytes` invariants (both must be ≥ 1)
    /// hold even if the caller passed `0`.
    #[must_use]
    pub fn new(config: BatchConfig) -> Self {
        let config = config.normalize();
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
    ///
    /// `push` returns **at most one** batch per call. If the
    /// pre-push state has crossed a bound AND the new envelope
    /// would itself cross a bound (e.g. `max_events == 1`, or a
    /// single envelope larger than `max_bytes`), the pre-push
    /// batch is what comes out of this call; the oversized new
    /// envelope stays as the next pending batch and is flushed
    /// on the next `push` / `poll_timer` / `force_flush`.
    pub fn push(&mut self, envelope: Envelope) -> Option<Batch> {
        // Encode once at push time so both the bounds check and
        // the eventual flush use the same exact byte length —
        // this is the singular MessagePack encode pass for the
        // life of this envelope.
        let encoded = match EncodedEnvelope::encode(envelope) {
            Ok(e) => e,
            Err(e) => {
                // Drop the un-encodable envelope rather than
                // inserting a 0-byte entry that would corrupt the
                // MessagePack array header/body contract. This is
                // unreachable in practice (all Envelope field
                // types derive Serialize), but if a future field
                // introduces a non-trivially-serializable type the
                // operator gets a visible log line and the wire
                // format stays valid.
                warn!(error = %e, "envelope encoding failed; dropping");
                return None;
            }
        };
        let envelope_size = encoded.encoded_len();

        // Pre-push: if the current pending state already crosses
        // a bound, OR adding this envelope would, flush the
        // existing batch first and start a fresh one.
        let pre_flush = if !self.pending.is_empty()
            && (self.pending.len() >= self.config.max_events
                || self.estimated_bytes.saturating_add(envelope_size) > self.config.max_bytes)
        {
            let reason = if self.pending.len() >= self.config.max_events {
                BatchFlushReason::EventsLimit
            } else {
                BatchFlushReason::BytesLimit
            };
            Some(self.take(reason))
        } else {
            None
        };

        if self.started_at.is_none() {
            self.started_at = Some(encoded.envelope.timestamp);
        }
        self.estimated_bytes = self.estimated_bytes.saturating_add(envelope_size);
        self.pending.push(encoded);

        // Contract: `push` returns at most one batch. If the
        // pre-push already produced a batch, return it and leave
        // the new envelope pending — even if the new envelope
        // alone exceeds a bound. The oversized-single-event
        // batch will fire on the next `push` (becoming the
        // pre-push case), `poll_timer`, or `force_flush`.
        //
        // Earlier revisions of this method ran a second flush
        // check after the pre-push and silently dropped the
        // pre-push batch when both triggers fired (e.g.
        // `max_events == 1`, or a 70 KiB envelope arriving with
        // `max_bytes == 64 KiB` while pending was non-empty).
        // The regression is covered by
        // `pre_push_flush_is_not_dropped_when_new_event_alone_exceeds_max_bytes`
        // below.
        if pre_flush.is_some() {
            return pre_flush;
        }

        // Pre-push didn't fire: check whether the new envelope
        // ALONE crossed a bound and flush a single-event batch
        // if so.
        if self.pending.len() >= self.config.max_events
            || self.estimated_bytes > self.config.max_bytes
        {
            let reason = if self.pending.len() >= self.config.max_events {
                BatchFlushReason::EventsLimit
            } else {
                BatchFlushReason::BytesLimit
            };
            return Some(self.take(reason));
        }
        None
    }

    /// Check whether the flush-interval timer has elapsed and
    /// return the accumulated batch if so. Caller wires this up
    /// to a `tokio::time::interval` ticker in production.
    ///
    /// Resilient to wall-clock regression: if `now` precedes the
    /// stored `started_at` (NTP backward adjustment, VM
    /// snapshot-restore, leap-second handling), the timer is
    /// re-pinned to `now` and treated as zero-elapsed for this
    /// call. Without this, the negative `signed_duration_since`
    /// would propagate `None` from `.to_std().ok()?` and the
    /// batch would sit in memory until the clock recovered past
    /// `started + flush_interval` (or a size-based trigger
    /// fired). Re-pinning restores the wall-clock `flush_interval`
    /// guarantee from this point forward at the cost of one
    /// extra interval window of latency on the regression event
    /// itself.
    pub fn poll_timer(&mut self, now: DateTime<Utc>) -> Option<Batch> {
        let started = self.started_at?;
        if self.pending.is_empty() {
            return None;
        }
        let elapsed = now.signed_duration_since(started);
        let Ok(elapsed_std) = elapsed.to_std() else {
            // Backward clock jump — `started_at` is in the
            // future relative to `now`. Re-pin so the next
            // poll sees a sane forward duration.
            self.started_at = Some(now);
            return None;
        };
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

/// Write a MessagePack array-header (1-, 3-, or 5-byte form
/// depending on `len`) to `out`. This is the same framing
/// `rmp_serde::to_vec_named` would emit at the start of a
/// `Vec<T>` encoding, so concatenating the cached per-envelope
/// bytes after this header is byte-for-byte equivalent to
/// re-encoding the whole `Vec<Envelope>`.
pub(crate) fn write_msgpack_array_header(out: &mut Vec<u8>, len: usize) {
    // <https://github.com/msgpack/msgpack/blob/master/spec.md#array-format-family>
    // fixarray: 0x90 ..= 0x9F (length 0..=15)
    // array16:  0xDC + u16 big-endian (length 16..=65535)
    // array32:  0xDD + u32 big-endian (length ≥ 65536)
    if let Ok(l) = u8::try_from(len)
        && l <= 0xF
    {
        out.push(0x90 | l);
        return;
    }
    if let Ok(l) = u16::try_from(len) {
        out.push(0xDC);
        out.extend_from_slice(&l.to_be_bytes());
        return;
    }
    // `len` necessarily fits in u32 here on 64-bit targets only
    // up to 4 G envelopes — beyond which we saturate to u32::MAX
    // (a >4 G envelope batch would have crashed on RAM long
    // before reaching this branch).
    let l = u32::try_from(len).unwrap_or(u32::MAX);
    out.push(0xDD);
    out.extend_from_slice(&l.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use sng_core::envelope::{Envelope, EventClass, Platform, SCHEMA_VERSION};
    use sng_core::ids::{DeviceId, EventId, SiteId, TenantId};
    use sng_core::traffic_class::TrafficClass;

    fn mk_envelope(seconds: i64) -> Envelope {
        mk_envelope_with_payload(seconds, Vec::new())
    }

    fn mk_envelope_with_payload(seconds: i64, payload: Vec<u8>) -> Envelope {
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
            payload,
        }
    }

    /// The crucial equivalence: `array_header(N) ++ encoded[0]
    /// ++ … ++ encoded[N-1]` must be byte-for-byte the same as
    /// `rmp_serde::to_vec_named(&Vec<Envelope>)`. This is what
    /// lets the egress path avoid the second encode pass.
    /// Exercised across the 1-byte / 3-byte / 5-byte array
    /// header boundaries (fixarray ≤15, array16 ≤65535,
    /// array32 ≥65536) so a future change to the framing helper
    /// can't silently corrupt the wire format.
    #[test]
    fn array_header_plus_per_envelope_bytes_match_rmp_serde_named_vec() {
        for n in [0usize, 1, 2, 15, 16, 32, 257] {
            let envelopes: Vec<Envelope> = (0..n).map(|i| mk_envelope(i as i64)).collect();

            let direct = rmp_serde::to_vec_named(&envelopes).expect("direct encode");

            let mut spliced = Vec::with_capacity(direct.len());
            write_msgpack_array_header(&mut spliced, n);
            for env in &envelopes {
                spliced
                    .extend_from_slice(&rmp_serde::to_vec_named(env).expect("per-envelope encode"));
            }

            assert_eq!(spliced, direct, "splice equivalence broke for N={n}");
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
    fn poll_timer_recovers_from_backward_clock_jump() {
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: usize::MAX,
            max_bytes: usize::MAX,
            flush_interval: Duration::from_secs(1),
        });
        let env = mk_envelope(0);
        let pushed_at = env.timestamp;
        b.push(env);
        // Simulate a backward clock jump: poll with `now` ten
        // seconds *before* the push timestamp. Without the
        // regression guard `poll_timer` would return None
        // silently because `to_std()` errors on the negative
        // duration, and the batch would sit until the clock
        // caught back up past `pushed_at + 1s`.
        let backward_now = pushed_at - chrono::Duration::seconds(10);
        assert!(b.poll_timer(backward_now).is_none());
        // The internal start should have been re-pinned to
        // `backward_now`. After the configured interval has
        // elapsed *from there*, the next poll must flush — proving
        // the wall-clock guarantee was restored.
        let forward_now = backward_now + chrono::Duration::seconds(2);
        let flushed = b.poll_timer(forward_now).expect("flushes after re-pin");
        assert_eq!(flushed.reason, BatchFlushReason::TimerElapsed);
        assert_eq!(flushed.envelopes.len(), 1);
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
    fn pre_push_flush_is_not_dropped_when_new_event_alone_exceeds_max_bytes() {
        // Regression for the silent-drop reported by Devin Review:
        // when pending was non-empty AND the incoming envelope
        // alone exceeded `max_bytes`, the pre-push flush was
        // computed correctly but then overwritten by the
        // post-push branch which returned a fresh single-event
        // batch and dropped the old one on the floor.
        //
        // Set max_bytes large enough to hold 2-3 zero-payload
        // envelopes but smaller than a single envelope carrying
        // a multi-KiB payload; then arrange:
        //   1) push a small envelope (pending = 1)
        //   2) push a small envelope (still under max_bytes)
        //   3) push a big envelope whose encoded size alone > max_bytes
        // The third push must return the [small, small] batch
        // accumulated in (1)-(2). The big envelope stays pending
        // and is drained via `force_flush`.
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: usize::MAX,
            max_bytes: 512,
            flush_interval: Duration::from_secs(60),
        });
        let small_1 = mk_envelope(1);
        let small_2 = mk_envelope(2);
        let id_small_1 = small_1.event_id;
        let id_small_2 = small_2.event_id;
        assert!(b.push(small_1).is_none(), "first small push doesn't flush");
        assert!(
            b.push(small_2).is_none(),
            "second small push stays under max_bytes",
        );
        // Big envelope with a payload guaranteed to exceed
        // max_bytes by itself.
        let big = mk_envelope_with_payload(3, vec![0xab; 4096]);
        let id_big = big.event_id;
        let batch = b
            .push(big)
            .expect("oversized push must flush the accumulated pre-push batch");
        // Pre-push batch must carry BOTH small envelopes — the
        // bug was that it was overwritten with a fresh [big] batch.
        let ids: Vec<_> = batch
            .envelopes
            .iter()
            .map(|e| e.envelope.event_id)
            .collect();
        assert_eq!(
            ids,
            vec![id_small_1, id_small_2],
            "pre-push batch must contain the two small envelopes \
             accumulated before the oversized push",
        );
        assert_eq!(batch.reason, BatchFlushReason::BytesLimit);
        // The oversized envelope stayed in pending.
        assert_eq!(b.len(), 1, "oversized envelope is now the sole pending");
        let leftover = b
            .force_flush()
            .expect("force_flush drains the oversized envelope");
        let leftover_ids: Vec<_> = leftover
            .envelopes
            .iter()
            .map(|e| e.envelope.event_id)
            .collect();
        assert_eq!(leftover_ids, vec![id_big]);
        assert_eq!(leftover.reason, BatchFlushReason::Forced);
    }

    #[test]
    fn pre_push_flush_is_not_dropped_when_max_events_is_one() {
        // Same silent-drop class of bug for `max_events == 1`:
        // pending has one event (already at the limit), a second
        // push triggers pre-push (correct), the post-push then
        // saw `pending.len() == 1 >= max_events` and overwrote
        // the pre-push batch with a fresh single-event batch.
        let mut b = BatchBuilder::new(BatchConfig {
            max_events: 1,
            max_bytes: usize::MAX,
            flush_interval: Duration::from_secs(60),
        });
        let e1 = mk_envelope(1);
        let e2 = mk_envelope(2);
        let id_1 = e1.event_id;
        let id_2 = e2.event_id;
        // First push: post-push fires because max_events == 1.
        let first = b.push(e1).expect("max_events=1 flushes immediately");
        assert_eq!(first.envelopes.len(), 1);
        assert_eq!(first.envelopes[0].envelope.event_id, id_1);
        assert_eq!(first.reason, BatchFlushReason::EventsLimit);
        // Second push into a now-empty builder: pre-push does NOT
        // fire (pending is empty), post-push fires (max_events == 1).
        let second = b.push(e2).expect("second push also flushes");
        assert_eq!(second.envelopes.len(), 1);
        assert_eq!(second.envelopes[0].envelope.event_id, id_2);
        assert_eq!(second.reason, BatchFlushReason::EventsLimit);
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
        let event_id_1 = e1.event_id;
        let event_id_2 = e2.event_id;
        let event_id_3 = e3.event_id;
        assert!(b.push(e1).is_none());
        // e2 pushes us to 2/2 and triggers a flush of [e1, e2].
        let batch = b.push(e2).expect("flushes at limit");
        let collected_ids: Vec<_> = batch
            .envelopes
            .iter()
            .map(|e| e.envelope.event_id)
            .collect();
        assert_eq!(collected_ids, vec![event_id_1, event_id_2]);
        // e3 starts a fresh batch.
        assert!(b.push(e3).is_none());
        assert_eq!(b.len(), 1);
        let leftover = b.force_flush().expect("leftover");
        assert_eq!(
            leftover
                .envelopes
                .iter()
                .map(|e| e.envelope.event_id)
                .collect::<Vec<_>>(),
            vec![event_id_3],
        );
    }

    /// Regression: a caller-supplied `max_events == 0` /
    /// `max_bytes == 0` is structurally clamped to `1` at builder
    /// construction. Without this, the post-push bounds check
    /// (`>= max_events`) "happens to" still flush every event
    /// because `usize >= 0` is always true — but the invariant
    /// is implicit and a future refactor of the check from
    /// `>=` to `>` would silently turn `max_events = 0` into
    /// "never flush on event count".
    #[test]
    fn batch_config_normalize_clamps_zero_to_one() {
        let raw = BatchConfig {
            max_events: 0,
            max_bytes: 0,
            flush_interval: Duration::from_secs(5),
        };
        let norm = raw.normalize();
        assert_eq!(norm.max_events, 1);
        assert_eq!(norm.max_bytes, 1);
        assert_eq!(norm.flush_interval, Duration::from_secs(5));
    }

    #[test]
    fn batch_config_normalize_passes_through_positive() {
        let raw = BatchConfig {
            max_events: 256,
            max_bytes: 64 * 1024,
            flush_interval: Duration::from_secs(5),
        };
        let norm = raw.normalize();
        assert_eq!(norm.max_events, 256);
        assert_eq!(norm.max_bytes, 64 * 1024);
        assert_eq!(norm.flush_interval, Duration::from_secs(5));
    }

    /// Regression: `BatchBuilder::new` runs `normalize` so the
    /// `max_events = 0` footgun cannot create a builder whose
    /// invariants disagree with the documented contract.
    #[test]
    fn builder_new_normalises_zero_max_events_to_one() {
        let mut builder = BatchBuilder::new(BatchConfig {
            max_events: 0,
            max_bytes: 16,
            flush_interval: Duration::from_secs(60),
        });
        // Any push must produce a one-event batch immediately
        // because the normalised cap is 1.
        let env = mk_envelope(1);
        let event_id = env.event_id;
        let batch = builder.push(env).expect("push must flush at cap=1");
        assert_eq!(batch.envelopes.len(), 1);
        assert_eq!(batch.envelopes[0].envelope.event_id, event_id);
        assert_eq!(batch.reason, BatchFlushReason::EventsLimit);
    }
}

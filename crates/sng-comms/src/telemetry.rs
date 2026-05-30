//! Telemetry push over the native protocol.
//!
//! The [`TelemetryClient`] is the agent-side egress surface:
//!
//! 1. Local subsystems hand it [`Envelope`]s via [`submit`].
//! 2. The client buffers them in a per-stream [`BatchBuilder`]
//!    until a size / time threshold trips.
//! 3. Tripped batches go through the enrichment pipeline (site /
//!    tenant / device-id binding) → MessagePack encoding → zstd
//!    compression (if the negotiated content-encoding includes
//!    zstd) → HTTP/2 POST.
//! 4. The control plane responds with a JSON ack `{ "seq": N }`;
//!    the [`SequenceTracker`] validates that against the
//!    high-water mark.
//!
//! Backpressure: when the connection is unhealthy (or `submit`
//! is called between the connect attempt and the connection
//! becoming ready), the [`BoundedSpool`] holds the batch with
//! oldest-dropped-first eviction.
//!
//! **Metadata-first**: the client does NOT inspect or transform
//! the [`Envelope::payload`] bytes. Whether a payload is
//! attached at all is the producer's decision — driven by the
//! tenant's policy (see [`Envelope::payload`] docs). The client
//! redacts nothing of its own accord.

use crate::ack::{SequenceRegression, SequenceTracker};
use crate::batch::{Batch, BatchBuilder, BatchConfig};
use crate::client::{ControlPlaneConnection, RequestBody, RequestPath};
use crate::error::{CommsError, ResponseClass};
use crate::spool::{BoundedSpool, PushOutcome};
use bytes::Bytes;
use http::{HeaderValue, header};
use serde::{Deserialize, Serialize};
use sng_core::envelope::Envelope;
use sng_core::ids::{DeviceId, SiteId, TenantId};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// Compression strategy applied to outgoing batches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BatchCompression {
    /// Send the MessagePack bytes unmodified. No content-encoding
    /// header is set.
    None,
    /// zstd-compress the MessagePack body. Sets
    /// `Content-Encoding: zstd` on the request.
    Zstd {
        /// zstd compression level. The crate's default is 3,
        /// which matches the SDA agent's posture (good
        /// ratio / cpu trade-off).
        level: i32,
    },
}

impl Default for BatchCompression {
    fn default() -> Self {
        Self::Zstd { level: 3 }
    }
}

/// Local-enrichment context applied to every outgoing envelope
/// before encoding. Surfaces the device's tenant / site / device
/// identity, optionally overwriting the producer-supplied values
/// (which may be stub / placeholder for unbound subsystems).
#[derive(Debug, Clone)]
pub struct EnrichmentContext {
    /// Tenant the device is enrolled under.
    pub tenant_id: TenantId,
    /// Device identity (bound at enrolment time).
    pub device_id: DeviceId,
    /// Site, if the device is bound to one. Endpoints typically
    /// have `None` here.
    pub site_id: Option<SiteId>,
}

impl EnrichmentContext {
    /// Apply this context to an envelope in-place. The producer's
    /// tenant / device id / site id are *all* unconditionally
    /// overwritten with the canonical values — local subsystems
    /// may have constructed envelopes with placeholder or stale
    /// identifiers that the egress path is expected to fix up
    /// before they reach the wire. In particular, `site_id` is
    /// also cleared (assigned `None`) when this context has no
    /// site bound: an endpoint that has been re-bound away from
    /// a site must not leak the previous site id onto the wire
    /// because a producer happened to stamp one in.
    fn enrich(&self, envelope: &mut Envelope) {
        envelope.tenant_id = self.tenant_id;
        envelope.device_id = self.device_id;
        envelope.site_id = self.site_id;
    }
}

/// Configuration for [`TelemetryClient`].
#[derive(Debug, Clone)]
pub struct TelemetryClientConfig {
    /// Path the agent POSTs batches to. Defaults to
    /// `/api/v1/agents/telemetry/batches`.
    pub path: String,
    /// Batch builder thresholds.
    pub batch: BatchConfig,
    /// Compression posture for outbound batches.
    pub compression: BatchCompression,
    /// Spool capacity (number of batches that may sit in memory
    /// awaiting flush when the connection is unhealthy).
    pub spool_capacity: usize,
    /// Enrichment context.
    pub enrichment: EnrichmentContext,
    /// Stream identifier used by the sequence tracker.
    pub stream: String,
    /// First sequence number to emit. `1` for a freshly
    /// enrolled device.
    pub start_seq: u64,
}

impl TelemetryClientConfig {
    /// Convenience constructor that fills in canonical defaults
    /// around a caller-supplied [`EnrichmentContext`].
    #[must_use]
    pub fn with_defaults(enrichment: EnrichmentContext) -> Self {
        Self {
            path: "/api/v1/agents/telemetry/batches".into(),
            batch: BatchConfig::default(),
            compression: BatchCompression::default(),
            spool_capacity: 256,
            enrichment,
            stream: "telemetry".into(),
            start_seq: 1,
        }
    }
}

/// Server ack shape — JSON `{ "seq": N }` echoing the highest
/// sequence the control plane has durably accepted.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub struct BatchAck {
    /// Highest sequence number the server has durably accepted.
    pub seq: u64,
}

/// Result of a single [`TelemetryClient::flush_one`] cycle —
/// surfaced to the orchestrator so it can wire dashboards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlushOutcome {
    /// A batch was flushed and acknowledged at the given
    /// high-water mark.
    Acked { seq: u64 },
    /// The spool was empty; nothing to do.
    Empty,
    /// The control plane returned a non-success class; the batch
    /// has been re-spooled at the head of the queue. Caller
    /// decides whether to reconnect.
    Transient { class: ResponseClass },
}

/// High-level telemetry egress surface. Internally:
///
/// * a per-stream [`BatchBuilder`] accumulates envelopes
/// * a [`BoundedSpool`] of encoded batches buffers between
///   batch close and successful POST
/// * a [`SequenceTracker`] guards against ack regression
///
/// The client is `Send + Sync` (via inner `tokio::sync::Mutex`),
/// so producer + flusher tasks can share an `Arc<TelemetryClient>`.
pub struct TelemetryClient {
    config: TelemetryClientConfig,
    builder: Mutex<BatchBuilder>,
    /// Serializes the `encode → next_seq → spool.push` critical
    /// section inside [`Self::seal_batch`]. Without this lock,
    /// two concurrent seal paths (any combination of
    /// [`Self::submit`], [`Self::tick`], and [`Self::force_seal`])
    /// could interleave such that thread A allocates
    /// `next_seq() = N` and thread B allocates `next_seq() = N+1`,
    /// but B reaches `spool.push(entry_N+1)` before A reaches
    /// `spool.push(entry_N)`. The spool would then contain
    /// `[N+1, N]` (FIFO from head), and `flush_one` would send
    /// `N+1` first; the server's ack would lift high-water to
    /// `N+1`, and the subsequent `N` ack would be rejected as a
    /// sequence regression by the [`SequenceTracker`].
    ///
    /// The lock guarantees **spool-order monotonicity in
    /// sequence-number space** — the protocol-relevant invariant.
    /// It does NOT guarantee chronological ordering of the
    /// producer-side event timestamps between concurrently-sealing
    /// batches: if [`Self::tick`] decides to drain older events
    /// while [`Self::submit`] is mid-flight pushing a newer event,
    /// the newer event's batch can briefly win the race for the
    /// builder lock and end up with a lower seq than the older
    /// batch the tick path goes on to allocate. That micro-reorder
    /// is recoverable at the consumer because ClickHouse re-sorts
    /// by `Envelope.timestamp`, and at the wire because the
    /// per-batch seq is what `SequenceTracker` enforces — the
    /// stronger invariant ("first sealed = first pushed") would
    /// require holding the seal_lock across the builder lock too,
    /// which would force every non-sealing submit through the seal
    /// lock for a non-protocol property.
    ///
    /// `parking_lot::Mutex` is used here instead of
    /// `tokio::sync::Mutex` because the critical section is
    /// strictly sync (no `.await` inside `seal_batch`) and
    /// `parking_lot` avoids the executor-aware overhead.
    seal_lock: parking_lot::Mutex<()>,
    spool: Arc<BoundedSpool<EncodedBatch>>,
    tracker: SequenceTracker,
}

impl std::fmt::Debug for TelemetryClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `builder` is intentionally elided from Debug because
        // its `Mutex<BatchBuilder>` content can be locked by the
        // producer task and we never want to deadlock logging.
        f.debug_struct("TelemetryClient")
            .field("config", &self.config)
            .field("spool_len", &self.spool.len())
            .field("next_seq", &self.tracker.peek_next_seq())
            .finish_non_exhaustive()
    }
}

/// A batch that has been encoded, compressed, and sequenced —
/// ready to be POSTed to the control plane.
#[derive(Debug)]
struct EncodedBatch {
    seq: u64,
    body: Bytes,
    encoding: BatchCompression,
    event_count: usize,
}

impl TelemetryClient {
    /// Construct a fresh telemetry client.
    #[must_use]
    pub fn new(config: TelemetryClientConfig) -> Self {
        let batch_cfg = config.batch;
        let spool_cap = config.spool_capacity;
        let stream = config.stream.clone();
        let start_seq = config.start_seq;
        Self {
            config,
            builder: Mutex::new(BatchBuilder::new(batch_cfg)),
            seal_lock: parking_lot::Mutex::new(()),
            spool: Arc::new(BoundedSpool::new(spool_cap)),
            tracker: SequenceTracker::new(stream, start_seq),
        }
    }

    /// Snapshot of spool statistics.
    pub fn spool_stats(&self) -> crate::spool::SpoolStats {
        self.spool.stats()
    }

    /// Snapshot of the sequence tracker's high-water mark.
    pub fn ack_high_water(&self) -> Option<u64> {
        self.tracker.high_water()
    }

    /// Submit a single envelope. Returns `Ok(())` once the
    /// envelope has been enqueued (either still pending in the
    /// builder, or already sealed into the spool). The caller is
    /// expected to invoke [`flush_one`] from a separate task
    /// against an active connection.
    ///
    /// Returns [`CommsError::EnvelopeInvalid`] if the envelope
    /// fails [`Envelope::validate`] after enrichment. Validation
    /// runs *after* enrichment because the canonical
    /// `tenant_id` / `device_id` / `site_id` are stamped in by
    /// the egress path — a producer is allowed (and expected)
    /// to leave those slots in the producer-side default state.
    /// Other fields (`event_id`, `timestamp`, `schema_version`,
    /// `payload`) are the producer's responsibility, and the
    /// Go-side `Envelope.Validate` will reject malformed bytes
    /// server-side anyway; failing fast here means an invalid
    /// envelope cannot consume a spool slot or burn network
    /// bandwidth.
    pub async fn submit(&self, mut envelope: Envelope) -> Result<(), CommsError> {
        self.config.enrichment.enrich(&mut envelope);
        envelope.validate()?;
        let mut guard = self.builder.lock().await;
        if let Some(batch) = guard.push(envelope) {
            drop(guard);
            self.seal_batch(&batch);
        }
        Ok(())
    }

    /// Force a flush of any pending events in the builder onto
    /// the spool. Called on graceful shutdown and as part of the
    /// flush-timer wakeup.
    pub async fn force_seal(&self) {
        let mut guard = self.builder.lock().await;
        if let Some(batch) = guard.force_flush() {
            drop(guard);
            self.seal_batch(&batch);
        }
    }

    /// Drive any time-based flush. Caller is expected to wire
    /// this up to a `tokio::time::interval` ticker.
    pub async fn tick(&self, now: chrono::DateTime<chrono::Utc>) {
        let mut guard = self.builder.lock().await;
        if let Some(batch) = guard.poll_timer(now) {
            drop(guard);
            self.seal_batch(&batch);
        }
    }

    fn seal_batch(&self, batch: &Batch) {
        // Serialise the whole `encode → next_seq → spool.push`
        // critical section. See the doc comment on `seal_lock`
        // for the full reasoning; the short version is that two
        // concurrent submits that each trigger a seal can
        // otherwise allocate sequence numbers and push to the
        // spool in opposing orders, producing a spool whose head
        // ships out of monotonic-seq order.
        let _seal_guard = self.seal_lock.lock();

        // Encode first, then allocate the sequence number. If
        // encoding fails the batch is dropped without burning a
        // sequence — the tracker only sees monotonic sequences
        // that actually correspond to bytes pushed onto the
        // spool. (`SequenceTracker` tolerates gaps, but
        // gap-free emission keeps the wire trace easier to
        // reason about against the control plane's logs.)
        let encoded = match Self::encode_batch(batch, self.config.compression) {
            Ok(body) => body,
            Err(e) => {
                warn!(error = %e, "telemetry batch encoding failed; dropping batch");
                return;
            }
        };
        let seq = self.tracker.next_seq();
        let entry = EncodedBatch {
            seq,
            body: encoded,
            encoding: self.config.compression,
            event_count: batch.envelopes.len(),
        };
        match self.spool.push(entry) {
            PushOutcome::Accepted => debug!(seq, events = batch.envelopes.len(), "spooled batch"),
            PushOutcome::AcceptedWithEviction => {
                info!(
                    seq,
                    events = batch.envelopes.len(),
                    "spool full — evicted oldest batch to make room",
                );
            }
        }
    }

    /// Flush the oldest spooled batch onto the connection.
    /// Returns the per-flush outcome.
    pub async fn flush_one(
        &self,
        conn: &ControlPlaneConnection,
    ) -> Result<FlushOutcome, CommsError> {
        let Some(entry) = self.spool.pop_front() else {
            return Ok(FlushOutcome::Empty);
        };
        let mut request = RequestPath::post(self.config.path.clone()).with_header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/msgpack"),
        );
        match entry.encoding {
            BatchCompression::None => {}
            BatchCompression::Zstd { .. } => {
                request
                    .headers
                    .insert(header::CONTENT_ENCODING, HeaderValue::from_static("zstd"));
            }
        }
        request.headers.insert(
            http::HeaderName::from_static("x-sng-batch-seq"),
            HeaderValue::from(entry.seq),
        );

        let result = conn
            .send_request(request, RequestBody::Bytes(entry.body.clone()))
            .await;
        let response = match result {
            Ok(r) => r,
            Err(e) => {
                // Connection-level failure — re-queue the batch
                // at the *front* of the spool so it keeps its
                // FIFO position relative to any envelopes that
                // were concurrently submitted during the round
                // trip. If the spool is at capacity the
                // newest-pushed entry is evicted to make room;
                // this preserves the strict ordering guarantee
                // for re-spooled batches that the
                // SequenceTracker assumes when it accepts acks.
                self.spool.push_front(entry);
                return Err(e);
            }
        };
        match response.classify() {
            ResponseClass::Success => {
                // The server returned 2xx — the batch bytes are
                // server-side regardless of what happens below.
                // If the ack body is malformed, we cannot
                // advance the high-water mark, but we also must
                // NOT re-spool because the server already
                // accepted the batch and a re-send would
                // duplicate. The right behaviour is to drop the
                // batch from the local spool (already popped),
                // log loudly so operators can correlate against
                // a server-side ack-encoding bug, and surface
                // the error to the caller so the orchestrator
                // can decide whether to reset state.
                let ack = match parse_ack(&response.body) {
                    Ok(a) => a,
                    Err(e) => {
                        warn!(
                            seq = entry.seq,
                            events = entry.event_count,
                            error = %e,
                            "control plane returned 2xx with malformed ack \
                             body; batch is server-side, local high-water \
                             mark NOT advanced",
                        );
                        return Err(e);
                    }
                };
                self.tracker.record_ack(ack.seq).map_err(map_regression)?;
                debug!(seq = ack.seq, "batch acked");
                Ok(FlushOutcome::Acked { seq: ack.seq })
            }
            class if class.is_retryable() => {
                // Transient — re-spool at the front so the
                // batch retries before any newer ones, then let
                // the caller decide whether to reconnect.
                self.spool.push_front(entry);
                Ok(FlushOutcome::Transient { class })
            }
            class => {
                // Permanent — drop the batch with a log line.
                // (Re-pushing would loop forever.)
                warn!(
                    seq = entry.seq,
                    events = entry.event_count,
                    status = %response.status,
                    "control plane permanently rejected telemetry batch",
                );
                Err(CommsError::Server {
                    class,
                    reason: format!("telemetry batch rejected: HTTP {}", response.status),
                })
            }
        }
    }

    fn encode_batch(batch: &Batch, compression: BatchCompression) -> Result<Bytes, CommsError> {
        // The per-envelope MessagePack bytes were captured once
        // at `BatchBuilder::push` time using `to_vec_named` —
        // named maps (`{ "v": …, "id": …, … }`) with the
        // `#[serde(rename = "…")]` short tags the Go control
        // plane's `vmihailenco/msgpack/v5` decoder expects. We
        // splice them together under a single array header
        // here: `array_header(N) ++ envelope_0_bytes ++ …
        // ++ envelope_N-1_bytes` is byte-for-byte equivalent to
        // `to_vec_named(&Vec<Envelope>)` but avoids the second
        // full encode pass (the size-estimate at push time WAS
        // the encode pass). See `batch.rs::EncodedEnvelope` for
        // the equivalence proof.
        let mut raw = Vec::with_capacity(batch.estimated_bytes.saturating_add(8));
        crate::batch::write_msgpack_array_header(&mut raw, batch.envelopes.len());
        for item in &batch.envelopes {
            raw.extend_from_slice(&item.encoded);
        }
        match compression {
            BatchCompression::None => Ok(Bytes::from(raw)),
            BatchCompression::Zstd { level } => {
                let compressed = zstd::stream::encode_all(raw.as_slice(), level)
                    .map_err(|e| CommsError::Compression(format!("zstd encode: {e}")))?;
                Ok(Bytes::from(compressed))
            }
        }
    }
}

fn parse_ack(body: &Bytes) -> Result<BatchAck, CommsError> {
    if body.is_empty() {
        return Err(CommsError::Encoding(
            "empty ack body from control plane".into(),
        ));
    }
    // Server may send either JSON or MessagePack; both encodings
    // are tagged at the bytes level. JSON starts with `{`; the
    // MessagePack 1-field map starts with the `fixmap` byte `0x81`.
    match body[0] {
        b'{' => serde_json::from_slice(body)
            .map_err(|e| CommsError::Encoding(format!("decode JSON ack: {e}"))),
        _ => rmp_serde::from_slice(body)
            .map_err(|e| CommsError::Encoding(format!("decode msgpack ack: {e}"))),
    }
}

fn map_regression(reg: SequenceRegression) -> CommsError {
    CommsError::SequenceRegression {
        stream: reg.stream,
        highest: reg.highest_emitted,
        observed: reg.observed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use chrono::Utc;
    use sng_core::envelope::{EventClass, GO_ZERO_TIME_SECS, Platform, SCHEMA_VERSION};
    use sng_core::ids::EventId;
    use sng_core::traffic_class::TrafficClass;

    fn mk_enrichment() -> EnrichmentContext {
        EnrichmentContext {
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            site_id: Some(SiteId::new_v4()),
        }
    }

    fn mk_envelope() -> Envelope {
        Envelope {
            schema_version: SCHEMA_VERSION,
            event_id: EventId::new_v4(),
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            site_id: None,
            timestamp: Utc::now(),
            event_class: EventClass::Flow,
            platform: Platform::Linux,
            traffic_class: Some(TrafficClass::TrustedDirect),
            bytes_in: 100,
            bytes_out: 200,
            // Non-empty so `Envelope::validate()` accepts it.
            // The egress path is metadata-first so the actual
            // bytes are opaque to the client; any non-empty
            // slice suffices for the validation post-condition.
            payload: vec![0xc0],
        }
    }

    #[tokio::test]
    async fn submit_enriches_and_spools_when_batch_seals() {
        let enrichment = mk_enrichment();
        let mut cfg = TelemetryClientConfig::with_defaults(enrichment.clone());
        cfg.batch = BatchConfig {
            max_events: 2,
            max_bytes: usize::MAX,
            flush_interval: std::time::Duration::from_secs(60),
        };
        let client = TelemetryClient::new(cfg);
        client.submit(mk_envelope()).await.expect("submit ok");
        // Still buffered — nothing in the spool yet.
        assert_eq!(client.spool_stats().pushed, 0);
        client.submit(mk_envelope()).await.expect("submit ok");
        // Second submit hits max_events=2 and seals.
        assert_eq!(client.spool_stats().pushed, 1);
    }

    #[tokio::test]
    async fn force_seal_drains_pending() {
        let enrichment = mk_enrichment();
        let client = TelemetryClient::new(TelemetryClientConfig::with_defaults(enrichment));
        client.submit(mk_envelope()).await.expect("submit");
        client.force_seal().await;
        assert_eq!(client.spool_stats().pushed, 1);
        // Calling again with nothing pending is a no-op.
        client.force_seal().await;
        assert_eq!(client.spool_stats().pushed, 1);
    }

    #[test]
    fn parse_ack_accepts_json_and_msgpack() {
        let json = Bytes::from_static(br#"{"seq":7}"#);
        assert_eq!(parse_ack(&json).expect("json ack").seq, 7);
        // 1-field map { "seq": 42 } in MessagePack.
        let msgpack: Vec<u8> = vec![
            0x81, // fixmap len=1
            0xa3, b's', b'e', b'q', // fixstr "seq"
            0x2a, // 42
        ];
        let msgpack = Bytes::from(msgpack);
        assert_eq!(parse_ack(&msgpack).expect("msgpack ack").seq, 42);
    }

    #[test]
    fn parse_ack_rejects_empty() {
        let err = parse_ack(&Bytes::new()).expect_err("empty rejects");
        assert!(matches!(err, CommsError::Encoding(_)));
    }

    #[tokio::test]
    async fn enrichment_overrides_producer_values() {
        let enrichment = mk_enrichment();
        let mut cfg = TelemetryClientConfig::with_defaults(enrichment.clone());
        cfg.batch = BatchConfig {
            max_events: 1,
            ..BatchConfig::default()
        };
        let client = TelemetryClient::new(cfg);
        // Producer stamps a stale site_id; the enrichment must
        // overwrite it with the canonical value from the
        // EnrichmentContext.
        let mut env = mk_envelope();
        env.site_id = Some(SiteId::new_v4());
        client.submit(env).await.expect("submit");
        // Inspect the encoded batch via the spool — we know one
        // entry exists because max_events=1 forced a seal on
        // the very first submit.
        let entry = client.spool.pop_front().expect("one batch");
        // Decode + verify enrichment applied. We have to undo
        // the compression first because the default is zstd.
        let raw = zstd::stream::decode_all(entry.body.as_ref()).expect("zstd decode");
        let envelopes: Vec<Envelope> = rmp_serde::from_slice(&raw).expect("decode");
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].tenant_id, enrichment.tenant_id);
        assert_eq!(envelopes[0].device_id, enrichment.device_id);
        assert_eq!(envelopes[0].site_id, enrichment.site_id);
    }

    #[tokio::test]
    async fn enrichment_clears_producer_site_when_context_unbound() {
        // Endpoint scenario: device is *not* bound to a site, so
        // the EnrichmentContext.site_id is None. A producer
        // subsystem that left a stale site_id on the envelope
        // must NOT have that value reach the wire.
        let enrichment = EnrichmentContext {
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            site_id: None,
        };
        let mut cfg = TelemetryClientConfig::with_defaults(enrichment.clone());
        cfg.batch = BatchConfig {
            max_events: 1,
            ..BatchConfig::default()
        };
        let client = TelemetryClient::new(cfg);
        let mut env = mk_envelope();
        env.site_id = Some(SiteId::new_v4()); // producer's stale stamp
        client.submit(env).await.expect("submit");
        let entry = client.spool.pop_front().expect("one batch");
        let raw = zstd::stream::decode_all(entry.body.as_ref()).expect("zstd decode");
        let envelopes: Vec<Envelope> = rmp_serde::from_slice(&raw).expect("decode");
        assert_eq!(envelopes.len(), 1);
        // The canonical "unbound" identity wins — site is None
        // even though the producer stamped one in.
        assert_eq!(envelopes[0].site_id, None);
    }

    /// Regression: a producer must not be able to consume spool
    /// capacity or burn network bandwidth with an envelope the
    /// control plane will reject server-side. `submit` validates
    /// after enrichment and returns
    /// [`CommsError::EnvelopeInvalid`].
    #[tokio::test]
    async fn submit_rejects_envelope_with_empty_payload() {
        let enrichment = mk_enrichment();
        let client = TelemetryClient::new(TelemetryClientConfig::with_defaults(enrichment));
        let mut env = mk_envelope();
        env.payload.clear();

        let err = client
            .submit(env)
            .await
            .expect_err("empty payload must be rejected at the submit boundary");

        assert!(
            matches!(err, CommsError::EnvelopeInvalid(_)),
            "unexpected variant: {err:?}",
        );
        assert_eq!(err.code(), sng_core::error::ErrorCode::WireSchema);
        // Nothing reached the spool.
        assert_eq!(client.spool_stats().pushed, 0);
        // And nothing leaked into the pending builder either —
        // `force_seal` would otherwise drain it onto the spool.
        client.force_seal().await;
        assert_eq!(client.spool_stats().pushed, 0);
    }

    #[tokio::test]
    async fn submit_rejects_envelope_with_nil_event_id() {
        let enrichment = mk_enrichment();
        let client = TelemetryClient::new(TelemetryClientConfig::with_defaults(enrichment));
        let mut env = mk_envelope();
        env.event_id = EventId::nil();

        let err = client.submit(env).await.expect_err("nil event id rejected");
        assert!(matches!(err, CommsError::EnvelopeInvalid(_)));
        assert_eq!(err.code(), sng_core::error::ErrorCode::WireSchema);
        assert_eq!(client.spool_stats().pushed, 0);
    }

    #[tokio::test]
    async fn submit_rejects_envelope_with_zero_schema_version() {
        let enrichment = mk_enrichment();
        let client = TelemetryClient::new(TelemetryClientConfig::with_defaults(enrichment));
        let mut env = mk_envelope();
        env.schema_version = 0;

        let err = client
            .submit(env)
            .await
            .expect_err("zero schema version rejected");
        assert!(matches!(err, CommsError::EnvelopeInvalid(_)));
        assert_eq!(err.code(), sng_core::error::ErrorCode::WireSchema);
        assert_eq!(client.spool_stats().pushed, 0);
    }

    #[tokio::test]
    async fn submit_rejects_envelope_with_go_zero_timestamp() {
        let enrichment = mk_enrichment();
        let client = TelemetryClient::new(TelemetryClientConfig::with_defaults(enrichment));
        let mut env = mk_envelope();
        // Reconstruct Go's `time.Time{}` zero value on the wire:
        // exactly GO_ZERO_TIME_SECS seconds since the Unix epoch,
        // zero sub-second component.
        env.timestamp = chrono::Utc
            .timestamp_opt(GO_ZERO_TIME_SECS, 0)
            .single()
            .expect("Go zero timestamp must be representable");

        let err = client
            .submit(env)
            .await
            .expect_err("Go zero timestamp rejected");
        assert!(matches!(err, CommsError::EnvelopeInvalid(_)));
        assert_eq!(err.code(), sng_core::error::ErrorCode::WireSchema);
        assert_eq!(client.spool_stats().pushed, 0);
    }

    /// Enrichment must fix up nil tenant / device ids on the
    /// producer's behalf — a producer is allowed to leave those
    /// slots in their default state. Verify the post-enrichment
    /// validate doesn't trip on identifiers the enrichment
    /// pipeline has already stamped in.
    #[tokio::test]
    async fn submit_accepts_producer_nil_ids_after_enrichment() {
        let enrichment = mk_enrichment();
        let mut cfg = TelemetryClientConfig::with_defaults(enrichment.clone());
        cfg.batch = BatchConfig {
            max_events: 1,
            ..BatchConfig::default()
        };
        let client = TelemetryClient::new(cfg);
        let mut env = mk_envelope();
        env.tenant_id = TenantId::nil();
        env.device_id = DeviceId::nil();

        client
            .submit(env)
            .await
            .expect("enrichment fills in nil ids before validate");
        assert_eq!(client.spool_stats().pushed, 1);
    }

    /// Regression: concurrent `submit` calls that each trigger a
    /// batch seal must produce a spool whose entries come out in
    /// monotonic-sequence FIFO order. Without `seal_lock`, two
    /// submits on different runtime worker threads can interleave
    /// `next_seq` and `spool.push` such that the spool head is
    /// the higher-seq batch, and `flush_one` would ship batches
    /// out of monotonic order — the server would accept the
    /// higher seq first, lift its high-water mark, then reject
    /// the lower seq as a sequence regression.
    ///
    /// This test drives many concurrent submits on the
    /// multi-threaded runtime; the `max_events == 1` config
    /// forces every submit to seal independently, maximising the
    /// race window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_submits_seal_in_monotonic_spool_order() {
        let enrichment = mk_enrichment();
        let mut cfg = TelemetryClientConfig::with_defaults(enrichment);
        // Every submit seals → maximum race window.
        cfg.batch = BatchConfig {
            max_events: 1,
            ..BatchConfig::default()
        };
        cfg.spool_capacity = 256;

        let client = Arc::new(TelemetryClient::new(cfg));

        let mut handles = Vec::with_capacity(64);
        for _ in 0..64 {
            let c = client.clone();
            handles.push(tokio::spawn(async move {
                c.submit(mk_envelope()).await.expect("submit ok");
            }));
        }
        for h in handles {
            h.await.expect("task join");
        }

        assert_eq!(client.spool_stats().pushed, 64, "all submits sealed");

        // Drain the spool in head-to-tail order and verify the
        // sequence numbers are strictly monotonically increasing.
        // Without `seal_lock`, two concurrent seals can produce a
        // spool whose head has a higher seq than its tail.
        let mut last_seq: Option<u64> = None;
        let mut drained = 0usize;
        while let Some(entry) = client.spool.pop_front() {
            if let Some(prev) = last_seq {
                assert!(
                    entry.seq > prev,
                    "spool entries out of monotonic order: prev={prev}, curr={}",
                    entry.seq,
                );
            }
            last_seq = Some(entry.seq);
            drained += 1;
        }
        assert_eq!(drained, 64);
        // The first seq is the configured start (default 1) and
        // the last is start + N - 1.
        assert_eq!(last_seq, Some(64));
    }
}

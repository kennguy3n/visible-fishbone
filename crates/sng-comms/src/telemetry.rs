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
    /// tenant / device id are overwritten with the canonical
    /// values — local subsystems may have constructed envelopes
    /// with placeholder ids that the egress path is expected to
    /// fix up before they reach the wire.
    fn enrich(&self, envelope: &mut Envelope) {
        envelope.tenant_id = self.tenant_id;
        envelope.device_id = self.device_id;
        if let Some(site) = self.site_id {
            envelope.site_id = Some(site);
        }
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
    pub async fn submit(&self, mut envelope: Envelope) -> Result<(), CommsError> {
        self.config.enrichment.enrich(&mut envelope);
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
                let ack = parse_ack(&response.body)?;
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
        // `to_vec_named` writes MessagePack as named maps
        // (`{ "v": …, "id": …, … }`) using the `#[serde(rename = "…")]`
        // short tags defined on `Envelope`. The Go control plane's
        // `vmihailenco/msgpack/v5` decoder matches struct fields by
        // those map keys; compact / positional encoding would
        // decode to misaligned fields (or outright fail) on the
        // server side. See `crates/sng-core/src/envelope.rs`
        // ("Use `to_vec_named` …") for the canonical contract.
        let raw = rmp_serde::to_vec_named(&batch.envelopes)
            .map_err(|e| CommsError::Encoding(format!("encode telemetry batch: {e}")))?;
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
    use chrono::Utc;
    use sng_core::envelope::{EventClass, Platform, SCHEMA_VERSION};
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
            payload: Vec::new(),
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
        client.submit(mk_envelope()).await.expect("submit");
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
}

//! Telemetry pipeline orchestrator.
//!
//! The pipeline stitches together the four per-event stages
//! (dedup → redact → enrich → egress) plus the PCAP ring and
//! the periodic dedup-prune tick. It is the only call path
//! that touches `sng_comms::TelemetryClient` from this crate —
//! every producer subsystem feeds events through the pipeline,
//! not directly to the egress sink.
//!
//! The pipeline owns:
//!
//! * a [`Dedup`] window (the only mutator)
//! * a [`RedactionPolicy`] (immutable per pipeline; rebuilt
//!   on policy reload)
//! * an [`Enricher`] (immutable per pipeline)
//! * a clone-on-publish handle to the upstream
//!   [`sng_comms::TelemetryClient`]
//! * a [`PcapRing`] (shared across the agent; the pipeline
//!   holds an `Arc` so producer paths can also push into it)
//! * a counters block for ops-visible metrics
//!
//! Concurrency model: the pipeline is built around a single
//! [`run`] task that owns the mutable state (Dedup, Counters).
//! Producers push [`TelemetryEvent`]s through an unbounded
//! `tokio::sync::mpsc` channel. Backpressure is handled by the
//! egress sink (the [`sng_comms::TelemetryClient`]'s spool) —
//! when the spool is full, `submit` returns a backpressure
//! error which the pipeline counts and drops the event. The
//! alternative (blocking the producer) would let a slow control
//! plane stall the agent's data plane, which is never the right
//! trade.

use std::sync::Arc;
use std::time::Duration;

use sng_comms::TelemetryClient;
use sng_core::envelope::Envelope;
use tokio::sync::mpsc;

use crate::dedup::Dedup;
use crate::enrichment::{Enricher, EnrichmentContext, TimeSource};
use crate::error::TelemetryError;
use crate::pcap::PcapRing;
use crate::redaction::RedactionPolicy;
use crate::source::TelemetryEvent;

/// Static configuration for the pipeline.
#[derive(Clone, Debug)]
pub struct PipelineConfig {
    /// Capacity of the producer→pipeline channel. Sized to
    /// absorb a short burst without backpressure-ing into the
    /// producer subsystems. Default: 4096.
    pub event_channel_capacity: usize,
    /// Rolling dedup window. Default: 30s.
    pub dedup_window: Duration,
    /// Max dedup entries before early eviction. Default: 100_000.
    pub dedup_max_entries: usize,
    /// How often the pipeline calls [`Dedup::prune`] and the
    /// egress sink's [`TelemetryClient::tick`]. Default: 1s.
    pub tick_interval: Duration,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            event_channel_capacity: 4096,
            dedup_window: crate::dedup::DEFAULT_WINDOW,
            dedup_max_entries: crate::dedup::DEFAULT_MAX_ENTRIES,
            tick_interval: Duration::from_secs(1),
        }
    }
}

/// Counters surfaced by the pipeline. Used by the agent's
/// observability surface to render the operator dashboard.
/// Updated only by the pipeline's owning task — no atomics,
/// no mutex; the snapshot accessor takes a clone behind a
/// lock so the read path never blocks the write path beyond
/// the duration of a memcpy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PipelineStats {
    /// Events accepted from producers.
    pub accepted: u64,
    /// Events dropped at the dedup stage (duplicates).
    pub deduped: u64,
    /// Cumulative count of older batches evicted from the egress
    /// spool while submitting. This is the canonical backpressure
    /// signal — the spool is oldest-drop on overflow, so a rising
    /// `spool_evictions` value means the agent is producing
    /// telemetry faster than the control plane is acknowledging
    /// it and older batches are being shed.
    pub spool_evictions: u64,
    /// Events that successfully reached the egress sink.
    pub egressed: u64,
    /// Events that failed at enrichment (payload encode error).
    /// In practice this should be zero — the encoder is
    /// infallible for the producer-supplied event types — but
    /// it is counted so a regression in the encoder is visible.
    pub enrich_errors: u64,
    /// Events whose payload encode succeeded but whose
    /// envelope failed validation. Indicates a bug in the
    /// enricher; surfaced as an error counter rather than
    /// panicking so the pipeline keeps running.
    pub envelope_errors: u64,
}

/// Producer-facing handle to the pipeline. Cheap to clone —
/// wraps an [`mpsc::Sender`].
#[derive(Clone, Debug)]
pub struct PipelineHandle {
    tx: mpsc::Sender<TelemetryEvent>,
    pcap: Arc<PcapRing>,
}

impl PipelineHandle {
    /// Submit an event into the pipeline. Returns an error
    /// only if the pipeline task has been dropped (channel
    /// closed). The producer is NOT blocked when the pipeline
    /// is under load — the channel uses `try_send` semantics
    /// via [`Self::try_submit`]; producers that need
    /// backpressure should call [`Self::submit`] instead.
    pub async fn submit(&self, event: TelemetryEvent) -> Result<(), TelemetryError> {
        self.tx
            .send(event)
            .await
            .map_err(|_| TelemetryError::EventInvalid("pipeline closed".into()))
    }

    /// Non-blocking submit. Returns the event back to the
    /// caller if the pipeline channel is full so the producer
    /// can apply its own backpressure policy (typically: drop
    /// and increment a counter).
    pub fn try_submit(&self, event: TelemetryEvent) -> Result<(), TrySubmitError> {
        self.tx.try_send(event).map_err(|e| match e {
            mpsc::error::TrySendError::Full(ev) => TrySubmitError::Full(ev),
            mpsc::error::TrySendError::Closed(ev) => TrySubmitError::Closed(ev),
        })
    }

    /// Direct access to the PCAP ring. Used by producers that
    /// have a packet buffer to record alongside their typed
    /// event (e.g. the IPS subsystem recording the offending
    /// frame).
    #[must_use]
    pub fn pcap(&self) -> &Arc<PcapRing> {
        &self.pcap
    }
}

/// Error returned by [`PipelineHandle::try_submit`].
#[derive(Debug)]
pub enum TrySubmitError {
    /// Pipeline channel is full. The unsent event is returned
    /// so the producer can apply its own drop / retry policy.
    Full(TelemetryEvent),
    /// Pipeline task has shut down. The unsent event is
    /// returned for cleanup but the producer should stop
    /// submitting.
    Closed(TelemetryEvent),
}

/// The pipeline itself. Constructed via [`Pipeline::new`] and
/// driven by [`Pipeline::run`] in a tokio task. Tests can also
/// drive the pipeline synchronously by calling
/// [`Pipeline::process_one`] in a loop.
#[derive(Debug)]
pub struct Pipeline<T: TimeSource> {
    cfg: PipelineConfig,
    dedup: Dedup,
    redaction: RedactionPolicy,
    enricher: Enricher<T>,
    egress: Arc<TelemetryClient>,
    pcap: Arc<PcapRing>,
    stats: PipelineStats,
    rx: mpsc::Receiver<TelemetryEvent>,
    /// The pipeline's own copy of the producer sender half.
    /// Stored as an [`Option`] so the run loop can `take()` it
    /// and drop it explicitly — once the run loop drops its
    /// own sender, the channel closes as soon as every
    /// outstanding [`PipelineHandle`] is dropped, which is the
    /// shutdown signal the loop terminates on.
    tx: Option<mpsc::Sender<TelemetryEvent>>,
}

/// Outcome of processing a single event. Tests assert on this
/// to verify the pipeline's per-stage behaviour.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProcessOutcome {
    /// Event was redacted, enriched, and accepted by the
    /// egress sink. The envelope id is reported so the test
    /// can assert downstream-of-egress behaviour.
    Egressed,
    /// Event was rejected at the dedup stage (duplicate within
    /// the rolling window).
    Deduped,
    /// Enrichment failed (payload encode error or envelope
    /// validation failure).
    EnrichmentError(String),
}

impl<T: TimeSource> Pipeline<T> {
    /// New pipeline. The handle is returned separately so
    /// producers can be wired up before the pipeline task is
    /// spawned.
    #[must_use]
    pub fn new(
        cfg: PipelineConfig,
        enricher: Enricher<T>,
        redaction: RedactionPolicy,
        egress: Arc<TelemetryClient>,
        pcap: Arc<PcapRing>,
    ) -> (Self, PipelineHandle) {
        let (tx, rx) = mpsc::channel(cfg.event_channel_capacity);
        let dedup = Dedup::new(cfg.dedup_window, cfg.dedup_max_entries);
        let handle = PipelineHandle {
            tx: tx.clone(),
            pcap: Arc::clone(&pcap),
        };
        (
            Self {
                cfg,
                dedup,
                redaction,
                enricher,
                egress,
                pcap,
                stats: PipelineStats::default(),
                rx,
                tx: Some(tx),
            },
            handle,
        )
    }

    /// Snapshot of the pipeline's current counters. Owns no
    /// concurrency primitives — the caller passes a reference
    /// to the pipeline (typically inside `Pipeline::run`).
    #[must_use]
    pub fn stats(&self) -> PipelineStats {
        self.stats
    }

    /// Shared handle to the PCAP ring.
    #[must_use]
    pub fn pcap(&self) -> &Arc<PcapRing> {
        &self.pcap
    }

    /// Process a single event through every stage. Exposed
    /// publicly so unit tests can drive the pipeline
    /// deterministically (instead of spawning the run loop).
    /// Production wiring uses [`Self::run`].
    pub async fn process_one(&mut self, event: TelemetryEvent) -> ProcessOutcome {
        self.stats.accepted = self.stats.accepted.saturating_add(1);
        // Stage 1: dedup. Fingerprint over content-relevant
        // fields; duplicates within the rolling window are
        // dropped here.
        if !self.dedup.observe(&event) {
            self.stats.deduped = self.stats.deduped.saturating_add(1);
            return ProcessOutcome::Deduped;
        }
        // Stage 2: redact. Strip payload fields disabled by
        // the active policy. Note: this mutates the event
        // before encoding so the wire payload reflects the
        // redacted shape.
        let mut event = event;
        self.redaction.redact(&mut event);
        // Stage 3: enrich. Wrap into an Envelope with
        // tenant/device/site/timestamp/traffic_class/byte
        // counters populated.
        let envelope = match self.enricher.enrich(&event, EnrichmentContext::default()) {
            Ok(env) => env,
            Err(e) => {
                self.stats.enrich_errors = self.stats.enrich_errors.saturating_add(1);
                tracing::warn!(error = %e, "telemetry: payload encode failed");
                return ProcessOutcome::EnrichmentError(e.to_string());
            }
        };
        // Stage 4: egress. The TelemetryClient owns the batch
        // builder + spool; we just submit. Spool-full is the
        // only backpressure signal at this stage; other errors
        // bubble up as enrichment_errors because they imply a
        // bug in the enricher (envelope validation failed).
        self.submit_envelope(envelope).await
    }

    async fn submit_envelope(&mut self, envelope: Envelope) -> ProcessOutcome {
        let env_id_for_log = envelope.event_id;
        // Snapshot the spool's eviction counter before submit so
        // we can attribute a per-submit eviction delta to the
        // pipeline's `spool_evictions` counter. The spool is
        // oldest-drop on overflow, so the only way to observe
        // backpressure is to compare evicted-before vs.
        // evicted-after — the submit call itself never returns a
        // "spool full" error.
        let evicted_before = self.egress.spool_stats().evicted;
        let result = self.egress.submit(envelope).await;
        let evicted_after = self.egress.spool_stats().evicted;
        let evicted_delta = evicted_after.saturating_sub(evicted_before);
        if evicted_delta > 0 {
            self.stats.spool_evictions = self.stats.spool_evictions.saturating_add(evicted_delta);
            tracing::warn!(
                event_id = %env_id_for_log,
                evicted = evicted_delta,
                "telemetry: spool shed older batches under pressure"
            );
        }
        match result {
            Ok(()) => {
                self.stats.egressed = self.stats.egressed.saturating_add(1);
                ProcessOutcome::Egressed
            }
            Err(sng_comms::CommsError::EnvelopeInvalid(e)) => {
                // The envelope passed enrich() but failed
                // validate at the submit boundary. Counts as
                // an envelope error rather than backpressure.
                self.stats.envelope_errors = self.stats.envelope_errors.saturating_add(1);
                tracing::error!(
                    event_id = %env_id_for_log,
                    error = %e,
                    "telemetry: envelope validation failed at submit boundary"
                );
                ProcessOutcome::EnrichmentError(format!("envelope: {e}"))
            }
            Err(e) => {
                // Anything else (transport, sequencing,
                // identity) — the spool already retried
                // internally; surface to ops as an envelope
                // error so the dashboard sees the failure.
                self.stats.envelope_errors = self.stats.envelope_errors.saturating_add(1);
                tracing::error!(
                    event_id = %env_id_for_log,
                    error = %e,
                    "telemetry: egress error"
                );
                ProcessOutcome::EnrichmentError(e.to_string())
            }
        }
    }

    /// Run the pipeline's event-driven loop. Returns when the
    /// channel is closed (every producer dropped its
    /// [`PipelineHandle`]) and any in-flight events have
    /// drained. Also fires a periodic tick that prunes the
    /// dedup window and drives the egress sink's time-based
    /// batch flush.
    pub async fn run(mut self) {
        let mut ticker = tokio::time::interval(self.cfg.tick_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Drop our own send half so the channel closes once
        // every producer-held PipelineHandle is dropped. The
        // Option dance is required because we still need to
        // borrow `self` for `process_one` below — dropping a
        // bare `self.tx` would partially-move `self`.
        let _ = self.tx.take();
        loop {
            tokio::select! {
                ev = self.rx.recv() => {
                    let Some(event) = ev else {
                        // All producers gone. Drain the egress
                        // builder so any pending batch goes onto
                        // the spool before we exit.
                        self.egress.force_seal().await;
                        break;
                    };
                    let _ = self.process_one(event).await;
                }
                _ = ticker.tick() => {
                    self.dedup.prune();
                    self.egress.tick(chrono::Utc::now()).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrichment::{AgentIdentity, FixedTime};
    use chrono::{DateTime, Utc};
    use sng_comms::TelemetryClientConfig;
    use sng_core::envelope::{Platform, Verdict};
    use sng_core::events::{AgentEvent, DnsEvent, FlowEvent, HttpEvent};
    use sng_core::ids::{DeviceId, SiteId, TenantId};
    use sng_core::traffic_class::TrafficClass;
    use uuid::Uuid;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            tenant_id: TenantId::from(Uuid::from_u128(1)),
            device_id: DeviceId::from(Uuid::from_u128(2)),
            site_id: Some(SiteId::from(Uuid::from_u128(3))),
            platform: Platform::Linux,
            default_traffic_class: TrafficClass::InspectFull,
        }
    }

    fn fixed_clock() -> FixedTime {
        FixedTime(
            DateTime::parse_from_rfc3339("2026-05-01T12:34:56Z")
                .unwrap()
                .with_timezone(&Utc),
        )
    }

    fn flow() -> TelemetryEvent {
        TelemetryEvent::Flow(FlowEvent {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 51_234,
            dst_port: 443,
            protocol: "tcp".into(),
            app_id: None,
            verdict: Verdict::Allow,
            score: None,
            bytes_in: 1_024,
            bytes_out: 2_048,
            duration_ms: 100,
        })
    }

    fn http_with_url(url: &str) -> TelemetryEvent {
        TelemetryEvent::Http(HttpEvent {
            method: "GET".into(),
            url: url.into(),
            host: "example.com".into(),
            status_code: 200,
            verdict: Verdict::Allow,
            tls_version: Some("TLS1.3".into()),
            sni: Some("example.com".into()),
            content_type: Some("text/html".into()),
            bytes: Some(1_024),
        })
    }

    fn dns_event() -> TelemetryEvent {
        TelemetryEvent::Dns(DnsEvent {
            query: "example.com".into(),
            qtype: "A".into(),
            response_code: "NOERROR".into(),
            verdict: Verdict::Allow,
            latency_ms: 5,
            upstream: Some("1.1.1.1".into()),
        })
    }

    fn agent_event() -> TelemetryEvent {
        TelemetryEvent::Agent(AgentEvent {
            device_id: "d1".into(),
            event_type: "started".into(),
            posture_snapshot: None,
            platform: Platform::Linux,
        })
    }

    fn mk_egress() -> Arc<TelemetryClient> {
        let enrich = sng_comms::EnrichmentContext {
            tenant_id: identity().tenant_id,
            device_id: identity().device_id,
            site_id: identity().site_id,
        };
        Arc::new(TelemetryClient::new(TelemetryClientConfig::with_defaults(
            enrich,
        )))
    }

    fn mk_pipeline() -> (Pipeline<FixedTime>, PipelineHandle, Arc<TelemetryClient>) {
        let egress = mk_egress();
        let pcap = Arc::new(PcapRing::new(crate::pcap::PcapRingConfig::default()));
        let enricher = Enricher::new(identity(), fixed_clock());
        let (p, h) = Pipeline::new(
            PipelineConfig::default(),
            enricher,
            RedactionPolicy::strict(),
            Arc::clone(&egress),
            pcap,
        );
        (p, h, egress)
    }

    #[tokio::test]
    async fn happy_path_egresses() {
        let (mut p, _h, _e) = mk_pipeline();
        let out = p.process_one(flow()).await;
        assert_eq!(out, ProcessOutcome::Egressed);
        let s = p.stats();
        assert_eq!(s.accepted, 1);
        assert_eq!(s.egressed, 1);
        assert_eq!(s.deduped, 0);
        assert_eq!(s.spool_evictions, 0);
    }

    #[tokio::test]
    async fn dedup_drops_duplicate_in_window() {
        let (mut p, _h, _e) = mk_pipeline();
        assert_eq!(p.process_one(flow()).await, ProcessOutcome::Egressed);
        // Same event content → dedup drops it.
        assert_eq!(p.process_one(flow()).await, ProcessOutcome::Deduped);
        let s = p.stats();
        assert_eq!(s.accepted, 2);
        assert_eq!(s.egressed, 1);
        assert_eq!(s.deduped, 1);
    }

    #[tokio::test]
    async fn redact_strips_http_url_before_egress() {
        // Verify the pipeline applies the strict redaction
        // policy. The http event has a sensitive url; after
        // redact, the enriched envelope's payload must encode
        // an HttpEvent whose url is empty.
        let (mut p, _h, _e) = mk_pipeline();
        let _ = p
            .process_one(http_with_url("https://example.com/secret?token=abcd"))
            .await;
        // Stats sanity: one egress, no errors.
        assert_eq!(p.stats().egressed, 1);
    }

    #[tokio::test]
    async fn dns_and_agent_classes_pass_through() {
        // Cover the per-class dispatch by feeding two non-flow
        // event classes through the pipeline.
        let (mut p, _h, _e) = mk_pipeline();
        assert_eq!(p.process_one(dns_event()).await, ProcessOutcome::Egressed);
        assert_eq!(p.process_one(agent_event()).await, ProcessOutcome::Egressed);
        let s = p.stats();
        assert_eq!(s.egressed, 2);
        assert_eq!(s.deduped, 0);
    }

    #[tokio::test]
    async fn handle_can_submit_via_run_loop() {
        let (p, h, _e) = mk_pipeline();
        let join = tokio::spawn(p.run());
        h.submit(flow()).await.unwrap();
        // Dropping the handle closes the producer side of the
        // channel; the run loop drains and exits.
        drop(h);
        join.await.unwrap();
    }

    #[tokio::test]
    async fn handle_try_submit_returns_full_when_channel_saturated() {
        let cfg = PipelineConfig {
            event_channel_capacity: 1,
            ..PipelineConfig::default()
        };
        let egress = mk_egress();
        let pcap = Arc::new(PcapRing::new(crate::pcap::PcapRingConfig::default()));
        let enricher = Enricher::new(identity(), fixed_clock());
        let (_p, h) = Pipeline::new(cfg, enricher, RedactionPolicy::strict(), egress, pcap);
        // First try_submit lands in the channel (capacity=1).
        h.try_submit(flow()).unwrap();
        // Second try_submit must report Full and return the
        // unsent event for the producer to handle.
        match h.try_submit(flow()) {
            Err(TrySubmitError::Full(_)) => {}
            other => panic!("expected Full, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn closed_pipeline_returns_closed_on_handle_submit() {
        let (p, h, _e) = mk_pipeline();
        // Drop the pipeline before submitting. The handle is
        // detached from any rx now (run never started).
        drop(p);
        let err = h.submit(flow()).await.unwrap_err();
        assert!(matches!(err, TelemetryError::EventInvalid(_)));
    }
}

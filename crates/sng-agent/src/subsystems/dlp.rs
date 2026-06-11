// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Endpoint DLP subsystem.
//!
//! Drives the `sng-dlp` content-inspection engine over the set of
//! `sng-pal` [`sng_dlp::ChannelInterceptor`] backends (clipboard,
//! file-write, USB / removable media, print, browser upload). For
//! each [`sng_dlp::ContentEvent`] a backend surfaces, the subsystem:
//!
//! 1. Classifies it against the live [`sng_dlp::DlpEngine`] policy.
//! 2. Reports the resulting [`sng_dlp::DlpVerdict`] to a
//!    [`DlpVerdictSink`] — the telemetry seam. The default
//!    [`TracingDlpSink`] emits a structured `tracing` event that the
//!    agent's telemetry/log pipeline scrapes onto the
//!    `sng.<tenant>.telemetry.dlp` stream.
//! 3. Updates the per-action counters surfaced through the health
//!    probe.
//!
//! # Redaction invariant
//!
//! The subsystem only ever touches a [`sng_dlp::ContentEvent`]'s raw
//! bytes for the duration of the synchronous `evaluate_event` call.
//! The verdict it reports carries metadata only (matched rule id,
//! severity, action, match spans) — never the matched bytes — so a
//! reported verdict can never leak the sensitive content that
//! produced it.
//!
//! # Concurrency
//!
//! Each channel interceptor gets its own worker task: the OS hooks
//! are independent edge-triggered (or polling) sources, so draining
//! them on one shared loop would let a quiet channel's
//! internally-awaiting `next_event` starve a busy one. Every worker
//! co-operates with the supervisor's drain by selecting on the
//! shared [`ShutdownSignal`]; the coordinator task returned to the
//! supervisor joins them on shutdown.
//!
//! # Graceful degradation
//!
//! A backend whose OS API is unavailable in this build/environment
//! returns [`sng_dlp::ChannelError::Unavailable`] (or `Init`) from
//! its first `next_event`; the worker logs it once and exits,
//! leaving the other channels running. This is why the portable
//! polling watchers (which always succeed) and the native
//! edge-triggered hooks can be mixed in one interceptor set.

use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_dlp::{ChannelError, ChannelInterceptor, DlpEngine, DlpVerdict};
use sng_telemetry::{PipelineHandle, TelemetryEvent, TrySubmitError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::task;

/// A consumer of DLP verdicts — the reporting seam between the
/// inspection engine and the telemetry pipeline.
///
/// Implementations MUST honour the crate-wide redaction invariant:
/// a [`DlpVerdict`] carries metadata only, and a sink must not
/// attempt to recover or persist raw content (there is none to
/// recover — the bytes are already gone by the time a verdict
/// exists).
pub trait DlpVerdictSink: Send + Sync {
    /// Report a verdict. Called once per inspected content event,
    /// including `Allow` so a sink that wants a full audit trail
    /// sees every event; sinks that only care about enforcing
    /// verdicts can filter on [`DlpVerdict::is_silent_allow`].
    fn report(&self, verdict: &DlpVerdict);
}

/// Default sink: emit a structured `tracing` event carrying the
/// verdict metadata. The agent's telemetry pipeline lifts these
/// onto the `sng.<tenant>.telemetry.dlp` subject. Silent `Allow`
/// verdicts are dropped (no rule matched — nothing to report); the
/// enforcing verdicts are logged at a level matching their action.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingDlpSink;

impl DlpVerdictSink for TracingDlpSink {
    fn report(&self, verdict: &DlpVerdict) {
        let Some(details) = verdict.details() else {
            // `Allow` with no match: nothing to report.
            return;
        };
        let rule_ids: Vec<&str> = details.matches.iter().map(|m| m.rule_id.as_str()).collect();
        // Block is operator-actionable (the transfer was refused);
        // warn/log are informational.
        if verdict.is_blocking() {
            tracing::warn!(
                target: "sng_agent::dlp",
                channel = details.channel.as_str(),
                action = ?details.action,
                severity = ?details.severity,
                rules = ?rule_ids,
                "DLP blocked an egress transfer"
            );
        } else {
            tracing::info!(
                target: "sng_agent::dlp",
                channel = details.channel.as_str(),
                action = ?details.action,
                severity = ?details.severity,
                rules = ?rule_ids,
                "DLP matched an egress transfer"
            );
        }
    }
}

/// Atomic counters surfaced through the health endpoint.
#[derive(Debug, Default)]
pub struct DlpStats {
    /// Content events inspected across every channel.
    pub events_observed: AtomicU64,
    /// Verdicts that permitted the transfer with no match
    /// (`Allow`).
    pub verdict_allow: AtomicU64,
    /// Verdicts at `log` strength (`LogOnly`).
    pub verdict_log: AtomicU64,
    /// Verdicts at `warn` strength (`WarnUser`).
    pub verdict_warn: AtomicU64,
    /// Verdicts at `block` strength (`Block`).
    pub verdict_block: AtomicU64,
    /// Channel workers that exited because their backend reported
    /// an error (unavailable / init failure / closed).
    pub channels_stopped: AtomicU64,
    /// Flagged AI-app upload signals projected onto the telemetry
    /// pipeline as a [`TelemetryEvent::Dlp`] for the control-plane
    /// review queue. A subset of `verdict_warn` + `verdict_block`
    /// (only the AI-app upload channel produces a signal).
    pub dlp_signals_emitted: AtomicU64,
    /// Flagged signals dropped because the telemetry pipeline was
    /// full (backpressure). The verdict was still enforced at the
    /// edge; only the review-queue record was shed.
    pub dlp_signal_drops_full: AtomicU64,
    /// Flagged signals dropped because the telemetry pipeline had
    /// shut down.
    pub dlp_signal_drops_closed: AtomicU64,
}

/// Endpoint DLP subsystem.
pub struct DlpSubsystem {
    engine: Arc<DlpEngine>,
    interceptors: Vec<Arc<dyn ChannelInterceptor>>,
    sink: Arc<dyn DlpVerdictSink>,
    /// Telemetry pipeline handle. A flagged AI-app upload is
    /// projected onto it as a redacted [`TelemetryEvent::Dlp`] so the
    /// control plane can route it into the human-in-the-loop review
    /// queue — the producer half of that queue. Shares the same
    /// pipeline (dedup / redaction / batch) as every other class.
    telemetry: PipelineHandle,
    stats: Arc<DlpStats>,
    idle_sleep: Duration,
}

impl std::fmt::Debug for DlpSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DlpSubsystem")
            .field("interceptors", &self.interceptors.len())
            .field("idle_sleep", &self.idle_sleep)
            .finish_non_exhaustive()
    }
}

impl DlpSubsystem {
    /// Build from an engine, the channel interceptors to drive, and
    /// the verdict sink. `idle_sleep` bounds the backoff applied
    /// when a channel reports a clean close.
    #[must_use]
    pub fn new(
        engine: Arc<DlpEngine>,
        interceptors: Vec<Arc<dyn ChannelInterceptor>>,
        sink: Arc<dyn DlpVerdictSink>,
        telemetry: PipelineHandle,
        idle_sleep: Duration,
    ) -> Self {
        Self {
            engine,
            interceptors,
            telemetry,
            sink,
            stats: Arc::new(DlpStats::default()),
            idle_sleep,
        }
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<DlpStats> {
        &self.stats
    }

    /// The engine, exposed so the bundle-delivery path can hot-swap
    /// the DLP policy via [`DlpEngine::install`].
    #[must_use]
    pub fn engine(&self) -> &Arc<DlpEngine> {
        &self.engine
    }
}

/// Drive a single channel interceptor to completion: classify each
/// event, report the verdict, and update stats. Returns when the
/// shutdown signal fires or the backend reports a terminal error.
async fn run_channel_worker(
    interceptor: Arc<dyn ChannelInterceptor>,
    engine: Arc<DlpEngine>,
    sink: Arc<dyn DlpVerdictSink>,
    telemetry: PipelineHandle,
    stats: Arc<DlpStats>,
    shutdown: ShutdownSignal,
    idle_sleep: Duration,
) {
    let channel = interceptor.channel();
    loop {
        // Cancellation safety: when the shutdown branch wins, the
        // `next_event()` future is dropped mid-poll. This is safe
        // because the `ChannelInterceptor` contract is that an event
        // is only removed from the backend's source at the point it
        // is returned — every in-tree impl pops then returns with no
        // intervening await, so the sole await point (an empty-buffer
        // backoff sleep) holds no event. Dropping there loses nothing;
        // the event is still queued for the next `next_event()` call,
        // and on shutdown we are tearing the worker down regardless.
        tokio::select! {
            () = shutdown.wait() => break,
            next = interceptor.next_event() => match next {
                Ok(Some(event)) => {
                    stats.events_observed.fetch_add(1, Ordering::Relaxed);
                    let (verdict, signal) = engine.evaluate_event_with_signal(&event);
                    match &verdict {
                        DlpVerdict::Allow => {
                            stats.verdict_allow.fetch_add(1, Ordering::Relaxed);
                        }
                        DlpVerdict::LogOnly(_) => {
                            stats.verdict_log.fetch_add(1, Ordering::Relaxed);
                        }
                        DlpVerdict::WarnUser(_) => {
                            stats.verdict_warn.fetch_add(1, Ordering::Relaxed);
                        }
                        DlpVerdict::Block(_) => {
                            stats.verdict_block.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    sink.report(&verdict);

                    // A flagged AI-app upload (coach-first: an action
                    // above Monitor, or any finding) is the producer
                    // half of the control-plane review queue. Project
                    // the redacted signal onto the telemetry pipeline;
                    // it is metadata-only by construction (label/count
                    // summaries, never matched bytes). Enforcement
                    // already happened above via the verdict — a full
                    // or closed pipeline only sheds the review-queue
                    // record, never the edge decision.
                    if let Some(signal) = signal {
                        match telemetry.try_submit(TelemetryEvent::Dlp(signal.to_wire_event())) {
                            Ok(()) => {
                                stats.dlp_signals_emitted.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySubmitError::Full(_)) => {
                                stats.dlp_signal_drops_full.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(TrySubmitError::Closed(_)) => {
                                stats.dlp_signal_drops_closed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(None) => {
                    // Backend closed its source cleanly. Nothing more
                    // will arrive; stop polling this channel.
                    stats.channels_stopped.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        target: "sng_agent::dlp",
                        channel = channel.as_str(),
                        "DLP channel closed cleanly; worker exiting"
                    );
                    break;
                }
                Err(err) => {
                    // Every ChannelError variant is terminal for
                    // this backend (unavailable on this OS/build,
                    // init failure, or permanent close). Record it,
                    // log once, and exit the worker so the rest of
                    // the channels keep running (graceful
                    // degradation). The idle_sleep guards the
                    // pathological case where a future backend
                    // returns a transient error in a tight loop.
                    stats.channels_stopped.fetch_add(1, Ordering::Relaxed);
                    match err {
                        ChannelError::Unavailable(reason) => tracing::info!(
                            target: "sng_agent::dlp",
                            channel = channel.as_str(),
                            %reason,
                            "DLP channel backend unavailable on this host; skipping"
                        ),
                        other => tracing::warn!(
                            target: "sng_agent::dlp",
                            channel = channel.as_str(),
                            error = %other,
                            "DLP channel backend failed; worker exiting"
                        ),
                    }
                    tokio::time::sleep(idle_sleep).await;
                    break;
                }
            }
        }
    }
}

#[async_trait]
impl Subsystem for DlpSubsystem {
    fn name(&self) -> &'static str {
        "dlp"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let interceptors = self.interceptors.clone();
        let engine = Arc::clone(&self.engine);
        let sink = Arc::clone(&self.sink);
        let telemetry = self.telemetry.clone();
        let stats = Arc::clone(&self.stats);
        let idle_sleep = self.idle_sleep;

        Ok(task::spawn(async move {
            let mut workers = Vec::with_capacity(interceptors.len());
            for interceptor in interceptors {
                workers.push(task::spawn(run_channel_worker(
                    interceptor,
                    Arc::clone(&engine),
                    Arc::clone(&sink),
                    telemetry.clone(),
                    Arc::clone(&stats),
                    shutdown.clone(),
                    idle_sleep,
                )));
            }
            // Wait for shutdown, then join the per-channel workers so
            // the subsystem's drain doesn't return until every worker
            // has observed the signal and unwound.
            shutdown.wait().await;
            for worker in workers {
                let _ = worker.await;
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for DlpSubsystem {
    fn name(&self) -> &'static str {
        "dlp"
    }

    async fn check(&self) -> SubsystemHealth {
        let observed = self.stats.events_observed.load(Ordering::Relaxed);
        let allow = self.stats.verdict_allow.load(Ordering::Relaxed);
        let log = self.stats.verdict_log.load(Ordering::Relaxed);
        let warn = self.stats.verdict_warn.load(Ordering::Relaxed);
        let block = self.stats.verdict_block.load(Ordering::Relaxed);
        let stopped = self.stats.channels_stopped.load(Ordering::Relaxed);
        let total = self.interceptors.len() as u64;

        // Every channel stopping (e.g. all backends unavailable on a
        // headless host) is Degraded, not Down: the subsystem is
        // alive and would pick up events if a backend recovered, and
        // an endpoint with no DLP-relevant channels is a valid
        // deployment. Down is reserved for an unrecoverable state,
        // which this subsystem never enters on its own.
        let status = if total > 0 && stopped >= total {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "channels={total}, observed={observed}, allow={allow}, log={log}, \
                 warn={warn}, block={block}, stopped={stopped}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_dlp::{
        AiAppExfilDetector, AiAppPolicy, ChannelConfig, ContentEvent, ContentMetadata, DlpChannel,
        DlpPolicy, DlpRule, InMemoryInterceptor, PatternType, RuleAction, Severity,
    };
    use std::sync::Mutex;

    /// A live telemetry pipeline + handle for worker tests. Mirrors
    /// the `pal_posture` fixture: the egress client has no NATS
    /// connection, so submitted events drain harmlessly, but the
    /// handle's `try_submit` succeeds — which is all the DLP worker
    /// observes.
    fn test_pipeline_handle() -> (
        sng_telemetry::Pipeline<sng_telemetry::SystemTime>,
        PipelineHandle,
    ) {
        use sng_comms::{TelemetryClient, TelemetryClientConfig};
        use sng_core::envelope::Platform;
        use sng_core::ids::{DeviceId, TenantId};
        use sng_telemetry::{
            AgentIdentity, Enricher, PcapRing, PcapRingConfig, Pipeline, PipelineConfig,
            RedactionPolicy, SystemTime,
        };
        use uuid::Uuid;
        let identity = AgentIdentity::new(
            TenantId::from_uuid(Uuid::from_u128(1)),
            DeviceId::from_uuid(Uuid::from_u128(2)),
            None,
            Platform::Linux,
        );
        let enricher = Enricher::new(identity.clone(), SystemTime);
        let egress = Arc::new(TelemetryClient::new(TelemetryClientConfig::with_defaults(
            identity.to_comms_enrichment_context(),
        )));
        let pcap = Arc::new(PcapRing::new(PcapRingConfig {
            max_packets: 1,
            max_total_bytes: 1024,
            max_packet_bytes: 1024,
        }));
        Pipeline::new(
            PipelineConfig::default(),
            enricher,
            RedactionPolicy::strict(),
            egress,
            pcap,
        )
        .expect("pipeline")
    }

    /// A recording sink for assertions.
    #[derive(Default)]
    struct RecordingSink {
        verdicts: Mutex<Vec<DlpVerdict>>,
    }

    impl DlpVerdictSink for RecordingSink {
        fn report(&self, verdict: &DlpVerdict) {
            self.verdicts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(verdict.clone());
        }
    }

    fn engine_blocking_token() -> Arc<DlpEngine> {
        // A single block rule on a literal keyword so the test is
        // deterministic and doesn't depend on a builtin pattern.
        let rule = DlpRule {
            id: "secret-token".to_owned(),
            name: "test secret token".to_owned(),
            pattern_type: PatternType::Keyword,
            pattern_data: "TOPSECRET".to_owned(),
            severity: Severity::High,
            action: RuleAction::Block,
            channels: Vec::new(),
        };
        let mut channels = std::collections::BTreeMap::new();
        channels.insert(DlpChannel::FileWrite, ChannelConfig::default());
        let policy = DlpPolicy {
            rules: vec![rule],
            channels,
            ..DlpPolicy::default()
        };
        Arc::new(DlpEngine::new(policy).expect("engine"))
    }

    #[tokio::test(flavor = "current_thread")]
    async fn classifies_and_reports_block_then_allow() {
        let engine = engine_blocking_token();
        let sink = Arc::new(RecordingSink::default());
        let interceptor = InMemoryInterceptor::new(DlpChannel::FileWrite);
        // One matching event (blocks) and one clean event (allows).
        interceptor.push(ContentEvent::new(
            DlpChannel::FileWrite,
            b"this contains TOPSECRET data".to_vec(),
        ));
        interceptor.push(ContentEvent::new(
            DlpChannel::FileWrite,
            b"nothing sensitive here".to_vec(),
        ));

        let verdict_a = engine.evaluate_event(&ContentEvent::new(
            DlpChannel::FileWrite,
            b"this contains TOPSECRET data".to_vec(),
        ));
        assert!(verdict_a.is_blocking(), "expected block verdict");
        let verdict_b = engine.evaluate_event(&ContentEvent::new(
            DlpChannel::FileWrite,
            b"nothing sensitive here".to_vec(),
        ));
        assert!(matches!(verdict_b, DlpVerdict::Allow));

        // Exercise the sink directly with the two verdicts.
        sink.report(&verdict_a);
        sink.report(&verdict_b);
        let recorded = sink
            .verdicts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(recorded.len(), 2);
        assert!(recorded[0].is_blocking());
        assert!(matches!(recorded[1], DlpVerdict::Allow));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_counts_verdicts_and_stops_on_close() {
        let engine = engine_blocking_token();
        let sink = Arc::new(RecordingSink::default());
        let stats = Arc::new(DlpStats::default());
        let interceptor = Arc::new(InMemoryInterceptor::new(DlpChannel::FileWrite));
        interceptor.push(ContentEvent::new(
            DlpChannel::FileWrite,
            b"leak TOPSECRET now".to_vec(),
        ));
        interceptor.push(ContentEvent::new(DlpChannel::FileWrite, b"benign".to_vec()));

        // InMemoryInterceptor returns Ok(None) once drained, so the
        // worker classifies both events then exits on clean close.
        let (_pipeline, handle) = test_pipeline_handle();
        let (_trigger, signal) = sng_core::ShutdownTrigger::new();
        run_channel_worker(
            interceptor,
            engine,
            Arc::clone(&sink) as Arc<dyn DlpVerdictSink>,
            handle,
            Arc::clone(&stats),
            signal,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(stats.events_observed.load(Ordering::Relaxed), 2);
        assert_eq!(stats.verdict_block.load(Ordering::Relaxed), 1);
        assert_eq!(stats.verdict_allow.load(Ordering::Relaxed), 1);
        assert_eq!(stats.channels_stopped.load(Ordering::Relaxed), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn worker_emits_review_signal_for_flagged_ai_upload() {
        // A secret bound for a known AI app on the upload channel: the
        // worker enforces (coach) AND projects the redacted signal onto
        // the telemetry pipeline as the review-queue producer half.
        let engine = Arc::new(DlpEngine::new(DlpPolicy::default()).expect("engine"));
        engine
            .set_ai_app_policy(Some(AiAppPolicy::default()))
            .expect("enable ai-app");
        let sink = Arc::new(RecordingSink::default());
        let stats = Arc::new(DlpStats::default());

        let interceptor = Arc::new(InMemoryInterceptor::new(AiAppExfilDetector::channel()));
        interceptor.push(
            ContentEvent::new(
                AiAppExfilDetector::channel(),
                b"deploy key ghp_abcdefghijklmnopqrstuvwxyz0123456789 attached".to_vec(),
            )
            .with_metadata(ContentMetadata {
                source: Some("https://chat.openai.com/c/abc".to_owned()),
                ..ContentMetadata::default()
            }),
        );
        // A benign upload to the same app: enforced as Allow, no signal.
        interceptor.push(
            ContentEvent::new(AiAppExfilDetector::channel(), b"hello there".to_vec()).with_metadata(
                ContentMetadata {
                    source: Some("https://chat.openai.com/c/abc".to_owned()),
                    ..ContentMetadata::default()
                },
            ),
        );

        let (pipeline, handle) = test_pipeline_handle();
        let pipeline_task = tokio::spawn(async move { pipeline.run().await });
        let (_trigger, signal) = sng_core::ShutdownTrigger::new();
        run_channel_worker(
            interceptor,
            engine,
            Arc::clone(&sink) as Arc<dyn DlpVerdictSink>,
            handle,
            Arc::clone(&stats),
            signal,
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(stats.events_observed.load(Ordering::Relaxed), 2);
        // Exactly the flagged upload produced a review-queue signal.
        assert_eq!(stats.dlp_signals_emitted.load(Ordering::Relaxed), 1);
        assert_eq!(stats.dlp_signal_drops_full.load(Ordering::Relaxed), 0);
        assert_eq!(stats.dlp_signal_drops_closed.load(Ordering::Relaxed), 0);
        pipeline_task.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_policy_allows_everything() {
        let engine = Arc::new(DlpEngine::new(DlpPolicy::default()).expect("engine"));
        let verdict = engine.evaluate_event(&ContentEvent::new(
            DlpChannel::Clipboard,
            b"anything at all TOPSECRET".to_vec(),
        ));
        assert!(matches!(verdict, DlpVerdict::Allow));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn health_degrades_when_all_channels_stop() {
        let engine = Arc::new(DlpEngine::new(DlpPolicy::default()).expect("engine"));
        let interceptor: Arc<dyn ChannelInterceptor> =
            Arc::new(InMemoryInterceptor::new(DlpChannel::FileWrite));
        let (_pipeline, handle) = test_pipeline_handle();
        let sub = DlpSubsystem::new(
            engine,
            vec![interceptor],
            Arc::new(TracingDlpSink),
            handle,
            Duration::from_millis(1),
        );
        // Simulate the single channel having stopped.
        sub.stats.channels_stopped.store(1, Ordering::Relaxed);
        let health = sub.check().await;
        assert_eq!(health.status, HealthStatus::Degraded);
    }
}

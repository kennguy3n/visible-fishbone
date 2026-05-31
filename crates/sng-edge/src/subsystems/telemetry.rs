// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Telemetry pipeline subsystem adapter.
//!
//! Owns the long-running [`sng_telemetry::Pipeline`] +
//! [`sng_comms::TelemetryClient`] tower. The start task spawns
//! two sub-tasks:
//!
//! 1. **pipeline drain** — `pipeline.run()` consumes events from
//!    every producer's [`PipelineHandle`], runs the dedup /
//!    redact / enrich / spool chain, and exits when every
//!    producer has dropped its handle.
//! 2. **egress flush** — periodic `flush_one` against a fresh
//!    [`ControlPlaneConnection`] drains the spool to the control
//!    plane. Reconnects with backoff on connection-level errors.
//!
//! The adapter exposes [`TelemetrySubsystem::pipeline_handle`]
//! so any other subsystem (dns / ips / fw / swg / sdwan /
//! updater) can clone it and emit events through the standard
//! `submit` surface.

use crate::config::{IdentityConfig, TelemetryConfig};
use async_trait::async_trait;
use sng_comms::{
    Backoff, ControlPlaneClient, ControlPlaneConnection, FlushOutcome, ReconnectBackoff,
    TelemetryClient, TelemetryClientConfig,
};
use sng_core::envelope::Platform;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_telemetry::{
    AgentIdentity, Enricher, PcapRing, PcapRingConfig, Pipeline, PipelineConfig, PipelineHandle,
    RedactionPolicy, SystemTime, TelemetryError,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task;
use tokio::time::{MissedTickBehavior, interval};

/// Edge-tier telemetry subsystem.
pub struct TelemetrySubsystem {
    /// Producer-facing handle (cheap to clone).
    handle: PipelineHandle,
    /// The pipeline itself — taken out of the `Mutex<Option<…>>`
    /// once when `start` runs and moved into the run task.
    pipeline: Mutex<Option<Pipeline<SystemTime>>>,
    /// Egress client (shared with the flush task).
    egress: Arc<TelemetryClient>,
    /// HTTP/2 client used to dial the control plane for batch
    /// uploads.
    client: Arc<ControlPlaneClient>,
    /// PCAP ring buffer (shared with producers that want to
    /// attach a capture).
    pcap: Arc<PcapRing>,
    /// Stats.
    stats: Arc<TelemetryStats>,
    /// Flush cadence.
    tick_interval: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
}

impl std::fmt::Debug for TelemetrySubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TelemetrySubsystem")
            .field("tick_interval", &self.tick_interval)
            .finish_non_exhaustive()
    }
}

/// Atomic health counters.
#[derive(Debug, Default)]
pub struct TelemetryStats {
    /// Successful TCP+TLS+H2 connects for egress.
    pub connects: AtomicU64,
    /// Connect attempts that failed.
    pub connect_failures: AtomicU64,
    /// Batches successfully acked by the control plane.
    pub batches_acked: AtomicU64,
    /// Batches the control plane returned a transient error for
    /// (re-spooled at head).
    pub batches_transient: AtomicU64,
    /// Flush attempts that failed at the transport layer (i.e.
    /// connection-fatal); the connection was dropped + a
    /// reconnect was scheduled.
    pub flush_transport_errors: AtomicU64,
}

/// Errors surfaced at build time.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryBuildError {
    /// Identity contract check failed inside the pipeline
    /// constructor (producer / egress disagreed on
    /// tenant/device/site).
    #[error("pipeline build failed: {0}")]
    Pipeline(#[from] TelemetryError),
}

impl TelemetrySubsystem {
    /// Build from config. The supplied
    /// [`ControlPlaneClient`] is what the flush task uses to
    /// open a fresh connection on each backoff cycle; the
    /// telemetry pipeline does NOT reuse the comms subsystem's
    /// long-lived policy-pull connection because the two run on
    /// independent backoff schedules.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryBuildError::Pipeline`] when the
    /// pipeline's boot-time identity-contract check fails (the
    /// only way `Pipeline::new` can fail).
    pub fn new(
        cfg: &TelemetryConfig,
        identity_cfg: &IdentityConfig,
        platform: Platform,
        client: Arc<ControlPlaneClient>,
    ) -> Result<Self, TelemetryBuildError> {
        let identity = AgentIdentity::new(
            identity_cfg.tenant_id,
            identity_cfg.device_id,
            Some(identity_cfg.site_id),
            platform,
        );
        let enricher = Enricher::new(identity.clone(), SystemTime);
        let redaction = RedactionPolicy::strict();
        let telemetry_cfg = TelemetryClientConfig {
            path: cfg.egress_path.clone(),
            spool_capacity: cfg.spool_capacity,
            ..TelemetryClientConfig::with_defaults(identity.to_comms_enrichment_context())
        };
        let egress = Arc::new(TelemetryClient::new(telemetry_cfg));
        let pcap = Arc::new(PcapRing::new(PcapRingConfig::default()));

        let pipeline_cfg = PipelineConfig {
            event_channel_capacity: cfg.event_channel_capacity,
            dedup_window: cfg.dedup_window,
            dedup_max_entries: cfg.dedup_max_entries,
            tick_interval: cfg.tick_interval,
        };
        let (pipeline, handle) = Pipeline::new(
            pipeline_cfg,
            enricher,
            redaction,
            Arc::clone(&egress),
            Arc::clone(&pcap),
        )?;

        Ok(Self {
            handle,
            pipeline: Mutex::new(Some(pipeline)),
            egress,
            client,
            pcap,
            stats: Arc::new(TelemetryStats::default()),
            tick_interval: cfg.tick_interval,
            backoff_initial: Duration::from_millis(500),
            backoff_max: Duration::from_secs(30),
        })
    }

    /// Producer-facing handle. Clone-and-share to every
    /// subsystem that emits telemetry.
    #[must_use]
    pub fn pipeline_handle(&self) -> PipelineHandle {
        self.handle.clone()
    }

    /// PCAP ring buffer, for producers that want to attach a
    /// capture to an event.
    #[must_use]
    pub fn pcap(&self) -> &Arc<PcapRing> {
        &self.pcap
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<TelemetryStats> {
        &self.stats
    }
}

#[async_trait]
impl Subsystem for TelemetrySubsystem {
    fn name(&self) -> &'static str {
        "telemetry"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        // Take the pipeline out of the Option so we can move it
        // into the spawn closure. Subsequent calls would panic
        // (or return an error) — start() is documented to be
        // called once.
        let pipeline = self.pipeline.lock().await.take().ok_or_else(|| {
            Box::<dyn std::error::Error + Send + Sync>::from("telemetry: start called twice")
        })?;
        let handle_clone = self.handle.clone();
        let egress = Arc::clone(&self.egress);
        let client = Arc::clone(&self.client);
        let stats = Arc::clone(&self.stats);
        let tick_interval = self.tick_interval;
        let backoff_initial = self.backoff_initial;
        let backoff_max = self.backoff_max;
        let shutdown_clone = shutdown.clone();

        Ok(task::spawn(async move {
            // Sub-task 1: pipeline drain. Drop our local
            // handle clone INSIDE the spawned closure so
            // `pipeline.run` can observe channel closure on
            // producer drop. Without this drop the channel
            // would stay open forever — the pipeline's
            // shutdown contract is "every producer dropped
            // its PipelineHandle".
            //
            // We hold the handle across the shutdown.wait()
            // below to give producers a graceful drain window;
            // the explicit drop below schedules it just
            // before we await the pipeline's exit.
            let pipeline_task = task::spawn(async move {
                pipeline.run().await;
            });

            // Sub-task 2: egress flush.
            let flush_task = task::spawn(run_flush_loop(
                shutdown_clone,
                egress,
                client,
                stats,
                tick_interval,
                backoff_initial,
                backoff_max,
            ));

            // Wait on the shutdown signal at the supervisor
            // level. When it fires, drop the local handle
            // clone so the pipeline sees its producer count
            // hit zero and exits cleanly.
            shutdown.wait().await;
            drop(handle_clone);

            // Drain both sub-tasks. We tolerate a join error
            // (panic) and surface it as a subsystem error.
            let pipeline_join = pipeline_task.await;
            let flush_join = flush_task.await;

            match (pipeline_join, flush_join) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(e), _) => Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "telemetry: pipeline task panicked: {e}"
                ))),
                (_, Err(e)) => Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                    "telemetry: flush task panicked: {e}"
                ))),
            }
        }))
    }
}

/// Background flush loop draining the telemetry egress over
/// the control-plane channel. Extracted from
/// `Subsystem::start` to keep the spawn closure short and to
/// surface the tick-cadence + backoff state as an honest set
/// of parameters instead of half-a-dozen captured upvalues.
async fn run_flush_loop(
    shutdown: ShutdownSignal,
    egress: Arc<TelemetryClient>,
    client: Arc<ControlPlaneClient>,
    stats: Arc<TelemetryStats>,
    tick_interval: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
) {
    let mut backoff = ReconnectBackoff::new(backoff_initial, backoff_max, 2);
    let mut conn: Option<ControlPlaneConnection> = None;
    let mut ticker = interval(tick_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    ticker.tick().await;

    loop {
        tokio::select! {
            () = shutdown.wait() => break,
            _ = ticker.tick() => {
                if conn.is_none() {
                    match client.connect().await {
                        Ok(c) => {
                            stats.connects.fetch_add(1, Ordering::Relaxed);
                            backoff.reset();
                            conn = Some(c);
                        }
                        Err(err) => {
                            stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                            let delay = backoff.next_backoff();
                            // u128 → u64 saturating cast for the trace
                            // field. Any Duration over u64::MAX ms
                            // (~580M years) is obviously a config bug
                            // we surface as "saturated" rather than
                            // silently truncate.
                            let delay_ms =
                                u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
                            tracing::warn!(
                                target: "sng_edge::telemetry",
                                error = %err,
                                delay_ms,
                                "telemetry egress connect failed; will retry"
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    }
                }

                // The `conn.is_none()` branch above either populated
                // `conn` or hit `continue`. A panic here would be a
                // logic bug; match instead of `.expect` so a future
                // refactor that breaks the invariant skips the flush
                // rather than aborting.
                let Some(active) = conn.as_ref() else {
                    continue;
                };
                // Drain as many batches as possible per tick —
                // short loop bounded by `Empty` or first error to
                // keep p99 tick latency predictable.
                for _ in 0..32 {
                    match egress.flush_one(active).await {
                        Ok(FlushOutcome::Acked { .. }) => {
                            stats.batches_acked.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(FlushOutcome::Empty) => break,
                        Ok(FlushOutcome::Transient { class }) => {
                            stats.batches_transient.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                target: "sng_edge::telemetry",
                                class = ?class,
                                "telemetry batch transient error; re-spooled at head"
                            );
                            break;
                        }
                        Err(err) => {
                            stats.flush_transport_errors.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                target: "sng_edge::telemetry",
                                error = %err,
                                "telemetry flush failed; dropping connection"
                            );
                            conn = None;
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[async_trait]
impl HealthCheck for TelemetrySubsystem {
    fn name(&self) -> &'static str {
        "telemetry"
    }

    async fn check(&self) -> SubsystemHealth {
        let connects = self.stats.connects.load(Ordering::Relaxed);
        let connect_failures = self.stats.connect_failures.load(Ordering::Relaxed);
        let acked = self.stats.batches_acked.load(Ordering::Relaxed);
        let transient = self.stats.batches_transient.load(Ordering::Relaxed);
        let transport_errors = self.stats.flush_transport_errors.load(Ordering::Relaxed);

        let status = if connect_failures > 0 && connects == 0 {
            HealthStatus::Down
        } else if transport_errors > 0 && acked == 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "connects={connects}, connect_failures={connect_failures}, \
                 acked={acked}, transient={transient}, \
                 transport_errors={transport_errors}"
            )),
        }
    }
}

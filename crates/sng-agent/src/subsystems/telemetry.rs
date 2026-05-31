// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Telemetry pipeline subsystem adapter.
//!
//! Endpoint-tier sibling of
//! [`sng_edge::subsystems::telemetry`]. Owns the long-running
//! [`sng_telemetry::Pipeline`] + [`sng_comms::TelemetryClient`]
//! tower. The start task spawns two sub-tasks:
//!
//! 1. **pipeline drain** — `pipeline.run()` consumes events
//!    from every producer's [`PipelineHandle`] and exits when
//!    every producer has dropped its handle.
//! 2. **egress flush** — periodic `flush_one` against a fresh
//!    [`ControlPlaneConnection`] drains the spool. Reconnects
//!    with backoff on connection-level errors.
//!
//! The endpoint agent does NOT keep a PCAP ring buffer — the
//! edge does (so the operator can attach a synchronised
//! capture to an IPS alert), but the agent's footprint budget
//! is much tighter and the OS already provides per-process
//! capture facilities (Wireshark / pktmon / Console.app).
//! The pipeline still requires a [`PcapRing`] instance; we
//! pass it a 0-byte ring that always reports empty so producers
//! can call `pcap()` without a special-case path.

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

/// Endpoint-tier telemetry subsystem.
pub struct TelemetrySubsystem {
    /// Producer-facing handle (cheap to clone).
    handle: PipelineHandle,
    /// The pipeline itself — taken out of the
    /// `Mutex<Option<…>>` once when `start` runs and moved
    /// into the run task.
    pipeline: Mutex<Option<Pipeline<SystemTime>>>,
    /// Egress client (shared with the flush task).
    egress: Arc<TelemetryClient>,
    /// HTTP/2 client used to dial the control plane for batch
    /// uploads.
    client: Arc<ControlPlaneClient>,
    /// PCAP ring buffer (zero-capacity on the agent — kept on
    /// the struct so producers can reach it via
    /// [`Self::pcap`] without a special-case path).
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
    /// Batches the control plane returned a transient error
    /// for (re-spooled at head).
    pub batches_transient: AtomicU64,
    /// Flush attempts that failed at the transport layer
    /// (i.e. connection-fatal); the connection was dropped
    /// and a reconnect was scheduled.
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
    /// Build from config. The supplied [`ControlPlaneClient`]
    /// is what the flush task uses to open a fresh connection
    /// on each backoff cycle; the telemetry pipeline reuses
    /// the comms subsystem's client (one TLS config + endpoint
    /// pairing serves both bundle pulls and event uploads),
    /// but each subsystem opens its own connection so the
    /// reconnect cadences stay independent.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryBuildError::Pipeline`] when the
    /// pipeline's boot-time identity-contract check fails.
    pub fn new(
        cfg: &TelemetryConfig,
        identity_cfg: &IdentityConfig,
        platform: Platform,
        client: Arc<ControlPlaneClient>,
    ) -> Result<Self, TelemetryBuildError> {
        let identity = AgentIdentity::new(
            identity_cfg.tenant_id,
            identity_cfg.device_id,
            identity_cfg.site_id,
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
        // Minimal PCAP ring — see the `pcap` field comment.
        // `PcapRing::new` asserts `max_packets > 0` so we
        // can't construct a zero-capacity ring; we use the
        // smallest valid sizing so the buffer's resident
        // footprint is negligible. Agent producers never push
        // here; the ring is held purely to honour the
        // [`Pipeline::new`] contract.
        let pcap = Arc::new(PcapRing::new(PcapRingConfig {
            max_packets: 1,
            max_total_bytes: 1024,
            max_packet_bytes: 1024,
        }));

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

    /// PCAP ring buffer. Zero-capacity on the agent — see the
    /// `pcap` field comment for why.
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
            let pipeline_task = task::spawn(async move {
                pipeline.run().await;
            });

            let flush_task = task::spawn(run_flush_loop(
                shutdown_clone,
                egress,
                client,
                stats,
                tick_interval,
                backoff_initial,
                backoff_max,
            ));

            shutdown.wait().await;
            drop(handle_clone);

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

/// Background flush loop driving the telemetry egress over
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
                                target: "sng_agent::telemetry",
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
                for _ in 0..32 {
                    match egress.flush_one(active).await {
                        Ok(FlushOutcome::Acked { .. }) => {
                            stats.batches_acked.fetch_add(1, Ordering::Relaxed);
                        }
                        Ok(FlushOutcome::Empty) => break,
                        Ok(FlushOutcome::Transient { class }) => {
                            stats.batches_transient.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                target: "sng_agent::telemetry",
                                class = ?class,
                                "telemetry batch transient error; re-spooled at head"
                            );
                            break;
                        }
                        Err(err) => {
                            stats.flush_transport_errors.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                target: "sng_agent::telemetry",
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
                 acked={acked}, transient={transient}, transport_errors={transport_errors}"
            )),
        }
    }
}

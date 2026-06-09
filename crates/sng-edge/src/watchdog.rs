// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Top-level edge watchdog: the escalation tier above the
//! per-subsystem self-healing supervisors.
//!
//! The IPS health supervisor ([`sng_ips::HealthSupervisor`]) and the
//! SWG Envoy supervisor ([`sng_swg::EnvoySupervisor`]) each self-heal
//! their own process — they poll liveness, restart with exponential
//! backoff under a last-known-good config, and, when their restart
//! budget is exhausted, *hand off to the top-level watchdog*. This
//! module is that watchdog.
//!
//! It observes aggregate subsystem health (via [`HealthSource`], which
//! the binary backs with the [`sng_core::Supervisor`]'s health
//! snapshot) and, when a subsystem stays `Down` past the
//! flap-suppression threshold, walks a fixed escalation ladder:
//!
//! 1. **Restart the subsystem** — ask the subsystem's own restarter
//!    ([`SubsystemRestarter`]) for one coarse in-place restart, under
//!    a bounded attempt budget with exponential backoff. The
//!    subsystem's own supervisor has already tried and failed, so this
//!    is a last in-process attempt before a heavier hammer.
//! 2. **Restart the edge** — if the subsystem will not come back,
//!    bounce the whole appliance via [`EdgeController`]. In production
//!    this fires the process shutdown so the supervising init system
//!    relaunches the binary from a clean slate (kernel modules
//!    reloaded, sockets re-bound, every subsystem re-initialised).
//! 3. **Alert the control plane** — if even the edge bounce cannot be
//!    initiated, emit a terminal [`SubsystemRestartOutcome::Exhausted`]
//!    [`SubsystemRestart`] with reason [`SubsystemRestartReason::Escalated`].
//!    This reaches the control-plane dashboard through the same
//!    telemetry pipeline as traffic events (the sink forwards it as a
//!    `TelemetryEvent::System`), signalling that automated recovery is
//!    spent and a human must intervene.
//!
//! Every tier emits a [`SubsystemRestart`] event through the injected
//! [`SubsystemRestartSink`], so the control plane sees the full
//! escalation trail — not just the terminal alert.
//!
//! # Why injected seams
//!
//! [`HealthSource`], [`SubsystemRestarter`], and [`EdgeController`] are
//! traits rather than concrete types so the escalation policy is unit
//! testable without a running appliance, and so the binary wiring
//! (which holds the subsystem managers and the process
//! [`ShutdownTrigger`]) supplies the real implementations. Concrete
//! production adapters [`SupervisorHealthSource`] and
//! [`ShutdownEdgeController`] are provided here; the per-subsystem
//! restarter is supplied by the binary because an in-place subsystem
//! restart is necessarily subsystem-specific.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use sng_core::events::{SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason};
use sng_core::lifecycle::{Health, HealthStatus};
use sng_core::restart::{NoopRestartSink, SubsystemRestartSink};
use sng_core::{ShutdownSignal, ShutdownTrigger, Supervisor};
use sng_telemetry::{PipelineHandle, TelemetryEvent, TrySubmitError};

/// Stable subsystem name used in watchdog-originated
/// [`SubsystemRestart`] telemetry whose escalation is appliance-wide
/// rather than tied to a single subsystem (e.g. an edge bounce).
pub const WATCHDOG_NAME: &str = "edge_watchdog";

/// Errors raised by the watchdog's escalation actions.
#[derive(Debug, Error)]
pub enum WatchdogError {
    /// A subsystem restart could not be initiated.
    #[error("subsystem `{subsystem}` restart failed: {detail}")]
    SubsystemRestart {
        /// Subsystem name.
        subsystem: String,
        /// Human-readable cause.
        detail: String,
    },
    /// The edge could not be restarted (no init supervisor to relaunch
    /// the process, or the controller refused). Triggers the terminal
    /// control-plane alert.
    #[error("edge restart failed: {0}")]
    EdgeRestart(String),
}

/// Source of aggregate subsystem health.
///
/// Backed in production by [`SupervisorHealthSource`], which samples
/// the [`Supervisor`]'s on-demand health snapshot.
#[async_trait]
pub trait HealthSource: Send + Sync + std::fmt::Debug {
    /// Take a fresh aggregate health sample.
    async fn health(&self) -> Health;
}

/// In-place restarter for a single named subsystem.
///
/// Supplied by the binary wiring, which holds the concrete subsystem
/// managers (the IPS Suricata manager, the SWG Envoy manager, …). A
/// restart is "accepted" — the watchdog re-probes [`HealthSource`] to
/// confirm the subsystem actually returned to health rather than
/// trusting an optimistic `Ok`.
#[async_trait]
pub trait SubsystemRestarter: Send + Sync + std::fmt::Debug {
    /// Attempt to restart the named subsystem in place.
    async fn restart_subsystem(&self, name: &str) -> Result<(), WatchdogError>;
}

/// Controller for whole-appliance restart.
///
/// Backed in production by [`ShutdownEdgeController`], which fires the
/// process [`ShutdownTrigger`] so the supervising init relaunches the
/// binary.
#[async_trait]
pub trait EdgeController: Send + Sync + std::fmt::Debug {
    /// Initiate a restart of the whole edge appliance. `Ok(())` means
    /// the bounce was initiated; the process is expected to exit
    /// shortly afterwards.
    async fn restart_edge(&self, reason: &str) -> Result<(), WatchdogError>;
}

/// Production [`HealthSource`] backed by the [`Supervisor`]'s
/// on-demand health snapshot.
#[derive(Clone, Debug)]
pub struct SupervisorHealthSource {
    supervisor: Arc<Supervisor>,
}

impl SupervisorHealthSource {
    /// Wrap a shared supervisor.
    #[must_use]
    pub fn new(supervisor: Arc<Supervisor>) -> Self {
        Self { supervisor }
    }
}

#[async_trait]
impl HealthSource for SupervisorHealthSource {
    async fn health(&self) -> Health {
        self.supervisor.health_snapshot().await
    }
}

/// Production [`EdgeController`] that bounces the appliance by firing
/// the process [`ShutdownTrigger`].
///
/// Firing the trigger drives [`Supervisor::run`] to drain every
/// subsystem and return; the supervising init system (systemd with
/// `Restart=always`, or the appliance's PID-1 shim) then relaunches
/// the binary. This is a *clean* bounce — not a panic / abort — so the
/// drain budget is honoured and no subsystem is hard-killed mid-write.
#[derive(Clone, Debug)]
pub struct ShutdownEdgeController {
    trigger: Arc<ShutdownTrigger>,
}

impl ShutdownEdgeController {
    /// Wrap the process-wide shutdown trigger.
    #[must_use]
    pub fn new(trigger: Arc<ShutdownTrigger>) -> Self {
        Self { trigger }
    }
}

#[async_trait]
impl EdgeController for ShutdownEdgeController {
    async fn restart_edge(&self, reason: &str) -> Result<(), WatchdogError> {
        warn!(
            target: "sng_edge::watchdog",
            reason,
            "edge watchdog escalating to full appliance restart"
        );
        self.trigger.fire();
        Ok(())
    }
}

/// Production [`SubsystemRestartSink`] that forwards every restart
/// event onto the edge telemetry pipeline as a
/// [`TelemetryEvent::System`].
///
/// This is the shared sink wired into all three WS2 supervisors at the
/// edge (the IPS health supervisor, the SWG Envoy supervisor, and this
/// watchdog) so their restart telemetry reaches the control-plane
/// dashboard through the same dedup / redaction / batch path as
/// traffic events — the "alert control plane" leg of the escalation
/// chain.
///
/// # Non-blocking
///
/// [`SubsystemRestartSink::record`] is on the supervisors' critical
/// self-healing path, so this uses the pipeline's non-blocking
/// [`PipelineHandle::try_submit`] and drops (with a warning) on
/// backpressure rather than awaiting channel capacity. Losing a
/// restart-telemetry record is strictly preferable to delaying the
/// restart it describes.
#[derive(Clone, Debug)]
pub struct PipelineRestartSink {
    pipeline: PipelineHandle,
}

impl PipelineRestartSink {
    /// Wrap a telemetry pipeline handle.
    #[must_use]
    pub fn new(pipeline: PipelineHandle) -> Self {
        Self { pipeline }
    }
}

#[async_trait]
impl SubsystemRestartSink for PipelineRestartSink {
    async fn record(&self, event: SubsystemRestart) {
        match self.pipeline.try_submit(TelemetryEvent::System(event)) {
            Ok(()) => {}
            Err(TrySubmitError::Full(ev)) => {
                warn!(
                    target: "sng_edge::watchdog",
                    ?ev,
                    "telemetry pipeline full; dropping restart event to avoid stalling self-healing"
                );
            }
            Err(TrySubmitError::Closed(ev)) => {
                debug!(
                    target: "sng_edge::watchdog",
                    ?ev,
                    "telemetry pipeline closed; restart event not recorded"
                );
            }
        }
    }
}

/// Tunables for the [`Watchdog`] escalation engine.
#[derive(Clone, Debug)]
pub struct WatchdogConfig {
    /// Cadence at which the watchdog samples aggregate health.
    pub poll_interval: Duration,
    /// Consecutive `Down` samples for a single subsystem before the
    /// watchdog begins escalation. Suppresses flap on a transient
    /// probe miss (the per-subsystem supervisor owns fine-grained
    /// restarts; the watchdog only fires on a sustained outage its
    /// owner could not fix).
    pub down_threshold: u32,
    /// Tier-1 budget: in-place subsystem restart attempts before
    /// escalating to an edge bounce.
    pub subsystem_restart_attempts: u32,
    /// First backoff applied before a tier-1 restart. Doubles per
    /// attempt up to [`Self::restart_max_backoff`].
    pub restart_initial_backoff: Duration,
    /// Ceiling for the tier-1 exponential backoff.
    pub restart_max_backoff: Duration,
}

impl Default for WatchdogConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            down_threshold: 3,
            subsystem_restart_attempts: 2,
            restart_initial_backoff: Duration::from_secs(2),
            restart_max_backoff: Duration::from_secs(30),
        }
    }
}

/// Per-subsystem escalation tier.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Tier {
    /// Tier 1 — retry an in-place subsystem restart.
    Subsystem,
    /// Tier 2 — bounce the whole edge.
    Edge,
    /// Terminal — control plane has been alerted; do not act again
    /// until the subsystem recovers (avoids alert spam).
    Alerted,
}

/// Mutable escalation bookkeeping for one subsystem.
#[derive(Debug)]
struct Escalation {
    /// Consecutive `Down` samples observed.
    consecutive_down: u32,
    /// Current tier.
    tier: Tier,
    /// Tier-1 restart attempts spent in this episode.
    attempts: u32,
    /// Current tier-1 backoff.
    backoff: Duration,
}

impl Escalation {
    fn new(initial_backoff: Duration) -> Self {
        Self {
            consecutive_down: 0,
            tier: Tier::Subsystem,
            attempts: 0,
            backoff: initial_backoff,
        }
    }
}

/// Outcome of a single escalation step, telling the run loop how to
/// update its escalation map and whether to keep running.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Step {
    /// Escalation advanced or retried; keep the entry and keep running.
    Continue,
    /// The subsystem recovered; drop its escalation state.
    Recovered,
    /// An edge bounce was fired (or shutdown signalled); stop the loop.
    Stop,
}

/// Top-level edge watchdog. See the module docs for the escalation
/// ladder.
#[derive(Debug)]
pub struct Watchdog {
    health: Arc<dyn HealthSource>,
    restarter: Arc<dyn SubsystemRestarter>,
    edge: Arc<dyn EdgeController>,
    sink: Arc<dyn SubsystemRestartSink>,
    config: WatchdogConfig,
}

impl Watchdog {
    /// Build a watchdog over the given health source, subsystem
    /// restarter, and edge controller.
    #[must_use]
    pub fn new(
        health: Arc<dyn HealthSource>,
        restarter: Arc<dyn SubsystemRestarter>,
        edge: Arc<dyn EdgeController>,
        config: WatchdogConfig,
    ) -> Self {
        Self {
            health,
            restarter,
            edge,
            sink: Arc::new(NoopRestartSink),
            config,
        }
    }

    /// Attach the telemetry sink escalation events are reported to.
    /// Defaults to a no-op sink when not set.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn SubsystemRestartSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Run the watchdog until `shutdown` fires. Samples health on
    /// [`WatchdogConfig::poll_interval`] and drives the escalation
    /// ladder for any subsystem that stays `Down`.
    pub async fn run(&self, shutdown: ShutdownSignal) {
        // Per-subsystem escalation state, keyed by subsystem name.
        let mut escalations: HashMap<String, Escalation> = HashMap::new();

        loop {
            tokio::select! {
                () = shutdown.wait() => {
                    debug!(target: "sng_edge::watchdog", "shutdown signalled");
                    return;
                }
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }

            let health = self.health.health().await;
            // Names reported Down this tick — used to clear escalation
            // state for subsystems that have recovered.
            let mut down_now: Vec<String> = Vec::new();

            for sub in &health.subsystems {
                if sub.status == HealthStatus::Down {
                    down_now.push(sub.name.clone());
                }
            }

            // Drop escalation state for any subsystem no longer Down —
            // it recovered (whether by its own supervisor, our tier-1
            // restart, or transiently). Emit a Recovered event if we
            // had been actively escalating it.
            self.reap_recovered(&mut escalations, &down_now).await;

            for name in &down_now {
                {
                    let entry = escalations
                        .entry(name.clone())
                        .or_insert_with(|| Escalation::new(self.config.restart_initial_backoff));
                    entry.consecutive_down = entry.consecutive_down.saturating_add(1);
                    if entry.consecutive_down < self.config.down_threshold {
                        debug!(
                            target: "sng_edge::watchdog",
                            subsystem = %name,
                            consecutive_down = entry.consecutive_down,
                            "subsystem down but below escalation threshold"
                        );
                        continue;
                    }
                }

                // One escalation step per tick. The mutable borrow of
                // the entry ends when `step_escalation` returns, so we
                // can mutate the map (remove on recovery) afterwards.
                // The entry is always present — it was inserted above
                // this tick — but match defensively rather than panic.
                let Some(state) = escalations.get_mut(name) else {
                    continue;
                };
                match self.step_escalation(name, state, &shutdown).await {
                    Step::Continue => {}
                    Step::Recovered => {
                        escalations.remove(name);
                    }
                    Step::Stop => return,
                }
            }
        }
    }

    /// Clear escalation state for subsystems that are no longer `Down`,
    /// emitting a `Recovered` event for any we had escalated past the
    /// threshold.
    async fn reap_recovered(
        &self,
        escalations: &mut HashMap<String, Escalation>,
        down_now: &[String],
    ) {
        let recovered: Vec<String> = escalations
            .keys()
            .filter(|name| !down_now.contains(name))
            .cloned()
            .collect();
        for name in recovered {
            if let Some(state) = escalations.remove(&name) {
                // Only report recovery if we had actually started
                // acting (reached the threshold / spent an attempt).
                if state.consecutive_down >= self.config.down_threshold || state.attempts > 0 {
                    info!(
                        target: "sng_edge::watchdog",
                        subsystem = %name,
                        "subsystem recovered; escalation cleared"
                    );
                    self.emit(
                        &name,
                        SubsystemRestartReason::Escalated,
                        SubsystemRestartOutcome::Recovered,
                        state.attempts,
                        0,
                        "subsystem recovered; watchdog escalation cleared".to_owned(),
                    )
                    .await;
                }
            }
        }
    }

    /// Run one escalation step for a subsystem that has been `Down`
    /// past the threshold, mutating its escalation `state`.
    async fn step_escalation(
        &self,
        name: &str,
        state: &mut Escalation,
        shutdown: &ShutdownSignal,
    ) -> Step {
        match state.tier {
            Tier::Subsystem => self.step_subsystem_restart(name, state, shutdown).await,
            Tier::Edge => self.step_edge_restart(name, state).await,
            // Already alerted the control plane; nothing further to do
            // until the subsystem recovers (reaped by `reap_recovered`).
            Tier::Alerted => Step::Continue,
        }
    }

    /// Tier 1: one in-place subsystem restart attempt under backoff.
    async fn step_subsystem_restart(
        &self,
        name: &str,
        state: &mut Escalation,
        shutdown: &ShutdownSignal,
    ) -> Step {
        // Interruptible backoff before the attempt so an operator stop()
        // during a long window does not hang the watchdog.
        tokio::select! {
            () = shutdown.wait() => return Step::Stop,
            () = tokio::time::sleep(state.backoff) => {}
        }

        state.attempts = state.attempts.saturating_add(1);
        let attempt = state.attempts;
        let backoff_ms = u64::try_from(state.backoff.as_millis()).unwrap_or(u64::MAX);

        // The restarter's contract: `Ok` means restarted *and* confirmed
        // healthy (it blocks on the subsystem's own supervisor), so we
        // can trust it without waiting for the next health sample.
        match self.restarter.restart_subsystem(name).await {
            Ok(()) => {
                info!(
                    target: "sng_edge::watchdog",
                    subsystem = %name,
                    attempt,
                    "watchdog subsystem restart recovered the subsystem"
                );
                self.emit(
                    name,
                    SubsystemRestartReason::Escalated,
                    SubsystemRestartOutcome::Recovered,
                    attempt,
                    backoff_ms,
                    "watchdog in-place subsystem restart succeeded".to_owned(),
                )
                .await;
                Step::Recovered
            }
            Err(e) => {
                warn!(
                    target: "sng_edge::watchdog",
                    subsystem = %name,
                    attempt,
                    error = %e,
                    "watchdog subsystem restart attempt failed"
                );
                if attempt >= self.config.subsystem_restart_attempts {
                    // Tier-1 budget spent — escalate to an edge bounce on
                    // the next tick.
                    state.tier = Tier::Edge;
                    self.emit(
                        name,
                        SubsystemRestartReason::Escalated,
                        SubsystemRestartOutcome::Failed,
                        attempt,
                        backoff_ms,
                        format!("subsystem restart budget exhausted; escalating to edge restart: {e}"),
                    )
                    .await;
                } else {
                    state.backoff = (state.backoff * 2).min(self.config.restart_max_backoff);
                    self.emit(
                        name,
                        SubsystemRestartReason::Escalated,
                        SubsystemRestartOutcome::Failed,
                        attempt,
                        backoff_ms,
                        format!("subsystem restart failed; will retry: {e}"),
                    )
                    .await;
                }
                Step::Continue
            }
        }
    }

    /// Tier 2: bounce the whole edge. On success the process is going
    /// down (`Step::Stop`); on failure, alert the control plane and
    /// latch `Alerted` (`Step::Continue`).
    async fn step_edge_restart(&self, name: &str, state: &mut Escalation) -> Step {
        match self.edge.restart_edge(name).await {
            Ok(()) => {
                self.emit(
                    name,
                    SubsystemRestartReason::Escalated,
                    SubsystemRestartOutcome::Exhausted,
                    state.attempts,
                    0,
                    "subsystem unrecoverable in place; bouncing edge appliance".to_owned(),
                )
                .await;
                Step::Stop
            }
            Err(e) => {
                // Terminal: even the edge bounce could not be initiated.
                // Alert the control plane and stop acting on this
                // subsystem until it recovers.
                error!(
                    target: "sng_edge::watchdog",
                    subsystem = %name,
                    error = %e,
                    "edge restart failed; alerting control plane — manual intervention required"
                );
                state.tier = Tier::Alerted;
                self.emit(
                    name,
                    SubsystemRestartReason::Escalated,
                    SubsystemRestartOutcome::Exhausted,
                    state.attempts,
                    0,
                    format!("automated recovery exhausted; edge restart failed: {e}"),
                )
                .await;
                Step::Continue
            }
        }
    }

    /// Emit one [`SubsystemRestart`] escalation event through the sink.
    async fn emit(
        &self,
        subsystem: &str,
        reason: SubsystemRestartReason,
        outcome: SubsystemRestartOutcome,
        attempt: u32,
        backoff_ms: u64,
        detail: String,
    ) {
        self.sink
            .record(SubsystemRestart {
                subsystem: subsystem.to_owned(),
                reason,
                outcome,
                attempt,
                // The watchdog tier does not itself choose a data-path
                // posture; that is the per-subsystem supervisor's
                // concern. Report fail-open (traffic preserved) since
                // an edge bounce preserves no inspection mid-restart.
                fail_open: true,
                rolled_back_config: false,
                backoff_ms,
                detail,
            })
            .await;
    }
}

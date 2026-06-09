//! Three-state IDS liveness machine with configurable
//! fail-open / fail-closed policy.
//!
//! Subsystem health distinguishes three observable states:
//!
//! * **`Healthy`** — Suricata is alive, accepting packets, and
//!   the drop ratio is within the operator's bound. Traffic
//!   flows normally.
//! * **`Degraded`** — Process is alive but the drop ratio
//!   exceeded the operator's threshold *or* the EVE writer has
//!   not made progress within the staleness window. The traffic
//!   path is unchanged (we still defer to Suricata for verdicts)
//!   but the manager surfaces an alert and increases the probe
//!   cadence.
//! * **`Failed`** — Process is dead / unreachable. The manager
//!   either fails the data path open (legacy posture: keep the
//!   link up, lose IDS coverage) or fails it closed (high-trust
//!   posture: drop traffic until coverage is restored), per the
//!   per-state [`FailMode`] policy.
//!
//! The state machine is pure: it never touches the OS or
//! Suricata, just consumes a [`HealthProbe`] snapshot and returns
//! the new state.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use sng_core::ShutdownSignal;
use sng_core::events::{SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason};
use sng_core::restart::{NoopRestartSink, SubsystemRestartSink};

use crate::process::{StatsDelta, SuricataProcess, SuricataStats};

/// Operator-controlled action when Suricata is unhealthy.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Keep traffic flowing even when IPS coverage is missing.
    /// Acceptable for legacy operators and the initial roll-out
    /// window; the manager still emits a high-severity event so
    /// the operator dashboard can act on it.
    Open,
    /// Drop traffic when IPS coverage is missing. The strict
    /// posture — the data path is held until coverage returns.
    Closed,
}

/// Health state observable by the rest of the subsystem.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Process alive, drop ratio inside the operator bound, EVE
    /// writer making forward progress.
    Healthy,
    /// Process alive but at least one quality signal is out of
    /// bounds.
    Degraded,
    /// Process unreachable. Data-plane behaviour is governed by
    /// the operator's [`FailMode`].
    Failed,
}

impl HealthState {
    /// Should the data plane keep forwarding traffic in this
    /// health state, given the policy for `Failed`?
    #[must_use]
    pub const fn forwarding_allowed(self, fail_mode_when_failed: FailMode) -> bool {
        match self {
            // Healthy + Degraded both forward — degradation is a
            // signal, not a closure.
            Self::Healthy | Self::Degraded => true,
            Self::Failed => matches!(fail_mode_when_failed, FailMode::Open),
        }
    }
}

/// A single observation the manager hands to the state machine.
/// Built from the result of one polling round (PID liveness +
/// stats read + EVE writer staleness).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthProbe {
    /// Did the process respond at all? Combines the OS-level PID
    /// liveness check with whether the stats socket answered.
    pub process_alive: bool,
    /// Has the EVE writer made any forward progress (new
    /// alert / metadata line) within the manager's staleness
    /// window? Set to `true` on a quiet but healthy interval;
    /// `false` only when the file has been stuck for longer than
    /// the window allows.
    pub eve_progressing: bool,
    /// Per-interval delta of process counters — used to evaluate
    /// the drop ratio threshold.
    pub stats_delta: StatsDelta,
}

/// Tunable thresholds for the state machine. Operators typically
/// flex `degraded_drop_ratio` and `failed_drop_ratio` — the rest
/// are defensible defaults that match the published Suricata
/// performance guidance.
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthThresholds {
    /// Drop ratio in `[0.0, 1.0]` above which the state degrades
    /// to `Degraded`. Default 1 %.
    pub degraded_drop_ratio: f64,
    /// Drop ratio at which the manager treats the subsystem as
    /// `Failed` even though the process is technically alive
    /// (e.g. ring buffer saturated). Default 25 %.
    pub failed_drop_ratio: f64,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            degraded_drop_ratio: 0.01,
            failed_drop_ratio: 0.25,
        }
    }
}

/// Result of a single state-machine step.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HealthTransition {
    /// The state before the probe was processed.
    pub previous: HealthState,
    /// The state after the probe was processed.
    pub current: HealthState,
    /// Convenience: did the probe move the machine?
    pub changed: bool,
}

/// State machine. Owns its current state; not thread-safe — the
/// manager holds it behind its own lock.
#[derive(Clone, Debug)]
pub struct HealthMonitor {
    state: HealthState,
    thresholds: HealthThresholds,
    /// How many consecutive "process_alive == false" probes the
    /// machine needs to see before transitioning to `Failed`.
    /// Single missed probes happen — make `Failed` sticky enough
    /// to suppress alarm flap.
    failed_consecutive_required: u32,
    consecutive_dead: u32,
}

impl HealthMonitor {
    /// Construct a monitor that starts `Healthy` with default
    /// thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::with_thresholds(HealthThresholds::default())
    }

    /// Construct with operator-supplied thresholds.
    #[must_use]
    pub fn with_thresholds(thresholds: HealthThresholds) -> Self {
        Self {
            state: HealthState::Healthy,
            thresholds,
            failed_consecutive_required: 3,
            consecutive_dead: 0,
        }
    }

    /// Override how many consecutive dead probes promote to
    /// `Failed`. Useful in unit tests that need a single probe
    /// to drive the transition.
    #[must_use]
    pub const fn with_failed_threshold(mut self, n: u32) -> Self {
        // Clamp at 1 — a zero-threshold would mean "Failed on
        // every probe", which would race against startup.
        self.failed_consecutive_required = if n == 0 { 1 } else { n };
        self
    }

    /// Current state.
    #[must_use]
    pub const fn state(&self) -> HealthState {
        self.state
    }

    /// Number of consecutive dead probes the monitor has seen
    /// without a recovery. Reset on the first alive probe.
    #[must_use]
    pub const fn consecutive_dead(&self) -> u32 {
        self.consecutive_dead
    }

    /// Process one probe and emit the transition.
    pub fn observe(&mut self, probe: HealthProbe) -> HealthTransition {
        let previous = self.state;
        let next = self.compute_next(&probe);
        self.state = next;
        HealthTransition {
            previous,
            current: next,
            changed: previous != next,
        }
    }

    fn compute_next(&mut self, probe: &HealthProbe) -> HealthState {
        if !probe.process_alive {
            self.consecutive_dead = self.consecutive_dead.saturating_add(1);
            if self.consecutive_dead >= self.failed_consecutive_required {
                return HealthState::Failed;
            }
            // Not yet at the consecutive-dead threshold. Two cases:
            //
            // 1. We were Healthy / Degraded before. The first
            //    transient probe miss should degrade — never jump
            //    straight to Failed — so alarm flap is suppressed.
            //
            // 2. We were *already* Failed (the drop-ratio branch
            //    below put us there on an earlier alive probe, then
            //    the process died). Downgrading to Degraded just
            //    because the dead counter only sits at 1/3 would
            //    *relax* the observable state: dashboards would see
            //    Failed → Degraded → Failed as the counter climbed
            //    to the threshold. That oscillation is purely a
            //    state-machine artefact — there has been no real
            //    recovery between the two Failed observations. Keep
            //    Failed sticky against transient dead probes; only
            //    a clean alive probe in the alive branch below can
            //    legitimately move us out.
            return match self.state {
                HealthState::Failed => HealthState::Failed,
                HealthState::Healthy | HealthState::Degraded => HealthState::Degraded,
            };
        }
        // Live probe — reset the dead counter.
        self.consecutive_dead = 0;
        let drop_ratio = probe.stats_delta.drop_ratio();
        if drop_ratio >= self.thresholds.failed_drop_ratio {
            return HealthState::Failed;
        }
        if drop_ratio >= self.thresholds.degraded_drop_ratio {
            return HealthState::Degraded;
        }
        if !probe.eve_progressing {
            // Counters healthy but EVE writer is stuck — usually
            // means the worker thread serving outputs is wedged.
            // Treat as degraded so the operator sees a signal
            // before alerts go silent.
            return HealthState::Degraded;
        }
        HealthState::Healthy
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Stable subsystem name used in emitted [`SubsystemRestart`]
/// telemetry. Matches the IPS subsystem's lifecycle name so the
/// control plane can join restart events against the `/health`
/// report.
pub const SUBSYSTEM_NAME: &str = "ips";

/// Tunables for the active [`HealthSupervisor`] control loop.
#[derive(Clone, Debug)]
pub struct HealthSupervisorConfig {
    /// Cadence at which the supervisor polls `is_alive()` + the
    /// stats socket. The manager's EVE-stats path runs on its own
    /// cadence; this is purely the self-healing liveness probe.
    pub poll_interval: Duration,
    /// Thresholds handed to the underlying [`HealthMonitor`].
    pub thresholds: HealthThresholds,
    /// Consecutive dead probes required before the monitor latches
    /// `Failed` — suppresses alarm flap on a single missed probe.
    pub failed_consecutive_required: u32,
    /// Operator fail posture applied while the subsystem is
    /// `Failed`. Surfaced on the emitted telemetry so the control
    /// plane knows whether traffic kept flowing.
    pub fail_mode: FailMode,
    /// First restart backoff. Doubles per consecutive failed
    /// restart up to [`Self::restart_max_backoff`].
    pub restart_initial_backoff: Duration,
    /// Ceiling for the exponential restart backoff.
    pub restart_max_backoff: Duration,
    /// Optional cap on restart attempts within a single failure
    /// episode. `None` means the supervisor keeps trying
    /// indefinitely; `Some(n)` makes it emit an
    /// [`SubsystemRestartOutcome::Exhausted`] event and hand off to
    /// the top-level watchdog after `n` consecutive failed attempts.
    pub restart_max_attempts: Option<u32>,
}

impl Default for HealthSupervisorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            thresholds: HealthThresholds::default(),
            failed_consecutive_required: 3,
            // Fail-open is the default roll-out posture: losing IDS
            // coverage must not black-hole a tenant's traffic unless
            // the operator explicitly opts into the strict posture.
            fail_mode: FailMode::Open,
            restart_initial_backoff: Duration::from_secs(1),
            restart_max_backoff: Duration::from_secs(30),
            restart_max_attempts: None,
        }
    }
}

/// Active self-healing supervisor for a Suricata process.
///
/// Where [`HealthMonitor`] is the *pure* state machine, the
/// `HealthSupervisor` is the *driver*: it polls the process on a
/// fixed cadence, feeds each observation into the state machine,
/// and — when the machine latches [`HealthState::Failed`] — restarts
/// Suricata under an exponential backoff, rolling back to the
/// last-known-good config and emitting a [`SubsystemRestart`]
/// telemetry event per attempt.
///
/// # Last-known-good config
///
/// The supervisor is told the *active* config via
/// [`Self::set_active_config`] whenever the manager applies one.
/// Every time the subsystem is observed `Healthy`, the active config
/// is promoted to last-known-good. On a restart the supervisor
/// re-launches with the last-known-good config rather than the one
/// that was live at failure — so a freshly-applied config that
/// crashes Suricata before it ever reaches `Healthy` is rolled back
/// automatically instead of being re-applied into a crash loop.
///
/// # Concurrency
///
/// Cheap to wrap in an `Arc` and share: [`Self::run`] takes `&self`
/// so one clone can drive the loop while others call
/// [`Self::set_active_config`] / [`Self::state`]. The mutable state
/// machine is held behind a non-async [`parking_lot::Mutex`] that is
/// never held across an `.await`.
#[derive(Debug)]
pub struct HealthSupervisor {
    process: Arc<dyn SuricataProcess>,
    monitor: Mutex<HealthMonitor>,
    config: HealthSupervisorConfig,
    sink: Arc<dyn SubsystemRestartSink>,
    /// Config the process is currently running under. Updated by
    /// the manager via [`Self::set_active_config`].
    active_config: ArcSwap<PathBuf>,
    /// Most recent config under which the subsystem was observed
    /// `Healthy`. `None` until the first healthy observation.
    last_known_good: ArcSwapOption<PathBuf>,
}

impl HealthSupervisor {
    /// Build a supervisor for `process`, told that `initial_config`
    /// is the config Suricata was launched with.
    #[must_use]
    pub fn new(
        process: Arc<dyn SuricataProcess>,
        initial_config: impl Into<PathBuf>,
        config: HealthSupervisorConfig,
    ) -> Self {
        let monitor = HealthMonitor::with_thresholds(config.thresholds)
            .with_failed_threshold(config.failed_consecutive_required);
        Self {
            process,
            monitor: Mutex::new(monitor),
            config,
            sink: Arc::new(NoopRestartSink),
            active_config: ArcSwap::from_pointee(initial_config.into()),
            last_known_good: ArcSwapOption::empty(),
        }
    }

    /// Attach the telemetry sink restart events are reported to.
    /// Defaults to a no-op sink when not set.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn SubsystemRestartSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Record that the manager has applied a new active config. The
    /// supervisor restarts against this path while it is healthy and
    /// promotes it to last-known-good on the next healthy probe.
    pub fn set_active_config(&self, path: impl Into<PathBuf>) {
        self.active_config.store(Arc::new(path.into()));
    }

    /// Current health state observed by the supervisor.
    #[must_use]
    pub fn state(&self) -> HealthState {
        self.monitor.lock().state()
    }

    /// Last-known-good config, if the subsystem has ever been
    /// observed healthy.
    #[must_use]
    pub fn last_known_good(&self) -> Option<PathBuf> {
        self.last_known_good.load_full().map(|p| (*p).clone())
    }

    /// Run the supervisor until `shutdown` fires. Polls the process
    /// on [`HealthSupervisorConfig::poll_interval`], driving the
    /// state machine and self-healing on `Failed`.
    pub async fn run(&self, shutdown: ShutdownSignal) {
        // Previous stats snapshot, for the per-interval delta. None
        // until the first successful stats read and reset across a
        // restart (Suricata's counters reset, so a post-restart read
        // must not be diffed against the pre-crash snapshot — that
        // would saturate to zero anyway, but resetting is clearer).
        let mut prev_stats: Option<SuricataStats> = None;
        let mut backoff = self.config.restart_initial_backoff;
        // Restart attempts within the current failure episode. Reset
        // to zero on a healthy observation.
        let mut episode_attempts: u32 = 0;

        loop {
            tokio::select! {
                () = shutdown.wait() => {
                    debug!(target: "sng_ips::health::supervisor", "shutdown signalled");
                    return;
                }
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }

            let alive_pid = self.process.is_alive().await;
            let stats_res = self.process.stats().await;
            let stats_ok = stats_res.is_ok();
            let stats_delta = match &stats_res {
                Ok(stats) => {
                    let delta = prev_stats
                        .as_ref()
                        .map_or_else(StatsDelta::zero, |prev| stats.delta_since(prev));
                    prev_stats = Some(stats.clone());
                    delta
                }
                // Stats socket did not answer — no delta to compute.
                // The lost-socket signal is carried by `process_alive`
                // below, not by a fabricated drop ratio.
                Err(_) => StatsDelta::zero(),
            };

            let probe = HealthProbe {
                // "alive" requires BOTH the PID to be live AND the
                // stats socket to answer — the classic "alive but
                // wedged" failure (PID up, control socket dead) must
                // count as a missed probe.
                process_alive: alive_pid && stats_ok,
                // The supervisor does not tail EVE; the manager owns
                // EVE-staleness detection on its own cadence. Passing
                // `true` keeps this probe's opinion scoped to liveness
                // + drop-ratio and avoids double-counting staleness.
                eve_progressing: true,
                stats_delta,
            };

            let transition = self.monitor.lock().observe(probe);

            match transition.current {
                HealthState::Healthy => {
                    // Promote the active config to last-known-good and
                    // close out any in-flight failure episode.
                    self.last_known_good
                        .store(Some(self.active_config.load_full()));
                    backoff = self.config.restart_initial_backoff;
                    episode_attempts = 0;
                }
                HealthState::Degraded => {
                    if transition.changed {
                        warn!(
                            target: "sng_ips::health::supervisor",
                            "ips degraded; traffic path unchanged, increasing scrutiny"
                        );
                    }
                }
                HealthState::Failed => {
                    let reason = if alive_pid && !stats_ok {
                        // PID alive but the stats socket went silent.
                        SubsystemRestartReason::Unresponsive
                    } else if !alive_pid {
                        SubsystemRestartReason::LivenessLost
                    } else {
                        // Alive and answering, but a quality signal
                        // (sustained drop-ratio breach) drove Failed.
                        SubsystemRestartReason::HealthFailed
                    };

                    // Interruptible backoff before the attempt so an
                    // operator stop() during a 30s window does not hang.
                    tokio::select! {
                        () = shutdown.wait() => {
                            debug!(
                                target: "sng_ips::health::supervisor",
                                "shutdown signalled during restart backoff"
                            );
                            return;
                        }
                        () = tokio::time::sleep(backoff) => {}
                    }

                    episode_attempts = episode_attempts.saturating_add(1);
                    let backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
                    let outcome = self
                        .perform_restart(reason, episode_attempts, backoff_ms)
                        .await;

                    match outcome {
                        SubsystemRestartOutcome::Recovered => {
                            // Counters reset across a restart; drop the
                            // pre-restart snapshot so the next delta is
                            // computed from the fresh baseline. The
                            // episode is over, so reset its attempt count
                            // too — otherwise a stale count from this
                            // episode would carry into the next one and
                            // could exhaust the restart budget early.
                            prev_stats = None;
                            backoff = self.config.restart_initial_backoff;
                            episode_attempts = 0;
                        }
                        SubsystemRestartOutcome::Failed => {
                            backoff = (backoff * 2).min(self.config.restart_max_backoff);
                        }
                        SubsystemRestartOutcome::Exhausted => {
                            warn!(
                                target: "sng_ips::health::supervisor",
                                attempts = episode_attempts,
                                "ips restart budget exhausted; handing off to top-level watchdog"
                            );
                            return;
                        }
                    }
                }
            }
        }
    }

    /// Issue a single restart attempt and report it. Returns the
    /// outcome; the caller owns the backoff schedule. Never sleeps —
    /// the interruptible backoff is the caller's responsibility.
    async fn perform_restart(
        &self,
        reason: SubsystemRestartReason,
        attempt: u32,
        backoff_ms: u64,
    ) -> SubsystemRestartOutcome {
        let active = self.active_config.load_full();
        // Prefer the last-known-good config; fall back to the active
        // one if the subsystem has never been healthy (cold start).
        let (restart_path, rolled_back_config) = match self.last_known_good.load_full() {
            Some(good) => {
                let rolled = *good != *active;
                (good, rolled)
            }
            None => (active, false),
        };

        // Best-effort stop: the process may already be dead (the
        // common case for a liveness-lost restart). A stop error is
        // not fatal — start() below is what matters.
        if let Err(e) = self.process.stop().await {
            debug!(
                target: "sng_ips::health::supervisor",
                error = %e,
                "stop before restart failed (process likely already dead)"
            );
        }

        let (outcome, detail) = match self.process.start(&restart_path).await {
            Ok(()) => {
                // start() returning Ok means the launch was accepted;
                // confirm the process is actually alive before we call
                // it a recovery rather than reporting an optimistic
                // success the very next probe would contradict.
                if self.process.is_alive().await {
                    info!(
                        target: "sng_ips::health::supervisor",
                        attempt,
                        config = %restart_path.display(),
                        rolled_back_config,
                        "ips restarted and is alive"
                    );
                    (SubsystemRestartOutcome::Recovered, String::new())
                } else {
                    (
                        self.failed_or_exhausted(attempt),
                        "process not alive after start".to_owned(),
                    )
                }
            }
            Err(e) => {
                warn!(
                    target: "sng_ips::health::supervisor",
                    attempt,
                    error = %e,
                    "ips restart failed"
                );
                (self.failed_or_exhausted(attempt), e.to_string())
            }
        };

        self.sink
            .record(SubsystemRestart {
                subsystem: SUBSYSTEM_NAME.to_owned(),
                reason,
                outcome,
                attempt,
                fail_open: matches!(self.config.fail_mode, FailMode::Open),
                rolled_back_config,
                backoff_ms,
                detail,
            })
            .await;

        outcome
    }

    /// Map a failed attempt to either `Failed` (retry) or
    /// `Exhausted` (give up and escalate) per the configured cap.
    fn failed_or_exhausted(&self, attempt: u32) -> SubsystemRestartOutcome {
        match self.config.restart_max_attempts {
            Some(max) if attempt >= max => SubsystemRestartOutcome::Exhausted,
            _ => SubsystemRestartOutcome::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn alive_probe(processed: u64, dropped: u64, eve_progressing: bool) -> HealthProbe {
        HealthProbe {
            process_alive: true,
            eve_progressing,
            stats_delta: StatsDelta {
                packets_processed: processed,
                alerts_emitted: 0,
                packets_dropped: dropped,
                cpu_ms: 100,
            },
        }
    }

    fn dead_probe() -> HealthProbe {
        HealthProbe {
            process_alive: false,
            eve_progressing: false,
            stats_delta: StatsDelta {
                packets_processed: 0,
                alerts_emitted: 0,
                packets_dropped: 0,
                cpu_ms: 0,
            },
        }
    }

    #[test]
    fn healthy_stays_healthy_when_everything_is_fine() {
        let mut m = HealthMonitor::new();
        let t = m.observe(alive_probe(1000, 0, true));
        assert_eq!(t.current, HealthState::Healthy);
        assert!(!t.changed);
    }

    #[test]
    fn degrades_when_drop_ratio_crosses_first_threshold() {
        let mut m = HealthMonitor::new();
        // 1 % drops crosses the default degraded threshold.
        let t = m.observe(alive_probe(990, 10, true));
        assert_eq!(t.current, HealthState::Degraded);
        assert!(t.changed);
    }

    #[test]
    fn fails_when_drop_ratio_crosses_failure_threshold() {
        let mut m = HealthMonitor::new();
        // 30 % drops > default 25 % failure threshold.
        let t = m.observe(alive_probe(700, 300, true));
        assert_eq!(t.current, HealthState::Failed);
    }

    #[test]
    fn degrades_on_stuck_eve_writer_even_when_counters_clean() {
        let mut m = HealthMonitor::new();
        let t = m.observe(alive_probe(1000, 0, false));
        assert_eq!(t.current, HealthState::Degraded);
    }

    #[test]
    fn requires_consecutive_dead_probes_to_declare_failed() {
        let mut m = HealthMonitor::new(); // default threshold = 3
        // First dead probe degrades.
        assert_eq!(m.observe(dead_probe()).current, HealthState::Degraded);
        assert_eq!(m.consecutive_dead(), 1);
        // Second dead probe still degraded.
        assert_eq!(m.observe(dead_probe()).current, HealthState::Degraded);
        assert_eq!(m.consecutive_dead(), 2);
        // Third dead probe trips Failed.
        assert_eq!(m.observe(dead_probe()).current, HealthState::Failed);
        assert_eq!(m.consecutive_dead(), 3);
    }

    #[test]
    fn recovery_resets_dead_counter() {
        let mut m = HealthMonitor::new();
        m.observe(dead_probe());
        m.observe(dead_probe());
        assert_eq!(m.consecutive_dead(), 2);
        let recovery = m.observe(alive_probe(1000, 0, true));
        assert_eq!(recovery.current, HealthState::Healthy);
        assert_eq!(m.consecutive_dead(), 0);
    }

    #[test]
    fn custom_failed_threshold_of_one_trips_immediately() {
        let mut m = HealthMonitor::new().with_failed_threshold(1);
        let t = m.observe(dead_probe());
        assert_eq!(t.current, HealthState::Failed);
    }

    #[test]
    fn custom_failed_threshold_of_zero_clamps_to_one() {
        let mut m = HealthMonitor::new().with_failed_threshold(0);
        assert_eq!(m.observe(dead_probe()).current, HealthState::Failed);
    }

    #[test]
    fn failed_state_can_recover_to_healthy_on_clean_probe() {
        let mut m = HealthMonitor::new().with_failed_threshold(1);
        m.observe(dead_probe());
        assert_eq!(m.state(), HealthState::Failed);
        let t = m.observe(alive_probe(1000, 0, true));
        assert_eq!(t.current, HealthState::Healthy);
        assert!(t.changed);
    }

    #[test]
    fn drop_ratio_at_exact_degraded_threshold_degrades() {
        // The threshold comparison is `>=`, so a probe that
        // sits exactly on the line is considered Degraded.
        let mut m = HealthMonitor::new();
        // 1 % exactly.
        let t = m.observe(alive_probe(99, 1, true));
        assert_eq!(t.current, HealthState::Degraded);
    }

    #[test]
    fn forwarding_allowed_respects_fail_mode_only_for_failed_state() {
        // Healthy / Degraded forward regardless of fail_mode.
        assert!(HealthState::Healthy.forwarding_allowed(FailMode::Closed));
        assert!(HealthState::Degraded.forwarding_allowed(FailMode::Closed));
        // Failed + Open → forward (lose coverage).
        assert!(HealthState::Failed.forwarding_allowed(FailMode::Open));
        // Failed + Closed → hold.
        assert!(!HealthState::Failed.forwarding_allowed(FailMode::Closed));
    }

    #[test]
    fn thresholds_round_trip_via_serde() {
        let t = HealthThresholds {
            degraded_drop_ratio: 0.05,
            failed_drop_ratio: 0.5,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: HealthThresholds = serde_json::from_str(&json).unwrap();
        assert!((t.degraded_drop_ratio - back.degraded_drop_ratio).abs() < 1e-9);
        assert!((t.failed_drop_ratio - back.failed_drop_ratio).abs() < 1e-9);
    }

    #[test]
    fn failed_due_to_drop_ratio_stays_failed_on_subsequent_dead_probe() {
        // Regression: if the drop-ratio branch put the monitor in
        // Failed and the very next probe is a single transient
        // dead miss, the old machine downgraded to Degraded
        // (because consecutive_dead climbed from 0 to 1 < 3) and
        // dashboards saw Failed → Degraded → Failed flap before
        // the actual recovery. Once Failed, only a clean alive
        // probe can move us out.
        let mut m = HealthMonitor::new();
        // 30 % drops trips Failed in the alive branch (process is
        // technically up but ring buffer is saturating).
        assert_eq!(
            m.observe(alive_probe(700, 300, true)).current,
            HealthState::Failed,
        );
        // A single dead probe should NOT relax the visible state
        // back to Degraded.
        let t = m.observe(dead_probe());
        assert_eq!(t.current, HealthState::Failed);
        assert!(!t.changed);
        // Still Failed after a second dead probe (counter climbing
        // toward the threshold).
        assert_eq!(m.observe(dead_probe()).current, HealthState::Failed);
        // A clean alive probe is the only thing that can recover
        // out of Failed.
        let recovery = m.observe(alive_probe(1000, 0, true));
        assert_eq!(recovery.current, HealthState::Healthy);
        assert!(recovery.changed);
    }

    #[test]
    fn transition_change_flag_only_set_when_state_actually_changes() {
        let mut m = HealthMonitor::new();
        // First observation: Healthy → Healthy → no change.
        assert!(!m.observe(alive_probe(1000, 0, true)).changed);
        // Second: Healthy → Degraded → change.
        assert!(m.observe(alive_probe(990, 10, true)).changed);
        // Third: Degraded → Degraded → no change.
        assert!(!m.observe(alive_probe(990, 10, true)).changed);
    }
}

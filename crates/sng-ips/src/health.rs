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

use serde::{Deserialize, Serialize};

use crate::process::StatsDelta;

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

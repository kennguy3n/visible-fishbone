//! Per-listener health state machine + manager summary.
//!
//! The supervisor calls into this module on a periodic timer to
//! convert raw observations (Envoy alive? admin port reachable?
//! ext-authz handler responsive?) into a three-state outcome the
//! manager publishes on its health report.
//!
//! Distilled to the same three states as `sng-ips::health`:
//! `Healthy`, `Degraded`, `Failed`. The mapping rules are:
//!
//! * `Healthy` — Envoy alive AND admin port reachable AND the
//!   ext-authz handler emitted a verdict in the last
//!   `verdict_staleness_window`.
//! * `Degraded` — Envoy alive but one of the secondary signals
//!   is missing (admin port down, no verdict in the window).
//!   Traffic still flows; the manager raises the operator
//!   alert level.
//! * `Failed` — Envoy is dead / unreachable. The supervisor
//!   applies the operator-configured fail mode (open / closed).

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Operator-controlled action when Envoy is unhealthy. Mirrors
/// the same enum on sng-ips so an operator only learns one
/// vocabulary.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Keep traffic flowing without TLS interception when Envoy
    /// is down. Acceptable when the firewall + IPS still provide
    /// L3-L7 coverage.
    Open,
    /// Drop all egress traffic until Envoy is restored. Required
    /// for tenants that committed to no-egress-without-inspection
    /// compliance.
    Closed,
}

/// State output by the health state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    /// Envoy alive + admin port reachable + recent verdict.
    Healthy,
    /// Envoy alive but one secondary signal missing.
    Degraded,
    /// Envoy unreachable. Apply fail mode.
    Failed,
    /// No probe observed yet. Initial state.
    #[default]
    Unknown,
}

/// Single per-tick probe. Built by the manager from the process
/// + handler observations and fed into [`evaluate`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthProbe {
    /// Process supervisor `is_alive()` result.
    pub envoy_alive: bool,
    /// Admin port healthcheck — a TCP connect to the admin port
    /// succeeded.
    pub admin_port_reachable: bool,
    /// Wall time since the ext-authz handler last emitted a
    /// verdict. `None` when no verdict has been observed since
    /// process start (cold start, no traffic yet).
    pub since_last_verdict: Option<Duration>,
    /// Acceptable staleness window. The state machine treats
    /// `Some(d) > verdict_staleness_window` as degradation.
    pub verdict_staleness_window: Duration,
}

/// One health snapshot. Returned by [`evaluate`] and surfaced
/// on the manager's [`ManagerHealth`] report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub state: HealthState,
    /// Free-text explanation for the operator dashboard —
    /// "envoy unreachable", "no verdict for 60s", etc.
    pub detail: String,
}

impl HealthReport {
    /// Build a healthy report.
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            state: HealthState::Healthy,
            detail: "envoy alive, admin reachable, recent verdict observed".into(),
        }
    }
}

/// Pure health-state evaluator. Same probe shape always
/// produces the same state.
#[must_use]
pub fn evaluate(p: &HealthProbe) -> HealthReport {
    if !p.envoy_alive {
        return HealthReport {
            state: HealthState::Failed,
            detail: "envoy process not alive".into(),
        };
    }
    if !p.admin_port_reachable {
        return HealthReport {
            state: HealthState::Degraded,
            detail: "envoy admin port unreachable".into(),
        };
    }
    if let Some(idle) = p.since_last_verdict {
        if idle > p.verdict_staleness_window {
            return HealthReport {
                state: HealthState::Degraded,
                detail: format!(
                    "no verdict in {idle_s}s (limit {limit_s}s)",
                    idle_s = idle.as_secs(),
                    limit_s = p.verdict_staleness_window.as_secs()
                ),
            };
        }
    }
    HealthReport::healthy()
}

/// Aggregate health snapshot the manager publishes on its
/// status endpoint. Wraps the [`HealthReport`] plus the
/// operator-controlled fail mode so a downstream dashboard can
/// render the full picture from one document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagerHealth {
    pub report: HealthReport,
    pub fail_mode: FailMode,
    /// Computed wire-level posture given the report + fail mode.
    /// `true` means traffic flows; `false` means the SWG drops
    /// requests under the active fail mode.
    pub traffic_permitted: bool,
}

impl ManagerHealth {
    /// Build the aggregate by applying `fail_mode` to the
    /// underlying report.
    #[must_use]
    pub fn from(report: HealthReport, fail_mode: FailMode) -> Self {
        // Healthy / Degraded / Unknown always permit traffic —
        // the SWG only stops the world on Failed, at which point
        // the operator-chosen fail mode decides whether to keep
        // traffic flowing (open) or drop everything (closed).
        let traffic_permitted = match report.state {
            HealthState::Healthy | HealthState::Degraded | HealthState::Unknown => true,
            HealthState::Failed => matches!(fail_mode, FailMode::Open),
        };
        Self {
            report,
            fail_mode,
            traffic_permitted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn probe(alive: bool, admin: bool, idle: Option<Duration>) -> HealthProbe {
        HealthProbe {
            envoy_alive: alive,
            admin_port_reachable: admin,
            since_last_verdict: idle,
            verdict_staleness_window: Duration::from_secs(30),
        }
    }

    #[test]
    fn healthy_when_all_signals_good() {
        let r = evaluate(&probe(true, true, Some(Duration::from_secs(2))));
        assert_eq!(r.state, HealthState::Healthy);
    }

    #[test]
    fn healthy_when_no_verdict_yet() {
        // Cold start with no traffic — not a degradation.
        let r = evaluate(&probe(true, true, None));
        assert_eq!(r.state, HealthState::Healthy);
    }

    #[test]
    fn failed_when_envoy_not_alive() {
        let r = evaluate(&probe(false, true, Some(Duration::from_secs(1))));
        assert_eq!(r.state, HealthState::Failed);
        assert!(r.detail.contains("alive"), "{}", r.detail);
    }

    #[test]
    fn degraded_when_admin_port_unreachable_but_envoy_alive() {
        let r = evaluate(&probe(true, false, Some(Duration::from_secs(1))));
        assert_eq!(r.state, HealthState::Degraded);
        assert!(r.detail.contains("admin"), "{}", r.detail);
    }

    #[test]
    fn degraded_when_verdict_stale() {
        let r = evaluate(&probe(true, true, Some(Duration::from_secs(60))));
        assert_eq!(r.state, HealthState::Degraded);
        assert!(r.detail.contains("no verdict"), "{}", r.detail);
    }

    #[test]
    fn manager_health_open_permits_traffic_on_failed() {
        let r = HealthReport {
            state: HealthState::Failed,
            detail: "dead".into(),
        };
        let mh = ManagerHealth::from(r, FailMode::Open);
        assert!(
            mh.traffic_permitted,
            "open mode must permit traffic on failed"
        );
    }

    #[test]
    fn manager_health_closed_blocks_traffic_on_failed() {
        let r = HealthReport {
            state: HealthState::Failed,
            detail: "dead".into(),
        };
        let mh = ManagerHealth::from(r, FailMode::Closed);
        assert!(
            !mh.traffic_permitted,
            "closed mode must block traffic on failed"
        );
    }

    #[test]
    fn manager_health_always_permits_on_degraded_regardless_of_mode() {
        for fm in [FailMode::Open, FailMode::Closed] {
            let r = HealthReport {
                state: HealthState::Degraded,
                detail: "slow".into(),
            };
            let mh = ManagerHealth::from(r, fm);
            assert!(
                mh.traffic_permitted,
                "degraded ({fm:?}) must permit traffic"
            );
        }
    }

    #[test]
    fn unknown_initial_state_permits_traffic() {
        // The manager starts at Unknown — we must NOT drop
        // traffic just because no probe has run yet.
        let r = HealthReport {
            state: HealthState::Unknown,
            detail: "no probe yet".into(),
        };
        for fm in [FailMode::Open, FailMode::Closed] {
            let mh = ManagerHealth::from(r.clone(), fm);
            assert!(mh.traffic_permitted, "unknown ({fm:?}) must permit");
        }
    }

    #[test]
    fn report_serializes_with_stable_field_names() {
        let r = HealthReport::healthy();
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"state\":\"healthy\""));
        assert!(json.contains("\"detail\""));
    }
}

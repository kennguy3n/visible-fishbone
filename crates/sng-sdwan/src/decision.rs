//! Steering decision + structured reason.
//!
//! The brain returns a [`SteeringDecision`] for every
//! [`crate::request::SteeringRequest`]. The decision
//! always carries a [`SteeringReason`] — even the deny
//! / no-path outcomes — so dashboards bucket selections
//! by structured cause rather than by free-form string.

use serde::{Deserialize, Serialize};

use crate::path::{PathId, TrafficClass};
use crate::score::ScoreBreakdown;

/// Structured reason the brain returned this
/// decision. Each variant maps to a stable wire string
/// via [`SteeringReason::as_str`] — the value lands on
/// [`sng_core::events::SdwanEvent::steering_decision`]
/// and shows up on ops dashboards.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SteeringReason {
    /// A path was selected — the lowest-scoring fresh,
    /// in-budget candidate.
    Best,
    /// No fresh + usable candidate was in budget — every
    /// scored candidate exceeded at least one SLO floor
    /// (latency / loss / jitter) — so the selector
    /// chose the *least-bad* out-of-budget candidate
    /// (lowest scoring path among those that failed a
    /// floor). The decision still surfaces the *winning*
    /// path id; this reason just tells dashboards that
    /// the winning path is degraded relative to the
    /// policy's SLO floors.
    ///
    /// Note: this is "fallback" in the sense that policy
    /// **fell through to** out-of-budget candidates after
    /// finding nothing in-budget — NOT in the sense that
    /// some other in-budget candidate exists. If any
    /// in-budget candidate existed it would have won as
    /// [`Self::Best`] instead.
    ///
    /// Useful for ops alerting on "we're regularly
    /// running on a path below floor".
    FallbackBelowFloor,
    /// The flow stayed pinned to its previously-selected
    /// path because the [`crate::policy::SdwanPolicy::sticky_window_ms`]
    /// hadn't elapsed and the prior choice was still
    /// fresh + in-budget. Distinct from
    /// [`Self::Best`] so dashboards can quantify how
    /// often sticky-flow pinning is suppressing a
    /// reselection.
    StickyPinned,
    /// No path is eligible for the requested
    /// [`TrafficClass`]. The data path is expected to
    /// map this to a deny verdict.
    NoAvailablePath,
    /// Every path eligible for the class lacked usable
    /// probe data. "Usable" here means: a probe exists,
    /// was observed within `probe_max_age_ms` of
    /// `now_ms`, AND every metric on it (`latency_ms`,
    /// `loss_pct`, `jitter_ms`) is finite (not NaN, not
    /// ±INFINITY). A NaN-metric probe is informationally
    /// equivalent to a missing one — the selector cannot
    /// score it without leaking a non-finite total onto
    /// the wire event — so it counts as "stale" for the
    /// purposes of this reason. Distinct from
    /// `NoAvailablePath` so ops can tell "we have paths
    /// but their probes are stale / broken" from "the
    /// path catalog is empty".
    AllProbesStale,
}

impl SteeringReason {
    /// Stable wire string. The value lands on
    /// [`sng_core::events::SdwanEvent::steering_decision`]
    /// and ops dashboards bucket by it.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Best => "best",
            Self::FallbackBelowFloor => "fallback_below_floor",
            Self::StickyPinned => "sticky_pinned",
            Self::NoAvailablePath => "no_available_path",
            Self::AllProbesStale => "all_probes_stale",
        }
    }

    /// True iff this reason corresponds to a path
    /// having been selected. The data path uses this
    /// shape to decide between "use the selected path"
    /// and "drop / deny the flow".
    #[must_use]
    pub const fn is_selected(&self) -> bool {
        matches!(
            self,
            Self::Best | Self::FallbackBelowFloor | Self::StickyPinned
        )
    }
}

/// Steering decision returned by
/// [`crate::service::SdwanService::evaluate`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SteeringDecision {
    /// The selected path id, when a path was selected.
    /// `None` for [`SteeringReason::NoAvailablePath`] /
    /// [`SteeringReason::AllProbesStale`].
    pub path_id: Option<PathId>,
    /// Structured reason. Always present.
    pub reason: SteeringReason,
    /// Score breakdown for the selected path. `None`
    /// when no path was selected.
    pub score: Option<ScoreBreakdown>,
    /// Traffic class the decision was for. Echoed back
    /// for the telemetry emission code path so it
    /// doesn't have to hold the request alongside the
    /// decision.
    pub traffic_class: TrafficClass,
}

impl SteeringDecision {
    /// Convenience constructor for a no-path decision.
    /// Always carries `traffic_class` so the telemetry
    /// emission can label the event correctly.
    #[must_use]
    pub fn no_path(reason: SteeringReason, traffic_class: TrafficClass) -> Self {
        debug_assert!(
            !reason.is_selected(),
            "no_path() called with a selected reason: {reason:?}"
        );
        Self {
            path_id: None,
            reason,
            score: None,
            traffic_class,
        }
    }

    /// Convenience constructor for a selected-path
    /// decision.
    #[must_use]
    pub fn selected(
        path_id: PathId,
        reason: SteeringReason,
        score: ScoreBreakdown,
        traffic_class: TrafficClass,
    ) -> Self {
        debug_assert!(
            reason.is_selected(),
            "selected() called with a non-selected reason: {reason:?}"
        );
        Self {
            path_id: Some(path_id),
            reason,
            score: Some(score),
            traffic_class,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn reason_wire_strings_are_stable_snake_case() {
        assert_eq!(SteeringReason::Best.as_str(), "best");
        assert_eq!(
            SteeringReason::FallbackBelowFloor.as_str(),
            "fallback_below_floor"
        );
        assert_eq!(SteeringReason::StickyPinned.as_str(), "sticky_pinned");
        assert_eq!(
            SteeringReason::NoAvailablePath.as_str(),
            "no_available_path"
        );
        assert_eq!(SteeringReason::AllProbesStale.as_str(), "all_probes_stale");
    }

    #[test]
    fn is_selected_only_true_for_pick_variants() {
        assert!(SteeringReason::Best.is_selected());
        assert!(SteeringReason::FallbackBelowFloor.is_selected());
        assert!(SteeringReason::StickyPinned.is_selected());
        assert!(!SteeringReason::NoAvailablePath.is_selected());
        assert!(!SteeringReason::AllProbesStale.is_selected());
    }

    #[test]
    fn no_path_constructor_clears_path_and_score() {
        let d = SteeringDecision::no_path(SteeringReason::AllProbesStale, TrafficClass::Bulk);
        assert!(d.path_id.is_none());
        assert!(d.score.is_none());
        assert_eq!(d.reason, SteeringReason::AllProbesStale);
        assert_eq!(d.traffic_class, TrafficClass::Bulk);
    }

    #[test]
    fn selected_constructor_carries_path_and_score() {
        let s = ScoreBreakdown::new(10.0, 1.0, 0.5, 0.0, 11.5);
        let d = SteeringDecision::selected(
            PathId::new("mpls-east"),
            SteeringReason::Best,
            s,
            TrafficClass::Interactive,
        );
        assert_eq!(d.path_id, Some(PathId::new("mpls-east")));
        assert_eq!(d.score, Some(s));
        assert_eq!(d.reason, SteeringReason::Best);
    }
}

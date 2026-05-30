//! SD-WAN runtime stats — atomic counters surfaced to
//! ops dashboards via [`SdwanStatsSnapshot`].

use crate::decision::SteeringReason;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Live atomic counters. All operations use
/// [`Ordering::Relaxed`] — these are pure observability,
/// not coordination primitives, and the cost difference
/// vs. `SeqCst` is measurable on the data path.
///
/// The invariant `requests_evaluated == sum(reason_*)`
/// holds across all counters — every evaluation bumps
/// exactly one of the reason counters in
/// [`SdwanStats::record_decision`].
#[derive(Debug, Default)]
pub struct SdwanStats {
    /// Total steering requests the brain evaluated.
    requests_evaluated: AtomicU64,
    /// Best-scoring candidate selected (the typical
    /// happy path).
    reason_best: AtomicU64,
    /// Best candidate failed an SLO floor; selector fell
    /// through to a lower-scored but in-budget candidate.
    reason_fallback_below_floor: AtomicU64,
    /// Sticky-flow pinning kept the previously-selected
    /// path even though a new candidate now scores
    /// better. Pure observability — operators alert when
    /// this ratio is too high or too low.
    reason_sticky_pinned: AtomicU64,
    /// No path was eligible for the requested traffic
    /// class. Distinct from `all_probes_stale` so
    /// dashboards can spot "catalog hole" vs. "probe
    /// pipeline broken".
    reason_no_available_path: AtomicU64,
    /// Every candidate's probe was stale (or out of
    /// floor).
    reason_all_probes_stale: AtomicU64,
    /// Successful policy bundle reloads.
    bundle_loads: AtomicU64,
    /// Failed policy bundle reloads.
    bundle_load_failures: AtomicU64,
    /// Telemetry submissions dropped because the egress
    /// channel was full (`try_send` saturated).
    telemetry_drops: AtomicU64,
    /// Provider failures observed.
    provider_failures: AtomicU64,
}

impl SdwanStats {
    /// Bump the appropriate reason counter. The service
    /// calls this exactly once per evaluation, ensuring
    /// `requests_evaluated == sum(reason_*)`.
    pub fn record_decision(&self, reason: &SteeringReason) {
        self.requests_evaluated.fetch_add(1, Ordering::Relaxed);
        let counter = match reason {
            SteeringReason::Best => &self.reason_best,
            SteeringReason::FallbackBelowFloor => &self.reason_fallback_below_floor,
            SteeringReason::StickyPinned => &self.reason_sticky_pinned,
            SteeringReason::NoAvailablePath => &self.reason_no_available_path,
            SteeringReason::AllProbesStale => &self.reason_all_probes_stale,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// One successful bundle reload.
    pub fn record_bundle_load(&self) {
        self.bundle_loads.fetch_add(1, Ordering::Relaxed);
    }

    /// One failed bundle reload.
    pub fn record_bundle_load_failure(&self) {
        self.bundle_load_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// One telemetry submission dropped at the egress.
    pub fn record_telemetry_drop(&self) {
        self.telemetry_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// One provider failure observed.
    pub fn record_provider_failure(&self) {
        self.provider_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomic snapshot for serialization. Reads each
    /// counter independently; values are observably
    /// consistent within each counter but the snapshot
    /// as a whole is not a global-instantaneous read.
    #[must_use]
    pub fn snapshot(&self) -> SdwanStatsSnapshot {
        SdwanStatsSnapshot {
            requests_evaluated: self.requests_evaluated.load(Ordering::Relaxed),
            reason_best: self.reason_best.load(Ordering::Relaxed),
            reason_fallback_below_floor: self.reason_fallback_below_floor.load(Ordering::Relaxed),
            reason_sticky_pinned: self.reason_sticky_pinned.load(Ordering::Relaxed),
            reason_no_available_path: self.reason_no_available_path.load(Ordering::Relaxed),
            reason_all_probes_stale: self.reason_all_probes_stale.load(Ordering::Relaxed),
            bundle_loads: self.bundle_loads.load(Ordering::Relaxed),
            bundle_load_failures: self.bundle_load_failures.load(Ordering::Relaxed),
            telemetry_drops: self.telemetry_drops.load(Ordering::Relaxed),
            provider_failures: self.provider_failures.load(Ordering::Relaxed),
        }
    }
}

/// Serializable snapshot of [`SdwanStats`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdwanStatsSnapshot {
    /// Total evaluations.
    pub requests_evaluated: u64,
    /// Best-candidate selections.
    pub reason_best: u64,
    /// Fallback selections (best candidate failed SLO floor).
    pub reason_fallback_below_floor: u64,
    /// Sticky-pin selections.
    pub reason_sticky_pinned: u64,
    /// No-path denies.
    pub reason_no_available_path: u64,
    /// All-stale denies.
    pub reason_all_probes_stale: u64,
    /// Successful bundle reloads.
    pub bundle_loads: u64,
    /// Failed bundle reloads.
    pub bundle_load_failures: u64,
    /// Telemetry submissions dropped.
    pub telemetry_drops: u64,
    /// Provider failures.
    pub provider_failures: u64,
}

impl SdwanStatsSnapshot {
    /// True iff the snapshot's reason counters sum to
    /// `requests_evaluated`. Useful for unit tests
    /// confirming the invariant holds.
    #[must_use]
    pub fn invariant_holds(&self) -> bool {
        self.requests_evaluated
            == self.reason_best
                + self.reason_fallback_below_floor
                + self.reason_sticky_pinned
                + self.reason_no_available_path
                + self.reason_all_probes_stale
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn record_decision_bumps_both_total_and_per_reason() {
        let stats = SdwanStats::default();
        stats.record_decision(&SteeringReason::Best);
        stats.record_decision(&SteeringReason::Best);
        stats.record_decision(&SteeringReason::AllProbesStale);
        let snap = stats.snapshot();
        assert_eq!(snap.requests_evaluated, 3);
        assert_eq!(snap.reason_best, 2);
        assert_eq!(snap.reason_all_probes_stale, 1);
        assert!(snap.invariant_holds());
    }

    #[test]
    fn invariant_holds_across_all_variants() {
        // Hit every reason once; the invariant must
        // still hold.
        let stats = SdwanStats::default();
        stats.record_decision(&SteeringReason::Best);
        stats.record_decision(&SteeringReason::FallbackBelowFloor);
        stats.record_decision(&SteeringReason::StickyPinned);
        stats.record_decision(&SteeringReason::NoAvailablePath);
        stats.record_decision(&SteeringReason::AllProbesStale);
        let snap = stats.snapshot();
        assert_eq!(snap.requests_evaluated, 5);
        assert!(snap.invariant_holds());
    }

    #[test]
    fn telemetry_and_bundle_counters_independent_of_evaluation_total() {
        let stats = SdwanStats::default();
        stats.record_bundle_load();
        stats.record_bundle_load();
        stats.record_bundle_load_failure();
        stats.record_telemetry_drop();
        stats.record_provider_failure();
        let snap = stats.snapshot();
        // These counters do NOT participate in the
        // requests_evaluated invariant — they're
        // operational, not decision-shape.
        assert_eq!(snap.requests_evaluated, 0);
        assert_eq!(snap.bundle_loads, 2);
        assert_eq!(snap.bundle_load_failures, 1);
        assert_eq!(snap.telemetry_drops, 1);
        assert_eq!(snap.provider_failures, 1);
        assert!(snap.invariant_holds());
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        // Default snapshot must serialize / deserialize
        // cleanly — the ops endpoint uses serde_json to
        // surface this.
        let stats = SdwanStats::default();
        stats.record_decision(&SteeringReason::Best);
        let snap = stats.snapshot();
        let s = serde_json::to_string(&snap).unwrap();
        let back: SdwanStatsSnapshot = serde_json::from_str(&s).unwrap();
        assert_eq!(snap, back);
    }
}

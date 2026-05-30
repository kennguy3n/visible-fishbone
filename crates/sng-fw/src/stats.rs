//! Counters the firewall surfaces to operations. The
//! counters are intentionally minimal — three buckets:
//! flow-lifecycle, verdict-cache, drop reasons. Anything
//! richer (per-rule hit counts, per-app byte totals) goes
//! through the telemetry pipeline as a `FlowEvent` and is
//! aggregated downstream.
//!
//! Atomic counters with `Ordering::Relaxed`. The values are
//! observability data only — no decision in the firewall
//! depends on their precise ordering, and the relaxed
//! ordering keeps the hot path free of barriers.

use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

/// Live counters. Cheap to read (snapshot via [`Self::snapshot`]).
#[derive(Debug, Default)]
pub struct FwStats {
    flows_created: AtomicU64,
    flows_evicted_idle: AtomicU64,
    flows_evicted_capacity: AtomicU64,
    verdict_cache_hits: AtomicU64,
    verdict_cache_misses: AtomicU64,
    policy_evaluations: AtomicU64,
    policy_failures: AtomicU64,
    verdict_allows: AtomicU64,
    verdict_denies: AtomicU64,
    verdict_inspects: AtomicU64,
    telemetry_events_emitted: AtomicU64,
    telemetry_events_dropped: AtomicU64,
    state_update_races: AtomicU64,
}

/// Sampled view of the counters at a point in time. The
/// firewall snapshots this at the end of each maintenance
/// tick and pushes it to the telemetry pipeline as an
/// engine-stats event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FwStatsSnapshot {
    pub flows_created: u64,
    pub flows_evicted_idle: u64,
    pub flows_evicted_capacity: u64,
    pub verdict_cache_hits: u64,
    pub verdict_cache_misses: u64,
    pub policy_evaluations: u64,
    pub policy_failures: u64,
    pub verdict_allows: u64,
    pub verdict_denies: u64,
    pub verdict_inspects: u64,
    pub telemetry_events_emitted: u64,
    pub telemetry_events_dropped: u64,
    /// Number of times `FwService::observe_packet` completed
    /// policy evaluation but found the conntrack entry had
    /// been swept away before the state update could land
    /// (a race between a producer thread and the
    /// maintenance `tick()`). Should be near-zero in steady
    /// state; non-trivial values indicate the conntrack
    /// idle timeouts are too aggressive relative to the
    /// data-path latency.
    pub state_update_races: u64,
}

impl FwStats {
    /// Construct a fresh counter set with every field at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment counters when a new flow lands in conntrack.
    pub fn record_flow_created(&self) {
        self.flows_created.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment when an idle sweep drops a flow.
    pub fn record_flow_evicted_idle(&self) {
        self.flows_evicted_idle.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment when a capacity-pressure eviction kicks an
    /// older flow out to make room.
    pub fn record_flow_evicted_capacity(&self) {
        self.flows_evicted_capacity.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment on a verdict-cache hit (no policy eval).
    pub fn record_cache_hit(&self) {
        self.verdict_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment on a verdict-cache miss (cold flow, policy
    /// eval ran).
    pub fn record_cache_miss(&self) {
        self.verdict_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment after a policy evaluation completes,
    /// regardless of outcome.
    pub fn record_policy_eval(&self) {
        self.policy_evaluations.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment when the policy engine returns
    /// [`crate::error::FwError::PolicyUnavailable`].
    pub fn record_policy_failure(&self) {
        self.policy_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment by a verdict's wire-level disposition.
    pub fn record_verdict(&self, disposition: sng_core::envelope::Verdict) {
        use sng_core::envelope::Verdict;
        match disposition {
            Verdict::Allow | Verdict::Alert => {
                self.verdict_allows.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Deny => {
                self.verdict_denies.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Inspect => {
                self.verdict_inspects.fetch_add(1, Ordering::Relaxed);
            }
            Verdict::Log => {
                // Logs aren't allows or denies; they land in
                // their own bucket implicitly (allows -
                // denies - inspects from the total event count).
            }
        }
    }

    /// Increment when a flow event lands in the telemetry
    /// pipeline.
    pub fn record_telemetry_emit(&self) {
        self.telemetry_events_emitted
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment when a flow event is dropped because the
    /// telemetry pipeline is back-pressured.
    pub fn record_telemetry_drop(&self) {
        self.telemetry_events_dropped
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Increment when an `observe_packet` call discovers
    /// the conntrack entry it had just minted/lookedup has
    /// already been swept away by the time the `with_entry`
    /// closure runs. See [`FwStatsSnapshot::state_update_races`]
    /// for ops semantics.
    pub fn record_state_update_race(&self) {
        self.state_update_races.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot every counter into a serialisable view.
    #[must_use]
    pub fn snapshot(&self) -> FwStatsSnapshot {
        FwStatsSnapshot {
            flows_created: self.flows_created.load(Ordering::Relaxed),
            flows_evicted_idle: self.flows_evicted_idle.load(Ordering::Relaxed),
            flows_evicted_capacity: self.flows_evicted_capacity.load(Ordering::Relaxed),
            verdict_cache_hits: self.verdict_cache_hits.load(Ordering::Relaxed),
            verdict_cache_misses: self.verdict_cache_misses.load(Ordering::Relaxed),
            policy_evaluations: self.policy_evaluations.load(Ordering::Relaxed),
            policy_failures: self.policy_failures.load(Ordering::Relaxed),
            verdict_allows: self.verdict_allows.load(Ordering::Relaxed),
            verdict_denies: self.verdict_denies.load(Ordering::Relaxed),
            verdict_inspects: self.verdict_inspects.load(Ordering::Relaxed),
            telemetry_events_emitted: self.telemetry_events_emitted.load(Ordering::Relaxed),
            telemetry_events_dropped: self.telemetry_events_dropped.load(Ordering::Relaxed),
            state_update_races: self.state_update_races.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::envelope::Verdict;

    #[test]
    fn snapshot_is_all_zero_after_construction() {
        let s = FwStats::new();
        let snap = s.snapshot();
        assert_eq!(snap.flows_created, 0);
        assert_eq!(snap.verdict_cache_hits, 0);
        assert_eq!(snap.policy_evaluations, 0);
        assert_eq!(snap.telemetry_events_dropped, 0);
    }

    #[test]
    fn flow_lifecycle_counters_increment_independently() {
        let s = FwStats::new();
        s.record_flow_created();
        s.record_flow_created();
        s.record_flow_evicted_idle();
        s.record_flow_evicted_capacity();
        let snap = s.snapshot();
        assert_eq!(snap.flows_created, 2);
        assert_eq!(snap.flows_evicted_idle, 1);
        assert_eq!(snap.flows_evicted_capacity, 1);
    }

    #[test]
    fn state_update_race_counter_increments_and_snapshots() {
        let s = FwStats::new();
        s.record_state_update_race();
        s.record_state_update_race();
        s.record_state_update_race();
        let snap = s.snapshot();
        assert_eq!(snap.state_update_races, 3);
    }

    #[test]
    fn cache_hit_miss_separate() {
        let s = FwStats::new();
        for _ in 0..7 {
            s.record_cache_hit();
        }
        for _ in 0..3 {
            s.record_cache_miss();
        }
        let snap = s.snapshot();
        assert_eq!(snap.verdict_cache_hits, 7);
        assert_eq!(snap.verdict_cache_misses, 3);
    }

    #[test]
    fn verdict_buckets_route_correctly() {
        let s = FwStats::new();
        s.record_verdict(Verdict::Allow);
        s.record_verdict(Verdict::Allow);
        s.record_verdict(Verdict::Alert);
        s.record_verdict(Verdict::Deny);
        s.record_verdict(Verdict::Inspect);
        s.record_verdict(Verdict::Log);
        let snap = s.snapshot();
        // Allow + Alert share a bucket (Alert = allow-with-flag).
        assert_eq!(snap.verdict_allows, 3);
        assert_eq!(snap.verdict_denies, 1);
        assert_eq!(snap.verdict_inspects, 1);
        // Log has no counter (implicit by subtraction).
    }

    #[test]
    fn telemetry_emit_drop_separate() {
        let s = FwStats::new();
        s.record_telemetry_emit();
        s.record_telemetry_emit();
        s.record_telemetry_drop();
        let snap = s.snapshot();
        assert_eq!(snap.telemetry_events_emitted, 2);
        assert_eq!(snap.telemetry_events_dropped, 1);
    }

    #[test]
    fn snapshot_is_serializable_to_json() {
        // Pin the wire-shape contract — every field is a
        // plain u64 so serde_json can produce a flat
        // object. If a future contributor adds a non-Serialize
        // field, this test fails immediately.
        let s = FwStats::new();
        s.record_flow_created();
        let snap = s.snapshot();
        let json = serde_json::to_string(&snap).expect("serialize");
        assert!(json.contains("\"flows_created\":1"));
    }
}

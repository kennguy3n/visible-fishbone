//! IPS subsystem counters.
//!
//! Counters are atomic `u64`s incremented from the data
//! path; the `snapshot()` method copies them into a
//! `serde`-friendly struct for dashboards / JSON
//! diagnostics. The ordering is `Relaxed` because the
//! counters are purely observability — they never gate any
//! algorithm, so cross-counter consistency at a particular
//! snapshot instant is not required.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic IPS counters. One instance per [`crate::IpsService`].
#[derive(Debug, Default)]
pub struct IpsStats {
    payloads_scanned: AtomicU64,
    bytes_scanned: AtomicU64,
    hits_total: AtomicU64,
    hits_alert: AtomicU64,
    hits_drop: AtomicU64,
    hits_reset: AtomicU64,
    hits_block: AtomicU64,
    bundle_loads: AtomicU64,
    bundle_load_failures: AtomicU64,
    telemetry_drops: AtomicU64,
    reassembly_window_overflows: AtomicU64,
    inspection_table_full: AtomicU64,
    suppressed_dup_hits: AtomicU64,
}

/// Serializable snapshot of [`IpsStats`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpsStatsSnapshot {
    /// Number of payloads handed to the matcher.
    pub payloads_scanned: u64,
    /// Total bytes presented to the IPS service via
    /// [`crate::service::IpsService::observe_payload`]
    /// (`PayloadObservation::payload.len()` summed across
    /// every call).
    ///
    /// This is an **input-throughput** counter, not a
    /// matcher-work counter. Under the consume-and-
    /// lookback model the assembled buffer the matcher
    /// actually scans on a given call includes lookback
    /// bytes carried over from the previous scan, so the
    /// per-call number of bytes the matcher compared
    /// against patterns can exceed the per-call payload
    /// length. Operators interpreting this counter on a
    /// dashboard should read it as "ingest volume," not
    /// "matcher byte-compare volume." There is no
    /// separate work counter today; the matcher's cost is
    /// instead bounded by the per-flow reassembly window
    /// (`reassembly_window_overflows` surfaces when that
    /// bound is hit).
    pub bytes_scanned: u64,
    /// Total **observations** (`observe_payload` calls)
    /// that produced at least one signature hit. This is
    /// a per-observation counter, not a per-signature
    /// counter: a single observation that fires three
    /// signatures still bumps `hits_total` by exactly 1.
    /// The matcher's per-hit detail lands on the
    /// telemetry pipeline as individual
    /// [`sng_core::events::IpsEvent`]s, which is the
    /// authoritative per-signature audit log; these
    /// stats are observability for the **service**, not
    /// the matcher.
    pub hits_total: u64,
    /// Observations whose folded action was `Alert`
    /// (per-observation, not per-hit — same semantics as
    /// `hits_total`).
    pub hits_alert: u64,
    /// Observations whose folded action was `Drop`
    /// (per-observation, see `hits_total`).
    pub hits_drop: u64,
    /// Observations whose folded action was `Reset`
    /// (per-observation, see `hits_total`).
    pub hits_reset: u64,
    /// Observations whose folded action was `Block`
    /// (per-observation, see `hits_total`).
    pub hits_block: u64,
    /// Bundle reload successes — the number of times
    /// `on_policy_reload` was called with a valid
    /// signature set.
    pub bundle_loads: u64,
    /// Bundle reload failures — counted when a compile
    /// of the candidate signature set errored. The
    /// previous set stays in place.
    pub bundle_load_failures: u64,
    /// Times the IPS service dropped an alert because
    /// the telemetry channel rejected it (closed or
    /// full). Operators correlate this with the
    /// pipeline's own egress stats.
    pub telemetry_drops: u64,
    /// Bytes dropped because the per-flow reassembly
    /// buffer overflowed its sliding window. If this is
    /// non-zero, ops tunes the buffer size up.
    pub reassembly_window_overflows: u64,
    /// Times the inspection-state table refused a new
    /// flow because it was at capacity. Operators tune
    /// `max_flows` up.
    pub inspection_table_full: u64,
    /// Times a hit was suppressed because the same
    /// (flow, signature) tuple fired again inside the
    /// dedup window. Useful for tuning the dedup TTL.
    pub suppressed_dup_hits: u64,
}

impl IpsStats {
    /// Record one payload scan.
    pub fn record_payload_scanned(&self, bytes: u64) {
        self.payloads_scanned.fetch_add(1, Ordering::Relaxed);
        self.bytes_scanned.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record one signature hit with its folded action.
    pub fn record_hit(&self, action: crate::signature::Action) {
        use crate::signature::Action;
        self.hits_total.fetch_add(1, Ordering::Relaxed);
        match action {
            Action::Alert => self.hits_alert.fetch_add(1, Ordering::Relaxed),
            Action::Drop => self.hits_drop.fetch_add(1, Ordering::Relaxed),
            Action::Reset => self.hits_reset.fetch_add(1, Ordering::Relaxed),
            Action::Block => self.hits_block.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Record one bundle load (successful).
    pub fn record_bundle_load(&self) {
        self.bundle_loads.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one bundle load failure.
    pub fn record_bundle_load_failure(&self) {
        self.bundle_load_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one telemetry-channel drop.
    pub fn record_telemetry_drop(&self) {
        self.telemetry_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Record bytes that fell off the reassembly window.
    pub fn record_reassembly_overflow(&self, bytes: u64) {
        self.reassembly_window_overflows
            .fetch_add(bytes, Ordering::Relaxed);
    }

    /// Record one inspection-table-full rejection.
    pub fn record_inspection_table_full(&self) {
        self.inspection_table_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Record one dedup-suppressed hit.
    pub fn record_suppressed_dup_hit(&self) {
        self.suppressed_dup_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Capture a JSON-serialisable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> IpsStatsSnapshot {
        IpsStatsSnapshot {
            payloads_scanned: self.payloads_scanned.load(Ordering::Relaxed),
            bytes_scanned: self.bytes_scanned.load(Ordering::Relaxed),
            hits_total: self.hits_total.load(Ordering::Relaxed),
            hits_alert: self.hits_alert.load(Ordering::Relaxed),
            hits_drop: self.hits_drop.load(Ordering::Relaxed),
            hits_reset: self.hits_reset.load(Ordering::Relaxed),
            hits_block: self.hits_block.load(Ordering::Relaxed),
            bundle_loads: self.bundle_loads.load(Ordering::Relaxed),
            bundle_load_failures: self.bundle_load_failures.load(Ordering::Relaxed),
            telemetry_drops: self.telemetry_drops.load(Ordering::Relaxed),
            reassembly_window_overflows: self.reassembly_window_overflows.load(Ordering::Relaxed),
            inspection_table_full: self.inspection_table_full.load(Ordering::Relaxed),
            suppressed_dup_hits: self.suppressed_dup_hits.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::Action;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_snapshot_is_zeros() {
        let s = IpsStats::default().snapshot();
        assert_eq!(s.payloads_scanned, 0);
        assert_eq!(s.bytes_scanned, 0);
        assert_eq!(s.hits_total, 0);
        assert_eq!(s.hits_alert, 0);
        assert_eq!(s.hits_drop, 0);
        assert_eq!(s.hits_reset, 0);
        assert_eq!(s.hits_block, 0);
        assert_eq!(s.bundle_loads, 0);
        assert_eq!(s.bundle_load_failures, 0);
        assert_eq!(s.telemetry_drops, 0);
        assert_eq!(s.reassembly_window_overflows, 0);
        assert_eq!(s.inspection_table_full, 0);
        assert_eq!(s.suppressed_dup_hits, 0);
    }

    #[test]
    fn payload_scan_increments_count_and_bytes() {
        let s = IpsStats::default();
        s.record_payload_scanned(100);
        s.record_payload_scanned(50);
        let snap = s.snapshot();
        assert_eq!(snap.payloads_scanned, 2);
        assert_eq!(snap.bytes_scanned, 150);
    }

    #[test]
    fn record_hit_buckets_by_action() {
        let s = IpsStats::default();
        s.record_hit(Action::Alert);
        s.record_hit(Action::Drop);
        s.record_hit(Action::Drop);
        s.record_hit(Action::Reset);
        s.record_hit(Action::Block);
        let snap = s.snapshot();
        assert_eq!(snap.hits_total, 5);
        assert_eq!(snap.hits_alert, 1);
        assert_eq!(snap.hits_drop, 2);
        assert_eq!(snap.hits_reset, 1);
        assert_eq!(snap.hits_block, 1);
    }

    #[test]
    fn bundle_load_and_failure_counters_are_independent() {
        let s = IpsStats::default();
        s.record_bundle_load();
        s.record_bundle_load();
        s.record_bundle_load_failure();
        let snap = s.snapshot();
        assert_eq!(snap.bundle_loads, 2);
        assert_eq!(snap.bundle_load_failures, 1);
    }

    #[test]
    fn telemetry_drop_counter_increments() {
        let s = IpsStats::default();
        s.record_telemetry_drop();
        s.record_telemetry_drop();
        assert_eq!(s.snapshot().telemetry_drops, 2);
    }

    #[test]
    fn reassembly_overflow_accumulates_bytes() {
        let s = IpsStats::default();
        s.record_reassembly_overflow(64);
        s.record_reassembly_overflow(128);
        assert_eq!(s.snapshot().reassembly_window_overflows, 192);
    }

    #[test]
    fn inspection_table_full_counter_increments() {
        let s = IpsStats::default();
        s.record_inspection_table_full();
        assert_eq!(s.snapshot().inspection_table_full, 1);
    }

    #[test]
    fn suppressed_dup_hit_counter_increments() {
        let s = IpsStats::default();
        s.record_suppressed_dup_hit();
        s.record_suppressed_dup_hit();
        assert_eq!(s.snapshot().suppressed_dup_hits, 2);
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        let s = IpsStats::default();
        s.record_payload_scanned(99);
        s.record_hit(Action::Drop);
        s.record_telemetry_drop();
        let snap = s.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let round: IpsStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, round);
    }
}

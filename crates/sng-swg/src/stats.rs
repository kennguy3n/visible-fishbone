//! SWG runtime stats — atomic counters surfaced to ops
//! dashboards via [`IpsStatsSnapshot`]-style snapshots.

use crate::malware::MalwareVerdict;
use crate::policy::Posture;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Live atomic counters. All operations use
/// [`Ordering::Relaxed`] — these are pure observability,
/// not coordination primitives, and the cost difference
/// vs. SeqCst is measurable on the data path.
#[derive(Debug, Default)]
pub struct SwgStats {
    /// Total HTTP requests observed by the SWG.
    requests_observed: AtomicU64,
    /// Total bytes inspected on response bodies.
    bytes_inspected: AtomicU64,
    /// Requests that returned `Posture::Allow` /
    /// `AlertOnly` (per posture).
    posture_allow: AtomicU64,
    posture_alert_only: AtomicU64,
    posture_inspect_full: AtomicU64,
    posture_tls_bypass: AtomicU64,
    posture_quarantine: AtomicU64,
    posture_block: AtomicU64,
    /// Malware verdicts seen on response paths.
    malware_clean: AtomicU64,
    malware_suspicious: AtomicU64,
    malware_malicious: AtomicU64,
    /// Times a category lookup was a hit (provider had
    /// an entry).
    category_hits: AtomicU64,
    /// Times a category lookup was a miss (provider
    /// returned `None`, request fell through to the
    /// uncategorised posture).
    category_misses: AtomicU64,
    /// Times a reputation lookup was a hit.
    reputation_hits: AtomicU64,
    /// Times a reputation lookup was a miss.
    reputation_misses: AtomicU64,
    /// Successful policy bundle reloads.
    bundle_loads: AtomicU64,
    /// Failed policy bundle reloads.
    bundle_load_failures: AtomicU64,
    /// Telemetry submissions dropped because the egress
    /// channel was full (try_send saturated).
    telemetry_drops: AtomicU64,
    /// Times a request was rejected because the session
    /// table was full.
    session_table_full: AtomicU64,
}

impl SwgStats {
    /// Observed one more request, accumulate `bytes` on
    /// the inspected-bytes counter.
    pub fn record_request_observed(&self, bytes: u64) {
        self.requests_observed.fetch_add(1, Ordering::Relaxed);
        self.bytes_inspected.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Bump the counter for `posture`.
    pub fn record_posture(&self, posture: Posture) {
        let counter = match posture {
            Posture::Allow => &self.posture_allow,
            Posture::AlertOnly => &self.posture_alert_only,
            Posture::InspectFull => &self.posture_inspect_full,
            Posture::TlsBypass => &self.posture_tls_bypass,
            Posture::Quarantine => &self.posture_quarantine,
            Posture::Block => &self.posture_block,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Bump the counter for `verdict`.
    pub fn record_malware(&self, verdict: MalwareVerdict) {
        let counter = match verdict {
            MalwareVerdict::Clean => &self.malware_clean,
            MalwareVerdict::Suspicious => &self.malware_suspicious,
            MalwareVerdict::Malicious => &self.malware_malicious,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a category-provider hit (`got_value=true`)
    /// or miss (`false`).
    pub fn record_category_lookup(&self, got_value: bool) {
        if got_value {
            self.category_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.category_misses.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record a reputation-provider hit / miss.
    pub fn record_reputation_lookup(&self, got_value: bool) {
        if got_value {
            self.reputation_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.reputation_misses.fetch_add(1, Ordering::Relaxed);
        }
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

    /// One request rejected because the session table
    /// was full.
    pub fn record_session_table_full(&self) {
        self.session_table_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomic snapshot for serialization. Reads each
    /// counter independently; values are observably
    /// consistent within each counter but the snapshot
    /// as a whole is not a global-instantaneous read.
    #[must_use]
    pub fn snapshot(&self) -> SwgStatsSnapshot {
        SwgStatsSnapshot {
            requests_observed: self.requests_observed.load(Ordering::Relaxed),
            bytes_inspected: self.bytes_inspected.load(Ordering::Relaxed),
            posture_allow: self.posture_allow.load(Ordering::Relaxed),
            posture_alert_only: self.posture_alert_only.load(Ordering::Relaxed),
            posture_inspect_full: self.posture_inspect_full.load(Ordering::Relaxed),
            posture_tls_bypass: self.posture_tls_bypass.load(Ordering::Relaxed),
            posture_quarantine: self.posture_quarantine.load(Ordering::Relaxed),
            posture_block: self.posture_block.load(Ordering::Relaxed),
            malware_clean: self.malware_clean.load(Ordering::Relaxed),
            malware_suspicious: self.malware_suspicious.load(Ordering::Relaxed),
            malware_malicious: self.malware_malicious.load(Ordering::Relaxed),
            category_hits: self.category_hits.load(Ordering::Relaxed),
            category_misses: self.category_misses.load(Ordering::Relaxed),
            reputation_hits: self.reputation_hits.load(Ordering::Relaxed),
            reputation_misses: self.reputation_misses.load(Ordering::Relaxed),
            bundle_loads: self.bundle_loads.load(Ordering::Relaxed),
            bundle_load_failures: self.bundle_load_failures.load(Ordering::Relaxed),
            telemetry_drops: self.telemetry_drops.load(Ordering::Relaxed),
            session_table_full: self.session_table_full.load(Ordering::Relaxed),
        }
    }
}

/// Serializable snapshot of [`SwgStats`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwgStatsSnapshot {
    pub requests_observed: u64,
    pub bytes_inspected: u64,
    pub posture_allow: u64,
    pub posture_alert_only: u64,
    pub posture_inspect_full: u64,
    pub posture_tls_bypass: u64,
    pub posture_quarantine: u64,
    pub posture_block: u64,
    pub malware_clean: u64,
    pub malware_suspicious: u64,
    pub malware_malicious: u64,
    pub category_hits: u64,
    pub category_misses: u64,
    pub reputation_hits: u64,
    pub reputation_misses: u64,
    pub bundle_loads: u64,
    pub bundle_load_failures: u64,
    pub telemetry_drops: u64,
    pub session_table_full: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_snapshot_is_zeros() {
        let s = SwgStats::default().snapshot();
        assert_eq!(s, SwgStatsSnapshot::default());
    }

    #[test]
    fn record_request_observed_increments_count_and_bytes() {
        let s = SwgStats::default();
        s.record_request_observed(100);
        s.record_request_observed(50);
        let snap = s.snapshot();
        assert_eq!(snap.requests_observed, 2);
        assert_eq!(snap.bytes_inspected, 150);
    }

    #[test]
    fn record_posture_buckets_by_posture() {
        let s = SwgStats::default();
        s.record_posture(Posture::Allow);
        s.record_posture(Posture::Allow);
        s.record_posture(Posture::Block);
        s.record_posture(Posture::InspectFull);
        s.record_posture(Posture::Quarantine);
        s.record_posture(Posture::TlsBypass);
        s.record_posture(Posture::AlertOnly);
        let snap = s.snapshot();
        assert_eq!(snap.posture_allow, 2);
        assert_eq!(snap.posture_alert_only, 1);
        assert_eq!(snap.posture_inspect_full, 1);
        assert_eq!(snap.posture_tls_bypass, 1);
        assert_eq!(snap.posture_quarantine, 1);
        assert_eq!(snap.posture_block, 1);
    }

    #[test]
    fn record_malware_buckets_by_verdict() {
        let s = SwgStats::default();
        s.record_malware(MalwareVerdict::Clean);
        s.record_malware(MalwareVerdict::Malicious);
        s.record_malware(MalwareVerdict::Malicious);
        s.record_malware(MalwareVerdict::Suspicious);
        let snap = s.snapshot();
        assert_eq!(snap.malware_clean, 1);
        assert_eq!(snap.malware_suspicious, 1);
        assert_eq!(snap.malware_malicious, 2);
    }

    #[test]
    fn record_category_lookup_buckets_by_outcome() {
        let s = SwgStats::default();
        s.record_category_lookup(true);
        s.record_category_lookup(true);
        s.record_category_lookup(false);
        let snap = s.snapshot();
        assert_eq!(snap.category_hits, 2);
        assert_eq!(snap.category_misses, 1);
    }

    #[test]
    fn record_reputation_lookup_buckets_by_outcome() {
        let s = SwgStats::default();
        s.record_reputation_lookup(true);
        s.record_reputation_lookup(false);
        s.record_reputation_lookup(false);
        let snap = s.snapshot();
        assert_eq!(snap.reputation_hits, 1);
        assert_eq!(snap.reputation_misses, 2);
    }

    #[test]
    fn bundle_load_counters_are_independent() {
        let s = SwgStats::default();
        s.record_bundle_load();
        s.record_bundle_load();
        s.record_bundle_load_failure();
        let snap = s.snapshot();
        assert_eq!(snap.bundle_loads, 2);
        assert_eq!(snap.bundle_load_failures, 1);
    }

    #[test]
    fn telemetry_and_session_counters_increment() {
        let s = SwgStats::default();
        s.record_telemetry_drop();
        s.record_telemetry_drop();
        s.record_session_table_full();
        let snap = s.snapshot();
        assert_eq!(snap.telemetry_drops, 2);
        assert_eq!(snap.session_table_full, 1);
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        let s = SwgStats::default();
        s.record_request_observed(42);
        s.record_posture(Posture::Block);
        let snap = s.snapshot();
        let j = serde_json::to_string(&snap).unwrap();
        let round: SwgStatsSnapshot = serde_json::from_str(&j).unwrap();
        assert_eq!(snap, round);
    }
}

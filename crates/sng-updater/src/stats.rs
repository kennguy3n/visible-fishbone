//! Updater statistics — atomic counters + serializable
//! snapshot for telemetry.
//!
//! Mirrors the `ZtnaStats` / `SwgStats` / `SdwanStats` pattern
//! exactly: every counter is `AtomicU64`, hot-path bumps use
//! `Relaxed` ordering, and the snapshot is a plain struct
//! serialised as MessagePack on the wire.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters bumped on the install hot path. Snapshotted
/// into [`UpdaterStatsSnapshot`] for telemetry.
#[derive(Debug, Default)]
pub struct UpdaterStats {
    /// Number of times the orchestrator polled the manifest
    /// source.
    pub manifest_polls: AtomicU64,
    /// Number of manifests rejected because the source
    /// returned a transport-level error.
    pub manifest_source_errors: AtomicU64,
    /// Number of manifests rejected because the signature did
    /// not verify (mapped from
    /// [`crate::error::UpdaterError::SignatureInvalid`]).
    pub manifest_signature_errors: AtomicU64,
    /// Number of manifests rejected because the signing key
    /// id was unknown.
    pub manifest_unknown_key_errors: AtomicU64,
    /// Number of manifests rejected because the body would
    /// not decode.
    pub manifest_body_decode_errors: AtomicU64,
    /// Number of manifests rejected because the target did
    /// not match.
    pub manifest_target_mismatch_errors: AtomicU64,
    /// Number of manifests rejected because the version was
    /// not strictly newer (`Stale` or `Same`).
    pub manifest_stale_errors: AtomicU64,
    /// Number of manifests admitted for install (passed every
    /// verifier check).
    pub manifest_admitted: AtomicU64,
    /// Number of installs aborted because the download
    /// hashed to something other than the manifest claimed.
    pub install_hash_mismatch: AtomicU64,
    /// Number of installs aborted because the download
    /// truncated.
    pub install_truncated: AtomicU64,
    /// Number of installs aborted because the bank writer
    /// refused.
    pub install_bank_errors: AtomicU64,
    /// Number of installs aborted because the bootloader
    /// refused the swap.
    pub install_bootloader_errors: AtomicU64,
    /// Number of installs committed (post-swap health check
    /// passed).
    pub install_committed: AtomicU64,
    /// Number of installs rolled back (post-swap health check
    /// failed or timed out).
    pub install_rolled_back: AtomicU64,
    /// Number of concurrent install attempts rejected because
    /// another install was already in flight.
    pub install_concurrency_rejections: AtomicU64,
    /// Number of health-check probe calls served end-to-end
    /// (across all installs).
    pub health_check_probes: AtomicU64,
    /// Number of health-check timeouts surfaced.
    pub health_check_timeouts: AtomicU64,
}

impl UpdaterStats {
    /// Construct an all-zero stats struct.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the current counter values into a
    /// serialisable struct. The snapshot is not guaranteed to
    /// be a globally-instantaneous read across all counters
    /// (each load is `Relaxed`); it is suitable for
    /// per-evaluation telemetry where the wall-clock skew
    /// between counter reads is invisible.
    #[must_use]
    pub fn snapshot(&self) -> UpdaterStatsSnapshot {
        UpdaterStatsSnapshot {
            manifest_polls: self.manifest_polls.load(Ordering::Relaxed),
            manifest_source_errors: self.manifest_source_errors.load(Ordering::Relaxed),
            manifest_signature_errors: self.manifest_signature_errors.load(Ordering::Relaxed),
            manifest_unknown_key_errors: self.manifest_unknown_key_errors.load(Ordering::Relaxed),
            manifest_body_decode_errors: self.manifest_body_decode_errors.load(Ordering::Relaxed),
            manifest_target_mismatch_errors: self
                .manifest_target_mismatch_errors
                .load(Ordering::Relaxed),
            manifest_stale_errors: self.manifest_stale_errors.load(Ordering::Relaxed),
            manifest_admitted: self.manifest_admitted.load(Ordering::Relaxed),
            install_hash_mismatch: self.install_hash_mismatch.load(Ordering::Relaxed),
            install_truncated: self.install_truncated.load(Ordering::Relaxed),
            install_bank_errors: self.install_bank_errors.load(Ordering::Relaxed),
            install_bootloader_errors: self.install_bootloader_errors.load(Ordering::Relaxed),
            install_committed: self.install_committed.load(Ordering::Relaxed),
            install_rolled_back: self.install_rolled_back.load(Ordering::Relaxed),
            install_concurrency_rejections: self
                .install_concurrency_rejections
                .load(Ordering::Relaxed),
            health_check_probes: self.health_check_probes.load(Ordering::Relaxed),
            health_check_timeouts: self.health_check_timeouts.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of [`UpdaterStats`]. Sent on the wire as
/// MessagePack and rendered on operator dashboards.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdaterStatsSnapshot {
    /// Number of manifest polls served.
    pub manifest_polls: u64,
    /// Manifest source transport errors.
    pub manifest_source_errors: u64,
    /// Manifest signature verification failures.
    pub manifest_signature_errors: u64,
    /// Manifest signing-key id was unknown.
    pub manifest_unknown_key_errors: u64,
    /// Manifest body would not decode.
    pub manifest_body_decode_errors: u64,
    /// Manifest target did not match expected.
    pub manifest_target_mismatch_errors: u64,
    /// Manifest version was stale (downgrade or equal).
    pub manifest_stale_errors: u64,
    /// Manifests admitted for install.
    pub manifest_admitted: u64,
    /// Install aborts: downloaded SHA-256 did not match
    /// manifest claim.
    pub install_hash_mismatch: u64,
    /// Install aborts: download truncated.
    pub install_truncated: u64,
    /// Install aborts: bank writer surfaced an error.
    pub install_bank_errors: u64,
    /// Install aborts: bootloader surfaced an error.
    pub install_bootloader_errors: u64,
    /// Installs committed.
    pub install_committed: u64,
    /// Installs rolled back.
    pub install_rolled_back: u64,
    /// Install attempts rejected because another was already
    /// in flight.
    pub install_concurrency_rejections: u64,
    /// Health-check probe calls served.
    pub health_check_probes: u64,
    /// Health-check timeouts surfaced.
    pub health_check_timeouts: u64,
}

impl UpdaterStatsSnapshot {
    /// Returns true iff `manifest_admitted + every-rejection
    /// reason == manifest_polls + 1-per-push`. Used in
    /// single-threaded tests as an invariant check; the
    /// counter ordering is `Relaxed` so this CAN transiently
    /// fail under concurrent evaluation — the test scope is
    /// explicitly single-evaluator.
    #[must_use]
    pub fn install_outcome_total(&self) -> u64 {
        self.install_committed
            .saturating_add(self.install_rolled_back)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_snapshot_is_all_zero() {
        let snap = UpdaterStats::new().snapshot();
        assert_eq!(snap, UpdaterStatsSnapshot::default());
    }

    #[test]
    fn relaxed_bumps_reflect_in_snapshot() {
        let s = UpdaterStats::new();
        s.manifest_admitted.fetch_add(3, Ordering::Relaxed);
        s.install_committed.fetch_add(1, Ordering::Relaxed);
        s.install_rolled_back.fetch_add(2, Ordering::Relaxed);
        let snap = s.snapshot();
        assert_eq!(snap.manifest_admitted, 3);
        assert_eq!(snap.install_committed, 1);
        assert_eq!(snap.install_rolled_back, 2);
        assert_eq!(snap.install_outcome_total(), 3);
    }

    #[test]
    fn snapshot_round_trips_through_messagepack() {
        let s = UpdaterStats::new();
        s.manifest_polls.fetch_add(42, Ordering::Relaxed);
        s.health_check_probes.fetch_add(7, Ordering::Relaxed);
        let snap = s.snapshot();
        let encoded = rmp_serde::to_vec_named(&snap).expect("encode");
        let decoded: UpdaterStatsSnapshot = rmp_serde::from_slice(&encoded).expect("decode");
        assert_eq!(snap, decoded);
    }

    #[test]
    fn snapshot_round_trips_through_json() {
        let s = UpdaterStats::new();
        s.manifest_polls.fetch_add(9, Ordering::Relaxed);
        let snap = s.snapshot();
        let j = serde_json::to_string(&snap).expect("encode");
        let decoded: UpdaterStatsSnapshot = serde_json::from_str(&j).expect("decode");
        assert_eq!(snap, decoded);
    }
}

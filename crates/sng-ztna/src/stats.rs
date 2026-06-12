//! ZTNA runtime stats — atomic counters surfaced to ops
//! dashboards via [`ZtnaStatsSnapshot`].

use crate::policy::ZtnaDecisionReason;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

/// Live atomic counters. All operations use
/// [`Ordering::Relaxed`] — these are pure observability,
/// not coordination primitives, and the cost difference
/// vs. SeqCst is measurable on the data path.
#[derive(Debug, Default)]
pub struct ZtnaStats {
    /// Total access requests the brain evaluated.
    requests_evaluated: AtomicU64,
    /// Allows.
    decision_allow: AtomicU64,
    /// Denies — broken out by reason so dashboards can
    /// distinguish "posture issues" from "missing
    /// identity" without grepping events.
    deny_unknown_app: AtomicU64,
    deny_device_not_enrolled: AtomicU64,
    deny_device_posture_stale: AtomicU64,
    deny_device_posture_insufficient: AtomicU64,
    deny_identity_not_found: AtomicU64,
    deny_identity_absent: AtomicU64,
    deny_mfa_stale: AtomicU64,
    deny_not_entitled: AtomicU64,
    deny_tenant_mismatch: AtomicU64,
    deny_revoked: AtomicU64,
    deny_geo_blocked: AtomicU64,
    deny_network_type_blocked: AtomicU64,
    deny_outside_hours: AtomicU64,
    deny_tag_mismatch: AtomicU64,
    /// Successful policy bundle reloads.
    bundle_loads: AtomicU64,
    /// Failed policy bundle reloads.
    bundle_load_failures: AtomicU64,
    /// Telemetry submissions dropped because the egress
    /// channel was full (`try_send` saturated).
    telemetry_drops: AtomicU64,
    /// Provider failures observed (the orchestrator's
    /// fail-policy decides whether the request is then
    /// allowed or blocked; this counter is independent of
    /// the deny buckets above).
    provider_failures: AtomicU64,
}

impl ZtnaStats {
    /// Bump the appropriate decision counter. The
    /// service calls this exactly once per evaluation.
    pub fn record_decision(&self, reason: &ZtnaDecisionReason) {
        self.requests_evaluated.fetch_add(1, Ordering::Relaxed);
        let counter = match reason {
            ZtnaDecisionReason::Allow => &self.decision_allow,
            ZtnaDecisionReason::UnknownApp => &self.deny_unknown_app,
            ZtnaDecisionReason::DeviceNotEnrolled => &self.deny_device_not_enrolled,
            ZtnaDecisionReason::DevicePostureStale => &self.deny_device_posture_stale,
            ZtnaDecisionReason::DevicePostureInsufficient => &self.deny_device_posture_insufficient,
            ZtnaDecisionReason::IdentityNotFound => &self.deny_identity_not_found,
            ZtnaDecisionReason::IdentityAbsent => &self.deny_identity_absent,
            ZtnaDecisionReason::MfaStale => &self.deny_mfa_stale,
            ZtnaDecisionReason::NotEntitled => &self.deny_not_entitled,
            ZtnaDecisionReason::TenantMismatch => &self.deny_tenant_mismatch,
            ZtnaDecisionReason::Revoked => &self.deny_revoked,
            ZtnaDecisionReason::GeoBlocked => &self.deny_geo_blocked,
            ZtnaDecisionReason::NetworkTypeBlocked => &self.deny_network_type_blocked,
            ZtnaDecisionReason::OutsideAllowedHours => &self.deny_outside_hours,
            ZtnaDecisionReason::TagMismatch => &self.deny_tag_mismatch,
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

    /// One provider failure observed (e.g. timeout
    /// reaching the IdP cache or the device-trust
    /// store).
    pub fn record_provider_failure(&self) {
        self.provider_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomic snapshot for serialization. Reads each
    /// counter independently; values are observably
    /// consistent within each counter but the snapshot
    /// as a whole is not a global-instantaneous read.
    #[must_use]
    pub fn snapshot(&self) -> ZtnaStatsSnapshot {
        ZtnaStatsSnapshot {
            requests_evaluated: self.requests_evaluated.load(Ordering::Relaxed),
            decision_allow: self.decision_allow.load(Ordering::Relaxed),
            deny_unknown_app: self.deny_unknown_app.load(Ordering::Relaxed),
            deny_device_not_enrolled: self.deny_device_not_enrolled.load(Ordering::Relaxed),
            deny_device_posture_stale: self.deny_device_posture_stale.load(Ordering::Relaxed),
            deny_device_posture_insufficient: self
                .deny_device_posture_insufficient
                .load(Ordering::Relaxed),
            deny_identity_not_found: self.deny_identity_not_found.load(Ordering::Relaxed),
            deny_identity_absent: self.deny_identity_absent.load(Ordering::Relaxed),
            deny_mfa_stale: self.deny_mfa_stale.load(Ordering::Relaxed),
            deny_not_entitled: self.deny_not_entitled.load(Ordering::Relaxed),
            deny_tenant_mismatch: self.deny_tenant_mismatch.load(Ordering::Relaxed),
            deny_revoked: self.deny_revoked.load(Ordering::Relaxed),
            deny_geo_blocked: self.deny_geo_blocked.load(Ordering::Relaxed),
            deny_network_type_blocked: self.deny_network_type_blocked.load(Ordering::Relaxed),
            deny_outside_hours: self.deny_outside_hours.load(Ordering::Relaxed),
            deny_tag_mismatch: self.deny_tag_mismatch.load(Ordering::Relaxed),
            bundle_loads: self.bundle_loads.load(Ordering::Relaxed),
            bundle_load_failures: self.bundle_load_failures.load(Ordering::Relaxed),
            telemetry_drops: self.telemetry_drops.load(Ordering::Relaxed),
            provider_failures: self.provider_failures.load(Ordering::Relaxed),
        }
    }
}

/// Serializable snapshot of [`ZtnaStats`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtnaStatsSnapshot {
    /// Total access requests evaluated.
    pub requests_evaluated: u64,
    /// Total allows.
    pub decision_allow: u64,
    /// Deny because the app id was not in the catalog.
    pub deny_unknown_app: u64,
    /// Deny because the device id was not enrolled.
    pub deny_device_not_enrolled: u64,
    /// Deny because the device posture attestation was
    /// older than the policy window.
    pub deny_device_posture_stale: u64,
    /// Deny because the device posture did not meet the
    /// app's [`crate::PostureRequirement`].
    pub deny_device_posture_insufficient: u64,
    /// Deny because the identity was not registered.
    pub deny_identity_not_found: u64,
    /// Deny because no user subject was present at all and
    /// the identity-gated portion of the decision could not
    /// be completed (the explicit degraded verdict). Counted
    /// separately from [`Self::deny_identity_not_found`] so
    /// dashboards can tell degraded-by-design traffic (no
    /// subject supplied) apart from a genuine identity miss
    /// (a `user_id` was supplied but is unknown).
    pub deny_identity_absent: u64,
    /// Deny because the user's MFA timestamp was older
    /// than the policy window.
    pub deny_mfa_stale: u64,
    /// Deny because the user was not in any of the app's
    /// `required_groups`.
    pub deny_not_entitled: u64,
    /// Deny because the device or identity tenant did
    /// not match the policy tenant.
    pub deny_tenant_mismatch: u64,
    /// Deny because the device or user was on the
    /// revocation list.
    pub deny_revoked: u64,
    /// Deny because the request's source country was
    /// blocked or outside the app's allow-list.
    pub deny_geo_blocked: u64,
    /// Deny because the request's network type was not in
    /// the app's allowed set.
    pub deny_network_type_blocked: u64,
    /// Deny because the request arrived outside the app's
    /// allowed access hours.
    pub deny_outside_hours: u64,
    /// Deny because a device / user tag condition on the
    /// app's access conditions was not satisfied.
    pub deny_tag_mismatch: u64,
    /// Successful policy bundle reloads.
    pub bundle_loads: u64,
    /// Failed policy bundle reloads.
    pub bundle_load_failures: u64,
    /// Telemetry submissions dropped at the egress
    /// (try_send saturated).
    pub telemetry_drops: u64,
    /// Provider failures (timeout / I/O on the device,
    /// identity, or app providers).
    pub provider_failures: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn default_snapshot_is_zeros() {
        let s = ZtnaStats::default().snapshot();
        assert_eq!(s, ZtnaStatsSnapshot::default());
    }

    #[test]
    fn record_decision_buckets_each_reason() {
        let s = ZtnaStats::default();
        s.record_decision(&ZtnaDecisionReason::Allow);
        s.record_decision(&ZtnaDecisionReason::Allow);
        s.record_decision(&ZtnaDecisionReason::UnknownApp);
        s.record_decision(&ZtnaDecisionReason::DeviceNotEnrolled);
        s.record_decision(&ZtnaDecisionReason::DevicePostureStale);
        s.record_decision(&ZtnaDecisionReason::DevicePostureInsufficient);
        s.record_decision(&ZtnaDecisionReason::IdentityNotFound);
        s.record_decision(&ZtnaDecisionReason::MfaStale);
        s.record_decision(&ZtnaDecisionReason::NotEntitled);
        s.record_decision(&ZtnaDecisionReason::TenantMismatch);
        let snap = s.snapshot();
        assert_eq!(snap.requests_evaluated, 10);
        assert_eq!(snap.decision_allow, 2);
        assert_eq!(snap.deny_unknown_app, 1);
        assert_eq!(snap.deny_device_not_enrolled, 1);
        assert_eq!(snap.deny_device_posture_stale, 1);
        assert_eq!(snap.deny_device_posture_insufficient, 1);
        assert_eq!(snap.deny_identity_not_found, 1);
        assert_eq!(snap.deny_mfa_stale, 1);
        assert_eq!(snap.deny_not_entitled, 1);
        assert_eq!(snap.deny_tenant_mismatch, 1);
    }

    #[test]
    fn record_bundle_load_increments_independently() {
        let s = ZtnaStats::default();
        s.record_bundle_load();
        s.record_bundle_load();
        s.record_bundle_load_failure();
        let snap = s.snapshot();
        assert_eq!(snap.bundle_loads, 2);
        assert_eq!(snap.bundle_load_failures, 1);
    }

    #[test]
    fn telemetry_drop_counter_increments() {
        let s = ZtnaStats::default();
        s.record_telemetry_drop();
        s.record_telemetry_drop();
        let snap = s.snapshot();
        assert_eq!(snap.telemetry_drops, 2);
    }

    #[test]
    fn provider_failure_counter_increments() {
        let s = ZtnaStats::default();
        s.record_provider_failure();
        let snap = s.snapshot();
        assert_eq!(snap.provider_failures, 1);
    }

    #[test]
    fn snapshot_roundtrips_through_json() {
        let s = ZtnaStats::default();
        s.record_decision(&ZtnaDecisionReason::Allow);
        let snap = s.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: ZtnaStatsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }
}

//! ZTNA policy + evaluator.
//!
//! The brain joins three signals — identity (groups +
//! MFA freshness), device (enrolment + posture
//! freshness), and the per-app catalog (required groups,
//! minimum posture) — into a single
//! [`ZtnaDecision`].
//!
//! Two crisp invariants hold:
//!
//! 1. **Deny-by-default.** Any signal that cannot be
//!    confirmed — unknown app, unenrolled device, missing
//!    identity record, stale MFA, stale posture — is a
//!    deny. The orchestrator never allows on a missing
//!    signal.
//! 2. **Reason is structured.** The decision carries a
//!    [`ZtnaDecisionReason`] that maps onto a stable wire
//!    string ([`ZtnaDecisionReason::as_str`]), so
//!    dashboards bucket denies by cause without parsing a
//!    free-form message.
//!
//! Reload semantics mirror the SWG brain
//! ([`crate::ZtnaPolicyHolder::replace`]): the holder
//! wraps the active [`ZtnaPolicy`] in `arc_swap::ArcSwap`
//! so the data path reads without taking a lock and the
//! bundle adapter swaps whole policies atomically.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::app::App;
use crate::device::{DevicePosture, DeviceTrust};
use crate::identity::UserIdentity;

/// Minimum device-posture requirement an app may declare.
///
/// Variants are ordered from least to most strict — the
/// derived `Ord` impl agrees with
/// [`PostureRequirement::satisfied_by`] so callers can
/// `cmp` two requirements directly if they ever need to
/// pick the more-strict of a pair.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureRequirement {
    /// No posture floor. Useful for low-risk apps that
    /// the catalog wants open to any authenticated user.
    None,
    /// Basic posture: disk encryption + OS patched. The
    /// floor for most internal-tooling apps.
    Basic,
    /// Strict posture: every signal in
    /// [`DevicePosture`] must be true.
    Strict,
}

impl PostureRequirement {
    /// True iff `posture` meets this requirement.
    #[must_use]
    pub const fn satisfied_by(self, posture: &DevicePosture) -> bool {
        match self {
            Self::None => true,
            Self::Basic => posture.disk_encrypted && posture.os_patched,
            Self::Strict => {
                posture.disk_encrypted
                    && posture.os_patched
                    && posture.antimalware_running
                    && posture.firewall_enabled
                    && posture.screen_lock_configured
            }
        }
    }

    /// Stable wire string. Dashboards and the
    /// [`sng_core::events::ZtnaEvent`] use this — the
    /// serde rename is the same string but lifted here
    /// so non-serde call sites get the canonical label
    /// without going through `serde_json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::Strict => "strict",
        }
    }
}

/// The reason an evaluator denied (or allowed) a
/// request. Every reason maps to a stable wire string
/// for downstream dashboards and the
/// [`sng_core::events::ZtnaEvent::decision`] +
/// `posture_result` fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZtnaDecisionReason {
    /// Allow. The user was in the app's group set, the
    /// device posture met the floor, MFA was fresh, and
    /// the device's attestation was fresh.
    Allow,
    /// Deny — request referenced an `app_id` not present
    /// in the active app catalog.
    UnknownApp,
    /// Deny — device_id was not enrolled in the device
    /// trust provider.
    DeviceNotEnrolled,
    /// Deny — device's latest posture attestation is
    /// older than `policy.device_posture_max_age_ms`.
    DevicePostureStale,
    /// Deny — device's posture does not meet the app's
    /// [`PostureRequirement`].
    DevicePostureInsufficient,
    /// Deny — identity not registered with the identity
    /// provider.
    IdentityNotFound,
    /// Deny — identity's MFA timestamp is older than
    /// `policy.mfa_max_age_ms`.
    MfaStale,
    /// Deny — user is not a member of any of the app's
    /// `required_groups`.
    NotEntitled,
    /// Deny — request's tenant does not match the
    /// device's or identity's tenant. Cross-tenant
    /// requests are never allowed.
    TenantMismatch,
}

impl ZtnaDecisionReason {
    /// Stable wire string for the
    /// [`sng_core::events::ZtnaEvent::decision`] field
    /// (when this is an allow) or the dashboards' deny
    /// bucket label (when this is a deny).
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::UnknownApp => "unknown_app",
            Self::DeviceNotEnrolled => "device_not_enrolled",
            Self::DevicePostureStale => "device_posture_stale",
            Self::DevicePostureInsufficient => "device_posture_insufficient",
            Self::IdentityNotFound => "identity_not_found",
            Self::MfaStale => "mfa_stale",
            Self::NotEntitled => "not_entitled",
            Self::TenantMismatch => "tenant_mismatch",
        }
    }

    /// True iff this reason represents an allow.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// True iff this reason represents a deny.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        !self.is_allow()
    }
}

/// The decision the evaluator returns. The brain
/// converts this into a wire
/// [`sng_core::envelope::Verdict`] and a
/// [`sng_core::events::ZtnaEvent`] for telemetry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtnaDecision {
    /// Allow / deny.
    pub allow: bool,
    /// Structured reason — for both allows (= `Allow`)
    /// and denies (= a specific failure cause).
    pub reason: ZtnaDecisionReason,
    /// Whether the device posture met the app's
    /// requirement. Surfaced to the
    /// [`sng_core::events::ZtnaEvent::posture_result`]
    /// field. False on any deny path that didn't reach
    /// the posture check (e.g. `UnknownApp`) so
    /// dashboards see a single boolean.
    pub posture_pass: bool,
}

impl ZtnaDecision {
    /// Convenience: allow with `posture_pass=true`.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allow: true,
            reason: ZtnaDecisionReason::Allow,
            posture_pass: true,
        }
    }

    /// Convenience: deny with the given reason; the
    /// caller supplies whether the posture check passed
    /// before the deny was raised (it's still useful for
    /// dashboards to know whether the deny was posture-
    /// related or identity-related).
    #[must_use]
    pub const fn deny(reason: ZtnaDecisionReason, posture_pass: bool) -> Self {
        Self {
            allow: false,
            reason,
            posture_pass,
        }
    }
}

/// The policy knobs the brain consults while joining the
/// per-app catalog with the live identity / device
/// signals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtnaPolicy {
    /// Maximum age of a device's posture attestation
    /// before it is considered stale. Sourced from the
    /// tenant policy bundle.
    pub device_posture_max_age_ms: u64,
    /// Maximum age of a user's MFA completion before it
    /// must be re-prompted. Sourced from the tenant
    /// policy bundle.
    pub mfa_max_age_ms: u64,
    /// Tenant ID this policy belongs to. The evaluator
    /// rejects cross-tenant requests (where the user or
    /// device belongs to a different tenant than the
    /// policy is configured for).
    pub tenant_id: String,
}

impl Default for ZtnaPolicy {
    fn default() -> Self {
        Self {
            // 12 hours of posture freshness aligns with
            // the agent's default re-attestation cadence
            // (every hour) leaving a comfortable margin
            // for agents that miss a few cycles.
            device_posture_max_age_ms: 12 * 60 * 60 * 1_000,
            // 8 hours of MFA freshness covers a working
            // day; sensitive apps can drop this with a
            // per-app override (out of scope for the
            // initial bundle schema, but the policy
            // already supports refreshing the whole
            // policy on every bundle reload).
            mfa_max_age_ms: 8 * 60 * 60 * 1_000,
            tenant_id: String::new(),
        }
    }
}

/// `ArcSwap`-backed holder for the active
/// [`ZtnaPolicy`]. The data path snapshots a cheap
/// `Arc<ZtnaPolicy>` per evaluation; the bundle adapter
/// swaps the policy atomically when a new bundle is
/// pushed.
#[derive(Debug, Default)]
pub struct ZtnaPolicyHolder {
    inner: ArcSwap<ZtnaPolicy>,
}

impl ZtnaPolicyHolder {
    /// Construct a holder initialised with `policy`.
    #[must_use]
    pub fn new(policy: ZtnaPolicy) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(policy)),
        }
    }

    /// Replace the active policy. In-flight evaluations
    /// see the old policy until they finish.
    pub fn replace(&self, policy: ZtnaPolicy) {
        self.inner.store(Arc::new(policy));
    }

    /// Cheap snapshot of the active policy — clones the
    /// `Arc`, never copies the policy body.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ZtnaPolicy> {
        self.inner.load_full()
    }
}

/// Inputs to [`evaluate_policy`]. Bundles the per-
/// request facts the orchestrator has resolved by the
/// time it calls the evaluator.
#[derive(Clone, Debug)]
pub struct EvaluationInputs<'a> {
    /// The app the request is targeting. The orchestrator
    /// resolves this via the
    /// [`crate::app::AppCatalogProvider`]; if not found,
    /// the orchestrator builds a deny directly without
    /// calling the evaluator.
    pub app: &'a App,
    /// The device's trust + posture record. The
    /// orchestrator resolves this via the
    /// [`crate::device::DeviceTrustProvider`]; if not
    /// found, the orchestrator builds a deny directly.
    pub device: &'a DeviceTrust,
    /// The user's identity record. The orchestrator
    /// resolves this via the
    /// [`crate::identity::IdentityProvider`]; if not
    /// found, the orchestrator builds a deny directly.
    pub identity: &'a UserIdentity,
    /// Monotonic millisecond timestamp the orchestrator
    /// captured when the request arrived. Used for the
    /// MFA + posture freshness checks.
    pub now_ms: u64,
}

/// Run the policy. **Order matters** — the evaluator
/// checks the cheapest signals first so the most common
/// deny paths short-circuit without computing later
/// signals.
///
/// Steps:
///
/// 1. **Tenant match.** The policy belongs to one
///    tenant; the device and the identity must both
///    belong to the same tenant. Cross-tenant requests
///    are denied without further checks.
/// 2. **Identity entitlement.** If the app has a non-
///    empty `required_groups` set, the user's groups
///    must intersect it. Otherwise the user is
///    `not_entitled`.
/// 3. **MFA freshness.** The user's `mfa_at_ms` must
///    be within `policy.mfa_max_age_ms` of `now_ms`.
/// 4. **Device posture freshness.** The device's
///    `attested_at_ms` must be within
///    `policy.device_posture_max_age_ms` of `now_ms`.
/// 5. **Device posture sufficiency.** The device's
///    posture must satisfy the app's
///    [`PostureRequirement`].
///
/// On every deny the [`ZtnaDecision::posture_pass`]
/// flag reflects whether the posture check passed
/// (or, for denies that short-circuit before the posture
/// check, `false`).
//
// `EvaluationInputs` holds three references plus a `u64`,
// so passing by value is essentially the same cost as
// passing by reference — but it lets the function
// destructure the inputs (`let EvaluationInputs { app, .. } = inputs;`)
// instead of writing `inputs.app` / `inputs.device` /
// `inputs.identity` at every use site. The
// `needless_pass_by_value` lint cannot see this trade-off,
// so we allow it explicitly.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn evaluate_policy(policy: &ZtnaPolicy, inputs: EvaluationInputs<'_>) -> ZtnaDecision {
    let EvaluationInputs {
        app,
        device,
        identity,
        now_ms,
    } = inputs;

    // 1. Tenant guard. Cross-tenant requests never
    // proceed past this gate.
    if !policy.tenant_id.is_empty()
        && (device.tenant_id != policy.tenant_id || identity.tenant_id != policy.tenant_id)
    {
        return ZtnaDecision::deny(ZtnaDecisionReason::TenantMismatch, false);
    }

    // 2. Group entitlement. Empty `required_groups`
    // means "any authenticated user", consistent with
    // the catalog's documented semantics.
    if !app.required_groups.is_empty() {
        let entitled = app
            .required_groups
            .iter()
            .any(|g| identity.groups.contains(g));
        if !entitled {
            return ZtnaDecision::deny(ZtnaDecisionReason::NotEntitled, false);
        }
    }

    // 3. MFA freshness.
    if !identity.mfa_fresh(now_ms, policy.mfa_max_age_ms) {
        return ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, false);
    }

    // 4. Device posture freshness.
    if !device.posture_fresh(now_ms, policy.device_posture_max_age_ms) {
        return ZtnaDecision::deny(ZtnaDecisionReason::DevicePostureStale, false);
    }

    // 5. Device posture sufficiency.
    if !app.posture_requirement.satisfied_by(&device.posture) {
        return ZtnaDecision::deny(ZtnaDecisionReason::DevicePostureInsufficient, false);
    }

    ZtnaDecision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn app(name: &str, posture: PostureRequirement, groups: &[&str]) -> App {
        App {
            app_id: name.into(),
            display_name: name.into(),
            host_patterns: Vec::new(),
            required_groups: groups.iter().map(|s| (*s).to_string()).collect(),
            posture_requirement: posture,
        }
    }

    fn device(tenant: &str, posture: DevicePosture) -> DeviceTrust {
        DeviceTrust {
            device_id: "dev-1".into(),
            tenant_id: tenant.into(),
            posture,
        }
    }

    fn user(tenant: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
        UserIdentity {
            user_id: "alice".into(),
            tenant_id: tenant.into(),
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            mfa_at_ms,
        }
    }

    fn policy(tenant: &str) -> ZtnaPolicy {
        ZtnaPolicy {
            tenant_id: tenant.into(),
            ..Default::default()
        }
    }

    fn now() -> u64 {
        // Pick a round number well above the policy's
        // max-age windows so we can roll it back to
        // produce stale-MFA / stale-posture cases.
        1_000_000_000
    }

    fn inputs<'a>(
        a: &'a App,
        d: &'a DeviceTrust,
        u: &'a UserIdentity,
        now_ms: u64,
    ) -> EvaluationInputs<'a> {
        EvaluationInputs {
            app: a,
            device: d,
            identity: u,
            now_ms,
        }
    }

    #[test]
    fn posture_none_satisfied_by_unmanaged() {
        assert!(PostureRequirement::None.satisfied_by(&DevicePosture::unmanaged()));
    }

    #[test]
    fn posture_basic_requires_disk_encrypted_and_os_patched() {
        let mut p = DevicePosture::unmanaged();
        assert!(!PostureRequirement::Basic.satisfied_by(&p));
        p.disk_encrypted = true;
        assert!(!PostureRequirement::Basic.satisfied_by(&p));
        p.os_patched = true;
        assert!(PostureRequirement::Basic.satisfied_by(&p));
    }

    #[test]
    fn posture_strict_requires_every_signal() {
        assert!(!PostureRequirement::Strict.satisfied_by(&DevicePosture::unmanaged()));
        assert!(PostureRequirement::Strict.satisfied_by(&DevicePosture::pristine(now())));
    }

    #[test]
    fn posture_requirement_ord_matches_satisfied_by_strictness() {
        // None is least strict (always passes), Strict is
        // most strict — derived Ord agrees.
        assert!(PostureRequirement::None < PostureRequirement::Basic);
        assert!(PostureRequirement::Basic < PostureRequirement::Strict);
    }

    #[test]
    fn posture_requirement_wire_strings_are_stable() {
        assert_eq!(PostureRequirement::None.as_str(), "none");
        assert_eq!(PostureRequirement::Basic.as_str(), "basic");
        assert_eq!(PostureRequirement::Strict.as_str(), "strict");
    }

    #[test]
    fn decision_reason_wire_strings_cover_every_variant() {
        assert_eq!(ZtnaDecisionReason::Allow.as_str(), "allow");
        assert_eq!(ZtnaDecisionReason::UnknownApp.as_str(), "unknown_app");
        assert_eq!(
            ZtnaDecisionReason::DeviceNotEnrolled.as_str(),
            "device_not_enrolled"
        );
        assert_eq!(
            ZtnaDecisionReason::DevicePostureStale.as_str(),
            "device_posture_stale"
        );
        assert_eq!(
            ZtnaDecisionReason::DevicePostureInsufficient.as_str(),
            "device_posture_insufficient"
        );
        assert_eq!(
            ZtnaDecisionReason::IdentityNotFound.as_str(),
            "identity_not_found"
        );
        assert_eq!(ZtnaDecisionReason::MfaStale.as_str(), "mfa_stale");
        assert_eq!(ZtnaDecisionReason::NotEntitled.as_str(), "not_entitled");
        assert_eq!(
            ZtnaDecisionReason::TenantMismatch.as_str(),
            "tenant_mismatch"
        );
    }

    #[test]
    fn decision_reason_is_allow_only_for_allow() {
        assert!(ZtnaDecisionReason::Allow.is_allow());
        assert!(!ZtnaDecisionReason::Allow.is_deny());
        for r in [
            ZtnaDecisionReason::UnknownApp,
            ZtnaDecisionReason::DeviceNotEnrolled,
            ZtnaDecisionReason::DevicePostureStale,
            ZtnaDecisionReason::DevicePostureInsufficient,
            ZtnaDecisionReason::IdentityNotFound,
            ZtnaDecisionReason::MfaStale,
            ZtnaDecisionReason::NotEntitled,
            ZtnaDecisionReason::TenantMismatch,
        ] {
            assert!(r.is_deny(), "expected deny: {r:?}");
            assert!(!r.is_allow(), "expected !allow: {r:?}");
        }
    }

    #[test]
    fn allow_when_all_signals_pass() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::Basic, &["eng"]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["eng"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::Allow);
        assert!(dec.posture_pass);
    }

    #[test]
    fn deny_when_user_not_in_required_groups() {
        let p = policy("t1");
        let a = app("payroll", PostureRequirement::Basic, &["finance"]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["eng"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::NotEntitled);
        assert!(!dec.posture_pass);
    }

    #[test]
    fn allow_when_required_groups_empty() {
        let p = policy("t1");
        let a = app("public", PostureRequirement::None, &[]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn deny_on_stale_mfa() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::None, &[]);
        let d = device("t1", DevicePosture::pristine(now()));
        // MFA was completed 10 hours ago; default
        // mfa_max_age_ms is 8 hours.
        let u = user("t1", &[], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);
    }

    #[test]
    fn deny_on_stale_posture() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::None, &[]);
        let mut posture = DevicePosture::pristine(now());
        // Posture attested 13 hours ago; default
        // device_posture_max_age_ms is 12 hours.
        posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d = device("t1", posture);
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureStale);
    }

    #[test]
    fn deny_on_posture_insufficient() {
        let p = policy("t1");
        let a = app("admin", PostureRequirement::Strict, &[]);
        let mut posture = DevicePosture::pristine(now());
        // Strict requires every signal; drop one.
        posture.antimalware_running = false;
        let d = device("t1", posture);
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureInsufficient);
    }

    #[test]
    fn deny_on_cross_tenant_device() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::None, &[]);
        let d = device("t-other", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
    }

    #[test]
    fn deny_on_cross_tenant_identity() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::None, &[]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t-other", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
    }

    #[test]
    fn empty_tenant_disables_tenant_guard() {
        // Tenant guard is skipped when the policy itself
        // has no tenant — useful for single-tenant
        // deployments where the bundle adapter does not
        // bother setting the tenant string.
        let p = ZtnaPolicy::default();
        let a = app("wiki", PostureRequirement::None, &[]);
        let d = device("anything", DevicePosture::pristine(now()));
        let u = user("anything-else", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn tenant_check_runs_before_group_check() {
        // A user lacking the required group AND in the
        // wrong tenant should deny on tenant first — the
        // tenant signal is structurally cheaper and more
        // informative.
        let p = policy("t1");
        let a = app("payroll", PostureRequirement::Basic, &["finance"]);
        let d = device("t-other", DevicePosture::pristine(now()));
        let u = user("t-other", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
    }

    #[test]
    fn group_check_runs_before_mfa_check() {
        // If both group and MFA fail, group check fires
        // first (preserves the order in the doc above).
        let p = policy("t1");
        let a = app("payroll", PostureRequirement::None, &["finance"]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["eng"], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::NotEntitled);
    }

    #[test]
    fn mfa_check_runs_before_posture_freshness() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::None, &[]);
        let mut posture = DevicePosture::pristine(now());
        posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d = device("t1", posture);
        let u = user("t1", &[], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        // MFA is checked before posture freshness.
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);
    }

    #[test]
    fn posture_freshness_runs_before_sufficiency() {
        let p = policy("t1");
        let a = app("admin", PostureRequirement::Strict, &[]);
        let mut posture = DevicePosture::unmanaged();
        posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d = device("t1", posture);
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        // Freshness fires before sufficiency.
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureStale);
    }

    #[test]
    fn decision_serde_roundtrips_via_json() {
        let dec = ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, false);
        let json = serde_json::to_string(&dec).unwrap();
        let back: ZtnaDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, back);
    }

    #[test]
    fn policy_holder_swaps_atomically() {
        let h = ZtnaPolicyHolder::new(policy("t1"));
        assert_eq!(h.snapshot().tenant_id, "t1");
        h.replace(policy("t2"));
        assert_eq!(h.snapshot().tenant_id, "t2");
    }

    #[test]
    fn policy_holder_default_is_empty_tenant() {
        let h = ZtnaPolicyHolder::default();
        assert!(h.snapshot().tenant_id.is_empty());
    }

    #[test]
    fn required_groups_use_set_semantics() {
        // Single intersect element is enough — verify
        // with a larger set so the test does more than
        // exercise the empty-set short circuit.
        let p = policy("t1");
        let mut groups = HashSet::new();
        groups.insert("eng".to_string());
        groups.insert("admin".to_string());
        groups.insert("finance".to_string());
        let a = App {
            app_id: "x".into(),
            display_name: "x".into(),
            host_patterns: Vec::new(),
            required_groups: groups,
            posture_requirement: PostureRequirement::None,
        };
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["admin"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn allow_decision_constructor_sets_posture_pass() {
        let dec = ZtnaDecision::allow();
        assert!(dec.allow);
        assert!(dec.posture_pass);
        assert_eq!(dec.reason, ZtnaDecisionReason::Allow);
    }

    #[test]
    fn deny_decision_constructor_preserves_posture_pass_flag() {
        // The orchestrator builds an early deny (e.g.
        // UnknownApp) with posture_pass=false — preserve
        // that bit on construction.
        let dec = ZtnaDecision::deny(ZtnaDecisionReason::UnknownApp, false);
        assert!(!dec.allow);
        assert!(!dec.posture_pass);
        // For a posture-passed-but-MFA-failed deny, the
        // orchestrator can pass true; verify it round-
        // trips.
        let dec2 = ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, true);
        assert!(dec2.posture_pass);
    }
}

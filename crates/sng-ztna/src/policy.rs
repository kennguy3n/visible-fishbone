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
use crate::error::ZtnaError;
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
/// [`sng_core::events::ZtnaEvent::reason`] field (the
/// sibling [`sng_core::events::ZtnaEvent::decision`]
/// field carries the binary `allow`/`deny` outcome).
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
    /// [`sng_core::events::ZtnaEvent::reason`] field —
    /// `allow` on the allow path, or the dashboards'
    /// deny bucket label on a deny.
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

/// Tri-state outcome of the device posture check.
///
/// Replaces the prior `bool posture_pass` field on
/// [`ZtnaDecision`] so dashboards can distinguish a
/// genuine posture failure ([`Self::Fail`]) from a
/// deny that short-circuited before the posture check
/// ran ([`Self::NotEvaluated`]).
///
/// # Wire form
///
/// Mapped to a stable lowercase string by
/// [`Self::as_str`] and emitted on
/// [`sng_core::events::ZtnaEvent::posture_result`] (Rust
/// side) / `ZTNAEvent.PostureResult` (Go side). The
/// wire alphabet is `"pass" | "fail" | "not_evaluated"`.
/// Older consumers that only know `"pass"` / `"fail"`
/// will see `"not_evaluated"` as an unknown bucket —
/// safer than the previous behavior of stamping
/// `"fail"` on every non-posture deny, which made the
/// field literally lie about whether the device's
/// posture had failed.
///
/// # Why a tri-state and not just two booleans
///
/// A `(posture_evaluated, posture_passed)` pair would
/// encode the same information but invites the
/// `(false, true)` impossible state. The enum makes
/// the invariant unrepresentable at the type level —
/// `Pass` and `Fail` are only reachable after the
/// posture check actually ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureResult {
    /// The posture check ran and the device satisfied
    /// the app's [`PostureRequirement`]. Set on the
    /// allow path and on any deny that occurred after
    /// the posture check passed (none today — the
    /// evaluator currently denies immediately when the
    /// posture check fails — but the variant exists so
    /// a future check ordered after posture can produce
    /// a `(deny, Pass)` decision).
    Pass,
    /// The posture check ran and the device failed it
    /// — either because the attestation was stale
    /// ([`ZtnaDecisionReason::DevicePostureStale`]) or
    /// the requirement was unsatisfied
    /// ([`ZtnaDecisionReason::DevicePostureInsufficient`]).
    Fail,
    /// The decision short-circuited before the posture
    /// check ran. Set on
    /// [`ZtnaDecisionReason::TenantMismatch`],
    /// [`ZtnaDecisionReason::NotEntitled`],
    /// [`ZtnaDecisionReason::MfaStale`], and any other
    /// pre-posture deny added in the future. Dashboards
    /// that bucket on "device-related" denies should
    /// treat this as orthogonal to the
    /// posture-pass / posture-fail axis.
    NotEvaluated,
}

impl PostureResult {
    /// Stable wire-form string used in the
    /// [`sng_core::events::ZtnaEvent::posture_result`]
    /// field (and the Go-side `ZTNAEvent.PostureResult`
    /// peer).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotEvaluated => "not_evaluated",
        }
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
    /// Tri-state outcome of the device posture check.
    /// Surfaced to the
    /// [`sng_core::events::ZtnaEvent::posture_result`]
    /// field so dashboards can distinguish a genuine
    /// posture failure from a deny that short-circuited
    /// before the posture check ran (e.g. a tenant
    /// mismatch or a stale MFA assertion).
    ///
    /// The previous shape (`posture_pass: bool`)
    /// collapsed these two cases into `false`, which
    /// made `posture_result = "fail"` ambiguous on the
    /// wire — it could mean either "the device's
    /// posture failed" or "this deny short-circuited
    /// before posture was even checked." Splitting them
    /// out via [`PostureResult`] keeps the field name's
    /// promise.
    pub posture_result: PostureResult,
}

impl ZtnaDecision {
    /// Convenience: allow with
    /// `posture_result=PostureResult::Pass`. The allow
    /// path always traverses the posture check, so
    /// `Pass` is the only valid spelling for the
    /// posture outcome on an allow.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allow: true,
            reason: ZtnaDecisionReason::Allow,
            posture_result: PostureResult::Pass,
        }
    }

    /// Convenience: deny with the given reason and
    /// posture result. The caller is responsible for
    /// supplying the correct posture-check outcome:
    /// [`PostureResult::Fail`] for posture-related
    /// denies, [`PostureResult::NotEvaluated`] for
    /// pre-posture short-circuits.
    #[must_use]
    pub const fn deny(reason: ZtnaDecisionReason, posture_result: PostureResult) -> Self {
        Self {
            allow: false,
            reason,
            posture_result,
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
    ///
    /// **Empty string disables the cross-tenant guard.**
    /// This is the intentional shape for single-tenant
    /// deployments where every device and user belong
    /// to the same implicit tenant and the bundle
    /// adapter has no tenant claim to install. Multi-
    /// tenant deployments MUST reject an empty
    /// `tenant_id` at the bundle adapter — the
    /// evaluator can't tell single-tenant-by-design
    /// apart from multi-tenant-misconfiguration, only
    /// the bundle source knows. [`Self::validate`] is
    /// intentionally silent on emptiness for this
    /// reason; the multi-tenant bundle adapter layers
    /// its own non-empty check on top.
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

impl ZtnaPolicy {
    /// Validate the value-domain invariants on this
    /// policy. Called from
    /// [`ZtnaPolicyHolder::try_replace`] (and indirectly
    /// from [`crate::service::ZtnaService::reload_policy`])
    /// so a misconfigured bundle is rejected at load
    /// time and the previously-active ruleset stays in
    /// force.
    ///
    /// The current checks reject:
    ///
    /// - `mfa_max_age_ms == 0` — a zero freshness budget
    ///   marks every MFA assertion stale, making the
    ///   evaluator a uniform deny.
    /// - `device_posture_max_age_ms == 0` — same reason
    ///   for posture freshness.
    ///
    /// `tenant_id` is *not* checked here — the empty
    /// string is the intentional spelling for single-
    /// tenant deployments (see the doc on
    /// [`Self::tenant_id`]). Multi-tenant deployments
    /// add a non-empty check at the bundle adapter
    /// layer where the bundle's claim on a tenant is
    /// known.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when any of the
    ///   above invariants fail.
    pub fn validate(&self) -> Result<(), ZtnaError> {
        if self.mfa_max_age_ms == 0 {
            return Err(ZtnaError::InvalidPolicy(
                "mfa_max_age_ms must be > 0 (a zero budget marks every MFA assertion stale)"
                    .to_owned(),
            ));
        }
        if self.device_posture_max_age_ms == 0 {
            return Err(ZtnaError::InvalidPolicy(
                "device_posture_max_age_ms must be > 0 (a zero budget marks every posture attestation stale)"
                    .to_owned(),
            ));
        }
        Ok(())
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
    /// Construct a holder around `policy` *without*
    /// validating it. Reserved for callers that already
    /// own a known-good policy — primarily
    /// [`ZtnaPolicy::default`] and unit tests. Bundle
    /// adapters and any externally-sourced policy should
    /// use [`try_new`](Self::try_new) instead so a
    /// misconfigured bundle is rejected at load time
    /// rather than silently replacing the working
    /// ruleset with one that denies every request.
    #[must_use]
    pub fn new(policy: ZtnaPolicy) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(policy)),
        }
    }

    /// Construct a holder around `policy`, returning an
    /// error if the policy fails [`ZtnaPolicy::validate`].
    /// The intended call site is the bundle adapter that
    /// converts a decoded policy bundle into the in-memory
    /// ZTNA snapshot — a misconfigured bundle is rejected
    /// at load time and the supervisor keeps the
    /// previously-active policy.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when `policy`
    ///   fails [`ZtnaPolicy::validate`].
    pub fn try_new(policy: ZtnaPolicy) -> Result<Self, ZtnaError> {
        policy.validate()?;
        Ok(Self::new(policy))
    }

    /// Replace the active policy *without* validating
    /// it. Reserved for known-good policies; bundle
    /// adapters should use
    /// [`try_replace`](Self::try_replace) so a
    /// misconfigured candidate cannot clobber the live
    /// ruleset. In-flight evaluations see the old policy
    /// until they finish.
    pub fn replace(&self, policy: ZtnaPolicy) {
        self.inner.store(Arc::new(policy));
    }

    /// Validate and atomically replace the policy. On
    /// validation failure the previously-loaded policy
    /// is preserved and the data path keeps running
    /// against the last known-good ruleset.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when `policy`
    ///   fails [`ZtnaPolicy::validate`].
    pub fn try_replace(&self, policy: ZtnaPolicy) -> Result<(), ZtnaError> {
        policy.validate()?;
        self.replace(policy);
        Ok(())
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
/// On every deny the [`ZtnaDecision::posture_result`]
/// field reflects whether the posture check ran and
/// what it found:
///
/// - [`PostureResult::Pass`] — only on the allow path
///   (the evaluator currently denies immediately on a
///   posture failure, so a `(deny, Pass)` decision is
///   unreachable today but the variant is reserved for
///   future checks ordered after posture).
/// - [`PostureResult::Fail`] — on denies in steps 4-5
///   ([`ZtnaDecisionReason::DevicePostureStale`] and
///   [`ZtnaDecisionReason::DevicePostureInsufficient`]),
///   i.e. the posture check ran and failed.
/// - [`PostureResult::NotEvaluated`] — on denies in
///   steps 1-3 ([`ZtnaDecisionReason::TenantMismatch`],
///   [`ZtnaDecisionReason::NotEntitled`],
///   [`ZtnaDecisionReason::MfaStale`]), i.e. the
///   evaluator short-circuited before the posture check
///   ran. The prior shape collapsed this case into
///   `posture_pass=false`, which made the wire field
///   ambiguous — a dashboard couldn't tell whether a
///   `posture_result=fail` row meant "device posture
///   failed" or "deny landed before posture was even
///   checked."
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
        return ZtnaDecision::deny(
            ZtnaDecisionReason::TenantMismatch,
            PostureResult::NotEvaluated,
        );
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
            return ZtnaDecision::deny(
                ZtnaDecisionReason::NotEntitled,
                PostureResult::NotEvaluated,
            );
        }
    }

    // 3. MFA freshness.
    if !identity.mfa_fresh(now_ms, policy.mfa_max_age_ms) {
        return ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, PostureResult::NotEvaluated);
    }

    // 4. Device posture freshness.
    if !device.posture_fresh(now_ms, policy.device_posture_max_age_ms) {
        return ZtnaDecision::deny(ZtnaDecisionReason::DevicePostureStale, PostureResult::Fail);
    }

    // 5. Device posture sufficiency.
    if !app.posture_requirement.satisfied_by(&device.posture) {
        return ZtnaDecision::deny(
            ZtnaDecisionReason::DevicePostureInsufficient,
            PostureResult::Fail,
        );
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
        assert_eq!(dec.posture_result, PostureResult::Pass);
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
        // Short-circuited before the posture check ran
        // — not_evaluated, not fail.
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);
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
        let dec = ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, PostureResult::NotEvaluated);
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
    fn allow_decision_constructor_sets_posture_result_pass() {
        let dec = ZtnaDecision::allow();
        assert!(dec.allow);
        assert_eq!(dec.posture_result, PostureResult::Pass);
        assert_eq!(dec.reason, ZtnaDecisionReason::Allow);
    }

    #[test]
    fn deny_decision_constructor_preserves_posture_result() {
        // Pre-posture short-circuit deny (e.g. UnknownApp)
        // emits NotEvaluated so dashboards can distinguish
        // it from a posture failure.
        let dec = ZtnaDecision::deny(ZtnaDecisionReason::UnknownApp, PostureResult::NotEvaluated);
        assert!(!dec.allow);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);
        // A posture-related deny carries Fail; verify the
        // constructor preserves whatever the caller passes
        // (the right variant is chosen by the call site,
        // not the constructor).
        let dec2 = ZtnaDecision::deny(
            ZtnaDecisionReason::DevicePostureInsufficient,
            PostureResult::Fail,
        );
        assert_eq!(dec2.posture_result, PostureResult::Fail);
        // And the constructor also accepts Pass on a deny
        // — the variant is reserved for future checks
        // ordered after the posture check (today the
        // evaluator denies immediately on posture fail,
        // but a future `(deny, Pass)` is structurally
        // valid).
        let dec3 = ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, PostureResult::Pass);
        assert_eq!(dec3.posture_result, PostureResult::Pass);
    }

    #[test]
    fn posture_result_wire_alphabet_is_stable() {
        // The wire form is contract-stable across
        // releases; pin every variant so a renamed
        // serde tag (or a refactor to a different
        // string) fails the build.
        assert_eq!(PostureResult::Pass.as_str(), "pass");
        assert_eq!(PostureResult::Fail.as_str(), "fail");
        assert_eq!(PostureResult::NotEvaluated.as_str(), "not_evaluated");
    }

    #[test]
    fn posture_result_per_deny_branch_matches_contract() {
        // Steps 1–3 (pre-posture short-circuits) emit
        // NotEvaluated; steps 4–5 (posture-related)
        // emit Fail; allow emits Pass. This pins the
        // doc on evaluate_policy as executable contract.
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::Basic, &["eng"]);

        // Step 1: tenant mismatch — NotEvaluated.
        let d_wrong = device("t2", DevicePosture::pristine(now()));
        let u_ok = user("t1", &["eng"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d_wrong, &u_ok, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Step 2: not entitled — NotEvaluated.
        let d = device("t1", DevicePosture::pristine(now()));
        let u_wrong_group = user("t1", &["sales"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u_wrong_group, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::NotEntitled);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Step 3: MFA stale — NotEvaluated.
        let u_stale_mfa = user("t1", &["eng"], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u_stale_mfa, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Step 4: posture stale — Fail.
        let mut stale_posture = DevicePosture::pristine(now());
        stale_posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d_stale = device("t1", stale_posture);
        let dec = evaluate_policy(&p, inputs(&a, &d_stale, &u_ok, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureStale);
        assert_eq!(dec.posture_result, PostureResult::Fail);

        // Step 5: posture insufficient — Fail. Build a
        // *fresh-attested* unmanaged posture so the
        // staleness check (step 4) doesn't fire first.
        let a_strict = app("admin", PostureRequirement::Strict, &["eng"]);
        let mut unmanaged_fresh = DevicePosture::unmanaged();
        unmanaged_fresh.attested_at_ms = now();
        let d_unmanaged = device("t1", unmanaged_fresh);
        let dec = evaluate_policy(&p, inputs(&a_strict, &d_unmanaged, &u_ok, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureInsufficient);
        assert_eq!(dec.posture_result, PostureResult::Fail);

        // Allow path — Pass.
        let dec = evaluate_policy(&p, inputs(&a, &d, &u_ok, now()));
        assert!(dec.allow);
        assert_eq!(dec.posture_result, PostureResult::Pass);
    }

    #[test]
    fn validate_accepts_default_policy() {
        ZtnaPolicy::default()
            .validate()
            .expect("default policy must be valid");
    }

    #[test]
    fn validate_accepts_empty_tenant_id() {
        // Empty tenant_id is the intentional spelling
        // for single-tenant deployments — the multi-
        // tenant bundle-adapter layer adds its own
        // non-empty check. The policy itself must not
        // reject it.
        let p = ZtnaPolicy {
            tenant_id: String::new(),
            ..ZtnaPolicy::default()
        };
        p.validate().expect("empty tenant_id is intentional");
    }

    #[test]
    fn validate_rejects_zero_mfa_freshness() {
        // A zero MFA budget marks every assertion stale
        // — every request becomes a uniform deny. That
        // is almost certainly a misconfigured bundle,
        // not an operator intent, so the policy holder
        // rejects it at load time.
        let p = ZtnaPolicy {
            mfa_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = p.validate().expect_err("zero MFA budget must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(ref m) if m.contains("mfa_max_age_ms")));
    }

    #[test]
    fn validate_rejects_zero_device_posture_freshness() {
        let p = ZtnaPolicy {
            device_posture_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = p
            .validate()
            .expect_err("zero posture budget must be rejected");
        assert!(
            matches!(err, ZtnaError::InvalidPolicy(ref m) if m.contains("device_posture_max_age_ms"))
        );
    }

    #[test]
    fn policy_holder_try_new_rejects_invalid_policy() {
        let bad = ZtnaPolicy {
            mfa_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = ZtnaPolicyHolder::try_new(bad).expect_err("zero MFA budget must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(_)));
    }

    #[test]
    fn policy_holder_try_replace_preserves_previous_policy_on_invalid_input() {
        // Critical safety property: a bundle adapter
        // that feeds a malformed policy must NOT clobber
        // the last-known-good policy. The data path
        // keeps running with whatever was loaded before.
        let h = ZtnaPolicyHolder::new(policy("t1"));
        let baseline = h.snapshot();
        let bad = ZtnaPolicy {
            mfa_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = h
            .try_replace(bad)
            .expect_err("zero MFA budget must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(_)));
        // Old policy still present (Arc-identity check).
        assert!(Arc::ptr_eq(&baseline, &h.snapshot()));
    }

    #[test]
    fn policy_holder_try_replace_swaps_on_valid_policy() {
        let h = ZtnaPolicyHolder::new(policy("t1"));
        h.try_replace(policy("t2"))
            .expect("valid policy must install");
        assert_eq!(h.snapshot().tenant_id, "t2");
    }
}

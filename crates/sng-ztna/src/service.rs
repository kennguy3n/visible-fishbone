//! ZTNA orchestrator.
//!
//! [`ZtnaService`] is the brain that the proxy / sng-edge
//! calls per per-application access attempt. Flow:
//!
//! 1. Producer calls [`ZtnaService::evaluate`] with an
//!    [`crate::request::AccessRequest`] and the current
//!    monotonic millisecond timestamp.
//! 2. Service resolves the app via the configured
//!    [`crate::app::AppCatalogProvider`]; an unknown
//!    `app_id` short-circuits to a deny with reason
//!    `unknown_app`.
//! 3. Service resolves the device via the configured
//!    [`crate::device::DeviceTrustProvider`]; an unenrolled
//!    `device_id` short-circuits to a deny with reason
//!    `device_not_enrolled`.
//! 4. Service resolves the identity via the configured
//!    [`crate::identity::IdentityProvider`]; an unknown
//!    `user_id` short-circuits to a deny with reason
//!    `identity_not_found`.
//! 5. Service runs the inputs through
//!    [`crate::policy::evaluate_policy`] against the
//!    active [`crate::policy::ZtnaPolicyHolder`] snapshot
//!    to produce a [`crate::policy::ZtnaDecision`].
//! 6. Service maps the decision to an
//!    [`sng_core::envelope::Verdict`] and emits one
//!    [`sng_core::events::ZtnaEvent`] through the
//!    telemetry channel — `try_send`, never blocking.
//! 7. Service bumps the appropriate
//!    [`crate::stats::ZtnaStats`] counter and returns the
//!    decision to the producer.
//!
//! The whole call is **sync** — no I/O. Providers refresh
//! their tables off the request path (downloader tasks
//! repopulate the in-process maps; producer-side caches
//! sit in front of remote APIs).

use crate::app::{AppCatalogProvider, StaticAppCatalog};
use crate::device::{DeviceTrustProvider, StaticDeviceTrustProvider};
use crate::error::ZtnaError;
use crate::identity::{IdentityProvider, StaticIdentityProvider};
use crate::policy::{
    EvaluationInputs, PostureResult, ZtnaDecision, ZtnaDecisionReason, ZtnaPolicy,
    ZtnaPolicyHolder, evaluate_policy,
};
use crate::request::AccessRequest;
use crate::stats::ZtnaStats;
use sng_core::envelope::Verdict;
use sng_core::events::ZtnaEvent;
use sng_telemetry::TelemetryEvent;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Map a [`ZtnaDecision`] to the wire-level [`Verdict`]
/// the data path consumes.
///
/// `Allow` → [`Verdict::Allow`]; every deny variant →
/// [`Verdict::Deny`]. The ZTNA brain does not produce
/// `Alert` or `Inspect` verdicts — access is binary at
/// this layer, and any "soft" enforcement is expressed
/// at the SWG / IPS layers, not here.
#[must_use]
pub const fn decision_to_verdict(decision: &ZtnaDecision) -> Verdict {
    if decision.allow {
        Verdict::Allow
    } else {
        Verdict::Deny
    }
}

/// Configuration for [`ZtnaService`].
#[derive(Clone, Debug)]
pub struct ZtnaServiceConfig {
    /// Producer-enforced ceiling on the number of
    /// concurrent ZTNA sessions the brain advertises
    /// it is willing to evaluate access requests for.
    ///
    /// # Enforcement contract
    ///
    /// The ZTNA brain is **stateless per-request** — it
    /// has no notion of a "session" beyond the single
    /// [`crate::request::AccessRequest`] currently being
    /// evaluated. Session lifecycle (TCP connection up
    /// / down, idle-timeout, user-initiated logout,
    /// proxy-side reaper) is owned exclusively by the
    /// **producer layer** (`sng-edge` proxy /
    /// `sng-agent` endpoint client), which is the only
    /// component with the visibility to count live
    /// sessions across the data path.
    ///
    /// This field is therefore an **advisory ceiling**:
    /// the brain plumbs it through via
    /// [`ZtnaService::max_sessions`] so the producer
    /// can read the configured cap (operator-set in the
    /// policy bundle) and shed load *before* calling
    /// [`ZtnaService::evaluate`] when its own live-
    /// session counter would exceed the ceiling. "Shed
    /// load" concretely means: return a 429-class
    /// transport-level error to the originating flow,
    /// or queue / reject the new connection, without
    /// the request ever reaching the brain.
    ///
    /// Brain-side enforcement would be structurally
    /// wrong: a counter incremented on `Allow` and
    /// decremented on "session end" requires the brain
    /// to be notified of every session termination,
    /// which crosses the per-request boundary that
    /// makes the brain trivially sharable across
    /// producer instances (multiple `sng-edge`
    /// processes can call into a single brain via
    /// `Arc<ZtnaService>`).
    pub max_sessions: usize,
}

impl Default for ZtnaServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 131_072,
        }
    }
}

/// Builder for [`ZtnaService`]. Mirrors
/// [`crate::SwgServiceBuilder`](../../sng_swg/struct.SwgServiceBuilder.html)'s
/// shape so call sites that wire one subsystem can wire
/// the other with the same idioms.
#[allow(missing_debug_implementations)]
pub struct ZtnaServiceBuilder {
    cfg: ZtnaServiceConfig,
    policy: Arc<ZtnaPolicyHolder>,
    apps: Arc<dyn AppCatalogProvider>,
    devices: Arc<dyn DeviceTrustProvider>,
    identities: Arc<dyn IdentityProvider>,
    stats: Arc<ZtnaStats>,
}

impl ZtnaServiceBuilder {
    /// Initialise a builder with default providers
    /// (empty in-memory tables) and default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfg: ZtnaServiceConfig::default(),
            policy: Arc::new(ZtnaPolicyHolder::default()),
            apps: Arc::new(StaticAppCatalog::default()),
            devices: Arc::new(StaticDeviceTrustProvider::default()),
            identities: Arc::new(StaticIdentityProvider::default()),
            stats: Arc::new(ZtnaStats::default()),
        }
    }

    /// Override the config.
    #[must_use]
    pub fn with_config(mut self, cfg: ZtnaServiceConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Override the policy holder.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<ZtnaPolicyHolder>) -> Self {
        self.policy = policy;
        self
    }

    /// Override the app catalog provider.
    #[must_use]
    pub fn with_app_catalog(mut self, p: Arc<dyn AppCatalogProvider>) -> Self {
        self.apps = p;
        self
    }

    /// Override the device-trust provider.
    #[must_use]
    pub fn with_device_trust(mut self, p: Arc<dyn DeviceTrustProvider>) -> Self {
        self.devices = p;
        self
    }

    /// Override the identity provider.
    #[must_use]
    pub fn with_identity(mut self, p: Arc<dyn IdentityProvider>) -> Self {
        self.identities = p;
        self
    }

    /// Override the stats handle (so peers can share a
    /// single bucket).
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<ZtnaStats>) -> Self {
        self.stats = stats;
        self
    }

    /// Build the service. `telemetry` is the egress
    /// channel — every evaluation `try_send`s one
    /// [`sng_core::events::ZtnaEvent`] here.
    #[must_use]
    pub fn build(self, telemetry: mpsc::Sender<TelemetryEvent>) -> ZtnaService {
        ZtnaService {
            cfg: self.cfg,
            policy: self.policy,
            apps: self.apps,
            devices: self.devices,
            identities: self.identities,
            stats: self.stats,
            telemetry,
        }
    }
}

impl Default for ZtnaServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The ZTNA service. Cheap to share via [`Arc`] — every
/// internal handle is itself clone-cheap (the providers
/// hold their state in [`arc_swap::ArcSwap`] or
/// [`parking_lot::Mutex`] internally, the policy holder
/// is `ArcSwap`-backed, and the telemetry sender is an
/// `mpsc::Sender` clone).
#[derive(Clone)]
pub struct ZtnaService {
    cfg: ZtnaServiceConfig,
    policy: Arc<ZtnaPolicyHolder>,
    apps: Arc<dyn AppCatalogProvider>,
    devices: Arc<dyn DeviceTrustProvider>,
    identities: Arc<dyn IdentityProvider>,
    stats: Arc<ZtnaStats>,
    telemetry: mpsc::Sender<TelemetryEvent>,
}

impl std::fmt::Debug for ZtnaService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZtnaService")
            .field("cfg", &self.cfg)
            .field("policy", &"<policy>")
            .field("apps", &"<provider>")
            .field("devices", &"<provider>")
            .field("identities", &"<provider>")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl ZtnaService {
    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<ZtnaStats> {
        &self.stats
    }

    /// Policy holder.
    #[must_use]
    pub fn policy(&self) -> &Arc<ZtnaPolicyHolder> {
        &self.policy
    }

    /// Producer-side advisory ceiling on concurrent
    /// sessions. See the doc comment on
    /// [`ZtnaServiceConfig::max_sessions`] for the full
    /// enforcement contract: this returns the
    /// configured cap, but the brain does not count
    /// or reject — the producer (`sng-edge` /
    /// `sng-agent`) reads this value and sheds load
    /// before calling [`Self::evaluate`].
    #[must_use]
    pub fn max_sessions(&self) -> usize {
        self.cfg.max_sessions
    }

    /// Reload the active ZTNA policy. Atomic from the
    /// data path's point of view — in-flight evaluations
    /// finish against the old policy snapshot they
    /// already loaded.
    ///
    /// The reload validates the candidate policy via
    /// [`ZtnaPolicy::validate`] before installing it. A
    /// failed validation leaves the previously-loaded
    /// policy active (the data path keeps running with
    /// the last known-good ruleset), records a
    /// [`ZtnaStats::record_bundle_load_failure`], and
    /// returns the error so the bundle adapter (or the
    /// caller that explicitly drove the reload) can
    /// surface it. The success counter
    /// [`ZtnaStats::record_bundle_load`] is bumped only
    /// on a successful install — ops dashboards can
    /// distinguish `new policy applied` from `new
    /// policy rejected`.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when the candidate
    ///   policy fails [`ZtnaPolicy::validate`] (zero
    ///   freshness budget for MFA or device posture).
    pub fn reload_policy(&self, policy: ZtnaPolicy) -> Result<(), ZtnaError> {
        match self.policy.try_replace(policy) {
            Ok(()) => {
                self.stats.record_bundle_load();
                Ok(())
            }
            Err(e) => {
                self.stats.record_bundle_load_failure();
                Err(e)
            }
        }
    }

    /// Record a failed bundle reload. The bundle adapter
    /// calls this when bundle decode itself fails (before
    /// it has a `ZtnaPolicy` to hand to
    /// [`Self::reload_policy`]).
    pub fn record_bundle_load_failure(&self) {
        self.stats.record_bundle_load_failure();
    }

    /// Evaluate one access attempt.
    ///
    /// The function is sync and allocation-light: on the
    /// allow path it allocates only for the one
    /// [`ZtnaEvent`] handed to telemetry (and only when
    /// telemetry actually accepts the event; a dropped
    /// `try_send` returns the unsent event so no
    /// downstream allocator is touched). Deny paths do
    /// the same work plus the deny-reason string lookup,
    /// which is a static `&'static str`.
    ///
    /// # Errors
    ///
    /// Returns an [`ZtnaError`] only when the orchestrator
    /// would otherwise have had to fabricate a synthetic
    /// allow / deny to handle a provider-resolution miss.
    /// Specifically:
    ///
    /// - [`ZtnaError::UnknownApp`] when `request.app_id`
    ///   is not in the active catalog.
    /// - [`ZtnaError::DeviceNotEnrolled`] when
    ///   `request.device_id` is not in the device-trust
    ///   provider.
    /// - [`ZtnaError::IdentityNotFound`] when
    ///   `request.user_id` is not in the identity
    ///   provider.
    ///
    /// In each case the orchestrator has already (a)
    /// bumped the appropriate `deny_*` counter on
    /// [`ZtnaStats`] and (b) emitted a `deny` telemetry
    /// event so the dashboards see the request even if
    /// the producer drops the error on the floor. The
    /// data path then treats the error as a deny.
    pub fn evaluate(&self, request: &AccessRequest) -> Result<ZtnaDecision, ZtnaError> {
        // Step 1: resolve the app.
        let Some(app) = self.apps.get(&request.app_id) else {
            self.emit_deny(
                &request.device_id,
                &request.app_id,
                ZtnaDecisionReason::UnknownApp,
                PostureResult::NotEvaluated,
                false,
            );
            return Err(ZtnaError::UnknownApp {
                app_id: request.app_id.clone(),
            });
        };

        // Step 2: resolve the device.
        let Some(device) = self.devices.get(&request.device_id) else {
            self.emit_deny(
                &request.device_id,
                &request.app_id,
                ZtnaDecisionReason::DeviceNotEnrolled,
                PostureResult::NotEvaluated,
                false,
            );
            return Err(ZtnaError::DeviceNotEnrolled {
                device_id: request.device_id.clone(),
            });
        };

        // Step 3: resolve the identity. We pass
        // `identity_verified=false` on the missing-
        // identity path because, while the IdP-side
        // verification may have produced a `sub` claim,
        // the ZTNA brain itself cannot vouch for an
        // identity it has no record of.
        let Some(identity) = self.identities.get(&request.user_id) else {
            self.emit_deny(
                &request.device_id,
                &request.app_id,
                ZtnaDecisionReason::IdentityNotFound,
                PostureResult::NotEvaluated,
                false,
            );
            return Err(ZtnaError::IdentityNotFound {
                user_id: request.user_id.clone(),
            });
        };

        // Step 4: run the policy.
        let policy_snap = self.policy.snapshot();
        let decision = evaluate_policy(
            &policy_snap,
            EvaluationInputs {
                app: &app,
                device: &device,
                identity: &identity,
                now_ms: request.now_ms,
            },
        );

        // Step 5: stats + telemetry. The decision reason
        // is the authoritative bucket; the boolean
        // `allow` is just a derived view for the
        // producer.
        self.stats.record_decision(&decision.reason);
        let event = build_ztna_event(
            &request.device_id,
            &request.app_id,
            &decision,
            // identity was resolved successfully — the
            // producer's mTLS + IdP chain *did* yield a
            // recognisable user.
            true,
        );
        if self
            .telemetry
            .try_send(TelemetryEvent::Ztna(event))
            .is_err()
        {
            self.stats.record_telemetry_drop();
        }

        Ok(decision)
    }

    /// Helper that emits a deny telemetry event +
    /// records the deny counter for the early-return
    /// paths (provider misses). Kept as a method on
    /// `&self` so the borrow stays clean inside
    /// `evaluate`'s `let-else` short-circuits. The
    /// `reason` is moved into the constructed
    /// [`ZtnaDecision`] so the helper allocates nothing
    /// of its own beyond the [`ZtnaEvent`] body.
    fn emit_deny(
        &self,
        device_id: &str,
        app_id: &str,
        reason: ZtnaDecisionReason,
        posture_result: PostureResult,
        identity_verified: bool,
    ) {
        let decision = ZtnaDecision::deny(reason, posture_result);
        self.stats.record_decision(&decision.reason);
        let event = build_ztna_event(device_id, app_id, &decision, identity_verified);
        if self
            .telemetry
            .try_send(TelemetryEvent::Ztna(event))
            .is_err()
        {
            self.stats.record_telemetry_drop();
        }
    }
}

/// Build a wire-shape [`ZtnaEvent`] from a decision +
/// the per-request identifiers. Kept free-standing so
/// both [`ZtnaService::evaluate`] and
/// [`ZtnaService::emit_deny`] can share the construction
/// without re-implementing the field mapping.
fn build_ztna_event(
    device_id: &str,
    app_id: &str,
    decision: &ZtnaDecision,
    identity_verified: bool,
) -> ZtnaEvent {
    // `decision` carries the binary allow/deny outcome
    // (the field is documented as such on
    // [`ZtnaEvent::decision`]); the detailed structured
    // reason — e.g. `unknown_app`, `mfa_stale`,
    // `tenant_mismatch` — lives on
    // [`ZtnaEvent::reason`]. Dashboards that bucket by
    // outcome and dashboards that bucket by cause both
    // have one place to read from.
    ZtnaEvent {
        device_id: device_id.to_string(),
        app_id: app_id.to_string(),
        // The wire alphabet is the tri-state
        // `"pass" | "fail" | "not_evaluated"`; see
        // [`crate::policy::PostureResult`] for the
        // contract. Older consumers that only know
        // `"pass"` / `"fail"` will see
        // `"not_evaluated"` as an unknown bucket
        // — safer than the previous behavior of
        // stamping `"fail"` on every non-posture deny,
        // which made the field literally lie about
        // whether the device's posture had failed.
        posture_result: decision.posture_result.as_str().to_string(),
        decision: if decision.allow { "allow" } else { "deny" }.to_string(),
        reason: decision.reason.as_str().to_string(),
        identity_verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use crate::device::{DevicePosture, DeviceTrust};
    use crate::identity::UserIdentity;
    use crate::policy::PostureRequirement;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;
    use tokio::sync::mpsc;

    const TENANT: &str = "t1";

    fn pristine_posture(now_ms: u64) -> DevicePosture {
        DevicePosture::pristine(now_ms)
    }

    fn app(name: &str, posture: PostureRequirement, groups: &[&str]) -> App {
        App {
            app_id: name.into(),
            display_name: name.into(),
            host_patterns: Vec::new(),
            required_groups: groups.iter().map(|s| (*s).to_string()).collect(),
            posture_requirement: posture,
        }
    }

    fn device(id: &str, tenant: &str, posture: DevicePosture) -> DeviceTrust {
        DeviceTrust {
            device_id: id.into(),
            tenant_id: tenant.into(),
            posture,
        }
    }

    fn user(id: &str, tenant: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
        UserIdentity {
            user_id: id.into(),
            tenant_id: tenant.into(),
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            mfa_at_ms,
        }
    }

    fn policy(tenant: &str) -> ZtnaPolicy {
        ZtnaPolicy {
            tenant_id: tenant.into(),
            ..ZtnaPolicy::default()
        }
    }

    fn mk_service(
        apps: Vec<App>,
        devices: Vec<DeviceTrust>,
        users: Vec<UserIdentity>,
        pol: ZtnaPolicy,
        chan_cap: usize,
    ) -> (ZtnaService, mpsc::Receiver<TelemetryEvent>) {
        let (tx, rx) = mpsc::channel(chan_cap);
        let svc = ZtnaServiceBuilder::new()
            .with_policy(Arc::new(ZtnaPolicyHolder::new(pol)))
            .with_app_catalog(Arc::new(StaticAppCatalog::new(apps)))
            .with_device_trust(Arc::new(StaticDeviceTrustProvider::new(devices)))
            .with_identity(Arc::new(StaticIdentityProvider::new(users)))
            .build(tx);
        (svc, rx)
    }

    fn req(app_id: &str, device_id: &str, user_id: &str, now_ms: u64) -> AccessRequest {
        AccessRequest::new(app_id, device_id, user_id, now_ms)
    }

    fn drain<T>(rx: &mut mpsc::Receiver<T>) -> Vec<T> {
        let mut out = Vec::new();
        while let Ok(v) = rx.try_recv() {
            out.push(v);
        }
        out
    }

    fn ztna_event(ev: &TelemetryEvent) -> &ZtnaEvent {
        match ev {
            TelemetryEvent::Ztna(e) => e,
            other => panic!("expected ZtnaEvent, got {other:?}"),
        }
    }

    #[test]
    fn allow_path_emits_allow_event_and_returns_allow_decision() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::Basic, &["eng"])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![user("alice", TENANT, &["eng"], now)],
            policy(TENANT),
            8,
        );
        let d = svc
            .evaluate(&req("wiki", "dev-1", "alice", now))
            .expect("allow path returns Ok");
        assert!(d.allow);
        assert_eq!(d.reason, ZtnaDecisionReason::Allow);
        assert_eq!(d.posture_result, PostureResult::Pass);
        // One ZtnaEvent on the channel, identity verified,
        // posture pass.
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 1);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.device_id, "dev-1");
        assert_eq!(ev.app_id, "wiki");
        assert_eq!(ev.posture_result, "pass");
        assert_eq!(ev.decision, "allow");
        // Allow path: `reason` carries the same `allow`
        // marker as `decision` — dashboards keying off the
        // dedicated reason field see a non-empty,
        // discriminating bucket label.
        assert_eq!(ev.reason, "allow");
        assert!(ev.identity_verified);
        // Stats: one request, one allow.
        let snap = svc.stats.snapshot();
        assert_eq!(snap.requests_evaluated, 1);
        assert_eq!(snap.decision_allow, 1);
    }

    #[test]
    fn unknown_app_short_circuits_with_error_and_emits_deny_event() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![user("alice", TENANT, &[], now)],
            policy(TENANT),
            4,
        );
        let err = svc
            .evaluate(&req("missing", "dev-1", "alice", now))
            .expect_err("unknown app returns Err");
        match err {
            ZtnaError::UnknownApp { app_id } => assert_eq!(app_id, "missing"),
            other => panic!("expected UnknownApp, got {other:?}"),
        }
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 1);
        let ev = ztna_event(&evs[0]);
        // The wire-shape `decision` field is the binary
        // outcome (`deny`) and the detailed bucket label
        // (`unknown_app`) lives on `reason` — see
        // `build_ztna_event` for why the split is
        // intentional.
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "unknown_app");
        // UnknownApp short-circuits before the policy
        // evaluator runs the posture check — the wire
        // field correctly reflects "not evaluated"
        // rather than "fail" (which would falsely
        // suggest a device-posture issue).
        assert_eq!(ev.posture_result, "not_evaluated");
        // identity_verified is false on the early-return
        // path because the orchestrator never reached the
        // identity provider.
        assert!(!ev.identity_verified);
        let snap = svc.stats.snapshot();
        assert_eq!(snap.requests_evaluated, 1);
        assert_eq!(snap.deny_unknown_app, 1);
        assert_eq!(snap.decision_allow, 0);
    }

    #[test]
    fn device_not_enrolled_short_circuits_with_error() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![],
            vec![user("alice", TENANT, &[], now)],
            policy(TENANT),
            4,
        );
        let err = svc
            .evaluate(&req("wiki", "dev-1", "alice", now))
            .expect_err("device-not-enrolled returns Err");
        assert!(matches!(err, ZtnaError::DeviceNotEnrolled { .. }));
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "device_not_enrolled");
        assert!(!ev.identity_verified);
        let snap = svc.stats.snapshot();
        assert_eq!(snap.deny_device_not_enrolled, 1);
    }

    #[test]
    fn identity_not_found_short_circuits_with_error() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![],
            policy(TENANT),
            4,
        );
        let err = svc
            .evaluate(&req("wiki", "dev-1", "alice", now))
            .expect_err("identity-not-found returns Err");
        assert!(matches!(err, ZtnaError::IdentityNotFound { .. }));
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "identity_not_found");
        // Even though the IdP chain validated the `sub`
        // claim, the brain's identity provider has no
        // record, so we report `identity_verified=false`
        // — the brain cannot vouch for an identity it
        // does not know.
        assert!(!ev.identity_verified);
        let snap = svc.stats.snapshot();
        assert_eq!(snap.deny_identity_not_found, 1);
    }

    #[test]
    fn tenant_mismatch_denies_with_structured_reason() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", "OTHER_TENANT", pristine_posture(now))],
            vec![user("alice", TENANT, &[], now)],
            policy(TENANT),
            4,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert!(!d.allow);
        assert_eq!(d.reason, ZtnaDecisionReason::TenantMismatch);
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "tenant_mismatch");
        // identity_verified=true here because the brain
        // *did* resolve every provider; the policy is
        // what said no.
        assert!(ev.identity_verified);
        assert_eq!(svc.stats.snapshot().deny_tenant_mismatch, 1);
    }

    #[test]
    fn not_entitled_denies_when_user_lacks_required_group() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &["eng"])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![user("alice", TENANT, &["sales"], now)],
            policy(TENANT),
            4,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert_eq!(d.reason, ZtnaDecisionReason::NotEntitled);
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "not_entitled");
        assert_eq!(svc.stats.snapshot().deny_not_entitled, 1);
    }

    #[test]
    fn mfa_stale_denies_after_max_age() {
        let now = 100_000_000;
        let pol = ZtnaPolicy {
            mfa_max_age_ms: 60_000,
            ..policy(TENANT)
        };
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            // mfa_at_ms is 5 minutes ago; max age is 1 min.
            vec![user("alice", TENANT, &[], now - 5 * 60_000)],
            pol,
            4,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert_eq!(d.reason, ZtnaDecisionReason::MfaStale);
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "mfa_stale");
        assert_eq!(svc.stats.snapshot().deny_mfa_stale, 1);
    }

    #[test]
    fn device_posture_stale_denies_after_max_age() {
        let now = 100_000_000;
        let pol = ZtnaPolicy {
            device_posture_max_age_ms: 60_000,
            ..policy(TENANT)
        };
        let stale_posture = DevicePosture {
            attested_at_ms: now - 5 * 60_000,
            ..DevicePosture::pristine(0)
        };
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", TENANT, stale_posture)],
            vec![user("alice", TENANT, &[], now)],
            pol,
            4,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert_eq!(d.reason, ZtnaDecisionReason::DevicePostureStale);
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "device_posture_stale");
        assert_eq!(svc.stats.snapshot().deny_device_posture_stale, 1);
    }

    #[test]
    fn device_posture_insufficient_denies_when_strict_unmet() {
        let now = 1_000_000;
        let mut posture = DevicePosture::pristine(now);
        // Drop one signal to fail Strict.
        posture.screen_lock_configured = false;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::Strict, &[])],
            vec![device("dev-1", TENANT, posture)],
            vec![user("alice", TENANT, &[], now)],
            policy(TENANT),
            4,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert_eq!(d.reason, ZtnaDecisionReason::DevicePostureInsufficient);
        // Posture check ran and the device failed it
        // — wire field reflects "fail" honestly here
        // (contrast with the UnknownApp test above,
        // where the field reflects "not_evaluated").
        assert_eq!(d.posture_result, PostureResult::Fail);
        let evs = drain(&mut rx);
        let ev = ztna_event(&evs[0]);
        assert_eq!(ev.decision, "deny");
        assert_eq!(ev.reason, "device_posture_insufficient");
        assert_eq!(ev.posture_result, "fail");
        assert_eq!(svc.stats.snapshot().deny_device_posture_insufficient, 1);
    }

    #[test]
    fn telemetry_full_records_drop_counter_and_returns_decision() {
        let now = 1_000_000;
        // Channel of capacity 1; first allow fills it,
        // second allow must `try_send` and credit the
        // drop counter — without blocking.
        let (svc, _rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![user("alice", TENANT, &[], now)],
            policy(TENANT),
            1,
        );
        let _ = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        let _ = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        // First fits, second drops.
        assert_eq!(svc.stats.snapshot().telemetry_drops, 1);
    }

    #[test]
    fn decision_to_verdict_is_total() {
        let allow = ZtnaDecision::allow();
        let deny = ZtnaDecision::deny(ZtnaDecisionReason::NotEntitled, PostureResult::NotEvaluated);
        assert_eq!(decision_to_verdict(&allow), Verdict::Allow);
        assert_eq!(decision_to_verdict(&deny), Verdict::Deny);
    }

    #[test]
    fn reload_policy_swaps_active_set_and_records_counter() {
        let now = 1_000_000;
        let (svc, mut rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![user("alice", "OTHER_TENANT", &[], now)],
            policy(TENANT),
            4,
        );
        // First evaluation under the original policy:
        // user is in OTHER_TENANT vs. policy TENANT.
        // Tenant mismatch.
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert_eq!(d.reason, ZtnaDecisionReason::TenantMismatch);

        // Reload with a policy whose tenant is empty,
        // disabling the tenant guard.
        svc.reload_policy(ZtnaPolicy {
            tenant_id: String::new(),
            ..ZtnaPolicy::default()
        })
        .expect("default policy with empty tenant_id is valid");
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert!(d.allow);

        // Drain the two events.
        let evs = drain(&mut rx);
        assert_eq!(evs.len(), 2);
        // Two distinct events on the wire: first the
        // (deny, tenant_mismatch) and then the (allow,
        // allow) once the request is re-driven against a
        // policy with a matching tenant.
        let pre_swap = ztna_event(&evs[0]);
        assert_eq!(pre_swap.decision, "deny");
        assert_eq!(pre_swap.reason, "tenant_mismatch");
        let post_swap = ztna_event(&evs[1]);
        assert_eq!(post_swap.decision, "allow");
        assert_eq!(post_swap.reason, "allow");

        assert_eq!(svc.stats.snapshot().bundle_loads, 1);
    }

    #[test]
    fn record_bundle_load_failure_increments_failure_counter() {
        let (svc, _rx) = mk_service(vec![], vec![], vec![], ZtnaPolicy::default(), 1);
        assert_eq!(svc.stats.snapshot().bundle_load_failures, 0);
        svc.record_bundle_load_failure();
        svc.record_bundle_load_failure();
        assert_eq!(svc.stats.snapshot().bundle_load_failures, 2);
    }

    #[test]
    fn empty_required_groups_allows_any_authenticated_user() {
        let now = 1_000_000;
        let (svc, _rx) = mk_service(
            vec![App {
                app_id: "wiki".into(),
                display_name: "Wiki".into(),
                host_patterns: Vec::new(),
                required_groups: HashSet::new(),
                posture_requirement: PostureRequirement::None,
            }],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            // No groups on the user.
            vec![user("alice", TENANT, &[], now)],
            policy(TENANT),
            4,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert!(d.allow);
    }

    #[test]
    fn forward_skewed_mfa_clock_is_tolerated() {
        // Identity provider says MFA happened 1s in the
        // future relative to the request clock — the
        // brain accepts this rather than starving the
        // user; see `UserIdentity::mfa_fresh` doc.
        let now = 1_000_000;
        let (svc, _rx) = mk_service(
            vec![app("wiki", PostureRequirement::None, &[])],
            vec![device("dev-1", TENANT, pristine_posture(now))],
            vec![user("alice", TENANT, &[], now + 1_000)],
            policy(TENANT),
            2,
        );
        let d = svc.evaluate(&req("wiki", "dev-1", "alice", now)).unwrap();
        assert!(d.allow);
    }

    #[test]
    fn service_builder_default_uses_static_providers_and_compiles() {
        let (tx, _rx) = mpsc::channel(1);
        let svc = ZtnaServiceBuilder::new().build(tx);
        // Empty catalog → unknown_app on every request.
        let err = svc
            .evaluate(&req("wiki", "dev-1", "alice", 0))
            .expect_err("default catalog is empty");
        assert!(matches!(err, ZtnaError::UnknownApp { .. }));
    }
}

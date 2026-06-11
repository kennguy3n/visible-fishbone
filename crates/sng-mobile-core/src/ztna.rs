//! Mobile ZTNA session manager.
//!
//! The per-flow access decision is *not* reimplemented here — it is
//! delegated to the shared [`sng_ztna::ZtnaService`], which evaluates
//! the request against the locally-held, signed policy bundle. This
//! manager layers the mobile-specific concerns on top:
//!
//! * it converts every decision into a metadata-only
//!   [`MobileTelemetryEvent::ZtnaAccess`] and records it through the
//!   shared telemetry egress, and
//! * it tracks per-app access state so the agent's tunnel
//!   reconciliation loop knows which apps are currently allowed
//!   (and should have a tunnel route) versus denied.
//!
//! The `ZtnaService` is built by the agent (mirroring the desktop
//! `sng-agent` wiring) and injected here as an `Arc`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tracing::warn;

use sng_ztna::{
    AccessRequest, PostureResult, ZtnaDecision, ZtnaDecisionReason, ZtnaError, ZtnaService,
};

use crate::error::MobileError;
use crate::posture::MobilePostureSnapshot;
use crate::telemetry::{MobileTelemetry, MobileTelemetryEvent};

/// Fail-closed mobile posture pre-gate run before the shared ZTNA
/// policy evaluation.
///
/// The shared [`ZtnaService`] evaluates the device-trust posture
/// the *control plane* last recorded for the device; this local
/// gate additionally refuses access whenever the device's own,
/// freshly-collected posture cannot be proven healthy, so a device
/// that has *become* compromised / unlocked since its last
/// attestation is cut off immediately rather than waiting for the
/// attestation to expire. It only inspects signals a mobile OS
/// actually exposes (jailbreak/root + screen lock); desktop-only
/// signals are never fabricated.
///
/// Returns the stable deny label when access must be refused, or
/// `None` to proceed to the shared policy evaluation. "Unprovable"
/// (a missing snapshot or an unknown signal) denies just like an
/// explicit failure — the gate never grants access on absent
/// evidence.
fn posture_pre_gate(posture: Option<&MobilePostureSnapshot>) -> Option<&'static str> {
    let Some(posture) = posture else {
        return Some("posture_unprovable");
    };
    if posture.is_compromised() {
        return Some("posture_compromised");
    }
    match posture.passcode_set {
        Some(true) => None,
        Some(false) => Some("posture_screen_lock_off"),
        None => Some("posture_unprovable"),
    }
}

/// The latest access disposition recorded for an app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppAccessState {
    /// Whether the most recent evaluation allowed the app.
    pub allowed: bool,
    /// Stable reason label of the most recent decision.
    pub reason: String,
    /// When the decision was recorded (informational / display).
    pub decided_at: DateTime<Utc>,
    /// Strictly-monotonic per-decision version stamp, allocated from the
    /// manager's [`AtomicU64`] counter. This — not `decided_at` — is the
    /// compare-and-set token the adaptive-trust sweep guards on in
    /// [`MobileZtnaManager::revoke_if_unchanged`]: a wall-clock timestamp
    /// can repeat (sub-resolution) or run backwards (NTP step), either of
    /// which could make a stale sweep deny falsely match a fresh grant. A
    /// counter is unique and monotonic by construction.
    pub version: u64,
    /// The originating access request, retained so the periodic
    /// adaptive-trust sweep ([`MobileZtnaManager::reevaluate_active`])
    /// can re-run the decision against freshly-collected posture
    /// without the caller replaying it. The sweep clones this and
    /// refreshes its `now_ms` per pass.
    request: AccessRequest,
}

/// The side-effect-free outcome of evaluating one request, shared by
/// the explicit-access path ([`MobileZtnaManager::evaluate`], which
/// always records + emits) and the adaptive-trust sweep
/// ([`MobileZtnaManager::reevaluate_active`], which records + emits
/// only on a revocation). Computing the decision here, away from the
/// recording, lets the two callers shape their telemetry differently
/// without duplicating the pre-gate / policy / provider-miss branches.
struct Classified {
    /// Whether the request is allowed.
    allow: bool,
    /// Stable reason label stored in per-app state and on the wire.
    reason: String,
    /// Wire `posture_result` spelling.
    posture_result: String,
    /// The fail-closed pre-gate cause, when the local posture pre-gate
    /// (not the shared policy) denied; `None` otherwise.
    posture_detail: Option<String>,
    /// Whether identity was verified (the shared policy ran).
    identity_verified: bool,
    /// The typed decision the explicit-access caller returns: `Ok` for
    /// a pre-gate or policy decision, `Err` for a provider miss.
    result: Result<ZtnaDecision, ZtnaError>,
}

/// Which observability path [`MobileZtnaManager::classify`] drives the
/// shared evaluator through. The verdict is identical either way (same
/// evaluator, so a tracked grant can never outlive a fresh access
/// request); only the service-side bookkeeping differs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EvalPath {
    /// An explicit user access request: emit the access-path telemetry
    /// event and bump the access decision counters
    /// ([`ZtnaService::evaluate`]).
    Access,
    /// The periodic adaptive-trust sweep: re-run the evaluator quietly
    /// ([`ZtnaService::evaluate_for_reeval`]). A sweep touches every
    /// live session across ~5000 tenants each cycle, so routing it
    /// through the access path would drown the producer's telemetry
    /// channel and double-count sweep verdicts into access counters.
    /// The sweep owns its own revocation telemetry instead.
    Reeval,
}

/// Map a [`ZtnaError`] (the provider-miss short-circuits that
/// `ZtnaService::evaluate` returns as `Err`) to the same stable
/// reason label the allow/deny telemetry uses, so dashboards bucket
/// provider misses consistently with policy denies.
fn error_reason_label(err: &ZtnaError) -> &'static str {
    match err {
        ZtnaError::UnknownApp { .. } => "unknown_app",
        ZtnaError::DeviceNotEnrolled { .. } => "device_not_enrolled",
        ZtnaError::IdentityNotFound { .. } => "identity_not_found",
        ZtnaError::TokenRejected { .. } => "token_rejected",
        ZtnaError::IdpConfigNotFound { .. } => "idp_config_not_found",
        ZtnaError::BundleDecode(_) | ZtnaError::InvalidPolicy(_) => "policy_unavailable",
        ZtnaError::ProviderFailure { .. } => "provider_failure",
        ZtnaError::Telemetry(_) => "telemetry_error",
    }
}

/// Mobile ZTNA session manager. Cheap to clone (`Arc`-backed).
#[derive(Clone)]
pub struct MobileZtnaManager {
    service: Arc<ZtnaService>,
    telemetry: Arc<MobileTelemetry>,
    app_state: Arc<Mutex<HashMap<String, AppAccessState>>>,
    /// Monotonic decision-version source for the `revoke_if_unchanged`
    /// compare-and-set (see [`AppAccessState::version`]).
    decision_seq: Arc<AtomicU64>,
}

impl std::fmt::Debug for MobileZtnaManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobileZtnaManager")
            .field("tracked_apps", &self.app_state.lock().len())
            .finish_non_exhaustive()
    }
}

impl MobileZtnaManager {
    /// Construct a manager over an already-built ZTNA service and a
    /// shared telemetry egress.
    #[must_use]
    pub fn new(service: Arc<ZtnaService>, telemetry: Arc<MobileTelemetry>) -> Self {
        Self {
            service,
            telemetry,
            app_state: Arc::new(Mutex::new(HashMap::new())),
            decision_seq: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Allocate the next strictly-monotonic decision version. Backed by
    /// an `AtomicU64` rather than the wall clock so the
    /// `revoke_if_unchanged` compare-and-set can never collide
    /// (sub-resolution timestamps) or run backwards (NTP step) — every
    /// recorded decision gets a unique, increasing stamp.
    fn next_version(&self) -> u64 {
        self.decision_seq.fetch_add(1, Ordering::Relaxed)
    }

    fn record_state(
        &self,
        request: &AccessRequest,
        allowed: bool,
        reason: &str,
        now: DateTime<Utc>,
    ) {
        // Allocate the version *inside* the lock — matching
        // `revoke_if_unchanged` — so the stored version is monotonic
        // with respect to lock-acquisition order. Allocating before the
        // lock would let a concurrent `revoke_if_unchanged` acquire the
        // lock first, write a higher version, and then have this insert
        // overwrite it with a lower one; the equality-based CAS stays
        // correct either way, but ordering the allocation by the lock
        // keeps the "stored version only ever increases" invariant easy
        // to reason about.
        let mut state = self.app_state.lock();
        let version = self.next_version();
        state.insert(
            request.app_id.clone(),
            AppAccessState {
                allowed,
                reason: reason.to_owned(),
                decided_at: now,
                version,
                request: request.clone(),
            },
        );
    }

    /// Apply a sweep-driven revocation only if the app's state has not
    /// changed since the sweep snapshotted it, returning whether the
    /// deny was written.
    ///
    /// The sweep snapshots the allowed apps under the lock, releases it
    /// to run `classify` (which must not hold the lock across the
    /// service call), then re-acquires it here to record a demotion.
    /// That gap is a TOCTOU window: a concurrent explicit
    /// [`Self::evaluate`] could re-decide the same app — typically a
    /// user re-requesting it against a *fresher* posture than the sweep
    /// saw — and a blind write would clobber that newer grant with the
    /// stale sweep deny. Guarding on `version` (the strictly-monotonic
    /// per-decision stamp from [`Self::next_version`]) makes the
    /// revocation a compare-and-set: if the entry was re-decided under us
    /// (different `version`) or already revoked, the fresher decision
    /// wins and the sweep drops its stale deny.
    fn revoke_if_unchanged(
        &self,
        request: &AccessRequest,
        reason: &str,
        now: DateTime<Utc>,
        snapshot_version: u64,
    ) -> bool {
        let mut state = self.app_state.lock();
        match state.get(&request.app_id) {
            Some(s) if s.allowed && s.version == snapshot_version => {
                state.insert(
                    request.app_id.clone(),
                    AppAccessState {
                        allowed: false,
                        reason: reason.to_owned(),
                        decided_at: now,
                        version: self.next_version(),
                        request: request.clone(),
                    },
                );
                true
            }
            _ => false,
        }
    }

    /// Evaluate one request without recording any side effects: run
    /// the fail-closed mobile posture pre-gate, then (if it passes)
    /// the shared policy engine, collapsing all three outcomes
    /// (pre-gate deny / policy decision / provider miss) into a
    /// [`Classified`]. Both the explicit-access path and the sweep
    /// build on this so their decision logic can never diverge.
    fn classify(
        &self,
        request: &AccessRequest,
        posture: Option<&MobilePostureSnapshot>,
        path: EvalPath,
    ) -> Classified {
        if let Some(gate_label) = posture_pre_gate(posture) {
            let reason = ZtnaDecisionReason::DevicePostureInsufficient;
            let decision = ZtnaDecision {
                allow: false,
                reason: reason.clone(),
                posture_result: PostureResult::Fail,
            };
            return Classified {
                allow: false,
                reason: reason.as_str().to_owned(),
                posture_result: decision.posture_result.as_str().to_owned(),
                // The stable wire reason stays `device_posture_insufficient`
                // (consistent with a policy-side posture deny); the gate
                // label rides the additive `posture_detail` field so
                // dashboards can break out the cause.
                posture_detail: Some(gate_label.to_owned()),
                identity_verified: false,
                result: Ok(decision),
            };
        }
        // Same verdict on both paths; `Reeval` stays off the
        // access-path counters and telemetry channel (see [`EvalPath`]).
        let result = match path {
            EvalPath::Access => self.service.evaluate(request),
            EvalPath::Reeval => self.service.evaluate_for_reeval(request),
        };
        match result {
            Ok(decision) => Classified {
                allow: decision.allow,
                reason: decision.reason.as_str().to_owned(),
                posture_result: decision.posture_result.as_str().to_owned(),
                // Shared-policy decisions carry no mobile pre-gate cause.
                posture_detail: None,
                identity_verified: true,
                result: Ok(decision),
            },
            Err(err) => Classified {
                allow: false,
                reason: error_reason_label(&err).to_owned(),
                // Provider-miss errors short-circuit before the posture
                // check; no posture result was produced.
                posture_result: "not_evaluated".to_owned(),
                posture_detail: None,
                identity_verified: false,
                result: Err(err),
            },
        }
    }

    /// Evaluate one access request against the local policy bundle,
    /// emit a metadata-only telemetry event for the outcome, and
    /// update the per-app access state.
    ///
    /// A provider-miss (unknown app / unenrolled device / unknown
    /// identity) surfaces from `ZtnaService::evaluate` as `Err`; it
    /// is still recorded as a deny (state + telemetry) before the
    /// typed error is returned, so the caller's accounting stays
    /// consistent with the policy-deny path.
    ///
    /// Telemetry recording is best-effort: it is observability, not a
    /// correctness gate. A failure to spool the event is logged but
    /// never shadows the access decision or the per-app state update,
    /// so the tunnel reconciler's view (`allowed_apps`) always tracks
    /// the latest decision.
    ///
    /// Before delegating, a fail-closed mobile posture pre-gate
    /// inspects the freshly-collected `posture`: when the device
    /// cannot be proven healthy the request is denied locally
    /// without consulting the shared
    /// policy engine, recorded as a `device_posture_insufficient`
    /// deny so the wire + per-app state stay consistent with a
    /// policy-side posture deny.
    pub async fn evaluate(
        &self,
        request: &AccessRequest,
        posture: Option<&MobilePostureSnapshot>,
        now: DateTime<Utc>,
    ) -> Result<ZtnaDecision, MobileError> {
        let c = self.classify(request, posture, EvalPath::Access);
        if let Some(gate_label) = c.posture_detail.as_deref() {
            warn!(
                app_id = %request.app_id,
                gate = gate_label,
                "mobile posture pre-gate denied access (fail-closed)"
            );
        }
        let event = MobileTelemetryEvent::ZtnaAccess {
            app_id: request.app_id.clone(),
            allow: c.allow,
            reason: c.reason.clone(),
            posture_detail: c.posture_detail.clone(),
            posture_result: c.posture_result.clone(),
            identity_verified: c.identity_verified,
        };
        self.record_telemetry_best_effort(&event, now).await;
        self.record_state(request, c.allow, &c.reason, now);
        c.result.map_err(MobileError::Ztna)
    }

    /// Re-evaluate every currently-allowed app against freshly
    /// collected `posture`, demoting any whose decision no longer
    /// holds. This is the mobile adaptive-trust sweep: the agent's
    /// periodic posture collector drives it, so a device whose posture
    /// decays mid-session (screen lock disabled, jailbreak / root, or a
    /// server-side device-trust downgrade folded into the next policy
    /// pull) loses access on the next sweep instead of retaining it
    /// until the user happens to re-request the app.
    ///
    /// Only allow→deny transitions are acted on: a demotion flips the
    /// per-app state (dropping the app from [`Self::allowed_apps`],
    /// which the agent's tunnel reconciler then tears down) and emits
    /// exactly one revocation telemetry event. Apps that stay allowed
    /// are left untouched and emit nothing, so a steady fleet does not
    /// inflate telemetry every posture interval — important at
    /// 5000-tenant scale. A denied app is never re-evaluated here:
    /// re-granting happens only on an explicit user access request,
    /// never silently by a sweep. The originating request is replayed
    /// with its `now_ms` refreshed to `now_ms` so freshness-sensitive
    /// gates judge against the sweep time, not the stale grant time.
    ///
    /// Returns the app IDs revoked this sweep (for the caller to log /
    /// act on).
    pub async fn reevaluate_active(
        &self,
        posture: Option<&MobilePostureSnapshot>,
        now: DateTime<Utc>,
        now_ms: u64,
    ) -> Vec<String> {
        // Snapshot the allowed apps' originating requests (with the
        // `version` stamp that `revoke_if_unchanged` guards on) under the
        // lock, then release it before evaluating — `classify` does not
        // touch the lock but `record_state` / `allowed_apps` do, and
        // holding it across the await would serialise the egress.
        let active: Vec<(AccessRequest, u64)> = {
            let state = self.app_state.lock();
            state
                .values()
                .filter(|s| s.allowed)
                .map(|s| {
                    let mut req = s.request.clone();
                    req.now_ms = now_ms;
                    (req, s.version)
                })
                .collect()
        };
        let mut revoked = Vec::new();
        for (request, snapshot_version) in active {
            let c = self.classify(&request, posture, EvalPath::Reeval);
            if c.allow {
                // Still allowed: leave the per-app state and telemetry
                // untouched so an unchanged fleet stays silent.
                continue;
            }
            // Compare-and-set the demotion against the snapshot stamp. If
            // a concurrent explicit access re-decided the app under us,
            // that fresher decision wins and we emit nothing — keeping
            // the revocation telemetry in lock-step with the state we
            // actually changed.
            if !self.revoke_if_unchanged(&request, &c.reason, now, snapshot_version) {
                continue;
            }
            if let Some(gate_label) = c.posture_detail.as_deref() {
                warn!(
                    app_id = %request.app_id,
                    gate = gate_label,
                    "adaptive-trust sweep revoked access (fail-closed posture)"
                );
            }
            let event = MobileTelemetryEvent::ZtnaAccess {
                app_id: request.app_id.clone(),
                allow: false,
                reason: c.reason.clone(),
                posture_detail: c.posture_detail.clone(),
                posture_result: c.posture_result.clone(),
                identity_verified: c.identity_verified,
            };
            self.record_telemetry_best_effort(&event, now).await;
            revoked.push(request.app_id);
        }
        revoked
    }

    /// Spool a ZTNA telemetry event without letting a telemetry
    /// failure shadow the access decision that produced it.
    async fn record_telemetry_best_effort(&self, event: &MobileTelemetryEvent, now: DateTime<Utc>) {
        if let Err(e) = self.telemetry.record(event, now).await {
            warn!(error = %e, "failed to record ZTNA telemetry event; continuing");
        }
    }

    /// The most recent access state recorded for `app_id`, if any.
    #[must_use]
    pub fn app_state(&self, app_id: &str) -> Option<AppAccessState> {
        self.app_state.lock().get(app_id).cloned()
    }

    /// The set of apps currently in the allowed state — the agent's
    /// tunnel reconciler uses this to decide which routes to keep up.
    #[must_use]
    pub fn allowed_apps(&self) -> Vec<String> {
        self.app_state
            .lock()
            .iter()
            .filter(|(_, state)| state.allowed)
            .map(|(app_id, _)| app_id.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use sng_comms::{EnrichmentContext, TelemetryClient, TelemetryClientConfig};
    use sng_core::envelope::Platform;
    use sng_core::{DeviceId, TenantId};
    use sng_ztna::{
        App, DeviceTrust, StaticAppCatalog, StaticDeviceTrustProvider, StaticIdentityProvider,
        UserIdentity, ZtnaPolicy, ZtnaPolicyHolder, ZtnaServiceBuilder,
    };
    use tokio::sync::mpsc;

    use crate::telemetry::EnvelopeContext;

    fn device(id: &str, tenant: &str) -> DeviceTrust {
        DeviceTrust {
            device_id: id.into(),
            tenant_id: tenant.into(),
            posture: sng_ztna::DevicePosture::pristine(1_000),
            tags: std::collections::HashMap::new(),
        }
    }

    fn healthy_posture() -> MobilePostureSnapshot {
        MobilePostureSnapshot {
            passcode_set: Some(true),
            jailbroken: Some(false),
            root_detected: Some(false),
            ..MobilePostureSnapshot::default()
        }
    }

    /// A posture that decayed since the grant: the screen lock /
    /// passcode is now off, which the fail-closed pre-gate denies.
    fn screen_unlocked_posture() -> MobilePostureSnapshot {
        MobilePostureSnapshot {
            passcode_set: Some(false),
            jailbroken: Some(false),
            root_detected: Some(false),
            ..MobilePostureSnapshot::default()
        }
    }

    fn user(id: &str, tenant: &str, mfa_at_ms: u64) -> UserIdentity {
        UserIdentity {
            user_id: id.into(),
            tenant_id: tenant.into(),
            groups: std::collections::HashSet::new(),
            mfa_at_ms,
            tags: std::collections::HashMap::new(),
        }
    }

    fn manager_with(
        apps: Vec<App>,
        devices: Vec<DeviceTrust>,
        users: Vec<UserIdentity>,
        policy: ZtnaPolicy,
    ) -> MobileZtnaManager {
        // The service's own telemetry channel is not forwarded on
        // mobile — the manager emits its own metadata-only events —
        // so a small channel whose receiver we drop is fine
        // (ZtnaService records a drop stat on a closed channel).
        let (tx, _rx): (mpsc::Sender<sng_telemetry::TelemetryEvent>, _) = mpsc::channel(16);
        let service = ZtnaServiceBuilder::new()
            .with_policy(Arc::new(ZtnaPolicyHolder::new(policy)))
            .with_app_catalog(Arc::new(StaticAppCatalog::new(apps)))
            .with_device_trust(Arc::new(StaticDeviceTrustProvider::new(devices)))
            .with_identity(Arc::new(StaticIdentityProvider::new(users)))
            .build(tx);

        let ctx = EnvelopeContext {
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            platform: Platform::Ios,
        };
        let client = Arc::new(TelemetryClient::new(TelemetryClientConfig::with_defaults(
            EnrichmentContext {
                tenant_id: ctx.tenant_id,
                device_id: ctx.device_id,
                site_id: None,
            },
        )));
        let telemetry = Arc::new(MobileTelemetry::new(client, ctx));
        MobileZtnaManager::new(Arc::new(service), telemetry)
    }

    #[tokio::test]
    async fn unknown_app_records_deny_and_errors() {
        let mgr = manager_with(vec![], vec![], vec![], ZtnaPolicy::default());
        let req = AccessRequest::new("ghost", "dev-1", "alice", 1_000);
        let err = mgr
            .evaluate(&req, Some(&healthy_posture()), Utc::now())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            MobileError::Ztna(ZtnaError::UnknownApp { .. })
        ));

        let state = mgr.app_state("ghost").expect("state recorded");
        assert!(!state.allowed);
        assert_eq!(state.reason, "unknown_app");
        assert!(mgr.allowed_apps().is_empty());
    }

    #[tokio::test]
    async fn allowed_app_is_tracked_allowed() {
        // App with no group / posture floor → any enrolled device +
        // known identity in the same tenant is allowed.
        let app = App::new("wiki", "Wiki");
        let pol = ZtnaPolicy {
            tenant_id: "t1".into(),
            ..ZtnaPolicy::default()
        };
        // Posture/MFA timestamps are recent relative to now_ms so the
        // freshness budgets (12h / 8h) are satisfied.
        let now_ms = 2_000;
        let mgr = manager_with(
            vec![app],
            vec![device("dev-1", "t1")],
            vec![user("alice", "t1", now_ms)],
            pol,
        );
        let req = AccessRequest::new("wiki", "dev-1", "alice", now_ms);
        let decision = mgr
            .evaluate(&req, Some(&healthy_posture()), Utc::now())
            .await
            .unwrap();
        assert!(decision.allow, "decision: {decision:?}");

        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(state.allowed);
        assert_eq!(state.reason, "allow");
        assert_eq!(mgr.allowed_apps(), vec!["wiki".to_owned()]);
    }

    // Build a manager that grants `wiki` to dev-1/alice in tenant t1,
    // and record the initial allow so the adaptive-trust sweep has a
    // tracked, allowed app to re-evaluate.
    async fn manager_with_granted_wiki(now_ms: u64) -> MobileZtnaManager {
        let pol = ZtnaPolicy {
            tenant_id: "t1".into(),
            ..ZtnaPolicy::default()
        };
        let mgr = manager_with(
            vec![App::new("wiki", "Wiki")],
            vec![device("dev-1", "t1")],
            vec![user("alice", "t1", now_ms)],
            pol,
        );
        let req = AccessRequest::new("wiki", "dev-1", "alice", now_ms);
        let decision = mgr
            .evaluate(&req, Some(&healthy_posture()), Utc::now())
            .await
            .unwrap();
        assert!(decision.allow, "setup decision: {decision:?}");
        assert_eq!(mgr.allowed_apps(), vec!["wiki".to_owned()]);
        mgr
    }

    #[tokio::test]
    async fn reeval_revokes_app_when_posture_decays() {
        // The grant happened under a healthy posture; by the next sweep
        // the screen lock is off. The sweep must demote the app — the
        // adaptive-trust property: posture decay revokes access on the
        // periodic cadence, not only on the user's next request.
        let now_ms = 2_000;
        let mgr = manager_with_granted_wiki(now_ms).await;
        let revoked = mgr
            .reevaluate_active(Some(&screen_unlocked_posture()), Utc::now(), now_ms + 1)
            .await;
        assert_eq!(revoked, vec!["wiki".to_owned()]);
        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(!state.allowed);
        assert_eq!(state.reason, "device_posture_insufficient");
        assert!(
            mgr.allowed_apps().is_empty(),
            "a revoked app must drop out of allowed_apps so the tunnel reconciler tears it down"
        );
    }

    #[tokio::test]
    async fn reeval_keeps_app_when_posture_holds() {
        // Posture still healthy at sweep time → no flip, no revocation,
        // and (deliberately) no telemetry churn for a steady fleet.
        let now_ms = 2_000;
        let mgr = manager_with_granted_wiki(now_ms).await;
        let revoked = mgr
            .reevaluate_active(Some(&healthy_posture()), Utc::now(), now_ms + 1)
            .await;
        assert!(revoked.is_empty(), "a holding posture must revoke nothing");
        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(state.allowed);
        assert_eq!(state.reason, "allow");
        assert_eq!(mgr.allowed_apps(), vec!["wiki".to_owned()]);
    }

    #[tokio::test]
    async fn reeval_never_regrants_a_denied_app() {
        // Cross-tenant deny: device in t1, identity in t2.
        let pol = ZtnaPolicy {
            tenant_id: "t1".into(),
            ..ZtnaPolicy::default()
        };
        let mgr = manager_with(
            vec![App::new("wiki", "Wiki")],
            vec![device("dev-1", "t1")],
            vec![user("alice", "t2", 2_000)],
            pol,
        );
        let req = AccessRequest::new("wiki", "dev-1", "alice", 2_000);
        assert!(
            !mgr.evaluate(&req, Some(&healthy_posture()), Utc::now())
                .await
                .unwrap()
                .allow
        );
        assert!(mgr.allowed_apps().is_empty());
        // A healthy-posture sweep must never silently re-grant a denied
        // app: the sweep only re-evaluates currently-allowed apps, so a
        // re-grant can only come from an explicit user request.
        let revoked = mgr
            .reevaluate_active(Some(&healthy_posture()), Utc::now(), 3_000)
            .await;
        assert!(revoked.is_empty());
        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(!state.allowed);
        assert!(mgr.allowed_apps().is_empty());
    }

    #[tokio::test]
    async fn reeval_does_not_clobber_a_concurrent_regrant() {
        // TOCTOU guard: the sweep snapshots an app as allowed, releases
        // the lock to classify it, and decides to revoke. If an explicit
        // access re-decided that app against a *fresher* posture in the
        // gap, the sweep's stale deny must not overwrite the newer grant.
        let now_ms = 2_000;
        let mgr = manager_with_granted_wiki(now_ms).await;
        let req = AccessRequest::new("wiki", "dev-1", "alice", now_ms);

        // The version stamp the sweep would have snapshotted at grant time.
        let snapshot_version = mgr.app_state("wiki").expect("granted").version;

        // A concurrent explicit re-grant lands with a fresh version stamp.
        let regrant_at =
            mgr.app_state("wiki").expect("granted").decided_at + chrono::Duration::seconds(1);
        mgr.evaluate(&req, Some(&healthy_posture()), regrant_at)
            .await
            .unwrap();
        let regrant_version = mgr.app_state("wiki").expect("regranted").version;
        assert_ne!(
            regrant_version, snapshot_version,
            "the re-grant must advance the version stamp"
        );

        // The sweep now tries to revoke against its *stale* snapshot stamp.
        let applied = mgr.revoke_if_unchanged(
            &req,
            "device_posture_insufficient",
            regrant_at + chrono::Duration::seconds(1),
            snapshot_version,
        );
        assert!(
            !applied,
            "a stale sweep deny must not clobber a newer grant"
        );
        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(state.allowed, "the concurrent re-grant must survive");
        assert_eq!(state.decided_at, regrant_at);
        assert_eq!(mgr.allowed_apps(), vec!["wiki".to_owned()]);

        // With the up-to-date stamp the same revocation does apply, so the
        // guard only suppresses *stale* writes, never legitimate ones.
        let applied = mgr.revoke_if_unchanged(
            &req,
            "device_posture_insufficient",
            regrant_at + chrono::Duration::seconds(2),
            regrant_version,
        );
        assert!(applied, "an unchanged entry must still revoke");
        assert!(!mgr.app_state("wiki").expect("state recorded").allowed);
    }

    #[tokio::test]
    async fn cross_tenant_request_is_denied_not_errored() {
        let app = App::new("wiki", "Wiki");
        // A non-empty policy tenant arms the cross-tenant guard. The
        // device is in `t1` (matches) but the identity is in `t2`
        // (mismatches), so the request is denied — not errored.
        let pol = ZtnaPolicy {
            tenant_id: "t1".into(),
            ..ZtnaPolicy::default()
        };
        let mgr = manager_with(
            vec![app],
            vec![device("dev-1", "t1")],
            vec![user("alice", "t2", 2_000)],
            pol,
        );
        let req = AccessRequest::new("wiki", "dev-1", "alice", 2_000);
        let decision = mgr
            .evaluate(&req, Some(&healthy_posture()), Utc::now())
            .await
            .unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_str(), "tenant_mismatch");
        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(!state.allowed);
    }

    #[tokio::test]
    async fn unprovable_posture_denies_before_policy_is_consulted() {
        // Empty catalog: a normal evaluation would surface
        // `UnknownApp` as an `Err`. With no posture snapshot the
        // fail-closed pre-gate must deny *first*, returning a clean
        // posture deny without ever consulting the policy engine.
        let mgr = manager_with(vec![], vec![], vec![], ZtnaPolicy::default());
        let req = AccessRequest::new("wiki", "dev-1", "alice", 1_000);
        let decision = mgr.evaluate(&req, None, Utc::now()).await.unwrap();
        assert!(!decision.allow);
        assert_eq!(decision.reason.as_str(), "device_posture_insufficient");
        assert_eq!(decision.posture_result.as_str(), "fail");
        let state = mgr.app_state("wiki").expect("state recorded");
        assert!(!state.allowed);
        assert!(mgr.allowed_apps().is_empty());
    }

    #[tokio::test]
    async fn compromised_device_is_denied_fail_closed() {
        let app = App::new("wiki", "Wiki");
        let pol = ZtnaPolicy {
            tenant_id: "t1".into(),
            ..ZtnaPolicy::default()
        };
        let mgr = manager_with(
            vec![app],
            vec![device("dev-1", "t1")],
            vec![user("alice", "t1", 2_000)],
            pol,
        );
        let jailbroken = MobilePostureSnapshot {
            jailbroken: Some(true),
            passcode_set: Some(true),
            ..MobilePostureSnapshot::default()
        };
        let req = AccessRequest::new("wiki", "dev-1", "alice", 2_000);
        let decision = mgr
            .evaluate(&req, Some(&jailbroken), Utc::now())
            .await
            .unwrap();
        assert!(!decision.allow, "a jailbroken device must be denied");
        assert_eq!(decision.reason.as_str(), "device_posture_insufficient");
    }

    #[tokio::test]
    async fn unlocked_device_is_denied_fail_closed() {
        let app = App::new("wiki", "Wiki");
        let pol = ZtnaPolicy {
            tenant_id: "t1".into(),
            ..ZtnaPolicy::default()
        };
        let mgr = manager_with(
            vec![app],
            vec![device("dev-1", "t1")],
            vec![user("alice", "t1", 2_000)],
            pol,
        );
        let unlocked = MobilePostureSnapshot {
            passcode_set: Some(false),
            jailbroken: Some(false),
            root_detected: Some(false),
            ..MobilePostureSnapshot::default()
        };
        let req = AccessRequest::new("wiki", "dev-1", "alice", 2_000);
        let decision = mgr
            .evaluate(&req, Some(&unlocked), Utc::now())
            .await
            .unwrap();
        assert!(!decision.allow, "a device with no screen lock is denied");
        assert_eq!(decision.reason.as_str(), "device_posture_insufficient");
    }

    #[test]
    fn posture_pre_gate_labels_each_deny_cause() {
        // No snapshot → unprovable.
        assert_eq!(posture_pre_gate(None), Some("posture_unprovable"));

        // Healthy device proceeds to the shared policy.
        assert_eq!(posture_pre_gate(Some(&healthy_posture())), None);

        // Jailbroken → compromised.
        let compromised = MobilePostureSnapshot {
            jailbroken: Some(true),
            passcode_set: Some(true),
            ..MobilePostureSnapshot::default()
        };
        assert_eq!(
            posture_pre_gate(Some(&compromised)),
            Some("posture_compromised")
        );

        // Screen lock off → screen_lock_off.
        let unlocked = MobilePostureSnapshot {
            passcode_set: Some(false),
            jailbroken: Some(false),
            root_detected: Some(false),
            ..MobilePostureSnapshot::default()
        };
        assert_eq!(
            posture_pre_gate(Some(&unlocked)),
            Some("posture_screen_lock_off")
        );

        // Unknown passcode (older OS) → unprovable, never granted.
        let unknown_lock = MobilePostureSnapshot {
            passcode_set: None,
            jailbroken: Some(false),
            root_detected: Some(false),
            ..MobilePostureSnapshot::default()
        };
        assert_eq!(
            posture_pre_gate(Some(&unknown_lock)),
            Some("posture_unprovable")
        );
    }
}

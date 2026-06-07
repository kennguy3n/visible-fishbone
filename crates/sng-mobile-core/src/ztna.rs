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
    /// When the decision was recorded.
    pub decided_at: DateTime<Utc>,
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
        }
    }

    fn record_state(&self, app_id: &str, allowed: bool, reason: &str, now: DateTime<Utc>) {
        self.app_state.lock().insert(
            app_id.to_owned(),
            AppAccessState {
                allowed,
                reason: reason.to_owned(),
                decided_at: now,
            },
        );
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
        if let Some(gate_label) = posture_pre_gate(posture) {
            warn!(
                app_id = %request.app_id,
                gate = gate_label,
                "mobile posture pre-gate denied access (fail-closed)"
            );
            let reason = ZtnaDecisionReason::DevicePostureInsufficient;
            let decision = ZtnaDecision {
                allow: false,
                reason: reason.clone(),
                posture_result: PostureResult::Fail,
            };
            let event = MobileTelemetryEvent::ZtnaAccess {
                app_id: request.app_id.clone(),
                allow: false,
                reason: reason.as_str().to_owned(),
                // The stable wire reason stays `device_posture_insufficient`
                // (consistent with a policy-side posture deny); the gate
                // label rides the additive `posture_detail` field so
                // dashboards can break out the cause.
                posture_detail: Some(gate_label.to_owned()),
                posture_result: decision.posture_result.as_str().to_owned(),
                identity_verified: false,
            };
            self.record_telemetry_best_effort(&event, now).await;
            self.record_state(&request.app_id, false, reason.as_str(), now);
            return Ok(decision);
        }
        match self.service.evaluate(request) {
            Ok(decision) => {
                let reason = decision.reason.as_str();
                let event = MobileTelemetryEvent::ZtnaAccess {
                    app_id: request.app_id.clone(),
                    allow: decision.allow,
                    reason: reason.to_owned(),
                    // Shared-policy decisions carry no mobile pre-gate
                    // cause; the field stays unset.
                    posture_detail: None,
                    posture_result: decision.posture_result.as_str().to_owned(),
                    identity_verified: true,
                };
                self.record_telemetry_best_effort(&event, now).await;
                self.record_state(&request.app_id, decision.allow, reason, now);
                Ok(decision)
            }
            Err(err) => {
                let reason = error_reason_label(&err);
                let event = MobileTelemetryEvent::ZtnaAccess {
                    app_id: request.app_id.clone(),
                    allow: false,
                    reason: reason.to_owned(),
                    // Provider-miss errors short-circuit before the
                    // posture check; no pre-gate cause applies.
                    posture_detail: None,
                    posture_result: "not_evaluated".to_owned(),
                    identity_verified: false,
                };
                self.record_telemetry_best_effort(&event, now).await;
                self.record_state(&request.app_id, false, reason, now);
                Err(MobileError::Ztna(err))
            }
        }
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
            posture: sng_ztna::DevicePosture {
                disk_encrypted: true,
                os_patched: true,
                antimalware_running: true,
                firewall_enabled: true,
                screen_lock_configured: true,
                attested_at_ms: 1_000,
            },
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

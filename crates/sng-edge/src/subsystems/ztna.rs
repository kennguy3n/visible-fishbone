// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! ZTNA service subsystem adapter.
//!
//! Wraps [`sng_ztna::ZtnaService`]. Like
//! [`super::policy_eval::PolicyEvalSubsystem`], evaluation is
//! purely synchronous — the subsystem's `start` task only waits
//! on shutdown.

use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_telemetry::TelemetryEvent;
use sng_ztna::{
    AccessGrant, AccessRequest, SessionTracker, ZtnaDecision, ZtnaError, ZtnaService,
    ZtnaServiceBuilder, ZtnaServiceConfig, ZtnaStats,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;

/// Edge-tier ZTNA subsystem.
#[derive(Clone)]
pub struct ZtnaSubsystem {
    service: Arc<ZtnaService>,
    stats: Arc<ZtnaStats>,
    /// Session store shared with the continuous re-evaluation loop
    /// ([`super::ztna_reeval::ZtnaReevalSubsystem`]). `Some` only when
    /// the operator has enabled re-evaluation: the producer
    /// ([`Self::open_session`]) records a grant per allowed session
    /// here and the loop sweeps the same store. `None` keeps the
    /// access path byte-for-byte unchanged when re-evaluation is off —
    /// no grant is ever recorded, so there is nothing to walk.
    sessions: Option<Arc<SessionTracker>>,
}

impl std::fmt::Debug for ZtnaSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ZtnaService is `Clone` but not `Debug` because of its
        // trait-object providers; expose the stable summary the
        // operator dashboard would show.
        f.debug_struct("ZtnaSubsystem")
            .field("max_sessions", &self.service.max_sessions())
            .field("stats", &self.stats.snapshot())
            .field("tracked_sessions", &self.sessions.as_ref().map(|t| t.len()))
            .finish_non_exhaustive()
    }
}

impl ZtnaSubsystem {
    /// Build a subsystem with default empty providers (apps /
    /// devices / identities). Providers are populated by the
    /// policy puller in production; the binary's supervisor
    /// wiring at boot uses this constructor.
    ///
    /// `telemetry` is the producer half of the pipeline channel
    /// — every evaluation emits one [`sng_core::events::ZtnaEvent`]
    /// to this sender.
    #[must_use]
    pub fn new(cfg: ZtnaServiceConfig, telemetry: mpsc::Sender<TelemetryEvent>) -> Self {
        let stats = Arc::new(ZtnaStats::default());
        let service = ZtnaServiceBuilder::new()
            .with_config(cfg)
            .with_stats(Arc::clone(&stats))
            .build(telemetry);
        Self {
            service: Arc::new(service),
            stats,
            sessions: None,
        }
    }

    /// Build from an explicitly-constructed service. Used by
    /// the integration tests when they want to seed non-empty
    /// providers without going through the policy puller.
    #[must_use]
    pub fn from_service(service: Arc<ZtnaService>) -> Self {
        let stats = Arc::clone(service.stats());
        Self {
            service,
            stats,
            sessions: None,
        }
    }

    /// Wire the access path to a shared [`SessionTracker`] so every
    /// allowed session is recorded for continuous re-evaluation. The
    /// supervisor calls this with the tracker the
    /// [`super::ztna_reeval::ZtnaReevalSubsystem`] sweeps, and only
    /// when `ztna.reeval_enabled` is set — when it is off the producer
    /// stays untracked and the access path is unchanged.
    #[must_use]
    pub fn with_session_tracker(mut self, tracker: Arc<SessionTracker>) -> Self {
        self.sessions = Some(tracker);
        self
    }

    /// The session tracker the producer records into, if wired. `None`
    /// when continuous re-evaluation is disabled.
    #[must_use]
    pub fn sessions(&self) -> Option<&Arc<SessionTracker>> {
        self.sessions.as_ref()
    }

    /// Borrow the underlying service. Other subsystems (e.g.
    /// the comms control-plane RPC handlers) call this to
    /// evaluate access requests.
    #[must_use]
    pub fn service(&self) -> &Arc<ZtnaService> {
        &self.service
    }

    /// Stats handle. Shared with the operator-facing health
    /// endpoint.
    #[must_use]
    pub fn stats(&self) -> &Arc<ZtnaStats> {
        &self.stats
    }

    /// Thin convenience around [`ZtnaService::evaluate`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`ZtnaError`] surfaced by the
    /// service (unknown app id, device-trust resolver error,
    /// etc.).
    pub fn evaluate(&self, req: &AccessRequest) -> Result<ZtnaDecision, ZtnaError> {
        self.service.evaluate(req)
    }

    /// Open (or re-authorise) a ZTNA session: evaluate `request` on the
    /// access path exactly as [`Self::evaluate`], then — when the
    /// re-evaluation tracker is wired ([`Self::with_session_tracker`])
    /// — bind the verdict to the session lifecycle so the continuous
    /// loop re-evaluates it:
    ///
    /// - **Allow** records an [`AccessGrant`] under `session_id`
    ///   (re-recording the same id refreshes a step-up re-auth in
    ///   place), so the loop re-runs the *same* evaluator over it each
    ///   sweep and tears it down once the verdict flips (posture decay,
    ///   MFA expiry, device / user revocation, app de-listing).
    /// - **Deny** (including the provider-miss errors) removes any
    ///   grant previously recorded under `session_id`, so a re-auth
    ///   that loses access is evicted immediately rather than waiting
    ///   for the next sweep.
    ///
    /// `session_id` is the opaque, globally-unique id the producer
    /// mints for the connection; `tenant_id` is the owning tenant
    /// (carried on the grant so revocations stay tenant-scoped without
    /// a second lookup). When the tracker is not wired this is exactly
    /// [`Self::evaluate`] plus the returned decision — no state is
    /// touched.
    ///
    /// # Errors
    ///
    /// Propagates the same provider-resolution [`ZtnaError`]s as
    /// [`Self::evaluate`] (unknown app / device not enrolled / identity
    /// not found). The error is a deny, so any prior grant for
    /// `session_id` is torn down before the error is returned.
    pub fn open_session(
        &self,
        session_id: impl Into<String>,
        tenant_id: impl Into<String>,
        request: AccessRequest,
    ) -> Result<ZtnaDecision, ZtnaError> {
        // Fast path: tracking disabled => pure access decision, no
        // session id allocation, no tracker touch.
        let Some(tracker) = self.sessions.as_ref() else {
            return self.service.evaluate(&request);
        };
        let session_id = session_id.into();
        let decision = match self.service.evaluate(&request) {
            Ok(decision) => decision,
            Err(err) => {
                // A provider-miss re-auth is a deny: evict any grant
                // recorded under this id before surfacing the error.
                tracker.remove(&session_id);
                return Err(err);
            }
        };
        if decision.allow {
            let granted_at_ms = request.now_ms;
            tracker.record(AccessGrant::new(
                session_id,
                tenant_id,
                request,
                granted_at_ms,
            ));
        } else {
            tracker.remove(&session_id);
        }
        Ok(decision)
    }

    /// Close a ZTNA session: remove its grant from the shared tracker
    /// so the re-evaluation loop stops walking a session the proxy has
    /// already torn down. Returns the removed [`AccessGrant`], or
    /// `None` if no grant was tracked (session never opened, already
    /// closed, or tracking disabled).
    pub fn close_session(&self, session_id: &str) -> Option<AccessGrant> {
        self.sessions.as_ref()?.remove(session_id)
    }
}

#[async_trait]
impl Subsystem for ZtnaSubsystem {
    fn name(&self) -> &'static str {
        "ztna"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        Ok(task::spawn(async move {
            shutdown.wait().await;
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for ZtnaSubsystem {
    fn name(&self) -> &'static str {
        "ztna"
    }

    async fn check(&self) -> SubsystemHealth {
        let snap = self.stats.snapshot();
        // Denies aren't surfaced as a single counter — sum the
        // per-reason buckets so the operator dashboard sees one
        // total. Bundle / telemetry / provider failures degrade
        // status to Degraded so the dashboard renders an amber
        // marker rather than a green one.
        let denies = snap.deny_unknown_app
            + snap.deny_device_not_enrolled
            + snap.deny_device_posture_stale
            + snap.deny_device_posture_insufficient
            + snap.deny_identity_not_found
            + snap.deny_mfa_stale
            + snap.deny_not_entitled
            + snap.deny_tenant_mismatch;
        let status = if snap.bundle_load_failures > 0 || snap.provider_failures > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "evaluated={}, allow={}, deny={}, bundle_failures={}, telemetry_drops={}, provider_failures={}",
                snap.requests_evaluated,
                snap.decision_allow,
                denies,
                snap.bundle_load_failures,
                snap.telemetry_drops,
                snap.provider_failures,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use sng_ztna::{
        App, DevicePosture, DeviceTrust, PostureRequirement, RevocationProvider, StaticAppCatalog,
        StaticDeviceTrustProvider, StaticIdentityProvider, StaticRevocationList, UserIdentity,
        ZtnaPolicy, ZtnaPolicyHolder,
    };
    use std::collections::HashSet;

    const TENANT: &str = "t1";
    const APP: &str = "wiki";
    const DEVICE: &str = "dev-1";
    const USER: &str = "alice";
    const NOW_MS: u64 = 1_000_000;

    /// A service whose providers admit `(wiki, dev-1, alice)` at
    /// `NOW_MS`, returned alongside the revocation list so a test can
    /// flip a verdict to deny after a grant. Mirrors the producer's
    /// real wiring: empty `required_groups` (any authenticated user),
    /// default posture floor satisfied by a pristine device.
    fn allow_service() -> (Arc<ZtnaService>, Arc<StaticRevocationList>) {
        let apps = Arc::new(StaticAppCatalog::new(vec![App {
            app_id: APP.into(),
            display_name: APP.into(),
            host_patterns: vec![],
            required_groups: HashSet::new(),
            posture_requirement: PostureRequirement::new(0),
            mfa_max_age_override_ms: None,
            conditions: sng_ztna::AccessConditions::default(),
            tags: std::collections::HashMap::new(),
        }]));
        let devices = Arc::new(StaticDeviceTrustProvider::new(vec![DeviceTrust {
            device_id: DEVICE.into(),
            tenant_id: TENANT.into(),
            posture: DevicePosture::pristine(NOW_MS),
            tags: std::collections::HashMap::new(),
        }]));
        let identities = Arc::new(StaticIdentityProvider::new(vec![UserIdentity {
            user_id: USER.into(),
            tenant_id: TENANT.into(),
            groups: HashSet::new(),
            mfa_at_ms: NOW_MS,
            tags: std::collections::HashMap::new(),
        }]));
        let revocation = Arc::new(StaticRevocationList::default());
        let policy = Arc::new(ZtnaPolicyHolder::new(ZtnaPolicy {
            tenant_id: TENANT.into(),
            ..ZtnaPolicy::default()
        }));
        let revocation_dyn: Arc<dyn RevocationProvider> = revocation.clone();
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(16);
        let service = ZtnaServiceBuilder::new()
            .with_policy(policy)
            .with_app_catalog(apps)
            .with_device_trust(devices)
            .with_identity(identities)
            .with_revocation(revocation_dyn)
            .build(tx);
        (Arc::new(service), revocation)
    }

    fn req() -> AccessRequest {
        AccessRequest::new(APP, DEVICE, USER, NOW_MS)
    }

    #[test]
    fn open_session_records_allowed_grant_into_shared_tracker() {
        let (service, _rev) = allow_service();
        let tracker = Arc::new(SessionTracker::new());
        let sub = ZtnaSubsystem::from_service(service).with_session_tracker(Arc::clone(&tracker));

        let decision = sub.open_session("sess-1", TENANT, req()).expect("evaluate");
        assert!(decision.allow, "pristine device must be allowed");
        assert!(
            tracker.contains("sess-1"),
            "an allowed session must be recorded for re-evaluation"
        );
        let grant = tracker.get("sess-1").expect("grant present");
        assert_eq!(grant.tenant_id, TENANT);
        assert_eq!(grant.device_id(), DEVICE);
    }

    #[test]
    fn open_session_denied_reauth_evicts_prior_grant() {
        let (service, revocation) = allow_service();
        let tracker = Arc::new(SessionTracker::new());
        let sub = ZtnaSubsystem::from_service(service).with_session_tracker(Arc::clone(&tracker));

        assert!(
            sub.open_session("sess-1", TENANT, req())
                .expect("allow")
                .allow
        );
        assert!(tracker.contains("sess-1"));

        // The device is revoked; re-authorising the same session must
        // flip to deny and tear the grant down immediately.
        revocation.replace_devices(HashSet::from([DEVICE.to_owned()]));
        let decision = sub.open_session("sess-1", TENANT, req()).expect("evaluate");
        assert!(!decision.allow, "revoked device must be denied");
        assert!(
            !tracker.contains("sess-1"),
            "a re-auth that loses access must evict the grant"
        );
    }

    #[test]
    fn open_session_provider_miss_evicts_and_errors() {
        let (service, _rev) = allow_service();
        let tracker = Arc::new(SessionTracker::new());
        let sub = ZtnaSubsystem::from_service(service).with_session_tracker(Arc::clone(&tracker));

        assert!(
            sub.open_session("sess-1", TENANT, req())
                .expect("allow")
                .allow
        );
        // An unknown app surfaces an error (a deny); the prior grant
        // under this id must still be evicted.
        let err = sub
            .open_session(
                "sess-1",
                TENANT,
                AccessRequest::new("ghost", DEVICE, USER, NOW_MS),
            )
            .expect_err("unknown app errors");
        assert!(matches!(err, ZtnaError::UnknownApp { .. }));
        assert!(!tracker.contains("sess-1"), "an errored re-auth must evict");
    }

    #[test]
    fn close_session_removes_grant() {
        let (service, _rev) = allow_service();
        let tracker = Arc::new(SessionTracker::new());
        let sub = ZtnaSubsystem::from_service(service).with_session_tracker(Arc::clone(&tracker));

        sub.open_session("sess-1", TENANT, req()).expect("allow");
        let removed = sub.close_session("sess-1").expect("grant removed");
        assert_eq!(removed.session_id, "sess-1");
        assert!(!tracker.contains("sess-1"));
        assert!(
            sub.close_session("sess-1").is_none(),
            "closing an already-closed session is a no-op"
        );
    }

    #[test]
    fn open_session_without_tracker_is_pure_evaluate() {
        // Default-OFF: no tracker wired => the producer records nothing
        // and is exactly the access decision.
        let (service, _rev) = allow_service();
        let sub = ZtnaSubsystem::from_service(service);
        assert!(sub.sessions().is_none());

        let decision = sub.open_session("sess-1", TENANT, req()).expect("evaluate");
        assert!(decision.allow);
        assert!(
            sub.close_session("sess-1").is_none(),
            "no tracker => nothing to close"
        );
    }

    #[tokio::test]
    async fn subsystem_idles_until_shutdown() {
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = ZtnaSubsystem::new(ZtnaServiceConfig::default(), tx);
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        let res = tokio::time::timeout(std::time::Duration::from_secs(1), handle)
            .await
            .expect("drain budget");
        assert!(res.expect("join").is_ok());
    }

    #[tokio::test]
    async fn health_renders_stats_snapshot() {
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = ZtnaSubsystem::new(ZtnaServiceConfig::default(), tx);
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Up);
        let detail = h.detail.expect("detail");
        assert!(detail.contains("evaluated="));
        assert!(detail.contains("allow="));
        assert!(detail.contains("deny="));
    }
}

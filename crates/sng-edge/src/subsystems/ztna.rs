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
    AccessRequest, ZtnaDecision, ZtnaError, ZtnaService, ZtnaServiceBuilder, ZtnaServiceConfig,
    ZtnaStats,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;

/// Edge-tier ZTNA subsystem.
#[derive(Clone)]
pub struct ZtnaSubsystem {
    service: Arc<ZtnaService>,
    stats: Arc<ZtnaStats>,
}

impl std::fmt::Debug for ZtnaSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ZtnaService is `Clone` but not `Debug` because of its
        // trait-object providers; expose the stable summary the
        // operator dashboard would show.
        f.debug_struct("ZtnaSubsystem")
            .field("max_sessions", &self.service.max_sessions())
            .field("stats", &self.stats.snapshot())
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
        }
    }

    /// Build from an explicitly-constructed service. Used by
    /// the integration tests when they want to seed non-empty
    /// providers without going through the policy puller.
    #[must_use]
    pub fn from_service(service: Arc<ZtnaService>) -> Self {
        let stats = Arc::clone(service.stats());
        Self { service, stats }
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

// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! ZTNA service subsystem adapter.
//!
//! Endpoint-tier sibling of
//! [`sng_edge::subsystems::ztna`]. Wraps
//! [`sng_ztna::ZtnaService`]; evaluation is purely synchronous
//! so the subsystem's `start` task only waits on shutdown.

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

/// Endpoint-tier ZTNA subsystem.
#[derive(Clone)]
pub struct ZtnaSubsystem {
    service: Arc<ZtnaService>,
    stats: Arc<ZtnaStats>,
}

impl std::fmt::Debug for ZtnaSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    /// `telemetry` is the producer half of the pipeline
    /// channel — every evaluation emits one
    /// [`sng_core::events::ZtnaEvent`] to this sender.
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

    /// Borrow the underlying service.
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
    /// service.
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
    async fn subsystem_start_waits_for_shutdown_and_returns_ok() {
        let (tx, _rx) = mpsc::channel(8);
        let subsys = ZtnaSubsystem::new(
            ZtnaServiceConfig {
                max_sessions: 4,
                ..ZtnaServiceConfig::default()
            },
            tx,
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = subsys.start(signal).await.expect("start");
        trigger.fire();
        let join = handle.await.expect("join");
        assert!(join.is_ok());
    }

    #[tokio::test]
    async fn health_check_initially_reports_up_with_zero_evaluations() {
        let (tx, _rx) = mpsc::channel(8);
        let subsys = ZtnaSubsystem::new(
            ZtnaServiceConfig {
                max_sessions: 4,
                ..ZtnaServiceConfig::default()
            },
            tx,
        );
        let snap = subsys.check().await;
        assert_eq!(snap.status, HealthStatus::Up);
        assert!(
            snap.detail
                .as_deref()
                .unwrap_or_default()
                .contains("evaluated=0")
        );
    }
}

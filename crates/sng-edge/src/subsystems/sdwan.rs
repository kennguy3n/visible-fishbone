// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! SD-WAN steering subsystem adapter.
//!
//! Wraps [`sng_sdwan::SdwanService`]. Like the ZTNA subsystem,
//! evaluation is purely synchronous — the start task only waits
//! on shutdown. The probe ingest pipeline lives on a separate
//! thread elsewhere; the adapter just exposes the service so the
//! comms / RPC layer can call `evaluate` for steering decisions.

use crate::config::SdwanConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_sdwan::{
    SdwanService, SdwanServiceBuilder, SdwanServiceConfig, SdwanStats, SteeringDecision,
    SteeringRequest,
};
use sng_telemetry::TelemetryEvent;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task;

/// Edge-tier SD-WAN subsystem.
#[derive(Clone)]
pub struct SdwanSubsystem {
    service: Arc<SdwanService>,
    stats: Arc<SdwanStats>,
}

impl std::fmt::Debug for SdwanSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdwanSubsystem")
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl SdwanSubsystem {
    /// Build a subsystem with default empty providers. The
    /// policy puller populates the path / probe providers
    /// post-boot; the operator-facing service is up and
    /// returning `NoPaths` decisions in the meantime.
    #[must_use]
    pub fn new(cfg: &SdwanConfig, telemetry: mpsc::Sender<TelemetryEvent>) -> Self {
        let stats = Arc::new(SdwanStats::default());
        let service_cfg = SdwanServiceConfig {
            sticky_cache_capacity: cfg.sticky_cache_capacity,
            ..SdwanServiceConfig::default()
        };
        let service = SdwanServiceBuilder::new()
            .with_config(service_cfg)
            .with_stats(Arc::clone(&stats))
            .build(telemetry);
        Self {
            service: Arc::new(service),
            stats,
        }
    }

    /// Build from a pre-built service. Used by integration tests
    /// that want to seed non-empty providers.
    #[must_use]
    pub fn from_service(service: Arc<SdwanService>) -> Self {
        let stats = Arc::clone(service.stats());
        Self { service, stats }
    }

    /// Borrow the underlying service. The comms subsystem's
    /// SD-WAN RPC handler calls this to evaluate steering
    /// requests.
    #[must_use]
    pub fn service(&self) -> &Arc<SdwanService> {
        &self.service
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<SdwanStats> {
        &self.stats
    }

    /// Convenience wrapper around [`SdwanService::evaluate`].
    #[must_use]
    pub fn evaluate(&self, req: &SteeringRequest) -> SteeringDecision {
        self.service.evaluate(req)
    }
}

#[async_trait]
impl Subsystem for SdwanSubsystem {
    fn name(&self) -> &'static str {
        "sdwan"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        Ok(task::spawn(async move {
            shutdown.wait().await;
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for SdwanSubsystem {
    fn name(&self) -> &'static str {
        "sdwan"
    }

    async fn check(&self) -> SubsystemHealth {
        let snap = self.stats.snapshot();
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status: HealthStatus::Up,
            detail: Some(format!(
                "evaluated={}, best={}, fallback={}, no_paths={}, sticky_pinned={}, telemetry_drops={}",
                snap.requests_evaluated,
                snap.reason_best,
                snap.reason_fallback_below_floor,
                snap.reason_no_available_path,
                snap.reason_sticky_pinned,
                snap.telemetry_drops,
            )),
        }
    }
}

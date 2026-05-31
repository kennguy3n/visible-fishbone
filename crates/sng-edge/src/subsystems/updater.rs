// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Self-update subsystem adapter.
//!
//! Wraps [`sng_updater::UpdaterService`]. The start task polls
//! the manifest source at the operator-configured cadence; each
//! tick calls [`UpdaterService::poll_and_install`] which drives
//! the full state machine (verify → download → stage → swap →
//! health check → commit / rollback). On the in-memory backend
//! the bank-writer and bootloader are the library's own
//! [`sng_updater::InMemoryBankWriter`] / [`sng_updater::InMemoryBootloader`]
//! types; the disk-backed equivalents ship in a separate crate.

use crate::cli::UpdaterBackend;
use crate::config::UpdaterConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_updater::{
    Bank, ImageDownloader, InMemoryBankWriter, InMemoryBootloader, InMemoryDownloader,
    ManifestSource, ManifestVerifier, StaticHealthCheck, StaticManifestSource, UpdateTarget,
    UpdaterPolicy, UpdaterService, UpdaterServiceBuilder, UpdaterStatsSnapshot,
};
use std::sync::Arc;
use tokio::task;
use tokio::time::{MissedTickBehavior, interval};

/// Edge-tier updater subsystem.
pub struct UpdaterSubsystem {
    service: Arc<UpdaterService>,
    poll_interval: std::time::Duration,
    backend: UpdaterBackend,
}

impl std::fmt::Debug for UpdaterSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdaterSubsystem")
            .field("backend", &self.backend)
            .field("poll_interval", &self.poll_interval)
            .finish_non_exhaustive()
    }
}

/// Errors raised by [`UpdaterSubsystem::new`].
#[derive(Debug, thiserror::Error)]
pub enum UpdaterSubsystemError {
    /// Service builder rejected the wiring (missing component or
    /// invalid policy).
    #[error("updater service build failed: {0}")]
    Build(#[from] sng_updater::service::ServiceBuildError),
}

impl UpdaterSubsystem {
    /// Build with the in-memory backend. Honest about which
    /// backend is in play — the operator's boot log line uses
    /// `self.backend()` so the appliance never silently runs
    /// the test backend in production.
    ///
    /// # Errors
    ///
    /// Returns [`UpdaterSubsystemError::Build`] when the
    /// service builder rejects the assembled wiring.
    pub fn new_in_memory(
        cfg: &UpdaterConfig,
        target: UpdateTarget,
        verifier: Arc<ManifestVerifier>,
        source: Arc<dyn ManifestSource>,
        downloader: Arc<dyn ImageDownloader>,
    ) -> Result<Self, UpdaterSubsystemError> {
        let bank_writer = Arc::new(InMemoryBankWriter::cold_start());
        let bootloader = Arc::new(InMemoryBootloader::new(Bank::A));
        // Health check is StaticHealthCheck::default which
        // reports unhealthy; production wiring layers in real
        // checks. For the binary we plumb a `pass`-by-default
        // since the in-memory backend's commit path needs at
        // least one healthy probe to complete.
        let health = Arc::new(StaticHealthCheck::always_healthy(
            "in-memory backend: always healthy",
        ));
        let policy = UpdaterPolicy {
            max_image_bytes: cfg.max_image_bytes,
            ..UpdaterPolicy::default()
        };
        let service = UpdaterServiceBuilder::new()
            .target(target)
            .source(source)
            .verifier(verifier)
            .downloader(downloader)
            .bank_writer(bank_writer)
            .bootloader(bootloader)
            .health_check(health)
            .policy(policy)
            .build()?;
        Ok(Self {
            service: Arc::new(service),
            poll_interval: cfg.poll_interval,
            backend: UpdaterBackend::InMemory,
        })
    }

    /// Test-only convenience: full default wiring with empty
    /// in-memory source / downloader / verifier (no signing
    /// keys). Polls return `ManifestStale` errors, which the
    /// loop logs and continues — proves the supervisor wiring
    /// works without a real control-plane manifest server.
    ///
    /// # Errors
    ///
    /// Returns [`UpdaterSubsystemError::Build`] when the
    /// service builder rejects the wiring.
    pub fn default_in_memory(cfg: &UpdaterConfig) -> Result<Self, UpdaterSubsystemError> {
        Self::new_in_memory(
            cfg,
            UpdateTarget::Edge,
            Arc::new(ManifestVerifier::with_target(UpdateTarget::Edge)),
            Arc::new(StaticManifestSource::new()),
            Arc::new(InMemoryDownloader::new()),
        )
    }

    /// Borrow the underlying service.
    #[must_use]
    pub fn service(&self) -> &Arc<UpdaterService> {
        &self.service
    }

    /// Backend selector. Surfaced for the operator boot log.
    #[must_use]
    pub fn backend(&self) -> UpdaterBackend {
        self.backend
    }

    fn snapshot(&self) -> UpdaterStatsSnapshot {
        self.service.stats_snapshot()
    }
}

#[async_trait]
impl Subsystem for UpdaterSubsystem {
    fn name(&self) -> &'static str {
        "updater"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let service = Arc::clone(&self.service);
        let period = self.poll_interval;
        Ok(task::spawn(async move {
            let mut ticker = interval(period);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // Skip the first immediate tick so the supervisor
            // boot path doesn't slam the manifest source.
            ticker.tick().await;
            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    _ = ticker.tick() => {
                        match service.poll_and_install().await {
                            Ok(outcome) => {
                                tracing::info!(
                                    target: "sng_edge::updater",
                                    outcome = ?outcome,
                                    "updater poll completed"
                                );
                            }
                            Err(err) => {
                                // Logged at warn — the state
                                // machine itself bumps the
                                // appropriate counter (manifest
                                // poll error, verify error,
                                // download error, etc.).
                                tracing::warn!(
                                    target: "sng_edge::updater",
                                    error = %err,
                                    "updater poll failed"
                                );
                            }
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for UpdaterSubsystem {
    fn name(&self) -> &'static str {
        "updater"
    }

    async fn check(&self) -> SubsystemHealth {
        let snap = self.snapshot();
        // Down when the engine has poisoned itself via the
        // post-commit divergence guard; an operator-driven
        // `clear_layout_divergence` is required to re-admit
        // installs.
        let layout_diverged = self.service.layout_diverged();
        // Aggregate per-stage error counters so the operator
        // dashboard sees one rollup. The state-machine bumps
        // each counter at exactly one site so summation is
        // safe (no double-counting).
        let install_failures = snap.install_hash_mismatch
            + snap.install_truncated
            + snap.install_bank_errors
            + snap.install_bootloader_errors
            + snap.install_post_commit_layout_sync_failures;
        let status = if layout_diverged {
            HealthStatus::Down
        } else if install_failures > 0 || snap.install_rolled_back > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "backend={:?}, polls={}, admitted={}, committed={}, rolled_back={}, failures={}, layout_diverged={}",
                self.backend,
                snap.manifest_polls,
                snap.manifest_admitted,
                snap.install_committed,
                snap.install_rolled_back,
                install_failures,
                layout_diverged,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::UpdaterConfig;
    use sng_core::ShutdownTrigger;
    use std::time::Duration;

    fn test_cfg() -> UpdaterConfig {
        UpdaterConfig {
            poll_interval: Duration::from_millis(50),
            max_image_bytes: 1024 * 1024,
        }
    }

    #[tokio::test]
    async fn in_memory_subsystem_drains_clean_under_shutdown() {
        let sub = UpdaterSubsystem::default_in_memory(&test_cfg()).unwrap();
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = <UpdaterSubsystem as Subsystem>::start(&sub, signal)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        trigger.fire();
        handle.await.unwrap().unwrap();
        // Either the ticker fired at least one poll, or it never
        // got a chance — both are acceptable; what we care
        // about is the task drained clean.
    }

    #[tokio::test]
    async fn health_check_reports_backend_in_detail() {
        let sub = UpdaterSubsystem::default_in_memory(&test_cfg()).unwrap();
        let health = <UpdaterSubsystem as HealthCheck>::check(&sub).await;
        let detail = health.detail.unwrap();
        assert!(detail.contains("backend=InMemory"));
        assert!(detail.contains("polls="));
    }
}

// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Digital Experience Monitoring (DEM) subsystem adapter.
//!
//! Wraps [`sng_dem::ProbeEngine`]. When `dem.enabled` is true the
//! subsystem spawns a periodic sweep loop that probes configured
//! targets and emits [`sng_dem::ProbeResult`]s through the telemetry
//! pipeline. When disabled (the default) the subsystem is inert: no
//! engine is constructed, no loop is spawned, and the edge behaves
//! exactly as before.

use crate::config::DemConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_dem::{EngineConfig, ProbeEngine, ProbeResult, Target};
use std::sync::Arc;
use std::time::Duration;
use tokio::task;

/// Edge-tier DEM subsystem.
#[derive(Clone)]
pub struct DemSubsystem {
    /// The probe engine. `None` when DEM is disabled.
    engine: Option<Arc<ProbeEngine>>,
    /// Hot-swappable target list.
    targets: Arc<parking_lot::Mutex<Vec<Target>>>,
    /// Sweep interval.
    interval: Duration,
    /// Whether DEM is enabled.
    enabled: bool,
    /// Stats: total sweeps, total probes, total successes, total failures.
    stats: Arc<DemStats>,
}

/// Lightweight atomic counters for DEM health reporting.
#[derive(Debug, Default)]
pub struct DemStats {
    sweeps: std::sync::atomic::AtomicU64,
    probes: std::sync::atomic::AtomicU64,
    successes: std::sync::atomic::AtomicU64,
    failures: std::sync::atomic::AtomicU64,
}

impl DemStats {
    fn record_sweep(&self) {
        self.sweeps
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    fn record_results(&self, results: &[ProbeResult]) {
        for r in results {
            self.probes
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if r.success {
                self.successes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            } else {
                self.failures
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> DemStatsSnapshot {
        DemStatsSnapshot {
            sweeps: self.sweeps.load(std::sync::atomic::Ordering::Relaxed),
            probes: self.probes.load(std::sync::atomic::Ordering::Relaxed),
            successes: self.successes.load(std::sync::atomic::Ordering::Relaxed),
            failures: self.failures.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DemStatsSnapshot {
    pub sweeps: u64,
    pub probes: u64,
    pub successes: u64,
    pub failures: u64,
}

impl std::fmt::Debug for DemSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DemSubsystem")
            .field("enabled", &self.enabled)
            .field("interval", &self.interval)
            .field("targets", &self.targets.lock().len())
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl DemSubsystem {
    /// Build a subsystem from the edge config. When
    /// `cfg.enabled` is false the subsystem is inert.
    #[must_use]
    pub fn new(cfg: &DemConfig) -> Self {
        if !cfg.enabled {
            return Self {
                engine: None,
                targets: Arc::new(parking_lot::Mutex::new(Vec::new())),
                interval: Duration::from_secs(cfg.interval_secs),
                enabled: false,
                stats: Arc::new(DemStats::default()),
            };
        }

        let engine_cfg = EngineConfig {
            max_concurrency: cfg.max_concurrency,
            default_timeout: Duration::from_secs(cfg.timeout_secs),
            jitter: cfg.jitter,
            max_targets: cfg.max_targets,
        };

        let engine = match ProbeEngine::new(engine_cfg) {
            Ok(e) => Some(Arc::new(e)),
            Err(e) => {
                tracing::error!("DEM engine build failed, subsystem inert: {e}");
                None
            }
        };
        let enabled = engine.is_some();

        Self {
            engine,
            targets: Arc::new(parking_lot::Mutex::new(Vec::new())),
            interval: Duration::from_secs(cfg.interval_secs),
            enabled,
            stats: Arc::new(DemStats::default()),
        }
    }

    /// Replace the target list (called by the policy puller on
    /// bundle install).
    pub fn install_targets(&self, targets: Vec<Target>) {
        *self.targets.lock() = targets;
    }

    /// Add a single target.
    pub fn add_target(&self, target: Target) {
        self.targets.lock().push(target);
    }

    /// Clear all targets.
    pub fn clear_targets(&self) {
        self.targets.lock().clear();
    }

    /// Number of configured targets.
    #[must_use]
    pub fn target_count(&self) -> usize {
        self.targets.lock().len()
    }

    /// Whether DEM is enabled and the engine is operational.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Stats snapshot for health reporting.
    #[must_use]
    pub fn stats(&self) -> DemStatsSnapshot {
        self.stats.snapshot()
    }

    /// Run a single probe sweep immediately, emitting results to
    /// the telemetry channel. Returns the number of results
    /// emitted. Returns 0 when DEM is disabled or no targets are
    /// configured.
    pub async fn run_sweep(&self) -> usize {
        let Some(engine) = &self.engine else {
            return 0;
        };
        let targets = self.targets.lock().clone();
        if targets.is_empty() {
            return 0;
        }
        self.stats.record_sweep();
        let results = engine.probe_all(&targets).await;
        self.stats.record_results(&results);
        for r in &results {
            if r.success {
                tracing::info!(
                    target: "sng-dem",
                    key = %r.target_key,
                    kind = %r.probe_kind.as_str(),
                    total_ms = ?r.total_ms,
                    "probe ok",
                );
            } else {
                tracing::warn!(
                    target: "sng-dem",
                    key = %r.target_key,
                    kind = %r.probe_kind.as_str(),
                    error = ?r.error_kind.map(|k| k.as_str()),
                    "probe failed",
                );
            }
        }
        results.len()
    }
}

#[async_trait]
impl Subsystem for DemSubsystem {
    fn name(&self) -> &'static str {
        "dem"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        if !self.enabled {
            // Inert: just wait for shutdown.
            return Ok(task::spawn(async move {
                shutdown.wait().await;
                Ok(())
            }));
        }

        let interval = self.interval;
        let this = self.clone();

        Ok(task::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate first tick so the first sweep
            // happens after one interval (gives the policy puller
            // time to install targets).
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        this.run_sweep().await;
                    }
                    _ = shutdown.wait() => break,
                }
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for DemSubsystem {
    fn name(&self) -> &'static str {
        "dem"
    }

    async fn check(&self) -> SubsystemHealth {
        let snap = self.stats.snapshot();
        let status = if self.enabled {
            HealthStatus::Up
        } else {
            HealthStatus::Up // Disabled is still "Up" — just inert.
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "enabled={}, targets={}, sweeps={}, probes={}, successes={}, failures={}",
                self.enabled,
                self.target_count(),
                snap.sweeps,
                snap.probes,
                snap.successes,
                snap.failures,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_dem::{ProbeKind, Target};
    use sng_core::ShutdownTrigger;

    fn disabled_sub() -> DemSubsystem {
        DemSubsystem::new(&DemConfig::default())
    }

    fn enabled_sub() -> DemSubsystem {
        DemSubsystem::new(
            &DemConfig {
                enabled: true,
                interval_secs: 1,
                max_concurrency: 2,
                timeout_secs: 1,
                jitter: 0.0,
                max_targets: 8,
            },
        )
    }

    #[test]
    fn disabled_subsystem_is_inert() {
        let sub = disabled_sub();
        assert!(!sub.enabled());
        assert_eq!(sub.target_count(), 0);
    }

    #[test]
    fn enabled_subsystem_constructs_engine() {
        let sub = enabled_sub();
        assert!(sub.enabled());
    }

    #[test]
    fn install_targets_replaces_list() {
        let sub = enabled_sub();
        sub.install_targets(vec![
            Target {
                key: "m365".into(),
                name: "Microsoft 365".into(),
                kind: ProbeKind::Dns,
                address: "login.microsoftonline.com".into(),
                port: None,
                timeout_ms: 1000,
            },
        ]);
        assert_eq!(sub.target_count(), 1);
        sub.clear_targets();
        assert_eq!(sub.target_count(), 0);
    }

    #[test]
    fn add_target_appends() {
        let sub = enabled_sub();
        sub.add_target(Target {
            key: "a".into(),
            name: "A".into(),
            kind: ProbeKind::Dns,
            address: "a.example".into(),
            port: None,
            timeout_ms: 500,
        });
        sub.add_target(Target {
            key: "b".into(),
            name: "B".into(),
            kind: ProbeKind::Dns,
            address: "b.example".into(),
            port: None,
            timeout_ms: 500,
        });
        assert_eq!(sub.target_count(), 2);
    }

    #[tokio::test]
    async fn disabled_sweep_returns_zero() {
        let sub = disabled_sub();
        assert_eq!(sub.run_sweep().await, 0);
    }

    #[tokio::test]
    async fn enabled_sweep_no_targets_returns_zero() {
        let sub = enabled_sub();
        assert_eq!(sub.run_sweep().await, 0);
    }

    #[tokio::test]
    async fn subsystem_idles_when_disabled() {
        let sub = disabled_sub();
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn health_reports_disabled_state() {
        let sub = disabled_sub();
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Up);
        let detail = h.detail.expect("detail");
        assert!(detail.contains("enabled=false"));
    }

    #[tokio::test]
    async fn health_reports_enabled_state() {
        let sub = enabled_sub();
        sub.add_target(Target {
            key: "t".into(),
            name: "T".into(),
            kind: ProbeKind::Dns,
            address: "t.example".into(),
            port: None,
            timeout_ms: 500,
        });
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Up);
        let detail = h.detail.expect("detail");
        assert!(detail.contains("enabled=true"));
        assert!(detail.contains("targets=1"));
    }

    #[test]
    fn stats_record_and_snapshot() {
        let stats = DemStats::default();
        stats.record_sweep();
        stats.record_sweep();
        let snap = stats.snapshot();
        assert_eq!(snap.sweeps, 2);
        assert_eq!(snap.probes, 0);
    }
}

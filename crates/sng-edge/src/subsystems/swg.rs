// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Secure Web Gateway (SWG) subsystem adapter.
//!
//! Wraps [`sng_swg::SwgManager`] driving a
//! [`sng_swg::ShellEnvoy`] backend. On boot the adapter installs
//! a minimal forward-proxy config so the operator gets a working
//! TLS-intercepting gateway out of the box; the policy puller
//! later swaps in the tenant-specific [`EnvoyConfig`] through
//! [`SwgSubsystem::install`]. The `start` task waits on shutdown
//! and calls [`SwgManager::stop`] for a graceful Envoy SIGTERM.

use crate::config::SwgConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_swg::health::FailMode;
use sng_swg::manager::SwgManagerConfig;
use sng_swg::{EnvoyConfig, EnvoyProcess, HealthState, MockEnvoy, ShellEnvoy, SwgManager};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::task;

/// Edge-tier SWG subsystem.
pub struct SwgSubsystem {
    manager: Arc<SwgManager>,
    config_path: PathBuf,
    enable: bool,
    initial: Option<EnvoyConfig>,
}

impl std::fmt::Debug for SwgSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwgSubsystem")
            .field("config_path", &self.config_path)
            .field("enable", &self.enable)
            .finish_non_exhaustive()
    }
}

impl SwgSubsystem {
    /// Build with a [`ShellEnvoy`] backend honouring the optional
    /// `envoy_binary` override. When `enable=false` the manager
    /// is constructed but never started; a future hot-enable
    /// path can call [`SwgSubsystem::install`] directly.
    #[must_use]
    pub fn new(cfg: &SwgConfig) -> Self {
        let process: Arc<dyn EnvoyProcess> = match &cfg.envoy_binary {
            Some(p) => Arc::new(ShellEnvoy::new().with_binary(p.clone())),
            None => Arc::new(ShellEnvoy::new()),
        };
        Self::with_process(cfg, process)
    }

    /// Test-only constructor. Inject a [`MockEnvoy`] (or any
    /// other [`EnvoyProcess`] impl) so integration tests can
    /// drive the manager without spawning real Envoy.
    #[must_use]
    pub fn with_process(cfg: &SwgConfig, process: Arc<dyn EnvoyProcess>) -> Self {
        let initial = if cfg.enable {
            Some(EnvoyConfig::minimal_forward_proxy(
                "unix:///var/run/sng/ext_authz.sock",
            ))
        } else {
            None
        };
        let mgr_cfg = SwgManagerConfig {
            config_path: cfg.config_path.clone(),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: Some(Duration::from_secs(30)),
        };
        Self {
            manager: Arc::new(SwgManager::new(mgr_cfg, process)),
            config_path: cfg.config_path.clone(),
            enable: cfg.enable,
            initial,
        }
    }

    /// Build with the in-process [`MockEnvoy`]. Used by the
    /// integration tests.
    #[must_use]
    pub fn with_mock(cfg: &SwgConfig) -> Self {
        Self::with_process(cfg, Arc::new(MockEnvoy::new()))
    }

    /// Borrow the underlying manager. Other subsystems (e.g.
    /// the comms control-plane bundle pull) push new
    /// [`EnvoyConfig`] objects through it.
    #[must_use]
    pub fn manager(&self) -> &Arc<SwgManager> {
        &self.manager
    }

    /// Install a fresh [`EnvoyConfig`]. Thin pass-through to
    /// [`SwgManager::install`] so the binary's other subsystems
    /// don't need to thread the manager around.
    ///
    /// # Errors
    ///
    /// Returns [`sng_swg::SwgError`] when render / validate /
    /// kernel apply fails.
    pub async fn install(&self, cfg: EnvoyConfig) -> Result<(), sng_swg::SwgError> {
        self.manager.install(cfg).await.map(|_| ())
    }
}

#[async_trait]
impl Subsystem for SwgSubsystem {
    fn name(&self) -> &'static str {
        "swg"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let manager = Arc::clone(&self.manager);
        let initial = self.initial.clone();
        let enable = self.enable;
        Ok(task::spawn(async move {
            if !enable {
                // Disabled: idle until shutdown. Operator can
                // hot-enable later by calling
                // SwgSubsystem::install() directly.
                shutdown.wait().await;
                return Ok(());
            }
            if let Some(cfg) = initial {
                manager.install(cfg).await.map_err(|e| -> SubsystemError {
                    Box::new(std::io::Error::other(format!(
                        "swg initial install failed: {e}"
                    )))
                })?;
            }
            shutdown.wait().await;
            if let Err(e) = manager.stop().await {
                tracing::warn!(target: "sng_edge::swg", error = %e, "swg manager stop failed");
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for SwgSubsystem {
    fn name(&self) -> &'static str {
        "swg"
    }

    async fn check(&self) -> SubsystemHealth {
        if !self.enable {
            return SubsystemHealth {
                name: <Self as HealthCheck>::name(self).into(),
                status: HealthStatus::Up,
                detail: Some("enabled=false".into()),
            };
        }
        // Probe with admin_port_reachable=true. A real production
        // wiring would hook this off a TCP connect on the
        // admin port; we trust the process status here.
        let snap = self.manager.probe(true).await;
        let status = match snap.health.report.state {
            HealthState::Healthy => HealthStatus::Up,
            HealthState::Degraded | HealthState::Unknown => HealthStatus::Degraded,
            HealthState::Failed => HealthStatus::Down,
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "listeners={}, clusters={}, digest={}, state={:?}, traffic_permitted={}",
                snap.listener_count,
                snap.cluster_count,
                snap.digest.as_deref().unwrap_or("none"),
                snap.health.report.state,
                snap.health.traffic_permitted,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use tempfile::tempdir;

    fn cfg(dir: &std::path::Path, enable: bool) -> SwgConfig {
        SwgConfig {
            config_path: dir.join("envoy.yaml"),
            envoy_binary: None,
            enable,
            ..SwgConfig::default()
        }
    }

    #[tokio::test]
    async fn disabled_subsystem_idles_until_shutdown() {
        let dir = tempdir().unwrap();
        let sub = SwgSubsystem::with_mock(&cfg(dir.path(), false));
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = <SwgSubsystem as Subsystem>::start(&sub, signal)
            .await
            .unwrap();
        trigger.fire();
        handle.await.unwrap().unwrap();
        let health = <SwgSubsystem as HealthCheck>::check(&sub).await;
        assert_eq!(health.status, HealthStatus::Up);
        assert!(health.detail.unwrap().contains("enabled=false"));
    }
}

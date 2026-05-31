// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! IPS subsystem adapter.
//!
//! Wraps [`sng_ips::IpsManager`] driving a
//! [`sng_ips::ShellSuricata`] process backend. The
//! subsystem's [`Subsystem::start`] implementation invokes
//! [`IpsManager::start`] (renders config, spawns Suricata)
//! and [`IpsManager::spawn_background_tasks`] (EVE tail +
//! stats poll + restart watchdog), then awaits the supervisor
//! shutdown signal. On drain, it calls [`IpsManager::stop`]
//! and joins every background task.
//!
//! When `IpsConfig::enable` is `false`, the subsystem builds
//! the manager but does NOT start Suricata — the manager is
//! held so operators can issue a hot-enable via
//! [`IpsSubsystem::manager`].`apply_rule_bundle` /
//! `apply_config` once they have provisioned rules. Health
//! reports `Up` with `enabled=false` so the operator
//! dashboard renders an explicit "disabled by config" badge
//! instead of a misleading "process not running" alert.

use crate::config::IpsConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_ips::{
    AlwaysValidValidator, FsRuleStager, IpsConfigInput, IpsEventSource, IpsManager,
    IpsManagerConfig, IpsRuleVerifier, RuleStager, RuleStagerConfig, RuleValidator, ShellSuricata,
    SuricataProcess,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task;

/// Edge-tier IPS subsystem.
pub struct IpsSubsystem {
    manager: Arc<IpsManager>,
    initial_input: IpsConfigInput,
    enable: bool,
    event_source: Arc<Mutex<Option<IpsEventSource>>>,
}

impl std::fmt::Debug for IpsSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `manager` + `event_source` deliberately omitted —
        // they hold large internal state (process handles,
        // unbounded receiver) that isn't safe to dump.
        // `finish_non_exhaustive` signals the omission and
        // silences `clippy::missing_fields_in_debug`.
        f.debug_struct("IpsSubsystem")
            .field("enable", &self.enable)
            .field("interface", &self.initial_input.interface)
            .field("runtime", &self.initial_input.runtime)
            .finish_non_exhaustive()
    }
}

impl IpsSubsystem {
    /// Build a subsystem wiring real `ShellSuricata`,
    /// `FsRuleStager` (validator chosen below), and the
    /// canonical [`IpsRuleVerifier`] (empty trust store at
    /// boot; operators add keys via the manager API).
    ///
    /// When the operator-supplied `cfg.enable` is `true` AND
    /// `cfg.suricata_binary` is present (or the default
    /// `suricata` is on `$PATH`), the production validator is
    /// used. When `cfg.enable` is `false`, the
    /// [`AlwaysValidValidator`] is used — there is no point
    /// shelling out to `suricata -T` if the binary is never
    /// going to be started, and the operator may not have
    /// installed `suricata` yet on a brand-new VM.
    #[must_use]
    pub fn new(cfg: &IpsConfig) -> Self {
        let process: Arc<dyn SuricataProcess> = match &cfg.suricata_binary {
            Some(p) => Arc::new(ShellSuricata::new(cfg.interface.clone()).with_binary(p.clone())),
            None => Arc::new(ShellSuricata::new(cfg.interface.clone())),
        };
        let validator: Arc<dyn RuleValidator> = if cfg.enable {
            // SuricataValidator with default binary; operator
            // override is honored via cfg.suricata_binary.
            let mut v = sng_ips::SuricataValidator::new();
            if let Some(p) = &cfg.suricata_binary {
                p.clone_into(&mut v.binary);
            }
            Arc::new(v)
        } else {
            Arc::new(AlwaysValidValidator)
        };
        let stager_cfg = RuleStagerConfig {
            final_path: cfg.rule_file_path.clone(),
            staging_dir: cfg.staging_dir.clone(),
            config_path: cfg.config_path.clone(),
        };
        let stager: Arc<dyn RuleStager> = Arc::new(FsRuleStager::new(stager_cfg, validator));
        let verifier = Arc::new(IpsRuleVerifier::new());
        let (sink, source) = IpsEventSource::channel(cfg.event_channel_capacity);
        let manager_cfg = IpsManagerConfig {
            config_path: cfg.config_path.clone(),
            eve_log_path: cfg.eve_log_path.clone(),
            ..IpsManagerConfig::default()
        };
        let manager = Arc::new(IpsManager::new(
            manager_cfg,
            process,
            stager,
            verifier,
            sink,
        ));
        let initial_input = build_initial_input(cfg);
        Self {
            manager,
            initial_input,
            enable: cfg.enable,
            event_source: Arc::new(Mutex::new(Some(source))),
        }
    }

    /// Borrow the underlying manager. Used by the comms
    /// subsystem to push new rule bundles, by operator-tools
    /// to query status, etc.
    #[must_use]
    pub fn manager(&self) -> &Arc<IpsManager> {
        &self.manager
    }

    /// Take ownership of the EVE event source. Callable once
    /// per subsystem; subsequent calls return `None`. The
    /// telemetry subsystem drains this source on its own task
    /// and forwards into the [`sng_telemetry`] pipeline.
    pub async fn take_event_source(&self) -> Option<IpsEventSource> {
        self.event_source.lock().await.take()
    }
}

fn build_initial_input(cfg: &IpsConfig) -> IpsConfigInput {
    IpsConfigInput {
        rule_file_path: cfg.rule_file_path.clone(),
        interface: cfg.interface.clone(),
        runtime: cfg.runtime.into_lib(),
        eve_log_path: cfg.eve_log_path.clone(),
        stats_socket_path: cfg.stats_socket_path.clone(),
        home_net: cfg.home_net.clone(),
        external_net: cfg.external_net.clone(),
        app_layer_enabled: default_app_layer(),
        force_drop_on_alert: None,
        max_pending_packets: Some(1024),
    }
}

fn default_app_layer() -> std::collections::BTreeMap<String, bool> {
    let mut m = std::collections::BTreeMap::new();
    for parser in ["tls", "http", "dns", "smb", "ssh", "smtp", "ftp"] {
        m.insert(parser.to_owned(), true);
    }
    m
}

#[async_trait]
impl Subsystem for IpsSubsystem {
    fn name(&self) -> &'static str {
        "ips"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let manager = Arc::clone(&self.manager);
        let initial = self.initial_input.clone();
        let enable = self.enable;
        Ok(task::spawn(async move {
            // When disabled, just idle until shutdown. The
            // manager is constructed but never started, so the
            // operator can hot-enable later by calling
            // start() / spawn_background_tasks() through
            // IpsSubsystem::manager().
            if !enable {
                shutdown.wait().await;
                return Ok(());
            }
            // Render config, spawn Suricata.
            manager
                .start(&initial)
                .await
                .map_err(|e| -> SubsystemError {
                    Box::new(std::io::Error::other(format!(
                        "ips manager start failed: {e}"
                    )))
                })?;
            let handles = manager.spawn_background_tasks();
            // Wait for shutdown.
            shutdown.wait().await;
            // Graceful stop.
            if let Err(e) = manager.stop().await {
                tracing::warn!(target: "sng_edge::ips", error = %e, "ips manager stop failed");
            }
            // Drain background tasks with a budget so a wedged
            // tail doesn't hold the supervisor forever.
            let join_fut = handles.join();
            tokio::pin!(join_fut);
            let _ = tokio::time::timeout(Duration::from_secs(10), join_fut).await;
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for IpsSubsystem {
    fn name(&self) -> &'static str {
        "ips"
    }

    async fn check(&self) -> SubsystemHealth {
        if !self.enable {
            return SubsystemHealth {
                name: <Self as HealthCheck>::name(self).into(),
                status: HealthStatus::Up,
                detail: Some("enabled=false".into()),
            };
        }
        let status_snapshot = self.manager.status().await;
        let status = if status_snapshot.forwarding_allowed {
            HealthStatus::Up
        } else {
            HealthStatus::Down
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "process={:?}, health={:?}, forwarding_allowed={}, decode_errors={}, events_emitted={}",
                status_snapshot.process,
                status_snapshot.health,
                status_snapshot.forwarding_allowed,
                status_snapshot.eve_decode_errors,
                status_snapshot.events_emitted
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use std::time::Duration;

    fn disabled_cfg() -> IpsConfig {
        IpsConfig {
            enable: false,
            ..IpsConfig::default()
        }
    }

    #[tokio::test]
    async fn subsystem_idles_when_disabled_and_drains_cleanly() {
        let sub = IpsSubsystem::new(&disabled_cfg());
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        let res = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("drain budget");
        assert!(res.expect("join").is_ok());
    }

    #[tokio::test]
    async fn health_when_disabled_is_up_with_explicit_marker() {
        let sub = IpsSubsystem::new(&disabled_cfg());
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Up);
        assert!(h.detail.expect("detail").contains("enabled=false"));
    }

    #[tokio::test]
    async fn take_event_source_yields_exactly_once() {
        let sub = IpsSubsystem::new(&disabled_cfg());
        assert!(sub.take_event_source().await.is_some());
        assert!(sub.take_event_source().await.is_none());
    }
}

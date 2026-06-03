// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! High-availability (active/passive failover) subsystem adapter.
//!
//! Wraps [`sng_ha::HaController`]. When `HaConfig::enabled` is
//! `true` the subsystem's [`Subsystem::start`] drives the
//! controller's VRRP election + VIP ownership + health-driven
//! demotion loop until the supervisor signals shutdown; on drain
//! the controller releases the VIP if it is the current Master so
//! the peer can take over without waiting out the master-down
//! interval.
//!
//! When HA is disabled (the default — a single-edge deployment)
//! the subsystem is a no-op: it builds no socket, owns no VIP,
//! and its `start` task simply idles until shutdown. Health then
//! reports `Up` with `enabled=false` so the operator dashboard
//! renders an explicit "standalone" badge rather than a
//! misleading failover-state alert.

use crate::config::HaConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_ha::{
    HaController, HaSettings, HaStats, HealthRegistry, InterfaceUpProbe, MulticastChannel,
    ShellVipManager, ShutdownGate, SyncQueue, VipSpec, VrrpConfig, role_label, vrrp::VRRP_UDP_PORT,
};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::task;

/// Edge-tier HA subsystem.
pub struct HaSubsystem {
    enabled: bool,
    /// `None` when HA is disabled.
    controller: Option<Arc<HaController>>,
    /// Always present so the health probe has a stable handle
    /// even before / after the controller runs. When disabled
    /// this stays at its `Initialize`-role default.
    stats: Arc<HaStats>,
}

impl std::fmt::Debug for HaSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HaSubsystem")
            .field("enabled", &self.enabled)
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl HaSubsystem {
    /// Build the subsystem from its config slice.
    ///
    /// When disabled, returns a no-op adapter immediately. When
    /// enabled, binds the VRRP multicast socket on the configured
    /// interface address, assembles the health registry (a
    /// mandatory interface-up probe), and composes the
    /// [`HaController`].
    ///
    /// # Errors
    ///
    /// Returns [`sng_ha::HaError`] if the config is internally
    /// inconsistent (re-checked here via
    /// [`HaSettings::validate`]) or the multicast socket cannot
    /// be bound / joined. Cross-field invariants are already
    /// enforced at config load by `validate_ha`, so a failure
    /// here on a well-formed config indicates an environment
    /// problem (interface missing, address not local) rather than
    /// an operator typo.
    pub fn new(cfg: &HaConfig) -> Result<Self, sng_ha::HaError> {
        if !cfg.enabled {
            return Ok(Self {
                enabled: false,
                controller: None,
                stats: Arc::new(HaStats::default()),
            });
        }

        // These were validated as present + IPv4 at config load
        // (`validate_ha`); re-derive defensively and surface a
        // typed error rather than panicking if a caller built the
        // config in code without going through `load_from_path`.
        let local_addr = cfg.local_address.ok_or_else(|| {
            sng_ha::HaError::InvalidConfig("ha.local_address is required when enabled".into())
        })?;
        let bind_v4 = match local_addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
                return Err(sng_ha::HaError::InvalidConfig(
                    "ha.local_address must be IPv4".into(),
                ));
            }
        };
        let virtual_ip = cfg.virtual_ip.ok_or_else(|| {
            sng_ha::HaError::InvalidConfig("ha.virtual_ip is required when enabled".into())
        })?;

        let settings = HaSettings {
            vrrp: VrrpConfig {
                virtual_router_id: cfg.virtual_router_id,
                priority: cfg.priority,
                advertisement_interval: cfg.advertisement_interval,
                preempt_mode: cfg.preempt_mode,
            },
            vip: VipSpec::new(virtual_ip, cfg.virtual_ip_prefix_len, cfg.interface.clone()),
            local_addr,
            health_interval: cfg.health_interval,
            sync_batch: cfg.sync_batch,
        };
        settings.validate()?;

        let channel = Arc::new(MulticastChannel::bind(bind_v4, VRRP_UDP_PORT)?);
        let vip = Arc::new(ShellVipManager::new());
        // Mandatory interface-up probe: a Master whose data-plane
        // NIC has gone down must not keep the VIP. Additional
        // signals (control-plane reachability, Suricata liveness,
        // bundle-loaded) are added by their owning subsystems in
        // follow-up wiring; the registry composes them in order.
        let registry = Arc::new(
            HealthRegistry::new()
                .with_probe(Arc::new(InterfaceUpProbe::new(cfg.interface.clone(), true))),
        );
        let queue = Arc::new(SyncQueue::new(cfg.sync_queue_capacity));

        let controller = Arc::new(HaController::new(settings, channel, vip, registry, queue)?);
        let stats = controller.stats();
        Ok(Self {
            enabled: true,
            controller: Some(controller),
            stats,
        })
    }

    /// Shared stats handle. Tests assert promotion / demotion /
    /// advertisement counters here.
    #[must_use]
    pub fn stats(&self) -> &Arc<HaStats> {
        &self.stats
    }

    /// Whether HA is enabled for this appliance.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Borrow the controller (present only when enabled). The
    /// state-sync producer side reaches the bounded queue through
    /// [`HaController::sync_queue`].
    #[must_use]
    pub fn controller(&self) -> Option<&Arc<HaController>> {
        self.controller.as_ref()
    }
}

/// Adapts the supervisor's [`ShutdownSignal`] onto the
/// controller's [`ShutdownGate`] so `sng-ha` stays independent of
/// `sng-core`'s lifecycle types.
struct SignalGate(ShutdownSignal);

impl ShutdownGate for SignalGate {
    async fn wait(&mut self) {
        self.0.wait().await;
    }

    fn is_shutdown(&mut self) -> bool {
        self.0.is_fired()
    }
}

#[async_trait]
impl Subsystem for HaSubsystem {
    fn name(&self) -> &'static str {
        "ha"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let controller = self.controller.clone();
        Ok(task::spawn(async move {
            if let Some(controller) = controller {
                // Drive the failover loop. A controller error
                // (socket failure mid-run) propagates as a
                // subsystem drain error.
                controller
                    .run(SignalGate(shutdown))
                    .await
                    .map_err(|e| -> SubsystemError { Box::new(e) })
            } else {
                // Disabled — hold the slot and idle until drain.
                shutdown.wait().await;
                Ok(())
            }
        }))
    }
}

#[async_trait]
impl HealthCheck for HaSubsystem {
    fn name(&self) -> &'static str {
        "ha"
    }

    async fn check(&self) -> SubsystemHealth {
        let detail = if self.enabled {
            let snap = self.stats.snapshot();
            format!(
                "enabled=true, role={}, promotions={}, demotions={}, adv_sent={}, adv_recv={}, health_releases={}",
                role_label(snap.role),
                snap.promotions,
                snap.demotions,
                snap.advertisements_sent,
                snap.advertisements_received,
                snap.health_releases,
            )
        } else {
            "enabled=false, role=standalone".to_owned()
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status: HealthStatus::Up,
            detail: Some(detail),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use std::net::Ipv4Addr;

    fn disabled_cfg() -> HaConfig {
        HaConfig::default()
    }

    fn enabled_cfg() -> HaConfig {
        HaConfig {
            enabled: true,
            interface: "lo".into(),
            local_address: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            peer_address: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
            virtual_ip: Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 50))),
            ..HaConfig::default()
        }
    }

    #[tokio::test]
    async fn disabled_subsystem_is_inert_and_idles_until_shutdown() {
        let sub = HaSubsystem::new(&disabled_cfg()).expect("build disabled");
        assert!(!sub.is_enabled());
        assert!(sub.controller().is_none());

        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        // No work to do; firing shutdown lets the idle task exit.
        trigger.fire();
        handle.await.expect("join").expect("run ok");

        let health = HealthCheck::check(&sub).await;
        assert_eq!(health.status, HealthStatus::Up);
        assert!(health.detail.unwrap().contains("enabled=false"));
    }

    #[tokio::test]
    async fn enabled_subsystem_reports_failover_health_detail() {
        // Binding the VRRP multicast socket on loopback exercises
        // the real socket2 path; if the sandbox forbids multicast
        // joins we skip rather than fail (the unit-level socket
        // behaviour is covered in `sng-ha`'s own tests).
        let Ok(sub) = HaSubsystem::new(&enabled_cfg()) else {
            eprintln!("skipping: multicast bind unavailable in this environment");
            return;
        };
        assert!(sub.is_enabled());
        assert!(sub.controller().is_some());

        let health = HealthCheck::check(&sub).await;
        assert_eq!(health.status, HealthStatus::Up);
        let detail = health.detail.unwrap();
        assert!(detail.contains("enabled=true"));
        assert!(detail.contains("role="));
    }
}

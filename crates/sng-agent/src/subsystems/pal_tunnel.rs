// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! PAL tunnel-provider subsystem.
//!
//! Reconciles the *desired* set of tunnels (driven by the
//! control plane via the comms subsystem) against the set
//! currently active on the [`sng_pal::TunnelProvider`]
//! backend. Endpoint agents typically run a single tunnel
//! (laptop → SNG cloud) but the design supports more so the
//! same crate can ship on the edge VM when an SD-WAN
//! configuration brings up multiple peers.
//!
//! Reconciliation runs on a fixed cadence and on every
//! change to the `desired_rx` watch channel. The loop:
//!
//! 1. Read the desired set from the watch channel.
//! 2. Ask the provider for its current set (`list`).
//! 3. For each tunnel in `desired \ current`, call `start`.
//! 4. For each tunnel in `current \ desired`, call `stop`.
//!
//! Counters surfaced through the health endpoint distinguish
//! steady-state success from transient backend errors so the
//! operator dashboard renders an amber marker only when
//! tunnel ops are actually failing rather than just
//! oscillating.

use crate::config::TunnelConfig as TunnelCadenceConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_pal::tunnel::{TunnelConfig, TunnelHandle, TunnelProvider};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task;
use tokio::time::{MissedTickBehavior, interval};

/// PAL tunnel-provider subsystem.
pub struct PalTunnelSubsystem {
    provider: Arc<dyn TunnelProvider>,
    desired_rx: watch::Receiver<Vec<TunnelConfig>>,
    stats: Arc<TunnelStats>,
    reconcile_interval: Duration,
}

impl std::fmt::Debug for PalTunnelSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PalTunnelSubsystem")
            .field("reconcile_interval", &self.reconcile_interval)
            .finish_non_exhaustive()
    }
}

/// Atomic counters surfaced through the health endpoint.
#[derive(Debug, Default)]
pub struct TunnelStats {
    /// Successful reconcile cycles (regardless of whether any
    /// state change was applied).
    pub reconciles: AtomicU64,
    /// Tunnels successfully brought up.
    pub starts_ok: AtomicU64,
    /// Tunnels the provider refused to bring up.
    pub starts_failed: AtomicU64,
    /// Tunnels successfully torn down.
    pub stops_ok: AtomicU64,
    /// Tunnel teardown attempts the provider refused.
    pub stops_failed: AtomicU64,
    /// `list` calls that surfaced an error.
    pub list_errors: AtomicU64,
}

impl PalTunnelSubsystem {
    /// Build from the selected provider backend + the watch
    /// channel that the control-plane consumer (typically
    /// driven by the comms subsystem) updates with the
    /// desired tunnel set.
    #[must_use]
    pub fn new(
        cfg: &TunnelCadenceConfig,
        provider: Arc<dyn TunnelProvider>,
        desired_rx: watch::Receiver<Vec<TunnelConfig>>,
    ) -> Self {
        Self {
            provider,
            desired_rx,
            stats: Arc::new(TunnelStats::default()),
            reconcile_interval: cfg.reconcile_interval,
        }
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<TunnelStats> {
        &self.stats
    }
}

#[async_trait]
impl Subsystem for PalTunnelSubsystem {
    fn name(&self) -> &'static str {
        "pal_tunnel"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let provider = Arc::clone(&self.provider);
        let mut desired_rx = self.desired_rx.clone();
        let stats = Arc::clone(&self.stats);
        let reconcile_interval = self.reconcile_interval;

        Ok(task::spawn(async move {
            let mut ticker = interval(reconcile_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // Drain the immediate first tick so we don't
            // double-reconcile (once on this tick, once on
            // the initial watch read below).
            ticker.tick().await;

            // Always do one reconcile pass at startup so the
            // initial desired set is realised without
            // waiting `reconcile_interval`.
            reconcile_once(&*provider, &desired_rx, &stats).await;

            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    _ = ticker.tick() => {
                        reconcile_once(&*provider, &desired_rx, &stats).await;
                    }
                    res = desired_rx.changed() => {
                        if res.is_err() {
                            // Sender dropped — no further
                            // updates will arrive. Continue
                            // honouring the tick loop so the
                            // last-known-good set stays
                            // reconciled.
                            tracing::warn!(
                                target: "sng_agent::pal_tunnel",
                                "desired tunnel set publisher dropped; \
                                 holding last-known-good set"
                            );
                            continue;
                        }
                        reconcile_once(&*provider, &desired_rx, &stats).await;
                    }
                }
            }

            // On shutdown, tear down every active tunnel so
            // the OS isn't left with a dangling kernel
            // interface. This is best-effort: a provider
            // error here is logged + counted but does not
            // fail the subsystem (the OS will reclaim the
            // resource when the process exits anyway).
            if let Ok(active) = provider.list().await {
                for id in active {
                    if let Err(err) = provider.stop(TunnelHandle { id: id.clone() }).await {
                        stats.stops_failed.fetch_add(1, Ordering::Relaxed);
                        tracing::warn!(
                            target: "sng_agent::pal_tunnel",
                            tunnel_id = %id,
                            error = %err,
                            "drain: tunnel stop failed during shutdown"
                        );
                    } else {
                        stats.stops_ok.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }

            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for PalTunnelSubsystem {
    fn name(&self) -> &'static str {
        "pal_tunnel"
    }

    async fn check(&self) -> SubsystemHealth {
        let reconciles = self.stats.reconciles.load(Ordering::Relaxed);
        let starts_ok = self.stats.starts_ok.load(Ordering::Relaxed);
        let starts_failed = self.stats.starts_failed.load(Ordering::Relaxed);
        let stops_ok = self.stats.stops_ok.load(Ordering::Relaxed);
        let stops_failed = self.stats.stops_failed.load(Ordering::Relaxed);
        let list_errors = self.stats.list_errors.load(Ordering::Relaxed);

        // A failed start with no successful start is the
        // "tunnel is dead" signal — Down. A failed stop or
        // intermittent list error degrades but doesn't kill.
        let status = if starts_failed > 0 && starts_ok == 0 {
            HealthStatus::Down
        } else if starts_failed > 0 || stops_failed > 0 || list_errors > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "reconciles={reconciles}, starts_ok={starts_ok}, starts_failed={starts_failed}, \
                 stops_ok={stops_ok}, stops_failed={stops_failed}, list_errors={list_errors}"
            )),
        }
    }
}

/// Single reconcile pass: compute (desired \ current) and
/// (current \ desired) sets, then apply start / stop calls.
async fn reconcile_once(
    provider: &dyn TunnelProvider,
    desired_rx: &watch::Receiver<Vec<TunnelConfig>>,
    stats: &Arc<TunnelStats>,
) {
    stats.reconciles.fetch_add(1, Ordering::Relaxed);
    let desired_snapshot = desired_rx.borrow().clone();
    let desired_ids: HashSet<String> = desired_snapshot.iter().map(|c| c.id.clone()).collect();
    let active = match provider.list().await {
        Ok(active) => active,
        Err(err) => {
            stats.list_errors.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                target: "sng_agent::pal_tunnel",
                error = %err,
                "tunnel provider list failed; skipping this reconcile cycle"
            );
            return;
        }
    };
    let active_ids: HashSet<String> = active.iter().cloned().collect();

    for cfg in &desired_snapshot {
        if active_ids.contains(&cfg.id) {
            continue;
        }
        match provider.start(cfg.clone()).await {
            Ok(_) => {
                stats.starts_ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                stats.starts_failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "sng_agent::pal_tunnel",
                    tunnel_id = %cfg.id,
                    error = %err,
                    "tunnel start failed"
                );
            }
        }
    }
    for id in &active_ids {
        if desired_ids.contains(id) {
            continue;
        }
        match provider.stop(TunnelHandle { id: id.clone() }).await {
            Ok(()) => {
                stats.stops_ok.fetch_add(1, Ordering::Relaxed);
            }
            Err(err) => {
                stats.stops_failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "sng_agent::pal_tunnel",
                    tunnel_id = %id,
                    error = %err,
                    "tunnel stop failed"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use sng_core::ShutdownTrigger;
    use sng_pal::tunnel::InMemoryTunnelProvider;
    use std::str::FromStr;

    fn cfg(id: &str) -> TunnelConfig {
        TunnelConfig {
            id: id.into(),
            endpoint: "1.2.3.4:51820".parse().expect("addr"),
            peer_public_key_b64: "A".repeat(43) + "=",
            keepalive_seconds: 25,
            allowed_ips: vec![IpNet::from_str("0.0.0.0/0").expect("net")],
        }
    }

    #[tokio::test]
    async fn reconcile_starts_desired_tunnels_at_boot() {
        let (tx, rx) = watch::channel(vec![cfg("t1")]);
        let provider = Arc::new(InMemoryTunnelProvider::new());
        let subsys = PalTunnelSubsystem::new(
            &TunnelCadenceConfig {
                reconcile_interval: Duration::from_secs(3600),
            },
            provider.clone(),
            rx,
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = subsys.start(signal).await.expect("start");
        // Wait briefly for the initial reconcile pass.
        for _ in 0..20 {
            if !provider.list().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            provider.list().await.unwrap(),
            vec!["t1".to_owned()],
            "tunnel t1 should be up after initial reconcile"
        );
        trigger.fire();
        handle.await.expect("join").expect("clean shutdown");
        // On shutdown the subsystem drains every active
        // tunnel.
        let after = provider.list().await.unwrap();
        assert!(
            after.is_empty(),
            "tunnels should be drained on shutdown, got: {after:?}"
        );
        drop(tx);
    }

    #[tokio::test]
    async fn reconcile_stops_tunnels_no_longer_desired() {
        let (tx, rx) = watch::channel(vec![cfg("t1"), cfg("t2")]);
        let provider = Arc::new(InMemoryTunnelProvider::new());
        let subsys = PalTunnelSubsystem::new(
            &TunnelCadenceConfig {
                reconcile_interval: Duration::from_millis(10),
            },
            provider.clone(),
            rx,
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = subsys.start(signal).await.expect("start");

        // Wait for initial reconcile.
        for _ in 0..40 {
            if provider.list().await.unwrap().len() == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(provider.list().await.unwrap().len(), 2);

        // Drop t2 from desired; reconcile must converge.
        tx.send(vec![cfg("t1")]).expect("send");
        for _ in 0..40 {
            if provider.list().await.unwrap() == vec!["t1".to_owned()] {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(provider.list().await.unwrap(), vec!["t1".to_owned()]);

        trigger.fire();
        handle.await.expect("join").expect("clean shutdown");
        drop(tx);
    }

    #[tokio::test]
    async fn reconcile_is_idempotent_when_desired_matches_active() {
        let (tx, rx) = watch::channel(vec![cfg("t1")]);
        let provider = Arc::new(InMemoryTunnelProvider::new());
        let subsys = PalTunnelSubsystem::new(
            &TunnelCadenceConfig {
                reconcile_interval: Duration::from_millis(10),
            },
            provider.clone(),
            rx,
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = subsys.start(signal).await.expect("start");

        // Wait until at least 3 reconcile cycles have run.
        let stats = subsys.stats();
        for _ in 0..100 {
            if stats.reconciles.load(Ordering::Relaxed) >= 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Exactly one start; subsequent reconciles must be
        // no-ops.
        assert_eq!(stats.starts_ok.load(Ordering::Relaxed), 1);
        assert_eq!(stats.stops_ok.load(Ordering::Relaxed), 0);
        assert_eq!(stats.starts_failed.load(Ordering::Relaxed), 0);

        trigger.fire();
        handle.await.expect("join").expect("clean shutdown");
        drop(tx);
    }
}

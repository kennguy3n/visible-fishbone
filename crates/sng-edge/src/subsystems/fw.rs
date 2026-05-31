// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Firewall (L3/L4 + L7) subsystem adapter.
//!
//! Wraps [`sng_fw::FirewallEngine`] driving a
//! [`sng_fw::ShellNftables`] backend. The subsystem's
//! background task is the install loop: the policy puller
//! delivers compiled rulesets through a `tokio::sync::watch`
//! channel, and the install task drains them in order,
//! `await`ing the kernel apply (via
//! [`FirewallEngine::install`]) for each one.
//!
//! Like the DNS subsystem, the source of compiled rulesets
//! (the control-plane policy bundle) is wired through the
//! comms / policy_eval subsystems — at this PR's scope the
//! ruleset channel is held by the FW subsystem as a
//! [`tokio::sync::watch::Sender`] that other subsystems hand
//! new rulesets through. The supervisor's startup does NOT
//! install a default ruleset — the engine boots with `None`,
//! which the engine's own evaluate path treats as fail-closed
//! (every packet denied).

use crate::config::FwConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_fw::{CompiledRuleSet, FirewallEngine, NftablesBackend, ShellNftables};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::watch;
use tokio::task;

/// Edge-tier firewall subsystem.
pub struct FwSubsystem {
    engine: Arc<FirewallEngine>,
    rx: watch::Receiver<Option<Arc<CompiledRuleSet>>>,
    /// Holds the producer half so the subsystem outlives the
    /// last external sender — without this, the watch channel
    /// would close once the last operator-held sender is
    /// dropped and the install loop would exit early.
    tx_anchor: watch::Sender<Option<Arc<CompiledRuleSet>>>,
    installs_total: Arc<AtomicU64>,
    install_failures: Arc<AtomicU64>,
}

impl std::fmt::Debug for FwSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FwSubsystem")
            .field(
                "installs_total",
                &self.installs_total.load(Ordering::Relaxed),
            )
            .field(
                "install_failures",
                &self.install_failures.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl FwSubsystem {
    /// Build a subsystem with a [`ShellNftables`] backend
    /// honouring the operator-supplied `nft` binary override.
    /// The watch channel starts with `None` (no ruleset
    /// installed); the policy puller pushes the first ruleset
    /// once it lands the first bundle.
    #[must_use]
    pub fn new(cfg: &FwConfig) -> Self {
        let backend: Arc<dyn NftablesBackend> = match &cfg.nft_binary {
            Some(p) => Arc::new(ShellNftables::with_binary(p.to_string_lossy().into_owned())),
            None => Arc::new(ShellNftables::new()),
        };
        Self::with_backend(backend)
    }

    /// Build with an explicit backend. Used by the integration
    /// tests so they can drive a [`sng_fw::MockNftables`] (or
    /// the in-memory test double the FW crate ships).
    #[must_use]
    pub fn with_backend(backend: Arc<dyn NftablesBackend>) -> Self {
        let (tx, rx) = watch::channel(None);
        let engine = Arc::new(FirewallEngine::new(backend));
        Self {
            engine,
            rx,
            tx_anchor: tx,
            installs_total: Arc::new(AtomicU64::new(0)),
            install_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Borrow the engine. Used by other subsystems (e.g. the
    /// firewall-RPC handler in the comms adapter) for
    /// per-packet evaluation.
    #[must_use]
    pub fn engine(&self) -> &Arc<FirewallEngine> {
        &self.engine
    }

    /// Producer half of the ruleset channel. Hand the result to
    /// any subsystem that produces compiled rulesets (the
    /// policy puller, integration tests).
    #[must_use]
    pub fn ruleset_sender(&self) -> watch::Sender<Option<Arc<CompiledRuleSet>>> {
        self.tx_anchor.clone()
    }
}

#[async_trait]
impl Subsystem for FwSubsystem {
    fn name(&self) -> &'static str {
        "fw"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let engine = Arc::clone(&self.engine);
        let mut rx = self.rx.clone();
        let installs_total = Arc::clone(&self.installs_total);
        let install_failures = Arc::clone(&self.install_failures);
        Ok(task::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    res = rx.changed() => {
                        if res.is_err() {
                            // All senders dropped — channel
                            // closed. The supervisor will see
                            // this as an early exit and drain
                            // every other subsystem, which is
                            // the correct semantics.
                            break;
                        }
                        let next = rx.borrow_and_update().clone();
                        let Some(ruleset) = next else { continue };
                        let ruleset = Arc::try_unwrap(ruleset).unwrap_or_else(|arc| (*arc).clone());
                        match engine.install(ruleset).await {
                            Ok(()) => {
                                installs_total.fetch_add(1, Ordering::Relaxed);
                                tracing::info!(
                                    target: "sng_edge::fw",
                                    "firewall ruleset installed"
                                );
                            }
                            Err(e) => {
                                install_failures.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(
                                    target: "sng_edge::fw",
                                    error = %e,
                                    "firewall ruleset install failed"
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
impl HealthCheck for FwSubsystem {
    fn name(&self) -> &'static str {
        "fw"
    }

    async fn check(&self) -> SubsystemHealth {
        let installs = self.installs_total.load(Ordering::Relaxed);
        let failures = self.install_failures.load(Ordering::Relaxed);
        let has_ruleset = self.engine.current_ruleset().is_some();
        let status = if failures > 0 && installs == 0 {
            HealthStatus::Down
        } else if failures > 0 || !has_ruleset {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "installs={installs}, failures={failures}, has_ruleset={has_ruleset}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use sng_fw::MockNftables;
    use std::time::Duration;

    #[tokio::test]
    async fn subsystem_idles_and_drains_cleanly() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let sub = FwSubsystem::with_backend(backend);
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        let res = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("drain budget");
        assert!(res.expect("join").is_ok());
    }

    #[tokio::test]
    async fn health_is_degraded_before_first_install() {
        let backend: Arc<dyn NftablesBackend> = Arc::new(MockNftables::new());
        let sub = FwSubsystem::with_backend(backend);
        let h = sub.check().await;
        // No ruleset installed yet — degraded (operator's
        // signal that the policy puller hasn't delivered).
        assert_eq!(h.status, HealthStatus::Degraded);
    }
}

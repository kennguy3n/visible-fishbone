// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! ZTNA continuous re-evaluation subsystem adapter.
//!
//! Where [`super::ztna::ZtnaSubsystem`] owns the *synchronous*
//! [`sng_ztna::ZtnaService`] that decides access once, at the
//! moment a session opens, this adapter owns the *continuous* half
//! — the [`sng_ztna::ReevalLoop`] that periodically re-runs that
//! same evaluator over every live session in a
//! [`sng_ztna::SessionTracker`] and tears down the ones whose
//! verdict has flipped to deny (posture decayed, MFA lapsed, device
//! / user revoked, app de-listed).
//!
//! The two subsystems deliberately **share one
//! [`sng_ztna::ZtnaService`]** (passed in at construction): the loop
//! never re-implements the access decision, it re-uses
//! [`sng_ztna::ZtnaService::evaluate_for_reeval`] verbatim, so a
//! tracked grant can never keep access alive that a fresh request
//! would now deny.
//!
//! # Default-off
//!
//! The whole surface is **default-off** (`ztna.reeval_enabled =
//! false`), mirroring [`super::extauthz::ExtAuthzSubsystem`]. Until
//! an operator opts in, the subsystem idles on `shutdown.wait()`:
//! the sweep never spawns, the session tracker is never walked, and
//! the appliance behaves byte-for-byte as it did before the loop was
//! wired in.
//!
//! # Cadence
//!
//! When enabled, the cadence follows the control-plane bundle's
//! [`sng_ztna::ZtnaPolicy::reeval_interval_ms`] (re-read live each
//! cycle so a bundle reload retunes it without a restart) unless the
//! operator pins an edge-local override via `ztna.reeval_interval_ms
//! > 0`.
//!
//! # Session tracker ownership
//!
//! The adapter owns the [`sng_ztna::SessionTracker`] the loop
//! sweeps and exposes it via [`ZtnaReevalSubsystem::tracker`] so the
//! producer that opens ZTNA sessions records its
//! [`sng_ztna::AccessGrant`]s against the very store the loop
//! re-evaluates. Wiring that producer is a separate concern; with no
//! producer yet the tracker is simply empty and each sweep is a
//! no-op.

use crate::config::ZtnaConfig;
use async_trait::async_trait;
use parking_lot::Mutex;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_ztna::{ReevalLoop, SessionRevoked, SessionTracker, ZtnaService};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio::task;

/// Capacity of the revocation event channel between the sweep and
/// the drain. Generous so a burst of revocations on a single sweep
/// (e.g. a whole tenant's devices failing posture at once) is
/// buffered rather than dropped; a saturated channel only degrades
/// observability — the session is still removed from the tracker.
const REVOCATION_CHANNEL_CAPACITY: usize = 1024;

/// Edge-tier ZTNA continuous re-evaluation subsystem.
pub struct ZtnaReevalSubsystem {
    /// Master gate. When false the subsystem idles and never spawns
    /// the loop.
    enabled: bool,
    /// Fixed cadence override. `None` => follow the policy bundle's
    /// `reeval_interval_ms` live; `Some(d)` => sweep every `d`.
    interval: Option<Duration>,
    /// The loop, sharing the access-path service + the tracker below.
    reeval_loop: ReevalLoop,
    /// The session store the loop sweeps. Exposed so a producer can
    /// record grants against the same tracker.
    tracker: Arc<SessionTracker>,
    /// Consumer half of the revocation channel, taken by the first
    /// `start` call. Behind a `Mutex<Option<…>>` because `start`
    /// takes `&self` but must move the receiver into its task.
    revoked_rx: Mutex<Option<mpsc::Receiver<SessionRevoked>>>,
}

impl std::fmt::Debug for ZtnaReevalSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZtnaReevalSubsystem")
            .field("enabled", &self.enabled)
            .field("interval", &self.interval)
            .field("tracked_sessions", &self.tracker.len())
            .finish_non_exhaustive()
    }
}

impl ZtnaReevalSubsystem {
    /// Build the subsystem over the shared `service` (the same
    /// [`ZtnaService`] the [`super::ztna::ZtnaSubsystem`] evaluates
    /// against) and the `ztna` config slice. When
    /// `cfg.reeval_enabled` is false the subsystem is inert.
    #[must_use]
    pub fn new(service: Arc<ZtnaService>, cfg: &ZtnaConfig) -> Self {
        let tracker = Arc::new(SessionTracker::new());
        let (revoked_tx, revoked_rx) = mpsc::channel(REVOCATION_CHANNEL_CAPACITY);
        // The producer stamps wall-clock millis on its access
        // requests, so the loop measures freshness against the same
        // base via the system clock.
        let reeval_loop = ReevalLoop::with_system_clock(service, Arc::clone(&tracker), revoked_tx);
        let interval =
            (cfg.reeval_interval_ms > 0).then(|| Duration::from_millis(cfg.reeval_interval_ms));
        Self {
            enabled: cfg.reeval_enabled,
            interval,
            reeval_loop,
            tracker,
            revoked_rx: Mutex::new(Some(revoked_rx)),
        }
    }

    /// The session tracker the loop sweeps. The producer that opens
    /// ZTNA sessions records / removes its grants here so the loop
    /// re-evaluates exactly the live sessions.
    #[must_use]
    pub fn tracker(&self) -> &Arc<SessionTracker> {
        &self.tracker
    }

    /// The re-evaluation loop. Exposed so the posture-push path can
    /// call [`ReevalLoop::reevaluate_device`] out of cycle without
    /// waiting for the next sweep.
    ///
    /// Only meaningful once [`Self::is_enabled`] is true. A disabled
    /// subsystem is fully inert: its `start` consumes and drops the
    /// revocation receiver, so the `SessionRevoked` channel is closed
    /// for the process lifetime. Driving `reevaluate_device` against a
    /// disabled loop would still remove the session from the tracker,
    /// but the revocation event has nowhere to go (it is counted as a
    /// drop in the sweep stats). Gate on [`Self::is_enabled`] before
    /// using this accessor.
    #[must_use]
    pub fn reeval_loop(&self) -> &ReevalLoop {
        &self.reeval_loop
    }

    /// Whether continuous re-evaluation is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Record a revoked session on the tracing trail. Lifting these
/// onto the shared telemetry pipeline (via the same mechanism the
/// access path uses) is a follow-up, mirroring the ext-authz
/// adapter's logging-only first slice; logging keeps the revocation
/// stream observable without a half-built pipeline hook.
fn log_revocation(ev: &SessionRevoked) {
    tracing::info!(
        target: "sng_edge::ztna_reeval",
        session = %ev.session_id,
        tenant = %ev.tenant_id,
        app = %ev.app_id,
        device = %ev.device_id,
        user = %ev.user_id,
        reason = ?ev.reason,
        revoked_at_ms = ev.revoked_at_ms,
        "ztna session revoked by continuous re-evaluation"
    );
}

#[async_trait]
impl Subsystem for ZtnaReevalSubsystem {
    fn name(&self) -> &'static str {
        "ztna_reeval"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let enabled = self.enabled;
        let interval = self.interval;
        let reeval_loop = self.reeval_loop.clone();
        let revoked_rx = self.revoked_rx.lock().take();
        Ok(task::spawn(async move {
            // Disabled: idle until shutdown so the supervisor sees a
            // well-behaved subsystem and behaviour is unchanged.
            if !enabled {
                shutdown.wait().await;
                return Ok(());
            }

            // Bridge the `ShutdownSignal` onto the
            // `watch::Receiver<bool>` the loop's run API consumes.
            // `ShutdownSignal` is watch-backed internally but does
            // not expose its receiver, so we forward the signal.
            let (stop_tx, stop_rx) = watch::channel(false);
            let shutdown_for_stop = shutdown.clone();
            let stop_bridge = task::spawn(async move {
                shutdown_for_stop.wait().await;
                let _ = stop_tx.send(true);
            });

            // The receiver is taken exactly once. `Supervisor::run`
            // starts each subsystem a single time, so this is always
            // `Some` on the live path; guard the hypothetical second
            // start (e.g. a future restart-in-place) loudly rather
            // than silently running the sweep with no drain, which
            // would let revocations back up in the channel.
            if revoked_rx.is_none() {
                tracing::warn!(
                    target: "sng_edge::ztna_reeval",
                    "revocation receiver already consumed by a prior start; \
                     revocation events will not be observed this run"
                );
            }

            // Drain the revocation stream concurrently so the channel
            // stays clear while the loop sweeps. A saturated channel
            // would only drop events (counted in the sweep's stats),
            // never block the sweep or affect safety.
            let drain = revoked_rx.map(|mut rx| {
                let shutdown_for_drain = shutdown.clone();
                task::spawn(async move {
                    loop {
                        tokio::select! {
                            // Poll shutdown first so a steady stream of
                            // revocations can never starve the exit
                            // branch, matching the `biased;` discipline
                            // of the telemetry bridge in `supervisor`.
                            biased;
                            () = shutdown_for_drain.wait() => break,
                            ev = rx.recv() => match ev {
                                Some(ev) => log_revocation(&ev),
                                None => break,
                            },
                        }
                    }
                    // Best-effort flush of anything buffered at the
                    // moment shutdown fired.
                    while let Ok(ev) = rx.try_recv() {
                        log_revocation(&ev);
                    }
                })
            });

            tracing::info!(
                target: "sng_edge::ztna_reeval",
                cadence = ?interval,
                "ztna continuous re-evaluation loop starting"
            );
            // Drive the (well-tested) loop until shutdown. A fixed
            // interval override pins the cadence; otherwise the loop
            // follows the live policy snapshot.
            match interval {
                Some(d) => reeval_loop.run_with_interval(stop_rx, d).await,
                None => reeval_loop.run(stop_rx).await,
            }

            // The loop has exited (shutdown fired). Join the helpers.
            let _ = stop_bridge.await;
            if let Some(drain) = drain {
                let _ = drain.await;
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for ZtnaReevalSubsystem {
    fn name(&self) -> &'static str {
        "ztna_reeval"
    }

    async fn check(&self) -> SubsystemHealth {
        let name = <Self as HealthCheck>::name(self).into();
        if !self.enabled {
            return SubsystemHealth {
                name,
                status: HealthStatus::Up,
                detail: Some("enabled=false".into()),
            };
        }
        let cadence = match self.interval {
            Some(d) => format!("cadence=fixed:{}ms", d.as_millis()),
            None => "cadence=policy".to_owned(),
        };
        SubsystemHealth {
            name,
            status: HealthStatus::Up,
            detail: Some(format!(
                "enabled=true, {cadence}, tracked_sessions={}",
                self.tracker.len()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use sng_telemetry::TelemetryEvent;
    use sng_ztna::{AccessGrant, AccessRequest, ZtnaServiceBuilder};

    const TENANT: &str = "t1";
    const NOW_MS: u64 = 1_000_000;

    /// A service with empty providers. Its app catalog is empty, so
    /// a re-evaluation of any session denies (`unknown_app`) — handy
    /// for asserting whether the loop swept: a swept session is
    /// revoked, an un-swept one survives.
    fn empty_service() -> Arc<ZtnaService> {
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(16);
        Arc::new(ZtnaServiceBuilder::new().build(tx))
    }

    fn record_session(sub: &ZtnaReevalSubsystem, session: &str) {
        let req = AccessRequest::new("wiki", "dev-1", "alice", NOW_MS);
        sub.tracker()
            .record(AccessGrant::new(session, TENANT, req, NOW_MS));
        assert!(sub.tracker().contains(session));
    }

    #[test]
    fn default_config_is_disabled() {
        let sub = ZtnaReevalSubsystem::new(empty_service(), &ZtnaConfig::default());
        assert!(!sub.is_enabled());
        assert!(sub.interval.is_none());
    }

    #[test]
    fn zero_interval_means_follow_policy() {
        let cfg = ZtnaConfig {
            reeval_enabled: true,
            reeval_interval_ms: 0,
            ..ZtnaConfig::default()
        };
        let sub = ZtnaReevalSubsystem::new(empty_service(), &cfg);
        assert!(sub.is_enabled());
        assert!(sub.interval.is_none(), "0 ms must map to policy cadence");
    }

    #[test]
    fn nonzero_interval_pins_cadence() {
        let cfg = ZtnaConfig {
            reeval_enabled: true,
            reeval_interval_ms: 250,
            ..ZtnaConfig::default()
        };
        let sub = ZtnaReevalSubsystem::new(empty_service(), &cfg);
        assert_eq!(sub.interval, Some(Duration::from_millis(250)));
    }

    #[tokio::test(start_paused = true)]
    async fn disabled_subsystem_does_not_sweep() {
        // Gating proof: a session that WOULD be revoked (empty
        // catalog => unknown app => deny) must survive when the
        // subsystem is disabled, because the loop never runs.
        let sub = ZtnaReevalSubsystem::new(empty_service(), &ZtnaConfig::default());
        record_session(&sub, "s1");

        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        // Advance well past any plausible cadence across many
        // windows; a disabled loop must never sweep, so the session
        // must survive every step.
        for _ in 0..20 {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(500)).await;
            tokio::task::yield_now().await;
            assert!(
                sub.tracker().contains("s1"),
                "disabled subsystem must not sweep the tracker"
            );
        }

        trigger.fire();
        handle.await.expect("join").expect("clean exit");

        let health = sub.check().await;
        assert_eq!(health.status, HealthStatus::Up);
        assert!(health.detail.unwrap().contains("enabled=false"));
    }

    #[tokio::test(start_paused = true)]
    async fn enabled_subsystem_drives_loop_and_revokes() {
        // Loop-is-driven proof: with the subsystem enabled and a
        // fixed cadence, the recorded session is re-evaluated and
        // revoked (empty catalog => unknown app => deny) without any
        // external sweep call.
        let cfg = ZtnaConfig {
            reeval_enabled: true,
            reeval_interval_ms: 100,
            ..ZtnaConfig::default()
        };
        let sub = ZtnaReevalSubsystem::new(empty_service(), &cfg);
        record_session(&sub, "s1");

        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");

        // Drive the paused clock forward one cadence at a time. The
        // leading yield lets the freshly-spawned loop task register
        // its sleep timer *before* we advance, so `advance` actually
        // fires it; the trailing yield lets the sweep run and revoke.
        let mut swept = false;
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::advance(Duration::from_millis(100)).await;
            tokio::task::yield_now().await;
            if !sub.tracker().contains("s1") {
                swept = true;
                break;
            }
        }
        assert!(
            swept,
            "enabled subsystem must drive the loop and revoke the session"
        );

        trigger.fire();
        handle.await.expect("join").expect("clean exit");
    }

    #[tokio::test(start_paused = true)]
    async fn enabled_with_empty_tracker_is_a_noop_until_shutdown() {
        // Enabled but with no sessions: the loop runs but every sweep
        // is a no-op, and the subsystem drains cleanly on shutdown.
        let cfg = ZtnaConfig {
            reeval_enabled: true,
            reeval_interval_ms: 50,
            ..ZtnaConfig::default()
        };
        let sub = ZtnaReevalSubsystem::new(empty_service(), &cfg);

        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        tokio::time::advance(Duration::from_millis(200)).await;
        tokio::task::yield_now().await;

        let health = sub.check().await;
        assert_eq!(health.status, HealthStatus::Up);
        let detail = health.detail.unwrap();
        assert!(detail.contains("enabled=true"));
        assert!(detail.contains("tracked_sessions=0"));

        trigger.fire();
        handle.await.expect("join").expect("clean exit");
    }
}

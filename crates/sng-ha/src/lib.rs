// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-ha` — active/passive high availability for the edge VM.
//!
//! A branch-site edge appliance is a single point of failure: if
//! the VM dies, the site loses its secure-access data plane. This
//! crate removes that SPOF by letting two `sng-edge` instances on
//! the same L2 segment run as an active/passive pair behind a
//! shared virtual IP (VIP).
//!
//! The design is a simplified RFC 5798 (VRRP) election plus three
//! supporting subsystems, each in its own module:
//!
//! * [`vrrp`] — the election. A pure, exhaustively-tested state
//!   machine ([`vrrp::VrrpInstance`]) decides who is Master; the
//!   wire lives behind [`vrrp::AdvertisementChannel`] (real
//!   multicast on `224.0.0.18`, or an in-memory test double).
//! * [`health`] — the demotion trigger. The Master continuously
//!   probes mandatory signals (data-plane interface up, control
//!   plane reachable, Suricata responsive, policy bundle loaded);
//!   if any goes red it drops its VRRP priority to 0 and hands the
//!   VIP to the healthy peer.
//! * [`state_sync`] — flow-state replication. While Master, the
//!   active streams conntrack / ZTNA / SD-WAN state to the passive
//!   over a bounded, MessagePack-framed TCP channel so a failover
//!   does not reset every live connection. The queue never blocks
//!   the active: it evicts + latches a lag flag, and the passive
//!   does a full-state pull on promotion if it fell behind.
//! * [`vip`] — address ownership. On promotion the Master adds the
//!   VIP and announces it with a gratuitous ARP; on demotion it
//!   releases it.
//!
//! [`HaController`] composes the four into a single run loop. The
//! `sng-edge` binary wraps it in a supervisor subsystem; when HA
//! is disabled the edge installs a no-op so a single-edge
//! deployment is unaffected.

// Test-only allows mirror the sister enforcement-plane crates
// (sng-sdwan / sng-fw / sng-edge) so the workspace lints stay
// consistent: `.expect("fixture")` and `panic!`-style assertions
// are idiomatic in the unit tests but `-D warnings` would
// otherwise reject the warn-level `expect_used` / `unwrap_used`.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::float_cmp
    )
)]

pub mod error;
pub mod health;
pub mod state_sync;
pub mod vip;
pub mod vrrp;

pub use error::{HaError, HaResult};
pub use health::{
    FlagProbe, HealthProbe, HealthRegistry, HealthVerdict, InterfaceUpProbe, ProbeReport,
    StaticHealthProbe,
};
pub use state_sync::{
    ConntrackEntry, SdwanPathScoreState, StateApplier, StaticStateApplier, SyncQueue,
    SyncQueueStats, SyncRecord, ZtnaSessionState, pump_from_reader, pump_to_writer,
};
pub use vip::{NoopVipManager, ShellVipManager, VipManager, VipSpec};
pub use vrrp::{
    AdvertisementChannel, MasterDown, MulticastChannel, RoleChange, Transition, VrrpAdvertisement,
    VrrpConfig, VrrpEvent, VrrpInstance, VrrpState,
};

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::{Instant, MissedTickBehavior, interval, sleep_until};

/// Default cadence at which the Master re-evaluates its health
/// probes.
pub const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(1);

/// Effectively-disabled master-down deadline used while this
/// instance is Master or in Initialize — far enough out that the
/// `select!` arm never fires spuriously, re-armed the moment the
/// instance returns to Backup.
const MASTER_DOWN_DISABLED: Duration = Duration::from_secs(3600);

/// Settings for a [`HaController`].
#[derive(Clone, Debug)]
pub struct HaSettings {
    /// VRRP election parameters.
    pub vrrp: VrrpConfig,
    /// The VIP this pair fails over.
    pub vip: VipSpec,
    /// This instance's own address, stamped into outbound
    /// advertisements for the priority tie-break.
    pub local_addr: IpAddr,
    /// How often to re-poll the health registry.
    pub health_interval: Duration,
    /// Maximum records drained from the sync queue per flush.
    pub sync_batch: usize,
}

impl HaSettings {
    /// Validate the embedded VRRP + VIP config.
    ///
    /// # Errors
    ///
    /// Propagates [`VrrpConfig::validate`] and
    /// [`VipSpec::validate`], and rejects a zero health interval.
    pub fn validate(&self) -> HaResult<()> {
        self.vrrp.validate()?;
        self.vip.validate()?;
        if self.health_interval.is_zero() {
            return Err(HaError::InvalidConfig(
                "health_interval must be non-zero".into(),
            ));
        }
        Ok(())
    }
}

/// Lock-free snapshot of controller activity for the health
/// endpoint.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct HaStatsSnapshot {
    /// Current role (see [`role_label`]).
    pub role: u8,
    /// Times this instance promoted Backup -> Master.
    pub promotions: u64,
    /// Times this instance demoted Master -> Backup.
    pub demotions: u64,
    /// Advertisements sent.
    pub advertisements_sent: u64,
    /// Advertisements received.
    pub advertisements_received: u64,
    /// Times a mandatory health probe forced a release.
    pub health_releases: u64,
}

/// Numeric role codes used in [`HaStatsSnapshot::role`].
const ROLE_INITIALIZE: u8 = 0;
const ROLE_BACKUP: u8 = 1;
const ROLE_MASTER: u8 = 2;

/// Human-readable label for a [`HaStatsSnapshot::role`] code.
#[must_use]
pub fn role_label(role: u8) -> &'static str {
    match role {
        ROLE_BACKUP => "backup",
        ROLE_MASTER => "master",
        _ => "initialize",
    }
}

fn state_to_code(state: VrrpState) -> u8 {
    match state {
        VrrpState::Initialize => ROLE_INITIALIZE,
        VrrpState::Backup => ROLE_BACKUP,
        VrrpState::Master => ROLE_MASTER,
    }
}

/// Shared, lock-free controller counters. Cloned (via `Arc`) into
/// the health probe so the supervisor reads them without touching
/// the run loop's state.
#[derive(Debug, Default)]
pub struct HaStats {
    role: AtomicU8,
    promotions: AtomicU64,
    demotions: AtomicU64,
    advertisements_sent: AtomicU64,
    advertisements_received: AtomicU64,
    health_releases: AtomicU64,
}

impl HaStats {
    fn set_role(&self, state: VrrpState) {
        self.role.store(state_to_code(state), Ordering::Release);
    }

    /// Snapshot every counter.
    #[must_use]
    pub fn snapshot(&self) -> HaStatsSnapshot {
        HaStatsSnapshot {
            role: self.role.load(Ordering::Acquire),
            promotions: self.promotions.load(Ordering::Relaxed),
            demotions: self.demotions.load(Ordering::Relaxed),
            advertisements_sent: self.advertisements_sent.load(Ordering::Relaxed),
            advertisements_received: self.advertisements_received.load(Ordering::Relaxed),
            health_releases: self.health_releases.load(Ordering::Relaxed),
        }
    }
}

/// Composes VRRP election, health probing, VIP ownership, and the
/// state-sync queue into a single failover run loop.
#[derive(Debug)]
pub struct HaController {
    settings: HaSettings,
    channel: Arc<dyn AdvertisementChannel>,
    vip: Arc<dyn VipManager>,
    health: Arc<HealthRegistry>,
    sync_queue: Arc<SyncQueue>,
    stats: Arc<HaStats>,
}

impl HaController {
    /// Build a controller.
    ///
    /// # Errors
    ///
    /// Propagates [`HaSettings::validate`].
    pub fn new(
        settings: HaSettings,
        channel: Arc<dyn AdvertisementChannel>,
        vip: Arc<dyn VipManager>,
        health: Arc<HealthRegistry>,
        sync_queue: Arc<SyncQueue>,
    ) -> HaResult<Self> {
        settings.validate()?;
        Ok(Self {
            settings,
            channel,
            vip,
            health,
            sync_queue,
            stats: Arc::new(HaStats::default()),
        })
    }

    /// Shared stats handle for the health probe.
    #[must_use]
    pub fn stats(&self) -> Arc<HaStats> {
        Arc::clone(&self.stats)
    }

    /// The sync queue the active enqueues flow state into.
    #[must_use]
    pub fn sync_queue(&self) -> Arc<SyncQueue> {
        Arc::clone(&self.sync_queue)
    }

    /// Run the failover loop until `is_shutdown()` returns `true`.
    ///
    /// The closure is the shutdown signal so the controller stays
    /// independent of `sng-core`'s `ShutdownSignal` type (the edge
    /// adapter passes a closure that polls it); tests pass a
    /// counter-based stub. The loop also returns when the closure
    /// trips, after releasing the VIP if it is currently Master.
    ///
    /// # Errors
    ///
    /// Returns the first fatal [`HaError`] from VIP management;
    /// transient channel send/recv errors are logged and the loop
    /// continues (a dropped advertisement is recovered by the next
    /// interval).
    pub async fn run<F>(&self, mut shutdown: F) -> HaResult<()>
    where
        F: ShutdownGate,
    {
        let mut vrrp = VrrpInstance::new(self.settings.vrrp.clone(), self.settings.local_addr)?;
        self.stats.set_role(vrrp.state());

        // Leaving Initialize: an address owner promotes immediately.
        let start = vrrp.start();
        self.apply_transition(&vrrp, start).await?;

        let mut adv_timer = interval(self.settings.vrrp.advertisement_interval);
        adv_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut health_timer = interval(self.settings.health_interval);
        health_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut next_master_down = Self::arm_master_down(&vrrp);

        loop {
            if shutdown.is_shutdown() {
                break;
            }
            let master_down = sleep_until(next_master_down);
            tokio::pin!(master_down);

            tokio::select! {
                () = shutdown.wait() => break,

                _ = adv_timer.tick() => {
                    let t = vrrp.handle(&VrrpEvent::AdvertisementTimer);
                    self.apply_transition(&vrrp, t).await?;
                }

                () = &mut master_down => {
                    let t = vrrp.handle(&VrrpEvent::MasterDownTimer);
                    self.apply_transition(&vrrp, t).await?;
                    next_master_down = Self::arm_master_down(&vrrp);
                }

                recv = self.channel.recv() => {
                    match recv {
                        Ok(adv) => {
                            self.stats.advertisements_received.fetch_add(1, Ordering::Relaxed);
                            let t = vrrp.handle(&VrrpEvent::Advertisement(adv));
                            let directive = t.master_down;
                            let role_changed = t.role_change.is_some();
                            self.apply_transition(&vrrp, t).await?;
                            // The state machine tells us exactly what
                            // to do with the master-down timer, so the
                            // timer decision can never disagree with the
                            // election decision (which is what made
                            // preempt mode break before):
                            //   * ResetFull — heard an acceptable Master.
                            //   * ResetSkew — Master is releasing; promote
                            //     promptly.
                            //   * Leave     — don't touch the deadline, so
                            //     a preempting Backup's timer runs out;
                            //     unless we just changed role, in which
                            //     case re-arm by the new state (a demotion
                            //     starts a fresh interval, a promotion
                            //     disables it).
                            next_master_down = match directive {
                                MasterDown::ResetSkew => Instant::now() + vrrp.skew_time(),
                                MasterDown::ResetFull => {
                                    Instant::now() + vrrp.master_down_interval()
                                }
                                MasterDown::Leave if role_changed => Self::arm_master_down(&vrrp),
                                MasterDown::Leave => next_master_down,
                            };
                        }
                        Err(e) => {
                            tracing::warn!(target: "sng_ha", error = %e, "advertisement recv failed; continuing");
                        }
                    }
                }

                _ = health_timer.tick() => {
                    if self.evaluate_health(&mut vrrp).await? {
                        // Priority was restored on a health-recovery edge;
                        // recompute the Backup master-down deadline from the
                        // now-correct (shorter) skew instead of leaving the
                        // stale priority-0 deadline in place.
                        next_master_down = Self::arm_master_down(&vrrp);
                    }
                }
            }
        }

        // Clean shutdown: relinquish the VIP if we hold it so the
        // peer can take over without waiting out the master-down
        // interval.
        if vrrp.state() == VrrpState::Master {
            self.vip.release(&self.settings.vip).await?;
            tracing::info!(target: "sng_ha", "released VIP on shutdown");
        }
        Ok(())
    }

    /// Compute the next master-down deadline: a real interval when
    /// Backup, effectively-never otherwise.
    fn arm_master_down(vrrp: &VrrpInstance) -> Instant {
        if vrrp.state() == VrrpState::Backup {
            Instant::now() + vrrp.master_down_interval()
        } else {
            Instant::now() + MASTER_DOWN_DISABLED
        }
    }

    /// Enact a [`Transition`]: send an advertisement and/or acquire
    /// / release the VIP, and update stats.
    async fn apply_transition(&self, vrrp: &VrrpInstance, t: Transition) -> HaResult<()> {
        self.stats.set_role(vrrp.state());
        if let Some(change) = t.role_change {
            match change {
                RoleChange::Promoted => {
                    self.stats.promotions.fetch_add(1, Ordering::Relaxed);
                    self.vip.acquire(&self.settings.vip).await?;
                    // If our view of synced state is incomplete, the
                    // passive-side reconciliation (full-state pull)
                    // is signalled by the latched lag flag; clear it
                    // now that we own the data plane.
                    if self.sync_queue.is_lagged() {
                        tracing::info!(
                            target: "sng_ha",
                            "promoted with lagged sync state; full-state reconciliation required"
                        );
                        self.sync_queue.reset_lagged();
                    }
                }
                RoleChange::Demoted => {
                    self.stats.demotions.fetch_add(1, Ordering::Relaxed);
                    self.vip.release(&self.settings.vip).await?;
                }
            }
        }
        if t.send_advertisement {
            self.send_advertisement(vrrp).await;
        }
        Ok(())
    }

    /// Encode and multicast this instance's current advertisement.
    /// A send failure is logged, not fatal — the next interval
    /// re-asserts.
    async fn send_advertisement(&self, vrrp: &VrrpInstance) {
        let adv = vrrp.advertisement();
        let frame = adv.encode();
        match self.channel.send(&frame).await {
            Ok(()) => {
                self.stats
                    .advertisements_sent
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                tracing::warn!(target: "sng_ha", error = %e, "advertisement send failed; continuing");
            }
        }
    }

    /// Poll the health registry and drive voluntary demotion /
    /// recovery off the result.
    ///
    /// Returns `true` when a Backup just restored its priority after a
    /// health recovery, so the caller must re-arm the master-down timer:
    /// the deadline was computed from the released (priority-0) skew, and
    /// leaving it would delay promotion by up to one advertisement
    /// interval. Re-arming recomputes it from the restored priority.
    async fn evaluate_health(&self, vrrp: &mut VrrpInstance) -> HaResult<bool> {
        let verdict = self.health.evaluate().await;
        if verdict.fit_for_master {
            let mut rearm_master_down = false;
            if vrrp.effective_priority() == vrrp::PRIORITY_RELEASE {
                // Health recovered — restore our configured
                // priority so preempt can win the role back.
                vrrp.clear_released();
                rearm_master_down = vrrp.state() == VrrpState::Backup;
                tracing::info!(target: "sng_ha", "health recovered; priority restored");
            }
            return Ok(rearm_master_down);
        }
        // A mandatory probe is red.
        if vrrp.effective_priority() != vrrp::PRIORITY_RELEASE {
            let failing = verdict.failing_mandatory();
            tracing::warn!(
                target: "sng_ha",
                failing = ?failing,
                "mandatory health probe failed; releasing VRRP priority"
            );
            self.stats.health_releases.fetch_add(1, Ordering::Relaxed);
            let t = vrrp.set_released();
            // set_released only asks to advertise (when Master); it
            // never changes role on its own, so this never acquires
            // / releases the VIP directly.
            if t.send_advertisement {
                self.send_advertisement(vrrp).await;
            }
        }
        // A release lowers priority; the master-down deadline is
        // re-armed only on the recovery edge, not here (a released
        // Master keeps the role until the peer takes over, and a
        // released Backup's deadline is already the longest possible).
        Ok(false)
    }
}

/// Abstraction over a shutdown signal so the controller does not
/// depend on `sng-core`'s concrete `ShutdownSignal`. The edge
/// adapter implements it over the real signal; tests implement it
/// over a tick counter.
pub trait ShutdownGate: Send {
    /// Resolve when shutdown has been requested.
    fn wait(&mut self) -> impl std::future::Future<Output = ()> + Send;
    /// Non-blocking check used to break before re-entering the
    /// `select!`.
    fn is_shutdown(&mut self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vrrp::AdvertisementChannel;
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::net::Ipv4Addr;
    use tokio::sync::Notify;

    /// In-memory advertisement channel that records sent frames
    /// and lets a test inject inbound advertisements.
    #[derive(Debug)]
    struct TestChannel {
        sent: Mutex<Vec<Vec<u8>>>,
        inbound: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<VrrpAdvertisement>>,
    }

    impl TestChannel {
        fn new() -> (Arc<Self>, tokio::sync::mpsc::Sender<VrrpAdvertisement>) {
            let (tx, rx) = tokio::sync::mpsc::channel(16);
            (
                Arc::new(Self {
                    sent: Mutex::new(Vec::new()),
                    inbound: tokio::sync::Mutex::new(rx),
                }),
                tx,
            )
        }
    }

    #[async_trait]
    impl AdvertisementChannel for TestChannel {
        async fn send(&self, frame: &[u8]) -> HaResult<()> {
            self.sent.lock().push(frame.to_vec());
            Ok(())
        }

        async fn recv(&self) -> HaResult<VrrpAdvertisement> {
            let mut rx = self.inbound.lock().await;
            match rx.recv().await {
                Some(a) => Ok(a),
                // No more injected adverts: park forever so the
                // select! arm never busy-loops on a closed channel.
                None => std::future::pending().await,
            }
        }
    }

    /// Shutdown gate driven by a `Notify`.
    struct NotifyGate {
        notify: Arc<Notify>,
        fired: bool,
    }

    impl ShutdownGate for NotifyGate {
        async fn wait(&mut self) {
            self.notify.notified().await;
            self.fired = true;
        }
        fn is_shutdown(&mut self) -> bool {
            self.fired
        }
    }

    fn settings(priority: u8) -> HaSettings {
        HaSettings {
            vrrp: VrrpConfig {
                virtual_router_id: 5,
                priority,
                advertisement_interval: Duration::from_millis(50),
                preempt_mode: true,
            },
            vip: VipSpec::new(IpAddr::V4(Ipv4Addr::new(192, 168, 9, 1)), 24, "eth0"),
            local_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 9, 2)),
            health_interval: Duration::from_millis(50),
            sync_batch: 64,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn backup_promotes_and_acquires_vip_when_no_master_heard() {
        let (channel, _tx) = TestChannel::new();
        let recorder = Arc::new(vip::RecordingVipManager::new());
        let registry = Arc::new(HealthRegistry::new());
        let queue = Arc::new(SyncQueue::new(16));
        let controller = HaController::new(
            settings(100),
            channel.clone(),
            recorder.clone(),
            registry,
            queue,
        )
        .expect("controller");
        let stats = controller.stats();

        let notify = Arc::new(Notify::new());
        let gate = NotifyGate {
            notify: Arc::clone(&notify),
            fired: false,
        };
        let handle = tokio::spawn(async move { controller.run(gate).await });

        // Sleeping under `start_paused` parks the test task and lets
        // the runtime auto-advance virtual time to the spawned
        // controller's earliest timer — the master-down deadline —
        // so the Backup promotes itself deterministically.
        tokio::time::sleep(Duration::from_millis(700)).await;

        notify.notify_one();
        let res = handle.await.expect("join");
        assert!(res.is_ok());

        let snap = stats.snapshot();
        assert_eq!(snap.promotions, 1, "should have promoted once");
        assert!(snap.advertisements_sent >= 1, "master should advertise");
        // VIP acquired on promotion, released on shutdown.
        let events = recorder.events();
        assert_eq!(
            events.first(),
            Some(&vip::VipEvent::Acquired(settings(100).vip))
        );
        assert_eq!(
            events.last(),
            Some(&vip::VipEvent::Released(settings(100).vip))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn higher_priority_peer_keeps_us_in_backup() {
        let (channel, tx) = TestChannel::new();
        let recorder = Arc::new(vip::RecordingVipManager::new());
        let registry = Arc::new(HealthRegistry::new());
        let queue = Arc::new(SyncQueue::new(16));
        let controller = HaController::new(
            settings(100),
            channel.clone(),
            recorder.clone(),
            registry,
            queue,
        )
        .expect("controller");
        let stats = controller.stats();

        let notify = Arc::new(Notify::new());
        let gate = NotifyGate {
            notify: Arc::clone(&notify),
            fired: false,
        };
        let handle = tokio::spawn(async move { controller.run(gate).await });

        // Feed a steady stream of higher-priority master adverts so
        // the master-down timer keeps getting reset.
        for _ in 0..10 {
            tx.send(VrrpAdvertisement {
                virtual_router_id: 5,
                priority: 200,
                advertisement_interval: Duration::from_millis(50),
                source: IpAddr::V4(Ipv4Addr::new(192, 168, 9, 3)),
            })
            .await
            .expect("send");
            tokio::time::advance(Duration::from_millis(60)).await;
        }

        notify.notify_one();
        handle.await.expect("join").expect("run ok");

        let snap = stats.snapshot();
        assert_eq!(
            snap.promotions, 0,
            "should never promote behind a higher-priority master"
        );
        assert!(recorder.events().is_empty(), "should never touch the VIP");
    }

    #[tokio::test(start_paused = true)]
    async fn higher_priority_backup_preempts_lower_priority_master() {
        // BUG-0001 regression at the controller level: a priority-200
        // Backup that keeps hearing a priority-100 Master must still
        // promote. With the old `resets_master_down_timer`, the
        // lower-priority adverts reset the timer forever and preempt
        // never happened; now the state machine returns
        // `MasterDown::Leave` so the deadline expires and we take over.
        let (channel, tx) = TestChannel::new();
        let recorder = Arc::new(vip::RecordingVipManager::new());
        let registry = Arc::new(HealthRegistry::new());
        let queue = Arc::new(SyncQueue::new(16));
        let controller = HaController::new(
            settings(200),
            channel.clone(),
            recorder.clone(),
            registry,
            queue,
        )
        .expect("controller");
        let stats = controller.stats();

        let notify = Arc::new(Notify::new());
        let gate = NotifyGate {
            notify: Arc::clone(&notify),
            fired: false,
        };
        let handle = tokio::spawn(async move { controller.run(gate).await });

        // Steady stream of *lower*-priority master adverts.
        for _ in 0..10 {
            tx.send(VrrpAdvertisement {
                virtual_router_id: 5,
                priority: 100,
                advertisement_interval: Duration::from_millis(50),
                source: IpAddr::V4(Ipv4Addr::new(192, 168, 9, 3)),
            })
            .await
            .expect("send");
            tokio::time::advance(Duration::from_millis(60)).await;
        }

        notify.notify_one();
        handle.await.expect("join").expect("run ok");

        let snap = stats.snapshot();
        assert_eq!(
            snap.promotions, 1,
            "higher-priority backup must preempt a lower-priority master"
        );
        assert_eq!(
            recorder.events().first(),
            Some(&vip::VipEvent::Acquired(settings(200).vip)),
            "preemption must acquire the VIP"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn failing_mandatory_health_probe_releases_priority() {
        let (channel, _tx) = TestChannel::new();
        let recorder = Arc::new(vip::RecordingVipManager::new());
        let probe = Arc::new(StaticHealthProbe::new("iface", true, true));
        let registry = Arc::new(HealthRegistry::new().with_probe(probe.clone()));
        let queue = Arc::new(SyncQueue::new(16));
        let controller = HaController::new(
            settings(100),
            channel.clone(),
            recorder.clone(),
            registry,
            queue,
        )
        .expect("controller");
        let stats = controller.stats();

        let notify = Arc::new(Notify::new());
        let gate = NotifyGate {
            notify: Arc::clone(&notify),
            fired: false,
        };
        let handle = tokio::spawn(async move { controller.run(gate).await });

        // Promote first (auto-advance past the master-down timer).
        tokio::time::sleep(Duration::from_millis(500)).await;
        // Now fail the mandatory probe; the next health tick releases.
        probe.set_healthy(false);
        tokio::time::sleep(Duration::from_millis(300)).await;

        notify.notify_one();
        handle.await.expect("join").expect("run ok");

        let snap = stats.snapshot();
        assert_eq!(snap.promotions, 1);
        assert!(
            snap.health_releases >= 1,
            "health failure should release priority"
        );
    }

    #[tokio::test]
    async fn health_recovery_rearms_master_down_for_released_backup() {
        // A Backup that had voluntarily released its priority computed
        // its master-down deadline from the priority-0 (full) skew. When
        // health recovers, `evaluate_health` must restore the priority
        // *and* tell the run loop to re-arm the now-stale deadline so
        // promotion is not delayed by the longer released interval.
        let (channel, _tx) = TestChannel::new();
        let recorder = Arc::new(vip::RecordingVipManager::new());
        let probe = Arc::new(StaticHealthProbe::new("iface", true, true));
        let registry = Arc::new(HealthRegistry::new().with_probe(probe.clone()));
        let queue = Arc::new(SyncQueue::new(16));
        let controller = HaController::new(settings(100), channel, recorder, registry, queue)
            .expect("controller");

        let mut vrrp =
            VrrpInstance::new(settings(100).vrrp, settings(100).local_addr).expect("vrrp");
        vrrp.start();
        assert_eq!(vrrp.state(), VrrpState::Backup);
        vrrp.set_released();
        assert_eq!(vrrp.effective_priority(), vrrp::PRIORITY_RELEASE);

        // Probe is green: recovery edge restores priority and requests a re-arm.
        let rearm = controller.evaluate_health(&mut vrrp).await.expect("health");
        assert!(rearm, "recovery on a released Backup must request a re-arm");
        assert_eq!(vrrp.effective_priority(), 100, "priority restored");

        // Idempotent: nothing changed on a second green evaluation, so no re-arm.
        let rearm_again = controller.evaluate_health(&mut vrrp).await.expect("health");
        assert!(!rearm_again, "no re-arm when priority is already restored");
    }
}

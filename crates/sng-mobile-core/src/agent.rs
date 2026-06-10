//! The mobile agent: lifecycle state machine + subsystem
//! orchestration.
//!
//! [`MobileAgent`] is the object the host application drives. It
//! owns:
//!
//! * an explicit [`LifecycleState`] machine
//!   (`Init → Enrolling → Enrolled ⇄ Connected ⇄ Suspended →
//!   Terminated`) with validated transitions, so an illegal
//!   transition is a typed error rather than undefined behaviour.
//!   Enrolment lands in `Enrolled` (control plane up, data-plane
//!   tunnel down); [`MobileAgent::connect`] brings the
//!   [`MobileTunnelProvider`] up to reach `Connected`, and
//!   [`MobileAgent::disconnect`] takes it back down;
//! * the claim-token [`Enroller`];
//! * a coalescing [`Scheduler`] that folds the policy-pull,
//!   telemetry-flush, and posture-collection timers into a single
//!   wakeup source — central to the sub-0.5%-idle-CPU budget, since
//!   three independent timers would treble the radio/scheduler
//!   wakeups; and
//! * the post-enrolment runtime subsystems
//!   ([`MobileTelemetry`], [`MobileZtnaManager`]) once transport is
//!   established.
//!
//! All control-plane I/O is performed under an explicit per-request
//! timeout drawn from [`MobileAgentConfig`], so a stalled radio
//! link can never pin a wakeup open.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use sng_ztna::{AccessRequest, ZtnaDecision};
use tracing::{debug, warn};

use sng_comms::{
    BundlePullOutcome, ControlPlaneClient, ControlPlaneConnection, DeviceIdentity, FlushOutcome,
    PolicyPuller, PolicyPullerConfig, PolicyTrustStore, build_client_config_with_webpki_roots,
};
use sng_core::BundleTarget;

use crate::auth::AuthSession;
use crate::config::MobileAgentConfig;
use crate::enrollment::{DEFAULT_DEVICE_KEY_LABEL, Enroller, EnrollmentOutcome, SecureKeyStore};
use crate::error::MobileError;
use crate::posture::{MobilePostureCollector, MobilePostureSnapshot};
use crate::telemetry::MobileTelemetry;
use crate::tunnel::{MobileTunnelProvider, TunnelConfig, TunnelStatus};
use crate::ztna::MobileZtnaManager;

/// The agent's lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Constructed, config validated, not yet enrolled.
    Init,
    /// An enrolment attempt is in flight.
    Enrolling,
    /// Enrolment complete: the control plane has issued the device
    /// its certificate chain and the control-plane subsystems
    /// (policy pulls, telemetry, ZTNA) can operate, but the
    /// data-plane tunnel is **not** up. This is the resting state of
    /// an enrolled device whose VPN is paused — distinct from
    /// [`Self::Connected`], where [`MobileTunnelProvider`] is
    /// actively carrying traffic.
    Enrolled,
    /// Enrolled **and** the data-plane tunnel is up: the
    /// [`MobileTunnelProvider`] has been started and the
    /// steady-state heartbeat loop runs here.
    Connected,
    /// Temporarily parked (app backgrounded / network lost) —
    /// the control-plane heartbeat is halted but identity is
    /// retained. The platform data-plane extension
    /// (`NEPacketTunnelProvider` / `VpnService`) keeps running on its
    /// own out-of-process, so suspension does not tear the tunnel
    /// down.
    Suspended,
    /// Shut down. Terminal: no further transitions are permitted.
    Terminated,
}

impl LifecycleState {
    /// Whether `to` is a legal successor of `self`.
    #[must_use]
    pub fn can_transition_to(self, to: LifecycleState) -> bool {
        use LifecycleState::{Connected, Enrolled, Enrolling, Init, Suspended, Terminated};
        matches!(
            (self, to),
            // Begin an enrolment attempt.
            (Init, Enrolling)
                // Enrolment succeeds into Enrolled (control plane up,
                // tunnel down) or rolls back to Init on failure.
                | (Enrolling, Enrolled | Init)
                // The data-plane tunnel comes up (connect, from
                // Enrolled) or the heartbeat resumes (from Suspended);
                // both land in Connected.
                | (Enrolled | Suspended, Connected)
                // From Connected the tunnel goes down (disconnect →
                // Enrolled) or the heartbeat parks (suspend →
                // Suspended).
                | (Connected, Enrolled | Suspended)
                // Terminate is reachable from any non-terminal state.
                | (Init | Enrolling | Enrolled | Connected | Suspended, Terminated)
        )
    }
}

/// The explicit lifecycle state machine. Kept separate from
/// [`MobileAgent`] so the transition rules are unit-testable in
/// isolation from any I/O.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentLifecycle {
    state: LifecycleState,
}

impl Default for AgentLifecycle {
    fn default() -> Self {
        Self {
            state: LifecycleState::Init,
        }
    }
}

impl AgentLifecycle {
    /// Start in [`LifecycleState::Init`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Current state.
    #[must_use]
    pub fn state(self) -> LifecycleState {
        self.state
    }

    /// Attempt a transition, returning [`MobileError::Lifecycle`]
    /// if it is not permitted from the current state.
    pub fn transition_to(&mut self, to: LifecycleState) -> Result<(), MobileError> {
        if self.state.can_transition_to(to) {
            self.state = to;
            Ok(())
        } else {
            Err(MobileError::Lifecycle(format!(
                "illegal transition {:?} -> {:?}",
                self.state, to
            )))
        }
    }
}

/// A coalesced subsystem timer task.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScheduledTask {
    /// Pull the mobile policy bundle.
    PullPolicy,
    /// Flush the telemetry spool.
    PushTelemetry,
    /// Collect a fresh posture snapshot.
    CollectPosture,
}

const SCHEDULE_SLOTS: usize = 3;

/// Factor by which every periodic interval is stretched while the
/// device reports [`PowerState::LowPower`].
///
/// On low power the agent quarters its wakeup rate — each of the
/// coalesced policy-pull / telemetry-flush / posture timers fires a
/// quarter as often — so the effective heartbeat is 4× longer. This
/// is the single biggest idle-battery lever the agent has: radio
/// wakeups dominate the mobile power budget, and the coalescing
/// [`Scheduler`] already folds the three timers into one wakeup, so
/// scaling all three intervals by the same factor cleanly stretches
/// that one wakeup rather than skewing the tasks relative to each
/// other.
pub const LOW_POWER_INTERVAL_MULTIPLIER: u32 = 4;

/// Device power state the [`Scheduler`] adapts its cadence to.
///
/// This is a *push* signal: the host app feeds it from the
/// platform's own power-state notification (iOS
/// `NSProcessInfoPowerStateDidChange` /
/// `ProcessInfo.isLowPowerModeEnabled`, Android
/// `PowerManager.ACTION_POWER_SAVE_MODE_CHANGED` /
/// `isPowerSaveMode`) via [`MobileAgent::set_power_state`]. The agent
/// never polls a battery API itself — polling would itself cost
/// wakeups — so an idle device in low-power mode incurs zero extra
/// work beyond the (now rarer) coalesced timer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PowerState {
    /// Normal power: the configured intervals are used as-is.
    #[default]
    Normal,
    /// Low power (battery saver / iOS Low Power Mode): every
    /// periodic interval is stretched by
    /// [`LOW_POWER_INTERVAL_MULTIPLIER`].
    LowPower,
}

impl PowerState {
    /// The interval multiplier this power state applies.
    #[must_use]
    pub const fn interval_multiplier(self, low_power_multiplier: u32) -> u32 {
        match self {
            Self::Normal => 1,
            Self::LowPower => low_power_multiplier,
        }
    }
}

/// Coalescing timer for the three periodic subsystem tasks.
///
/// Rather than arm three independent `tokio` intervals (and pay
/// three wakeups), the agent asks this scheduler for the single
/// next-due instant, sleeps once, then drains *every* task that has
/// come due at that instant. Time is modelled as a monotonic
/// [`Duration`] offset so the logic is deterministic and fully
/// unit-testable without a clock.
///
/// The scheduler is **power-aware**: while the device reports
/// [`PowerState::LowPower`] every interval is stretched by
/// [`LOW_POWER_INTERVAL_MULTIPLIER`], so the single coalesced wakeup
/// fires a quarter as often. The base (normal-power) intervals are
/// retained so returning to [`PowerState::Normal`] restores the
/// original cadence exactly, with no drift.
#[derive(Clone, Copy, Debug)]
pub struct Scheduler {
    tasks: [ScheduledTask; SCHEDULE_SLOTS],
    /// The configured normal-power intervals; the effective interval
    /// is this scaled by the current [`PowerState`].
    base_intervals: [Duration; SCHEDULE_SLOTS],
    next: [Duration; SCHEDULE_SLOTS],
    power: PowerState,
    low_power_multiplier: u32,
}

impl Scheduler {
    /// Build a scheduler whose first fire of each task is one
    /// (normal-power) interval after `now`. Starts in
    /// [`PowerState::Normal`] with the default
    /// [`LOW_POWER_INTERVAL_MULTIPLIER`].
    #[must_use]
    pub fn new(
        poll_interval: Duration,
        telemetry_interval: Duration,
        posture_interval: Duration,
        now: Duration,
    ) -> Self {
        let tasks = [
            ScheduledTask::PullPolicy,
            ScheduledTask::PushTelemetry,
            ScheduledTask::CollectPosture,
        ];
        let base_intervals = [poll_interval, telemetry_interval, posture_interval];
        let next = [
            now.saturating_add(poll_interval),
            now.saturating_add(telemetry_interval),
            now.saturating_add(posture_interval),
        ];
        Self {
            tasks,
            base_intervals,
            next,
            power: PowerState::Normal,
            low_power_multiplier: LOW_POWER_INTERVAL_MULTIPLIER,
        }
    }

    /// Override the low-power interval multiplier (the factor every
    /// interval is stretched by under [`PowerState::LowPower`]),
    /// returning `self` for chaining off [`Self::new`].
    ///
    /// Clamped to a floor of `1` so a misconfigured `0` cannot zero
    /// out the intervals and spin the coalesced loop; `1` simply
    /// disables stretching (low power then paces like normal).
    #[must_use]
    pub fn with_low_power_multiplier(mut self, multiplier: u32) -> Self {
        self.low_power_multiplier = multiplier.max(1);
        self
    }

    /// The effective interval of slot `i` under the current power
    /// state: the base interval scaled by the active multiplier.
    fn effective_interval(&self, i: usize) -> Duration {
        self.base_intervals[i]
            .saturating_mul(self.power.interval_multiplier(self.low_power_multiplier))
    }

    /// The current device power state.
    #[must_use]
    pub fn power_state(&self) -> PowerState {
        self.power
    }

    /// Apply a new device power `state` as of `now`, returning
    /// whether the state actually changed.
    ///
    /// On a real change every slot's next fire is recomputed
    /// `now + effective_interval`, so entering low power immediately
    /// pushes the next wakeup out to the stretched cadence (the
    /// battery win lands at once, not after the in-flight short
    /// interval elapses) and returning to normal pulls it back in.
    /// Rescheduling relative to `now` — rather than the already-armed
    /// deadline — is the same burst-free philosophy [`Self::pop_due`]
    /// documents: it never fires a catch-up burst on the transition.
    /// An unchanged state is a no-op (the armed deadlines are left
    /// untouched), so a host that re-asserts the same power state on
    /// every platform notification cannot perturb the cadence.
    pub fn set_power_state(&mut self, now: Duration, state: PowerState) -> bool {
        if state == self.power {
            return false;
        }
        self.power = state;
        for i in 0..SCHEDULE_SLOTS {
            self.next[i] = now.saturating_add(self.effective_interval(i));
        }
        true
    }

    /// Delay from `now` until the earliest next-due task
    /// (saturating at zero if one is already due).
    #[must_use]
    pub fn time_until_next(&self, now: Duration) -> Duration {
        let earliest = self.next.iter().copied().min().unwrap_or(now);
        earliest.saturating_sub(now)
    }

    /// Pop the earliest task that is due as of `now`, rescheduling
    /// it one interval out. Returns `None` when nothing is due yet.
    /// Call in a loop to drain all coalesced tasks for the instant.
    ///
    /// The next fire is computed relative to `now`, not to the missed
    /// deadline. This is deliberate: after the agent is suspended
    /// (app backgrounded, radio off) a deadline-relative reschedule
    /// would fire a catch-up burst of every overdue task the instant
    /// we resume, spiking wakeups exactly when the mobile power budget
    /// is tightest. Spacing the next fire a full interval from the
    /// resume instant trades a little long-run interval drift for
    /// steady, burst-free wakeups — the right call under the
    /// sub-0.5%-idle-CPU budget.
    pub fn pop_due(&mut self, now: Duration) -> Option<ScheduledTask> {
        let mut chosen: Option<usize> = None;
        for i in 0..SCHEDULE_SLOTS {
            if self.next[i] <= now && chosen.is_none_or(|c| self.next[i] < self.next[c]) {
                chosen = Some(i);
            }
        }
        let i = chosen?;
        self.next[i] = now.saturating_add(self.effective_interval(i));
        Some(self.tasks[i])
    }
}

/// The platform-provided dependencies the agent orchestrates. Each
/// is a trait object the iOS / Android PAL implements; the agent
/// never constructs them itself.
#[derive(Clone)]
pub struct MobileAgentDeps {
    /// Secure key store backing enrolment-key generation + signing.
    pub key_store: Arc<dyn SecureKeyStore>,
    /// OIDC session providing access tokens.
    pub auth: Arc<dyn AuthSession>,
    /// Platform posture collector.
    pub posture: Arc<dyn MobilePostureCollector>,
    /// Platform data-plane tunnel.
    pub tunnel: Arc<dyn MobileTunnelProvider>,
    /// Trusted policy-bundle signer keys (seeded by the host).
    pub policy_trust: Arc<PolicyTrustStore>,
}

impl fmt::Debug for MobileAgentDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The trait objects are not Debug; report the shape only.
        f.debug_struct("MobileAgentDeps").finish_non_exhaustive()
    }
}

/// Secret-free health snapshot for the host app / control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentHealth {
    /// Current lifecycle phase.
    pub lifecycle: LifecycleState,
    /// Whether the auth session currently holds a usable token.
    pub authenticated: bool,
    /// Number of apps currently in the allowed state.
    pub allowed_apps: usize,
    /// Device power state the steady-state loop is pacing itself to;
    /// [`PowerState::LowPower`] means the heartbeat is stretched by
    /// [`LOW_POWER_INTERVAL_MULTIPLIER`].
    pub power: PowerState,
}

/// The mobile agent core.
pub struct MobileAgent {
    config: MobileAgentConfig,
    deps: MobileAgentDeps,
    enroller: Enroller,
    lifecycle: Mutex<AgentLifecycle>,
    telemetry: Mutex<Option<MobileTelemetry>>,
    ztna: Mutex<Option<MobileZtnaManager>>,
    policy_puller: Mutex<Option<Arc<PolicyPuller>>>,
    /// Most recent posture snapshot collected by the steady-state
    /// loop, retained so the periodic sample has an observable effect
    /// (host health surface today; control-plane posture upload in a
    /// later session) instead of being collected and dropped.
    last_posture: Mutex<Option<MobilePostureSnapshot>>,
    /// Wakes the steady-state [`Self::run`] loop the instant the
    /// lifecycle leaves `Connected`, so a `suspend`/`terminate` stops
    /// work (and radio wakeups) immediately instead of after the
    /// pending coalesced sleep elapses. Also re-armed on a power-state
    /// change so the new cadence takes effect at once.
    wake: tokio::sync::Notify,
    /// Latest device power state pushed by the host. Read by the
    /// steady-state loop each cycle to pace the [`Scheduler`]; under
    /// [`PowerState::LowPower`] the heartbeat is stretched by
    /// [`LOW_POWER_INTERVAL_MULTIPLIER`].
    power: Mutex<PowerState>,
    /// Serializes the lifecycle-mutating operations that span an async
    /// tunnel call — [`Self::connect`], [`Self::disconnect`] and
    /// [`Self::wipe`] — so their check → `start`/`stop` → transition
    /// sequences cannot interleave with one another. The sync
    /// [`Self::suspend`] / [`Self::resume`] take it with `try_lock`,
    /// failing fast while such an operation is in flight rather than
    /// racing it — e.g. a `suspend` slipping between a `disconnect`'s
    /// `stop_tunnel` and its transition, which would strand a
    /// `Suspended` agent whose data plane has already been cut.
    /// [`Self::terminate`] deliberately does **not** take it: it is the
    /// unconditional kill switch and must win even mid-operation.
    control: tokio::sync::Mutex<()>,
}

impl fmt::Debug for MobileAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileAgent")
            .field("device_id", &self.config.device_id)
            .field("platform", &self.config.platform)
            .field("lifecycle", &self.lifecycle.lock().state())
            .finish_non_exhaustive()
    }
}

impl MobileAgent {
    /// Construct an agent, validating `config` up front. The agent
    /// starts in [`LifecycleState::Init`]; the host drives it
    /// forward with [`Self::enroll`].
    pub fn new(config: MobileAgentConfig, deps: MobileAgentDeps) -> Result<Self, MobileError> {
        config.validate()?;
        let enroller = Enroller::new(config.tenant_id, config.device_id, DEFAULT_DEVICE_KEY_LABEL);
        Ok(Self {
            config,
            deps,
            enroller,
            lifecycle: Mutex::new(AgentLifecycle::new()),
            telemetry: Mutex::new(None),
            ztna: Mutex::new(None),
            policy_puller: Mutex::new(None),
            last_posture: Mutex::new(None),
            wake: tokio::sync::Notify::new(),
            power: Mutex::new(PowerState::Normal),
            control: tokio::sync::Mutex::new(()),
        })
    }

    /// Current lifecycle phase.
    #[must_use]
    pub fn state(&self) -> LifecycleState {
        self.lifecycle.lock().state()
    }

    /// Secret-free health snapshot.
    #[must_use]
    pub fn health(&self) -> AgentHealth {
        let allowed_apps = self
            .ztna
            .lock()
            .as_ref()
            .map_or(0, |z| z.allowed_apps().len());
        AgentHealth {
            lifecycle: self.state(),
            authenticated: self.deps.auth.is_authenticated(),
            allowed_apps,
            power: self.power_state(),
        }
    }

    /// The device power state the agent is currently pacing itself
    /// to.
    #[must_use]
    pub fn power_state(&self) -> PowerState {
        *self.power.lock()
    }

    /// Push a new device power `state` from the host.
    ///
    /// The host wires this to the platform's power-state notification
    /// (iOS `NSProcessInfoPowerStateDidChange` /
    /// `ProcessInfo.isLowPowerModeEnabled`; Android
    /// `PowerManager.ACTION_POWER_SAVE_MODE_CHANGED` /
    /// `isPowerSaveMode`). The steady-state [`Self::run`] loop applies
    /// it to its [`Scheduler`] each cycle; setting it while the agent
    /// is `Connected` also wakes the sleeping loop so the new cadence
    /// takes effect immediately rather than after the in-flight
    /// coalesced sleep. Safe to call in any lifecycle state — it is a
    /// no-op on the cadence until the agent is `Connected` and running.
    pub fn set_power_state(&self, state: PowerState) {
        let changed = {
            let mut guard = self.power.lock();
            let changed = *guard != state;
            *guard = state;
            changed
        };
        // Only wake a loop that is actually parked on the coalesced
        // sleep, i.e. when the agent is `Connected` and `run` is live.
        // In any other state the loop is not waiting on `wake`, so
        // storing a permit would just make the next `run` burn one
        // no-op iteration — the same stale-permit discipline
        // [`Self::transition`] follows by gating on its `Suspended` /
        // `Terminated` targets. A change applied while not `Connected`
        // is not lost: `run` re-reads [`Self::power_state`] every cycle,
        // so it is picked up the moment the loop next paces the
        // scheduler.
        if changed && self.state() == LifecycleState::Connected {
            self.wake.notify_one();
        }
    }

    fn transition(&self, to: LifecycleState) -> Result<(), MobileError> {
        let mut guard = self.lifecycle.lock();
        let from = guard.state();
        let result = guard.transition_to(to);
        drop(guard);
        if result.is_ok() && from == LifecycleState::Connected && to != LifecycleState::Connected {
            // Only a transition *out of* `Connected` needs to wake a
            // sleeping `run` loop so it re-checks the loop condition at
            // once rather than finishing the pending coalesced sleep.
            // Gating on "left Connected" (rather than on the target)
            // covers every exit — disconnect → Enrolled, suspend →
            // Suspended, terminate → Terminated — while avoiding a
            // stale permit when *entering* Connected (e.g.
            // `Suspended → Connected` resume), which would otherwise
            // make the next `run` burn one no-op iteration.
            // `notify_one` stores a permit if no waiter is parked yet,
            // so an exit racing the loop's state check is still
            // delivered.
            self.wake.notify_one();
        }
        result
    }

    /// Suspend the agent (app backgrounded / network lost). Only
    /// valid from [`LifecycleState::Connected`].
    ///
    /// Returns a [`MobileError::Lifecycle`] busy error if a
    /// connect/disconnect/wipe is in flight, so a suspend can never
    /// split such an operation's check → tunnel-call → transition.
    pub fn suspend(&self) -> Result<(), MobileError> {
        let _control = self.control.try_lock().map_err(|_| {
            MobileError::Lifecycle(
                "a tunnel operation is in progress; retry suspend once it completes".into(),
            )
        })?;
        self.transition(LifecycleState::Suspended)
    }

    /// Resume the parked heartbeat, moving [`LifecycleState::Suspended`]
    /// → [`LifecycleState::Connected`].
    ///
    /// Only valid from [`LifecycleState::Suspended`]. Resuming from any
    /// other state is rejected — notably [`LifecycleState::Enrolled`],
    /// which also legally precedes `Connected` (via [`Self::connect`]):
    /// without this guard a `resume` could reach `Connected` from
    /// `Enrolled` without the data-plane tunnel ever being started,
    /// leaving the steady-state loop spinning against a down tunnel.
    ///
    /// Returns a [`MobileError::Lifecycle`] busy error while a
    /// connect/disconnect/wipe holds the control lock.
    pub fn resume(&self) -> Result<(), MobileError> {
        let _control = self.control.try_lock().map_err(|_| {
            MobileError::Lifecycle(
                "a tunnel operation is in progress; retry resume once it completes".into(),
            )
        })?;
        let state = self.state();
        if state != LifecycleState::Suspended {
            return Err(MobileError::Lifecycle(format!(
                "resume is only valid from Suspended, not {state:?}"
            )));
        }
        self.transition(LifecycleState::Connected)
    }

    /// Terminate the agent. Valid from any non-terminal state.
    ///
    /// This is the synchronous control-plane shutdown: it stops the
    /// heartbeat loop but does **not** itself tear the data-plane
    /// tunnel down (that is an async platform call). A host that owns
    /// a live tunnel should [`Self::disconnect`] first, or use
    /// [`Self::wipe`] — which cuts the data plane as part of
    /// de-enrolment — when revoking the device.
    ///
    /// Deliberately does **not** take the control lock the tunnel ops
    /// hold: terminate is the unconditional kill switch and must win
    /// even while a connect/disconnect/wipe is in flight. A `connect`
    /// racing it detects the lost transition and tears its own tunnel
    /// back down, so no data plane is leaked.
    pub fn terminate(&self) -> Result<(), MobileError> {
        self.transition(LifecycleState::Terminated)
    }

    /// Bring the data-plane tunnel up and move
    /// [`LifecycleState::Enrolled`] → [`LifecycleState::Connected`].
    ///
    /// Starts the platform [`MobileTunnelProvider`]
    /// (`NEPacketTunnelProvider` / `VpnService`) with `config` under
    /// the configured connect deadline, then — and only once the
    /// data plane is actually up — marks the agent `Connected` so the
    /// steady-state loop may run. The lifecycle is left in `Enrolled`
    /// if the tunnel fails to start, so the host can retry without
    /// losing its enrolment.
    ///
    /// # Errors
    ///
    /// * [`MobileError::Lifecycle`] if the agent is not in
    ///   [`LifecycleState::Enrolled`] (connect is only valid from a
    ///   freshly-enrolled or disconnected agent).
    /// * [`MobileError::Tunnel`] if `config` is invalid or the
    ///   platform tunnel backend rejects the start.
    /// * [`MobileError::Timeout`] if the start exceeds
    ///   [`MobileAgentConfig::connect_timeout`].
    pub async fn connect(&self, config: TunnelConfig) -> Result<(), MobileError> {
        // Serialize the whole check → start_tunnel → transition
        // sequence against every other tunnel-affecting lifecycle op so
        // they cannot interleave (and so a racing suspend/resume fails
        // fast rather than mutating the lifecycle underneath us).
        let _control = self.control.lock().await;
        // Fail fast before touching the platform backend if the
        // lifecycle does not permit a connect; the authoritative
        // guard is still the `Enrolled → Connected` transition below,
        // which closes the race where another thread moves us first.
        let state = self.state();
        if state != LifecycleState::Enrolled {
            return Err(MobileError::Lifecycle(format!(
                "connect is only valid from Enrolled, not {state:?}"
            )));
        }
        config.validate()?;
        // Start the tunnel under the connect deadline so a wedged
        // Network Extension / VpnService cannot pin the call open.
        self.deadline(self.config.connect_timeout, async {
            self.deps
                .tunnel
                .start_tunnel(config)
                .await
                .map_err(MobileError::from)
        })
        .await?;
        // Only claim `Connected` once the data plane is genuinely up.
        // If the transition now loses a race with a concurrent
        // terminate, tear the freshly-started tunnel back down rather
        // than leak an orphaned data plane the agent no longer tracks.
        if let Err(e) = self.transition(LifecycleState::Connected) {
            // Bound the compensating stop under the same deadline as the
            // start so a wedged backend cannot pin this call open while
            // we hold the control lock.
            if let Err(stop_err) = self
                .deadline(self.config.connect_timeout, async {
                    self.deps
                        .tunnel
                        .stop_tunnel()
                        .await
                        .map_err(MobileError::from)
                })
                .await
            {
                warn!(
                    error = %stop_err,
                    "failed to stop tunnel after connect lost the lifecycle race; \
                     the data plane may be left up"
                );
            }
            return Err(e);
        }
        Ok(())
    }

    /// Tear the data-plane tunnel down and move
    /// [`LifecycleState::Connected`] → [`LifecycleState::Enrolled`].
    ///
    /// The agent stays enrolled (identity + cert retained) so the
    /// host can [`Self::connect`] again without re-enrolling. The
    /// tunnel is stopped **first**; the agent only reports `Enrolled`
    /// once the data plane is down, so a teardown failure leaves the
    /// agent `Connected` and surfaces the error rather than claiming
    /// a disconnect that did not happen.
    ///
    /// # Errors
    ///
    /// * [`MobileError::Lifecycle`] if the agent is not
    ///   [`LifecycleState::Connected`].
    /// * [`MobileError::Tunnel`] if the platform backend fails to
    ///   stop the tunnel.
    pub async fn disconnect(&self) -> Result<(), MobileError> {
        // Hold the control lock across stop_tunnel → transition so a
        // concurrent suspend/resume cannot split the teardown and
        // strand a Suspended agent whose data plane is already cut.
        let _control = self.control.lock().await;
        let state = self.state();
        if state != LifecycleState::Connected {
            return Err(MobileError::Lifecycle(format!(
                "disconnect is only valid from Connected, not {state:?}"
            )));
        }
        // Bound the stop the same way connect bounds the start: a
        // wedged Network Extension / VpnService must not pin the call
        // open while we hold the control lock, which would brick every
        // later lifecycle op. On timeout the agent stays Connected and
        // the error surfaces, exactly as a stop failure already does.
        self.deadline(self.config.connect_timeout, async {
            self.deps
                .tunnel
                .stop_tunnel()
                .await
                .map_err(MobileError::from)
        })
        .await?;
        self.transition(LifecycleState::Enrolled)?;
        Ok(())
    }

    /// The platform tunnel's current observable status.
    ///
    /// A direct read-through to [`MobileTunnelProvider::status`];
    /// infallible (the provider reports [`TunnelStatus::Down`] /
    /// [`TunnelStatus::Failed`] rather than erroring) so the host can
    /// poll it for a status surface regardless of lifecycle state.
    pub async fn tunnel_status(&self) -> TunnelStatus {
        self.deps.tunnel.status().await
    }

    /// Attach the post-enrolment runtime subsystems. The host
    /// builds the steady-state mTLS transport (from the enrolment
    /// cert + secure-enclave key) and the ZTNA service, then hands
    /// the assembled telemetry + ZTNA manager here.
    pub fn attach_runtime(&self, telemetry: MobileTelemetry, ztna: MobileZtnaManager) {
        *self.telemetry.lock() = Some(telemetry);
        *self.ztna.lock() = Some(ztna);
    }

    /// Borrow the attached ZTNA manager, if the runtime has been
    /// attached.
    #[must_use]
    pub fn ztna(&self) -> Option<MobileZtnaManager> {
        self.ztna.lock().clone()
    }

    /// Evaluate a ZTNA access `request`, feeding the agent's most
    /// recent posture snapshot into the manager's fail-closed
    /// posture pre-gate.
    ///
    /// This is the production access-check entry point: it binds
    /// the freshly-collected device posture (from the steady-state
    /// loop / [`Self::collect_posture`]) to every evaluation, so a
    /// device that has become compromised or unlocked is cut off
    /// locally without waiting for its server-side attestation to
    /// age out. A `None` snapshot (no posture collected yet) is
    /// itself a fail-closed deny inside the pre-gate.
    ///
    /// # Errors
    ///
    /// [`MobileError::Lifecycle`] if the post-enrolment runtime has
    /// not been attached yet (no ZTNA manager), or the manager's
    /// own [`MobileError`] for a provider miss.
    pub async fn check_access(
        &self,
        request: &AccessRequest,
        now: DateTime<Utc>,
    ) -> Result<ZtnaDecision, MobileError> {
        let ztna = self
            .ztna()
            .ok_or_else(|| MobileError::Lifecycle("ZTNA runtime not attached".to_owned()))?;
        let posture = self.last_posture();
        ztna.evaluate(request, posture.as_ref(), now).await
    }

    /// Build a control-plane client. `identity` is `None` for the
    /// enrolment dial (server-auth-only TLS; the device has no cert
    /// yet) and `Some` for steady-state mTLS.
    fn build_client(
        &self,
        identity: Option<&DeviceIdentity>,
    ) -> Result<ControlPlaneClient, MobileError> {
        let tls = build_client_config_with_webpki_roots(identity)
            .map_err(|e| MobileError::Comms(sng_comms::CommsError::from(e)))?;
        let server_name = ServerName::try_from(self.config.server_name()?)
            .map_err(|e| MobileError::Config(format!("invalid server name: {e}")))?;
        Ok(ControlPlaneClient::new(
            self.config.control_plane_addr()?,
            server_name,
            Arc::new(tls),
        )?)
    }

    /// Establish the server-auth-only connection used for the
    /// enrolment exchange.
    pub async fn connect_for_enrollment(&self) -> Result<ControlPlaneConnection, MobileError> {
        let client = self.build_client(None)?;
        self.deadline(self.config.connect_timeout, async move {
            client.connect().await.map_err(MobileError::from)
        })
        .await
    }

    /// Establish the steady-state mTLS connection from a device
    /// identity (built by the host from the enrolment cert + key).
    pub async fn connect_with_identity(
        &self,
        identity: &DeviceIdentity,
    ) -> Result<ControlPlaneConnection, MobileError> {
        let client = self.build_client(Some(identity))?;
        self.deadline(self.config.connect_timeout, async move {
            client.connect().await.map_err(MobileError::from)
        })
        .await
    }

    /// Run `fut` under `budget`, mapping an elapsed deadline to
    /// [`MobileError::Timeout`].
    async fn deadline<F, T>(&self, budget: Duration, fut: F) -> Result<T, MobileError>
    where
        F: std::future::Future<Output = Result<T, MobileError>>,
    {
        match tokio::time::timeout(budget, fut).await {
            Ok(res) => res,
            Err(_) => Err(MobileError::Timeout(budget)),
        }
    }

    /// Run the claim-token enrolment exchange: generate the
    /// enrolment keypair (if absent), present the public key + claim
    /// token to the control plane, and receive the device's
    /// certificate chain.
    ///
    /// Transitions `Init → Enrolling → Enrolled` on success, or
    /// back to `Init` on failure so the host can retry. Enrolment
    /// establishes the device identity (cert chain) only; the host
    /// then drives [`Self::connect`] to bring the data-plane tunnel
    /// up and reach [`LifecycleState::Connected`].
    pub async fn enroll(&self, claim_token: &str) -> Result<EnrollmentOutcome, MobileError> {
        self.transition(LifecycleState::Enrolling)?;
        match self.enroll_inner(claim_token).await {
            Ok(outcome) => {
                // The control plane has already issued the device its
                // certificate chain. If the `Enrolling → Enrolled`
                // transition now fails — only possible if we were
                // concurrently terminated mid-round-trip — we must
                // still hand the outcome back rather than drop it,
                // otherwise the server-side enrolment is orphaned (a
                // cert was minted that the client threw away). The
                // caller can persist the cert and re-drive the
                // lifecycle.
                if let Err(e) = self.transition(LifecycleState::Enrolled) {
                    warn!(
                        device_id = %outcome.device_id,
                        error = %e,
                        "enrolment succeeded but lifecycle left Enrolling (concurrent terminate?); \
                         returning the issued identity so it is not lost"
                    );
                }
                Ok(outcome)
            }
            Err(e) => {
                // Roll back so the host can retry; ignore a rollback
                // error (only possible if we were concurrently
                // terminated, which is itself a valid end state).
                let _ = self.transition(LifecycleState::Init);
                Err(e)
            }
        }
    }

    async fn enroll_inner(&self, claim_token: &str) -> Result<EnrollmentOutcome, MobileError> {
        let conn = self.connect_for_enrollment().await?;
        let outcome = self
            .enroller
            .enroll(self.deps.key_store.as_ref(), &conn, claim_token)
            .await?;
        debug!(device_id = %outcome.device_id, status = %outcome.status, "device enrolled");
        Ok(outcome)
    }

    /// Wipe the device's enrolment and move the agent to the
    /// terminal state.
    ///
    /// Cuts the data-plane tunnel, deletes the enrolment keypair
    /// from the secure store (after which the device can no longer
    /// mTLS-authenticate, so it is de-enrolled) and then transitions
    /// to [`LifecycleState::Terminated`] so the steady-state loop
    /// stops and no further work is attempted with the destroyed
    /// identity.
    ///
    /// The tunnel is stopped **first** so a revoked device stops
    /// carrying traffic immediately; this step is best-effort
    /// (a tunnel already down, or a provider that errors, must never
    /// block destroying the key) and is logged but not propagated.
    ///
    /// This is the device-local half of a leaver / revoke: the
    /// control-plane-side revocation (ZTNA revocation list) is
    /// driven separately by the operator workflow. Idempotent — the
    /// tunnel stop and key delete both tolerate an absent target and
    /// an already-terminated agent is the desired end state — so a
    /// revoke can be replayed.
    pub async fn wipe(&self) -> Result<(), MobileError> {
        // Serialize against connect/disconnect so a revoke cannot race
        // a connect bringing the tunnel back up underneath it.
        let _control = self.control.lock().await;
        // Cut the data plane before destroying the identity so a
        // revoked device stops carrying traffic at once, even if the
        // key delete or lifecycle move below runs into trouble.
        // Best-effort, but still bounded by the connect deadline so a
        // wedged backend cannot hold the control lock open forever and
        // block the key delete / later lifecycle ops.
        if let Err(e) = self
            .deadline(self.config.connect_timeout, async {
                self.deps
                    .tunnel
                    .stop_tunnel()
                    .await
                    .map_err(MobileError::from)
            })
            .await
        {
            warn!(
                error = %e,
                "wipe: tunnel stop failed; continuing de-enrolment"
            );
        }
        self.enroller.wipe(self.deps.key_store.as_ref()).await?;
        if self.state() != LifecycleState::Terminated
            && let Err(e) = self.transition(LifecycleState::Terminated)
        {
            warn!(
                error = %e,
                "wipe destroyed the enrolment key but could not move to Terminated"
            );
        }
        Ok(())
    }

    fn policy_puller(&self) -> Arc<PolicyPuller> {
        let mut guard = self.policy_puller.lock();
        if let Some(p) = guard.as_ref() {
            return Arc::clone(p);
        }
        let puller = Arc::new(PolicyPuller::new(
            PolicyPullerConfig {
                tenant_id: self.config.tenant_id,
                target: BundleTarget::Mobile,
                path_override: None,
            },
            Arc::clone(&self.deps.policy_trust),
        ));
        *guard = Some(Arc::clone(&puller));
        puller
    }

    /// Pull the mobile policy bundle once over `conn`, under the
    /// per-request timeout. Returns `true` if a fresh bundle was
    /// received, `false` on a `304 Not Modified`.
    pub async fn pull_policy(&self, conn: &ControlPlaneConnection) -> Result<bool, MobileError> {
        let puller = self.policy_puller();
        let outcome = self
            .deadline(self.config.request_timeout, async move {
                puller.pull(conn).await.map_err(MobileError::from)
            })
            .await?;
        Ok(matches!(outcome, BundlePullOutcome::Updated(_)))
    }

    /// Flush one telemetry batch over `conn`, if the runtime is
    /// attached. A no-op (returns `Ok`) before runtime attach.
    pub async fn flush_telemetry(&self, conn: &ControlPlaneConnection) -> Result<(), MobileError> {
        let telemetry = self.telemetry.lock().clone();
        if let Some(telemetry) = telemetry {
            let outcome = self
                .deadline(self.config.request_timeout, async move {
                    telemetry.flush_one(conn).await
                })
                .await?;
            // A `Transient` outcome means the control plane returned a
            // retryable (e.g. 5xx) class and the batch was re-spooled,
            // so no data is lost — the next flush cycle retries it. It
            // is not an error, but log it so a run of server-side 5xx
            // on the telemetry path is observable rather than silent.
            if let FlushOutcome::Transient { class } = outcome {
                debug!(
                    ?class,
                    "telemetry batch re-spooled after transient control-plane response; retrying next cycle"
                );
            }
        }
        Ok(())
    }

    /// Collect a fresh posture snapshot from the PAL.
    pub async fn collect_posture(&self) -> Result<MobilePostureSnapshot, MobileError> {
        Ok(self.deps.posture.collect().await?)
    }

    /// The most recent posture snapshot collected by the steady-state
    /// loop, if one has been taken since enrolment.
    #[must_use]
    pub fn last_posture(&self) -> Option<MobilePostureSnapshot> {
        self.last_posture.lock().clone()
    }

    /// Execute a single due subsystem task over `conn`. The
    /// steady-state loop ([`Self::run`]) calls this; exposed so a
    /// host with its own scheduler can drive the agent directly.
    pub async fn run_task(
        &self,
        task: ScheduledTask,
        conn: &ControlPlaneConnection,
    ) -> Result<(), MobileError> {
        match task {
            ScheduledTask::PullPolicy => {
                self.pull_policy(conn).await?;
            }
            ScheduledTask::PushTelemetry => {
                self.flush_telemetry(conn).await?;
            }
            ScheduledTask::CollectPosture => {
                let snapshot = self.collect_posture().await?;
                *self.last_posture.lock() = Some(snapshot);
            }
        }
        Ok(())
    }

    /// Steady-state loop: coalesce the subsystem timers, sleep once
    /// per cycle, and drain every task that has come due. Runs until
    /// the agent leaves [`LifecycleState::Connected`] (suspended or
    /// terminated). A per-task error that is retryable is logged and
    /// the loop continues; a permanent error on a transport-bound task
    /// (policy pull / telemetry flush) stops the loop and is returned.
    /// A posture-collection failure is always non-fatal — it is a
    /// periodic best-effort device sample and must never tear down
    /// policy enforcement + telemetry — so it is logged and the loop
    /// continues regardless of the error's retryability.
    pub async fn run(&self, conn: &ControlPlaneConnection) -> Result<(), MobileError> {
        let start = tokio::time::Instant::now();
        let mut scheduler = Scheduler::new(
            self.config.poll_interval,
            self.config.telemetry_interval,
            self.config.posture_interval,
            Duration::ZERO,
        )
        .with_low_power_multiplier(self.config.low_power_multiplier);
        while self.state() == LifecycleState::Connected {
            let now = start.elapsed();
            // Pace the coalesced timer to the latest pushed power
            // state before arming this cycle's sleep. A no-op while the
            // state is unchanged; on a transition it re-arms every slot
            // to the stretched / normal cadence as of `now`.
            scheduler.set_power_state(now, self.power_state());
            let sleep_for = scheduler.time_until_next(now);
            tokio::select! {
                () = tokio::time::sleep(sleep_for) => {}
                () = self.wake.notified() => {
                    // A lifecycle transition (suspend / terminate) or a
                    // power-state change landed: re-check the loop
                    // condition and re-pace the scheduler immediately,
                    // skipping this cycle's task drain. On suspend /
                    // terminate the loop then exits; on a power change
                    // it re-arms the cadence without firing a burst.
                    continue;
                }
            }
            let now = start.elapsed();
            while let Some(task) = scheduler.pop_due(now) {
                if let Err(e) = self.run_task(task, conn).await {
                    if task == ScheduledTask::CollectPosture {
                        warn!(?task, error = %e, "posture collection failed; continuing");
                    } else if e.is_retryable() {
                        warn!(?task, error = %e, "retryable subsystem error; continuing");
                    } else {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn lifecycle_happy_path() {
        let mut lc = AgentLifecycle::new();
        assert_eq!(lc.state(), LifecycleState::Init);
        lc.transition_to(LifecycleState::Enrolling).unwrap();
        // Enrolment lands in Enrolled (control plane up, tunnel down).
        lc.transition_to(LifecycleState::Enrolled).unwrap();
        // connect() brings the data-plane tunnel up.
        lc.transition_to(LifecycleState::Connected).unwrap();
        // Background / resume around the live tunnel.
        lc.transition_to(LifecycleState::Suspended).unwrap();
        lc.transition_to(LifecycleState::Connected).unwrap();
        // disconnect() drops back to Enrolled without de-enrolling.
        lc.transition_to(LifecycleState::Enrolled).unwrap();
        lc.transition_to(LifecycleState::Terminated).unwrap();
        assert_eq!(lc.state(), LifecycleState::Terminated);
    }

    #[test]
    fn enrollment_can_roll_back_to_init() {
        let mut lc = AgentLifecycle::new();
        lc.transition_to(LifecycleState::Enrolling).unwrap();
        lc.transition_to(LifecycleState::Init).unwrap();
        assert_eq!(lc.state(), LifecycleState::Init);
    }

    #[test]
    fn illegal_transitions_are_rejected() {
        let mut lc = AgentLifecycle::new();
        // Cannot connect straight from Init.
        assert!(lc.transition_to(LifecycleState::Connected).is_err());
        // Cannot reach Enrolled without enrolling first.
        assert!(lc.transition_to(LifecycleState::Enrolled).is_err());
        // Cannot suspend from Init.
        assert!(lc.transition_to(LifecycleState::Suspended).is_err());
        // Enrolment cannot skip straight past Enrolled to Connected.
        lc.transition_to(LifecycleState::Enrolling).unwrap();
        assert!(lc.transition_to(LifecycleState::Connected).is_err());
        // Nor can it suspend from Enrolled (the tunnel is not up yet).
        lc.transition_to(LifecycleState::Enrolled).unwrap();
        assert!(lc.transition_to(LifecycleState::Suspended).is_err());
    }

    #[test]
    fn terminated_is_terminal() {
        let mut lc = AgentLifecycle::new();
        lc.transition_to(LifecycleState::Terminated).unwrap();
        for to in [
            LifecycleState::Init,
            LifecycleState::Enrolling,
            LifecycleState::Enrolled,
            LifecycleState::Connected,
            LifecycleState::Suspended,
        ] {
            assert!(lc.transition_to(to).is_err());
        }
    }

    #[test]
    fn scheduler_reports_earliest_delay() {
        let s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(10));
        let mut s = s;
        assert_eq!(s.pop_due(Duration::ZERO), None);
    }

    #[test]
    fn scheduler_pops_and_reschedules() {
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        assert_eq!(
            s.pop_due(Duration::from_secs(10)),
            Some(ScheduledTask::PullPolicy)
        );
        // PullPolicy now next at 20s; nothing else due at 10s.
        assert_eq!(s.pop_due(Duration::from_secs(10)), None);
    }

    #[test]
    fn scheduler_coalesces_simultaneously_due_tasks() {
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        // At 60s all three are due (60 is a multiple of 10/20/30).
        let now = Duration::from_secs(60);
        let mut drained = Vec::new();
        while let Some(task) = s.pop_due(now) {
            drained.push(task);
        }
        assert_eq!(
            drained,
            vec![
                ScheduledTask::PullPolicy,
                ScheduledTask::PushTelemetry,
                ScheduledTask::CollectPosture
            ]
        );
    }

    #[test]
    fn scheduler_starts_in_normal_power() {
        let s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        assert_eq!(s.power_state(), PowerState::Normal);
    }

    #[test]
    fn low_power_stretches_every_interval_by_the_multiplier() {
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        // Enter low power at t=0: each slot re-arms to 4× its base.
        assert!(s.set_power_state(Duration::ZERO, PowerState::LowPower));
        assert_eq!(s.power_state(), PowerState::LowPower);
        // Earliest is now the policy pull at 4×10s = 40s, not 10s.
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(40));
        // Nothing fires at the old 10s deadline.
        assert_eq!(s.pop_due(Duration::from_secs(10)), None);
        // Policy pull fires at 40s and re-arms a further 40s out.
        assert_eq!(
            s.pop_due(Duration::from_secs(40)),
            Some(ScheduledTask::PullPolicy)
        );
        assert_eq!(s.pop_due(Duration::from_secs(40)), None);
        assert_eq!(
            s.pop_due(Duration::from_secs(80)),
            Some(ScheduledTask::PullPolicy)
        );
    }

    #[test]
    fn with_low_power_multiplier_overrides_the_default_stretch() {
        // A deployment-configured multiplier (here 2×) replaces the
        // default 4× while leaving the normal cadence untouched.
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        )
        .with_low_power_multiplier(2);
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(10));
        assert!(s.set_power_state(Duration::ZERO, PowerState::LowPower));
        // Policy pull now stretches to 2×10s = 20s, not the default 40s.
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(20));
    }

    #[test]
    fn with_low_power_multiplier_clamps_zero_to_one() {
        // A degenerate 0 must not zero out the intervals (which would
        // spin the coalesced loop); it clamps to 1, i.e. no stretch.
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        )
        .with_low_power_multiplier(0);
        assert!(s.set_power_state(Duration::ZERO, PowerState::LowPower));
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(10));
    }

    #[test]
    fn set_power_state_is_noop_when_unchanged() {
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        // Re-asserting Normal must not perturb the armed deadlines.
        assert!(!s.set_power_state(Duration::from_secs(5), PowerState::Normal));
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(10));
        // First low-power assert changes state; a second identical one
        // is a no-op that leaves the stretched deadlines untouched.
        assert!(s.set_power_state(Duration::ZERO, PowerState::LowPower));
        assert!(!s.set_power_state(Duration::from_secs(7), PowerState::LowPower));
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(40));
    }

    #[test]
    fn returning_to_normal_restores_base_cadence_without_drift() {
        let mut s = Scheduler::new(
            Duration::from_secs(10),
            Duration::from_secs(20),
            Duration::from_secs(30),
            Duration::ZERO,
        );
        s.set_power_state(Duration::ZERO, PowerState::LowPower);
        assert_eq!(s.time_until_next(Duration::ZERO), Duration::from_secs(40));
        // Back to normal at t=100s: every slot re-arms to base+100.
        assert!(s.set_power_state(Duration::from_secs(100), PowerState::Normal));
        assert_eq!(s.power_state(), PowerState::Normal);
        // Earliest is the 10s base interval from t=100 → 110s.
        assert_eq!(
            s.time_until_next(Duration::from_secs(100)),
            Duration::from_secs(10)
        );
        assert_eq!(
            s.pop_due(Duration::from_secs(110)),
            Some(ScheduledTask::PullPolicy)
        );
        // And it keeps the base 10s cadence thereafter.
        assert_eq!(
            s.pop_due(Duration::from_secs(120)),
            Some(ScheduledTask::PullPolicy)
        );
    }

    #[test]
    fn power_state_multiplier_mapping() {
        assert_eq!(PowerState::Normal.interval_multiplier(4), 1);
        assert_eq!(PowerState::LowPower.interval_multiplier(4), 4);
        assert_eq!(LOW_POWER_INTERVAL_MULTIPLIER, 4);
    }

    // -- End-to-end lifecycle tests -------------------------------
    //
    // These drive a real `MobileAgent` (not just the bare
    // `AgentLifecycle`) through `Init → Enrolling → Enrolled →
    // Connected ⇄ Suspended` and out via `disconnect` / `wipe`,
    // asserting the data-plane `MobileTunnelProvider` is started and
    // stopped at exactly the right edges. The enrolment *network*
    // leg (`enroll_inner` → control-plane mTLS round-trip) needs a
    // live control plane and is exercised by the comms-layer suites;
    // here we drive the lifecycle past it via the same private
    // `transition` the real `enroll` uses, so the tunnel
    // orchestration and state machine are tested end-to-end against
    // recording PAL doubles.

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::auth::{AccessToken, AuthError, AuthSession, AuthState};
    use crate::config::{AuthConfig, MobileAgentConfig, MobilePlatform};
    use crate::enrollment::InMemorySecureKeyStore;
    use crate::posture::{MobilePostureCollector, MobilePostureSnapshot, PostureError};
    use crate::tunnel::{TUNNEL_KEY_LEN, TunnelError, TunnelPrivateKey, TunnelPublicKey};
    use sng_comms::PolicyTrustStore;
    use sng_core::{DeviceId, TenantId};

    /// Auth double: never holds a credential. The lifecycle/tunnel
    /// paths under test never touch it, so it only has to satisfy the
    /// trait.
    struct StubAuth;

    #[async_trait::async_trait]
    impl AuthSession for StubAuth {
        async fn access_token(&self) -> Result<AccessToken, AuthError> {
            Err(AuthError::Unauthenticated)
        }
        async fn refresh(&self) -> Result<(), AuthError> {
            Err(AuthError::Unauthenticated)
        }
        fn state(&self) -> AuthState {
            AuthState::Unauthenticated
        }
        fn is_authenticated(&self) -> bool {
            false
        }
    }

    /// Posture double: the heartbeat loop is never spun up in these
    /// tests, so `collect` is unreachable; report unavailable rather
    /// than fabricate a snapshot.
    struct StubPosture;

    #[async_trait::async_trait]
    impl MobilePostureCollector for StubPosture {
        async fn collect(&self) -> Result<MobilePostureSnapshot, PostureError> {
            Err(PostureError::Unavailable("stub".into()))
        }
    }

    /// Recording tunnel double: counts `start`/`stop`, can be told to
    /// fail either call, and reports a status consistent with the
    /// calls it has seen so `tunnel_status` is meaningful.
    struct RecordingTunnel {
        starts: AtomicUsize,
        stops: AtomicUsize,
        fail_start: AtomicBool,
        fail_stop: AtomicBool,
        status: Mutex<TunnelStatus>,
        /// When set, `stop_tunnel` signals `stop_entered` and parks on
        /// `stop_release`, so a test can hold a `disconnect`/`wipe`
        /// in-flight (its control lock held) and observe what races it.
        gate_stop: AtomicBool,
        stop_entered: tokio::sync::Notify,
        stop_release: tokio::sync::Notify,
    }

    impl RecordingTunnel {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                starts: AtomicUsize::new(0),
                stops: AtomicUsize::new(0),
                fail_start: AtomicBool::new(false),
                fail_stop: AtomicBool::new(false),
                status: Mutex::new(TunnelStatus::Down),
                gate_stop: AtomicBool::new(false),
                stop_entered: tokio::sync::Notify::new(),
                stop_release: tokio::sync::Notify::new(),
            })
        }
        fn starts(&self) -> usize {
            self.starts.load(Ordering::SeqCst)
        }
        fn stops(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl MobileTunnelProvider for RecordingTunnel {
        async fn start_tunnel(&self, _config: TunnelConfig) -> Result<(), TunnelError> {
            if self.fail_start.load(Ordering::SeqCst) {
                return Err(TunnelError::Backend("induced start failure".into()));
            }
            self.starts.fetch_add(1, Ordering::SeqCst);
            *self.status.lock() = TunnelStatus::Up { since: Utc::now() };
            Ok(())
        }
        async fn stop_tunnel(&self) -> Result<(), TunnelError> {
            if self.gate_stop.load(Ordering::SeqCst) {
                // Signal the call is in flight (the agent now holds its
                // control lock) and park until the test releases us.
                self.stop_entered.notify_one();
                self.stop_release.notified().await;
            }
            if self.fail_stop.load(Ordering::SeqCst) {
                return Err(TunnelError::Backend("induced stop failure".into()));
            }
            self.stops.fetch_add(1, Ordering::SeqCst);
            *self.status.lock() = TunnelStatus::Down;
            Ok(())
        }
        async fn status(&self) -> TunnelStatus {
            self.status.lock().clone()
        }
    }

    fn test_config() -> MobileAgentConfig {
        MobileAgentConfig {
            control_plane_url: "https://cp.example.com:8443".into(),
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            platform: MobilePlatform::Ios,
            device_name: "iPhone 15".into(),
            auth: AuthConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "sng-mobile".into(),
                scopes: vec!["openid".into(), "offline_access".into()],
                refresh_skew: Duration::from_secs(60),
                refresh_jitter: Duration::from_secs(30),
            },
            poll_interval: Duration::from_secs(300),
            telemetry_interval: Duration::from_secs(60),
            posture_interval: Duration::from_secs(900),
            low_power_multiplier: LOW_POWER_INTERVAL_MULTIPLIER,
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
        }
    }

    fn build_agent(tunnel: Arc<RecordingTunnel>) -> MobileAgent {
        let deps = MobileAgentDeps {
            key_store: Arc::new(InMemorySecureKeyStore::new()),
            auth: Arc::new(StubAuth),
            posture: Arc::new(StubPosture),
            tunnel,
            policy_trust: Arc::new(PolicyTrustStore::new()),
        };
        MobileAgent::new(test_config(), deps).expect("valid test config builds an agent")
    }

    fn valid_tunnel_config() -> TunnelConfig {
        TunnelConfig {
            interface_private_key: TunnelPrivateKey::from_bytes([7u8; TUNNEL_KEY_LEN]),
            peer_public_key: TunnelPublicKey::from_bytes([9u8; TUNNEL_KEY_LEN]),
            endpoint: "gw.example.com:51820".into(),
            allowed_ips: vec!["0.0.0.0/0".parse().expect("static CIDR parses")],
            dns: vec![],
            persistent_keepalive: Some(Duration::from_secs(25)),
            mtu: Some(1280),
        }
    }

    /// Move a freshly-built agent past the network enrolment leg into
    /// `Enrolled`, mirroring what a successful `enroll` would leave
    /// behind, so connect/disconnect can be exercised without a
    /// control plane.
    fn drive_to_enrolled(agent: &MobileAgent) {
        agent
            .transition(LifecycleState::Enrolling)
            .expect("Init → Enrolling");
        agent
            .transition(LifecycleState::Enrolled)
            .expect("Enrolling → Enrolled");
        assert_eq!(agent.state(), LifecycleState::Enrolled);
    }

    #[tokio::test]
    async fn full_lifecycle_init_enrolling_enrolled_connected_and_back() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));

        assert_eq!(agent.state(), LifecycleState::Init);
        drive_to_enrolled(&agent);
        // Enrolment alone must not bring the data plane up.
        assert_eq!(tunnel.starts(), 0);
        assert!(matches!(agent.tunnel_status().await, TunnelStatus::Down));

        // connect() starts the tunnel and only then reports Connected.
        agent
            .connect(valid_tunnel_config())
            .await
            .expect("connect from Enrolled");
        assert_eq!(agent.state(), LifecycleState::Connected);
        assert_eq!(tunnel.starts(), 1);
        assert!(matches!(
            agent.tunnel_status().await,
            TunnelStatus::Up { .. }
        ));

        // Suspend / resume park the heartbeat but leave the tunnel
        // (which lives out-of-process) untouched.
        agent.suspend().expect("Connected → Suspended");
        assert_eq!(agent.state(), LifecycleState::Suspended);
        agent.resume().expect("Suspended → Connected");
        assert_eq!(agent.state(), LifecycleState::Connected);
        assert_eq!(tunnel.starts(), 1, "resume must not re-start the tunnel");
        assert_eq!(tunnel.stops(), 0, "suspend must not stop the tunnel");

        // disconnect() drops the data plane and returns to Enrolled,
        // keeping the device enrolled for a later reconnect.
        agent.disconnect().await.expect("Connected → Enrolled");
        assert_eq!(agent.state(), LifecycleState::Enrolled);
        assert_eq!(tunnel.stops(), 1);
        assert!(matches!(agent.tunnel_status().await, TunnelStatus::Down));

        // A second connect proves Enrolled is a true resting state.
        agent
            .connect(valid_tunnel_config())
            .await
            .expect("reconnect from Enrolled");
        assert_eq!(agent.state(), LifecycleState::Connected);
        assert_eq!(tunnel.starts(), 2);

        agent.terminate().expect("Connected → Terminated");
        assert_eq!(agent.state(), LifecycleState::Terminated);
    }

    #[tokio::test]
    async fn connect_is_rejected_outside_enrolled() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));

        // From Init.
        let err = agent.connect(valid_tunnel_config()).await.unwrap_err();
        assert!(matches!(err, MobileError::Lifecycle(_)));

        // From Connected (already up).
        drive_to_enrolled(&agent);
        agent.connect(valid_tunnel_config()).await.unwrap();
        let err = agent.connect(valid_tunnel_config()).await.unwrap_err();
        assert!(matches!(err, MobileError::Lifecycle(_)));
        // Exactly one real start despite the rejected second attempt.
        assert_eq!(tunnel.starts(), 1);
    }

    #[tokio::test]
    async fn connect_with_invalid_config_does_not_start_tunnel() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);

        let mut cfg = valid_tunnel_config();
        cfg.endpoint = String::new(); // invalid: empty endpoint
        let err = agent.connect(cfg).await.unwrap_err();
        assert!(matches!(err, MobileError::Tunnel(_)));
        // Validation runs before the backend, so no start and no
        // half-open lifecycle.
        assert_eq!(tunnel.starts(), 0);
        assert_eq!(agent.state(), LifecycleState::Enrolled);
    }

    #[tokio::test]
    async fn connect_failure_leaves_agent_enrolled() {
        let tunnel = RecordingTunnel::new();
        tunnel.fail_start.store(true, Ordering::SeqCst);
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);

        let err = agent.connect(valid_tunnel_config()).await.unwrap_err();
        assert!(matches!(err, MobileError::Tunnel(_)));
        // Failed start must not claim Connected.
        assert_eq!(agent.state(), LifecycleState::Enrolled);
    }

    #[tokio::test]
    async fn disconnect_is_rejected_when_not_connected() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);

        let err = agent.disconnect().await.unwrap_err();
        assert!(matches!(err, MobileError::Lifecycle(_)));
        assert_eq!(tunnel.stops(), 0);
    }

    #[tokio::test]
    async fn disconnect_failure_keeps_agent_connected() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);
        agent.connect(valid_tunnel_config()).await.unwrap();

        tunnel.fail_stop.store(true, Ordering::SeqCst);
        let err = agent.disconnect().await.unwrap_err();
        assert!(matches!(err, MobileError::Tunnel(_)));
        // A failed teardown must not report a disconnect that did not
        // happen.
        assert_eq!(agent.state(), LifecycleState::Connected);
    }

    #[tokio::test]
    async fn wipe_cuts_the_tunnel_and_terminates() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);
        agent.connect(valid_tunnel_config()).await.unwrap();
        assert_eq!(agent.state(), LifecycleState::Connected);

        agent.wipe().await.expect("wipe from Connected");
        assert_eq!(agent.state(), LifecycleState::Terminated);
        // The data plane is cut as part of de-enrolment.
        assert_eq!(tunnel.stops(), 1);
        assert!(matches!(agent.tunnel_status().await, TunnelStatus::Down));
    }

    #[tokio::test]
    async fn wipe_tolerates_tunnel_stop_failure() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);
        agent.connect(valid_tunnel_config()).await.unwrap();

        // A best-effort tunnel stop must never block destroying the
        // identity / reaching the terminal state.
        tunnel.fail_stop.store(true, Ordering::SeqCst);
        agent
            .wipe()
            .await
            .expect("wipe completes despite stop error");
        assert_eq!(agent.state(), LifecycleState::Terminated);
    }

    #[tokio::test]
    async fn resume_is_rejected_outside_suspended() {
        let tunnel = RecordingTunnel::new();
        let agent = build_agent(Arc::clone(&tunnel));
        drive_to_enrolled(&agent);

        // Enrolled also legally precedes Connected (via connect), so a
        // resume that leaned only on the transition table could reach
        // Connected from Enrolled without ever starting the tunnel.
        let err = agent.resume().unwrap_err();
        assert!(matches!(err, MobileError::Lifecycle(_)));
        assert_eq!(agent.state(), LifecycleState::Enrolled);
        assert_eq!(tunnel.starts(), 0, "resume must never start the tunnel");
    }

    #[tokio::test]
    async fn disconnect_in_flight_blocks_suspend() {
        let tunnel = RecordingTunnel::new();
        let agent = Arc::new(build_agent(Arc::clone(&tunnel)));
        drive_to_enrolled(&agent);
        agent.connect(valid_tunnel_config()).await.unwrap();
        assert_eq!(agent.state(), LifecycleState::Connected);

        // Park disconnect inside stop_tunnel while it holds the control
        // lock, modelling a slow Network Extension / VpnService stop.
        tunnel.gate_stop.store(true, Ordering::SeqCst);
        let disconnect_agent = Arc::clone(&agent);
        let disconnecting = tokio::spawn(async move { disconnect_agent.disconnect().await });
        tunnel.stop_entered.notified().await;

        // Without serialization this suspend would succeed (Connected →
        // Suspended) and strand a Suspended agent whose tunnel is about
        // to be cut. It must instead fail fast and leave state intact.
        assert!(matches!(
            agent.suspend().unwrap_err(),
            MobileError::Lifecycle(_)
        ));
        assert_eq!(agent.state(), LifecycleState::Connected);

        // Releasing the stop lets disconnect finish and reach Enrolled.
        tunnel.stop_release.notify_one();
        disconnecting
            .await
            .expect("disconnect task joins")
            .expect("disconnect completes once the backend returns");
        assert_eq!(agent.state(), LifecycleState::Enrolled);
        assert_eq!(tunnel.stops(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn wedged_stop_tunnel_times_out_and_frees_the_control_lock() {
        let tunnel = RecordingTunnel::new();
        let agent = Arc::new(build_agent(Arc::clone(&tunnel)));
        drive_to_enrolled(&agent);
        agent.connect(valid_tunnel_config()).await.unwrap();

        // Wedge stop_tunnel: it parks and is never released, modelling a
        // hung Network Extension / VpnService. Because disconnect holds
        // the control lock across the stop, an unbounded wait here would
        // brick every later lifecycle op — the connect_timeout deadline
        // must break it instead.
        tunnel.gate_stop.store(true, Ordering::SeqCst);
        let disconnect_agent = Arc::clone(&agent);
        let disconnecting = tokio::spawn(async move { disconnect_agent.disconnect().await });
        tunnel.stop_entered.notified().await;

        // Advance past the connect deadline so the bounded stop elapses.
        tokio::time::advance(test_config().connect_timeout + Duration::from_secs(1)).await;
        let err = disconnecting
            .await
            .expect("disconnect task joins")
            .expect_err("a wedged stop must surface as an error");
        assert!(matches!(err, MobileError::Timeout(_)));
        // The agent is left Connected (the stop never confirmed) and,
        // crucially, the control lock was released — so the lifecycle is
        // still usable rather than permanently wedged.
        assert_eq!(agent.state(), LifecycleState::Connected);
        agent
            .suspend()
            .expect("control lock freed after the timeout");
        assert_eq!(agent.state(), LifecycleState::Suspended);
    }
}

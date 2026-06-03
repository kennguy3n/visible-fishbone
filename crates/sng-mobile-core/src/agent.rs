//! The mobile agent: lifecycle state machine + subsystem
//! orchestration.
//!
//! [`MobileAgent`] is the object the host application drives. It
//! owns:
//!
//! * an explicit [`LifecycleState`] machine
//!   (`Init → Enrolling → Connected ⇄ Suspended → Terminated`) with
//!   validated transitions, so an illegal transition is a typed
//!   error rather than undefined behaviour;
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

use parking_lot::Mutex;
use rustls::pki_types::ServerName;
use tracing::{debug, warn};

use sng_comms::{
    BundlePullOutcome, ControlPlaneClient, ControlPlaneConnection, DeviceIdentity, PolicyPuller,
    PolicyPullerConfig, PolicyTrustStore, build_client_config_with_webpki_roots,
};
use sng_core::BundleTarget;

use crate::auth::AuthSession;
use crate::config::MobileAgentConfig;
use crate::enrollment::{DEFAULT_DEVICE_KEY_LABEL, Enroller, EnrollmentOutcome, SecureKeyStore};
use crate::error::MobileError;
use crate::posture::{MobilePostureCollector, MobilePostureSnapshot};
use crate::telemetry::MobileTelemetry;
use crate::tunnel::MobileTunnelProvider;
use crate::ztna::MobileZtnaManager;

/// The agent's lifecycle phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    /// Constructed, config validated, not yet enrolled.
    Init,
    /// An enrolment attempt is in flight.
    Enrolling,
    /// Enrolled and operating (policy pulls, telemetry, ZTNA).
    Connected,
    /// Temporarily parked (app backgrounded / network lost) —
    /// timers are halted but identity is retained.
    Suspended,
    /// Shut down. Terminal: no further transitions are permitted.
    Terminated,
}

impl LifecycleState {
    /// Whether `to` is a legal successor of `self`.
    #[must_use]
    pub fn can_transition_to(self, to: LifecycleState) -> bool {
        use LifecycleState::{Connected, Enrolling, Init, Suspended, Terminated};
        matches!(
            (self, to),
            (Init, Enrolling)
                | (Enrolling | Suspended, Connected)
                | (Enrolling, Init)
                | (Connected, Suspended)
                // Terminate is reachable from any non-terminal state.
                | (Init | Enrolling | Connected | Suspended, Terminated)
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

/// Coalescing timer for the three periodic subsystem tasks.
///
/// Rather than arm three independent `tokio` intervals (and pay
/// three wakeups), the agent asks this scheduler for the single
/// next-due instant, sleeps once, then drains *every* task that has
/// come due at that instant. Time is modelled as a monotonic
/// [`Duration`] offset so the logic is deterministic and fully
/// unit-testable without a clock.
#[derive(Clone, Copy, Debug)]
pub struct Scheduler {
    tasks: [ScheduledTask; SCHEDULE_SLOTS],
    intervals: [Duration; SCHEDULE_SLOTS],
    next: [Duration; SCHEDULE_SLOTS],
}

impl Scheduler {
    /// Build a scheduler whose first fire of each task is one
    /// interval after `now`.
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
        let intervals = [poll_interval, telemetry_interval, posture_interval];
        let next = [
            now.saturating_add(poll_interval),
            now.saturating_add(telemetry_interval),
            now.saturating_add(posture_interval),
        ];
        Self {
            tasks,
            intervals,
            next,
        }
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
        self.next[i] = now.saturating_add(self.intervals[i]);
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
        }
    }

    fn transition(&self, to: LifecycleState) -> Result<(), MobileError> {
        self.lifecycle.lock().transition_to(to)
    }

    /// Suspend the agent (app backgrounded / network lost). Only
    /// valid from [`LifecycleState::Connected`].
    pub fn suspend(&self) -> Result<(), MobileError> {
        self.transition(LifecycleState::Suspended)
    }

    /// Resume from [`LifecycleState::Suspended`].
    pub fn resume(&self) -> Result<(), MobileError> {
        self.transition(LifecycleState::Connected)
    }

    /// Terminate the agent. Valid from any non-terminal state.
    pub fn terminate(&self) -> Result<(), MobileError> {
        self.transition(LifecycleState::Terminated)
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
    /// Transitions `Init → Enrolling → Connected` on success, or
    /// back to `Init` on failure so the host can retry.
    pub async fn enroll(&self, claim_token: &str) -> Result<EnrollmentOutcome, MobileError> {
        self.transition(LifecycleState::Enrolling)?;
        match self.enroll_inner(claim_token).await {
            Ok(outcome) => {
                // The control plane has already issued the device its
                // certificate chain. If the `Enrolling → Connected`
                // transition now fails — only possible if we were
                // concurrently terminated mid-round-trip — we must
                // still hand the outcome back rather than drop it,
                // otherwise the server-side enrolment is orphaned (a
                // cert was minted that the client threw away). The
                // caller can persist the cert and re-drive the
                // lifecycle.
                if let Err(e) = self.transition(LifecycleState::Connected) {
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
            self.deadline(self.config.request_timeout, async move {
                telemetry.flush_one(conn).await.map(|_| ())
            })
            .await?;
        }
        Ok(())
    }

    /// Collect a fresh posture snapshot from the PAL.
    pub async fn collect_posture(&self) -> Result<MobilePostureSnapshot, MobileError> {
        Ok(self.deps.posture.collect().await?)
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
                let _snapshot = self.collect_posture().await?;
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
        );
        while self.state() == LifecycleState::Connected {
            let now = start.elapsed();
            let sleep_for = scheduler.time_until_next(now);
            tokio::time::sleep(sleep_for).await;
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
        lc.transition_to(LifecycleState::Connected).unwrap();
        lc.transition_to(LifecycleState::Suspended).unwrap();
        lc.transition_to(LifecycleState::Connected).unwrap();
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
        // Cannot suspend from Init.
        assert!(lc.transition_to(LifecycleState::Suspended).is_err());
    }

    #[test]
    fn terminated_is_terminal() {
        let mut lc = AgentLifecycle::new();
        lc.transition_to(LifecycleState::Terminated).unwrap();
        for to in [
            LifecycleState::Init,
            LifecycleState::Enrolling,
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
}

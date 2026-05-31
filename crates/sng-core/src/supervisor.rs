//! Supervised subsystem lifecycle.
//!
//! The supervising binary (`sng-edge`, `sng-agent`, the
//! integration-test harness) registers a heterogeneous set of
//! long-running subsystems against a [`Supervisor`], then calls
//! [`Supervisor::run`]. The supervisor:
//!
//! 1. Spawns every subsystem in registration order on the tokio
//!    runtime, handing each a clone of the shared
//!    [`ShutdownSignal`](crate::lifecycle::ShutdownSignal) so
//!    each subsystem can co-operate with drain.
//! 2. Awaits either an OS shutdown signal (`SIGINT` / `SIGTERM`
//!    on Unix, `Ctrl-C` on Windows), an external
//!    [`ShutdownTrigger::fire`](crate::lifecycle::ShutdownTrigger::fire)
//!    call (used by tests and by subsystems that need to escalate
//!    a fatal local error to whole-process shutdown), or the
//!    early exit of any registered subsystem (which is reported
//!    via the returned [`SupervisorReport`]).
//! 3. Fires the shutdown trigger so every subsystem's
//!    `shutdown.wait()` resolves.
//! 4. Joins every subsystem with a per-subsystem drain budget.
//!    Subsystems that exceed the budget are reported as
//!    [`DrainTimeout`](crate::lifecycle::DrainTimeout) but
//!    *not* aborted — the OS supervisor (systemd, service
//!    control manager, container runtime) is responsible for
//!    the hard kill if the host has decided the process must
//!    exit. Aborting from inside the process would risk leaving
//!    on-disk state half-written for subsystems that own real
//!    partitions (`sng-updater`'s bank writer is the canonical
//!    example).
//!
//! Health probing is independent of the lifecycle hook: a
//! subsystem may have a `start`-driven background loop (the
//! telemetry pipeline run loop is the canonical example) and
//! also implement [`HealthCheck`](crate::lifecycle::HealthCheck)
//! so the supervisor's aggregated health endpoint reports the
//! subsystem's current state. Conversely, a pure-function
//! evaluator (`sng-policy-eval::PolicyEngine`) has no run loop
//! but still implements [`HealthCheck`] so `/health` reports
//! `Up` only when the engine has a loaded bundle.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{error, info, warn};

use crate::lifecycle::{
    DrainTimeout, Health, HealthCheck, HealthStatus, ShutdownSignal, ShutdownTrigger,
    SubsystemHealth,
};

/// Default drain budget per subsystem when the supervisor's
/// caller did not specify one explicitly. Chosen to be longer
/// than the longest-running known shutdown task (the telemetry
/// pipeline's final flush of in-memory batches into the local
/// spool) but shorter than the typical operator-set
/// systemd `TimeoutStopSec` (90 s by default).
pub const DEFAULT_DRAIN_BUDGET: Duration = Duration::from_secs(30);

/// Default cadence at which the supervisor's health aggregator
/// re-polls each subsystem. Chosen so the control plane's
/// 5-second `/health` scrape sees a sample no older than this
/// interval.
pub const DEFAULT_HEALTH_INTERVAL: Duration = Duration::from_secs(2);

/// Default budget for a single [`HealthCheck::check`] call.
/// Matches the lifecycle module's
/// [`HealthCheck::check_with_timeout`] contract: any subsystem
/// that does not return within this budget is reported as
/// `Down` rather than allowed to starve the aggregator.
pub const DEFAULT_HEALTH_PROBE_BUDGET: Duration = Duration::from_secs(1);

/// Error type returned from a [`Subsystem::start`] task. Boxed
/// so the supervisor does not have to enumerate every per-crate
/// error variant — each subsystem maps its own error type into
/// this on the way out.
pub type SubsystemError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Tokio join handle for a spawned subsystem run loop. Factored
/// out of the supervisor's internal vectors so the supervisor's
/// helpers don't trip `clippy::type_complexity` on every function
/// signature that has to pass a list of in-flight handles around.
///
/// Public so that downstream subsystem adapters can name the
/// return type of [`Subsystem::start`] without having to spell
/// out the full `JoinHandle<Result<(), SubsystemError>>` shape
/// on every impl.
pub type SubsystemHandle = JoinHandle<Result<(), SubsystemError>>;

/// Entry in the supervisor's in-flight handle list. Each tuple is
/// (subsystem name for logs/report, spawned task handle, per-
/// subsystem drain budget).
type InFlightHandle = (String, SubsystemHandle, Duration);

/// Long-running subsystem registered with a [`Supervisor`].
///
/// The trait deliberately keeps the lifecycle hook (`start`) and
/// the health probe (`health`) on separate trait objects. A
/// single subsystem implementation typically provides both via a
/// pair of methods, but the supervisor stores them independently
/// so that:
///
/// - Subsystems with no background loop (pure-function
///   evaluators) can register a no-op `start` that exits
///   immediately, while still participating in health
///   aggregation.
/// - Subsystems whose health probe needs `&self` but whose
///   `start` consumes `self` (e.g. moves a `tokio::sync::mpsc::Receiver`
///   onto the spawned task) can share an `Arc<inner>` between
///   the two — the trait does not force either method into a
///   specific ownership shape.
#[async_trait]
pub trait Subsystem: Send + Sync + 'static {
    /// Stable name. Used as the supervisor's log field, the
    /// `SubsystemHealth::name`, and the metrics label. Must be
    /// lowercase and `snake_case` so it round-trips cleanly
    /// through the control plane's wire schema.
    fn name(&self) -> &'static str;

    /// Spawn the subsystem's background task and return its
    /// join handle.
    ///
    /// Implementations MUST:
    /// - Spawn the run loop with `tokio::spawn` (not block the
    ///   caller).
    /// - Co-operate with `shutdown` — every run loop's outer
    ///   `select!` MUST include `_ = shutdown.wait() => break`
    ///   (or an equivalent) so the supervisor's drain budget
    ///   is honoured.
    /// - Map any in-task error to [`SubsystemError`] via
    ///   `Box::new` on the way out so the supervisor can
    ///   surface it through [`SupervisorReport`].
    ///
    /// Subsystems with no background loop (pure-function
    /// evaluators) return a join handle for an immediately-
    /// resolving task; the supervisor treats `Ok(Ok(()))` as a
    /// successful clean exit and only reports
    /// [`EarlyExitReason::SubsystemExited`] when a subsystem
    /// exits *before* shutdown was requested.
    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError>;
}

/// Adapter that lets a [`Subsystem`] register its health probe
/// with the supervisor without forcing the same struct to also
/// implement [`HealthCheck`] when the two share an inner `Arc`.
/// Most subsystems wrap an `Arc<inner>` and the inner type
/// implements both `Subsystem` and `HealthCheck` directly — for
/// those, registering with [`SupervisorBuilder::with_subsystem`]
/// captures both hooks in one call.
#[derive(Clone)]
struct SubsystemEntry {
    subsystem: Arc<dyn Subsystem>,
    health: Arc<dyn HealthCheck>,
    drain_budget: Duration,
}

// Manual Debug for SubsystemEntry: trait objects don't carry
// Debug by default, but the SubsystemBuilder Debug requirement
// only needs the subsystem's stable name + the drain budget
// for operator log readability.
impl std::fmt::Debug for SubsystemEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubsystemEntry")
            .field("name", &self.subsystem.name())
            .field("drain_budget", &self.drain_budget)
            .finish_non_exhaustive()
    }
}

/// Reason a [`Supervisor::run`] call returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupervisorExit {
    /// OS signal received (`SIGINT` / `SIGTERM` on Unix,
    /// `Ctrl-C` on Windows).
    OsSignal,
    /// External trigger fired — typically a test harness or a
    /// subsystem that escalated a fatal local error into a
    /// whole-process shutdown by holding a clone of the
    /// [`ShutdownTrigger`].
    ExternalTrigger,
    /// A subsystem exited before shutdown was requested. The
    /// supervisor still drains every other subsystem before
    /// returning.
    SubsystemExitedEarly(String),
}

/// Result of joining a single subsystem during drain.
#[derive(Debug)]
pub struct DrainResult {
    /// Subsystem name (matches [`Subsystem::name`]).
    pub name: String,
    /// `Ok(())` — task exited cleanly within drain budget.
    ///
    /// `Err(DrainOutcome::Failed(_))` — task exited with an
    /// error.
    ///
    /// `Err(DrainOutcome::Panicked(_))` — task panicked. The
    /// supervisor recovers (does not propagate the panic to its
    /// own caller) but logs the message and surfaces it in the
    /// report so the operator sees it.
    ///
    /// `Err(DrainOutcome::Timeout(_))` — task did not exit
    /// within the per-subsystem drain budget. Not aborted;
    /// see module docs for the rationale.
    pub outcome: Result<(), DrainOutcome>,
}

/// Per-subsystem drain failure mode.
#[derive(Debug, Error)]
pub enum DrainOutcome {
    /// Subsystem's `start` task returned `Err(_)`.
    #[error("subsystem `{name}` exited with error: {error}")]
    Failed {
        /// Subsystem name.
        name: String,
        /// Boxed error from the subsystem.
        error: SubsystemError,
    },
    /// Subsystem's `start` task panicked.
    #[error("subsystem `{name}` panicked: {message}")]
    Panicked {
        /// Subsystem name.
        name: String,
        /// Panic payload string-formatted (best-effort).
        message: String,
    },
    /// Subsystem's `start` task did not return within the
    /// per-subsystem drain budget. The handle is dropped — the
    /// OS supervisor is responsible for the hard kill.
    #[error(transparent)]
    Timeout(#[from] DrainTimeout),
}

/// Report returned by [`Supervisor::run`] once every subsystem
/// has been drained (or timed out).
#[derive(Debug)]
pub struct SupervisorReport {
    /// Why the supervisor exited its main wait loop.
    pub exit_reason: SupervisorExit,
    /// One entry per registered subsystem, in registration
    /// order, with the drain outcome.
    pub drain_results: Vec<DrainResult>,
}

impl SupervisorReport {
    /// True if every subsystem drained cleanly.
    #[must_use]
    pub fn all_clean(&self) -> bool {
        self.drain_results
            .iter()
            .all(|r| matches!(r.outcome, Ok(())))
    }
}

/// Builder for [`Supervisor`]. Construct via
/// [`Supervisor::builder`]; register subsystems in dependency
/// order via [`Self::with_subsystem`] (and friends); finalise
/// with [`Self::build`].
#[derive(Debug)]
pub struct SupervisorBuilder {
    entries: Vec<SubsystemEntry>,
    default_drain_budget: Duration,
    health_interval: Duration,
    health_probe_budget: Duration,
}

impl Default for SupervisorBuilder {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            default_drain_budget: DEFAULT_DRAIN_BUDGET,
            health_interval: DEFAULT_HEALTH_INTERVAL,
            health_probe_budget: DEFAULT_HEALTH_PROBE_BUDGET,
        }
    }
}

impl SupervisorBuilder {
    /// Register a subsystem that implements both
    /// [`Subsystem`] and [`HealthCheck`].
    ///
    /// The most common path — every adapter in `sng-edge` /
    /// `sng-agent` wraps the library service inside an `Arc`
    /// and implements both traits on that wrapper, so a single
    /// `Arc::clone` is shared between the lifecycle hook and
    /// the health hook.
    #[must_use]
    pub fn with_subsystem<S>(mut self, subsystem: Arc<S>) -> Self
    where
        S: Subsystem + HealthCheck + 'static,
    {
        let health: Arc<dyn HealthCheck> = subsystem.clone();
        let subsystem: Arc<dyn Subsystem> = subsystem;
        self.entries.push(SubsystemEntry {
            subsystem,
            health,
            drain_budget: self.default_drain_budget,
        });
        self
    }

    /// Register a subsystem and override its drain budget.
    /// Use this for subsystems that legitimately need longer
    /// drain (e.g. telemetry needs to flush in-flight batches
    /// into the local spool — the default 30 s budget might be
    /// too tight on a saturated control-plane uplink).
    #[must_use]
    pub fn with_subsystem_and_drain<S>(mut self, subsystem: Arc<S>, drain_budget: Duration) -> Self
    where
        S: Subsystem + HealthCheck + 'static,
    {
        let health: Arc<dyn HealthCheck> = subsystem.clone();
        let subsystem: Arc<dyn Subsystem> = subsystem;
        self.entries.push(SubsystemEntry {
            subsystem,
            health,
            drain_budget,
        });
        self
    }

    /// Register a subsystem whose lifecycle hook and health
    /// hook live on separate trait objects. Used by the
    /// integration-test harness; production adapters use
    /// [`Self::with_subsystem`].
    #[must_use]
    pub fn with_split_subsystem(
        mut self,
        subsystem: Arc<dyn Subsystem>,
        health: Arc<dyn HealthCheck>,
        drain_budget: Duration,
    ) -> Self {
        self.entries.push(SubsystemEntry {
            subsystem,
            health,
            drain_budget,
        });
        self
    }

    /// Override the default per-subsystem drain budget for any
    /// subsystem registered without an explicit one.
    #[must_use]
    pub fn with_default_drain_budget(mut self, budget: Duration) -> Self {
        self.default_drain_budget = budget;
        self
    }

    /// Override the cadence at which the supervisor's health
    /// aggregator re-polls each subsystem.
    #[must_use]
    pub fn with_health_interval(mut self, interval: Duration) -> Self {
        self.health_interval = interval;
        self
    }

    /// Override the per-probe budget for a single
    /// [`HealthCheck::check`] call.
    #[must_use]
    pub fn with_health_probe_budget(mut self, budget: Duration) -> Self {
        self.health_probe_budget = budget;
        self
    }

    /// Finalise the builder.
    #[must_use]
    pub fn build(self) -> Supervisor {
        let (trigger, signal) = ShutdownTrigger::new();
        Supervisor {
            entries: self.entries,
            trigger: Arc::new(trigger),
            signal,
            health_interval: self.health_interval,
            health_probe_budget: self.health_probe_budget,
        }
    }
}

/// Runtime supervisor. Owns the shutdown trigger, the registered
/// subsystems, and the health aggregator task.
#[derive(Debug)]
pub struct Supervisor {
    entries: Vec<SubsystemEntry>,
    trigger: Arc<ShutdownTrigger>,
    signal: ShutdownSignal,
    health_interval: Duration,
    health_probe_budget: Duration,
}

impl Supervisor {
    /// Construct a [`SupervisorBuilder`].
    #[must_use]
    pub fn builder() -> SupervisorBuilder {
        SupervisorBuilder::default()
    }

    /// Clone of the shutdown trigger. Useful for tests that
    /// want to drive shutdown without an OS signal, and for
    /// subsystems that need to escalate a fatal local error
    /// into a whole-process shutdown (the canonical example is
    /// `sng-updater::clear_layout_divergence` returning a
    /// configuration error — that subsystem can fire the
    /// trigger so the operator's `systemd` unit restarts the
    /// whole process after manual reconciliation).
    #[must_use]
    pub fn shutdown_trigger(&self) -> Arc<ShutdownTrigger> {
        Arc::clone(&self.trigger)
    }

    /// Clone of the shutdown signal. Subsystems that need to
    /// observe shutdown without being formally registered (e.g.
    /// an HTTP `/health` server task spawned by the binary
    /// directly) can clone this and select on
    /// [`ShutdownSignal::wait`].
    #[must_use]
    pub fn shutdown_signal(&self) -> ShutdownSignal {
        self.signal.clone()
    }

    /// Aggregate every registered subsystem's current health
    /// without driving the run loop. Useful for unit tests and
    /// for an external HTTP `/health` handler that wants a
    /// fresh sample on demand.
    pub async fn health_snapshot(&self) -> Health {
        let mut subsystems = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let check = entry
                .health
                .check_with_timeout(self.health_probe_budget)
                .await;
            subsystems.push(check);
        }
        Health::aggregate(subsystems)
    }

    /// Drive the supervised lifecycle to completion.
    ///
    /// 1. Spawn every subsystem's run loop in registration
    ///    order.
    /// 2. Spawn the OS signal listener.
    /// 3. Wait for whichever of `(os signal | external trigger
    ///    | early subsystem exit)` resolves first.
    /// 4. Fire the shutdown trigger.
    /// 5. Join every subsystem with its per-subsystem drain
    ///    budget.
    /// 6. Return a [`SupervisorReport`].
    ///
    /// The function does not return until every subsystem has
    /// been drained (or timed out). It does not abort any
    /// subsystem: the OS supervisor is responsible for the hard
    /// kill if the process must exit.
    ///
    /// # Errors
    ///
    /// Returns [`SupervisorRunError::StartFailed`] if any
    /// subsystem's `start` returns an `Err` before any other
    /// subsystem has been spawned. In that case the supervisor
    /// drains the subsystems that *did* start successfully
    /// before returning. Once every subsystem has started
    /// successfully, this function never returns `Err` — every
    /// run-loop-side failure is captured in the
    /// [`SupervisorReport`]'s `drain_results` instead.
    pub async fn run(self) -> Result<SupervisorReport, SupervisorRunError> {
        info!(
            subsystems = self.entries.len(),
            "supervisor starting registered subsystems"
        );

        // Spawn every subsystem. If any `start` returns an Err
        // before another subsystem has even been asked to spawn,
        // we drain the ones that did spawn and surface the
        // partial-startup failure to the caller. This prevents
        // a half-booted process from drifting into a state
        // where some subsystems are running and others never
        // got the chance — the operator either gets a clean
        // boot or a clean drain.
        let mut handles: Vec<InFlightHandle> = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let name = entry.subsystem.name().to_owned();
            match entry.subsystem.start(self.signal.clone()).await {
                Ok(handle) => {
                    info!(subsystem = %name, "subsystem started");
                    handles.push((name, handle, entry.drain_budget));
                }
                Err(e) => {
                    error!(subsystem = %name, error = %e, "subsystem failed to start; aborting boot");
                    // Drain the already-spawned subsystems.
                    self.trigger.fire();
                    let _ = drain_handles(handles).await;
                    return Err(SupervisorRunError::StartFailed { name, error: e });
                }
            }
        }

        // Spawn the health aggregator. It loops on the
        // configured interval, emitting a tracing event for
        // each composite snapshot. The aggregator itself
        // selects on the shutdown signal so it exits cleanly
        // when drain begins.
        let health_signal = self.signal.clone();
        let health_entries: Vec<(Arc<dyn HealthCheck>, Duration)> = self
            .entries
            .iter()
            .map(|e| (Arc::clone(&e.health), self.health_probe_budget))
            .collect();
        let health_interval = self.health_interval;
        let health_task = tokio::spawn(async move {
            health_aggregator_loop(health_entries, health_interval, health_signal).await;
        });

        // Wait for the first reason to drain.
        let exit_reason = self.await_exit(&mut handles).await;

        info!(
            reason = ?exit_reason,
            "supervisor entering drain"
        );
        self.trigger.fire();

        // Drain every subsystem.
        let drain_results = drain_handles(handles).await;

        // Drain the aggregator. It will exit on shutdown
        // signal, so just await its handle with the default
        // drain budget — if the aggregator is hung the
        // supervisor reports a warning but the process still
        // exits.
        if let Err(e) = timeout(DEFAULT_DRAIN_BUDGET, health_task).await {
            warn!(error = %e, "health aggregator did not exit within drain budget");
        }

        info!(
            clean = drain_results.iter().all(|r| matches!(r.outcome, Ok(()))),
            "supervisor drain complete"
        );
        Ok(SupervisorReport {
            exit_reason,
            drain_results,
        })
    }

    /// Await whichever of (OS signal | external trigger | early
    /// subsystem exit) resolves first. The mutable borrow on
    /// `handles` lets us watch every spawned task for an early
    /// exit without owning the vector.
    async fn await_exit(&self, handles: &mut Vec<InFlightHandle>) -> SupervisorExit {
        // OS signal future. On Unix we wait on either SIGINT
        // or SIGTERM; on Windows the only portable equivalent
        // is `tokio::signal::ctrl_c`. Either resolves to a
        // single `OsSignal` exit reason.
        let os_signal_fut = wait_for_os_shutdown_signal();
        tokio::pin!(os_signal_fut);

        // External trigger future. Resolves when the shutdown
        // trigger was fired by anything other than the
        // supervisor's own drain logic (tests; subsystems that
        // hold a clone of the trigger).
        let trigger_signal = self.signal.clone();
        let trigger_fut = async move { trigger_signal.wait().await };
        tokio::pin!(trigger_fut);

        loop {
            // We can't `select!` over an arbitrary-sized vector
            // of join handles with a fixed-arms macro, so we
            // pick one *biased* path: first check the OS /
            // trigger, then poll each handle non-blocking for
            // an early exit. The tradeoff is a short polling
            // delay on early exit (capped at 100 ms), which is
            // acceptable because early exit is itself a
            // pathological event — the supervisor's job is to
            // surface it, not to react to it within microseconds.
            tokio::select! {
                biased;
                () = &mut os_signal_fut => return SupervisorExit::OsSignal,
                () = &mut trigger_fut => return SupervisorExit::ExternalTrigger,
                () = tokio::time::sleep(Duration::from_millis(100)) => {
                    if let Some(name) = poll_for_early_exit(handles) {
                        return SupervisorExit::SubsystemExitedEarly(name);
                    }
                }
            }
        }
    }
}

/// Poll every spawned subsystem handle without blocking. If any
/// has already finished, returns its name; otherwise returns
/// `None`.
///
/// We do NOT remove the finished handle from the vector here —
/// the drain step needs to observe its `JoinHandle::join` outcome
/// to surface error / panic into the report. Marking-as-finished
/// is implicit: a finished handle's `await` in `drain_handles`
/// resolves immediately.
fn poll_for_early_exit(handles: &[InFlightHandle]) -> Option<String> {
    for (name, handle, _) in handles {
        if handle.is_finished() {
            return Some(name.clone());
        }
    }
    None
}

/// Drain every spawned subsystem, respecting per-subsystem
/// drain budgets. See [`Supervisor::run`] for the contract.
async fn drain_handles(handles: Vec<InFlightHandle>) -> Vec<DrainResult> {
    let mut results = Vec::with_capacity(handles.len());
    for (name, handle, budget) in handles {
        let outcome = match timeout(budget, handle).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(e))) => Err(DrainOutcome::Failed {
                name: name.clone(),
                error: e,
            }),
            Ok(Err(join_err)) => {
                // `JoinError::is_panic` is the canonical way to
                // distinguish a panic from a cancellation; we
                // never cancel inside the supervisor (drain is
                // co-operative via the shutdown signal), so a
                // join error is always a panic in practice.
                let message = if join_err.is_panic() {
                    format!("{join_err}")
                } else {
                    format!("join error: {join_err}")
                };
                Err(DrainOutcome::Panicked {
                    name: name.clone(),
                    message,
                })
            }
            Err(_elapsed) => Err(DrainOutcome::Timeout(DrainTimeout(name.clone(), budget))),
        };
        if let Err(ref e) = outcome {
            warn!(subsystem = %name, error = %e, "subsystem drain non-clean");
        } else {
            info!(subsystem = %name, "subsystem drained cleanly");
        }
        results.push(DrainResult { name, outcome });
    }
    results
}

/// Health aggregator loop. Polls every registered subsystem at
/// the configured interval, aggregates the result, emits a
/// tracing event. Exits cleanly when the shutdown signal fires.
async fn health_aggregator_loop(
    entries: Vec<(Arc<dyn HealthCheck>, Duration)>,
    interval: Duration,
    shutdown: ShutdownSignal,
) {
    let mut ticker = tokio::time::interval(interval);
    // `tokio::time::interval` is documented to fire its first tick
    // immediately on `tick().await`. The `Delay` missed-tick policy
    // controls how lagging ticks are coalesced — it does NOT suppress
    // that immediate first tick. Consume it explicitly so the health
    // aggregator's first probe lands one `interval` after subsystem
    // spawn (i.e. once subsystems have had a chance to reach steady
    // state) rather than racing them at t=0.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::select! {
        _ = ticker.tick() => {}
        () = shutdown.wait() => return,
    }
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let mut subs = Vec::with_capacity(entries.len());
                for (check, budget) in &entries {
                    subs.push(check.check_with_timeout(*budget).await);
                }
                let agg = Health::aggregate(subs);
                match agg.status {
                    HealthStatus::Up => tracing::debug!(
                        status = "up",
                        subsystems = agg.subsystems.len(),
                        "composite health"
                    ),
                    HealthStatus::Degraded => warn!(
                        status = "degraded",
                        subsystems = ?summarise_subsystem_status(&agg.subsystems),
                        "composite health"
                    ),
                    HealthStatus::Down => error!(
                        status = "down",
                        subsystems = ?summarise_subsystem_status(&agg.subsystems),
                        "composite health"
                    ),
                }
            }
            () = shutdown.wait() => break,
        }
    }
}

fn summarise_subsystem_status(subs: &[SubsystemHealth]) -> Vec<(String, HealthStatus)> {
    subs.iter().map(|s| (s.name.clone(), s.status)).collect()
}

/// Wait for any OS-level shutdown signal. Resolves on first
/// signal; the `Supervisor::run` loop then fires the trigger
/// exactly once and proceeds to drain. Subsequent signals are
/// ignored by the supervisor — the OS supervisor is responsible
/// for a hard kill if the process refuses to exit.
async fn wait_for_os_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to install SIGINT handler; supervisor will not exit on Ctrl-C");
                std::future::pending::<()>().await;
                return;
            }
        };
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!(error = %e, "failed to install SIGTERM handler; supervisor will not exit on systemd stop");
                std::future::pending::<()>().await;
                return;
            }
        };
        tokio::select! {
            _ = sigint.recv() => info!("SIGINT received; entering drain"),
            _ = sigterm.recv() => info!("SIGTERM received; entering drain"),
        }
    }
    #[cfg(not(unix))]
    {
        match tokio::signal::ctrl_c().await {
            Ok(()) => info!("Ctrl-C received; entering drain"),
            Err(e) => {
                error!(error = %e, "failed to install Ctrl-C handler; supervisor will not exit on Ctrl-C");
                std::future::pending::<()>().await;
            }
        }
    }
}

/// Error returned from [`Supervisor::run`] when a subsystem
/// failed to start. Every other failure mode (run-loop errors,
/// panics, drain timeouts) is captured in the
/// [`SupervisorReport`] returned by a successful `run`.
#[derive(Debug, Error)]
pub enum SupervisorRunError {
    /// One of the registered subsystems returned an `Err` from
    /// its `start` method. The supervisor drained any
    /// subsystems that did start successfully before returning.
    #[error("subsystem `{name}` failed to start: {error}")]
    StartFailed {
        /// Subsystem name.
        name: String,
        /// Boxed error from the subsystem's `start` method.
        error: SubsystemError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::HealthStatus;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use tokio::time::sleep;

    /// Fast-draining subsystem that records whether its run
    /// loop observed shutdown.
    /// Test-only knob set for [`TestSubsystem`]. We combine
    /// every "do something specific on run" flag into a single
    /// enum so the struct keeps a single behavior field instead
    /// of four parallel bools (which also avoids tripping
    /// `clippy::struct_excessive_bools`).
    #[derive(Copy, Clone)]
    enum RunBehavior {
        /// Wait for shutdown signal, then exit cleanly.
        DrainOnShutdown,
        /// `start` returns Err immediately.
        StartFails,
        /// Run task panics.
        PanicOnRun,
        /// Run task returns `Err(_)`.
        ErrOnRun,
        /// Run task ignores shutdown and sleeps far longer than
        /// the drain budget — used to exercise the timeout path.
        IgnoreShutdown,
        /// Run task races a long sleep against the shutdown
        /// signal in a `tokio::select!`. Models the
        /// reconnect-backoff loops in `sng-{agent,edge}::comms`
        /// and `::telemetry`: when `client.connect()` fails,
        /// each loop must race the backoff `sleep` against
        /// `shutdown.wait()` so an operator-initiated drain
        /// during a long retry interval does not get parked
        /// for the full backoff_max.
        LongSleepRacedWithShutdown,
    }

    struct TestSubsystem {
        name: &'static str,
        saw_shutdown: Arc<AtomicBool>,
        start_count: Arc<AtomicU32>,
        check_count: Arc<AtomicU32>,
        health: HealthStatus,
        behavior: RunBehavior,
    }

    impl TestSubsystem {
        fn new(name: &'static str) -> Arc<Self> {
            Arc::new(Self {
                name,
                saw_shutdown: Arc::new(AtomicBool::new(false)),
                start_count: Arc::new(AtomicU32::new(0)),
                check_count: Arc::new(AtomicU32::new(0)),
                health: HealthStatus::Up,
                behavior: RunBehavior::DrainOnShutdown,
            })
        }

        fn with_behavior(name: &'static str, behavior: RunBehavior) -> Arc<Self> {
            Arc::new(Self {
                name,
                saw_shutdown: Arc::new(AtomicBool::new(false)),
                start_count: Arc::new(AtomicU32::new(0)),
                check_count: Arc::new(AtomicU32::new(0)),
                health: HealthStatus::Up,
                behavior,
            })
        }

        fn with_health(name: &'static str, health: HealthStatus) -> Arc<Self> {
            Arc::new(Self {
                name,
                saw_shutdown: Arc::new(AtomicBool::new(false)),
                start_count: Arc::new(AtomicU32::new(0)),
                check_count: Arc::new(AtomicU32::new(0)),
                health,
                behavior: RunBehavior::DrainOnShutdown,
            })
        }
    }

    #[async_trait]
    impl Subsystem for TestSubsystem {
        fn name(&self) -> &'static str {
            self.name
        }

        async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
            self.start_count.fetch_add(1, Ordering::Relaxed);
            if matches!(self.behavior, RunBehavior::StartFails) {
                return Err("start failure".into());
            }
            let saw_shutdown = Arc::clone(&self.saw_shutdown);
            let behavior = self.behavior;
            let handle = tokio::spawn(async move {
                match behavior {
                    RunBehavior::PanicOnRun => {
                        panic!("test panic");
                    }
                    RunBehavior::ErrOnRun => Err(SubsystemError::from("run error")),
                    RunBehavior::IgnoreShutdown => {
                        // Sleep through the drain budget.
                        sleep(Duration::from_secs(60)).await;
                        Ok(())
                    }
                    RunBehavior::DrainOnShutdown => {
                        shutdown.wait().await;
                        saw_shutdown.store(true, Ordering::Relaxed);
                        Ok(())
                    }
                    RunBehavior::LongSleepRacedWithShutdown => {
                        // 60s is well beyond the supervisor's default
                        // 30s drain budget; if shutdown does NOT
                        // preempt the sleep the supervisor will
                        // report `DrainOutcome::Timeout`. Passing
                        // this test requires the `tokio::select!`
                        // arm to win the race and set
                        // `saw_shutdown`.
                        tokio::select! {
                            () = shutdown.wait() => {
                                saw_shutdown.store(true, Ordering::Relaxed);
                            }
                            () = sleep(Duration::from_secs(60)) => {}
                        }
                        Ok(())
                    }
                    // Already filtered above; keep the arm so
                    // future variants surface as a compile error
                    // rather than a silent fall-through.
                    RunBehavior::StartFails => unreachable!("start_fails handled above"),
                }
            });
            Ok(handle)
        }
    }

    #[async_trait]
    impl HealthCheck for TestSubsystem {
        fn name(&self) -> &str {
            self.name
        }
        async fn check(&self) -> SubsystemHealth {
            self.check_count.fetch_add(1, Ordering::Relaxed);
            SubsystemHealth {
                name: self.name.into(),
                status: self.health,
                detail: None,
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn external_trigger_drains_every_subsystem() {
        let a = TestSubsystem::new("a");
        let b = TestSubsystem::new("b");
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&a))
            .with_subsystem(Arc::clone(&b))
            .build();
        let trigger = supervisor.shutdown_trigger();
        let handle = tokio::spawn(supervisor.run());

        // Yield once so subsystems reach their await.
        tokio::task::yield_now().await;
        trigger.fire();

        let report = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        assert_eq!(report.exit_reason, SupervisorExit::ExternalTrigger);
        assert!(report.all_clean());
        assert_eq!(report.drain_results.len(), 2);
        assert_eq!(report.drain_results[0].name, "a");
        assert_eq!(report.drain_results[1].name, "b");
        assert!(a.saw_shutdown.load(Ordering::Relaxed));
        assert!(b.saw_shutdown.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn subsystem_start_failure_drains_already_started_subsystems() {
        let a = TestSubsystem::new("a");
        let bad = TestSubsystem::with_behavior("bad", RunBehavior::StartFails);
        let c = TestSubsystem::new("c");
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&a))
            .with_subsystem(Arc::clone(&bad))
            .with_subsystem(Arc::clone(&c))
            .build();
        let handle = tokio::spawn(supervisor.run());

        let err = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect_err("start should fail");

        match err {
            SupervisorRunError::StartFailed { name, .. } => assert_eq!(name, "bad"),
        }

        // `a` was started before `bad` failed; it must have
        // observed shutdown during the drain.
        assert!(a.saw_shutdown.load(Ordering::Relaxed));
        // `c` was never started — its run loop never set
        // saw_shutdown.
        assert!(!c.saw_shutdown.load(Ordering::Relaxed));
        // `c`'s start was never called either.
        assert_eq!(c.start_count.load(Ordering::Relaxed), 0);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn early_exit_surfaces_in_exit_reason() {
        let normal = TestSubsystem::new("normal");
        let early = TestSubsystem::with_behavior("early", RunBehavior::ErrOnRun);
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&normal))
            .with_subsystem(Arc::clone(&early))
            .build();
        let handle = tokio::spawn(supervisor.run());

        let report = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        match &report.exit_reason {
            SupervisorExit::SubsystemExitedEarly(name) => assert_eq!(name, "early"),
            other => panic!("expected early exit, got {other:?}"),
        }
        // The `early` subsystem returned an error — that surfaces
        // through its drain outcome, not through the run result.
        let early_outcome = report
            .drain_results
            .iter()
            .find(|r| r.name == "early")
            .expect("early in results");
        assert!(matches!(
            early_outcome.outcome,
            Err(DrainOutcome::Failed { .. })
        ));
        // The other subsystem drained cleanly via the shutdown
        // signal the supervisor fired after observing the early
        // exit.
        let normal_outcome = report
            .drain_results
            .iter()
            .find(|r| r.name == "normal")
            .expect("normal in results");
        assert!(matches!(normal_outcome.outcome, Ok(())));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn panic_in_run_loop_is_captured_in_report() {
        let bad = TestSubsystem::with_behavior("bad", RunBehavior::PanicOnRun);
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&bad))
            .build();
        let handle = tokio::spawn(supervisor.run());

        let report = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        let bad_outcome = &report.drain_results[0];
        match &bad_outcome.outcome {
            Err(DrainOutcome::Panicked { name, message }) => {
                assert_eq!(name, "bad");
                assert!(message.contains("panic"), "panic message: {message}");
            }
            other => panic!("expected panic outcome, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn unresponsive_subsystem_times_out_but_supervisor_still_returns() {
        let slow = TestSubsystem::with_behavior("slow", RunBehavior::IgnoreShutdown);
        let supervisor = Supervisor::builder()
            .with_subsystem_and_drain(Arc::clone(&slow), Duration::from_millis(100))
            .build();
        let trigger = supervisor.shutdown_trigger();
        let handle = tokio::spawn(supervisor.run());

        tokio::task::yield_now().await;
        trigger.fire();

        let report = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        let slow_outcome = &report.drain_results[0];
        assert!(matches!(
            slow_outcome.outcome,
            Err(DrainOutcome::Timeout(_))
        ));
    }

    #[tokio::test]
    async fn health_snapshot_aggregates_subsystem_statuses() {
        let up_a = TestSubsystem::with_health("up_a", HealthStatus::Up);
        let degraded_b = TestSubsystem::with_health("degraded_b", HealthStatus::Degraded);
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&up_a))
            .with_subsystem(Arc::clone(&degraded_b))
            .build();
        let snap = supervisor.health_snapshot().await;
        assert_eq!(snap.status, HealthStatus::Degraded);
        assert_eq!(snap.subsystems.len(), 2);
        assert_eq!(snap.subsystems[0].name, "up_a");
        assert_eq!(snap.subsystems[1].name, "degraded_b");
    }

    #[tokio::test]
    async fn empty_supervisor_health_snapshot_reports_down() {
        let supervisor = Supervisor::builder().build();
        let snap = supervisor.health_snapshot().await;
        assert_eq!(snap.status, HealthStatus::Down);
        assert!(snap.subsystems.is_empty());
    }

    /// Regression: the original health aggregator wrapper said
    /// "Skip immediate-first-tick burst" but only set
    /// `MissedTickBehavior::Delay` — which controls how missed
    /// ticks are coalesced, NOT whether the first call to
    /// `tick().await` resolves immediately. The fix consumes
    /// the immediate first tick explicitly before entering the
    /// loop, so the first probe lands one `interval` after
    /// supervisor spawn (giving subsystems time to reach a
    /// steady state).
    ///
    /// We exercise this by configuring a 1-second health
    /// interval and firing shutdown after only ~100ms. If the
    /// first tick still fired immediately the `check_count`
    /// would observe at least one probe; with the fix it sees
    /// none.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn health_aggregator_first_tick_does_not_fire_immediately() {
        let a = TestSubsystem::new("a");
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&a))
            .with_health_interval(Duration::from_secs(1))
            .build();
        let trigger = supervisor.shutdown_trigger();
        let handle = tokio::spawn(supervisor.run());

        // Yield so the spawn-and-tick race resolves in favour of
        // the aggregator's first `select!` arm. Then advance the
        // paused clock by a fraction of the interval — not enough
        // to deliver a tick.
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        trigger.fire();

        let _ = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        assert_eq!(
            a.check_count.load(Ordering::Relaxed),
            0,
            "health probe must NOT fire before the first interval elapses"
        );
    }

    /// Companion to the previous test: once the interval has
    /// actually elapsed, the aggregator must probe at every tick.
    /// Guards against an over-eager fix that consumed the first
    /// tick AND the wakeup signal.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn health_aggregator_probes_after_interval_elapses() {
        let a = TestSubsystem::new("a");
        let supervisor = Supervisor::builder()
            .with_subsystem(Arc::clone(&a))
            .with_health_interval(Duration::from_millis(100))
            .build();
        let trigger = supervisor.shutdown_trigger();
        let handle = tokio::spawn(supervisor.run());

        tokio::task::yield_now().await;
        // Advance past 3 intervals plus a margin so the aggregator
        // has a chance to be polled. Yield between advances so
        // each interval the supervisor's runtime gets to wake.
        for _ in 0..3 {
            tokio::time::advance(Duration::from_millis(150)).await;
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
        }
        trigger.fire();

        let _ = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        assert!(
            a.check_count.load(Ordering::Relaxed) >= 2,
            "expected at least 2 probes after 3 intervals elapsed, saw {}",
            a.check_count.load(Ordering::Relaxed)
        );
    }

    /// Regression: every reconnect-backoff loop in
    /// `sng-{agent,edge}::comms` and `::telemetry` calls
    /// `tokio::time::sleep(backoff)` after a `client.connect()`
    /// failure. Before the wave-1 fix that sleep was bare —
    /// shutdown could not preempt it, so a drain fired during
    /// the retry interval (default `backoff_max = 30s`, which
    /// also happens to be the supervisor's per-subsystem drain
    /// budget) would park the subsystem for the full budget and
    /// report `DrainOutcome::Timeout`.
    ///
    /// This test pins down the new behaviour: a subsystem whose
    /// run loop races a 60-second sleep against `shutdown.wait()`
    /// must observe the shutdown signal and exit cleanly within
    /// the drain budget, well under the bare-sleep value.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn backoff_sleep_raced_against_shutdown_drains_promptly() {
        let racer =
            TestSubsystem::with_behavior("comms-like", RunBehavior::LongSleepRacedWithShutdown);
        let supervisor = Supervisor::builder()
            // Pick a drain budget shorter than the 60s in-loop
            // sleep so a regression (bare sleep) would surface
            // as `DrainOutcome::Timeout` rather than passing by
            // accident.
            .with_subsystem_and_drain(Arc::clone(&racer), Duration::from_secs(5))
            .build();
        let trigger = supervisor.shutdown_trigger();
        let handle = tokio::spawn(supervisor.run());

        // Let the subsystem reach its `tokio::select!` arm.
        tokio::task::yield_now().await;
        trigger.fire();

        let report = timeout(Duration::from_secs(10), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");

        assert_eq!(report.drain_results.len(), 1);
        let drain = &report.drain_results[0];
        assert!(
            drain.outcome.is_ok(),
            "expected clean drain, got {:?}",
            drain.outcome
        );
        assert!(
            racer.saw_shutdown.load(Ordering::Relaxed),
            "shutdown signal must have preempted the 60s backoff sleep"
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn empty_supervisor_drains_immediately_on_trigger() {
        let supervisor = Supervisor::builder().build();
        let trigger = supervisor.shutdown_trigger();
        let handle = tokio::spawn(supervisor.run());
        tokio::task::yield_now().await;
        trigger.fire();
        let report = timeout(Duration::from_secs(5), handle)
            .await
            .expect("supervisor returned within budget")
            .expect("join ok")
            .expect("run ok");
        assert_eq!(report.exit_reason, SupervisorExit::ExternalTrigger);
        assert!(report.drain_results.is_empty());
    }
}

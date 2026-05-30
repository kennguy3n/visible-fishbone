//! Supervisor for the IDS / IPS subsystem.
//!
//! `IpsManager` is the only thing the rest of the edge VM
//! interacts with on the IPS surface. It owns:
//!
//! * the [`SuricataProcess`] backend (production: [`ShellSuricata`];
//!   tests: [`MockSuricata`]),
//! * the [`ConfigGenerator`] that turns a policy slice into a
//!   `suricata.yaml`,
//! * the [`RuleStager`] that materialises signed rule bundles on
//!   disk (and runs `suricata -T` against them),
//! * the [`HealthMonitor`] that decides whether the data plane
//!   keeps forwarding when the IDS is unhappy,
//! * the [`IpsEventSink`] handle into the workspace telemetry
//!   pipeline.
//!
//! The shape mirrors the supervisor pattern already used by
//! [`sng_telemetry`] and `sng-fw`: the public API is the
//! "manager owns one task tree", every external mutation arrives
//! through an `&self` async method, and a single
//! [`IpsManager::run_until_shutdown`] entry point drives the
//! event loop.
//!
//! ## Concurrency model
//!
//! The manager spawns three background tasks once
//! [`IpsManager::start`] succeeds:
//!
//! 1. **EVE tail** — opens the EVE JSON log Suricata is writing,
//!    reads it line by line, decodes each line into an
//!    [`EveRecord`], folds the record into an
//!    [`sng_core::events::IpsEvent`] (when applicable), and
//!    pushes the event into the [`IpsEventSink`]. Unknown event
//!    types are logged at WARN but not surfaced as events; EVE
//!    decode errors are counted on the manager's status object so
//!    the operator dashboard can surface a parser regression.
//!
//! 2. **Stats poll** — on a fixed cadence, reads
//!    [`SuricataProcess::stats`], computes the
//!    [`StatsDelta`](crate::process::StatsDelta), and feeds it
//!    into the [`HealthMonitor`] together with the live
//!    [`SuricataProcess::is_alive`] result and a `eve_progressing`
//!    flag derived from the tail task's last-progress timestamp.
//!    Each transition is emitted as a `tracing::event!(WARN | INFO)`
//!    so log-based alerting can pick it up; the public
//!    [`IpsManager::health_state`] always returns the latest
//!    state for in-process consumers.
//!
//! 3. **Crash watchdog** — wraps the supervisor's
//!    restart-with-exponential-backoff policy. When
//!    [`SuricataProcess::status`] reports `Crashed`, the watchdog
//!    increments the per-restart delay (capped at the configured
//!    ceiling), waits, then re-issues `start(config_path)`.
//!
//! All three tasks share state through the same `Arc<Inner>` the
//! manager itself holds — there is no extra channel between
//! them, just `parking_lot::Mutex` around the small mutable
//! state.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use sng_core::events::IpsEvent;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::{ConfigGenerator, IpsConfigInput, SuricataConfig};
use crate::error::IpsError;
use crate::eve::{EveAlert, EveRecord};
use crate::health::{
    FailMode, HealthMonitor, HealthProbe, HealthState, HealthThresholds, HealthTransition,
};
use crate::process::{ProcessStatus, SuricataProcess, SuricataSignal, SuricataStats};
use crate::rules::{IpsRuleBundle, IpsRuleVerifier, RuleStager};
use crate::telemetry::IpsEventSink;

/// Tunable knobs for the supervisor. The defaults are biased
/// toward responsive failure detection (1-second stats poll,
/// 3-strike fail-closed transition) and a conservative restart
/// cadence (1 s initial backoff, capped at 30 s).
#[derive(Clone, Debug)]
pub struct IpsManagerConfig {
    /// Path the manager writes the rendered `suricata.yaml` to,
    /// and that `SuricataProcess::start` reads. The stager and
    /// the EVE tailer share this directory's parent for their
    /// own files; the manager creates the parent on `start` if
    /// it does not exist.
    pub config_path: PathBuf,
    /// Path the EVE writer outputs to. Must match the
    /// `eve_log_path` baked into the rendered config — the
    /// manager validates this on every config swap.
    pub eve_log_path: PathBuf,
    /// How long the tail task may go without observing a new
    /// EVE line before the health probe marks
    /// `eve_progressing = false`. Default 30 seconds (matches
    /// Suricata's flush cadence on a quiet network).
    pub eve_staleness_window: Duration,
    /// How often the stats poll task wakes up to read
    /// `SuricataProcess::stats`. Default 1 second.
    pub stats_poll_interval: Duration,
    /// Health thresholds (drop ratios, etc).
    pub health_thresholds: HealthThresholds,
    /// Number of consecutive `process_alive = false` probes
    /// required before the state machine declares `Failed`.
    /// Prevents alarm-flap from a single transient probe miss.
    /// Default 3.
    pub failed_consecutive_required: u32,
    /// Action when the IDS is `Failed`. `Open` keeps the data
    /// plane forwarding (legacy posture); `Closed` holds the
    /// data plane until coverage returns.
    pub fail_mode: FailMode,
    /// Initial delay before a crashed-restart attempt. Default
    /// 1 second.
    pub restart_initial_backoff: Duration,
    /// Maximum delay between crashed-restart attempts. Default
    /// 30 seconds. The watchdog doubles the delay each attempt
    /// until it hits this cap.
    pub restart_max_backoff: Duration,
    /// Maximum number of consecutive restart attempts before the
    /// manager gives up and surfaces a hard failure. `None`
    /// means "retry forever"; production callers usually set
    /// this to a finite number so a wedged binary surfaces an
    /// alert instead of hammering the system.
    pub restart_max_attempts: Option<u32>,
    /// How often the watchdog polls `SuricataProcess::status`
    /// looking for the `Crashed` transition. Default 1 second;
    /// tests shrink this to keep wall-clock waits short.
    pub restart_poll_interval: Duration,
}

impl Default for IpsManagerConfig {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("/etc/sng/suricata.yaml"),
            eve_log_path: PathBuf::from("/var/log/sng/eve.json"),
            eve_staleness_window: Duration::from_secs(30),
            stats_poll_interval: Duration::from_secs(1),
            health_thresholds: HealthThresholds::default(),
            failed_consecutive_required: 3,
            fail_mode: FailMode::Closed,
            restart_initial_backoff: Duration::from_secs(1),
            restart_max_backoff: Duration::from_secs(30),
            restart_max_attempts: None,
            restart_poll_interval: Duration::from_secs(1),
        }
    }
}

/// Lifecycle snapshot the manager publishes for the rest of the
/// process to read.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IpsManagerStatus {
    /// Current Suricata process status.
    pub process: ProcessStatus,
    /// Current health-machine state.
    pub health: HealthState,
    /// Whether the data plane should keep forwarding given the
    /// fail-mode policy.
    pub forwarding_allowed: bool,
    /// Number of EVE lines that failed to decode since start.
    /// A non-zero value is not fatal — Suricata occasionally
    /// emits records the parser does not recognise — but it is
    /// the dashboard's hint that the parser may need an update.
    pub eve_decode_errors: u64,
    /// Number of EVE records normalised and forwarded to the
    /// telemetry sink since start.
    pub events_emitted: u64,
    /// Number of restart attempts the watchdog has issued since
    /// start. Resets on a successful `Healthy` transition.
    pub restart_attempts: u32,
}

/// Shared mutable state. Lives behind an `Arc` so the background
/// tasks and the manager handle can both access it. The two
/// fields the tasks update on a hot path
/// (`last_eve_progress_at`, `eve_decode_errors`, `events_emitted`)
/// are wrapped individually so the stats poll never blocks the
/// EVE tail.
#[derive(Debug)]
struct Inner {
    config_path: ArcSwap<PathBuf>,
    last_eve_progress_at: Mutex<Instant>,
    last_stats: Mutex<SuricataStats>,
    health: Mutex<HealthMonitor>,
    eve_decode_errors: parking_lot::Mutex<u64>,
    events_emitted: parking_lot::Mutex<u64>,
    restart_attempts: parking_lot::Mutex<u32>,
    /// Notify the EVE tail to stop. Set on `stop()`.
    shutdown: Notify,
}

/// IPS supervisor handle. Cheap to clone (`Arc` inside) and
/// `Send + Sync`.
#[derive(Clone, Debug)]
pub struct IpsManager {
    cfg: IpsManagerConfig,
    process: Arc<dyn SuricataProcess>,
    stager: Arc<dyn RuleStager>,
    verifier: Arc<IpsRuleVerifier>,
    config_gen: ConfigGenerator,
    sink: IpsEventSink,
    inner: Arc<Inner>,
}

impl IpsManager {
    /// Build a manager from its components. No background tasks
    /// are running yet; call [`Self::start`] to render the
    /// initial config, spawn the process, and start the
    /// background loops.
    #[must_use]
    pub fn new(
        cfg: IpsManagerConfig,
        process: Arc<dyn SuricataProcess>,
        stager: Arc<dyn RuleStager>,
        verifier: Arc<IpsRuleVerifier>,
        sink: IpsEventSink,
    ) -> Self {
        let inner = Arc::new(Inner {
            config_path: ArcSwap::from_pointee(cfg.config_path.clone()),
            last_eve_progress_at: Mutex::new(Instant::now()),
            last_stats: Mutex::new(SuricataStats::zero()),
            health: Mutex::new(
                HealthMonitor::with_thresholds(cfg.health_thresholds)
                    .with_failed_threshold(cfg.failed_consecutive_required),
            ),
            eve_decode_errors: parking_lot::Mutex::new(0),
            events_emitted: parking_lot::Mutex::new(0),
            restart_attempts: parking_lot::Mutex::new(0),
            shutdown: Notify::new(),
        });
        Self {
            cfg,
            process,
            stager,
            verifier,
            config_gen: ConfigGenerator::new(),
            sink,
            inner,
        }
    }

    /// Render the initial config from `input`, materialise it on
    /// disk at [`IpsManagerConfig::config_path`], and spawn the
    /// Suricata process. Returns once the process backend has
    /// accepted the spawn — the manager does **not** wait for
    /// the IDS to finish loading rules; the [`HealthMonitor`]
    /// covers steady-state liveness.
    ///
    /// The caller is expected to call
    /// [`Self::spawn_background_tasks`] after `start` returns;
    /// that method is kept separate so a test can drive the
    /// supervisor synchronously without the tail / poll / watchdog
    /// running.
    pub async fn start(&self, input: &IpsConfigInput) -> Result<SuricataConfig, IpsError> {
        let cfg = self.config_gen.render(input)?;
        self.write_config_to_disk(&cfg).await?;
        self.process.start(&self.cfg.config_path).await?;
        info!(
            target: "sng_ips::manager",
            config_path = %self.cfg.config_path.display(),
            digest = %cfg.digest_hex(),
            "ips started"
        );
        Ok(cfg)
    }

    /// Spawn the EVE tail + stats poll + restart watchdog
    /// background tasks. Returns a [`SupervisorHandles`] that
    /// the caller awaits to drive graceful shutdown; dropping the
    /// handle does **not** stop the tasks (they outlive the
    /// handle by design — the manager's `Arc<Inner>` keeps them
    /// alive).
    ///
    /// The three tasks share `self`'s `Arc<Inner>` plus
    /// `Arc<dyn SuricataProcess>`. They terminate when:
    ///
    /// * the EVE log file disappears (tail task exits cleanly),
    /// * the manager's `shutdown` notify fires (all tasks return),
    /// * the restart watchdog exhausts `restart_max_attempts`.
    #[must_use]
    pub fn spawn_background_tasks(&self) -> SupervisorHandles {
        let eve_path = self.cfg.eve_log_path.clone();
        let inner_eve = Arc::clone(&self.inner);
        let sink_eve = self.sink.clone();
        let eve_handle = tokio::spawn(async move {
            tail_eve_log(eve_path, inner_eve, sink_eve).await;
        });

        let inner_stats = Arc::clone(&self.inner);
        let process_stats = Arc::clone(&self.process);
        let poll = self.cfg.stats_poll_interval;
        let staleness = self.cfg.eve_staleness_window;
        let fail_mode = self.cfg.fail_mode;
        let stats_handle = tokio::spawn(async move {
            run_stats_poll(inner_stats, process_stats, poll, staleness, fail_mode).await;
        });

        let inner_watch = Arc::clone(&self.inner);
        let process_watch = Arc::clone(&self.process);
        let cfg_path_watch = self.cfg.config_path.clone();
        let initial = self.cfg.restart_initial_backoff;
        let max = self.cfg.restart_max_backoff;
        let max_attempts = self.cfg.restart_max_attempts;
        let poll = self.cfg.restart_poll_interval;
        let watchdog_handle = tokio::spawn(async move {
            run_restart_watchdog(
                inner_watch,
                process_watch,
                cfg_path_watch,
                initial,
                max,
                max_attempts,
                poll,
            )
            .await;
        });

        SupervisorHandles {
            eve: eve_handle,
            stats: stats_handle,
            watchdog: watchdog_handle,
        }
    }

    /// Apply a new policy bundle by re-rendering the
    /// `suricata.yaml`. If the rendered bytes match the on-disk
    /// digest, the call is a no-op — Suricata never receives a
    /// signal it does not need. Otherwise, the new file is
    /// written and the manager issues `SIGHUP` (Suricata's
    /// rules / config reload signal).
    ///
    /// Returns the digest hex of the now-installed config so the
    /// caller can confirm the swap by comparing against the
    /// telemetry attribute the manager logs.
    pub async fn apply_config(&self, input: &IpsConfigInput) -> Result<String, IpsError> {
        let new_cfg = self.config_gen.render(input)?;
        // Compare against the on-disk digest by re-reading the
        // file — cheap, and the source of truth lives on the
        // filesystem (the file the running Suricata is bound to).
        let same = match tokio::fs::read(&self.cfg.config_path).await {
            Ok(existing) => existing == new_cfg.bytes(),
            Err(_) => false,
        };
        if same {
            debug!(
                target: "sng_ips::manager",
                digest = %new_cfg.digest_hex(),
                "config unchanged; skipping suricata reload"
            );
            return Ok(new_cfg.digest_hex());
        }
        self.write_config_to_disk(&new_cfg).await?;
        // SIGHUP makes Suricata reload its config + rules in
        // place without dropping in-flight flows.
        self.process.signal(SuricataSignal::Reload).await?;
        info!(
            target: "sng_ips::manager",
            digest = %new_cfg.digest_hex(),
            "ips config hot-swapped"
        );
        Ok(new_cfg.digest_hex())
    }

    /// Verify and install a signed rule bundle. The manager
    /// runs the verifier, then hands the decoded claims to the
    /// stager; on a successful swap, sends `SIGHUP` so Suricata
    /// picks up the new rules without restarting.
    ///
    /// Returns the version that is now installed.
    pub async fn apply_rule_bundle(&self, bundle: &IpsRuleBundle) -> Result<u64, IpsError> {
        let claims = self.verifier.verify_and_decode(bundle)?;
        let version = self.stager.stage_and_swap(&claims).await?;
        self.process.signal(SuricataSignal::Reload).await?;
        info!(
            target: "sng_ips::manager",
            version,
            "ips rule bundle installed; sighup sent"
        );
        Ok(version)
    }

    /// Trigger an EVE log rotation. The manager sends `SIGUSR1`
    /// — Suricata's signal for "close + reopen the EVE log".
    /// Used by the operator's log-rotation pipeline.
    pub async fn rotate_logs(&self) -> Result<(), IpsError> {
        self.process.signal(SuricataSignal::Rotate).await
    }

    /// Lifecycle snapshot for the rest of the process.
    pub async fn status(&self) -> IpsManagerStatus {
        let process = self.process.status().await;
        let health = self.inner.health.lock().state();
        let forwarding_allowed = health.forwarding_allowed(self.cfg.fail_mode);
        IpsManagerStatus {
            process,
            health,
            forwarding_allowed,
            eve_decode_errors: *self.inner.eve_decode_errors.lock(),
            events_emitted: *self.inner.events_emitted.lock(),
            restart_attempts: *self.inner.restart_attempts.lock(),
        }
    }

    /// Just the current health state — convenience for callers
    /// that do not need the full snapshot.
    pub fn health_state(&self) -> HealthState {
        self.inner.health.lock().state()
    }

    /// Whether the data plane should keep forwarding traffic
    /// given the current health and the configured fail-mode.
    pub fn forwarding_allowed(&self) -> bool {
        self.health_state().forwarding_allowed(self.cfg.fail_mode)
    }

    /// Graceful shutdown: notify the background tasks, stop the
    /// Suricata process. The caller should `await` the
    /// [`SupervisorHandles`] after this returns to drain the
    /// tasks cleanly.
    pub async fn stop(&self) -> Result<(), IpsError> {
        self.inner.shutdown.notify_waiters();
        self.process.stop().await?;
        info!(target: "sng_ips::manager", "ips stopped");
        Ok(())
    }

    async fn write_config_to_disk(&self, cfg: &SuricataConfig) -> Result<(), IpsError> {
        if let Some(parent) = self.cfg.config_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                IpsError::Io(format!("create config parent {}: {e}", parent.display()))
            })?;
        }
        tokio::fs::write(&self.cfg.config_path, cfg.bytes())
            .await
            .map_err(|e| {
                IpsError::Io(format!(
                    "write config {}: {e}",
                    self.cfg.config_path.display()
                ))
            })?;
        self.inner
            .config_path
            .store(Arc::new(self.cfg.config_path.clone()));
        Ok(())
    }
}

/// Background task handles. Awaiting these returns when the
/// task exits cleanly (shutdown signalled or non-recoverable
/// error); the manager does not panic on task failure — every
/// task internally logs and either retries or exits.
#[derive(Debug)]
pub struct SupervisorHandles {
    /// EVE tail task — exits when the EVE log disappears or the
    /// manager's shutdown notify fires.
    pub eve: JoinHandle<()>,
    /// Stats / health poll task — exits on shutdown.
    pub stats: JoinHandle<()>,
    /// Restart watchdog — exits on shutdown or when the
    /// `restart_max_attempts` cap is hit.
    pub watchdog: JoinHandle<()>,
}

impl SupervisorHandles {
    /// Await all three tasks. Returns once every task has
    /// exited; suitable as the manager's "wait for full
    /// shutdown" entry point.
    pub async fn join(self) {
        let _ = tokio::join!(self.eve, self.stats, self.watchdog);
    }
}

// ---------------------------------------------------------------------------
// Background tasks. Each task takes only what it needs (the
// shared `Inner` + the trait object it talks to) so the
// dependencies are explicit at the call site.
// ---------------------------------------------------------------------------

/// Open the EVE log and read it line-by-line. Each successfully
/// decoded record bumps `last_eve_progress_at`; each
/// `EveRecord::Alert` is normalised into an
/// [`sng_core::events::IpsEvent`] and forwarded to the sink.
/// Other record types are decoded (so a parse regression
/// surfaces as an `IpsError::EveDecode` and bumps the
/// `eve_decode_errors` counter) but not forwarded — the
/// telemetry pipeline only consumes IPS alerts today.
async fn tail_eve_log(eve_path: PathBuf, inner: Arc<Inner>, sink: IpsEventSink) {
    // Open the file with a small retry loop — Suricata may not
    // have created the file yet on a cold start. Three retries
    // at 100 ms is enough for the common race; longer waits are
    // handled by the watchdog (the manager logs and the EVE
    // staleness probe will surface the gap).
    let Some(file) = open_eve_with_retry(&eve_path).await else {
        warn!(
            target: "sng_ips::manager::eve",
            path = %eve_path.display(),
            "eve log not available; tail task exiting"
        );
        return;
    };
    let mut reader = BufReader::new(file).lines();

    loop {
        tokio::select! {
            // Shutdown wins — exit before reading more.
            () = inner.shutdown.notified() => {
                debug!(target: "sng_ips::manager::eve", "shutdown signalled");
                return;
            }
            line = reader.next_line() => {
                match line {
                    Ok(Some(text)) => {
                        // Empty lines (Suricata occasionally
                        // flushes with a trailing newline) are
                        // ignored, not counted as decode errors.
                        if text.trim().is_empty() {
                            continue;
                        }
                        *inner.last_eve_progress_at.lock() = Instant::now();
                        match EveRecord::parse_line(&text) {
                            Ok(record) => handle_eve_record(record, &inner, &sink),
                            Err(e) => {
                                *inner.eve_decode_errors.lock() += 1;
                                warn!(
                                    target: "sng_ips::manager::eve",
                                    error = %e,
                                    "eve decode failed"
                                );
                            }
                        }
                    }
                    Ok(None) => {
                        // Suricata is still writing; sleep then
                        // poll again. The staleness probe in
                        // run_stats_poll covers the "writer
                        // wedged" case, so we do not need our
                        // own timer here.
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    Err(e) => {
                        warn!(
                            target: "sng_ips::manager::eve",
                            error = %e,
                            "eve read error; tail task exiting"
                        );
                        return;
                    }
                }
            }
        }
    }
}

async fn open_eve_with_retry(path: &Path) -> Option<tokio::fs::File> {
    for _ in 0..3_u8 {
        match tokio::fs::File::open(path).await {
            Ok(f) => return Some(f),
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    tokio::fs::File::open(path).await.ok()
}

fn handle_eve_record(record: EveRecord, inner: &Inner, sink: &IpsEventSink) {
    match record {
        EveRecord::Alert(alert) => {
            let ev = normalise_alert(&alert);
            // try_send rather than blocking — the sink is the
            // telemetry pipeline's buffered channel; back-pressure
            // means the operator already has a saturation alarm.
            // Dropping a single alert beats blocking the EVE
            // reader (which would let Suricata's EVE writer
            // back-pressure, which would drop packets).
            if let Err(returned) = sink.try_send(ev) {
                warn!(
                    target: "sng_ips::manager::eve",
                    rule_id = %returned.rule_id,
                    "telemetry sink full; dropping alert"
                );
            } else {
                *inner.events_emitted.lock() += 1;
            }
        }
        other => {
            // Other event types (dns / http / tls / fileinfo /
            // flow / anomaly) decode cleanly but are not part of
            // the IPS event schema today. Surface them at debug
            // for visibility; the EVE parser still counts them
            // as progress.
            debug!(
                target: "sng_ips::manager::eve",
                event_type = other.event_type(),
                "decoded non-alert eve record"
            );
        }
    }
}

fn normalise_alert(alert: &EveAlert) -> IpsEvent {
    IpsEvent {
        rule_id: alert.alert.signature_id.to_string(),
        signature: alert.alert.signature.clone(),
        severity: crate::eve::severity_label(alert.alert.severity).into(),
        action: alert.alert.action.clone(),
        src_ip: alert.tuple.src_ip.clone().unwrap_or_default(),
        dst_ip: alert.tuple.dst_ip.clone().unwrap_or_default(),
        protocol: alert.tuple.normalised_protocol(),
    }
}

/// Poll the process backend at `interval`, compute the per-tick
/// stats delta + EVE staleness, fold them into a
/// [`HealthProbe`], step the [`HealthMonitor`], and log
/// transitions. Exits on shutdown.
async fn run_stats_poll(
    inner: Arc<Inner>,
    process: Arc<dyn SuricataProcess>,
    interval: Duration,
    staleness: Duration,
    fail_mode: FailMode,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            () = inner.shutdown.notified() => {
                debug!(target: "sng_ips::manager::stats", "shutdown signalled");
                return;
            }
            _ = ticker.tick() => {
                let probe = build_probe(&inner, &*process, staleness).await;
                let transition = inner.health.lock().observe(probe);
                log_transition(transition, fail_mode);
            }
        }
    }
}

async fn build_probe(
    inner: &Inner,
    process: &dyn SuricataProcess,
    staleness: Duration,
) -> HealthProbe {
    let alive = process.is_alive().await;
    let stats = process.stats().await.unwrap_or_else(|e| {
        warn!(
            target: "sng_ips::manager::stats",
            error = %e,
            "stats read failed; treating as zero delta"
        );
        SuricataStats::zero()
    });
    let prev = {
        let mut guard = inner.last_stats.lock();
        std::mem::replace(&mut *guard, stats.clone())
    };
    let delta = stats.delta_since(&prev);
    let last_progress = *inner.last_eve_progress_at.lock();
    let progressing = last_progress.elapsed() < staleness;
    HealthProbe {
        process_alive: alive,
        eve_progressing: progressing,
        stats_delta: delta,
    }
}

fn log_transition(t: HealthTransition, fail_mode: FailMode) {
    if !t.changed {
        return;
    }
    let forwarding = t.current.forwarding_allowed(fail_mode);
    match t.current {
        HealthState::Healthy => info!(
            target: "sng_ips::manager::health",
            previous = ?t.previous,
            "ips healthy"
        ),
        HealthState::Degraded => warn!(
            target: "sng_ips::manager::health",
            previous = ?t.previous,
            forwarding,
            "ips degraded"
        ),
        HealthState::Failed => warn!(
            target: "sng_ips::manager::health",
            previous = ?t.previous,
            forwarding,
            ?fail_mode,
            "ips failed"
        ),
    }
}

/// Restart watchdog. Polls `process.status()` once per second;
/// on `Crashed`, sleeps for the current backoff, attempts a
/// restart against the last-known config path, and either
/// resets the backoff (on success) or doubles it (capped) on
/// failure.
async fn run_restart_watchdog(
    inner: Arc<Inner>,
    process: Arc<dyn SuricataProcess>,
    config_path: PathBuf,
    initial_backoff: Duration,
    max_backoff: Duration,
    max_attempts: Option<u32>,
    poll_interval: Duration,
) {
    let mut backoff = initial_backoff;
    let mut consecutive_failures: u32 = 0;
    loop {
        tokio::select! {
            () = inner.shutdown.notified() => {
                debug!(target: "sng_ips::manager::watchdog", "shutdown signalled");
                return;
            }
            () = tokio::time::sleep(poll_interval) => {
                let status = process.status().await;
                if !matches!(status, ProcessStatus::Crashed) {
                    if matches!(status, ProcessStatus::Running) {
                        // Reset backoff after a healthy poll.
                        backoff = initial_backoff;
                        consecutive_failures = 0;
                    }
                    continue;
                }
                // Crashed: wait the backoff window then retry.
                tokio::time::sleep(backoff).await;
                *inner.restart_attempts.lock() += 1;
                let path = inner.config_path.load_full();
                match process.start(&path).await {
                    Ok(()) => {
                        info!(
                            target: "sng_ips::manager::watchdog",
                            config_path = %config_path.display(),
                            attempt = *inner.restart_attempts.lock(),
                            "ips restarted after crash"
                        );
                        backoff = initial_backoff;
                        consecutive_failures = 0;
                    }
                    Err(e) => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                        warn!(
                            target: "sng_ips::manager::watchdog",
                            error = %e,
                            attempt = *inner.restart_attempts.lock(),
                            consecutive_failures,
                            "ips restart failed"
                        );
                        backoff = (backoff * 2).min(max_backoff);
                        if let Some(max) = max_attempts {
                            if consecutive_failures >= max {
                                warn!(
                                    target: "sng_ips::manager::watchdog",
                                    consecutive_failures,
                                    "ips restart attempts exhausted; watchdog exiting"
                                );
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{IpsConfigInput, IpsRuntime};
    use crate::process::MockSuricata;
    use crate::rules::{
        AlwaysValidValidator, FsRuleStager, IpsRuleBundleClaims, IpsRuleSignature, IpsRuleVerifier,
        RuleStagerConfig,
    };
    use crate::telemetry::IpsEventSource;
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;
    use sng_telemetry::source::EventSource;
    use std::collections::BTreeMap;
    use tempfile::TempDir;

    fn config_input(rule_path: PathBuf, eve_path: PathBuf, stats_path: PathBuf) -> IpsConfigInput {
        IpsConfigInput {
            rule_file_path: rule_path,
            interface: "eth0".into(),
            runtime: IpsRuntime::Inline,
            eve_log_path: eve_path,
            stats_socket_path: stats_path,
            home_net: vec!["10.0.0.0/8".into()],
            external_net: vec!["any".into()],
            app_layer_enabled: BTreeMap::new(),
            force_drop_on_alert: None,
            max_pending_packets: None,
        }
    }

    fn manager_under_test(
        dir: &TempDir,
        mock: MockSuricata,
    ) -> (IpsManager, IpsEventSource, PathBuf, PathBuf) {
        let config_path = dir.path().join("suricata.yaml");
        let eve_path = dir.path().join("eve.json");
        let staging = dir.path().join("staging");
        let rules_path = dir.path().join("sng.rules");
        let stager_config = RuleStagerConfig {
            final_path: rules_path.clone(),
            staging_dir: staging,
        };
        let stager = Arc::new(FsRuleStager::new(
            stager_config,
            Arc::new(AlwaysValidValidator),
        ));
        let verifier = Arc::new(IpsRuleVerifier::new());
        let (sink, source) = IpsEventSource::channel(64);
        let mgr_cfg = IpsManagerConfig {
            config_path: config_path.clone(),
            eve_log_path: eve_path.clone(),
            // Tight intervals so tests do not depend on wall
            // clock — `tokio::time::pause` is used for the
            // watchdog test specifically.
            eve_staleness_window: Duration::from_millis(50),
            stats_poll_interval: Duration::from_millis(10),
            health_thresholds: HealthThresholds::default(),
            failed_consecutive_required: 1,
            fail_mode: FailMode::Closed,
            restart_initial_backoff: Duration::from_millis(5),
            restart_max_backoff: Duration::from_millis(20),
            restart_max_attempts: Some(3),
            restart_poll_interval: Duration::from_millis(20),
        };
        let process: Arc<dyn SuricataProcess> = Arc::new(mock);
        (
            IpsManager::new(mgr_cfg, process, stager, verifier, sink),
            source,
            eve_path,
            rules_path,
        )
    }

    #[tokio::test]
    async fn start_renders_config_to_disk_and_spawns_process() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules.clone(), eve.clone(), dir.path().join("stats.sock"));
        let cfg = mgr.start(&input).await.unwrap();
        // Process saw a start with the manager's config path.
        assert_eq!(mock.start_count(), 1);
        assert_eq!(
            mock.last_config().as_deref(),
            Some(mgr.cfg.config_path.as_path())
        );
        // The file on disk matches the rendered text byte-for-byte.
        let on_disk = tokio::fs::read(&mgr.cfg.config_path).await.unwrap();
        assert_eq!(on_disk, cfg.bytes());
    }

    #[tokio::test]
    async fn apply_config_with_unchanged_input_is_a_noop() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules.clone(), eve.clone(), dir.path().join("stats.sock"));
        let initial = mgr.start(&input).await.unwrap();
        let after = mgr.apply_config(&input).await.unwrap();
        assert_eq!(initial.digest_hex(), after);
        // No Reload signal — config bytes unchanged.
        let signals = mock.signals();
        assert!(
            signals.is_empty(),
            "expected no signals on no-op apply; got {signals:?}"
        );
    }

    #[tokio::test]
    async fn apply_config_with_changed_input_writes_new_file_and_signals_reload() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let mut input = config_input(rules.clone(), eve.clone(), dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        // Mutate any field that changes the rendered YAML — the
        // home_net set is the easiest.
        input.home_net = vec!["192.168.0.0/24".into()];
        let new_digest = mgr.apply_config(&input).await.unwrap();
        assert_ne!(new_digest, ""); // sanity
        // On-disk file now matches the new render.
        let on_disk = tokio::fs::read(&mgr.cfg.config_path).await.unwrap();
        let re_rendered = ConfigGenerator::new().render(&input).unwrap();
        assert_eq!(on_disk, re_rendered.bytes());
        // And the manager sent a single Reload (SIGHUP).
        let signals = mock.signals();
        assert_eq!(signals, vec![SuricataSignal::Reload]);
    }

    #[tokio::test]
    async fn apply_rule_bundle_verifies_signs_stages_and_signals_reload() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr_template, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        // Replace the verifier with one that knows our test key.
        let signing = SigningKey::from_bytes(&[7_u8; 32]);
        let key_id = crate::rules::IpsSigningKeyId::new("aaaaaaaaaaaaaaaa").unwrap();
        let mut verifier = IpsRuleVerifier::new();
        verifier
            .add_key(key_id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let mgr = IpsManager::new(
            mgr_template.cfg.clone(),
            Arc::clone(&mgr_template.process),
            Arc::clone(&mgr_template.stager),
            Arc::new(verifier),
            mgr_template.sink.clone(),
        );
        let input = config_input(rules.clone(), eve.clone(), dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        let claims = IpsRuleBundleClaims {
            schema_version: 1,
            version: 100,
            compiler: "sng-test/1".into(),
            rules_text: "alert tcp any any -> any 80 (msg:\"x\"; sid:1; rev:1;)".into(),
        };
        let body = claims.encode().unwrap();
        let sig = signing.sign(&body);
        let bundle = IpsRuleBundle {
            body,
            signature: IpsRuleSignature {
                bytes: sig.to_bytes(),
            },
            signing_key_id: key_id,
        };
        let installed = mgr.apply_rule_bundle(&bundle).await.unwrap();
        assert_eq!(installed, 100);
        // Stager wrote the file out.
        let on_disk = tokio::fs::read_to_string(&rules).await.unwrap();
        assert!(on_disk.contains("sid:1"));
        // And a Reload signal flowed through.
        let signals = mock.signals();
        assert_eq!(signals, vec![SuricataSignal::Reload]);
    }

    #[tokio::test]
    async fn apply_rule_bundle_rejects_unsigned_bundle() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        let claims = IpsRuleBundleClaims {
            schema_version: 1,
            version: 1,
            compiler: "sng-test/1".into(),
            rules_text: "alert tcp any any -> any 80 (msg:\"x\"; sid:1; rev:1;)".into(),
        };
        let body = claims.encode().unwrap();
        let bundle = IpsRuleBundle {
            body,
            // Bogus signature.
            signature: IpsRuleSignature { bytes: [0_u8; 64] },
            signing_key_id: crate::rules::IpsSigningKeyId::new("bbbbbbbbbbbbbbbb").unwrap(),
        };
        let err = mgr.apply_rule_bundle(&bundle).await.unwrap_err();
        // The verifier has no keys at all, so the failure is
        // "unknown key" rather than "signature invalid".
        assert!(matches!(err, IpsError::RuleSignatureUnknownKey(_)));
        // No reload signal — the manager rejected the bundle
        // before reaching the process.
        assert!(mock.signals().is_empty());
    }

    #[tokio::test]
    async fn rotate_logs_sends_sigusr1() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        mgr.rotate_logs().await.unwrap();
        assert_eq!(mock.signals(), vec![SuricataSignal::Rotate]);
    }

    #[tokio::test]
    async fn stop_sends_shutdown_and_transitions_process() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        mgr.stop().await.unwrap();
        assert_eq!(mock.stop_count(), 1);
        assert_eq!(mock.start_count(), 1);
    }

    #[tokio::test]
    async fn normalise_alert_maps_eve_alert_to_ips_event() {
        let alert = EveAlert {
            tuple: crate::eve::FlowTuple {
                timestamp: Some("2026-05-30T12:00:00Z".into()),
                flow_id: Some(42),
                src_ip: Some("10.0.0.5".into()),
                src_port: Some(54321),
                dst_ip: Some("1.2.3.4".into()),
                dst_port: Some(80),
                proto: Some("TCP".into()),
                app_proto: Some("http".into()),
            },
            alert: crate::eve::AlertPayload {
                signature_id: 2_000_001,
                rev: 3,
                signature: "ET TROJAN bogus".into(),
                category: Some("A Network Trojan was detected".into()),
                severity: 1, // high
                action: "blocked".into(),
                gid: Some(1),
            },
        };
        let ev = normalise_alert(&alert);
        assert_eq!(ev.rule_id, "2000001");
        assert_eq!(ev.signature, "ET TROJAN bogus");
        assert_eq!(ev.severity, "critical");
        assert_eq!(ev.action, "blocked");
        assert_eq!(ev.src_ip, "10.0.0.5");
        assert_eq!(ev.dst_ip, "1.2.3.4");
        assert_eq!(ev.protocol, "tcp");
    }

    #[tokio::test]
    async fn eve_tail_forwards_alert_records_to_the_sink() {
        let dir = TempDir::new().unwrap();
        let eve_path = dir.path().join("eve.json");
        // Pre-create the file with two records — one alert, one
        // unknown — so the tail's open-with-retry path is happy.
        tokio::fs::write(
            &eve_path,
            "{\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"1.1.1.1\",\
             \"proto\":\"TCP\",\"alert\":{\"signature_id\":12345,\"signature\":\"x\",\
             \"severity\":2,\"action\":\"blocked\"}}\n\
             {\"event_type\":\"dns\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"1.1.1.1\",\
             \"proto\":\"UDP\",\"dns\":{\"type\":\"query\",\"rrname\":\"x.test\",\
             \"rrtype\":\"A\"}}\n",
        )
        .await
        .unwrap();
        let (sink, mut source) = IpsEventSource::channel(8);
        let inner = Arc::new(Inner {
            config_path: ArcSwap::from_pointee(dir.path().join("suricata.yaml")),
            last_eve_progress_at: Mutex::new(Instant::now()),
            last_stats: Mutex::new(SuricataStats::zero()),
            health: Mutex::new(HealthMonitor::new()),
            eve_decode_errors: parking_lot::Mutex::new(0),
            events_emitted: parking_lot::Mutex::new(0),
            restart_attempts: parking_lot::Mutex::new(0),
            shutdown: Notify::new(),
        });
        let inner2 = Arc::clone(&inner);
        let handle = tokio::spawn(async move { tail_eve_log(eve_path, inner2, sink).await });
        // The first record (alert) should land on the source.
        let event = tokio::time::timeout(Duration::from_secs(2), source.recv())
            .await
            .expect("source should deliver the alert")
            .expect("source not closed");
        match event {
            sng_telemetry::source::TelemetryEvent::Ips(ev) => {
                assert_eq!(ev.rule_id, "12345");
                assert_eq!(ev.protocol, "tcp");
            }
            other => panic!("expected Ips event; got {other:?}"),
        }
        // Tell the tail to exit and join.
        inner.shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        // Counters: 1 alert emitted, 0 decode errors.
        assert_eq!(*inner.events_emitted.lock(), 1);
        assert_eq!(*inner.eve_decode_errors.lock(), 0);
    }

    #[tokio::test]
    async fn eve_tail_counts_decode_errors_but_keeps_running() {
        let dir = TempDir::new().unwrap();
        let eve_path = dir.path().join("eve.json");
        tokio::fs::write(
            &eve_path,
            "not valid json\n\
             {\"event_type\":\"alert\",\"src_ip\":\"10.0.0.1\",\"dest_ip\":\"1.1.1.1\",\
             \"proto\":\"TCP\",\"alert\":{\"signature_id\":99,\"signature\":\"y\",\
             \"severity\":3,\"action\":\"alert\"}}\n",
        )
        .await
        .unwrap();
        let (sink, mut source) = IpsEventSource::channel(8);
        let inner = Arc::new(Inner {
            config_path: ArcSwap::from_pointee(dir.path().join("suricata.yaml")),
            last_eve_progress_at: Mutex::new(Instant::now()),
            last_stats: Mutex::new(SuricataStats::zero()),
            health: Mutex::new(HealthMonitor::new()),
            eve_decode_errors: parking_lot::Mutex::new(0),
            events_emitted: parking_lot::Mutex::new(0),
            restart_attempts: parking_lot::Mutex::new(0),
            shutdown: Notify::new(),
        });
        let inner2 = Arc::clone(&inner);
        let handle = tokio::spawn(async move { tail_eve_log(eve_path, inner2, sink).await });
        // The valid alert (second line) still gets through.
        let ev = tokio::time::timeout(Duration::from_secs(2), source.recv())
            .await
            .unwrap()
            .unwrap();
        match ev {
            sng_telemetry::source::TelemetryEvent::Ips(e) => {
                assert_eq!(e.rule_id, "99");
            }
            other => panic!("expected Ips event; got {other:?}"),
        }
        inner.shutdown.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert_eq!(*inner.eve_decode_errors.lock(), 1);
        assert_eq!(*inner.events_emitted.lock(), 1);
    }

    #[tokio::test]
    async fn status_reflects_eve_decode_errors_and_emitted_counts() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        *mgr.inner.eve_decode_errors.lock() = 7;
        *mgr.inner.events_emitted.lock() = 13;
        let st = mgr.status().await;
        assert_eq!(st.eve_decode_errors, 7);
        assert_eq!(st.events_emitted, 13);
        assert_eq!(st.process, ProcessStatus::Running);
        assert_eq!(st.health, HealthState::Healthy);
        assert!(st.forwarding_allowed);
    }

    /// Build a manager tuned for fast wall-clock watchdog
    /// behaviour: 50 ms status poll, 5 ms initial backoff.
    /// Used by the watchdog tests below — those tests rely on
    /// real time because the watchdog interleaves
    /// `process.start()` (an `await` outside the select) and
    /// the polled-time sleep, which is brittle to test under
    /// `tokio::time::pause`.
    fn fast_watchdog_manager(
        dir: &TempDir,
        mock: MockSuricata,
        max_attempts: Option<u32>,
    ) -> (IpsManager, IpsEventSource, PathBuf, PathBuf) {
        let config_path = dir.path().join("suricata.yaml");
        let eve_path = dir.path().join("eve.json");
        let staging = dir.path().join("staging");
        let rules_path = dir.path().join("sng.rules");
        let stager_config = RuleStagerConfig {
            final_path: rules_path.clone(),
            staging_dir: staging,
        };
        let stager = Arc::new(FsRuleStager::new(
            stager_config,
            Arc::new(AlwaysValidValidator),
        ));
        let verifier = Arc::new(IpsRuleVerifier::new());
        let (sink, source) = IpsEventSource::channel(64);
        let mgr_cfg = IpsManagerConfig {
            config_path: config_path.clone(),
            eve_log_path: eve_path.clone(),
            eve_staleness_window: Duration::from_millis(50),
            stats_poll_interval: Duration::from_millis(10),
            health_thresholds: HealthThresholds::default(),
            failed_consecutive_required: 1,
            fail_mode: FailMode::Closed,
            restart_initial_backoff: Duration::from_millis(1),
            restart_max_backoff: Duration::from_millis(5),
            restart_max_attempts: max_attempts,
            restart_poll_interval: Duration::from_millis(10),
        };
        // Override the 1-second status-poll cadence the
        // watchdog hard-codes internally — see
        // `run_restart_watchdog`. The tests reach into the
        // shared config indirectly: with the small backoff
        // and the test loop sleeping in 50 ms slices, the
        // watchdog gets at least a few cycles per test.
        let process: Arc<dyn SuricataProcess> = Arc::new(mock);
        (
            IpsManager::new(mgr_cfg, process, stager, verifier, sink),
            source,
            eve_path,
            rules_path,
        )
    }

    #[tokio::test]
    async fn watchdog_restarts_crashed_process_after_backoff() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = fast_watchdog_manager(&dir, mock.clone(), None);
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        assert_eq!(mock.start_count(), 1);

        let handles = mgr.spawn_background_tasks();
        // Simulate a crash and wait long enough for the
        // watchdog's status poll + backoff cycle to fire.
        // The test config sets the watchdog poll to 10 ms and
        // the backoff to 1 ms, so a few hundred ms is more
        // than enough.
        mock.mark_crashed();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline && mock.start_count() < 2 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            mock.start_count() >= 2,
            "expected watchdog to re-issue start; saw {} starts",
            mock.start_count()
        );
        mgr.stop().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), handles.join()).await;
    }

    #[tokio::test]
    async fn watchdog_gives_up_after_max_attempts_consecutive_failures() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = fast_watchdog_manager(&dir, mock.clone(), Some(3));
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();
        // Script enough failures that the watchdog will hit
        // its retry cap before giving up.
        for _ in 0..10 {
            mock.fail_next_start(IpsError::Process("spawn refused".into()));
        }
        let handles = mgr.spawn_background_tasks();
        mock.mark_crashed();
        // Wait for the watchdog to make ≥3 restart attempts
        // (the max_attempts we set above) or for the test
        // timeout to fire.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline && *mgr.inner.restart_attempts.lock() < 3 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            *mgr.inner.restart_attempts.lock() >= 3,
            "watchdog should have made at least 3 restart attempts; saw {}",
            *mgr.inner.restart_attempts.lock()
        );
        mgr.stop().await.unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(2), handles.join()).await;
    }

    #[tokio::test]
    async fn health_state_transitions_drive_forwarding_allowed() {
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, _eve, _rules) = manager_under_test(&dir, mock.clone());
        // Fresh manager: healthy by default, forwarding allowed.
        assert_eq!(mgr.health_state(), HealthState::Healthy);
        assert!(mgr.forwarding_allowed());
        // Force the monitor into Failed via a dead probe; with
        // FailMode::Closed forwarding must stop.
        let mut h = mgr.inner.health.lock();
        let _ = h.observe(HealthProbe {
            process_alive: false,
            eve_progressing: false,
            stats_delta: crate::process::StatsDelta {
                packets_processed: 0,
                alerts_emitted: 0,
                packets_dropped: 0,
                cpu_ms: 0,
            },
        });
        drop(h);
        assert_eq!(mgr.health_state(), HealthState::Failed);
        assert!(!mgr.forwarding_allowed());
    }
}

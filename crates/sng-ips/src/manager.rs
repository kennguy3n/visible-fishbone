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
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::config::{ConfigGenerator, IpsConfigInput, SuricataConfig};
use crate::error::IpsError;
use crate::eve::EveRecord;
use crate::health::{
    FailMode, HealthMonitor, HealthProbe, HealthState, HealthThresholds, HealthTransition,
};
use crate::process::{ProcessStatus, StatsDelta, SuricataProcess, SuricataSignal, SuricataStats};
use crate::rules::{IpsRuleBundle, IpsRuleVerifier, RuleStager};
use crate::telemetry::{IpsEventSink, SinkSendError};

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
    /// Whether the EVE tail seeks to end-of-file on initial
    /// open. Default `true` — the production-safe posture, which
    /// avoids re-emitting historical alerts from a pre-existing
    /// `eve.json` after a manager restart (those alerts have
    /// already been delivered to the telemetry sink by the
    /// previous manager instance; replaying them would duplicate
    /// every entry on the dashboard). Set to `false` to read
    /// from offset 0 — used by tests that pre-populate the EVE
    /// file before spawning the tail task, and by operators who
    /// explicitly want a one-shot replay (e.g. a forensics tool
    /// that consumes the entire file). Rotation handling is
    /// unaffected: the tail still resyncs to offset 0 of the
    /// new file when `file_identity` reports a change.
    pub eve_tail_seek_to_end: bool,
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
            eve_tail_seek_to_end: true,
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
    /// Number of `event_type: stats` EVE records the manager
    /// pushed into the process backend via `push_stats`. The
    /// health monitor's drop-ratio threshold only has real data
    /// when this counter is monotonically advancing.
    pub stats_records_seen: u64,
    /// Number of times the EVE tail observed a log rotation
    /// (inode change on the watched path) and re-opened the
    /// file. Surfaced for visibility — a non-zero value after
    /// `rotate_logs()` proves the rotate handler ran cleanly.
    pub eve_reopens: u64,
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
    stats_records_seen: parking_lot::Mutex<u64>,
    eve_reopens: parking_lot::Mutex<u64>,
    restart_attempts: parking_lot::Mutex<u32>,
    /// Level-triggered shutdown latch. The previous design used
    /// `tokio::sync::Notify` which is edge-triggered: a
    /// `notify_waiters()` issued while a task is between two
    /// `notified()` registrations is silently dropped on the
    /// floor. The EVE tail's EOF branch in particular sleeps
    /// for 200 ms with no `notified()` future live, so an
    /// unlucky `stop()` could leak that task forever.
    ///
    /// `watch` is level-triggered: any task that calls
    /// `subscribe().changed().await` after the sender published
    /// `true` returns immediately, regardless of when it
    /// subscribed. `stop()` sets the value to `true` exactly
    /// once; tasks loop while the current value is `false`.
    shutdown_tx: watch::Sender<bool>,
}

impl Inner {
    /// Spawn a fresh subscriber pinned to the shutdown latch.
    /// Each background task takes its own receiver so they all
    /// observe the level-true transition independently.
    fn shutdown_rx(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    /// Await the next `false -> true` transition on the latch.
    /// Returns immediately if the latch is already `true` (the
    /// `borrow_and_update` arm covers the already-shut-down
    /// case so a task started after `stop()` exits promptly).
    async fn wait_for_shutdown(rx: &mut watch::Receiver<bool>) {
        if *rx.borrow_and_update() {
            return;
        }
        // `changed()` only resolves on the next send. If the
        // sender has been dropped (impossible while `Inner` is
        // alive, since it owns `shutdown_tx`), exit as if we
        // had been told to shut down.
        let _ = rx.changed().await;
    }
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
            stats_records_seen: parking_lot::Mutex::new(0),
            eve_reopens: parking_lot::Mutex::new(0),
            restart_attempts: parking_lot::Mutex::new(0),
            shutdown_tx: watch::channel(false).0,
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
        // Enforce the same EVE path invariant `apply_config` does.
        // Without this check, a caller can start the manager with
        // an input whose `eve_log_path` differs from the one the
        // manager was constructed with — Suricata will then write
        // its EVE log to one path while the tail task spawned by
        // `spawn_background_tasks` reads from another, silently
        // dropping every alert. The defaults on `IpsManagerConfig`
        // and `IpsConfigInput` are aligned, but a caller who
        // overrides one without the other would still trip this.
        self.ensure_eve_path_matches(input)?;
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

    /// Reject an `IpsConfigInput` whose `eve_log_path` does not
    /// match the path the manager (and its tail task) are bound
    /// to. Centralised so `start` and `apply_config` cannot drift
    /// — a future entry point that takes an `IpsConfigInput` only
    /// has to call this helper to inherit the same invariant.
    fn ensure_eve_path_matches(&self, input: &IpsConfigInput) -> Result<(), IpsError> {
        if input.eve_log_path != self.cfg.eve_log_path {
            return Err(IpsError::Config(format!(
                "eve_log_path mismatch: manager bound to {} but config input has {}",
                self.cfg.eve_log_path.display(),
                input.eve_log_path.display()
            )));
        }
        Ok(())
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
        let seek_to_end = self.cfg.eve_tail_seek_to_end;
        let inner_eve = Arc::clone(&self.inner);
        let sink_eve = self.sink.clone();
        let process_eve = Arc::clone(&self.process);
        let eve_handle = tokio::spawn(async move {
            tail_eve_log(eve_path, seek_to_end, inner_eve, sink_eve, process_eve).await;
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
        // Enforce the invariant the manager's tail task depends on:
        // the EVE path baked into the rendered YAML must match the
        // path the tail is reading from. A mismatch would have
        // Suricata writing to one file and the tail reading from
        // another, silently losing every alert until somebody
        // noticed the dashboard had gone quiet. Reject the swap
        // before we ever touch disk or signal the process.
        self.ensure_eve_path_matches(input)?;
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
            stats_records_seen: *self.inner.stats_records_seen.lock(),
            eve_reopens: *self.inner.eve_reopens.lock(),
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
        // `send_replace` updates the latch even if no
        // subscribers exist yet; combined with `borrow_and_update`
        // in `wait_for_shutdown`, this means tasks started after
        // `stop()` still exit promptly.
        let _ = self.inner.shutdown_tx.send_replace(true);
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
// The tail loop runs three branches inline (shutdown, line,
// rotation poll) so the function naturally exceeds clippy's
// 100-line guideline. Splitting them out would require sharing
// the BufReader / inode / counters across helpers behind extra
// `&mut` references with no readability gain; keep them in one
// place and silence the lint at the function level.
#[allow(clippy::too_many_lines)]
async fn tail_eve_log(
    eve_path: PathBuf,
    seek_to_end: bool,
    inner: Arc<Inner>,
    sink: IpsEventSink,
    process: Arc<dyn SuricataProcess>,
) {
    // Open the file with a small retry loop — Suricata may not
    // have created the file yet on a cold start. Three retries
    // at 100 ms is enough for the common race; longer waits are
    // handled by the watchdog (the manager logs and the EVE
    // staleness probe will surface the gap).
    let Some(mut file) = open_eve_with_retry(&eve_path).await else {
        warn!(
            target: "sng_ips::manager::eve",
            path = %eve_path.display(),
            "eve log not available; tail task exiting"
        );
        return;
    };
    // Production posture: skip every line that already exists in
    // the file at the moment we opened it. These lines belong to
    // a previous manager instance and have already been delivered
    // to the telemetry sink; replaying them would duplicate every
    // entry on the dashboard. Rotation is unaffected — the tail
    // resyncs to offset 0 of the *new* file when `file_identity`
    // changes, so post-rotation lines are still observed in full.
    // Tests that pre-populate the EVE file set
    // `eve_tail_seek_to_end = false` to keep the replay behaviour.
    if seek_to_end {
        if let Err(e) = file.seek(std::io::SeekFrom::End(0)).await {
            warn!(
                target: "sng_ips::manager::eve",
                path = %eve_path.display(),
                error = %e,
                "failed to seek EVE log to end on initial open; falling back to offset 0 (may replay historical alerts)"
            );
        }
    }
    let mut current_inode = file_identity(&eve_path).await;
    let mut reader = BufReader::new(file).lines();
    let mut shutdown_rx = inner.shutdown_rx();

    loop {
        tokio::select! {
            // Shutdown wins — exit before reading more.
            () = Inner::wait_for_shutdown(&mut shutdown_rx) => {
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
                            Ok(record) => {
                                handle_eve_record(record, &inner, &sink, &*process).await;
                            }
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
                        // Reached EOF on the current file handle.
                        // Two reasons this happens in production:
                        //   1. Suricata is between flushes —
                        //      the same inode is still the live
                        //      log; we just need to wait.
                        //   2. Operator's logrotate moved the
                        //      old file aside (or `SIGHUP`'d
                        //      Suricata to reopen) and the path
                        //      now points at a brand-new inode
                        //      that we never attached to.
                        //
                        // `file_identity` returns either an
                        // `(st_dev, st_ino)` pair (Unix) or a
                        // size-only sentinel (non-Unix). The
                        // platform-aware comparison lives on
                        // `FileIdentity::rotated_from` so the
                        // tail loop does not have to encode the
                        // semantics for each platform. On Unix any
                        // identity change is a rotation; on
                        // non-Unix only a *shrink* counts — the
                        // append-during-flush case keeps the size
                        // monotonically growing and must NOT
                        // trigger a reopen, otherwise the tail
                        // would re-emit every previously-processed
                        // alert on every EOF tick.
                        let now = file_identity(&eve_path).await;
                        let rotated = match (current_inode, now) {
                            (Some(prev), Some(cur)) => cur.rotated_from(&prev),
                            // File disappeared (rotation step is
                            // mid-rename) — treat as rotation; the
                            // open_eve_with_retry loop will wait
                            // for the new file to materialise.
                            (Some(_), None) => true,
                            // We never observed an identity to
                            // begin with (e.g. a /proc-style FS
                            // that doesn't expose inodes). Fall
                            // through to the sleep+continue path.
                            _ => false,
                        };
                        if rotated {
                            info!(
                                target: "sng_ips::manager::eve",
                                path = %eve_path.display(),
                                previous = ?current_inode,
                                current = ?now,
                                "eve log rotated; reopening"
                            );
                            if let Some(new_file) = open_eve_with_retry(&eve_path).await {
                                current_inode = file_identity(&eve_path).await;
                                reader = BufReader::new(new_file).lines();
                                *inner.eve_reopens.lock() += 1;
                            } else {
                                warn!(
                                    target: "sng_ips::manager::eve",
                                    path = %eve_path.display(),
                                    "eve log unavailable after rotation; tail task exiting"
                                );
                                return;
                            }
                            continue;
                        }
                        // Same inode, still EOF — Suricata is
                        // mid-flush. Sleep then poll again. The
                        // staleness probe in run_stats_poll
                        // covers the "writer wedged" case.
                        //
                        // Wrap the sleep in a select against the
                        // shutdown latch so a `stop()` issued
                        // during the 200 ms idle window unblocks
                        // the task immediately (rather than
                        // waiting up to 200 ms per cycle for the
                        // next outer-select iteration).
                        tokio::select! {
                            () = Inner::wait_for_shutdown(&mut shutdown_rx) => {
                                debug!(
                                    target: "sng_ips::manager::eve",
                                    "shutdown signalled mid-EOF sleep"
                                );
                                return;
                            }
                            () = tokio::time::sleep(Duration::from_millis(200)) => {}
                        }
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

/// Cross-platform file identity used by the EVE tail to detect
/// log rotation. The two variants encode the rotation semantics
/// the underlying platform actually supports:
///
/// * On Unix we have an authoritative `(st_dev, st_ino)` pair.
///   Any change to either field means the path now resolves to a
///   different on-disk inode — i.e. a rotation. `==` / `!=` is
///   the right primitive.
/// * On non-Unix we only have file size to work with, and
///   Suricata is *constantly* appending to the live EVE log
///   between flushes. Using `!=` here would fire on every EOF
///   tick during normal operation and force the tail to reopen
///   from offset 0, re-emitting every previously-processed
///   alert to the telemetry sink. The only signal a portable
///   `len()` reading can reliably give us is *shrink*: a smaller
///   size than the cached value means the file was truncated
///   (logrotate `copytruncate`) or replaced with a fresh,
///   shorter file. Growth is the normal append path and must
///   NOT count as rotation.
///
/// Encoding the comparison on the type itself (rather than at
/// the call site) makes the platform difference impossible to
/// get wrong from the EVE-tail loop's perspective.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FileIdentity {
    /// Authoritative Unix identity. `dev` is the filesystem the
    /// inode lives on; `ino` is the inode number on that fs.
    Inode { dev: u64, ino: u64 },
    /// Non-Unix fallback. Only the file length is portable.
    /// Constructed only under `#[cfg(not(unix))]` but kept in
    /// the unified enum so `rotated_from` can be a single
    /// platform-agnostic match; the dead-code warning on Unix
    /// builds (where the variant is never constructed) is
    /// intentional and silenced here.
    #[cfg_attr(unix, allow(dead_code))]
    Size(u64),
}

impl FileIdentity {
    /// Did the path rotate relative to a previously captured
    /// identity? See the type-level doc for the per-variant
    /// semantics — most importantly, on `Size` we only flag a
    /// rotation on shrink, never on growth.
    fn rotated_from(&self, prev: &Self) -> bool {
        match (prev, self) {
            (
                Self::Inode {
                    dev: d_prev,
                    ino: i_prev,
                },
                Self::Inode {
                    dev: d_cur,
                    ino: i_cur,
                },
            ) => d_prev != d_cur || i_prev != i_cur,
            (Self::Size(prev_len), Self::Size(cur_len)) => cur_len < prev_len,
            // Variant mismatch (cross-platform recompile of an
            // in-memory cache, etc.) cannot happen in a single
            // process, but if it ever does the safer answer is
            // "rotated" so the tail reopens once and resyncs.
            _ => true,
        }
    }
}

async fn file_identity(path: &Path) -> Option<FileIdentity> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Some(FileIdentity::Inode {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Some(FileIdentity::Size(meta.len()))
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

async fn handle_eve_record(
    record: EveRecord,
    inner: &Inner,
    sink: &IpsEventSink,
    process: &dyn SuricataProcess,
) {
    match record {
        EveRecord::Alert(alert) => {
            // Delegate to `EveAlert::to_ips_event` so both the
            // public conversion API and the live telemetry path
            // produce identical events. The previous inline
            // implementation drifted on missing-IP handling
            // (empty string vs `"unknown"`); a single shared
            // converter prevents that class of bug.
            let ev = alert.to_ips_event();
            // try_send rather than blocking — the sink is the
            // telemetry pipeline's buffered channel; back-pressure
            // means the operator already has a saturation alarm.
            // Dropping a single alert beats blocking the EVE
            // reader (which would let Suricata's EVE writer
            // back-pressure, which would drop packets).
            // Distinguish back-pressure (channel full) from a
            // terminal shutdown (consumer dropped). Conflating
            // them produced misleading "telemetry sink full"
            // log lines when the telemetry pipeline had actually
            // shut down for good.
            match sink.try_send(ev) {
                Ok(()) => *inner.events_emitted.lock() += 1,
                Err(SinkSendError::Full(returned)) => {
                    warn!(
                        target: "sng_ips::manager::eve",
                        rule_id = %returned.rule_id,
                        "telemetry sink full; dropping alert"
                    );
                }
                Err(SinkSendError::Closed(returned)) => {
                    warn!(
                        target: "sng_ips::manager::eve",
                        rule_id = %returned.rule_id,
                        "telemetry sink closed; consumer has been dropped, dropping alert"
                    );
                }
            }
        }
        EveRecord::Stats(stats) => {
            // Project the nested EVE stats object into the
            // SuricataStats counter set the health monitor
            // gates on. push_stats merges the snapshot into
            // the process backend's cached stats so the next
            // run_stats_poll tick sees real packet/drop counts
            // (the /proc path only fills RSS + CPU).
            let counters = stats.counters();
            let snapshot = SuricataStats {
                packets_processed: counters.packets_processed,
                alerts_emitted: counters.alerts_emitted,
                packets_dropped: counters.packets_dropped,
                rules_loaded: counters.rules_loaded,
                // rss / cpu stay zero here; push_stats merges
                // by field so the live /proc-sourced values
                // are preserved on the backend.
                rss_bytes: 0,
                cpu_ms: 0,
            };
            if let Err(e) = process.push_stats(snapshot).await {
                warn!(
                    target: "sng_ips::manager::eve",
                    error = %e,
                    "push_stats failed; health monitor will see stale counters"
                );
            } else {
                *inner.stats_records_seen.lock() += 1;
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
    let mut shutdown_rx = inner.shutdown_rx();
    loop {
        tokio::select! {
            () = Inner::wait_for_shutdown(&mut shutdown_rx) => {
                debug!(target: "sng_ips::manager::stats", "shutdown signalled");
                return;
            }
            _ = ticker.tick() => {
                let probe = build_probe(&inner, &*process, staleness).await;
                let transition = inner.health.lock().observe(probe);
                // Reset the cumulative restart counter on every
                // transition INTO `Healthy`. The watchdog already
                // resets its own `consecutive_failures` local on a
                // successful restart, but the publicly-visible
                // `restart_attempts` counter on `IpsManagerStatus`
                // is documented as resetting on each healthy
                // transition so dashboards can count restarts
                // per incident rather than per process lifetime.
                if transition.changed && transition.current == HealthState::Healthy {
                    *inner.restart_attempts.lock() = 0;
                }
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
    // Compute the per-interval stats delta *only* when the read
    // actually succeeded. Earlier revisions of this function
    // substituted `SuricataStats::zero()` on read failure and
    // stored it as `last_stats`, which produced a spurious
    // lifetime-sized delta on the *next* successful tick (current
    // - 0 = full counters), inflating alerts-per-second and
    // packets-per-second telemetry the moment Suricata recovered.
    // Saturating subtraction also masked the failure tick itself
    // as a zero delta, so the health monitor could not see the
    // gap. Keep `last_stats` untouched on failure: the recovery
    // tick will then produce the actual cross-failure interval
    // delta (real recovered counter - last known good counter),
    // and the failure tick itself emits a `StatsDelta::zero()`
    // probe so the health monitor still observes a "no progress
    // during this window" signal.
    let stats_delta = match process.stats().await {
        Ok(stats) => {
            let prev = {
                let mut guard = inner.last_stats.lock();
                std::mem::replace(&mut *guard, stats.clone())
            };
            stats.delta_since(&prev)
        }
        Err(e) => {
            warn!(
                target: "sng_ips::manager::stats",
                error = %e,
                "stats read failed; emitting zero delta but keeping last_stats so the recovery tick reports the real interval"
            );
            StatsDelta::zero()
        }
    };
    let last_progress = *inner.last_eve_progress_at.lock();
    let progressing = last_progress.elapsed() < staleness;
    HealthProbe {
        process_alive: alive,
        eve_progressing: progressing,
        stats_delta,
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
    let mut shutdown_rx = inner.shutdown_rx();
    loop {
        tokio::select! {
            () = Inner::wait_for_shutdown(&mut shutdown_rx) => {
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
                // Make the backoff itself interruptible; an
                // operator-initiated `stop()` during a 30-second
                // restart backoff should not hang the manager.
                tokio::select! {
                    () = Inner::wait_for_shutdown(&mut shutdown_rx) => {
                        debug!(
                            target: "sng_ips::manager::watchdog",
                            "shutdown signalled during restart backoff"
                        );
                        return;
                    }
                    () = tokio::time::sleep(backoff) => {}
                }
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
            config_path: config_path.clone(),
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
            // Tests pre-populate the EVE file before the tail
            // task starts; opt out of the production-safe
            // seek-to-end posture so the pre-written lines are
            // observed by the tail.
            eve_tail_seek_to_end: false,
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
    async fn apply_config_rejects_mismatched_eve_log_path() {
        // Regression: the IpsManagerConfig doc promises that the
        // manager validates `input.eve_log_path` against its own
        // bound path on every config swap. Before the fix the
        // check was missing entirely — a caller could pass a
        // mismatched path and Suricata would write EVE output to
        // one file while the tail task read from another,
        // silently losing every alert.
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = manager_under_test(&dir, mock.clone());
        let input = config_input(rules.clone(), eve.clone(), dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();

        // Build an input whose eve_log_path diverges from the
        // manager's bound path.
        let mut bad_input = input.clone();
        bad_input.eve_log_path = dir.path().join("other-eve.json");
        let err = mgr
            .apply_config(&bad_input)
            .await
            .expect_err("apply_config must reject a mismatched eve_log_path");
        match err {
            IpsError::Config(msg) => {
                assert!(
                    msg.contains("eve_log_path mismatch"),
                    "error must name the violated invariant: {msg}"
                );
            }
            other => panic!("expected IpsError::Config, got {other:?}"),
        }
        // The mismatched apply MUST be a no-op on disk + signals.
        // We had a real reload before the fix.
        let signals = mock.signals();
        assert!(
            signals.is_empty(),
            "rejected apply must not have signalled the process; saw {signals:?}"
        );
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
    async fn eve_alert_to_ips_event_maps_fields() {
        // Smoke-cover: the manager used to wrap a private
        // `normalise_alert` helper that just delegated to
        // `EveAlert::to_ips_event`. We deleted the duplicate;
        // this test guards the live mapping path the tail
        // task actually uses.
        let alert = crate::eve::EveAlert {
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
        let ev = alert.to_ips_event();
        assert_eq!(ev.rule_id, "2000001");
        assert_eq!(ev.signature, "ET TROJAN bogus");
        assert_eq!(ev.severity, "critical");
        // Suricata emits `"blocked"` (past tense) but the SNG
        // event schema documents `"block"` — `to_ips_event` runs
        // every EVE `alert.action` through `normalise_suricata_action`
        // before storing it, so the regression contract is the
        // normalised value, not the raw EVE field.
        assert_eq!(ev.action, "block");
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
            stats_records_seen: parking_lot::Mutex::new(0),
            eve_reopens: parking_lot::Mutex::new(0),
            restart_attempts: parking_lot::Mutex::new(0),
            shutdown_tx: watch::channel(false).0,
        });
        let inner2 = Arc::clone(&inner);
        let process_for_tail: Arc<dyn SuricataProcess> = Arc::new(MockSuricata::new());
        let handle = tokio::spawn(async move {
            // Pre-populated EVE file — opt out of the
            // production-safe seek-to-end posture so the lines
            // written before the tail started are observed.
            tail_eve_log(eve_path, false, inner2, sink, process_for_tail).await;
        });
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
        let _ = inner.shutdown_tx.send_replace(true);
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
            stats_records_seen: parking_lot::Mutex::new(0),
            eve_reopens: parking_lot::Mutex::new(0),
            restart_attempts: parking_lot::Mutex::new(0),
            shutdown_tx: watch::channel(false).0,
        });
        let inner2 = Arc::clone(&inner);
        let process_for_tail: Arc<dyn SuricataProcess> = Arc::new(MockSuricata::new());
        let handle = tokio::spawn(async move {
            // Same rationale as the sibling test — EVE file is
            // pre-populated before the tail spawns.
            tail_eve_log(eve_path, false, inner2, sink, process_for_tail).await;
        });
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
        let _ = inner.shutdown_tx.send_replace(true);
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
            config_path: config_path.clone(),
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
            // Same rationale as the sibling helper: tests
            // pre-populate the EVE file.
            eve_tail_seek_to_end: false,
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
    async fn restart_attempts_reset_on_healthy_transition() {
        // Regression: `IpsManagerStatus::restart_attempts` is
        // documented as "Resets on a successful `Healthy`
        // transition", but before the fix the counter was only
        // ever incremented — operators reading the dashboard saw
        // a monotonically growing value that never matched the
        // post-recovery state. Pin the contract: a Crashed →
        // Running → Healthy sequence must zero the counter.
        let dir = TempDir::new().unwrap();
        let mock = MockSuricata::new();
        let (mgr, _source, eve, rules) = fast_watchdog_manager(&dir, mock.clone(), Some(10));
        let input = config_input(rules, eve, dir.path().join("stats.sock"));
        mgr.start(&input).await.unwrap();

        let handles = mgr.spawn_background_tasks();

        // Drive a crash so the watchdog increments
        // `restart_attempts` ≥ 1.
        mock.mark_crashed();
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline && *mgr.inner.restart_attempts.lock() == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let attempts_before_recovery = *mgr.inner.restart_attempts.lock();
        assert!(
            attempts_before_recovery >= 1,
            "watchdog should have bumped restart_attempts at least once before recovery"
        );

        // Force the next stats poll to observe a healthy probe:
        // process alive + eve progressing. The watchdog's next
        // start call returns `Ok` (no `fail_next_start` queued),
        // which flips status back to Running, and `force_alive`
        // pins is_alive() to true while we wait for the stats
        // tick.
        mock.force_alive(true);
        *mgr.inner.last_eve_progress_at.lock() = Instant::now();

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            let st = mgr.status().await;
            if st.health == HealthState::Healthy && *mgr.inner.restart_attempts.lock() == 0 {
                break;
            }
            // Keep tickling the progress timestamp so the stats
            // poll's staleness probe sees eve_progressing=true.
            *mgr.inner.last_eve_progress_at.lock() = Instant::now();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let final_status = mgr.status().await;
        assert_eq!(
            final_status.health,
            HealthState::Healthy,
            "manager should have recovered to Healthy; got {:?}",
            final_status.health
        );
        assert_eq!(
            *mgr.inner.restart_attempts.lock(),
            0,
            "restart_attempts must reset on the Healthy transition; \
             saw {} after recovery (had {} before)",
            *mgr.inner.restart_attempts.lock(),
            attempts_before_recovery
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

    // ---- FileIdentity rotation semantics ----
    //
    // These pin the contract the EVE tail relies on for log
    // rotation. The non-Unix variant must NOT flag a rotation on
    // growth — Suricata appends to the live EVE log continuously
    // between flushes, so a `!=` comparison would re-emit every
    // previously-processed alert on every EOF tick. See the
    // type-level doc on `FileIdentity` for the design rationale.

    #[test]
    fn file_identity_inode_unchanged_is_not_a_rotation() {
        let id = FileIdentity::Inode { dev: 64, ino: 42 };
        assert!(!id.rotated_from(&id));
    }

    #[test]
    fn file_identity_inode_change_flags_rotation() {
        let prev = FileIdentity::Inode { dev: 64, ino: 42 };
        // Same fs, new inode (logrotate move-then-create).
        let cur_new_inode = FileIdentity::Inode { dev: 64, ino: 99 };
        assert!(cur_new_inode.rotated_from(&prev));
        // Same inode number, different filesystem (rare but
        // possible if /var/log is bind-mounted aside).
        let cur_new_dev = FileIdentity::Inode { dev: 65, ino: 42 };
        assert!(cur_new_dev.rotated_from(&prev));
    }

    #[test]
    fn file_identity_size_growth_is_not_a_rotation() {
        // This is the precise BUG_0001 regression guard: the
        // non-Unix path must treat a *larger* size reading as
        // ordinary append, not as a rotation. The previous code
        // used `!=` which would have fired here and forced the
        // tail to reopen + reprocess every previously-seen line.
        let prev = FileIdentity::Size(1_000);
        let cur = FileIdentity::Size(2_000);
        assert!(!cur.rotated_from(&prev));
    }

    #[test]
    fn file_identity_size_shrink_flags_rotation() {
        // copytruncate / file-replacement leaves the new file
        // strictly smaller than the cached size; this is the
        // only signal a portable `len()` reading can give us.
        let prev = FileIdentity::Size(5_000);
        let cur = FileIdentity::Size(0);
        assert!(cur.rotated_from(&prev));
        let cur_shorter = FileIdentity::Size(4_999);
        assert!(cur_shorter.rotated_from(&prev));
    }

    #[test]
    fn file_identity_size_unchanged_is_not_a_rotation() {
        let id = FileIdentity::Size(1_234);
        assert!(!id.rotated_from(&id));
    }

    #[test]
    fn file_identity_variant_mismatch_flags_rotation() {
        // Cross-variant cannot occur in a single process build
        // but the safe answer is "rotated" so the tail reopens
        // once and resyncs.
        let inode = FileIdentity::Inode { dev: 0, ino: 0 };
        let size = FileIdentity::Size(0);
        assert!(inode.rotated_from(&size));
        assert!(size.rotated_from(&inode));
    }
}

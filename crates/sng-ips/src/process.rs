//! Suricata process lifecycle abstraction.
//!
//! The crate never speaks to `/usr/bin/suricata` directly — every
//! call goes through [`SuricataProcess`]. That lets:
//!
//! * production binaries plug in [`ShellSuricata`], which manages
//!   a real `suricata` child via `tokio::process::Command`, and
//! * tests plug in [`MockSuricata`], which scripts the full set of
//!   responses (start, stop, signal, stats, EVE tail) in-process
//!   without ever exec'ing the binary.
//!
//! The trait is intentionally narrow. Anything specific to one
//! deployment (PID file location, unix-socket stats path, log
//! rotation) lives on the implementor, not the trait surface, so
//! a future replacement (e.g. an eBPF / XDP IPS engine) can drop
//! in without touching the manager.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::IpsError;

/// Signals the manager can send to the IDS process. The set is
/// closed at the trait level (rather than exposing a raw `i32`)
/// so the mock can validate exactly what it received, and so a
/// future non-POSIX backend has a clear mapping target.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuricataSignal {
    /// Re-read configuration / rule files without dropping
    /// in-flight flows. Production Suricata listens for SIGHUP.
    Reload,
    /// Re-open log files. Used by log rotation.
    Rotate,
    /// Graceful shutdown — drain workers, flush queues, exit.
    Shutdown,
}

impl SuricataSignal {
    /// Map a logical signal to the POSIX number the production
    /// backend has to send. Kept on the type so the mock and the
    /// shell impl agree on the mapping in a single place.
    #[must_use]
    pub const fn as_posix(self) -> i32 {
        match self {
            // SIGHUP -- conventional config reload.
            Self::Reload => 1,
            // SIGUSR1 -- Suricata's documented log-rotate signal.
            Self::Rotate => 10,
            // SIGTERM -- graceful shutdown.
            Self::Shutdown => 15,
        }
    }
}

/// Lifecycle state of the IDS process from the manager's
/// perspective.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessStatus {
    /// `start` has not been called, or `stop` completed.
    #[default]
    Stopped,
    /// The process is running and the manager observed a PID.
    Running,
    /// The supervised binary exited unexpectedly. The manager
    /// will restart it (with exponential backoff) unless the
    /// operator has marked the subsystem disabled.
    Crashed,
}

/// Snapshot of Suricata's runtime counters, as reported via the
/// stats unix socket / EVE `stats` records. Only the fields the
/// manager actually consumes are modelled — the trait is not a
/// pass-through for every counter Suricata emits.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuricataStats {
    /// Resident-set size in bytes (best-effort; production
    /// reads `/proc/<pid>/status` on Linux).
    pub rss_bytes: u64,
    /// CPU time consumed since process start, in milliseconds.
    pub cpu_ms: u64,
    /// Total packets the capture layer accepted.
    pub packets_processed: u64,
    /// Total alerts the detect engine emitted across all loaded
    /// rule files.
    pub alerts_emitted: u64,
    /// Packets the capture layer dropped because the ring was
    /// full / the worker could not keep up. Used to drive the
    /// `Degraded` health transition.
    pub packets_dropped: u64,
    /// Number of rules the detect engine loaded on the most
    /// recent rule swap.
    pub rules_loaded: u64,
}

impl SuricataStats {
    /// Zero counters — used as the initial value on cold start
    /// and as the seed for the manager's per-interval deltas.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            rss_bytes: 0,
            cpu_ms: 0,
            packets_processed: 0,
            alerts_emitted: 0,
            packets_dropped: 0,
            rules_loaded: 0,
        }
    }

    /// Compute the per-interval deltas from a previous snapshot.
    /// Used by the telemetry path: the manager publishes packets
    /// per second / alerts per second / drop rate over a sliding
    /// window, all computed from successive `SuricataStats`.
    #[must_use]
    pub fn delta_since(&self, prev: &Self) -> StatsDelta {
        StatsDelta {
            packets_processed: self
                .packets_processed
                .saturating_sub(prev.packets_processed),
            alerts_emitted: self.alerts_emitted.saturating_sub(prev.alerts_emitted),
            packets_dropped: self.packets_dropped.saturating_sub(prev.packets_dropped),
            cpu_ms: self.cpu_ms.saturating_sub(prev.cpu_ms),
        }
    }
}

/// Delta between two consecutive [`SuricataStats`] reads. All
/// fields are saturating-subtracted: counter resets (process
/// restart) clamp to zero rather than wrapping.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsDelta {
    pub packets_processed: u64,
    pub alerts_emitted: u64,
    pub packets_dropped: u64,
    pub cpu_ms: u64,
}

impl StatsDelta {
    /// Drop ratio over the interval, as a value in `[0.0, 1.0]`.
    /// Returns `0.0` when no packets were observed (avoids a
    /// `NaN` from a `0 / 0` divide on a quiet interval).
    #[must_use]
    pub fn drop_ratio(&self) -> f64 {
        let total = self.packets_processed.saturating_add(self.packets_dropped);
        if total == 0 {
            return 0.0;
        }
        #[allow(clippy::cast_precision_loss)]
        let ratio = self.packets_dropped as f64 / total as f64;
        ratio
    }
}

/// Process supervision contract. Implementations are responsible
/// for keeping the underlying IDS reachable; the manager only
/// observes status and signals.
#[async_trait]
pub trait SuricataProcess: Send + Sync + std::fmt::Debug {
    /// Spawn the IDS with the supplied config path. Returns once
    /// the manager has observed a PID — not once the IDS has
    /// finished loading rules. The manager uses [`Self::stats`]
    /// to gate "fully up".
    async fn start(&self, config_path: &Path) -> Result<(), IpsError>;
    /// Graceful stop. Implementations should send `Shutdown`,
    /// wait up to the configured grace window, then escalate.
    async fn stop(&self) -> Result<(), IpsError>;
    /// Send a signal to the running process. Returns
    /// [`IpsError::Process`] if no process is currently running.
    async fn signal(&self, sig: SuricataSignal) -> Result<(), IpsError>;
    /// Read the most recent stats snapshot. Implementations may
    /// poll the stats unix socket on demand or serve a cached
    /// snapshot the supervisor updates on a timer — the manager
    /// does not care which.
    async fn stats(&self) -> Result<SuricataStats, IpsError>;
    /// Push a stats snapshot the manager harvested out-of-band
    /// (e.g. by parsing an `event_type: stats` EVE record).
    /// Implementations are expected to merge `update` into the
    /// value [`Self::stats`] returns next, so the health monitor
    /// sees real packet/drop counters instead of zero. The
    /// default implementation is a no-op so backends that
    /// already have a first-class stats path (e.g. a future
    /// `suricatasc`-backed reader) can ignore the EVE feed.
    async fn push_stats(&self, _update: SuricataStats) -> Result<(), IpsError> {
        Ok(())
    }
    /// Is the process currently alive? Implementations may
    /// short-circuit on a cached PID liveness check; an authoritative
    /// answer requires an OS query (`kill(0)` on POSIX).
    async fn is_alive(&self) -> bool;
    /// Current lifecycle state. The manager polls this between
    /// health checks to decide whether to drive a restart.
    async fn status(&self) -> ProcessStatus;
}

/// Production backend: forks a real `suricata` child via
/// `tokio::process::Command`, polls its stats unix socket on
/// demand, and propagates signals via the standard POSIX
/// signal interface (best-effort — tests cover the policy, the
/// platform glue is thin).
#[derive(Clone, Debug)]
pub struct ShellSuricata {
    /// Path to the `suricata` binary. Defaults to `"suricata"` so
    /// the resolution goes through `PATH`. Operators on the
    /// fixed SNG appliance image can pin an absolute path.
    pub binary: PathBuf,
    /// Interface to bind in inline (`AF_PACKET`) mode. Typically
    /// the LAN-side NIC on the edge VM.
    pub interface: String,
    /// Maximum number of seconds to wait for a graceful
    /// `Shutdown` before sending `SIGKILL`. Operators usually
    /// set this slightly below the deployment's restart budget.
    pub grace_period: Duration,
    state: Arc<AsyncMutex<ShellState>>,
}

#[derive(Debug, Default)]
struct ShellState {
    child: Option<Child>,
    status: ProcessStatus,
    last_stats: SuricataStats,
}

impl ShellSuricata {
    /// Construct a shell backend with sensible defaults: `suricata`
    /// resolved via `PATH`, inline-mode AF_PACKET bind to
    /// `interface`, 10-second graceful stop window.
    #[must_use]
    pub fn new(interface: impl Into<String>) -> Self {
        Self {
            binary: PathBuf::from("suricata"),
            interface: interface.into(),
            grace_period: Duration::from_secs(10),
            state: Arc::new(AsyncMutex::new(ShellState::default())),
        }
    }

    /// Override the binary path. Useful on the SNG appliance
    /// image where the binary lives outside `PATH`.
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }

    /// Override the grace period for the graceful-stop path.
    #[must_use]
    pub fn with_grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }

    /// Best-effort RSS read by parsing `/proc/<pid>/status`. The
    /// reported number is what the manager surfaces on the
    /// resource-budget telemetry; if the parse fails we fall
    /// back to zero rather than failing the whole stats call.
    async fn read_rss_bytes(pid: u32) -> u64 {
        let path = format!("/proc/{pid}/status");
        match tokio::fs::read_to_string(&path).await {
            Ok(contents) => parse_rss_from_proc_status(&contents),
            Err(_) => 0,
        }
    }
}

#[async_trait]
impl SuricataProcess for ShellSuricata {
    async fn start(&self, config_path: &Path) -> Result<(), IpsError> {
        let mut state = self.state.lock().await;
        if matches!(state.status, ProcessStatus::Running) && state.child.is_some() {
            return Err(IpsError::Process(
                "suricata already running; call stop() first".into(),
            ));
        }
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-c")
            .arg(config_path)
            .arg("--af-packet")
            .arg(&self.interface)
            // Foreground mode. Suricata's `-D` actually means
            // "daemonise" — the parent process exits immediately
            // and the daemon child reparents to init, which
            // would leave tokio holding a stale child PID and
            // break is_alive(), signal delivery, and the
            // restart watchdog. Foreground is the default when
            // `-D` is omitted; we rely on that so this tokio
            // `Child` handle stays bound to the actual Suricata
            // process for its full lifetime.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let child = cmd
            .spawn()
            .map_err(|e| IpsError::Process(format!("spawn suricata: {e}")))?;
        state.child = Some(child);
        state.status = ProcessStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), IpsError> {
        let mut state = self.state.lock().await;
        let Some(mut child) = state.child.take() else {
            state.status = ProcessStatus::Stopped;
            return Ok(());
        };
        // Graceful stop contract (trait doc):
        //   1. send SIGTERM (signal 15),
        //   2. wait up to `grace_period` for the child to exit,
        //   3. only then escalate to SIGKILL.
        //
        // tokio's `Child::start_kill()` is unconditionally
        // SIGKILL on Unix and would defeat the grace window
        // entirely — Suricata would never flush in-flight
        // flows or close the EVE log cleanly. So we issue the
        // signal ourselves through /bin/kill (matching the
        // pattern in `signal()` above), keep the child handle
        // so we can `wait()` on it, and only escalate if the
        // timeout expires.
        if let Some(pid) = child.id() {
            let sig_num = SuricataSignal::Shutdown.as_posix();
            let kill_res = Command::new("/bin/kill")
                .arg(format!("-{sig_num}"))
                .arg(pid.to_string())
                .output()
                .await;
            match kill_res {
                Ok(out) if out.status.success() => {}
                Ok(out) => {
                    // SIGTERM delivery failed (process already
                    // reaped between `id()` and the kill, EPERM,
                    // etc). Don't fail the stop — fall through
                    // to the escalation path so the supervisor's
                    // "stopped" invariant still holds.
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    tracing::warn!(
                        target: "sng_ips::process::shell",
                        pid,
                        sig = sig_num,
                        stderr = %stderr,
                        "SIGTERM delivery failed; escalating to SIGKILL after grace window"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        target: "sng_ips::process::shell",
                        pid,
                        error = %e,
                        "could not spawn /bin/kill for SIGTERM; escalating to SIGKILL"
                    );
                }
            }
        }
        match tokio::time::timeout(self.grace_period, child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                return Err(IpsError::Process(format!("wait failed: {e}")));
            }
            Err(_) => {
                // Grace period expired — escalate to SIGKILL via
                // tokio's `kill()` (which sends SIGKILL and waits).
                let _ = child.kill().await;
            }
        }
        state.status = ProcessStatus::Stopped;
        Ok(())
    }

    async fn signal(&self, sig: SuricataSignal) -> Result<(), IpsError> {
        let state = self.state.lock().await;
        let Some(child) = state.child.as_ref() else {
            return Err(IpsError::Process(
                "no suricata process to signal; start it first".into(),
            ));
        };
        let pid = child
            .id()
            .ok_or_else(|| IpsError::Process("child has no pid (already reaped)".into()))?;
        // Shell out to /bin/kill — avoids pulling in libc /
        // nix as a hard dep just for the signal path. The
        // command is a flat string of digits + a hardcoded
        // signal number, so there is no shell-injection
        // surface.
        let sig_num = sig.as_posix();
        let out = Command::new("/bin/kill")
            .arg(format!("-{sig_num}"))
            .arg(pid.to_string())
            .output()
            .await
            .map_err(|e| IpsError::Process(format!("kill spawn: {e}")))?;
        if !out.status.success() {
            return Err(IpsError::Process(format!(
                "kill -{sig_num} {pid} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    async fn stats(&self) -> Result<SuricataStats, IpsError> {
        let mut state = self.state.lock().await;
        let pid = state
            .child
            .as_ref()
            .and_then(tokio::process::Child::id)
            .ok_or_else(|| IpsError::Process("no running suricata to query".into()))?;
        // RSS via /proc/<pid>/status — best-effort.
        let rss = Self::read_rss_bytes(pid).await;
        state.last_stats.rss_bytes = rss;
        // CPU from /proc/<pid>/stat — utime+stime fields,
        // converted to ms via the kernel clock tick.
        let cpu_ms = match tokio::fs::read_to_string(format!("/proc/{pid}/stat")).await {
            Ok(contents) => parse_cpu_ms_from_proc_stat(&contents),
            Err(_) => state.last_stats.cpu_ms,
        };
        state.last_stats.cpu_ms = cpu_ms;
        // Packet / alert / rule counters come from the manager's
        // EVE-stats reader via `push_stats()` — see the trait
        // doc. They live in `state.last_stats` already (the
        // push_stats impl writes there); we read them out as-is.
        Ok(state.last_stats.clone())
    }

    async fn push_stats(&self, update: SuricataStats) -> Result<(), IpsError> {
        let mut state = self.state.lock().await;
        // Merge: take packet/alert/rule fields from `update`
        // (the EVE feed) and preserve rss/cpu (the /proc feed
        // owns those). This way two writers can update the
        // same snapshot without clobbering each other.
        state.last_stats.packets_processed = update.packets_processed;
        state.last_stats.alerts_emitted = update.alerts_emitted;
        state.last_stats.packets_dropped = update.packets_dropped;
        state.last_stats.rules_loaded = update.rules_loaded;
        Ok(())
    }

    async fn is_alive(&self) -> bool {
        // Take the lock as `mut` so we can drive the
        // Running→Crashed transition in one place (see
        // `status()` for the same pattern).
        let mut state = self.state.lock().await;
        Self::observe_child_exit(&mut state);
        match state.child.as_ref().and_then(tokio::process::Child::id) {
            Some(pid) => {
                // `kill -0` via /bin/kill: zero exit means the
                // PID exists and is owned by us.
                let res = Command::new("/bin/kill")
                    .arg("-0")
                    .arg(pid.to_string())
                    .output()
                    .await;
                matches!(res, Ok(o) if o.status.success())
            }
            None => false,
        }
    }

    async fn status(&self) -> ProcessStatus {
        // The manager's restart watchdog gates on `Crashed`,
        // so this is where we have to observe an unexpected
        // exit and transition out of `Running`. `try_wait()` is
        // non-blocking; a successful read with `Some(_)` means
        // the child has been reaped (it exited or was signalled),
        // at which point we drop the handle and flip to `Crashed`.
        let mut state = self.state.lock().await;
        Self::observe_child_exit(&mut state);
        state.status
    }
}

impl ShellSuricata {
    /// Drive the Running→Crashed transition by polling
    /// `try_wait()` on the cached child handle. Called by every
    /// status-observing entry point (`status`, `is_alive`) so the
    /// watchdog sees the new state on its next tick regardless of
    /// which method it called.
    fn observe_child_exit(state: &mut ShellState) {
        // Only meaningful while we believe the process is
        // running and we still hold a child handle. A child
        // that has already been taken (e.g. by `stop()`) is
        // either Stopped (clean exit) or Crashed (already
        // observed) — nothing to do either way.
        if !matches!(state.status, ProcessStatus::Running) {
            return;
        }
        let Some(child) = state.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            // Process still running.
            Ok(None) => {}
            // Process exited — reap and flip to Crashed.
            // We use `Crashed` rather than `Stopped` because we
            // didn't initiate the exit (a clean `stop()` takes
            // the child out of state before calling `wait()`,
            // so we'd never observe the exit here).
            Ok(Some(status)) => {
                tracing::warn!(
                    target: "sng_ips::process::shell",
                    ?status,
                    "suricata child exited unexpectedly; flipping to Crashed"
                );
                state.child = None;
                state.status = ProcessStatus::Crashed;
            }
            // try_wait itself failed (extremely rare; would be
            // a kernel-level oddity). Don't mutate state — the
            // next poll will retry.
            Err(e) => {
                tracing::warn!(
                    target: "sng_ips::process::shell",
                    error = %e,
                    "try_wait on suricata child failed; will retry next poll"
                );
            }
        }
    }
}

fn parse_rss_from_proc_status(contents: &str) -> u64 {
    // VmRSS lines look like:  `VmRSS:     12345 kB`.
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let trimmed = rest.trim();
            // Strip the trailing `kB` (may or may not be
            // present in unusual builds).
            let numeric: String = trimmed.chars().take_while(char::is_ascii_digit).collect();
            if let Ok(kb) = numeric.parse::<u64>() {
                return kb.saturating_mul(1024);
            }
        }
    }
    0
}

fn parse_cpu_ms_from_proc_stat(contents: &str) -> u64 {
    // /proc/<pid>/stat has 52+ fields separated by spaces; the
    // command field (index 1) is parenthesised and may contain
    // spaces, so we find the *last* `)` and parse from there.
    let Some(end_of_comm) = contents.rfind(')') else {
        return 0;
    };
    // After ')' we get a leading space then state, ppid, ...
    let rest = &contents[end_of_comm + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // utime is field 14 in /proc/<pid>/stat (1-indexed); after
    // skipping the command we've already consumed the first
    // two fields (pid, comm), so utime is at index 11 in
    // `fields`, stime at index 12. Numbers are in clock ticks.
    if fields.len() < 13 {
        return 0;
    }
    let utime: u64 = fields[11].parse().unwrap_or(0);
    let stime: u64 = fields[12].parse().unwrap_or(0);
    let ticks = utime.saturating_add(stime);
    // Most modern Linux kernels use 100 Hz (CONFIG_HZ=100), so
    // each tick is 10ms. We can't easily query sysconf without
    // libc, and a wrong constant here only affects the
    // telemetry magnitude, not correctness.
    ticks.saturating_mul(10)
}

/// In-process backend used by tests. Records every call made
/// against it and lets the test script the stats / status reads
/// the manager sees.
#[derive(Clone, Debug, Default)]
pub struct MockSuricata {
    inner: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    status: ProcessStatus,
    last_config: Option<PathBuf>,
    /// Cycling stats responses. The next `stats()` call pops the
    /// front of the queue (so the test can simulate a counter
    /// that ticks forward across calls). If empty, the
    /// `current_stats` value is returned instead.
    queued_stats: VecDeque<SuricataStats>,
    /// Sticky stats value — returned by `stats()` once the
    /// queue is empty. Tests use this to model a steady-state
    /// counter once the scripted burst is done.
    current_stats: SuricataStats,
    /// Every signal the manager has ever sent, in order.
    signals: Vec<SuricataSignal>,
    /// Queue of errors to return from successive `start()`
    /// calls. Each call pops one off the front; an empty queue
    /// means `start()` succeeds. Used to simulate launch
    /// failures (bad config, missing binary). Modelled as a
    /// queue rather than a single `Option` so a test can script
    /// a run of consecutive failures (e.g. the supervisor's
    /// restart-with-backoff path).
    fail_next_start: VecDeque<IpsError>,
    /// Same queue shape for `stats()`.
    fail_next_stats: VecDeque<IpsError>,
    /// Forces `is_alive()` to return this value regardless of
    /// `status`. None means "infer from status".
    forced_alive: Option<bool>,
    /// Total start invocations — tests use this to verify the
    /// supervisor's restart-on-crash policy.
    start_count: u32,
    stop_count: u32,
    /// Number of times the manager pushed an EVE-derived stats
    /// snapshot. Tests on the EVE-stats integration assert this
    /// monotonically advances.
    push_stats_calls: u32,
}

impl MockSuricata {
    /// Empty mock — `Stopped`, no scripted responses.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a stats snapshot onto the response queue. Calls to
    /// [`Self::stats`] pop from the front of this queue first.
    pub fn queue_stats(&self, stats: SuricataStats) {
        self.inner.lock().queued_stats.push_back(stats);
    }

    /// Set the sticky stats value returned once the queue is
    /// drained.
    pub fn set_current_stats(&self, stats: SuricataStats) {
        self.inner.lock().current_stats = stats;
    }

    /// Script the next `start()` call to fail with the supplied
    /// error. Calls compose: invoking this `n` times queues `n`
    /// failures, popped one-per-`start()` in FIFO order. Once
    /// the queue drains, `start()` succeeds.
    pub fn fail_next_start(&self, err: IpsError) {
        self.inner.lock().fail_next_start.push_back(err);
    }

    /// Script the next `stats()` call to fail with the supplied
    /// error. Composes the same way as [`Self::fail_next_start`].
    pub fn fail_next_stats(&self, err: IpsError) {
        self.inner.lock().fail_next_stats.push_back(err);
    }

    /// Force the value `is_alive` returns regardless of
    /// `status`.
    pub fn force_alive(&self, alive: bool) {
        self.inner.lock().forced_alive = Some(alive);
    }

    /// Mark the process as having crashed (used by tests that
    /// drive the manager's restart-on-failure path).
    pub fn mark_crashed(&self) {
        let mut s = self.inner.lock();
        s.status = ProcessStatus::Crashed;
    }

    /// Snapshot of the recorded signals so a test can assert on
    /// the supervisor's signal sequence.
    #[must_use]
    pub fn signals(&self) -> Vec<SuricataSignal> {
        self.inner.lock().signals.clone()
    }

    /// Last config path passed to `start`. Useful for asserting
    /// the manager hot-swapped to a new file.
    #[must_use]
    pub fn last_config(&self) -> Option<PathBuf> {
        self.inner.lock().last_config.clone()
    }

    /// Number of times `start` has been invoked.
    #[must_use]
    pub fn start_count(&self) -> u32 {
        self.inner.lock().start_count
    }

    /// Number of times `stop` has been invoked.
    #[must_use]
    pub fn stop_count(&self) -> u32 {
        self.inner.lock().stop_count
    }

    /// Number of times the manager pushed an EVE-derived stats
    /// snapshot via `push_stats`.
    #[must_use]
    pub fn push_stats_calls(&self) -> u32 {
        self.inner.lock().push_stats_calls
    }
}

#[async_trait]
impl SuricataProcess for MockSuricata {
    async fn start(&self, config_path: &Path) -> Result<(), IpsError> {
        let mut s = self.inner.lock();
        // Bump start_count BEFORE the queued-failure check so a
        // test counting attempted starts (vs. successful ones)
        // can use start_count regardless of the queued outcome.
        s.start_count = s.start_count.saturating_add(1);
        if let Some(err) = s.fail_next_start.pop_front() {
            return Err(err);
        }
        s.last_config = Some(config_path.to_path_buf());
        s.status = ProcessStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), IpsError> {
        let mut s = self.inner.lock();
        s.status = ProcessStatus::Stopped;
        s.stop_count = s.stop_count.saturating_add(1);
        Ok(())
    }

    async fn signal(&self, sig: SuricataSignal) -> Result<(), IpsError> {
        let mut s = self.inner.lock();
        if !matches!(s.status, ProcessStatus::Running) {
            return Err(IpsError::Process(format!(
                "cannot signal: process status is {:?}",
                s.status
            )));
        }
        s.signals.push(sig);
        if matches!(sig, SuricataSignal::Shutdown) {
            s.status = ProcessStatus::Stopped;
        }
        Ok(())
    }

    async fn stats(&self) -> Result<SuricataStats, IpsError> {
        let mut s = self.inner.lock();
        if let Some(err) = s.fail_next_stats.pop_front() {
            return Err(err);
        }
        if let Some(next) = s.queued_stats.pop_front() {
            s.current_stats = next.clone();
            return Ok(next);
        }
        Ok(s.current_stats.clone())
    }

    async fn push_stats(&self, update: SuricataStats) -> Result<(), IpsError> {
        // Mirror the production backend's merge semantics: the
        // EVE feed owns packet / alert / rule counters, the
        // /proc feed (which the test fakes out by setting
        // `current_stats` directly) owns rss/cpu. Tests can
        // drive the manager's EVE-stats path end-to-end and
        // then read back `stats()` to confirm the projection
        // arrived intact.
        let mut s = self.inner.lock();
        s.current_stats.packets_processed = update.packets_processed;
        s.current_stats.alerts_emitted = update.alerts_emitted;
        s.current_stats.packets_dropped = update.packets_dropped;
        s.current_stats.rules_loaded = update.rules_loaded;
        s.push_stats_calls = s.push_stats_calls.saturating_add(1);
        Ok(())
    }

    async fn is_alive(&self) -> bool {
        let s = self.inner.lock();
        if let Some(forced) = s.forced_alive {
            return forced;
        }
        matches!(s.status, ProcessStatus::Running)
    }

    async fn status(&self) -> ProcessStatus {
        self.inner.lock().status
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn signal_posix_mapping_is_stable() {
        // The numeric values are part of the wire contract with
        // the running Suricata process — they must not drift.
        assert_eq!(SuricataSignal::Reload.as_posix(), 1); // SIGHUP
        assert_eq!(SuricataSignal::Rotate.as_posix(), 10); // SIGUSR1
        assert_eq!(SuricataSignal::Shutdown.as_posix(), 15); // SIGTERM
    }

    #[test]
    fn stats_zero_is_identity_for_delta_since() {
        let s = SuricataStats {
            rss_bytes: 1_000_000,
            cpu_ms: 200,
            packets_processed: 500,
            alerts_emitted: 7,
            packets_dropped: 0,
            rules_loaded: 1024,
        };
        let delta = s.delta_since(&SuricataStats::zero());
        assert_eq!(delta.packets_processed, 500);
        assert_eq!(delta.alerts_emitted, 7);
        assert_eq!(delta.cpu_ms, 200);
    }

    #[test]
    fn stats_delta_saturates_on_counter_reset() {
        let now = SuricataStats {
            packets_processed: 10,
            ..SuricataStats::zero()
        };
        let prev = SuricataStats {
            packets_processed: 100,
            ..SuricataStats::zero()
        };
        // Process restarted between reads — counter went
        // backwards. The delta should clamp at zero rather
        // than wrap around.
        let delta = now.delta_since(&prev);
        assert_eq!(delta.packets_processed, 0);
    }

    #[test]
    fn drop_ratio_returns_zero_for_quiet_interval() {
        let delta = StatsDelta {
            packets_processed: 0,
            alerts_emitted: 0,
            packets_dropped: 0,
            cpu_ms: 0,
        };
        // 0 / 0 must not yield NaN.
        assert!((delta.drop_ratio() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn drop_ratio_with_packets_observed() {
        let delta = StatsDelta {
            packets_processed: 900,
            alerts_emitted: 0,
            packets_dropped: 100,
            cpu_ms: 0,
        };
        assert!((delta.drop_ratio() - 0.1).abs() < 1e-9);
    }

    #[test]
    fn proc_status_rss_parses_vmrss_line() {
        let sample =
            "Name:\tsuricata\nVmPeak:\t  14000 kB\nVmRSS:\t   12345 kB\nVmSize:\t  20000 kB\n";
        assert_eq!(parse_rss_from_proc_status(sample), 12_345_u64 * 1024);
    }

    #[test]
    fn proc_status_rss_returns_zero_on_missing_field() {
        let sample = "Name:\tsuricata\nState:\tR\n";
        assert_eq!(parse_rss_from_proc_status(sample), 0);
    }

    #[test]
    fn proc_stat_cpu_handles_command_with_spaces() {
        // Command field is parenthesised and may contain
        // spaces; rfind(')') has to land on the closing paren.
        let sample =
            "1234 (suricata Main) S 1 1234 1234 0 -1 4194560 100 0 0 0 50 25 0 0 20 0 1 0\n";
        // utime=50, stime=25, ticks=75 → 750ms
        assert_eq!(parse_cpu_ms_from_proc_stat(sample), 750);
    }

    #[test]
    fn proc_stat_cpu_returns_zero_on_malformed_input() {
        assert_eq!(parse_cpu_ms_from_proc_stat(""), 0);
        assert_eq!(parse_cpu_ms_from_proc_stat("no closing paren"), 0);
        assert_eq!(parse_cpu_ms_from_proc_stat("pid (a) S 1"), 0);
    }

    #[tokio::test]
    async fn mock_start_then_stop_tracks_status() {
        let m = MockSuricata::new();
        assert_eq!(m.status().await, ProcessStatus::Stopped);
        m.start(Path::new("/tmp/test.yaml")).await.unwrap();
        assert_eq!(m.status().await, ProcessStatus::Running);
        assert!(m.is_alive().await);
        assert_eq!(m.start_count(), 1);
        assert_eq!(m.last_config(), Some(PathBuf::from("/tmp/test.yaml")));
        m.stop().await.unwrap();
        assert_eq!(m.status().await, ProcessStatus::Stopped);
        assert!(!m.is_alive().await);
        assert_eq!(m.stop_count(), 1);
    }

    #[tokio::test]
    async fn mock_fail_next_start_returns_error() {
        let m = MockSuricata::new();
        m.fail_next_start(IpsError::Process("simulated".into()));
        let err = m.start(Path::new("/x")).await.unwrap_err();
        assert!(matches!(err, IpsError::Process(_)));
        // The status is unchanged after a failed start.
        assert_eq!(m.status().await, ProcessStatus::Stopped);
        // The error is one-shot — a subsequent start succeeds.
        m.start(Path::new("/x")).await.unwrap();
        assert_eq!(m.status().await, ProcessStatus::Running);
    }

    #[tokio::test]
    async fn mock_signal_requires_running_process() {
        let m = MockSuricata::new();
        let err = m.signal(SuricataSignal::Reload).await.unwrap_err();
        assert!(matches!(err, IpsError::Process(_)));
        // Signals are not recorded if the process was not
        // running.
        assert!(m.signals().is_empty());
    }

    #[tokio::test]
    async fn mock_signal_records_in_order() {
        let m = MockSuricata::new();
        m.start(Path::new("/x")).await.unwrap();
        m.signal(SuricataSignal::Rotate).await.unwrap();
        m.signal(SuricataSignal::Reload).await.unwrap();
        assert_eq!(
            m.signals(),
            vec![SuricataSignal::Rotate, SuricataSignal::Reload]
        );
    }

    #[tokio::test]
    async fn mock_shutdown_signal_transitions_to_stopped() {
        let m = MockSuricata::new();
        m.start(Path::new("/x")).await.unwrap();
        m.signal(SuricataSignal::Shutdown).await.unwrap();
        assert_eq!(m.status().await, ProcessStatus::Stopped);
        assert!(!m.is_alive().await);
    }

    #[tokio::test]
    async fn mock_stats_queue_then_falls_back_to_current() {
        let m = MockSuricata::new();
        m.start(Path::new("/x")).await.unwrap();
        let s1 = SuricataStats {
            packets_processed: 10,
            ..SuricataStats::zero()
        };
        let s2 = SuricataStats {
            packets_processed: 20,
            ..SuricataStats::zero()
        };
        m.queue_stats(s1.clone());
        m.queue_stats(s2.clone());
        let r1 = m.stats().await.unwrap();
        let r2 = m.stats().await.unwrap();
        let r3 = m.stats().await.unwrap();
        assert_eq!(r1.packets_processed, 10);
        assert_eq!(r2.packets_processed, 20);
        // After the queue drains, current_stats sticks.
        assert_eq!(r3.packets_processed, 20);
    }

    #[tokio::test]
    async fn mock_force_alive_overrides_status() {
        let m = MockSuricata::new();
        // Stopped + forced alive=true → is_alive returns true.
        m.force_alive(true);
        assert!(m.is_alive().await);
        // Running + forced alive=false → is_alive returns false.
        let m2 = MockSuricata::new();
        m2.start(Path::new("/x")).await.unwrap();
        m2.force_alive(false);
        assert!(!m2.is_alive().await);
    }

    #[tokio::test]
    async fn mock_mark_crashed_transitions_to_crashed() {
        let m = MockSuricata::new();
        m.start(Path::new("/x")).await.unwrap();
        m.mark_crashed();
        assert_eq!(m.status().await, ProcessStatus::Crashed);
        // is_alive() defaults to "Running ⇒ true, otherwise
        // false" when no forced value is set — Crashed is
        // therefore not alive.
        assert!(!m.is_alive().await);
    }

    #[tokio::test]
    async fn mock_fail_next_stats_returns_error_once() {
        let m = MockSuricata::new();
        m.start(Path::new("/x")).await.unwrap();
        m.fail_next_stats(IpsError::Process("io".into()));
        let err = m.stats().await.unwrap_err();
        assert!(matches!(err, IpsError::Process(_)));
        // Subsequent call succeeds with default stats.
        let ok = m.stats().await.unwrap();
        assert_eq!(ok, SuricataStats::zero());
    }

    #[test]
    fn shell_suricata_defaults_to_path_resolution() {
        let s = ShellSuricata::new("eth1");
        assert_eq!(s.binary, PathBuf::from("suricata"));
        assert_eq!(s.interface, "eth1");
        assert_eq!(s.grace_period, Duration::from_secs(10));
    }

    #[test]
    fn shell_suricata_with_binary_overrides_path() {
        let s = ShellSuricata::new("eth0").with_binary("/usr/sbin/suricata-edge");
        assert_eq!(s.binary, PathBuf::from("/usr/sbin/suricata-edge"));
    }

    #[test]
    fn shell_suricata_with_grace_period_overrides_default() {
        let s = ShellSuricata::new("eth0").with_grace_period(Duration::from_secs(30));
        assert_eq!(s.grace_period, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn shell_suricata_start_errors_when_binary_missing() {
        // /nonexistent/binary cannot be exec'd; start() should
        // surface a Process error rather than panic.
        let s = ShellSuricata::new("eth0").with_binary("/nonexistent/suricata");
        let err = s
            .start(Path::new("/etc/suricata/test.yaml"))
            .await
            .unwrap_err();
        assert!(matches!(err, IpsError::Process(_)));
    }

    #[tokio::test]
    async fn shell_suricata_signal_errors_when_no_process() {
        let s = ShellSuricata::new("eth0");
        let err = s.signal(SuricataSignal::Reload).await.unwrap_err();
        assert!(matches!(err, IpsError::Process(_)));
    }

    #[tokio::test]
    async fn shell_suricata_stop_is_idempotent_with_no_process() {
        let s = ShellSuricata::new("eth0");
        // No child has been started — stop() should still
        // succeed (idempotent for the supervisor's
        // shutdown-everything path).
        s.stop().await.unwrap();
        assert_eq!(s.status().await, ProcessStatus::Stopped);
    }
}

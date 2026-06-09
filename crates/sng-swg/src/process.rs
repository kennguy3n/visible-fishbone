//! Envoy process lifecycle abstraction.
//!
//! The crate never speaks to `/usr/bin/envoy` directly — every
//! call goes through [`EnvoyProcess`]. That lets:
//!
//! * production binaries plug in [`ShellEnvoy`], which manages
//!   a real `envoy` child via `tokio::process::Command`, and
//! * tests plug in [`MockEnvoy`], which scripts the full set of
//!   responses (start, stop, signal, validate, alive) in-process
//!   without ever exec'ing the binary.
//!
//! The trait is intentionally narrow. Anything specific to one
//! deployment (admin socket path, runtime overlay path, hot-
//! restart epoch number) lives on the implementor, not the trait
//! surface, so a future replacement (Pingora, a custom Rust
//! proxy) can drop in without touching the manager.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdout, Command};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

use crate::error::SwgError;

/// Signals the manager can send to Envoy. The set is closed
/// at the trait level (rather than exposing a raw `i32`) so
/// the mock can validate exactly what it received, and so a
/// future non-POSIX backend has a clear mapping target.
///
/// Note: there is no `Reload` variant. Envoy does not honour
/// `SIGHUP` for in-process config reload — its documented
/// hot-restart mechanism requires the legacy `hot-restarter.py`
/// supervisor or `--restart-epoch` shared-memory machinery,
/// neither of which this single-process supervisor implements.
/// Config-change pathways therefore go through
/// [`EnvoyProcess::restart`], a stop-then-start orchestration
/// that's honest about being a brief drain + restart rather
/// than a true hot-swap.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvoySignal {
    /// Re-open log files. Used by log rotation. Envoy honours
    /// `SIGUSR1` for this purpose and the mapping is stable
    /// across Envoy versions.
    Rotate,
    /// Graceful shutdown — drain connections, flush queues,
    /// exit. `SIGTERM`.
    Shutdown,
}

impl EnvoySignal {
    /// Map a logical signal to the POSIX number the production
    /// backend has to send. Kept on the type so the mock and
    /// the shell impl agree on the mapping in a single place.
    #[must_use]
    pub const fn as_posix(self) -> i32 {
        match self {
            // SIGUSR1 — Envoy's documented log-rotate signal.
            Self::Rotate => 10,
            // SIGTERM — graceful shutdown.
            Self::Shutdown => 15,
        }
    }
}

/// Lifecycle state of the Envoy process from the manager's
/// perspective. Identical shape to sng-ips so an operator
/// dashboard that handles one already handles the other.
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

/// Process supervision contract. Implementations are responsible
/// for keeping the underlying proxy reachable; the manager only
/// observes status and signals.
#[async_trait]
pub trait EnvoyProcess: Send + Sync + std::fmt::Debug {
    /// Spawn Envoy with the supplied config path. Returns once
    /// the manager has observed a PID — not once Envoy has
    /// finished binding its listeners. The manager calls
    /// [`Self::is_alive`] on a backoff to gate "fully up".
    ///
    /// Implementations that pipe Envoy's stdout / stderr (the
    /// production [`ShellEnvoy`] backend does, so boot
    /// diagnostics aren't lost) MUST also spawn reader tasks
    /// that continuously drain those pipes. Once Envoy fills
    /// the kernel's ~64 KiB pipe buffer the next `write(2)`
    /// blocks, freezing the event loop while `kill(0)` and
    /// `try_wait()` still report the process alive — the
    /// supervisor's [`Self::is_alive`] check cannot see the
    /// deadlock. The shipped backend wires drainers immediately
    /// after `spawn()` and exercises the path in
    /// `child_with_high_stdout_volume_does_not_deadlock`.
    async fn start(&self, config_path: &Path) -> Result<(), SwgError>;
    /// Graceful stop. Implementations should send `Shutdown`,
    /// wait up to the configured grace window, then escalate.
    async fn stop(&self) -> Result<(), SwgError>;
    /// Send a signal to the running process. Returns
    /// [`SwgError::Process`] if no process is currently running.
    async fn signal(&self, sig: EnvoySignal) -> Result<(), SwgError>;
    /// Apply a new config to a running supervisor. The default
    /// implementation is a graceful stop followed by a start
    /// against the new config path. We do not attempt Envoy
    /// hot-restart here — Envoy's documented hot-restart
    /// mechanism requires either the legacy `hot-restarter.py`
    /// supervisor or the `--restart-epoch` + shared-memory
    /// machinery, neither of which this single-process
    /// supervisor implements. The honest semantics for a
    /// config-change in this architecture is a brief drain +
    /// restart, which is what the default impl does.
    ///
    /// Implementations that bring true hot-restart support
    /// (e.g. via the Envoy admin API's `/runtime_modify` or by
    /// re-introducing `hot-restarter.py`) can override this.
    async fn restart(&self, config_path: &Path) -> Result<(), SwgError> {
        self.stop().await?;
        self.start(config_path).await
    }
    /// Hot-restart Envoy at the given restart epoch.
    ///
    /// Envoy's hot-restart protocol launches the replacement
    /// process with `--restart-epoch <n>` (strictly increasing per
    /// restart); parent and child rendezvous over the domain socket
    /// named by `--base-id`, the child adopts the listening sockets,
    /// and the parent drains in-flight connections then exits — a
    /// true zero-downtime restart.
    ///
    /// The default implementation does **not** perform that
    /// shared-memory handshake: the shipped single-process
    /// [`ShellEnvoy`] has no hot-restarter parent, so it falls back
    /// to a graceful drain + restart via [`Self::restart`], which is
    /// the honest behaviour for this architecture (`stop()` sends
    /// `Shutdown` and waits the grace window, draining connections,
    /// before the fresh `start()`). The `restart_epoch` is still
    /// threaded through so the supervisor's accounting and emitted
    /// telemetry are correct, and so a backend that reintroduces the
    /// hot-restarter (or runs Envoy under `hot-restarter.py`) can
    /// override this to pass the epoch to the child and get true
    /// zero-downtime restarts without any change to the supervisor.
    async fn hot_restart(&self, config_path: &Path, restart_epoch: u32) -> Result<(), SwgError> {
        let _ = restart_epoch;
        self.restart(config_path).await
    }
    /// Validate a candidate config without actually loading it.
    /// In production this calls `envoy --mode validate`; in the
    /// mock it consults a scripted result.
    async fn validate_config(&self, config_path: &Path) -> Result<(), SwgError>;
    /// Is the process currently alive?
    async fn is_alive(&self) -> bool;
    /// Current lifecycle state. The manager polls this between
    /// health checks to decide whether to drive a restart.
    async fn status(&self) -> ProcessStatus;
}

/// Production backend: forks a real `envoy` child via
/// `tokio::process::Command`. The signal path uses
/// `Child::id()` plus `nix::sys::signal::kill` on Unix for
/// best-effort signal delivery. We intentionally do NOT depend
/// on the platform-specific `nix` crate for this — the kill
/// shim is part of the integration boundary the caller can
/// stub in tests.
#[derive(Clone, Debug)]
pub struct ShellEnvoy {
    /// Path to the `envoy` binary. Defaults to `"envoy"` so the
    /// resolution goes through `PATH`. Operators on the fixed
    /// SNG appliance image can pin an absolute path.
    pub binary: PathBuf,
    /// Admin port Envoy binds for the internal management
    /// surface (stats, runtime overrides, log level). Stored on
    /// the type so the manager can spin up a healthcheck client
    /// without re-deriving it.
    pub admin_port: u16,
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
}

impl ShellEnvoy {
    /// Construct a shell backend with sensible defaults: `envoy`
    /// resolved via `PATH`, admin port
    /// [`crate::config::DEFAULT_ADMIN_PORT`], 10-second graceful
    /// stop window. The default admin port is shared with the
    /// renderer so a caller that picks defaults for both does
    /// not produce a renderer/supervisor mismatch — see the
    /// admin-port consistency note on
    /// [`crate::config::EnvoyConfig`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from("envoy"),
            admin_port: crate::config::DEFAULT_ADMIN_PORT,
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

    /// Override the admin port the supervisor expects Envoy to
    /// bind. The port number does not change the spawned
    /// process — Envoy reads its admin port from the config —
    /// but the supervisor needs to know it to perform healthchecks.
    #[must_use]
    pub fn with_admin_port(mut self, port: u16) -> Self {
        self.admin_port = port;
        self
    }

    /// Override the grace period for the graceful-stop path.
    #[must_use]
    pub fn with_grace_period(mut self, grace: Duration) -> Self {
        self.grace_period = grace;
        self
    }
}

impl Default for ShellEnvoy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnvoyProcess for ShellEnvoy {
    async fn start(&self, config_path: &Path) -> Result<(), SwgError> {
        let mut state = self.state.lock().await;
        if matches!(state.status, ProcessStatus::Running) && state.child.is_some() {
            return Err(SwgError::Process(
                "envoy already running; call stop() first".into(),
            ));
        }
        let mut cmd = Command::new(&self.binary);
        cmd.arg("-c")
            .arg(config_path)
            // Concurrency 0 lets Envoy auto-size to the number of
            // online CPUs — same default the unmodified binary
            // picks but spelled out so the spawn line is
            // self-documenting.
            .arg("--concurrency")
            .arg("0")
            // Restart epoch starts at 0; the hot-restart path
            // increments it on subsequent spawns. The supervisor
            // only does cold restarts at v0 (we re-spawn a fresh
            // process on config reload instead of an in-place
            // hot-restart), so the epoch stays at zero.
            .arg("--restart-epoch")
            .arg("0")
            // stdout/stderr are piped so we can forward them to
            // tracing — Envoy writes its access log + stats to
            // the configured sinks but reserves stdout / stderr
            // for boot diagnostics, fatal load errors, panic
            // backtraces, and the only-on-stderr messages that
            // surface when `--mode validate` accepted the config
            // but the live process refuses to come up.
            // `Stdio::null()` would lose those entirely. But
            // leaving the pipes alive *without* a reader
            // deadlocks Envoy once the ~64KiB kernel pipe buffer
            // fills (`write(2)` blocks on a full pipe), causing
            // the process to appear alive to `kill(0)` /
            // `try_wait()` while the event loop silently freezes
            // and traffic stops moving — the manager's
            // `is_alive()` would keep returning `true` and the
            // health monitor would not trip. Spawning drainer
            // tasks below keeps the pipes empty and lifts the
            // lines into structured logs. Same pattern as
            // `sng-ips::process::ShellSuricata::start`.
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Drop the child on supervisor exit so a panicking
            // supervisor doesn't leak an Envoy process.
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .map_err(|e| SwgError::Process(format!("spawn envoy: {e}")))?;
        // Hand stdout / stderr off to dedicated drainer tasks.
        // `Child::stdout` / `Child::stderr` are `Option<Owned>`
        // handles that we `take()` so the tasks own them
        // outright — once `kill_on_drop(true)` fires the pipes
        // close and the drainers exit on EOF, so we do not need
        // to track or join them explicitly.
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(drain_child_stdout(stdout));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(drain_child_stderr(stderr));
        }
        state.child = Some(child);
        state.status = ProcessStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), SwgError> {
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
        // tokio's `Child::start_kill()` is SIGKILL on Unix and
        // would defeat the grace window. We use the platform's
        // raw kill(2) via a helper module (test override).
        let pid = child.id();
        if let Some(pid) = pid {
            // Best-effort SIGTERM via /bin/kill. If the helper
            // fails we still escalate to SIGKILL below, so the
            // result is discarded — what matters is that the
            // kernel accepted the syscall.
            //
            // We shell out instead of linking libc/nix because
            // the SIGTERM path runs once per supervisor stop
            // — not per packet — and adding a hard dep on a
            // platform-specific signal crate is not justified
            // by that frequency. Same pattern as
            // `sng-ips::process::ShellSuricata::stop`.
            let sig_num = EnvoySignal::Shutdown.as_posix();
            let _ = Command::new("/bin/kill")
                .arg(format!("-{sig_num}"))
                .arg(pid.to_string())
                .output()
                .await;
        }
        // Wait the grace period for the child to exit on its
        // own. The select arm covers the case where Envoy honours
        // SIGTERM in well under grace_period — we don't want to
        // sit out the full window unnecessarily.
        let waited = tokio::time::timeout(self.grace_period, child.wait()).await;
        match waited {
            Ok(Ok(_)) => {
                state.status = ProcessStatus::Stopped;
                Ok(())
            }
            // Timed out — escalate to SIGKILL.
            Err(_) => {
                let _ = child.start_kill();
                let _ = child.wait().await;
                state.status = ProcessStatus::Stopped;
                Ok(())
            }
            Ok(Err(e)) => {
                state.status = ProcessStatus::Stopped;
                Err(SwgError::Process(format!("waitpid: {e}")))
            }
        }
    }

    async fn signal(&self, sig: EnvoySignal) -> Result<(), SwgError> {
        let state = self.state.lock().await;
        let Some(child) = state.child.as_ref() else {
            return Err(SwgError::Process(
                "no running envoy process to signal".into(),
            ));
        };
        let pid = child
            .id()
            .ok_or_else(|| SwgError::Process("envoy child has no pid (reaped)".into()))?;
        // Shell out to /bin/kill — same rationale as `stop`:
        // signals happen at supervisor cadence, not per
        // packet, so the syscall-cost of a /bin/kill fork is
        // immaterial and we avoid pulling in libc/nix.
        let sig_num = sig.as_posix();
        let out = Command::new("/bin/kill")
            .arg(format!("-{sig_num}"))
            .arg(pid.to_string())
            .output()
            .await
            .map_err(|e| SwgError::Process(format!("kill spawn: {e}")))?;
        if !out.status.success() {
            return Err(SwgError::Process(format!(
                "kill -{sig_num} {pid} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }

    async fn validate_config(&self, config_path: &Path) -> Result<(), SwgError> {
        // `envoy --mode validate` returns 0 if the config is
        // syntactically valid, non-zero otherwise. We capture
        // stderr so a failure carries the actual diagnostic
        // back to the supervisor — operator's first question
        // on a failed swap is "what did envoy say".
        let out = Command::new(&self.binary)
            .arg("--mode")
            .arg("validate")
            .arg("-c")
            .arg(config_path)
            .output()
            .await
            .map_err(|e| SwgError::Process(format!("spawn envoy --mode validate: {e}")))?;
        if out.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            Err(SwgError::ConfigValidate(stderr.to_string()))
        }
    }

    async fn is_alive(&self) -> bool {
        let mut state = self.state.lock().await;
        let Some(child) = state.child.as_mut() else {
            return false;
        };
        // `Ok(None)` from `try_wait` is the only outcome that
        // means "child is still alive and reapable". The two
        // terminal outcomes — `Ok(Some(_))` (the child exited
        // and `try_wait` reaped it) and `Err(_)` (a platform
        // condition like ECHILD where the child handle is no
        // longer ours to reap, typically because another thread
        // already reaped it) — both indicate the child is no
        // longer alive *and* no longer attached. Both must
        // therefore set status to `Crashed` and clear the child
        // handle so a subsequent [`Self::status`] call agrees
        // with [`Self::is_alive`]. Pre-fix, the `Err` arm fell
        // through with status untouched, so a health probe that
        // read both fields would render an internally
        // inconsistent `ManagerHealth` snapshot (is_alive=false
        // but status=Running). Merging the two terminal arms
        // closes the gap.
        if let Ok(None) = child.try_wait() {
            true
        } else {
            state.status = ProcessStatus::Crashed;
            state.child = None;
            false
        }
    }

    async fn status(&self) -> ProcessStatus {
        self.state.lock().await.status
    }
}

/// In-process Envoy mock. Records every call so tests can
/// assert exact lifecycle order and can script the
/// `validate_config` / `is_alive` results.
#[derive(Clone, Debug, Default)]
pub struct MockEnvoy {
    inner: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    status: ProcessStatus,
    started_with: Vec<PathBuf>,
    stopped_count: usize,
    signals: Vec<EnvoySignal>,
    validated: Vec<PathBuf>,
    /// Scripted validate_config outcome. None means "always
    /// succeed"; Some(err) means every call returns the error.
    validate_result: Option<SwgError>,
    /// Scripted is_alive outcome. None means "report true while
    /// status == Running"; Some(b) overrides.
    is_alive_override: Option<bool>,
    /// Optional gate used by tests to pause `validate_config`
    /// mid-flight so concurrent install / stop / probe paths can
    /// race against a known suspension point. The gate is read
    /// inside `validate_config`, the lock is dropped, and the
    /// gated call awaits `gate.notified()`. Tests release the
    /// pause by calling `gate.notify_one()`. When `None`,
    /// validate completes synchronously — the v0 default for
    /// every existing test.
    validate_gate: Option<Arc<tokio::sync::Notify>>,
    /// Queue of errors to return from successive `start()` calls,
    /// popped one-per-call in FIFO order. Empty => `start()`
    /// succeeds. Lets a supervisor test script a run of consecutive
    /// launch failures (the restart-with-backoff / exhaustion path).
    fail_next_start: std::collections::VecDeque<SwgError>,
    /// Restart epochs recorded by `hot_restart`, in call order. A
    /// supervisor test asserts the epoch increments monotonically.
    hot_restart_epochs: Vec<u32>,
    /// Total `start()` invocations (successful or not) — a
    /// supervisor test counts attempted launches independently of
    /// the scripted outcome.
    start_count: usize,
}

impl MockEnvoy {
    /// Build a mock seeded as Stopped with no scripted
    /// responses.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Force the next `validate_config` calls to fail with
    /// `err`. Returning the mock so tests can chain it onto
    /// construction.
    #[must_use]
    pub fn with_validate_failure(self, err: SwgError) -> Self {
        self.inner.lock().validate_result = Some(err);
        self
    }

    /// Arm a validate failure on an already-constructed mock.
    /// Used by tests that need a successful first install (to
    /// stage a previous-good config on disk) and then a failing
    /// second install (to assert the write-validate-rename
    /// preserves the previous bytes).
    pub fn set_validate_failure(&self, err: SwgError) {
        self.inner.lock().validate_result = Some(err);
    }

    /// Clear any armed validate failure so subsequent calls
    /// succeed again. Useful for tests that recover the mock to
    /// the success path after exercising a failure.
    pub fn clear_validate_failure(&self) {
        self.inner.lock().validate_result = None;
    }

    /// Force the next `is_alive` calls to return `alive`.
    #[must_use]
    pub fn with_alive(self, alive: bool) -> Self {
        self.inner.lock().is_alive_override = Some(alive);
        self
    }

    /// Install a gate that pauses every subsequent
    /// `validate_config` call until the returned
    /// [`tokio::sync::Notify`] receives a `notify_one()`. Used
    /// by concurrency tests that need a deterministic suspension
    /// point inside the install flow (so they can race a
    /// concurrent `stop()` against an in-flight install without
    /// real wall-clock timing).
    ///
    /// Returns the [`Arc<tokio::sync::Notify>`] the test
    /// retains; calling `notify_one()` on it releases the next
    /// gated validate. Each gated call consumes one
    /// `notify_one()` (the gate is single-permit, like a tokio
    /// `Notify`).
    #[must_use]
    pub fn install_validate_gate(&self) -> Arc<tokio::sync::Notify> {
        let notify = Arc::new(tokio::sync::Notify::new());
        self.inner.lock().validate_gate = Some(notify.clone());
        notify
    }

    /// Force `is_alive` / `status` to report a crashed process,
    /// regardless of any prior `is_alive` override. Used by
    /// supervisor tests to drive the restart-on-crash path: the
    /// override is cleared so a subsequent `start()` (issued by the
    /// supervisor's restart) naturally flips the process back to
    /// alive via its `Running` status.
    pub fn mark_crashed(&self) {
        let mut g = self.inner.lock();
        g.status = ProcessStatus::Crashed;
        g.is_alive_override = None;
    }

    /// Script the next `start()` call to fail with `err`. Composes:
    /// invoking this `n` times queues `n` failures, popped
    /// one-per-`start()` in FIFO order. Once the queue drains,
    /// `start()` succeeds.
    pub fn fail_next_start(&self, err: SwgError) {
        self.inner.lock().fail_next_start.push_back(err);
    }

    /// Number of times `start()` has been invoked (successful or
    /// not).
    #[must_use]
    pub fn start_count(&self) -> usize {
        self.inner.lock().start_count
    }

    /// Restart epochs passed to `hot_restart`, in call order.
    #[must_use]
    pub fn hot_restart_epochs(&self) -> Vec<u32> {
        self.inner.lock().hot_restart_epochs.clone()
    }

    /// Snapshot of recorded events — used by tests to assert
    /// the supervisor walked the exact lifecycle order.
    #[must_use]
    pub fn recorded(&self) -> MockRecord {
        let g = self.inner.lock();
        MockRecord {
            started_with: g.started_with.clone(),
            stopped_count: g.stopped_count,
            signals: g.signals.clone(),
            validated: g.validated.clone(),
            status: g.status,
        }
    }
}

/// Snapshot of mock activity. Returned by [`MockEnvoy::recorded`]
/// for test assertions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MockRecord {
    pub started_with: Vec<PathBuf>,
    pub stopped_count: usize,
    pub signals: Vec<EnvoySignal>,
    pub validated: Vec<PathBuf>,
    pub status: ProcessStatus,
}

#[async_trait]
impl EnvoyProcess for MockEnvoy {
    async fn start(&self, config_path: &Path) -> Result<(), SwgError> {
        let mut g = self.inner.lock();
        if matches!(g.status, ProcessStatus::Running) {
            return Err(SwgError::Process(
                "envoy already running; call stop() first".into(),
            ));
        }
        // Count the attempt before consulting the scripted-failure
        // queue so a test counting attempted starts sees every call.
        g.start_count += 1;
        if let Some(err) = g.fail_next_start.pop_front() {
            return Err(err);
        }
        g.started_with.push(config_path.to_path_buf());
        g.status = ProcessStatus::Running;
        Ok(())
    }

    async fn stop(&self) -> Result<(), SwgError> {
        let mut g = self.inner.lock();
        g.stopped_count += 1;
        g.status = ProcessStatus::Stopped;
        Ok(())
    }

    async fn signal(&self, sig: EnvoySignal) -> Result<(), SwgError> {
        let mut g = self.inner.lock();
        if !matches!(g.status, ProcessStatus::Running) {
            return Err(SwgError::Process(
                "no running envoy process to signal".into(),
            ));
        }
        g.signals.push(sig);
        Ok(())
    }

    async fn validate_config(&self, config_path: &Path) -> Result<(), SwgError> {
        // Snapshot the scripted outcome and the gate under the
        // sync lock, then release the lock before awaiting the
        // gate — a sync `parking_lot::Mutex` held across an
        // `.await` would block the tokio worker.
        let (gate, err) = {
            let mut g = self.inner.lock();
            g.validated.push(config_path.to_path_buf());
            // Clone the scripted error so the same value is returned
            // on every call. `SwgError: Clone` (see error.rs) makes
            // this exhaustive across every variant — a future variant
            // added to the taxonomy doesn't silently drop to `Ok(())`
            // the way a per-variant match did before.
            (g.validate_gate.clone(), g.validate_result.clone())
        };
        if let Some(gate) = gate {
            gate.notified().await;
        }
        match err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    async fn is_alive(&self) -> bool {
        let g = self.inner.lock();
        if let Some(o) = g.is_alive_override {
            return o;
        }
        matches!(g.status, ProcessStatus::Running)
    }

    async fn status(&self) -> ProcessStatus {
        self.inner.lock().status
    }

    async fn hot_restart(&self, config_path: &Path, restart_epoch: u32) -> Result<(), SwgError> {
        // Record the epoch (guard dropped before the await), then run
        // the honest graceful-drain restart the default impl provides.
        self.inner.lock().hot_restart_epochs.push(restart_epoch);
        self.restart(config_path).await
    }
}

/// Drain Envoy's stdout into structured logs.
///
/// Stdout carries Envoy's startup banner (listener bringup,
/// cluster init, runtime overlay load) and any unstructured
/// operator messages. None of it is access-log telemetry —
/// access logs go to the configured sinks — so we forward at
/// `debug` level so the volume doesn't drown out the manager's
/// own info-level lifecycle messages, while still being
/// available with `RUST_LOG=sng_swg=debug` when triaging a
/// stuck start.
///
/// The task exits cleanly when stdout closes (process exit or
/// pipe drop triggered by `kill_on_drop`). Any read error is
/// logged once at `warn` and the task ends — we deliberately do
/// not retry, because a broken pipe means the child is gone and
/// the manager's `is_alive()` check will pick that up.
async fn drain_child_stdout(stdout: ChildStdout) {
    let mut lines = BufReader::new(stdout).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => debug!(target: "sng_swg::envoy", "envoy stdout: {line}"),
            Ok(None) => break,
            Err(e) => {
                warn!(target: "sng_swg::envoy", "envoy stdout drain error: {e}");
                break;
            }
        }
    }
}

/// Drain Envoy's stderr into structured logs.
///
/// Stderr is the channel Envoy uses for the diagnostics an
/// operator actually needs to debug a non-starting proxy: bind
/// failures (EADDRINUSE), TLS-context init errors, fatal
/// extension load failures, panic backtraces, and the
/// startup-time validation errors that surface even when
/// `--mode validate` accepted the config statically. We forward
/// at `warn` because every line here is by Envoy's convention
/// something the binary considered worth printing outside the
/// access-log pipeline, and losing them to `Stdio::null()`
/// would make a failing `start()` undebuggable from logs alone.
async fn drain_child_stderr(stderr: ChildStderr) {
    let mut lines = BufReader::new(stderr).lines();
    loop {
        match lines.next_line().await {
            Ok(Some(line)) => warn!(target: "sng_swg::envoy", "envoy stderr: {line}"),
            Ok(None) => break,
            Err(e) => {
                warn!(target: "sng_swg::envoy", "envoy stderr drain error: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;

    #[tokio::test]
    async fn mock_records_start_signal_stop_lifecycle() {
        let m = MockEnvoy::new();
        let path = PathBuf::from("/tmp/envoy.yaml");
        m.start(&path).await.unwrap();
        m.signal(EnvoySignal::Rotate).await.unwrap();
        m.signal(EnvoySignal::Shutdown).await.unwrap();
        m.stop().await.unwrap();

        let rec = m.recorded();
        assert_eq!(rec.started_with, vec![path]);
        assert_eq!(
            rec.signals,
            vec![EnvoySignal::Rotate, EnvoySignal::Shutdown]
        );
        assert_eq!(rec.stopped_count, 1);
        assert_eq!(rec.status, ProcessStatus::Stopped);
    }

    #[tokio::test]
    async fn double_start_returns_error() {
        // The supervisor must detect a double-start so a
        // confused caller doesn't leak processes.
        let m = MockEnvoy::new();
        m.start(Path::new("/tmp/envoy.yaml")).await.unwrap();
        let err = m
            .start(Path::new("/tmp/envoy.yaml"))
            .await
            .expect_err("second start must fail");
        match err {
            SwgError::Process(msg) => assert!(msg.contains("already running"), "{msg}"),
            other => panic!("expected SwgError::Process, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn signal_when_stopped_returns_error() {
        // Sending a signal to a non-running process is a bug,
        // not a no-op — the supervisor wants the error so it
        // can promote the bundle to Crashed and trigger a
        // restart.
        let m = MockEnvoy::new();
        let err = m
            .signal(EnvoySignal::Rotate)
            .await
            .expect_err("signal-while-stopped must fail");
        match err {
            SwgError::Process(msg) => assert!(msg.contains("no running"), "{msg}"),
            other => panic!("expected SwgError::Process, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_config_records_invocation() {
        let m = MockEnvoy::new();
        let path = PathBuf::from("/tmp/envoy.yaml");
        m.validate_config(&path).await.unwrap();
        m.validate_config(&path).await.unwrap();
        let rec = m.recorded();
        assert_eq!(rec.validated, vec![path.clone(), path]);
    }

    #[tokio::test]
    async fn validate_config_returns_scripted_error() {
        let m = MockEnvoy::new().with_validate_failure(SwgError::ConfigValidate("bad yaml".into()));
        let err = m
            .validate_config(Path::new("/tmp/envoy.yaml"))
            .await
            .expect_err("must fail");
        match err {
            SwgError::ConfigValidate(msg) => assert_eq!(msg, "bad yaml"),
            other => panic!("expected ConfigValidate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_config_reproduces_every_swg_error_variant() {
        // Regression test for the per-variant match arm bug:
        // `with_validate_failure` previously matched only three
        // variants explicitly (ConfigValidate, Process, Config)
        // and silently dropped every other variant to `Ok(())`.
        // A test that scripted `Io("disk full")` would see the
        // mock accept the config — masking the failure the test
        // was trying to assert. The fix is for the mock to
        // `.clone()` whatever scripted error it was handed, which
        // covers every variant exhaustively (the type system
        // enforces it because `SwgError: Clone`). Enumerate one
        // case per discriminant so a future variant addition
        // forces the test author to drop it in here.
        let cases: Vec<SwgError> = vec![
            SwgError::Io("disk full".into()),
            SwgError::Process("envoy died".into()),
            SwgError::Config("bad render".into()),
            SwgError::ConfigValidate("bad yaml".into()),
            SwgError::CategoryBundleSignatureInvalid,
            SwgError::CategoryBundleUnknownKey("kid-3".into()),
            SwgError::CategoryBundleStale {
                incoming: 4,
                current: 7,
            },
            SwgError::CategoryBundleBodyDecode("trailing bytes".into()),
            SwgError::ExtAuthzDecode("missing url".into()),
            // `InstallBusy` is a unit variant so `Clone` is
            // trivial, but the test's stated contract is one
            // case per discriminant (so a future variant
            // addition cannot silently regress the mock's
            // clone-based round-trip path). Keep this entry
            // even though the field-free shape makes the
            // failure mode unlikely — it documents intent and
            // gives the `format!("{err:?}")` assertion a real
            // payload to compare against for this discriminant.
            SwgError::InstallBusy,
        ];
        for scripted in cases {
            let label = format!("{scripted:?}");
            let m = MockEnvoy::new().with_validate_failure(scripted.clone());
            let outcome = m.validate_config(Path::new("/tmp/envoy.yaml")).await;
            let err = match outcome {
                Ok(()) => panic!("variant must surface as error rather than Ok(()): {label}"),
                Err(e) => e,
            };
            // The reproduced error must match the variant the
            // test scripted — Debug-formatted comparison keeps
            // the assertion exhaustive across discriminants and
            // their payloads without naming every variant arm.
            assert_eq!(format!("{err:?}"), label);
        }
    }

    #[tokio::test]
    async fn is_alive_reflects_status_by_default() {
        let m = MockEnvoy::new();
        assert!(!m.is_alive().await, "fresh mock must not be alive");
        m.start(Path::new("/tmp/envoy.yaml")).await.unwrap();
        assert!(m.is_alive().await);
        m.stop().await.unwrap();
        assert!(!m.is_alive().await);
    }

    #[tokio::test]
    async fn is_alive_override_short_circuits_status() {
        // Test scenario: simulate "process died but supervisor
        // hasn't observed it yet" by forcing is_alive=false
        // while status reports Running.
        let m = MockEnvoy::new().with_alive(false);
        m.start(Path::new("/tmp/envoy.yaml")).await.unwrap();
        assert!(
            !m.is_alive().await,
            "scripted is_alive override must dominate"
        );
        assert_eq!(m.status().await, ProcessStatus::Running);
    }

    #[test]
    fn envoy_signal_posix_mapping_is_stable() {
        // The shell backend has to send the *same* POSIX
        // numbers; this lock-in test prevents a refactor from
        // remapping Rotate → SIGTERM (logs would not rotate)
        // or Shutdown → SIGKILL (Envoy would not drain).
        assert_eq!(EnvoySignal::Rotate.as_posix(), 10);
        assert_eq!(EnvoySignal::Shutdown.as_posix(), 15);
    }

    #[tokio::test]
    async fn mock_restart_default_impl_stops_then_starts() {
        // The trait default for `restart()` is stop + start;
        // the mock doesn't override it. This pins the
        // expected sequence so a future override on MockEnvoy
        // (e.g. to record a dedicated `restarts: Vec<...>`)
        // doesn't silently drop the stop call.
        let m = MockEnvoy::new();
        let path = PathBuf::from("/tmp/envoy.yaml");
        m.start(&path).await.unwrap();
        m.restart(&path).await.unwrap();
        let rec = m.recorded();
        // Two starts (initial + post-restart), one stop.
        assert_eq!(rec.started_with.len(), 2, "restart must call start");
        assert_eq!(rec.stopped_count, 1, "restart must call stop");
        assert_eq!(rec.status, ProcessStatus::Running);
    }

    #[test]
    fn shell_envoy_defaults_are_self_consistent() {
        let s = ShellEnvoy::new();
        assert_eq!(s.binary, PathBuf::from("envoy"));
        assert_eq!(s.admin_port, 9901);
        assert_eq!(s.grace_period, Duration::from_secs(10));
        let s = s
            .with_binary("/usr/local/bin/envoy")
            .with_admin_port(15001)
            .with_grace_period(Duration::from_secs(30));
        assert_eq!(s.binary, PathBuf::from("/usr/local/bin/envoy"));
        assert_eq!(s.admin_port, 15001);
        assert_eq!(s.grace_period, Duration::from_secs(30));
    }

    /// Regression test for the stdout/stderr drainer.
    ///
    /// `ShellEnvoy::start` pipes both stdout and stderr so the
    /// supervisor can lift Envoy's boot diagnostics into
    /// structured logs. The Linux kernel buffers each pipe at
    /// ~64 KiB by default; once that buffer fills, `write(2)`
    /// blocks the writing thread. Envoy is single-event-loop, so
    /// a blocked stdout write deadlocks the proxy: the process
    /// still answers `kill(0)` and `try_wait()` returns
    /// `Ok(None)`, but no traffic moves. The manager's
    /// `is_alive()` would keep returning `true` and the health
    /// monitor would never notice.
    ///
    /// `start()` spawns `drain_child_stdout` and
    /// `drain_child_stderr` to keep the pipes empty. This test
    /// exercises just the drainer side: it spawns a shell that
    /// spews well past the 64 KiB buffer on both pipes and wires
    /// the drainers in the same shape `start()` does. Without
    /// the drainers the inner `child.wait()` deadlocks and the
    /// timeout fires; with them in place the child completes
    /// promptly. We can't run the real Envoy binary in CI, but
    /// the spawn shape is identical so the regression catches
    /// here translates directly to the production path.
    #[cfg(unix)]
    #[tokio::test]
    async fn child_with_high_stdout_volume_does_not_deadlock() {
        use std::time::Duration as StdDuration;
        use tokio::time::timeout;

        // Spew ~200 KiB to stdout and ~50 KiB to stderr — both
        // well past the kernel's 64 KiB default pipe buffer, so
        // an undrained `Stdio::piped()` handle would block the
        // child here.
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(
                "for i in $(seq 1 2000); do \
                   echo 'stdout line padding padding padding padding padding padding padding padding padding'; \
                 done; \
                 for i in $(seq 1 500); do \
                   echo 'stderr line padding padding padding padding padding padding padding padding padding' 1>&2; \
                 done",
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = cmd
            .spawn()
            .expect("/bin/sh must be available on a unix CI runner");
        // Wire the drainers exactly as `ShellEnvoy::start` does.
        // Without these spawns the `wait()` below would hang
        // indefinitely on a stuck SIGPIPE-less child.
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(drain_child_stdout(stdout));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(drain_child_stderr(stderr));
        }
        let status = timeout(StdDuration::from_secs(10), child.wait())
            .await
            .expect("child must exit within the test timeout — drainer regression?")
            .expect("child.wait() must succeed");
        assert!(
            status.success(),
            "spew script should exit cleanly, got: {status:?}"
        );
    }
}

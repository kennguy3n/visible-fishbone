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
use tokio::process::{Child, Command};
use tokio::sync::Mutex as AsyncMutex;

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
    /// resolved via `PATH`, admin port 9901, 10-second graceful
    /// stop window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from("envoy"),
            admin_port: 9901,
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
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Drop the child on supervisor exit so a panicking
            // supervisor doesn't leak an Envoy process.
            .kill_on_drop(true);
        let child = cmd
            .spawn()
            .map_err(|e| SwgError::Process(format!("spawn envoy: {e}")))?;
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
        match child.try_wait() {
            // try_wait Ok(None) means the child is still alive.
            Ok(None) => true,
            Ok(Some(_)) => {
                state.status = ProcessStatus::Crashed;
                state.child = None;
                false
            }
            Err(_) => false,
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
        let mut g = self.inner.lock();
        g.validated.push(config_path.to_path_buf());
        // Clone the scripted error so the same value is returned
        // on every call. `SwgError: Clone` (see error.rs) makes
        // this exhaustive across every variant — a future variant
        // added to the taxonomy doesn't silently drop to `Ok(())`
        // the way a per-variant match did before.
        match &g.validate_result {
            Some(err) => Err(err.clone()),
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
}

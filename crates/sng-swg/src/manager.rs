//! SWG supervisor.
//!
//! Wraps the [`EnvoyProcess`], the rendered [`EnvoyConfig`] on
//! disk, and the per-request handler trait deps into one
//! lifecycle. Responsibilities:
//!
//! * Render the operator's bundle into Envoy YAML
//! * Validate the config (`envoy --mode validate`) before
//!   installing
//! * Materialise the config on disk
//! * Spawn / hot-restart the process
//! * Skip a no-op restart when the SHA-256 of the rendered config
//!   matches the installed digest (hot-swap dedup, mirrors the
//!   same pattern in `sng-fw::engine`)
//! * Take a health probe + publish a [`ManagerHealth`] snapshot
//!
//! The manager intentionally does not own the ext-authz HTTP
//! listener — the [`ExtAuthzHandler`] is constructed once by the
//! caller and held alongside the manager. The listener is a
//! deployment-layer concern (a thin tokio task that calls
//! `handler.handle_json_bytes` per request); the supervisor only
//! owns process + config lifecycle.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::Instant;

use crate::config::{EnvoyConfig, digest_envoy_yaml, render_envoy_yaml, summarize_listeners};
use crate::error::SwgError;
use crate::health::{FailMode, HealthProbe, ManagerHealth, evaluate};
use crate::process::{EnvoyProcess, ProcessStatus};

/// Operator-controlled manager configuration. Constructed by the
/// caller; not mutable post-construction (use [`SwgManager::install`]
/// to push a new config).
#[derive(Clone, Debug)]
pub struct SwgManagerConfig {
    /// Where the rendered Envoy YAML lands on disk. Envoy reads
    /// from this path; the supervisor rewrites it before sending
    /// the reload signal.
    pub config_path: PathBuf,
    /// Fail-mode applied when the process drops to Failed.
    pub fail_mode: FailMode,
    /// Maximum verdict staleness before the health monitor
    /// declares Degraded.
    pub verdict_staleness_window: Duration,
    /// Maximum time [`SwgManager::install`] or [`SwgManager::stop`]
    /// will wait to acquire the internal `install_lock` before
    /// surfacing a busy outcome.
    ///
    /// The `install_lock` serialises the entire install body
    /// (render → dedup → write → validate → rename → restart →
    /// commit) and `stop()`, so a slow Envoy graceful-stop
    /// (`grace_period` SIGTERM + SIGKILL escalation in
    /// [`crate::process::ShellEnvoy::stop`]) can block every
    /// subsequent caller for up to the full grace window.
    /// `None` (the default) waits indefinitely; `Some(d)` bounds
    /// the wait — install returns
    /// [`InstallOutcome::Busy`] and stop returns
    /// [`SwgError::InstallBusy`] when the timeout expires, so the
    /// caller (typically the policy-bundle controller) can
    /// reschedule rather than queueing arbitrary amounts of
    /// pending installs.
    pub install_lock_timeout: Option<Duration>,
}

impl SwgManagerConfig {
    /// Defaults: `/etc/sng/envoy.yaml`, `FailMode::Open`,
    /// 30-second verdict staleness window, install-lock wait is
    /// unbounded (matches the pre-timeout behaviour so existing
    /// operators see no change).
    #[must_use]
    pub fn defaults() -> Self {
        Self {
            config_path: PathBuf::from("/etc/sng/envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: None,
        }
    }
}

/// Snapshot of the manager's state. Published on every health
/// probe so a downstream consumer can drive the operator UI
/// without re-querying every component.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwgSnapshot {
    pub digest: Option<String>,
    pub listener_count: usize,
    pub cluster_count: usize,
    pub process_status: ProcessStatus,
    pub health: ManagerHealth,
}

/// SWG manager. Cheap to clone (`Arc` inside) and `Send + Sync`.
#[derive(Clone)]
pub struct SwgManager {
    cfg: SwgManagerConfig,
    process: Arc<dyn EnvoyProcess>,
    state: Arc<State>,
}

/// Last-installed `(config, digest)` pair, swapped atomically
/// as a unit so any reader (probe / listener summary / future
/// snapshot exporter) observes a consistent pair instead of
/// `(new_config, old_digest)` or `(old_config, new_digest)`
/// across the transient window between two separate field
/// swaps. Replaces the previous shape of two side-by-side
/// [`arc_swap::ArcSwap`]s (one per field). The `install_lock`
/// already serialises the *write* side, but a concurrent
/// reader correlating the two fields — even if the current
/// readers don't — would have observed a momentary mismatch.
/// Bundling them eliminates the inter-store window by
/// construction so a future reader cannot accidentally regress
/// the invariant.
#[derive(Default)]
struct InstalledSnapshot {
    /// Last installed `EnvoyConfig` (None on cold boot).
    config: Option<EnvoyConfig>,
    /// Hex SHA-256 of the rendered YAML for `config`. Used by
    /// [`SwgManager::install`] to skip the validate + signal
    /// cycle when the new render hashes the same. Invariant
    /// (enforced by [`SwgManager::install`] and
    /// [`SwgManager::stop`]): `config.is_some() ==
    /// digest.is_some()`. The two fields are written together
    /// in a single [`arc_swap::ArcSwap::store`] so a reader
    /// either sees the pre-install pair or the post-install
    /// pair — never a half-written intermediate.
    digest: Option<String>,
}

struct State {
    /// Atomic snapshot of `(config, digest)`. Single ArcSwap so
    /// the two fields swap as a unit.
    installed: ArcSwap<InstalledSnapshot>,
    /// Wall clock of the most recent verdict emission, set by
    /// the handler (via the [`SwgManager::mark_verdict_emitted`]
    /// hook). Used by the health monitor to compute staleness.
    last_verdict_at: Mutex<Option<Instant>>,
    /// Serialises [`SwgManager::install`] against itself so two
    /// concurrent installs do not race past the digest dedup
    /// and both try to validate / rename / restart Envoy. The
    /// `installed` ArcSwap above is atomic per-store, but
    /// `install()` performs a multi-step transition (digest read
    /// → staging write → validate → rename → restart → memory
    /// swap) that needs to be atomic *as a whole* to make the
    /// dedup path actually skip redundant restarts. An
    /// `AsyncMutex` is the right primitive because the install
    /// body awaits on filesystem and process I/O — a sync mutex
    /// held across those awaits would block tokio workers.
    install_lock: AsyncMutex<()>,
}

impl std::fmt::Debug for SwgManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwgManager")
            .field("config_path", &self.cfg.config_path)
            .field("fail_mode", &self.cfg.fail_mode)
            .finish_non_exhaustive()
    }
}

impl SwgManager {
    /// Build a manager wrapping `process`. No background tasks
    /// are started; the caller drives the lifecycle through
    /// [`Self::install`] / [`Self::stop`] / [`Self::probe`].
    #[must_use]
    pub fn new(cfg: SwgManagerConfig, process: Arc<dyn EnvoyProcess>) -> Self {
        Self {
            cfg,
            process,
            state: Arc::new(State {
                installed: ArcSwap::from_pointee(InstalledSnapshot::default()),
                last_verdict_at: Mutex::new(None),
                install_lock: AsyncMutex::new(()),
            }),
        }
    }

    /// Mark that the handler emitted a verdict. The handler
    /// calls this on every verdict; the timestamp drives the
    /// staleness window in the health monitor.
    pub fn mark_verdict_emitted(&self) {
        *self.state.last_verdict_at.lock() = Some(Instant::now());
    }

    /// Install a new Envoy config:
    ///
    /// 1. Render to YAML.
    /// 2. Compute the SHA-256 digest.
    /// 3. If the digest matches the last installed, skip the
    ///    rest (no-op hot-swap).
    /// 4. Write the YAML to a staging file (`<config>.staging`).
    /// 5. Run `envoy --mode validate` on the staging file.
    /// 6. On validate success, atomically rename the staging
    ///    file over the live config path so the on-disk live
    ///    config either stays as the last-good bytes (if
    ///    validate failed) or jumps to the new bytes (if
    ///    validate succeeded). A subsequent Envoy crash +
    ///    restart therefore always reads a config that has
    ///    passed `--mode validate`.
    /// 7. If Envoy is running, request a graceful restart;
    ///    otherwise start it. (The supervisor does not
    ///    implement Envoy hot-restart — see
    ///    [`EnvoyProcess::restart`] for the rationale.)
    /// 8. On success, atomically swap the in-memory config +
    ///    digest.
    ///
    /// Returns the installation outcome — distinguishes a no-op
    /// dedup hit from a real reload so the caller can surface
    /// the difference on operator dashboards.
    ///
    /// # Concurrency
    ///
    /// The body is serialised by an internal
    /// [`tokio::sync::Mutex`] (`install_lock`) so two concurrent
    /// install calls do not both race past the digest dedup and
    /// try to validate, rename, and restart Envoy. The lock is
    /// acquired before the digest comparison so the dedup check
    /// sees the post-commit state of whatever install ran just
    /// before it.
    ///
    /// The lock is held across [`EnvoyProcess::restart`], which
    /// in the production [`crate::process::ShellEnvoy`] backend
    /// performs a SIGTERM + `grace_period` wait + SIGKILL
    /// escalation. A slow Envoy graceful-stop therefore can
    /// block every concurrent `install()` caller for up to the
    /// full grace window. Operators that want a bounded wait can
    /// set
    /// [`SwgManagerConfig::install_lock_timeout`] — when the
    /// timeout expires before the lock is acquired, `install()`
    /// returns [`InstallOutcome::Busy`] without touching disk or
    /// signalling Envoy. The default is `None` (unbounded wait)
    /// to preserve the historical contract.
    pub async fn install(&self, cfg: EnvoyConfig) -> Result<InstallOutcome, SwgError> {
        // Render before acquiring the lock — render is pure CPU
        // and can happen concurrently across installers without
        // ordering hazards. Only the dedup compare + write +
        // validate + rename + restart need serialisation.
        let rendered = render_envoy_yaml(&cfg)?;
        let digest = digest_envoy_yaml(&rendered);
        let _guard = match self.acquire_install_lock().await {
            Ok(g) => g,
            Err(LockAcquireError::Timeout) => {
                return Ok(InstallOutcome::Busy { digest });
            }
        };
        if let Some(prev) = self.state.installed.load().digest.as_ref()
            && prev == &digest
        {
            return Ok(InstallOutcome::NoOp { digest });
        }
        // Write-validate-rename: stage the new bytes alongside
        // the live config, validate the staged file, and only
        // then atomically rename it onto the live path. If
        // validate fails, the live config is the previous
        // good bytes — so an Envoy crash-restart reads a
        // config that has passed validate, not the candidate
        // bytes we were trying out.
        let staging_path = staging_path_for(&self.cfg.config_path);
        tokio::fs::write(&staging_path, &rendered)
            .await
            .map_err(SwgError::from)?;
        // Validate the staging file before promoting it.
        match self.process.validate_config(&staging_path).await {
            Ok(()) => {}
            Err(e) => {
                // Clean up the staging file so a subsequent
                // failed validate doesn't leave bad bytes
                // littering the config directory. We deliberately
                // swallow remove_file errors — the original
                // validate failure is the operator-actionable
                // signal; a leftover staging file is a
                // self-cleaning nuisance the next install
                // overwrites.
                let _ = tokio::fs::remove_file(&staging_path).await;
                return Err(e);
            }
        }
        // Validate passed — atomically promote the staging file
        // to the live config path. `rename` is atomic on the
        // same filesystem (which the staging path is, by
        // construction — it's the same directory).
        tokio::fs::rename(&staging_path, &self.cfg.config_path)
            .await
            .map_err(SwgError::from)?;
        // Reload (== restart in this supervisor) or start.
        let status = self.process.status().await;
        match status {
            ProcessStatus::Running => {
                self.process.restart(&self.cfg.config_path).await?;
            }
            ProcessStatus::Stopped | ProcessStatus::Crashed => {
                self.process.start(&self.cfg.config_path).await?;
            }
        }
        // Memory swap last so a failure above leaves the
        // previous state intact. Single ArcSwap store publishes
        // the (config, digest) pair atomically: a concurrent
        // reader either sees the pre-install pair or the
        // post-install pair, never `(new_config, old_digest)` or
        // `(old_config, new_digest)` across two separate stores.
        self.state.installed.store(Arc::new(InstalledSnapshot {
            config: Some(cfg),
            digest: Some(digest.clone()),
        }));
        Ok(InstallOutcome::Reloaded { digest })
    }

    /// Graceful stop. Sends Shutdown via the process trait;
    /// clears the in-memory config + digest so a subsequent
    /// install fully re-installs.
    ///
    /// # Concurrency
    ///
    /// `stop()` acquires the same `install_lock` that
    /// [`Self::install`] holds, so a stop issued while an
    /// install is mid-flight waits for the install to commit (or
    /// fail and roll back) before tearing down the process.
    /// Without this, a stop could land between the validate +
    /// rename + restart steps of a concurrent install, leaving
    /// the in-memory `last_config` / `last_digest` populated
    /// from the freshly-installed bundle even though the
    /// operator's most recent stated intent was `stop`. Holding
    /// the lock makes the install ↔ stop ordering deterministic
    /// (last writer wins under the lock).
    ///
    /// When [`SwgManagerConfig::install_lock_timeout`] is set,
    /// `stop()` honours it the same way `install()` does — a
    /// timeout surfaces as [`SwgError::InstallBusy`] rather than
    /// blocking forever on a stuck installer. Without a timeout
    /// (the default), `stop()` waits indefinitely.
    pub async fn stop(&self) -> Result<(), SwgError> {
        let _guard = match self.acquire_install_lock().await {
            Ok(g) => g,
            Err(LockAcquireError::Timeout) => {
                return Err(SwgError::InstallBusy);
            }
        };
        self.process.stop().await?;
        // Atomically clear both fields in a single store so a
        // concurrent reader observes the pre-stop pair or the
        // post-stop empty pair, never a half-cleared mix.
        self.state
            .installed
            .store(Arc::new(InstalledSnapshot::default()));
        *self.state.last_verdict_at.lock() = None;
        Ok(())
    }

    /// Acquire `install_lock` honouring
    /// [`SwgManagerConfig::install_lock_timeout`]. Returns the
    /// owned guard on success or a typed timeout error so the
    /// caller can map it to the variant appropriate to its
    /// surface (an `Ok(InstallOutcome::Busy)` for `install`, an
    /// `Err(SwgError::InstallBusy)` for `stop`).
    async fn acquire_install_lock(
        &self,
    ) -> Result<tokio::sync::MutexGuard<'_, ()>, LockAcquireError> {
        match self.cfg.install_lock_timeout {
            None => Ok(self.state.install_lock.lock().await),
            Some(d) => match tokio::time::timeout(d, self.state.install_lock.lock()).await {
                Ok(guard) => Ok(guard),
                Err(_) => Err(LockAcquireError::Timeout),
            },
        }
    }

    /// Run a single health probe + return the snapshot.
    pub async fn probe(&self, admin_port_reachable: bool) -> SwgSnapshot {
        let alive = self.process.is_alive().await;
        let status = self.process.status().await;
        let since_last_verdict = {
            let last = self.state.last_verdict_at.lock();
            last.map(|t| t.elapsed())
        };
        let probe = HealthProbe {
            envoy_alive: alive,
            admin_port_reachable,
            since_last_verdict,
            verdict_staleness_window: self.cfg.verdict_staleness_window,
        };
        let report = evaluate(&probe);
        // Single load over the bundled snapshot so listener_count
        // / cluster_count and digest come from the same observed
        // generation — no chance of `(new_config, old_digest)` or
        // `(old_config, new_digest)` across the read.
        let installed = self.state.installed.load();
        let (listener_count, cluster_count) = match installed.config.as_ref() {
            Some(c) => (c.listeners.len(), c.clusters.len()),
            None => (0, 0),
        };
        let digest = installed.digest.clone();
        SwgSnapshot {
            digest,
            listener_count,
            cluster_count,
            process_status: status,
            health: ManagerHealth::from(report, self.cfg.fail_mode),
        }
    }

    /// Current rendered config digest, if any.
    #[must_use]
    pub fn current_digest(&self) -> Option<String> {
        self.state.installed.load().digest.clone()
    }

    /// Listener summary derived from the last installed config.
    /// Empty when no install has happened.
    #[must_use]
    pub fn listener_summary(
        &self,
    ) -> std::collections::BTreeMap<String, crate::config::ListenerSummary> {
        match self.state.installed.load().config.as_ref() {
            Some(c) => summarize_listeners(c),
            None => std::collections::BTreeMap::new(),
        }
    }
}

/// Outcome of [`SwgManager::install`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallOutcome {
    /// Config rendered + reloaded.
    Reloaded { digest: String },
    /// Rendered config matched the installed digest — no kernel
    /// action taken.
    NoOp { digest: String },
    /// The caller's
    /// [`SwgManagerConfig::install_lock_timeout`] elapsed before
    /// the install acquired the internal `install_lock`. No
    /// filesystem or process work was performed; the caller can
    /// reschedule. Carries the digest of the candidate render so
    /// the caller can correlate which install was deferred.
    Busy { digest: String },
}

impl InstallOutcome {
    /// True when the outcome resulted in a real Envoy reload.
    #[must_use]
    pub const fn was_reloaded(&self) -> bool {
        matches!(self, Self::Reloaded { .. })
    }

    /// True when the outcome was a no-op dedup hit. Distinct
    /// from [`Self::was_busy`] because dedup is the
    /// "already-current" state while busy is the
    /// "could-not-attempt" state.
    #[must_use]
    pub const fn was_noop(&self) -> bool {
        matches!(self, Self::NoOp { .. })
    }

    /// True when the install hit the
    /// [`SwgManagerConfig::install_lock_timeout`] and was
    /// deferred without touching the process or filesystem.
    #[must_use]
    pub const fn was_busy(&self) -> bool {
        matches!(self, Self::Busy { .. })
    }

    /// Pull the digest regardless of variant.
    #[must_use]
    pub fn digest(&self) -> &str {
        match self {
            Self::Reloaded { digest } | Self::NoOp { digest } | Self::Busy { digest } => digest,
        }
    }
}

/// Internal error from [`SwgManager::acquire_install_lock`].
/// Kept private to the module — callers map it to the
/// surface-appropriate user-visible type (`InstallOutcome::Busy`
/// or `SwgError::InstallBusy`).
enum LockAcquireError {
    Timeout,
}

/// Derive the staging-file path used during write-validate-
/// rename. Lives alongside the live config so the final rename
/// is intra-directory (atomic on every POSIX filesystem and on
/// NTFS via `MoveFileExW`).
///
/// `<config>.yaml` → `<config>.yaml.staging`. Extension-extension
/// avoids surprising operators who scan for `.yaml` and want a
/// stable filename without a staging suffix surfacing through.
fn staging_path_for(config_path: &std::path::Path) -> std::path::PathBuf {
    let mut name = config_path.file_name().unwrap_or_default().to_os_string();
    name.push(".staging");
    match config_path.parent() {
        Some(parent) => parent.join(name),
        None => std::path::PathBuf::from(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvoyConfig;
    use crate::process::MockEnvoy;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    fn manager(tmp: &TempDir) -> (SwgManager, Arc<MockEnvoy>) {
        let mock = Arc::new(MockEnvoy::new());
        let cfg = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: None,
        };
        let m = SwgManager::new(cfg, mock.clone());
        (m, mock)
    }

    #[tokio::test]
    async fn install_validates_writes_and_starts_envoy_on_cold_boot() {
        let tmp = TempDir::new().unwrap();
        let (m, mock) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let out = m.install(cfg).await.unwrap();
        assert!(out.was_reloaded());
        let rec = mock.recorded();
        assert_eq!(rec.validated.len(), 1, "validate must run once");
        assert_eq!(rec.started_with.len(), 1, "must start envoy on cold boot");
        assert!(rec.signals.is_empty(), "no signals on cold boot");
        let written = tokio::fs::read_to_string(&tmp.path().join("envoy.yaml"))
            .await
            .unwrap();
        assert!(written.contains("port_value: 8443"), "config must hit disk");
    }

    #[tokio::test]
    async fn second_identical_install_dedupes_to_noop() {
        let tmp = TempDir::new().unwrap();
        let (m, mock) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let _ = m.install(cfg.clone()).await.unwrap();
        let out = m.install(cfg).await.unwrap();
        assert!(!out.was_reloaded(), "identical install must dedup");
        let rec = mock.recorded();
        // The cold-boot install validated once and called start
        // once; the no-op install did neither.
        assert_eq!(rec.validated.len(), 1, "no-op skips validate");
        assert_eq!(rec.started_with.len(), 1, "no-op skips start");
        assert!(rec.signals.is_empty(), "no-op skips signal");
    }

    #[tokio::test]
    async fn different_config_restarts_running_envoy() {
        // The supervisor does not implement Envoy hot-restart —
        // a config change drives a graceful stop + start through
        // [`EnvoyProcess::restart`] (default impl), which the
        // mock records as one extra stop + one extra start.
        let tmp = TempDir::new().unwrap();
        let (m, mock) = manager(&tmp);
        let cfg1 = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let _ = m.install(cfg1).await.unwrap();

        // Change one byte → different digest → reload.
        let mut cfg2 = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg2.listeners[0].port = 9443;
        let out = m.install(cfg2).await.unwrap();
        assert!(out.was_reloaded());

        let rec = mock.recorded();
        // Initial install: 1 start.
        // Second install: restart() = 1 stop + 1 start = 2 total starts, 1 stop.
        assert_eq!(
            rec.started_with.len(),
            2,
            "second install must restart (stop + start) the running process"
        );
        assert_eq!(
            rec.stopped_count, 1,
            "second install must call stop() as the first half of restart"
        );
        assert!(
            rec.signals.is_empty(),
            "restart goes through stop()/start(), not signal()"
        );
        assert_eq!(rec.validated.len(), 2, "must validate the new config");
    }

    #[tokio::test]
    async fn invalid_config_fails_install_and_leaves_previous_intact() {
        let tmp = TempDir::new().unwrap();
        let mock = Arc::new(
            MockEnvoy::new().with_validate_failure(SwgError::ConfigValidate("bad listener".into())),
        );
        let cfgm = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: None,
        };
        let m = SwgManager::new(cfgm, mock);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let err = m.install(cfg).await.expect_err("validate must fail");
        match err {
            SwgError::ConfigValidate(msg) => assert!(msg.contains("bad listener"), "{msg}"),
            other => panic!("expected ConfigValidate, got {other:?}"),
        }
        // Previous in-memory state untouched.
        assert!(m.current_digest().is_none());
        // Write-validate-rename: the live config path must NOT
        // exist on disk — the candidate bytes never crossed the
        // validate gate, so they must not be visible as the
        // live config. A crash-restart at this point should find
        // either nothing (cold-boot path) or the previous good
        // config bytes (warm path); never the rejected
        // candidate.
        assert!(
            !tmp.path().join("envoy.yaml").exists(),
            "validate failure must leave no candidate bytes on the live path"
        );
        // And the staging file is cleaned up so a future install
        // doesn't see a stale staging blob.
        assert!(
            !tmp.path().join("envoy.yaml.staging").exists(),
            "validate failure must clean up its own staging file"
        );
    }

    #[tokio::test]
    async fn validate_failure_after_first_install_preserves_previous_live_config() {
        // Pin the write-validate-rename invariant on the warm
        // path: a successful first install leaves the live
        // config on disk. A second install whose candidate fails
        // validate must NOT corrupt that live config — a
        // crash-restart between the failed validate and the next
        // successful install must read the previous good bytes.
        let tmp = TempDir::new().unwrap();
        let mock = Arc::new(MockEnvoy::new());
        let cfgm = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: None,
        };
        let mgr = SwgManager::new(cfgm, mock.clone());

        // First install: passes validate, writes live config.
        let initial = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        mgr.install(initial).await.unwrap();
        let good_bytes = tokio::fs::read_to_string(tmp.path().join("envoy.yaml"))
            .await
            .unwrap();
        assert!(good_bytes.contains("port_value: 8443"));

        // Arm the mock to fail validate on the next call.
        mock.set_validate_failure(SwgError::ConfigValidate(
            "candidate has bad upstream cluster".into(),
        ));

        // Second install: passes the digest dedup (different
        // port), reaches validate, fails. The live config on
        // disk must still be the first-install bytes.
        let mut bad_candidate =
            EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        bad_candidate.listeners[0].port = 9443;
        let err = mgr
            .install(bad_candidate)
            .await
            .expect_err("rigged validate failure must surface");
        match err {
            SwgError::ConfigValidate(msg) => {
                assert!(msg.contains("bad upstream cluster"), "{msg}");
            }
            other => panic!("expected ConfigValidate, got {other:?}"),
        }

        let live_bytes_after = tokio::fs::read_to_string(tmp.path().join("envoy.yaml"))
            .await
            .unwrap();
        assert_eq!(
            live_bytes_after, good_bytes,
            "failed validate must not corrupt the previous-good live config"
        );
        assert!(
            !tmp.path().join("envoy.yaml.staging").exists(),
            "failed validate must clean up its staging file"
        );
    }

    #[tokio::test]
    async fn stop_clears_in_memory_state() {
        let tmp = TempDir::new().unwrap();
        let (m, mock) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        assert!(m.current_digest().is_some());
        m.stop().await.unwrap();
        assert!(m.current_digest().is_none());
        let rec = mock.recorded();
        assert_eq!(rec.stopped_count, 1);
    }

    #[tokio::test]
    async fn probe_reflects_envoy_status_and_listener_count() {
        let tmp = TempDir::new().unwrap();
        let (m, _) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        let snap = m.probe(true).await;
        assert_eq!(snap.listener_count, 1);
        assert_eq!(snap.cluster_count, 2);
        assert_eq!(snap.process_status, ProcessStatus::Running);
        assert_eq!(
            snap.health.report.state,
            crate::health::HealthState::Healthy
        );
        assert!(snap.health.traffic_permitted);
    }

    #[tokio::test]
    async fn probe_reports_failed_when_envoy_dies() {
        let tmp = TempDir::new().unwrap();
        let mock = Arc::new(MockEnvoy::new().with_alive(false));
        let cfgm = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Closed,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: None,
        };
        let m = SwgManager::new(cfgm, mock);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        let snap = m.probe(true).await;
        assert_eq!(snap.health.report.state, crate::health::HealthState::Failed);
        assert!(
            !snap.health.traffic_permitted,
            "fail-closed must block traffic"
        );
    }

    #[tokio::test]
    async fn probe_reports_degraded_when_admin_unreachable() {
        let tmp = TempDir::new().unwrap();
        let (m, _) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        let snap = m.probe(false).await;
        assert_eq!(
            snap.health.report.state,
            crate::health::HealthState::Degraded
        );
        assert!(snap.health.traffic_permitted, "degraded must still permit");
    }

    #[tokio::test]
    async fn mark_verdict_emitted_resets_staleness_clock() {
        let tmp = TempDir::new().unwrap();
        let (m, _) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        // Before any verdict, since_last_verdict is None which
        // is treated as "cold start, healthy".
        let snap = m.probe(true).await;
        assert_eq!(
            snap.health.report.state,
            crate::health::HealthState::Healthy
        );
        m.mark_verdict_emitted();
        // Immediately after a verdict the staleness is well
        // under the 30s window.
        let snap = m.probe(true).await;
        assert_eq!(
            snap.health.report.state,
            crate::health::HealthState::Healthy
        );
    }

    #[tokio::test]
    async fn listener_summary_keys_by_name() {
        let tmp = TempDir::new().unwrap();
        let (m, _) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        let sum = m.listener_summary();
        assert_eq!(sum.len(), 1);
        assert!(sum.contains_key("swg_forward"));
    }

    /// Regression: the manager's `(config, digest)` pair must be
    /// observable as a single atomic snapshot, never as
    /// `(new_config, old_digest)` or `(old_config, new_digest)`.
    /// Pre-bundling the two fields lived in separate
    /// [`arc_swap::ArcSwap`]s and were written one-at-a-time on
    /// install (and one-at-a-time on stop), so a reader between
    /// the two stores would observe a mismatched pair. After the
    /// bundling refactor both fields live in a single
    /// `ArcSwap<InstalledSnapshot>`, so every observable state
    /// pair the reader can witness satisfies the invariant
    /// `digest.is_some() == listener_count > 0`. Walks the full
    /// lifecycle (cold → install → reinstall → stop) and pins the
    /// invariant at each stage.
    #[tokio::test]
    async fn probe_observes_consistent_config_digest_pair_across_install_lifecycle() {
        let tmp = TempDir::new().unwrap();
        let (m, _) = manager(&tmp);
        let cold = m.probe(true).await;
        assert!(
            cold.digest.is_none() && cold.listener_count == 0,
            "cold-boot pair invariant: both empty"
        );
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        let post_install = m.probe(true).await;
        assert!(
            post_install.digest.is_some() && post_install.listener_count > 0,
            "post-install pair invariant: both populated"
        );
        // Reinstall a different cluster shape so the digest and
        // listener_count both advance to new values; observed
        // pair must still satisfy the invariant.
        let cfg2 = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz2.sock");
        m.install(cfg2).await.unwrap();
        let post_reinstall = m.probe(true).await;
        assert!(
            post_reinstall.digest.is_some() && post_reinstall.listener_count > 0,
            "post-reinstall pair invariant: both populated"
        );
        assert_ne!(
            post_install.digest, post_reinstall.digest,
            "digest must advance across different installs"
        );
        m.stop().await.unwrap();
        let post_stop = m.probe(true).await;
        assert!(
            post_stop.digest.is_none() && post_stop.listener_count == 0,
            "post-stop pair invariant: both cleared"
        );
    }

    /// Pin the atomicity of the install commit by reading the
    /// observable pair through both surfaces the manager exposes
    /// (`probe().digest` and `current_digest()`) — they must
    /// agree on every single call. Without bundling, a reader
    /// that called these two methods in sequence could in
    /// principle observe one populated and the other empty if
    /// another thread committed an install between the calls.
    /// With bundling both surfaces read from the same atomic
    /// snapshot, so the pair always agrees.
    #[tokio::test]
    async fn current_digest_and_probe_digest_agree_after_install_and_stop() {
        let tmp = TempDir::new().unwrap();
        let (m, _) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        m.install(cfg).await.unwrap();
        let probe_digest = m.probe(true).await.digest;
        let current_digest = m.current_digest();
        assert_eq!(
            probe_digest, current_digest,
            "post-install: probe and current_digest must agree"
        );
        assert!(current_digest.is_some());
        m.stop().await.unwrap();
        let probe_digest = m.probe(true).await.digest;
        let current_digest = m.current_digest();
        assert_eq!(
            probe_digest, current_digest,
            "post-stop: probe and current_digest must agree"
        );
        assert!(current_digest.is_none());
    }

    #[test]
    fn install_outcome_was_reloaded_distinguishes_variants() {
        let r = InstallOutcome::Reloaded {
            digest: "abc".into(),
        };
        let n = InstallOutcome::NoOp {
            digest: "abc".into(),
        };
        assert!(r.was_reloaded());
        assert!(!n.was_reloaded());
        assert_eq!(r.digest(), "abc");
        assert_eq!(n.digest(), "abc");
    }

    #[tokio::test]
    async fn install_outcome_busy_classifier_distinguishes_busy_from_reloaded_and_noop() {
        // The three classifiers (`was_reloaded`, `was_noop`,
        // `was_busy`) partition the outcome space exactly once
        // — a downstream consumer should be able to dispatch on
        // these without further matching.
        let r = InstallOutcome::Reloaded {
            digest: "abc".into(),
        };
        let n = InstallOutcome::NoOp {
            digest: "abc".into(),
        };
        let b = InstallOutcome::Busy {
            digest: "abc".into(),
        };
        assert!(r.was_reloaded() && !r.was_noop() && !r.was_busy());
        assert!(!n.was_reloaded() && n.was_noop() && !n.was_busy());
        assert!(!b.was_reloaded() && !b.was_noop() && b.was_busy());
        assert_eq!(b.digest(), "abc");
    }

    #[tokio::test(start_paused = true)]
    async fn install_returns_busy_when_lock_acquisition_exceeds_timeout() {
        // Pin the `install_lock_timeout` escape hatch: if the
        // lock is held by an in-flight install for longer than
        // the configured timeout, the second install returns
        // `Busy` without touching the process or filesystem.
        // We use `start_paused = true` so virtual tokio time
        // drives the timeout deterministically rather than
        // racing the wall clock.
        let tmp = TempDir::new().unwrap();
        let mock = Arc::new(MockEnvoy::new());
        let gate = mock.install_validate_gate();
        let cfgm = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: Some(Duration::from_millis(50)),
        };
        let m = SwgManager::new(cfgm, mock.clone());

        // First install: hangs inside validate (the mock awaits
        // the gate). We spawn it onto a task so the test body
        // continues without blocking on the gate itself.
        let m_slow = m.clone();
        let cfg_slow = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let slow = tokio::spawn(async move { m_slow.install(cfg_slow).await });

        // Yield so the slow install reaches the gate and holds
        // the install_lock.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Second install: races for the same lock. Different
        // digest so it would not dedup. The timeout elapses
        // before the first install completes (because the gate
        // is still closed) — install must return Busy.
        let mut cfg_busy = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        cfg_busy.listeners[0].port = 9443;
        let busy_outcome = m.install(cfg_busy).await.unwrap();
        assert!(
            busy_outcome.was_busy(),
            "second install must return Busy when lock_timeout expires; got {busy_outcome:?}"
        );

        // Releasing the gate lets the first install commit; we
        // observe it succeeded and that the busy install never
        // touched validate or start (so the mock only saw the
        // single first-install validate + start).
        gate.notify_one();
        let slow_outcome = slow.await.unwrap().unwrap();
        assert!(slow_outcome.was_reloaded());
        let rec = mock.recorded();
        assert_eq!(
            rec.validated.len(),
            1,
            "the Busy install must not have run validate",
        );
        assert_eq!(
            rec.started_with.len(),
            1,
            "the Busy install must not have started envoy",
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stop_returns_install_busy_when_lock_acquisition_exceeds_timeout() {
        // The same escape hatch applies to `stop()` — if an
        // in-flight install holds the install_lock past the
        // configured timeout, the operator-issued stop surfaces
        // `SwgError::InstallBusy` instead of blocking forever.
        let tmp = TempDir::new().unwrap();
        let mock = Arc::new(MockEnvoy::new());
        let gate = mock.install_validate_gate();
        let cfgm = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: Some(Duration::from_millis(50)),
        };
        let m = SwgManager::new(cfgm, mock.clone());

        let m_slow = m.clone();
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let slow = tokio::spawn(async move { m_slow.install(cfg).await });
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let stop_err = m.stop().await.expect_err("stop must time out");
        assert!(
            matches!(stop_err, SwgError::InstallBusy),
            "stop must surface InstallBusy when lock_timeout expires; got {stop_err:?}",
        );

        // Release the install so the spawned task can drain;
        // confirm it would otherwise have completed.
        gate.notify_one();
        let slow_outcome = slow.await.unwrap().unwrap();
        assert!(slow_outcome.was_reloaded());
    }

    #[tokio::test]
    async fn stop_serialises_with_in_flight_install_via_install_lock() {
        // Regression test for the `stop()` vs `install()` race.
        // Before stop() acquired the install_lock, a stop issued
        // mid-install could race past install's restart() step
        // and clear in-memory state out from under the still-
        // running install, leaving the supervisor in an
        // inconsistent "stopped but last_config populated" or
        // "installed but last_config cleared" state depending on
        // scheduling.
        //
        // Now that stop() acquires the same install_lock,
        // install() must commit fully (or fail) before stop()
        // runs. We pin this with a gated validate: install hangs
        // mid-validate (lock held), stop is issued, we assert
        // stop has NOT yet completed; we release the gate;
        // install commits; stop then proceeds and clears state.
        let tmp = TempDir::new().unwrap();
        let mock = Arc::new(MockEnvoy::new());
        let gate = mock.install_validate_gate();
        let cfgm = SwgManagerConfig {
            config_path: tmp.path().join("envoy.yaml"),
            fail_mode: FailMode::Open,
            verdict_staleness_window: Duration::from_secs(30),
            install_lock_timeout: None,
        };
        let m = SwgManager::new(cfgm, mock.clone());

        let m_install = m.clone();
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let install = tokio::spawn(async move { m_install.install(cfg).await });
        // Let install reach the gate.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let m_stop = m.clone();
        let stop = tokio::spawn(async move { m_stop.stop().await });
        // Stop is now contending for the lock; let the scheduler
        // run it.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // Stop MUST still be pending — install is mid-validate
        // and holds the lock. If we observed `is_finished()`
        // here, that would mean stop ran without waiting on the
        // lock, i.e. the race the fix targets is still live.
        assert!(
            !stop.is_finished(),
            "stop() must block on install_lock while install is mid-flight",
        );

        // Release the gate → install commits last_config &
        // last_digest, releases the lock; stop then acquires the
        // lock and clears state.
        gate.notify_one();
        let install_res = install.await.unwrap().unwrap();
        assert!(install_res.was_reloaded());
        stop.await.unwrap().unwrap();

        // Post-stop state must be the cleared state — stop ran
        // after install committed, so its clears observed the
        // installed state and cleared it. last_digest is None.
        assert!(
            m.current_digest().is_none(),
            "stop must clear digest after install committed",
        );
        let rec = mock.recorded();
        // install: 1 start, 0 stops; stop: 1 stop. Cold-boot
        // install does start (not restart), so stopped_count
        // ends up at exactly 1 from the stop() call.
        assert_eq!(rec.started_with.len(), 1);
        assert_eq!(
            rec.stopped_count, 1,
            "stop() must reach process.stop() once after install commits",
        );
    }

    #[tokio::test]
    async fn concurrent_installs_of_identical_config_dedup_via_install_lock() {
        // The install body has to be serialised under
        // `install_lock` for the digest-dedup short-circuit to be
        // meaningful. Without the lock, two concurrent installs
        // from a cold boot would both observe `last_digest =
        // None`, both proceed to write + validate + rename +
        // start Envoy, and the operator would see two restarts
        // for one config rotation. With the lock, the second
        // caller waits for the first to commit `last_digest`,
        // then observes the post-commit digest and short-circuits
        // to `NoOp`. We pin both observable effects: exactly one
        // validate + exactly one start, plus exactly one
        // `Reloaded` outcome with the other being `NoOp`.
        let tmp = TempDir::new().unwrap();
        let (m, mock) = manager(&tmp);
        let cfg = EnvoyConfig::minimal_forward_proxy("unix:///var/run/sng/ext_authz.sock");
        let (ra, rb) = tokio::join!(m.install(cfg.clone()), m.install(cfg));
        let ra = ra.unwrap();
        let rb = rb.unwrap();
        // Exactly one of the two outcomes is a reload — the
        // other is the dedup NoOp.
        let reloaded = [&ra, &rb].iter().filter(|o| o.was_reloaded()).count();
        let noop = [&ra, &rb].iter().filter(|o| !o.was_reloaded()).count();
        assert_eq!(
            reloaded, 1,
            "exactly one install must reload; got {ra:?} / {rb:?}",
        );
        assert_eq!(noop, 1, "exactly one install must NoOp");
        let rec = mock.recorded();
        assert_eq!(
            rec.validated.len(),
            1,
            "two concurrent identical installs must validate once",
        );
        assert_eq!(
            rec.started_with.len(),
            1,
            "two concurrent identical installs must start envoy once",
        );
    }
}

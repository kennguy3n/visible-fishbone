//! Active self-healing supervisor for the SWG's Envoy process.
//!
//! Where [`crate::health`] is the *pure* state evaluator, the
//! [`EnvoySupervisor`] is the *driver*: it polls Envoy on a fixed
//! cadence — combining the process-level `is_alive()` liveness check
//! with a query of Envoy's admin `/ready` endpoint — feeds each
//! observation through the health evaluator, and, when the subsystem
//! latches [`HealthState::Failed`], hot-restarts Envoy under an
//! exponential backoff. Each attempt rolls back to the last-known-good
//! config and emits a [`SubsystemRestart`] telemetry event.
//!
//! # `/ready` health check
//!
//! Envoy exposes a liveness signal on its admin listener at `/ready`:
//! HTTP `200` with body `LIVE` once the server has finished
//! initialising (listeners bound, clusters warmed), and `503`
//! otherwise. The supervisor treats "process alive but `/ready` not
//! `LIVE`" as a *degraded* observation and, if it persists past the
//! flap-suppression threshold, as an `Unresponsive` failure that
//! warrants a restart — the classic "Envoy is up but wedged on a bad
//! runtime overlay / stuck listener" failure that a bare PID check
//! cannot see. The probe is injected via the [`EnvoyReadiness`] trait
//! so tests drive it deterministically; production wires
//! [`HttpReadiness`], a dependency-free admin-port client.
//!
//! # Hot restart with `--restart-epoch`
//!
//! Each restart bumps a monotonic restart epoch and threads it into
//! [`EnvoyProcess::hot_restart`]. Envoy's hot-restart protocol keys
//! the parent/child rendezvous on a strictly-increasing
//! `--restart-epoch`; see the doc comment on
//! [`EnvoyProcess::hot_restart`] for why the shipped single-process
//! backend performs an honest graceful drain + restart rather than the
//! shared-memory handshake, and how a hot-restarter-backed backend can
//! consume the epoch for true zero-downtime restarts without any
//! change to this supervisor.
//!
//! # Last-known-good config
//!
//! The manager tells the supervisor the *active* config via
//! [`EnvoySupervisor::set_active_config`] whenever it applies one.
//! Every healthy observation promotes the active config to
//! last-known-good; a restart relaunches with the last-known-good
//! config, so a freshly-applied config that wedges Envoy before it
//! ever reaches `/ready == LIVE` is rolled back automatically instead
//! of being re-applied into a crash loop.
//!
//! # Concurrency
//!
//! Cheap to wrap in an `Arc` and share: [`EnvoySupervisor::run`] takes
//! `&self` so one clone drives the loop while others call
//! [`EnvoySupervisor::set_active_config`] / [`EnvoySupervisor::state`].
//! The latched state lives behind a non-async [`parking_lot::Mutex`]
//! that is never held across an `.await`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use sng_core::ShutdownSignal;
use sng_core::events::{SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason};
use sng_core::restart::{NoopRestartSink, SubsystemRestartSink};

use crate::health::{FailMode, HealthProbe, HealthState, evaluate};
use crate::process::EnvoyProcess;

/// Stable subsystem name used in emitted [`SubsystemRestart`]
/// telemetry. Matches the SWG subsystem's lifecycle name so the
/// control plane can join restart events against the `/health` report.
pub const SUBSYSTEM_NAME: &str = "swg";

/// Envoy admin `/ready` probe surface.
///
/// Injected into the supervisor so the readiness signal can be driven
/// deterministically in tests while production uses the real admin-port
/// client ([`HttpReadiness`]).
#[async_trait]
pub trait EnvoyReadiness: Send + Sync + std::fmt::Debug {
    /// Query Envoy's admin `/ready` endpoint. Returns `true` only when
    /// Envoy reports `LIVE` (fully initialised and serving). Any
    /// transport error, timeout, or non-`LIVE` body is `false`.
    async fn ready(&self) -> bool;
}

/// Production [`EnvoyReadiness`]: a dependency-free client for Envoy's
/// admin `/ready` endpoint.
///
/// Envoy answers `GET /ready` on its admin listener with `200` + body
/// `LIVE` once initialised, `503` otherwise. We speak the minimal
/// HTTP/1.1 needed over a [`TcpStream`] — the same hand-rolled-framing
/// approach the ext-authz server uses — so the crate keeps its
/// zero-HTTP-client-dependency posture. The whole exchange is bounded
/// by a timeout so a half-open admin socket cannot stall the
/// supervisor's poll loop.
#[derive(Clone, Debug)]
pub struct HttpReadiness {
    addr: SocketAddr,
    timeout: Duration,
}

impl HttpReadiness {
    /// Probe the admin listener on `127.0.0.1:admin_port`. The admin
    /// listener is loopback-only by configuration, so the host is
    /// fixed to localhost.
    #[must_use]
    pub fn new(admin_port: u16) -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), admin_port),
            timeout: Duration::from_secs(2),
        }
    }

    /// Override the per-probe timeout. Defaults to 2s.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// One probe round: connect, send the request, read the response,
    /// and decide liveness. Returns `Err` on any transport failure so
    /// the caller can map it uniformly to "not ready".
    async fn probe(&self) -> std::io::Result<bool> {
        let mut stream = TcpStream::connect(self.addr).await?;
        // `Connection: close` so Envoy closes the socket after the
        // response and `read_to_end` terminates without us parsing
        // Content-Length / chunked framing.
        stream
            .write_all(
                b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await?;
        stream.flush().await?;
        let mut buf = Vec::with_capacity(128);
        stream.read_to_end(&mut buf).await?;
        Ok(response_is_live(&buf))
    }
}

/// Decide whether an Envoy `/ready` HTTP response means `LIVE`.
///
/// Requires both a `200` status line and a body containing `LIVE`:
/// Envoy returns `503 ... not ready` during init, and a stray `200`
/// with an unexpected body should not be read as healthy.
fn response_is_live(raw: &[u8]) -> bool {
    let text = String::from_utf8_lossy(raw);
    let Some((status_line, rest)) = text.split_once("\r\n") else {
        return false;
    };
    if !status_line.starts_with("HTTP/1.1 200") && !status_line.starts_with("HTTP/1.0 200") {
        return false;
    }
    // Body follows the blank line that terminates the headers.
    rest.split_once("\r\n\r\n")
        .is_some_and(|(_headers, body)| body.contains("LIVE"))
}

#[async_trait]
impl EnvoyReadiness for HttpReadiness {
    async fn ready(&self) -> bool {
        match tokio::time::timeout(self.timeout, self.probe()).await {
            Ok(Ok(live)) => live,
            Ok(Err(e)) => {
                debug!(
                    target: "sng_swg::envoy::supervisor",
                    error = %e,
                    "envoy /ready probe transport error"
                );
                false
            }
            Err(_elapsed) => {
                debug!(
                    target: "sng_swg::envoy::supervisor",
                    timeout_ms = self.timeout.as_millis(),
                    "envoy /ready probe timed out"
                );
                false
            }
        }
    }
}

/// Tunables for the active [`EnvoySupervisor`] control loop.
#[derive(Clone, Debug)]
pub struct EnvoySupervisorConfig {
    /// Cadence at which the supervisor polls `is_alive()` + `/ready`.
    pub poll_interval: Duration,
    /// Consecutive unhealthy probes required before the supervisor
    /// latches `Failed` and drives a restart — suppresses alarm flap
    /// on a single missed probe or a brief readiness blip during
    /// listener warm-up.
    pub failed_consecutive_required: u32,
    /// Operator fail posture applied while the subsystem is `Failed`.
    /// Surfaced on the emitted telemetry so the control plane knows
    /// whether traffic kept flowing.
    pub fail_mode: FailMode,
    /// First restart backoff. Doubles per consecutive failed restart
    /// up to [`Self::restart_max_backoff`].
    pub restart_initial_backoff: Duration,
    /// Ceiling for the exponential restart backoff.
    pub restart_max_backoff: Duration,
    /// Optional cap on restart attempts within a single failure
    /// episode. `None` retries indefinitely; `Some(n)` emits an
    /// [`SubsystemRestartOutcome::Exhausted`] event and hands off to
    /// the top-level watchdog after `n` consecutive failed attempts.
    pub restart_max_attempts: Option<u32>,
}

impl Default for EnvoySupervisorConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
            failed_consecutive_required: 3,
            // Fail-open is the default roll-out posture: losing TLS
            // interception must not black-hole a tenant's egress
            // unless the operator explicitly opts into the strict
            // posture.
            fail_mode: FailMode::Open,
            restart_initial_backoff: Duration::from_secs(1),
            restart_max_backoff: Duration::from_secs(30),
            restart_max_attempts: None,
        }
    }
}

/// Active self-healing supervisor for an Envoy process. See the module
/// docs for the `/ready` probe, hot-restart epoch, and last-known-good
/// rollback semantics.
#[derive(Debug)]
pub struct EnvoySupervisor {
    process: Arc<dyn EnvoyProcess>,
    readiness: Arc<dyn EnvoyReadiness>,
    config: EnvoySupervisorConfig,
    sink: Arc<dyn SubsystemRestartSink>,
    /// Latched health state, readable via [`Self::state`].
    state: Mutex<HealthState>,
    /// Config Envoy is currently running under. Updated by the manager
    /// via [`Self::set_active_config`].
    active_config: ArcSwap<PathBuf>,
    /// Most recent config under which the subsystem was observed
    /// `Healthy`. `None` until the first healthy observation.
    last_known_good: ArcSwapOption<PathBuf>,
    /// Monotonic Envoy restart epoch. Starts at 0 (the manager's
    /// initial launch); the supervisor's first restart uses epoch 1.
    restart_epoch: AtomicU32,
}

impl EnvoySupervisor {
    /// Build a supervisor for `process`, probing readiness via
    /// `readiness`, told that `initial_config` is the config Envoy was
    /// launched with.
    #[must_use]
    pub fn new(
        process: Arc<dyn EnvoyProcess>,
        readiness: Arc<dyn EnvoyReadiness>,
        initial_config: impl Into<PathBuf>,
        config: EnvoySupervisorConfig,
    ) -> Self {
        Self {
            process,
            readiness,
            config,
            sink: Arc::new(NoopRestartSink),
            state: Mutex::new(HealthState::Unknown),
            active_config: ArcSwap::from_pointee(initial_config.into()),
            last_known_good: ArcSwapOption::empty(),
            restart_epoch: AtomicU32::new(0),
        }
    }

    /// Attach the telemetry sink restart events are reported to.
    /// Defaults to a no-op sink when not set.
    #[must_use]
    pub fn with_sink(mut self, sink: Arc<dyn SubsystemRestartSink>) -> Self {
        self.sink = sink;
        self
    }

    /// Record that the manager has applied a new active config. The
    /// supervisor restarts against this path while it is healthy and
    /// promotes it to last-known-good on the next healthy probe.
    pub fn set_active_config(&self, path: impl Into<PathBuf>) {
        self.active_config.store(Arc::new(path.into()));
    }

    /// Current health state observed by the supervisor.
    #[must_use]
    pub fn state(&self) -> HealthState {
        *self.state.lock()
    }

    /// Last-known-good config, if the subsystem has ever been observed
    /// healthy.
    #[must_use]
    pub fn last_known_good(&self) -> Option<PathBuf> {
        self.last_known_good.load_full().map(|p| (*p).clone())
    }

    /// Most recent restart epoch the supervisor has issued. `0` before
    /// the first restart.
    #[must_use]
    pub fn restart_epoch(&self) -> u32 {
        self.restart_epoch.load(Ordering::SeqCst)
    }

    /// Run the supervisor until `shutdown` fires. Polls the process on
    /// [`EnvoySupervisorConfig::poll_interval`], driving the latched
    /// state and self-healing on `Failed`.
    pub async fn run(&self, shutdown: ShutdownSignal) {
        let mut backoff = self.config.restart_initial_backoff;
        // Consecutive unhealthy observations in the current episode.
        let mut consecutive_unhealthy: u32 = 0;
        // Restart attempts within the current failure episode. Reset to
        // zero on a healthy observation.
        let mut episode_attempts: u32 = 0;

        loop {
            tokio::select! {
                () = shutdown.wait() => {
                    debug!(target: "sng_swg::envoy::supervisor", "shutdown signalled");
                    return;
                }
                () = tokio::time::sleep(self.config.poll_interval) => {}
            }

            let alive = self.process.is_alive().await;
            // Only probe readiness when the PID is live — a dead
            // process can't answer the admin port, and skipping the
            // probe avoids a guaranteed connect-refused round trip.
            let ready = alive && self.readiness.ready().await;

            let probe = HealthProbe {
                envoy_alive: alive,
                admin_port_reachable: ready,
                // The supervisor scopes its opinion to liveness +
                // readiness; verdict-staleness is the manager's
                // concern on its own cadence. `None` keeps this probe
                // from double-counting staleness.
                since_last_verdict: None,
                verdict_staleness_window: Duration::ZERO,
            };
            let report = evaluate(&probe);

            if report.state == HealthState::Healthy {
                self.last_known_good.store(Some(self.active_config.load_full()));
                backoff = self.config.restart_initial_backoff;
                consecutive_unhealthy = 0;
                episode_attempts = 0;
                *self.state.lock() = HealthState::Healthy;
                continue;
            }

            // Unhealthy observation (Degraded or Failed). Latch with
            // flap suppression: a single blip degrades; only a
            // sustained run promotes to Failed and drives a restart.
            consecutive_unhealthy = consecutive_unhealthy.saturating_add(1);
            if consecutive_unhealthy < self.config.failed_consecutive_required {
                *self.state.lock() = HealthState::Degraded;
                debug!(
                    target: "sng_swg::envoy::supervisor",
                    consecutive_unhealthy,
                    detail = %report.detail,
                    "envoy unhealthy probe below restart threshold"
                );
                continue;
            }

            *self.state.lock() = HealthState::Failed;
            let reason = if alive {
                // PID alive but `/ready` never came back LIVE.
                SubsystemRestartReason::Unresponsive
            } else {
                SubsystemRestartReason::LivenessLost
            };

            // Interruptible backoff before the attempt so an operator
            // stop() during a long window does not hang.
            tokio::select! {
                () = shutdown.wait() => {
                    debug!(
                        target: "sng_swg::envoy::supervisor",
                        "shutdown signalled during restart backoff"
                    );
                    return;
                }
                () = tokio::time::sleep(backoff) => {}
            }

            episode_attempts = episode_attempts.saturating_add(1);
            let backoff_ms = u64::try_from(backoff.as_millis()).unwrap_or(u64::MAX);
            let outcome = self
                .perform_restart(reason, episode_attempts, backoff_ms)
                .await;

            match outcome {
                SubsystemRestartOutcome::Recovered => {
                    backoff = self.config.restart_initial_backoff;
                    consecutive_unhealthy = 0;
                    episode_attempts = 0;
                }
                SubsystemRestartOutcome::Failed => {
                    backoff = (backoff * 2).min(self.config.restart_max_backoff);
                }
                SubsystemRestartOutcome::Exhausted => {
                    warn!(
                        target: "sng_swg::envoy::supervisor",
                        attempts = episode_attempts,
                        "swg restart budget exhausted; handing off to top-level watchdog"
                    );
                    return;
                }
            }
        }
    }

    /// Issue a single hot-restart attempt and report it. Returns the
    /// outcome; the caller owns the backoff schedule. Never sleeps —
    /// the interruptible backoff is the caller's responsibility.
    async fn perform_restart(
        &self,
        reason: SubsystemRestartReason,
        attempt: u32,
        backoff_ms: u64,
    ) -> SubsystemRestartOutcome {
        let active = self.active_config.load_full();
        // Prefer the last-known-good config; fall back to the active
        // one if the subsystem has never been healthy (cold start).
        let (restart_path, rolled_back_config) = match self.last_known_good.load_full() {
            Some(good) => {
                let rolled = *good != *active;
                (good, rolled)
            }
            None => (active, false),
        };

        // Strictly-increasing restart epoch: the manager owns epoch 0
        // (the initial launch), so the first supervisor restart is 1.
        let epoch = self.restart_epoch.fetch_add(1, Ordering::SeqCst) + 1;

        let (outcome, detail) = match self.process.hot_restart(&restart_path, epoch).await {
            Ok(()) => {
                // hot_restart returning Ok means the launch was
                // accepted; confirm the PID is actually live before we
                // call it a recovery. Readiness is re-checked on the
                // next poll — Envoy binds listeners asynchronously, so
                // a just-launched process is legitimately not yet
                // `/ready`.
                if self.process.is_alive().await {
                    info!(
                        target: "sng_swg::envoy::supervisor",
                        attempt,
                        restart_epoch = epoch,
                        config = %restart_path.display(),
                        rolled_back_config,
                        "envoy hot-restarted and is alive"
                    );
                    (
                        SubsystemRestartOutcome::Recovered,
                        format!("restart-epoch={epoch}"),
                    )
                } else {
                    (
                        self.failed_or_exhausted(attempt),
                        format!("restart-epoch={epoch}: process not alive after start"),
                    )
                }
            }
            Err(e) => {
                warn!(
                    target: "sng_swg::envoy::supervisor",
                    attempt,
                    restart_epoch = epoch,
                    error = %e,
                    "envoy hot-restart failed"
                );
                (
                    self.failed_or_exhausted(attempt),
                    format!("restart-epoch={epoch}: {e}"),
                )
            }
        };

        self.sink
            .record(SubsystemRestart {
                subsystem: SUBSYSTEM_NAME.to_owned(),
                reason,
                outcome,
                attempt,
                fail_open: matches!(self.config.fail_mode, FailMode::Open),
                rolled_back_config,
                backoff_ms,
                detail,
            })
            .await;

        outcome
    }

    /// Map a failed attempt to either `Failed` (retry) or `Exhausted`
    /// (give up and escalate) per the configured cap.
    fn failed_or_exhausted(&self, attempt: u32) -> SubsystemRestartOutcome {
        match self.config.restart_max_attempts {
            Some(max) if attempt >= max => SubsystemRestartOutcome::Exhausted,
            _ => SubsystemRestartOutcome::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn live_response_requires_200_and_live_body() {
        assert!(response_is_live(
            b"HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nLIVE\n"
        ));
        // 503 during init is not live.
        assert!(!response_is_live(
            b"HTTP/1.1 503 Service Unavailable\r\n\r\nPRE_INITIALIZING\n"
        ));
        // 200 but unexpected body is not trusted as live.
        assert!(!response_is_live(b"HTTP/1.1 200 OK\r\n\r\nMAYBE\n"));
        // Garbage / truncated response is not live.
        assert!(!response_is_live(b"nonsense"));
    }

    #[test]
    fn failed_or_exhausted_respects_attempt_budget() {
        let sup = EnvoySupervisor::new(
            Arc::new(crate::process::MockEnvoy::new()),
            Arc::new(AlwaysReady),
            "/etc/sng/envoy.yaml",
            EnvoySupervisorConfig {
                restart_max_attempts: Some(2),
                ..EnvoySupervisorConfig::default()
            },
        );
        assert_eq!(sup.failed_or_exhausted(1), SubsystemRestartOutcome::Failed);
        assert_eq!(
            sup.failed_or_exhausted(2),
            SubsystemRestartOutcome::Exhausted
        );
    }

    /// Minimal readiness stub for the unit tests in this module.
    #[derive(Debug)]
    struct AlwaysReady;

    #[async_trait]
    impl EnvoyReadiness for AlwaysReady {
        async fn ready(&self) -> bool {
            true
        }
    }
}

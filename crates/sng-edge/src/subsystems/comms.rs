// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Control-plane comms subsystem adapter.
//!
//! Owns the long-running mTLS / HTTP/2 connection to the SNG
//! control plane plus the policy-bundle puller. The start task:
//!
//! 1. Establishes a fresh [`ControlPlaneConnection`] via
//!    [`ControlPlaneClient::connect`].
//! 2. Pulls a bundle at the operator-configured cadence (or on
//!    operator-driven wake-ups via the cmd channel).
//! 3. Publishes any new bundle bytes through the supplied
//!    callback so the policy_eval / swg / fw subsystems can
//!    hot-swap their compiled state.
//! 4. On connection-level errors, drops the connection and
//!    reconnects with exponential backoff.
//!
//! The TLS material lives on disk — paths in
//! [`CommsConfig`] — so the binary fails fast at boot if the
//! cert / key / roots are missing rather than at first pull.

use crate::config::{CommsConfig, IdentityConfig, PolicyConfig};
use async_trait::async_trait;
use sng_comms::{
    Backoff, BundlePullOutcome, CommsError, ControlPlaneClient, ControlPlaneConnection,
    DeviceIdentity, PolicyPuller, PolicyPullerConfig, PolicyTrustStore, ReconnectBackoff,
    build_client_config, build_client_config_with_webpki_roots,
};
use sng_core::{
    BundleTarget, HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError,
    SubsystemHandle, SubsystemHealth,
};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::task;
use tokio::time::{MissedTickBehavior, interval};

/// Callback type for publishing freshly-pulled bundle bytes to
/// downstream consumers (policy_eval / swg / fw). Wrapped in a
/// `Send + Sync` Arc so the start task can hand off without
/// re-cloning the trait object for each callback fire.
pub type BundlePublisher =
    Arc<dyn Fn(BundleTarget, Vec<u8>) -> Result<(), String> + Send + Sync + 'static>;

/// Edge-tier control-plane comms subsystem.
pub struct CommsSubsystem {
    client: Arc<ControlPlaneClient>,
    puller: Arc<PolicyPuller>,
    target: BundleTarget,
    pull_interval: Duration,
    backoff_initial: Duration,
    backoff_max: Duration,
    publisher: BundlePublisher,
    /// Stats: monotonic counters for the health endpoint.
    stats: Arc<CommsStats>,
}

impl std::fmt::Debug for CommsSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommsSubsystem")
            .field("target", &self.target)
            .field("pull_interval", &self.pull_interval)
            .finish_non_exhaustive()
    }
}

/// Atomic-counter health stats for the comms subsystem.
#[derive(Debug, Default)]
pub struct CommsStats {
    /// Successful TCP+TLS+HTTP/2 connects.
    pub connects: AtomicU64,
    /// Connect attempts that failed.
    pub connect_failures: AtomicU64,
    /// Bundle pulls served by the control plane (any outcome).
    pub pulls: AtomicU64,
    /// Pulls that surfaced a fresh, validated bundle (200 OK +
    /// signature verified + version newer than cache).
    pub pulls_fresh: AtomicU64,
    /// Pulls that came back `304 Not Modified` (cache hit).
    pub pulls_not_modified: AtomicU64,
    /// Pulls that failed at any stage.
    pub pull_failures: AtomicU64,
    /// Bundles published downstream that the publisher rejected
    /// (e.g. policy_eval engine refused to swap).
    pub publish_failures: AtomicU64,
}

/// Errors raised when building the subsystem.
#[derive(Debug, thiserror::Error)]
pub enum CommsBuildError {
    /// Identity / cert / key load failure.
    #[error("identity load failed: {0}")]
    Identity(#[from] sng_comms::IdentityError),
    /// rustls ClientConfig construction failed (e.g. empty trust
    /// store).
    #[error("rustls client config failed: {0}")]
    Tls(#[from] sng_comms::ClientConfigError),
    /// ControlPlaneClient rejected the constructed config.
    #[error("control plane client init failed: {0}")]
    Client(#[from] CommsError),
    /// Server name override is not a valid DNS name.
    #[error("server name override is not a valid DNS name: {0}")]
    InvalidServerName(String),
    /// Trust roots file could not be parsed.
    #[error("trust roots file {path} could not be parsed: {source}")]
    TrustRoots {
        /// Path to the offending file.
        path: std::path::PathBuf,
        /// Underlying I/O / PEM parse error.
        #[source]
        source: std::io::Error,
    },
}

impl CommsSubsystem {
    /// Build from config — loads cert / key from disk, parses
    /// trust roots (or falls back to webpki built-ins), and
    /// constructs the [`ControlPlaneClient`]. Fails fast: if
    /// anything on the TLS / identity path is wrong the binary
    /// refuses to boot rather than failing on first pull.
    ///
    /// # Errors
    ///
    /// Returns [`CommsBuildError`] when identity load, TLS
    /// config, or client construction fails.
    pub fn new(
        cfg: &CommsConfig,
        identity_cfg: &IdentityConfig,
        policy_cfg: &PolicyConfig,
        target: BundleTarget,
        trust_store: Arc<PolicyTrustStore>,
        publisher: BundlePublisher,
    ) -> Result<Self, CommsBuildError> {
        let identity = DeviceIdentity::from_pem_files(&cfg.client_cert, &cfg.client_key)?;
        let tls_config = if let Some(path) = &cfg.trust_roots {
            let roots = load_root_pems(path)?;
            build_client_config(roots, Some(&identity))?
        } else {
            build_client_config_with_webpki_roots(Some(&identity))?
        };

        let server_name_owned = cfg
            .server_name
            .clone()
            .unwrap_or_else(|| host_from_endpoint(&cfg.endpoint));
        let server_name: rustls_pki_types::ServerName<'static> =
            rustls_pki_types::ServerName::try_from(server_name_owned.clone())
                .map_err(|_| CommsBuildError::InvalidServerName(server_name_owned))?;

        let client =
            ControlPlaneClient::new(cfg.endpoint.clone(), server_name, Arc::new(tls_config))?;

        let puller_cfg = PolicyPullerConfig {
            tenant_id: identity_cfg.tenant_id,
            target,
            path_override: policy_cfg.path_override.clone(),
        };
        let puller = PolicyPuller::new(puller_cfg, trust_store);

        Ok(Self {
            client: Arc::new(client),
            puller: Arc::new(puller),
            target,
            pull_interval: policy_cfg.pull_interval,
            backoff_initial: cfg.backoff_initial,
            backoff_max: cfg.backoff_max,
            publisher,
            stats: Arc::new(CommsStats::default()),
        })
    }

    /// Test-only constructor: takes a pre-built
    /// [`ControlPlaneClient`] + [`PolicyPuller`] so integration
    /// tests can wire a mock h2 endpoint.
    #[must_use]
    pub fn from_parts(
        client: Arc<ControlPlaneClient>,
        puller: Arc<PolicyPuller>,
        target: BundleTarget,
        pull_interval: Duration,
        backoff_initial: Duration,
        backoff_max: Duration,
        publisher: BundlePublisher,
    ) -> Self {
        Self {
            client,
            puller,
            target,
            pull_interval,
            backoff_initial,
            backoff_max,
            publisher,
            stats: Arc::new(CommsStats::default()),
        }
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<CommsStats> {
        &self.stats
    }

    /// The underlying control-plane client. Shared with the
    /// telemetry subsystem so a single TLS config + endpoint
    /// pairing serves both bundle pulls and event uploads.
    /// The client holds rustls + endpoint config only — actual
    /// sockets are opened independently by each subsystem via
    /// [`ControlPlaneClient::connect`], so sharing the client
    /// does not couple their reconnect cadences.
    #[must_use]
    pub fn client(&self) -> &Arc<ControlPlaneClient> {
        &self.client
    }
}

#[async_trait]
impl Subsystem for CommsSubsystem {
    fn name(&self) -> &'static str {
        "comms"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let client = Arc::clone(&self.client);
        let puller = Arc::clone(&self.puller);
        let publisher = Arc::clone(&self.publisher);
        let stats = Arc::clone(&self.stats);
        let target = self.target;
        let pull_interval = self.pull_interval;
        let backoff_initial = self.backoff_initial;
        let backoff_max = self.backoff_max;

        Ok(task::spawn(async move {
            let mut backoff = ReconnectBackoff::new(backoff_initial, backoff_max, 2);
            let mut conn: Option<ControlPlaneConnection> = None;
            let mut ticker = interval(pull_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // Skip the immediate first tick so we don't slam the
            // control plane the instant the supervisor boots.
            ticker.tick().await;

            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    _ = ticker.tick() => {
                        // Lazy-connect on first tick / after a
                        // drop.
                        if conn.is_none() {
                            match client.connect().await {
                                Ok(c) => {
                                    stats.connects.fetch_add(1, Ordering::Relaxed);
                                    backoff.reset();
                                    conn = Some(c);
                                }
                                Err(err) => {
                                    stats.connect_failures.fetch_add(1, Ordering::Relaxed);
                                    let delay = backoff.next_backoff();
                                    // u128 → u64 saturating cast keeps the
                                    // tracing field on the wire-friendly
                                    // schema; any Duration over u64::MAX ms
                                    // (~580M years) is obviously a config
                                    // bug we'd rather surface as "saturated"
                                    // than as a silent truncation.
                                    let delay_ms =
                                        u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
                                    tracing::warn!(
                                        target: "sng_edge::comms",
                                        error = %err,
                                        delay_ms,
                                        "control plane connect failed, will retry after delay"
                                    );
                                    // Race the backoff against shutdown so an
                                    // operator-initiated drain during a long
                                    // retry interval (default `backoff_max`
                                    // is 30s — exactly the supervisor's
                                    // per-subsystem drain budget) doesn't
                                    // park here until the budget elapses.
                                    tokio::select! {
                                        () = shutdown.wait() => break,
                                        () = tokio::time::sleep(delay) => {}
                                    }
                                    continue;
                                }
                            }
                        }

                        // The `conn.is_none()` branch above either
                        // populated `conn` or hit `continue`. A panic
                        // here would be a logic bug; match instead of
                        // `.expect` so a future refactor that breaks
                        // the invariant skips the pull rather than
                        // aborting.
                        let Some(active) = conn.as_ref() else {
                            continue;
                        };
                        stats.pulls.fetch_add(1, Ordering::Relaxed);
                        match puller.pull(active).await {
                            Ok(BundlePullOutcome::Updated(cached)) => {
                                stats.pulls_fresh.fetch_add(1, Ordering::Relaxed);
                                if let Err(e) = (publisher)(target, cached.bundle.body.clone()) {
                                    stats.publish_failures.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(
                                        target: "sng_edge::comms",
                                        publisher_error = %e,
                                        "policy bundle publisher rejected fresh bundle"
                                    );
                                }
                            }
                            Ok(BundlePullOutcome::NotModified) => {
                                stats.pulls_not_modified.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(err) => {
                                stats.pull_failures.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(
                                    target: "sng_edge::comms",
                                    error = %err,
                                    "policy bundle pull failed; will retry next tick"
                                );
                                if err.is_connection_fatal() {
                                    // Connection is unusable;
                                    // drop and reconnect on next
                                    // tick.
                                    conn = None;
                                }
                            }
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for CommsSubsystem {
    fn name(&self) -> &'static str {
        "comms"
    }

    async fn check(&self) -> SubsystemHealth {
        let connects = self.stats.connects.load(Ordering::Relaxed);
        let connect_failures = self.stats.connect_failures.load(Ordering::Relaxed);
        let pulls = self.stats.pulls.load(Ordering::Relaxed);
        let pulls_fresh = self.stats.pulls_fresh.load(Ordering::Relaxed);
        let pulls_not_modified = self.stats.pulls_not_modified.load(Ordering::Relaxed);
        let pull_failures = self.stats.pull_failures.load(Ordering::Relaxed);
        let publish_failures = self.stats.publish_failures.load(Ordering::Relaxed);

        // Degraded if we've never managed a connect and have
        // attempted at least one. Up otherwise.
        let status = if connects == 0 && connect_failures > 0 {
            HealthStatus::Down
        } else if pull_failures > 0 && pulls_fresh == 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "connects={connects}, connect_failures={connect_failures}, \
                 pulls={pulls}, fresh={pulls_fresh}, \
                 not_modified={pulls_not_modified}, \
                 pull_failures={pull_failures}, publish_failures={publish_failures}"
            )),
        }
    }
}

/// Reasonable "is this connection fatal" heuristic. Used to
/// decide whether to drop+reconnect or just retry the next pull.
trait IsConnectionFatal {
    fn is_connection_fatal(&self) -> bool;
}

impl IsConnectionFatal for CommsError {
    fn is_connection_fatal(&self) -> bool {
        matches!(
            self,
            CommsError::Connect(_)
                | CommsError::Http2(_)
                | CommsError::Io(_)
                | CommsError::AlpnMismatch
        )
    }
}

/// Extract the host portion of `host:port` (or `[ipv6]:port`),
/// stripping the IPv6 brackets if present. Used as the SNI when
/// the operator didn't override `server_name`.
fn host_from_endpoint(ep: &str) -> String {
    if let Some(rest) = ep.strip_prefix('[') {
        if let Some(close) = rest.find(']') {
            return rest[..close].to_owned();
        }
    }
    ep.rsplit_once(':')
        .map_or_else(|| ep.to_owned(), |(host, _port)| host.to_owned())
}

/// Load PEM-encoded root certificates from disk. Splits on the
/// `-----END CERTIFICATE-----` marker so a multi-cert PEM bundle
/// is admitted without pulling in `rustls-pemfile`.
fn load_root_pems(
    path: &Path,
) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, CommsBuildError> {
    let bytes = std::fs::read(path).map_err(|e| CommsBuildError::TrustRoots {
        path: path.to_path_buf(),
        source: e,
    })?;
    // Iterate PEM blocks. The hyper / rustls-pemfile crates do
    // this for us in production, but pulling in another dep
    // just for this is overkill — the parser is six lines.
    let mut out = Vec::new();
    let text = std::str::from_utf8(&bytes).map_err(|e| CommsBuildError::TrustRoots {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
    })?;
    let mut remaining = text;
    while let Some(start) = remaining.find("-----BEGIN CERTIFICATE-----") {
        let after_start = &remaining[start..];
        let Some(end) = after_start.find("-----END CERTIFICATE-----") else {
            break;
        };
        let block = &after_start[..end + "-----END CERTIFICATE-----".len()];
        let body_start = "-----BEGIN CERTIFICATE-----".len();
        let body_end = block.len() - "-----END CERTIFICATE-----".len();
        let body: String = block[body_start..body_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let der = base64_decode(&body).map_err(|e| CommsBuildError::TrustRoots {
            path: path.to_path_buf(),
            source: std::io::Error::other(e),
        })?;
        out.push(rustls_pki_types::CertificateDer::from(der));
        remaining = &after_start[end + "-----END CERTIFICATE-----".len()..];
    }
    if out.is_empty() {
        return Err(CommsBuildError::TrustRoots {
            path: path.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "no CERTIFICATE blocks in trust roots PEM",
            ),
        });
    }
    Ok(out)
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64 decode failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_from_endpoint_strips_brackets_and_port() {
        assert_eq!(
            host_from_endpoint("control.example.com:443"),
            "control.example.com"
        );
        assert_eq!(host_from_endpoint("[::1]:8443"), "::1");
        assert_eq!(host_from_endpoint("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(host_from_endpoint("plain.host"), "plain.host");
    }

    #[test]
    fn comms_stats_defaults_to_zero() {
        let stats = CommsStats::default();
        assert_eq!(stats.connects.load(Ordering::Relaxed), 0);
        assert_eq!(stats.pulls.load(Ordering::Relaxed), 0);
    }
}

// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Ext-authz verdict-listener subsystem adapter.
//!
//! This is the "deployment-layer concern" the [`sng_swg::manager`]
//! docs say the SWG manager deliberately does **not** own: the
//! in-process server that answers Envoy's ext-authz filter. The
//! [`crate::subsystems::SwgSubsystem`] owns Envoy's process + config
//! lifecycle; this adapter owns the [`sng_swg::ExtAuthzListener`]
//! task that binds the Unix socket Envoy's `ext_authz` cluster dials
//! and turns each forwarded request into an allow/deny verdict via a
//! composed [`sng_swg::ExtAuthzHandler`].
//!
//! The whole surface is **default-off** (`swg.ext_authz_enabled =
//! false`). Until an operator opts in, Envoy's ext-authz cluster
//! dials a socket nobody serves and — per its fail-open config —
//! waves traffic through, exactly as before this subsystem existed.
//! When enabled the adapter:
//!
//! * Composes a handler from the always-required verdict deps (URL
//!   categorizer, malware hash list, SNI bypass list, rate limiter,
//!   telemetry sink) plus the safe-browsing category deny policy
//!   ([`sng_swg::CategoryDenyPolicy::safe_browsing_defaults`]).
//! * Optionally wires a [`sng_swg::ClamdScanner`] as the streaming
//!   content-scan stage when `swg.clamav_enabled = true`.
//! * Binds the listener and serves verdicts until shutdown.
//!
//! The categorizer / malware / bypass sets start empty: like every
//! other producer in the edge they are seeded by the control-plane
//! policy bundle (the handler's rule sets are hot-swappable). A
//! freshly-enabled listener therefore enforces the safe-browsing
//! baseline + (optionally) ClamAV from the first request, and gains
//! tenant-specific category/hash rules once the first bundle lands.

use crate::config::SwgConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_swg::{
    BypassList, CategoryDenyPolicy, ClamdConfig, ClamdScanner, ContentScanner, ExtAuthzHandler,
    ExtAuthzHandlerBuilder, ExtAuthzListener, ExtAuthzListenerConfig, LocalCategoryDb, RateLimiter,
    StaticMalwareList, TelemetryEmitter, VerdictEvent,
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::task;

/// Telemetry sink for the listener's handler. Forwards each verdict
/// to the tracing subsystem at debug level. The richer integration —
/// lifting [`VerdictEvent`] onto the shared telemetry pipeline via
/// the existing [`sng_swg::telemetry::SwgEventSource`] `EventSource`
/// impl — is intentionally out of scope for this default-off slice:
/// it requires threading a producer-side pipeline source through the
/// supervisor's telemetry wiring, which is a follow-up. Logging keeps
/// the verdict stream observable without a half-built pipeline hook.
#[derive(Debug)]
struct TracingVerdictEmitter;

impl TelemetryEmitter for TracingVerdictEmitter {
    fn emit(&self, event: VerdictEvent) {
        tracing::debug!(
            target: "sng_edge::ext_authz",
            tenant = %event.tenant_id,
            principal = %event.principal_id,
            host = %event.http.host,
            verdict = ?event.swg_verdict,
            "ext_authz verdict"
        );
    }
}

/// Edge-tier ext-authz verdict-listener subsystem.
pub struct ExtAuthzSubsystem {
    enable: bool,
    listener_cfg: ExtAuthzListenerConfig,
    /// Composed handler. `None` when disabled, or when an enabled
    /// build failed (logged at construction; the subsystem then
    /// idles rather than crashing the supervisor).
    handler: Option<ExtAuthzHandler>,
    /// Human-readable description of the wired content-scan posture,
    /// surfaced on the health report.
    scanner_detail: String,
}

impl std::fmt::Debug for ExtAuthzSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthzSubsystem")
            .field("enable", &self.enable)
            .field("socket", &self.listener_cfg.socket_path)
            .field("handler_set", &self.handler.is_some())
            .field("scanner", &self.scanner_detail)
            .finish_non_exhaustive()
    }
}

impl ExtAuthzSubsystem {
    /// Build the subsystem from the SWG config slice. When
    /// `ext_authz_enabled` is false the handler is not composed and
    /// the subsystem idles until shutdown; the listener socket is
    /// never bound, so Envoy keeps fail-opening exactly as before.
    #[must_use]
    pub fn new(cfg: &SwgConfig) -> Self {
        let listener_cfg = ExtAuthzListenerConfig::with_socket(cfg.ext_authz_socket.clone());
        if !cfg.ext_authz_enabled {
            return Self {
                enable: false,
                listener_cfg,
                handler: None,
                scanner_detail: "disabled".into(),
            };
        }

        let (scanner, scanner_detail) = build_scanner(cfg);
        let handler = match build_handler(scanner) {
            Ok(h) => Some(h),
            Err(e) => {
                // The deps we feed the builder are always present, so
                // this is unreachable in practice; logging + idling
                // (rather than unwrapping) keeps the adapter contract
                // — never panic, never crash the supervisor.
                tracing::error!(
                    target: "sng_edge::ext_authz",
                    error = %e,
                    "ext_authz handler build failed; listener will idle"
                );
                None
            }
        };

        Self {
            enable: true,
            listener_cfg,
            handler,
            scanner_detail,
        }
    }

    /// The socket path the listener binds. Exposed for diagnostics /
    /// tests.
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.listener_cfg.socket_path
    }
}

/// Compose the verdict handler from the always-required deps plus the
/// safe-browsing deny policy and (optionally) the content scanner.
fn build_handler(
    scanner: Option<Arc<dyn ContentScanner>>,
) -> Result<ExtAuthzHandler, sng_swg::SwgError> {
    let mut builder = ExtAuthzHandlerBuilder::new()
        // Empty seed sets — the policy bundle hot-swaps real rules in.
        .with_categorizer(Arc::new(LocalCategoryDb::new(vec![])))
        .with_malware(Arc::new(StaticMalwareList::new(std::iter::empty())))
        .with_bypass(Arc::new(BypassList::industry_defaults()))
        // Effectively unlimited until a per-tenant rate policy lands,
        // so rate limiting never silently masks a verdict.
        .with_rate_limiter(RateLimiter::with_system_clock(1_000_000.0, 1_000_000.0))
        .with_telemetry(Arc::new(TracingVerdictEmitter))
        // The opt-in safe-browsing baseline: deny the malware /
        // phishing / etc. category subtree out of the box.
        .with_deny_policy(CategoryDenyPolicy::safe_browsing_defaults());
    if let Some(scanner) = scanner {
        builder = builder.with_content_scanner(scanner);
    }
    builder.build()
}

/// Build the optional ClamAV scanner from config. Returns the scanner
/// (when `clamav_enabled`) and a description for the health report.
fn build_scanner(cfg: &SwgConfig) -> (Option<Arc<dyn ContentScanner>>, String) {
    if !cfg.clamav_enabled {
        return (None, "clamav=off".into());
    }
    let mut clamd = parse_clamd_endpoint(&cfg.clamav_endpoint);
    clamd.max_scan_bytes = cfg.clamav_max_bytes;
    clamd.chunk_size = cfg.clamav_chunk_size;
    clamd.scan_timeout = cfg.clamav_timeout;
    clamd.fail_open = cfg.clamav_fail_open;
    let detail = format!(
        "clamav=on endpoint={} fail_open={}",
        cfg.clamav_endpoint, cfg.clamav_fail_open
    );
    let scanner: Arc<dyn ContentScanner> = Arc::new(ClamdScanner::new(clamd));
    (Some(scanner), detail)
}

/// Parse a `clamd` endpoint string into a [`ClamdConfig`]. Accepts
/// `unix:///path` (Unix only), `tcp://host:port`, or a bare
/// `host:port` (treated as TCP). A bare path on Unix is also accepted
/// as a Unix socket so an operator who writes `/run/clamd.sock`
/// without a scheme still works.
fn parse_clamd_endpoint(endpoint: &str) -> ClamdConfig {
    let trimmed = endpoint.trim();
    #[cfg(unix)]
    if let Some(path) = trimmed.strip_prefix("unix://") {
        return ClamdConfig::unix(PathBuf::from(path));
    }
    if let Some(addr) = trimmed.strip_prefix("tcp://") {
        return ClamdConfig::tcp(addr.to_string());
    }
    #[cfg(unix)]
    if trimmed.starts_with('/') {
        return ClamdConfig::unix(PathBuf::from(trimmed));
    }
    ClamdConfig::tcp(trimmed.to_string())
}

#[async_trait]
impl Subsystem for ExtAuthzSubsystem {
    fn name(&self) -> &'static str {
        "ext_authz"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let enable = self.enable;
        let handler = self.handler.clone();
        let listener_cfg = self.listener_cfg.clone();
        Ok(task::spawn(async move {
            // Disabled, or an enabled build that failed: idle until
            // shutdown so the supervisor sees a well-behaved
            // subsystem rather than an early exit.
            let Some(handler) = handler.filter(|_| enable) else {
                shutdown.wait().await;
                return Ok(());
            };
            let listener =
                ExtAuthzListener::bind(&listener_cfg, handler).map_err(|e| -> SubsystemError {
                    Box::new(std::io::Error::other(format!(
                        "ext_authz listener bind failed: {e}"
                    )))
                })?;
            tracing::info!(
                target: "sng_edge::ext_authz",
                socket = %listener.socket_path().display(),
                "ext_authz listener serving"
            );
            listener.run(async move { shutdown.wait().await }).await;
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for ExtAuthzSubsystem {
    fn name(&self) -> &'static str {
        "ext_authz"
    }

    async fn check(&self) -> SubsystemHealth {
        let name = <Self as HealthCheck>::name(self).into();
        if !self.enable {
            return SubsystemHealth {
                name,
                status: HealthStatus::Up,
                detail: Some("enabled=false".into()),
            };
        }
        // An enabled subsystem whose handler failed to build is the
        // one degraded state: the socket is never served, so report
        // it rather than masquerading as healthy.
        if self.handler.is_none() {
            return SubsystemHealth {
                name,
                status: HealthStatus::Down,
                detail: Some("enabled=true but handler build failed".into()),
            };
        }
        SubsystemHealth {
            name,
            status: HealthStatus::Up,
            detail: Some(format!(
                "socket={}, {}",
                self.listener_cfg.socket_path.display(),
                self.scanner_detail
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn base_cfg(dir: &std::path::Path) -> SwgConfig {
        SwgConfig {
            ext_authz_socket: dir.join("ext_authz.sock"),
            ..SwgConfig::default()
        }
    }

    #[test]
    fn parse_endpoint_tcp_scheme() {
        let c = parse_clamd_endpoint("tcp://10.0.0.1:3310");
        assert_eq!(c.endpoint.to_string(), "tcp://10.0.0.1:3310");
    }

    #[test]
    fn parse_endpoint_bare_hostport_is_tcp() {
        let c = parse_clamd_endpoint("127.0.0.1:3310");
        assert_eq!(c.endpoint.to_string(), "tcp://127.0.0.1:3310");
    }

    #[cfg(unix)]
    #[test]
    fn parse_endpoint_unix_scheme_and_bare_path() {
        assert_eq!(
            parse_clamd_endpoint("unix:///run/clamd.sock")
                .endpoint
                .to_string(),
            "unix:///run/clamd.sock"
        );
        assert_eq!(
            parse_clamd_endpoint("/run/clamd.sock").endpoint.to_string(),
            "unix:///run/clamd.sock"
        );
    }

    #[test]
    fn disabled_has_no_handler_and_idles() {
        let dir = tempdir().unwrap();
        let sub = ExtAuthzSubsystem::new(&base_cfg(dir.path()));
        assert!(!sub.enable);
        assert!(sub.handler.is_none());
    }

    #[tokio::test]
    async fn disabled_subsystem_idles_until_shutdown() {
        let dir = tempdir().unwrap();
        let sub = ExtAuthzSubsystem::new(&base_cfg(dir.path()));
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = <ExtAuthzSubsystem as Subsystem>::start(&sub, signal)
            .await
            .unwrap();
        trigger.fire();
        handle.await.unwrap().unwrap();
        let health = <ExtAuthzSubsystem as HealthCheck>::check(&sub).await;
        assert_eq!(health.status, HealthStatus::Up);
        assert!(health.detail.unwrap().contains("enabled=false"));
        // The socket was never bound.
        assert!(!sub.socket_path().exists());
    }

    #[test]
    fn enabled_builds_handler_without_scanner() {
        let dir = tempdir().unwrap();
        let cfg = SwgConfig {
            ext_authz_enabled: true,
            ..base_cfg(dir.path())
        };
        let sub = ExtAuthzSubsystem::new(&cfg);
        assert!(sub.enable);
        assert!(sub.handler.is_some());
        assert_eq!(sub.scanner_detail, "clamav=off");
    }

    #[test]
    fn enabled_with_clamav_wires_scanner_detail() {
        let dir = tempdir().unwrap();
        let cfg = SwgConfig {
            ext_authz_enabled: true,
            clamav_enabled: true,
            clamav_endpoint: "tcp://127.0.0.1:3310".into(),
            ..base_cfg(dir.path())
        };
        let sub = ExtAuthzSubsystem::new(&cfg);
        assert!(sub.handler.is_some());
        assert!(sub.scanner_detail.contains("clamav=on"));
        assert!(sub.scanner_detail.contains("127.0.0.1:3310"));
    }

    #[tokio::test]
    async fn enabled_subsystem_binds_and_serves_until_shutdown() {
        let dir = tempdir().unwrap();
        let cfg = SwgConfig {
            ext_authz_enabled: true,
            ..base_cfg(dir.path())
        };
        let sub = ExtAuthzSubsystem::new(&cfg);
        let socket = sub.socket_path().to_path_buf();
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = <ExtAuthzSubsystem as Subsystem>::start(&sub, signal)
            .await
            .unwrap();

        // Poll until the listener has bound the socket.
        let mut bound = false;
        for _ in 0..50 {
            if socket.exists() {
                bound = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(bound, "listener did not bind socket");

        // It answers a request with a verdict.
        let mut client = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let req = r#"{"headers":[[":method","get"],[":scheme","https"],[":path","/"],["host","example.com"],["x-sng-tenant","t1"],["x-sng-principal","p1"]]}"#;
        let frame = format!(
            "POST /ext_authz HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
            req.len(),
            req
        );
        client.write_all(frame.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        // Read a bounded amount; the response is small.
        let mut tmp = [0u8; 1024];
        let n = client.read(&mut tmp).await.unwrap();
        resp.extend_from_slice(&tmp[..n]);
        let text = String::from_utf8_lossy(&resp);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        assert!(text.contains("\"action\""), "{text}");

        let health = <ExtAuthzSubsystem as HealthCheck>::check(&sub).await;
        assert_eq!(health.status, HealthStatus::Up);

        trigger.fire();
        handle.await.unwrap().unwrap();
        // Socket unlinked on shutdown.
        assert!(!socket.exists());
    }
}

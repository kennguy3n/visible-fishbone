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
    BypassList, CategoryDenyPolicy, ClamdConfig, ClamdScanner, ContentScanner, DlpTelemetryEmitter,
    ExtAuthzHandler, ExtAuthzHandlerBuilder, ExtAuthzListener, ExtAuthzListenerConfig,
    DlpInlineEngine, LocalCategoryDb, RbiPolicyEngine, RbiProxyConfig, RateLimiter,
    StaticMalwareList, TelemetryEmitter, VerdictEvent,
    AiGovernanceEngine,
};
use sng_telemetry::TelemetryEvent;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use tokio::task;

/// Telemetry sink for the listener's handler. Publishes each ext-authz
/// verdict into the shared edge telemetry pipeline.
///
/// Each verdict is lifted onto the same [`TelemetryEvent::Http`]
/// envelope the canonical [`sng_swg::SwgEventSource`] produces and
/// pushed onto the producer half of the pipeline channel — the exact
/// `mpsc::Sender<TelemetryEvent>` bridge the DNS / ZTNA / SD-WAN
/// producers use ([`crate::supervisor`]). The pipeline's strict
/// redaction + identity enrichment then stamp the wire envelope, so an
/// ext-authz verdict surfaces on the operator dashboard through the
/// same dedup / redact / enrich / spool / batch path as every other
/// event class — observable, not just debug-logged.
///
/// **No-PII posture.** Only [`VerdictEvent::http`] crosses onto the
/// shared envelope; the per-request `tenant_id` / `principal_id` are
/// deliberately dropped here, identical to
/// [`sng_swg::SwgEventSource`]'s `recv`. The single-tenant edge wire
/// contract is preserved (the pipeline's [`sng_telemetry::Enricher`]
/// stamps the agent's bound identity) and no per-request identifier
/// leaks onto the wire. The deny path's `&'static str` reason rides
/// inside the normalised [`sng_core::events::HttpEvent`] exactly as the
/// verdict layer produced it.
///
/// **Hot-path safety.** [`TelemetryEmitter::emit`] runs synchronously
/// on the per-request verdict path Envoy is awaiting, so a full or
/// closed pipeline channel drops the event (counted + logged) rather
/// than blocking the verdict — the same drop-on-backpressure policy
/// [`sng_swg::SwgEventSink`] uses.
#[derive(Debug)]
struct PipelineVerdictEmitter {
    telemetry: mpsc::Sender<TelemetryEvent>,
    /// Shared with the owning subsystem so dropped-event pressure is
    /// surfaced on the health report rather than only in logs.
    dropped: Arc<AtomicU64>,
}

impl PipelineVerdictEmitter {
    fn new(telemetry: mpsc::Sender<TelemetryEvent>, dropped: Arc<AtomicU64>) -> Self {
        Self { telemetry, dropped }
    }
}

impl TelemetryEmitter for PipelineVerdictEmitter {
    fn emit(&self, event: VerdictEvent) {
        // Forward only the normalised, no-PII HttpEvent onto the shared
        // pipeline envelope (mirrors sng_swg::SwgEventSource::recv); the
        // per-request tenant / principal never reach the wire.
        if self
            .telemetry
            .try_send(TelemetryEvent::Http(event.http))
            .is_err()
        {
            // Per-request hot path: never block the verdict on telemetry
            // backpressure. Drop, count, and log so an operator can see
            // sustained pipeline pressure on the health report.
            let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                target: "sng_edge::ext_authz",
                dropped_total = total,
                "ext_authz telemetry channel full/closed — verdict event dropped"
            );
        }
    }
}

/// DLP telemetry sink for the listener's handler. Publishes each
/// inline DLP finding into the shared edge telemetry pipeline as a
/// `TelemetryEvent::Dlp` — the same envelope the endpoint DLP agent
/// uses. The `DlpEvent` is metadata-only by construction (no matched
/// bytes, no user content), so it rides the same dedup / redact /
/// batch path as every other event class.
///
/// **Hot-path safety.** Same drop-on-backpressure policy as
/// [`PipelineVerdictEmitter`]: `try_send` on the shared channel,
/// count + log on failure, never block the verdict.
#[derive(Debug)]
struct PipelineDlpEmitter {
    telemetry: mpsc::Sender<TelemetryEvent>,
    dropped: Arc<AtomicU64>,
}

impl PipelineDlpEmitter {
    fn new(telemetry: mpsc::Sender<TelemetryEvent>, dropped: Arc<AtomicU64>) -> Self {
        Self { telemetry, dropped }
    }
}

impl DlpTelemetryEmitter for PipelineDlpEmitter {
    fn emit_dlp(&self, event: sng_core::events::DlpEvent) {
        if self
            .telemetry
            .try_send(TelemetryEvent::Dlp(event))
            .is_err()
        {
            let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                target: "sng_edge::ext_authz",
                dropped_total = total,
                "ext_authz dlp telemetry channel full/closed — dlp event dropped"
            );
        }
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
    /// Human-readable description of the inline DLP posture,
    /// surfaced on the health report.
    dlp_detail: String,
    /// Human-readable description of the RBI posture,
    /// surfaced on the health report.
    rbi_detail: String,
    /// Human-readable description of the AI-governance posture,
    /// surfaced on the health report.
    ai_governance_detail: String,
    /// Count of verdict telemetry events the emitter dropped under
    /// pipeline backpressure. Shared with the [`PipelineVerdictEmitter`]
    /// and surfaced on the health report. Stays `0` when disabled
    /// (no emitter is wired, so nothing is ever published).
    telemetry_drops: Arc<AtomicU64>,
}

impl std::fmt::Debug for ExtAuthzSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthzSubsystem")
            .field("enable", &self.enable)
            .field("socket", &self.listener_cfg.socket_path)
            .field("handler_set", &self.handler.is_some())
            .field("scanner", &self.scanner_detail)
            .field("dlp", &self.dlp_detail)
            .field("rbi", &self.rbi_detail)
            .field("ai_governance", &self.ai_governance_detail)
            .field(
                "telemetry_drops",
                &self.telemetry_drops.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl ExtAuthzSubsystem {
    /// Build the subsystem from the SWG config slice. When
    /// `ext_authz_enabled` is false the handler is not composed and
    /// the subsystem idles until shutdown; the listener socket is
    /// never bound, so Envoy keeps fail-opening exactly as before.
    ///
    /// `telemetry` is the producer half of the shared edge telemetry
    /// pipeline channel (the same `mpsc::Sender<TelemetryEvent>` the
    /// DNS / ZTNA / SD-WAN producers receive). When enabled, the
    /// composed handler publishes each verdict through it via the
    /// [`PipelineVerdictEmitter`]. When **disabled**, the sender is
    /// dropped immediately and never used: no handler is composed, no
    /// socket is bound, and nothing is ever emitted — behaviour is
    /// byte-for-byte unchanged from before this subsystem existed.
    #[must_use]
    pub fn new(cfg: &SwgConfig, telemetry: mpsc::Sender<TelemetryEvent>) -> Self {
        let listener_cfg = ExtAuthzListenerConfig::with_socket(cfg.ext_authz_socket.clone());
        let telemetry_drops = Arc::new(AtomicU64::new(0));
        if !cfg.ext_authz_enabled {
            // Drop the producer-side sender immediately: a disabled
            // ext-authz surface holds no clone of the pipeline channel,
            // so it can never keep the channel alive nor emit.
            drop(telemetry);
            return Self {
                enable: false,
                listener_cfg,
                handler: None,
                scanner_detail: "disabled".into(),
                dlp_detail: "disabled".into(),
                rbi_detail: "disabled".into(),
                ai_governance_detail: "disabled".into(),
                telemetry_drops,
            };
        }

        let (scanner, scanner_detail) = build_scanner(cfg);

        // Wire the inline DLP engine when the operator has opted in.
        // The engine starts with an empty policy; the control plane
        // hot-swaps a real policy via the policy bundle. The DLP
        // telemetry emitter shares the same pipeline channel and
        // drop counter as the verdict emitter so both event classes
        // surface on the same health report.
        let (dlp_engine, dlp_telemetry, dlp_detail) = if cfg.dlp_inline_enabled {
            let engine = Arc::new(DlpInlineEngine::new());
            let dlp_emitter: Arc<dyn DlpTelemetryEmitter> =
                Arc::new(PipelineDlpEmitter::new(
                    telemetry.clone(),
                    Arc::clone(&telemetry_drops),
                ));
            (Some(engine), Some(dlp_emitter), "dlp=on".to_string())
        } else {
            (None, None, "dlp=off".to_string())
        };

        // Wire the RBI policy engine when the operator has opted in
        // and configured a proxy base URL. The engine starts with an
        // empty policy; the control plane hot-swaps a real policy via
        // the policy bundle.
        let (rbi_engine, rbi_detail) = if cfg.rbi_enabled && !cfg.rbi_proxy_base_url.is_empty() {
            let engine = Arc::new(RbiPolicyEngine::new(RbiProxyConfig {
                base_url: cfg.rbi_proxy_base_url.clone(),
            }));
            (Some(engine), "rbi=on".to_string())
        } else {
            (None, "rbi=off".to_string())
        };

        // Wire the AI-governance engine when the operator has opted
        // in. The engine starts with a default (monitor-only) policy;
        // the control plane hot-swaps a real policy via the policy
        // bundle.
        let (ai_governance_engine, ai_governance_detail) = if cfg.ai_governance_enabled {
            let engine = Arc::new(AiGovernanceEngine::new());
            (Some(engine), "ai_governance=on".to_string())
        } else {
            (None, "ai_governance=off".to_string())
        };

        let emitter: Arc<dyn TelemetryEmitter> = Arc::new(PipelineVerdictEmitter::new(
            telemetry,
            Arc::clone(&telemetry_drops),
        ));
        let handler = match build_handler(scanner, emitter, dlp_engine, dlp_telemetry, rbi_engine, ai_governance_engine) {
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
            dlp_detail,
            rbi_detail,
            ai_governance_detail,
            telemetry_drops,
        }
    }

    /// The socket path the listener binds. Exposed for diagnostics /
    /// tests.
    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        &self.listener_cfg.socket_path
    }

    /// Number of verdict telemetry events dropped under pipeline
    /// backpressure since boot. Always `0` while disabled. Exposed for
    /// diagnostics / tests and surfaced on the health report.
    #[must_use]
    pub fn telemetry_drops(&self) -> u64 {
        self.telemetry_drops.load(Ordering::Relaxed)
    }
}

/// Compose the verdict handler from the always-required deps plus the
/// safe-browsing deny policy and (optionally) the content scanner.
/// `telemetry` is the verdict emitter the composed handler invokes on
/// every decision; the caller wires the pipeline-integrated
/// [`PipelineVerdictEmitter`] here.
fn build_handler(
    scanner: Option<Arc<dyn ContentScanner>>,
    telemetry: Arc<dyn TelemetryEmitter>,
    dlp_engine: Option<Arc<DlpInlineEngine>>,
    dlp_telemetry: Option<Arc<dyn DlpTelemetryEmitter>>,
    rbi_engine: Option<Arc<RbiPolicyEngine>>,
    ai_governance_engine: Option<Arc<AiGovernanceEngine>>,
) -> Result<ExtAuthzHandler, sng_swg::SwgError> {
    let mut builder = ExtAuthzHandlerBuilder::new()
        // Empty seed sets — the policy bundle hot-swaps real rules in.
        .with_categorizer(Arc::new(LocalCategoryDb::new(vec![])))
        .with_malware(Arc::new(StaticMalwareList::new(std::iter::empty())))
        .with_bypass(Arc::new(BypassList::industry_defaults()))
        // Effectively unlimited until a per-tenant rate policy lands,
        // so rate limiting never silently masks a verdict.
        .with_rate_limiter(RateLimiter::with_system_clock(1_000_000.0, 1_000_000.0))
        .with_telemetry(telemetry)
        // The opt-in safe-browsing baseline: deny the malware /
        // phishing / etc. category subtree out of the box.
        .with_deny_policy(CategoryDenyPolicy::safe_browsing_defaults());
    if let Some(scanner) = scanner {
        builder = builder.with_content_scanner(scanner);
    }
    if let Some(engine) = dlp_engine {
        builder = builder.with_dlp_engine(engine);
    }
    if let Some(dlp_sink) = dlp_telemetry {
        builder = builder.with_dlp_telemetry(dlp_sink);
    }
    if let Some(rbi) = rbi_engine {
        builder = builder.with_rbi_engine(rbi);
    }
    if let Some(aig) = ai_governance_engine {
        builder = builder.with_ai_governance_engine(aig);
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
                "socket={}, {}, {}, telemetry_drops={}",
                self.listener_cfg.socket_path.display(),
                self.scanner_detail,
                self.dlp_detail,
                self.telemetry_drops.load(Ordering::Relaxed)
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

    fn telemetry_channel() -> (mpsc::Sender<TelemetryEvent>, mpsc::Receiver<TelemetryEvent>) {
        mpsc::channel(16)
    }

    /// Build a subsystem wired to a fresh telemetry channel, returning
    /// the receiver so a test can assert what reached the pipeline.
    fn new_sub(cfg: &SwgConfig) -> (ExtAuthzSubsystem, mpsc::Receiver<TelemetryEvent>) {
        let (tx, rx) = telemetry_channel();
        (ExtAuthzSubsystem::new(cfg, tx), rx)
    }

    fn sample_verdict_event() -> VerdictEvent {
        use sng_swg::{RequestContext, Verdict as SwgVerdict};
        let ctx = RequestContext {
            tenant_id: "t1".into(),
            principal_id: "p1".into(),
            method: "get".into(),
            scheme: "https".into(),
            host: "example.com".into(),
            path: "/".into(),
            sni: Some("example.com".into()),
            file_hash: None,
        };
        VerdictEvent::from_context(&ctx, SwgVerdict::allow_uncategorized())
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
        let (sub, _rx) = new_sub(&base_cfg(dir.path()));
        assert!(!sub.enable);
        assert!(sub.handler.is_none());
    }

    #[test]
    fn emitter_publishes_no_pii_http_event_onto_pipeline() {
        let (tx, mut rx) = telemetry_channel();
        let drops = Arc::new(AtomicU64::new(0));
        let emitter = PipelineVerdictEmitter::new(tx, Arc::clone(&drops));
        emitter.emit(sample_verdict_event());
        match rx.try_recv() {
            Ok(TelemetryEvent::Http(http)) => {
                assert_eq!(http.host, "example.com");
                assert_eq!(http.verdict, sng_core::envelope::Verdict::Allow);
                // status_code is request-side (Envoy stamps the wire
                // response), so it is 0 — confirms the normalised shape.
                assert_eq!(http.status_code, 0);
            }
            other => panic!("expected Http telemetry event, got {other:?}"),
        }
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn emitter_drops_and_counts_when_pipeline_closed() {
        let (tx, rx) = telemetry_channel();
        // Closing the consumer makes every try_send fail — the hot path
        // must drop + count rather than block or panic.
        drop(rx);
        let drops = Arc::new(AtomicU64::new(0));
        let emitter = PipelineVerdictEmitter::new(tx, Arc::clone(&drops));
        emitter.emit(sample_verdict_event());
        emitter.emit(sample_verdict_event());
        assert_eq!(drops.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn disabled_subsystem_idles_until_shutdown() {
        let dir = tempdir().unwrap();
        let (sub, mut rx) = new_sub(&base_cfg(dir.path()));
        // The disabled subsystem dropped its sender clone in `new`, so
        // the only producer is gone: the channel is closed and yields
        // nothing. This is the byte-for-byte "emit nothing when off"
        // guarantee at the wiring level.
        assert!(
            rx.recv().await.is_none(),
            "disabled subsystem must hold no sender and emit nothing"
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = <ExtAuthzSubsystem as Subsystem>::start(&sub, signal)
            .await
            .unwrap();
        trigger.fire();
        handle.await.unwrap().unwrap();
        let health = <ExtAuthzSubsystem as HealthCheck>::check(&sub).await;
        assert_eq!(health.status, HealthStatus::Up);
        assert!(health.detail.unwrap().contains("enabled=false"));
        assert_eq!(sub.telemetry_drops(), 0);
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
        let (sub, _rx) = new_sub(&cfg);
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
        let (sub, _rx) = new_sub(&cfg);
        assert!(sub.handler.is_some());
        assert!(sub.scanner_detail.contains("clamav=on"));
        assert!(sub.scanner_detail.contains("127.0.0.1:3310"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn enabled_subsystem_binds_and_serves_until_shutdown() {
        let dir = tempdir().unwrap();
        let cfg = SwgConfig {
            ext_authz_enabled: true,
            ..base_cfg(dir.path())
        };
        let (sub, _rx) = new_sub(&cfg);
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

    #[cfg(unix)]
    #[tokio::test]
    async fn enabled_listener_publishes_verdict_into_pipeline() {
        let dir = tempdir().unwrap();
        let cfg = SwgConfig {
            ext_authz_enabled: true,
            ..base_cfg(dir.path())
        };
        let (sub, mut rx) = new_sub(&cfg);
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

        // Drive one request end-to-end through the listener.
        let mut client = tokio::net::UnixStream::connect(&socket).await.unwrap();
        let req = r#"{"headers":[[":method","get"],[":scheme","https"],[":path","/"],["host","example.com"],["x-sng-tenant","t1"],["x-sng-principal","p1"]]}"#;
        let frame = format!(
            "POST /ext_authz HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n{}",
            req.len(),
            req
        );
        client.write_all(frame.as_bytes()).await.unwrap();
        let mut tmp = [0u8; 1024];
        let _ = client.read(&mut tmp).await.unwrap();

        // The verdict reached the shared telemetry pipeline, normalised
        // onto the no-PII HttpEvent envelope.
        let ev = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("verdict telemetry within budget")
            .expect("a telemetry event");
        match ev {
            TelemetryEvent::Http(http) => assert_eq!(http.host, "example.com"),
            other => panic!("expected Http telemetry event, got {other:?}"),
        }
        assert_eq!(sub.telemetry_drops(), 0);

        trigger.fire();
        handle.await.unwrap().unwrap();
    }
}

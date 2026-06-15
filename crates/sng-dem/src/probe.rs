//! The bounded synthetic-probe engine.
//!
//! [`ProbeEngine`] runs cheap synthetic probes against a set of
//! [`Target`]s and returns one [`ProbeResult`] per target. It is the
//! edge/agent half of DEM; the control-plane half
//! (`internal/service/dem`) ingests the results, scores them, and
//! alerts on degradation.
//!
//! ## Cost model (why this is safe at 5,000-tenant scale)
//!
//! * **Bounded concurrency.** A [`tokio::sync::Semaphore`] caps
//!   in-flight probes at [`EngineConfig::max_concurrency`]; the sweep
//!   never opens more sockets than that regardless of target count.
//! * **Bounded fan-out.** [`EngineConfig::max_targets`] hard-caps the
//!   targets evaluated per sweep, so a misconfigured tenant cannot
//!   enqueue unbounded work.
//! * **Hard per-probe deadlines.** Every phase is wrapped in
//!   [`tokio::time::timeout`] using the target's `timeout_ms`; a
//!   black-holed target costs at most one timeout, never a hang.
//! * **Startup jitter.** Each probe waits a uniform random fraction
//!   of its timeout before starting, smearing connection bursts so a
//!   fleet does not synchronise into a thundering herd.
//! * **Graceful degradation.** An unreachable target yields a
//!   `success == false` [`ProbeResult`] — a first-class signal — not
//!   an error that aborts the sweep.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::error::DemError;
use crate::resolver::{Resolver, SystemResolver};
use crate::result::{ProbeErrorKind, ProbeResult};
use crate::target::{EngineConfig, ProbeKind, Target};

/// Internal per-phase failure carrying the classified kind and a
/// human-readable detail.
struct ProbeFail {
    kind: ProbeErrorKind,
    detail: String,
}

impl ProbeFail {
    fn new(kind: ProbeErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Mutable accumulator of the per-phase timings populated as a probe
/// proceeds.
#[derive(Default)]
struct Phases {
    dns_ms: Option<f64>,
    tcp_ms: Option<f64>,
    ttfb_ms: Option<f64>,
    total_ms: Option<f64>,
    http_status: Option<u16>,
}

/// HTTP-phase timings.
struct HttpTiming {
    ttfb_ms: f64,
    total_ms: f64,
    status: u16,
}

/// Unix-epoch milliseconds, saturating rather than panicking on a
/// pre-epoch clock.
fn now_unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis());
    u64::try_from(ms).unwrap_or(u64::MAX)
}

/// Milliseconds elapsed since `start` on the (test-pausable) Tokio
/// clock.
fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

/// Run `fut` under a hard deadline, mapping an elapsed deadline onto a
/// [`ProbeErrorKind::Timeout`] failure.
async fn with_timeout<F, T>(deadline: Duration, fut: F) -> Result<T, ProbeFail>
where
    F: Future<Output = Result<T, ProbeFail>>,
{
    match tokio::time::timeout(deadline, fut).await {
        Ok(inner) => inner,
        Err(_elapsed) => Err(ProbeFail::new(ProbeErrorKind::Timeout, "deadline exceeded")),
    }
}

/// Classify a `reqwest` transport error into a probe-failure kind.
fn classify_reqwest(e: &reqwest::Error) -> ProbeFail {
    let kind = if e.is_timeout() {
        ProbeErrorKind::Timeout
    } else if e.is_connect() {
        ProbeErrorKind::Connect
    } else {
        // TLS handshake faults and other request-layer errors are
        // bucketed as `Tls` — they sit above the TCP connect that
        // already succeeded.
        ProbeErrorKind::Tls
    };
    ProbeFail::new(kind, e.to_string())
}

/// TCP-connect phase: open and immediately drop a connection to
/// `peer`, measuring nothing here (the caller times it).
async fn tcp_connect(peer: SocketAddr, deadline: Duration) -> Result<(), ProbeFail> {
    with_timeout(deadline, async move {
        tokio::net::TcpStream::connect(peer)
            .await
            .map(drop)
            .map_err(|e| ProbeFail::new(ProbeErrorKind::Connect, e.to_string()))
    })
    .await
}

/// HTTP(S) phase: issue a GET, timing TTFB (headers received) and
/// total (body drained). Returns the status regardless of value; the
/// caller decides health from it.
async fn http_phase(
    client: &reqwest::Client,
    url: &str,
    deadline: Duration,
) -> Result<HttpTiming, ProbeFail> {
    let start = Instant::now();
    let resp = with_timeout(deadline, async {
        client
            .get(url)
            .send()
            .await
            .map_err(|e| classify_reqwest(&e))
    })
    .await?;
    let ttfb_ms = elapsed_ms(start);
    let status = resp.status().as_u16();
    // Drain the body so `total_ms` reflects the full response and the
    // connection is released promptly (we keep no idle pool).
    let _body = with_timeout(deadline, async {
        resp.bytes().await.map_err(|e| classify_reqwest(&e))
    })
    .await?;
    let total_ms = elapsed_ms(start);
    Ok(HttpTiming {
        ttfb_ms,
        total_ms,
        status,
    })
}

/// Assemble the final [`ProbeResult`] from the collected phases and an
/// optional transport failure.
fn build_result(
    target: &Target,
    phases: &Phases,
    fail: Option<ProbeFail>,
    observed_at_ms: u64,
) -> ProbeResult {
    let status_healthy = phases.http_status.is_some_and(|s| s < 400);
    let success = fail.is_none()
        && match target.kind {
            ProbeKind::Http | ProbeKind::Https => status_healthy,
            ProbeKind::Dns | ProbeKind::Tcp => true,
        };
    let (error_kind, error_detail) = match fail {
        Some(f) => (Some(f.kind), Some(f.detail)),
        None if !success => (
            Some(ProbeErrorKind::Http),
            phases.http_status.map(|s| format!("unhealthy status {s}")),
        ),
        None => (None, None),
    };
    ProbeResult {
        target_key: target.key.clone(),
        target_name: target.name.clone(),
        probe_kind: target.kind,
        success,
        dns_ms: phases.dns_ms,
        tcp_ms: phases.tcp_ms,
        tls_ms: None,
        ttfb_ms: phases.ttfb_ms,
        total_ms: phases.total_ms,
        http_status: phases.http_status,
        error_kind,
        error_detail,
        observed_at_ms,
    }
}

/// Probe a single target end-to-end. Never returns an error: a failed
/// probe is a `success == false` result.
async fn probe_target<R: Resolver>(
    resolver: &R,
    client: &reqwest::Client,
    target: &Target,
) -> ProbeResult {
    let observed_at_ms = now_unix_millis();
    if let Err(e) = target.validate() {
        let phases = Phases::default();
        return build_result(
            target,
            &phases,
            Some(ProbeFail::new(ProbeErrorKind::Config, e.to_string())),
            observed_at_ms,
        );
    }
    let deadline = target.timeout();
    let mut phases = Phases::default();

    // Resolve the host:port for the chosen kind.
    let (host, port) = match target.kind {
        ProbeKind::Dns | ProbeKind::Tcp => (target.address.clone(), target.port.unwrap_or(0)),
        ProbeKind::Http | ProbeKind::Https => match target.parsed_url() {
            Ok(url) => {
                let host = url.host_str().unwrap_or_default().to_string();
                let default_port = if matches!(target.kind, ProbeKind::Https) {
                    443
                } else {
                    80
                };
                (host, url.port_or_known_default().unwrap_or(default_port))
            }
            Err(e) => {
                return build_result(
                    target,
                    &phases,
                    Some(ProbeFail::new(ProbeErrorKind::Config, e.to_string())),
                    observed_at_ms,
                );
            }
        },
    };
    let resolve_port = if port == 0 { 443 } else { port };

    // DNS phase (every kind resolves).
    let dns_start = Instant::now();
    let addresses = match with_timeout(deadline, async {
        resolver
            .resolve(&host, resolve_port)
            .await
            .map_err(|e| ProbeFail::new(ProbeErrorKind::Dns, e.to_string()))
    })
    .await
    {
        Ok(addrs) => {
            phases.dns_ms = Some(elapsed_ms(dns_start));
            addrs
        }
        Err(f) => return build_result(target, &phases, Some(f), observed_at_ms),
    };
    if matches!(target.kind, ProbeKind::Dns) {
        phases.total_ms = phases.dns_ms;
        return build_result(target, &phases, None, observed_at_ms);
    }

    // TCP-connect phase (tcp / http / https).
    let Some(peer) = addresses.first().copied() else {
        return build_result(
            target,
            &phases,
            Some(ProbeFail::new(ProbeErrorKind::Dns, "no addresses")),
            observed_at_ms,
        );
    };
    let tcp_start = Instant::now();
    if let Err(f) = tcp_connect(peer, deadline).await {
        return build_result(target, &phases, Some(f), observed_at_ms);
    }
    phases.tcp_ms = Some(elapsed_ms(tcp_start));
    if matches!(target.kind, ProbeKind::Tcp) {
        phases.total_ms = Some(phases.dns_ms.unwrap_or(0.0) + phases.tcp_ms.unwrap_or(0.0));
        return build_result(target, &phases, None, observed_at_ms);
    }

    // HTTP(S) phase.
    match http_phase(client, &target.address, deadline).await {
        Ok(h) => {
            phases.ttfb_ms = Some(h.ttfb_ms);
            phases.total_ms = Some(h.total_ms);
            phases.http_status = Some(h.status);
            build_result(target, &phases, None, observed_at_ms)
        }
        Err(f) => build_result(target, &phases, Some(f), observed_at_ms),
    }
}

/// Wait a uniform random fraction of the target's timeout before
/// probing, smearing connection bursts across the sweep.
async fn apply_jitter(fraction: f64, target: &Target) {
    if fraction <= 0.0 {
        return;
    }
    let max_ms = target.timeout().as_secs_f64() * 1000.0 * fraction;
    if max_ms <= 0.0 {
        return;
    }
    let delay_ms = {
        use rand::Rng;
        rand::thread_rng().gen_range(0.0..=max_ms)
    };
    tokio::time::sleep(Duration::from_secs_f64(delay_ms / 1000.0)).await;
}

/// The bounded synthetic-probe engine.
#[derive(Debug, Clone)]
pub struct ProbeEngine<R: Resolver = SystemResolver> {
    cfg: EngineConfig,
    resolver: R,
    client: reqwest::Client,
}

impl ProbeEngine<SystemResolver> {
    /// Build an engine using the OS resolver.
    pub fn new(cfg: EngineConfig) -> Result<Self, DemError> {
        Self::with_resolver(cfg, SystemResolver)
    }
}

impl<R: Resolver> ProbeEngine<R> {
    /// Build an engine with a caller-supplied [`Resolver`] (used by
    /// tests to drive the DNS phase deterministically). Fails closed
    /// if the budget is invalid or the HTTP client cannot be built.
    pub fn with_resolver(cfg: EngineConfig, resolver: R) -> Result<Self, DemError> {
        cfg.validate()?;
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .timeout(cfg.default_timeout)
            .connect_timeout(cfg.default_timeout)
            // A fresh connection per probe keeps phase timings honest
            // and bounds resident memory (no idle pool to grow).
            .pool_max_idle_per_host(0)
            // Measure the target itself, not wherever it redirects.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("sng-dem/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| DemError::Build(e.to_string()))?;
        Ok(Self {
            cfg,
            resolver,
            client,
        })
    }

    /// The engine's bounded cost model.
    #[must_use]
    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    /// Probe a single target. Never errors — a failed probe is a
    /// `success == false` result.
    pub async fn probe_one(&self, target: &Target) -> ProbeResult {
        probe_target(&self.resolver, &self.client, target).await
    }

    /// Probe every target with bounded concurrency, jitter, and a hard
    /// fan-out cap. Results are returned in completion order; match
    /// them by [`ProbeResult::target_key`].
    pub async fn probe_all(&self, targets: &[Target]) -> Vec<ProbeResult> {
        let limit = self.cfg.max_targets.min(targets.len());
        if targets.len() > self.cfg.max_targets {
            tracing::warn!(
                requested = targets.len(),
                cap = self.cfg.max_targets,
                "dem probe sweep truncated to target cap"
            );
        }
        let sem = Arc::new(Semaphore::new(self.cfg.max_concurrency));
        let jitter = self.cfg.jitter_clamped();
        let mut set: JoinSet<ProbeResult> = JoinSet::new();
        let selected: Vec<Target> = targets.iter().take(limit).cloned().collect();
        for target in selected {
            // Acquire before spawning so we never hold more than
            // `max_concurrency` pending tasks in memory at once.
            let Ok(permit) = sem.clone().acquire_owned().await else {
                break;
            };
            let resolver = self.resolver.clone();
            let client = self.client.clone();
            set.spawn(async move {
                let _permit = permit;
                apply_jitter(jitter, &target).await;
                probe_target(&resolver, &client, &target).await
            });
        }
        let mut out = Vec::with_capacity(limit);
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(r) => out.push(r),
                Err(e) => tracing::error!(error = %e, "dem probe task failed"),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::Resolver;
    use pretty_assertions::assert_eq;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::TcpListener;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A resolver that always returns a fixed address, optionally
    /// after a sleep (to exercise the timeout path under paused time).
    #[derive(Clone, Debug)]
    struct MockResolver {
        addr: SocketAddr,
        delay: Duration,
        fail: bool,
    }

    impl MockResolver {
        fn to(addr: SocketAddr) -> Self {
            Self {
                addr,
                delay: Duration::ZERO,
                fail: false,
            }
        }
        fn slow(addr: SocketAddr, delay: Duration) -> Self {
            Self {
                addr,
                delay,
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
                delay: Duration::ZERO,
                fail: true,
            }
        }
    }

    impl Resolver for MockResolver {
        async fn resolve(&self, _host: &str, port: u16) -> Result<Vec<SocketAddr>, DemError> {
            if !self.delay.is_zero() {
                tokio::time::sleep(self.delay).await;
            }
            if self.fail {
                return Err(DemError::Build("mock resolver failure".into()));
            }
            let mut a = self.addr;
            a.set_port(port);
            Ok(vec![a])
        }
    }

    fn dns_target() -> Target {
        Target {
            key: "dns-probe".into(),
            name: "DNS probe".into(),
            kind: ProbeKind::Dns,
            address: "example.test".into(),
            port: None,
            timeout_ms: 1_000,
        }
    }

    #[tokio::test]
    async fn dns_success_records_latency() {
        let resolver = MockResolver::to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443));
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let r = engine.probe_one(&dns_target()).await;
        assert!(r.success);
        assert_eq!(r.probe_kind, ProbeKind::Dns);
        assert!(r.dns_ms.is_some());
        assert_eq!(r.total_ms, r.dns_ms);
        assert!(r.error_kind.is_none());
    }

    #[tokio::test]
    async fn dns_failure_is_graceful() {
        let engine =
            ProbeEngine::with_resolver(EngineConfig::default(), MockResolver::failing()).unwrap();
        let r = engine.probe_one(&dns_target()).await;
        assert!(!r.success);
        assert_eq!(r.error_kind, Some(ProbeErrorKind::Dns));
        assert!(r.error_detail.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn dns_timeout_is_classified() {
        // The resolver sleeps 5s under a 1s target deadline; with the
        // clock paused this is deterministic — no wall-clock wait.
        let resolver = MockResolver::slow(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            Duration::from_secs(5),
        );
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let r = engine.probe_one(&dns_target()).await;
        assert!(!r.success);
        assert_eq!(r.error_kind, Some(ProbeErrorKind::Timeout));
    }

    #[tokio::test]
    async fn tcp_connect_success_against_loopback() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept loop so the connect completes.
        tokio::spawn(async move {
            loop {
                if listener.accept().await.is_err() {
                    break;
                }
            }
        });
        let resolver = MockResolver::to(addr);
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let target = Target {
            key: "tcp".into(),
            name: "loopback tcp".into(),
            kind: ProbeKind::Tcp,
            address: "loopback.test".into(),
            port: Some(addr.port()),
            timeout_ms: 1_000,
        };
        let r = engine.probe_one(&target).await;
        assert!(r.success, "expected success, got {r:?}");
        assert!(r.tcp_ms.is_some());
        assert!(r.dns_ms.is_some());
        assert!(r.total_ms.is_some());
    }

    #[tokio::test]
    async fn tcp_connect_refused_is_graceful() {
        // Bind then drop to obtain a port nothing is listening on.
        let addr = {
            let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            l.local_addr().unwrap()
        };
        let resolver = MockResolver::to(addr);
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let target = Target {
            key: "tcp".into(),
            name: "closed port".into(),
            kind: ProbeKind::Tcp,
            address: "loopback.test".into(),
            port: Some(addr.port()),
            timeout_ms: 1_000,
        };
        let r = engine.probe_one(&target).await;
        assert!(!r.success);
        assert_eq!(r.error_kind, Some(ProbeErrorKind::Connect));
    }

    #[tokio::test]
    async fn http_probe_healthy_status_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
            .mount(&server)
            .await;
        let uri = server.uri();
        let url = url::Url::parse(&uri).unwrap();
        let host = url.host_str().unwrap().to_string();
        let port = url.port().unwrap();
        let resolver = MockResolver::to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let target = Target {
            key: "http".into(),
            name: "mock http".into(),
            kind: ProbeKind::Http,
            address: format!("http://{host}:{port}/"),
            port: None,
            timeout_ms: 5_000,
        };
        let r = engine.probe_one(&target).await;
        assert!(r.success, "expected success, got {r:?}");
        assert_eq!(r.http_status, Some(200));
        assert!(r.ttfb_ms.is_some());
        assert!(r.total_ms.is_some());
        assert!(r.dns_ms.is_some());
        assert!(r.tcp_ms.is_some());
    }

    #[tokio::test]
    async fn http_probe_5xx_is_unhealthy_but_reachable() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        let uri = server.uri();
        let url = url::Url::parse(&uri).unwrap();
        let host = url.host_str().unwrap().to_string();
        let port = url.port().unwrap();
        let resolver = MockResolver::to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let target = Target {
            key: "http".into(),
            name: "mock http".into(),
            kind: ProbeKind::Http,
            address: format!("http://{host}:{port}/"),
            port: None,
            timeout_ms: 5_000,
        };
        let r = engine.probe_one(&target).await;
        assert!(!r.success);
        assert_eq!(r.http_status, Some(503));
        assert_eq!(r.error_kind, Some(ProbeErrorKind::Http));
        // Still reached the server, so the transport phases are timed.
        assert!(r.ttfb_ms.is_some());
    }

    #[tokio::test]
    async fn probe_all_bounds_and_covers_all_targets() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let url = url::Url::parse(&server.uri()).unwrap();
        let host = url.host_str().unwrap().to_string();
        let port = url.port().unwrap();
        let resolver = MockResolver::to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
        let cfg = EngineConfig {
            max_concurrency: 2,
            jitter: 0.0,
            ..EngineConfig::default()
        };
        let engine = ProbeEngine::with_resolver(cfg, resolver).unwrap();
        let targets: Vec<Target> = (0..5)
            .map(|i| Target {
                key: format!("t{i}"),
                name: format!("target {i}"),
                kind: ProbeKind::Http,
                address: format!("http://{host}:{port}/"),
                port: None,
                timeout_ms: 5_000,
            })
            .collect();
        let results = engine.probe_all(&targets).await;
        assert_eq!(results.len(), 5);
        assert!(results.iter().all(|r| r.success));
        let mut keys: Vec<_> = results.iter().map(|r| r.target_key.clone()).collect();
        keys.sort();
        assert_eq!(keys, vec!["t0", "t1", "t2", "t3", "t4"]);
    }

    #[tokio::test]
    async fn probe_all_respects_max_targets_cap() {
        let resolver = MockResolver::to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443));
        let cfg = EngineConfig {
            max_targets: 2,
            jitter: 0.0,
            ..EngineConfig::default()
        };
        let engine = ProbeEngine::with_resolver(cfg, resolver).unwrap();
        let targets: Vec<Target> = (0..5).map(|_| dns_target()).collect();
        let results = engine.probe_all(&targets).await;
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn invalid_target_yields_config_failure() {
        let resolver = MockResolver::to(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443));
        let engine = ProbeEngine::with_resolver(EngineConfig::default(), resolver).unwrap();
        let target = Target {
            key: "bad".into(),
            name: "bad".into(),
            kind: ProbeKind::Tcp,
            address: "host.test".into(),
            port: None, // tcp requires a port
            timeout_ms: 1_000,
        };
        let r = engine.probe_one(&target).await;
        assert!(!r.success);
        assert_eq!(r.error_kind, Some(ProbeErrorKind::Config));
    }
}

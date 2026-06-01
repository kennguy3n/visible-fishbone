// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding. The crate-level lib.rs allow only fires for
// `#[cfg(test)]` units inside the library crate; integration
// test files in `tests/` are separate crates so we repeat the
// same allow list at the file top.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::float_cmp,
    clippy::too_many_lines
)]

//! End-to-end integration tests for the composed `sng-agent`
//! endpoint binary. These drive the supervisor to completion
//! against an in-process control-plane mock that speaks real
//! TLS 1.3 + h2 ALPN over a 127.0.0.1 loopback. No code path
//! is mocked beyond:
//!
//!  * the PAL adapters (already covered by per-subsystem unit
//!    tests in `sng-pal`), and
//!  * the control plane itself (the HTTP/2 server is
//!    implemented in-process here).
//!
//! Every Rust subsystem runs the same code path it would in
//! production: PolicyPuller signature verification +
//! If-None-Match conditional + downgrade protection,
//! PolicyEngine atomic bundle swap with `graph_version`
//! monotonicity, the full Supervisor spawn / health-aggregate
//! / drain loop, real rustls TLS handshake with mTLS, real
//! h2 framing, the PAL tunnel reconciler driven by the
//! supervisor's `desired_tunnels_tx` watch channel.
//!
//! Tests:
//!
//!  * [`full_stack_boots_pulls_bundle_then_drains_cleanly`] —
//!    Task 26: boot all 7 subsystems, observe a fresh bundle
//!    pull land on the policy engine, push a desired tunnel
//!    set through the watch channel, observe the PAL tunnel
//!    reconciler bring up the requested tunnel, then drain
//!    inside budget.
//!  * [`agent_supervisor_drain_under_continuous_load_within_budget`]
//!    — Task 27a (agent half): drive a sustained bundle-pull
//!    cycle + a running PAL tunnel, fire shutdown mid-loop,
//!    assert every subsystem exits inside its per-subsystem
//!    drain budget. This is the agent-side counterpart to the
//!    edge test of the same shape and pins down that the
//!    supervisor's drain shape holds with the agent's
//!    different subsystem mix (no fw/ips/swg/sdwan/updater;
//!    three pal_* adapters instead).
//!
//! ## Why a `let BuiltAgent { supervisor, .. }` pattern is
//! ## forbidden in these tests
//!
//! All tests use a fully-named destructure of `BuiltAgent`
//! followed by an explicit `drop()` of every subsystem Arc +
//! the desired-tunnel watch sender BEFORE handing `supervisor`
//! off to its run loop. The reason is exactly the same as the
//! sister `sng-edge::tests::edge_e2e` file's comment: under
//! `..` Rust retains ownership of the unbound fields for the
//! rest of the enclosing scope (they have no explicit binding,
//! so they drop at scope-end, not at the destructure
//! statement). Because `supervisor.run().await` is also in
//! that scope, every other subsystem Arc would remain alive
//! across the entire run loop — the telemetry pipeline's
//! producer-channel sender count would never hit zero and the
//! supervisor would deadlock on drain.

use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey};
use http::{Request, Response, StatusCode};
use ipnet::IpNet;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use sng_agent::config::{
    AgentConfig, CaptureConfig, CommsConfig, IdentityConfig, PolicyConfig, PostureConfig,
    SupervisorConfig, TelemetryConfig, TunnelConfig as TunnelCadenceConfig, ZtnaConfig,
};
use sng_agent::{BuiltAgent, Cli, build_agent};
use sng_core::ids::{DeviceId, PolicySigningKeyId, TenantId};
use sng_core::policy::BundleTarget;
use sng_pal::tunnel::TunnelConfig as PalTunnelConfig;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::time::{Instant, sleep, timeout};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// PKI fixtures
// ---------------------------------------------------------------------------

/// In-memory PKI: a root that the comms subsystem trusts, plus
/// a server cert for the in-process control plane. The matching
/// client cert is materialised onto disk by [`mint_client_pem`]
/// so the existing `CommsConfig` PEM-path API can be used
/// without bypassing the binary's identity-load path.
struct TestPki {
    root_pem: String,
    server_config: Arc<rustls::ServerConfig>,
}

fn mk_pki() -> TestPki {
    // The process-global rustls crypto provider must be
    // installed exactly once. `install_ring_provider` is
    // idempotent (it ignores `CryptoProvider::install_default`
    // errors after the first install) so multiple tests in
    // the same binary do not collide.
    sng_comms::tls::install_ring_provider();

    let root_key = KeyPair::generate_for(&PKCS_ED25519).expect("root key");
    let mut root_params =
        CertificateParams::new(vec!["sng-agent-e2e-root".into()]).expect("params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root_cert = root_params.self_signed(&root_key).expect("root cert");
    let root_pem = root_cert.pem();
    let root_der_owned: Vec<u8> = root_cert.der().to_vec();
    let root_der = CertificateDer::from(root_der_owned);

    let server_key = KeyPair::generate_for(&PKCS_ED25519).expect("server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".into()]).expect("server params");
    server_params.is_ca = IsCa::NoCa;
    let server_cert = server_params
        .signed_by(&server_key, &root_cert, &root_key)
        .expect("server cert");
    let server_der = CertificateDer::from(server_cert.der().to_vec());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(root_der).expect("add root");

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_der],
            PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
                server_key.serialize_der(),
            )),
        )
        .expect("server tls config");
    // RFC 7540 §3.3: h2-over-TLS must negotiate the `h2` ALPN
    // identifier. Without this the rustls server will negotiate
    // the empty default and the h2 connection preface the
    // client sends next will be rejected.
    server_config.alpn_protocols = vec![b"h2".to_vec()];

    TestPki {
        root_pem,
        server_config: Arc::new(server_config),
    }
}

fn mint_client_pem() -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
    let mut params = CertificateParams::new(vec!["agent-e2e-test".into()]).expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "agent-e2e-test");
    let cert = params.self_signed(&key).expect("cert");
    (cert.pem().into_bytes(), key.serialize_pem().into_bytes())
}

/// Materialise the test PKI artefacts onto disk so `CommsConfig`
/// can point at real paths.
struct OnDiskPki {
    client_cert: PathBuf,
    client_key: PathBuf,
    trust_roots: PathBuf,
    _dir: TempDir,
}

fn write_pki_to_disk(pki: &TestPki) -> OnDiskPki {
    let dir = tempfile::tempdir().expect("tempdir");
    let client_cert = dir.path().join("client.pem");
    let client_key = dir.path().join("client.key");
    let trust_roots = dir.path().join("roots.pem");
    let (cert_pem, key_pem) = mint_client_pem();
    std::fs::write(&client_cert, &cert_pem).expect("write client cert");
    std::fs::write(&client_key, &key_pem).expect("write client key");
    std::fs::write(&trust_roots, pki.root_pem.as_bytes()).expect("write roots");
    OnDiskPki {
        client_cert,
        client_key,
        trust_roots,
        _dir: dir,
    }
}

// ---------------------------------------------------------------------------
// In-process control plane
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct ControlPlaneStats {
    bundle_pulls_total: AtomicU64,
    bundle_pulls_200: AtomicU64,
    bundle_pulls_304: AtomicU64,
    bundle_pulls_503: AtomicU64,
    telemetry_batches_total: AtomicU64,
    telemetry_batches_acked: AtomicU64,
    other_requests: AtomicU64,
}

impl ControlPlaneStats {
    fn new() -> Self {
        Self::default()
    }
}

#[derive(Clone)]
enum Resp {
    Bundle200 {
        body: Bytes,
        sig_b64: String,
        kid: String,
        etag: String,
    },
    Bundle304,
    Bundle503,
    TelemetryAck,
    Unknown,
}

fn dispatch(stats: &ControlPlaneStats, request: &Request<()>, bundle_state: &BundleState) -> Resp {
    let path = request.uri().path();
    if path.contains("/policy/bundles/") && request.method() == http::Method::GET {
        stats.bundle_pulls_total.fetch_add(1, Ordering::Relaxed);
        // 503 is checked BEFORE the If-None-Match / 304 path
        // on purpose: a real control plane returning 503 is
        // signalling "I am unhealthy" and does not engage in
        // etag negotiation in that state. If we ran the 304
        // path first, a puller that already cached an etag
        // from a prior 200 would short-circuit to 304 on
        // every subsequent request and never observe the
        // simulated outage.
        if bundle_state.return_503.load(Ordering::Acquire) {
            stats.bundle_pulls_503.fetch_add(1, Ordering::Relaxed);
            return Resp::Bundle503;
        }
        let inm = request
            .headers()
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        if let Some(want) = inm {
            if want == bundle_state.etag
                && bundle_state.served_at_least_once.load(Ordering::Acquire)
            {
                stats.bundle_pulls_304.fetch_add(1, Ordering::Relaxed);
                return Resp::Bundle304;
            }
        }
        stats.bundle_pulls_200.fetch_add(1, Ordering::Relaxed);
        bundle_state
            .served_at_least_once
            .store(true, Ordering::Release);
        return Resp::Bundle200 {
            body: bundle_state.body.clone(),
            sig_b64: bundle_state.sig_b64.clone(),
            kid: bundle_state.kid.clone(),
            etag: bundle_state.etag.clone(),
        };
    }
    if path.ends_with("/agents/telemetry/batches") && request.method() == http::Method::POST {
        stats
            .telemetry_batches_total
            .fetch_add(1, Ordering::Relaxed);
        stats
            .telemetry_batches_acked
            .fetch_add(1, Ordering::Relaxed);
        return Resp::TelemetryAck;
    }
    stats.other_requests.fetch_add(1, Ordering::Relaxed);
    Resp::Unknown
}

struct BundleState {
    body: Bytes,
    sig_b64: String,
    kid: String,
    etag: String,
    served_at_least_once: AtomicBool,
    return_503: AtomicBool,
}

struct ControlPlaneHandle {
    addr: String,
    shutdown: Option<oneshot::Sender<()>>,
    join: tokio::task::JoinHandle<()>,
}

impl ControlPlaneHandle {
    async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        let _ = self.join.await;
    }
}

async fn spawn_control_plane(
    pki: Arc<TestPki>,
    stats: Arc<ControlPlaneStats>,
    bundle: Arc<BundleState>,
) -> ControlPlaneHandle {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let addr_str = format!("127.0.0.1:{}", addr.port());
    let (tx, mut rx) = oneshot::channel::<()>();
    let server_config = pki.server_config.clone();
    let join = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => {
                    return;
                }
                accept = listener.accept() => {
                    let Ok((tcp, _peer)) = accept else {
                        continue;
                    };
                    let acceptor = tokio_rustls::TlsAcceptor::from(server_config.clone());
                    let stats = Arc::clone(&stats);
                    let bundle = Arc::clone(&bundle);
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let mut h2_builder = h2::server::Builder::new();
                        h2_builder.initial_window_size(1024 * 1024);
                        let Ok(mut conn) = h2_builder.handshake(tls).await else {
                            return;
                        };
                        while let Some(result) = conn.accept().await {
                            let Ok((request, mut respond)) = result else {
                                return;
                            };
                            let (parts, mut recv_body) = request.into_parts();
                            while let Some(chunk) = recv_body.data().await {
                                if let Ok(b) = chunk {
                                    let len = b.len();
                                    let _ = recv_body.flow_control().release_capacity(len);
                                }
                            }
                            let rebuilt = Request::from_parts(parts, ());
                            let resp = dispatch(&stats, &rebuilt, &bundle);
                            let (resp_status, resp_headers, resp_body) = match resp {
                                Resp::Bundle200 {
                                    body,
                                    sig_b64,
                                    kid,
                                    etag,
                                } => (
                                    StatusCode::OK,
                                    vec![
                                        ("x-sng-policy-signature".to_string(), sig_b64),
                                        ("x-sng-policy-key-id".to_string(), kid),
                                        ("etag".to_string(), etag),
                                        (
                                            "content-type".to_string(),
                                            "application/vnd.sng.policy-bundle".to_string(),
                                        ),
                                    ],
                                    body,
                                ),
                                Resp::Bundle304 => {
                                    (StatusCode::NOT_MODIFIED, vec![], Bytes::new())
                                }
                                Resp::Bundle503 => (
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    vec![],
                                    Bytes::new(),
                                ),
                                Resp::TelemetryAck => (
                                    StatusCode::OK,
                                    vec![(
                                        "content-type".to_string(),
                                        "application/json".to_string(),
                                    )],
                                    Bytes::from_static(b"{\"ok\":true}"),
                                ),
                                Resp::Unknown => (
                                    StatusCode::NOT_FOUND,
                                    vec![],
                                    Bytes::new(),
                                ),
                            };
                            let mut builder = Response::builder().status(resp_status);
                            for (k, v) in &resp_headers {
                                builder = builder.header(k.as_str(), v.as_str());
                            }
                            let Ok(response) = builder.body(()) else {
                                return;
                            };
                            let end = resp_body.is_empty();
                            let Ok(mut send) = respond.send_response(response, end) else {
                                return;
                            };
                            if !end && send.send_data(resp_body, true).is_err() {
                                return;
                            }
                        }
                    });
                }
            }
        }
    });
    ControlPlaneHandle {
        addr: addr_str,
        shutdown: Some(tx),
        join,
    }
}

// ---------------------------------------------------------------------------
// Bundle fixture — must match the wire shape both the comms
// `PolicyBundleClaims::from_body` decoder and the policy-eval
// `LoadedBundle::from_body` decoder expect.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct WireBundle<'a> {
    #[serde(rename = "v")]
    schema_version: u8,
    #[serde(rename = "t")]
    target: BundleTarget,
    #[serde(rename = "g")]
    graph_id: &'a str,
    #[serde(rename = "gv")]
    graph_version: i64,
    #[serde(rename = "c")]
    compiler: &'a str,
    #[serde(rename = "d")]
    default_action: &'a str,
    #[serde(rename = "r", with = "serde_bytes")]
    rules_json: &'a [u8],
    #[serde(
        rename = "st",
        with = "serde_bytes",
        skip_serializing_if = "<[u8]>::is_empty"
    )]
    steering_json: &'a [u8],
    #[serde(rename = "ts")]
    compiled_at: chrono::DateTime<chrono::Utc>,
}

fn build_signed_bundle(
    target: BundleTarget,
    graph_id: &str,
    graph_version: i64,
) -> (Bytes, String, String, SigningKey, PolicySigningKeyId) {
    let mut seed = [0u8; 32];
    seed[0] = 0xA2;
    seed[1] = u8::try_from(graph_version & 0xFF).expect("byte");
    let signing = SigningKey::from_bytes(&seed);

    let wire = WireBundle {
        schema_version: 1,
        target,
        graph_id,
        graph_version,
        compiler: "sng-agent-e2e",
        default_action: "deny",
        rules_json: b"[]",
        steering_json: b"",
        compiled_at: chrono::Utc::now(),
    };
    let body = rmp_serde::to_vec_named(&wire).expect("encode bundle");
    let sig = signing.sign(&body);
    let sig_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());
    let etag = format!("\"sng-agent-e2e-{graph_version}\"");
    let kid_str = format!("sng-agent-e2e-{graph_version}");
    let key_id = PolicySigningKeyId::new(&kid_str).expect("kid");
    (Bytes::from(body), sig_b64, etag, signing, key_id)
}

// ---------------------------------------------------------------------------
// Config + CLI fixtures
// ---------------------------------------------------------------------------

fn fresh_config_wired_to(endpoint: &str, pki: &OnDiskPki) -> AgentConfig {
    AgentConfig {
        identity: IdentityConfig {
            tenant_id: TenantId::from_uuid(Uuid::from_u128(0xA11C_E002)),
            device_id: DeviceId::from_uuid(Uuid::from_u128(0x0BEE_F002)),
            site_id: None,
        },
        comms: CommsConfig {
            endpoint: endpoint.to_string(),
            // The mock cert is issued for `localhost`; the
            // endpoint is `127.0.0.1:{port}` so SNI must be
            // set explicitly.
            server_name: Some("localhost".into()),
            client_cert: pki.client_cert.clone(),
            client_key: pki.client_key.clone(),
            trust_roots: Some(pki.trust_roots.clone()),
            backoff_initial: Duration::from_millis(25),
            backoff_max: Duration::from_millis(250),
        },
        policy: PolicyConfig {
            path_override: None,
            pull_interval: Duration::from_millis(50),
        },
        telemetry: TelemetryConfig {
            tick_interval: Duration::from_millis(50),
            ..TelemetryConfig::default()
        },
        ztna: ZtnaConfig::default(),
        capture: CaptureConfig::default(),
        posture: PostureConfig::default(),
        tunnel: TunnelCadenceConfig {
            // Tight cadence so the reconciler picks up the
            // desired-set update within a few hundred ms of
            // wall-clock rather than the default 30 s.
            reconcile_interval: Duration::from_millis(20),
        },
        supervisor: SupervisorConfig::default(),
    }
}

fn fresh_cli() -> Cli {
    Cli::try_parse_from(["sng-agent", "--config", "/dev/null"]).expect("parse")
}

fn init_test_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_test_writer()
            .try_init();
    });
}

async fn wait_until<F: FnMut() -> bool>(
    label: &str,
    budget: Duration,
    mut f: F,
) -> Result<(), String> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if f() {
            return Ok(());
        }
        sleep(Duration::from_millis(10)).await;
    }
    Err(format!(
        "predicate `{label}` did not become true within {budget:?}"
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// **Task 26** — drive the composed agent supervisor against an
/// in-process control plane. Verifies bundle pull lands on the
/// policy engine, the PAL tunnel reconciler picks up a
/// desired-set update via the watch channel, then drains
/// cleanly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stack_boots_pulls_bundle_then_drains_cleanly() {
    init_test_tracing();
    let pki = Arc::new(mk_pki());
    let on_disk = write_pki_to_disk(&pki);

    let graph_id_uuid = Uuid::from_u128(0xC0DE_AA0E);
    let graph_id_str = graph_id_uuid.to_string();
    let (body, sig_b64, etag, signing, kid) =
        build_signed_bundle(BundleTarget::Endpoint, &graph_id_str, 5);
    let pubkey_bytes = signing.verifying_key().to_bytes();

    let stats = Arc::new(ControlPlaneStats::new());
    let bundle = Arc::new(BundleState {
        body,
        sig_b64,
        kid: kid.as_str().to_string(),
        etag,
        served_at_least_once: AtomicBool::new(false),
        return_503: AtomicBool::new(false),
    });
    let server =
        spawn_control_plane(Arc::clone(&pki), Arc::clone(&stats), Arc::clone(&bundle)).await;

    let cli = fresh_cli();
    let cfg = fresh_config_wired_to(&server.addr, &on_disk);
    let built = build_agent(&cli, &cfg).expect("build_agent");

    // Seed the trust store *before* the supervisor spawns the
    // comms task so the first pull's signature check passes.
    built
        .comms
        .puller()
        .trust_store()
        .insert_key(&kid, &pubkey_bytes)
        .expect("seed trust key");

    // Extract everything we need to observe post-spawn (stats
    // handles, the policy engine, the shutdown trigger, the
    // desired-tunnel sender clone), then destructure `built`
    // so every `Arc<...Subsystem>` clone + the watch sender
    // it owns are dropped before `supervisor.run()` takes
    // over.
    let trigger = built.supervisor.shutdown_trigger();
    let comms_stats = Arc::clone(built.comms.stats());
    let tunnel_stats = Arc::clone(built.pal_tunnel.stats());
    let policy_engine = Arc::clone(built.policy_eval.engine());
    // Keep a separate sender clone so the test can drive the
    // desired-set update independently. The watch channel
    // stays open as long as at least one sender is alive,
    // and the subsystem holds its own receiver clone.
    let desired_tunnels_tx = built.desired_tunnels_tx.clone();

    let BuiltAgent {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        ztna,
        pal_capture,
        pal_posture,
        pal_tunnel,
        desired_tunnels_tx: built_desired_tunnels_tx,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(ztna);
    drop(pal_capture);
    drop(pal_posture);
    drop(pal_tunnel);
    drop(built_desired_tunnels_tx);

    let supervisor_handle = tokio::spawn(supervisor.run());

    // 1. Wait for at least one fresh bundle pull to land on
    //    policy_eval and assert the wire round-trip.
    let probe = wait_until(
        "policy_eval received the test bundle",
        Duration::from_secs(5),
        || {
            comms_stats.pulls_fresh.load(Ordering::Relaxed) >= 1
                && policy_engine.current_bundle().graph_version == 5
        },
    )
    .await;
    if probe.is_err() {
        eprintln!(
            "comms.stats = pulls={} pulls_fresh={} pulls_not_modified={} \
             pull_failures={} connects={} connect_failures={} publish_failures={}",
            comms_stats.pulls.load(Ordering::Relaxed),
            comms_stats.pulls_fresh.load(Ordering::Relaxed),
            comms_stats.pulls_not_modified.load(Ordering::Relaxed),
            comms_stats.pull_failures.load(Ordering::Relaxed),
            comms_stats.connects.load(Ordering::Relaxed),
            comms_stats.connect_failures.load(Ordering::Relaxed),
            comms_stats.publish_failures.load(Ordering::Relaxed),
        );
        eprintln!(
            "control-plane stats = bundle_pulls_total={} bundle_pulls_200={} \
             bundle_pulls_304={} bundle_pulls_503={} telemetry_total={} \
             telemetry_acked={} other={}",
            stats.bundle_pulls_total.load(Ordering::Relaxed),
            stats.bundle_pulls_200.load(Ordering::Relaxed),
            stats.bundle_pulls_304.load(Ordering::Relaxed),
            stats.bundle_pulls_503.load(Ordering::Relaxed),
            stats.telemetry_batches_total.load(Ordering::Relaxed),
            stats.telemetry_batches_acked.load(Ordering::Relaxed),
            stats.other_requests.load(Ordering::Relaxed),
        );
        eprintln!(
            "policy_engine.graph_version = {}",
            policy_engine.current_bundle().graph_version
        );
    }
    probe.expect("bundle did not propagate");

    let loaded = policy_engine.current_bundle();
    assert_eq!(loaded.graph_version, 5);
    assert_eq!(loaded.graph_id, graph_id_str);

    // 2. Push a desired tunnel through the supervisor's watch
    //    channel and assert the PAL tunnel reconciler brings
    //    it up. With `reconcile_interval = 20ms` this should
    //    fire on the next tick (≈20 ms).
    let desired = vec![PalTunnelConfig {
        id: "control-plane".into(),
        endpoint: "10.0.0.1:51820".parse().expect("addr"),
        peer_public_key_b64: "A".repeat(43) + "=",
        keepalive_seconds: 25,
        allowed_ips: vec![IpNet::from_str("0.0.0.0/0").expect("net")],
    }];
    desired_tunnels_tx
        .send(desired)
        .expect("publish desired tunnel set");

    wait_until("pal_tunnel.starts_ok ≥ 1", Duration::from_secs(2), || {
        tunnel_stats.starts_ok.load(Ordering::Relaxed) >= 1
    })
    .await
    .expect("pal_tunnel did not bring up desired tunnel");

    assert_eq!(
        tunnel_stats.starts_ok.load(Ordering::Relaxed),
        1,
        "expected exactly one tunnel start (the desired set has one entry)"
    );
    assert_eq!(
        tunnel_stats.starts_failed.load(Ordering::Relaxed),
        0,
        "reconciler reported tunnel start failures"
    );

    // 3. At least one 200 reached the control plane.
    assert!(
        stats.bundle_pulls_200.load(Ordering::Relaxed) >= 1,
        "control plane saw no 200 bundle pulls"
    );

    // 4. Drive shutdown and assert clean drain. The
    //    supervisor drain budget is 30 s; with all subsystems
    //    idle the drain completes in <1 s on a warm CI runner.
    trigger.fire();
    let report = timeout(Duration::from_secs(15), supervisor_handle)
        .await
        .expect("supervisor.run did not exit within 15s")
        .expect("join")
        .expect("supervisor.run returned Err");

    assert!(
        report.all_clean(),
        "supervisor drained dirty; results: {:#?}",
        report.drain_results
    );

    server.stop().await;
    let _ = bundle;
}

/// **Task 27a (agent half)** — supervisor drain under
/// continuous load. The agent runs against a fast (50 ms) pull
/// cycle and a running PAL tunnel for ~250 ms, then a shutdown
/// is fired. Every subsystem MUST exit inside its drain budget.
/// Mirror of the edge supervisor-drain test, pinned against
/// the agent's different subsystem mix.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_supervisor_drain_under_continuous_load_within_budget() {
    init_test_tracing();
    let pki = Arc::new(mk_pki());
    let on_disk = write_pki_to_disk(&pki);

    let graph_id_uuid = Uuid::from_u128(0xCAFE_BB12);
    let graph_id_str = graph_id_uuid.to_string();
    let (body, sig_b64, etag, signing, kid) =
        build_signed_bundle(BundleTarget::Endpoint, &graph_id_str, 1);
    let pubkey_bytes = signing.verifying_key().to_bytes();

    let stats = Arc::new(ControlPlaneStats::new());
    let bundle = Arc::new(BundleState {
        body,
        sig_b64,
        kid: kid.as_str().to_string(),
        etag,
        served_at_least_once: AtomicBool::new(false),
        return_503: AtomicBool::new(false),
    });
    let server =
        spawn_control_plane(Arc::clone(&pki), Arc::clone(&stats), Arc::clone(&bundle)).await;

    let cli = fresh_cli();
    let cfg = fresh_config_wired_to(&server.addr, &on_disk);
    let built = build_agent(&cli, &cfg).expect("build_agent");

    built
        .comms
        .puller()
        .trust_store()
        .insert_key(&kid, &pubkey_bytes)
        .expect("seed trust key");

    let trigger = built.supervisor.shutdown_trigger();
    let comms_stats = Arc::clone(built.comms.stats());
    let tunnel_stats = Arc::clone(built.pal_tunnel.stats());
    let desired_tunnels_tx = built.desired_tunnels_tx.clone();

    let BuiltAgent {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        ztna,
        pal_capture,
        pal_posture,
        pal_tunnel,
        desired_tunnels_tx: built_desired_tunnels_tx,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(ztna);
    drop(pal_capture);
    drop(pal_posture);
    drop(pal_tunnel);
    drop(built_desired_tunnels_tx);

    let supervisor_handle = tokio::spawn(supervisor.run());

    // Bring the PAL tunnel up so the reconciler is actively
    // managing state when shutdown fires.
    let desired = vec![PalTunnelConfig {
        id: "control-plane".into(),
        endpoint: "10.0.0.1:51820".parse().expect("addr"),
        peer_public_key_b64: "B".repeat(43) + "=",
        keepalive_seconds: 25,
        allowed_ips: vec![IpNet::from_str("0.0.0.0/0").expect("net")],
    }];
    desired_tunnels_tx
        .send(desired)
        .expect("publish desired tunnel set");

    // Wait until the comms subsystem has turned at least 3
    // pull cycles AND the tunnel reconciler has brought the
    // tunnel up — that's our "steady state with live load"
    // pre-condition.
    wait_until(
        "comms ≥3 pulls AND pal_tunnel.starts_ok ≥1",
        Duration::from_secs(5),
        || {
            comms_stats.pulls.load(Ordering::Relaxed) >= 3
                && tunnel_stats.starts_ok.load(Ordering::Relaxed) >= 1
        },
    )
    .await
    .expect("agent did not reach steady state");

    // Fire shutdown mid-loop and assert drain inside the
    // test's tighter budget. The 5 s budget here is well
    // below the default 30 s drain budget; a regression of
    // the wave-1 backoff-vs-shutdown race would land us
    // back near 30 s.
    let drain_start = Instant::now();
    trigger.fire();
    let report = timeout(Duration::from_secs(5), supervisor_handle)
        .await
        .expect("supervisor.run did not exit within 5s drain budget")
        .expect("join")
        .expect("supervisor.run returned Err");
    let drain_elapsed = drain_start.elapsed();

    assert!(
        report.all_clean(),
        "drain dirty after {drain_elapsed:?}; results: {:#?}",
        report.drain_results
    );

    server.stop().await;
    let _ = bundle;
}

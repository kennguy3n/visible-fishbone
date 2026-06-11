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

//! End-to-end integration tests for the composed `sng-edge`
//! appliance. These drive the supervisor to completion against
//! an in-process h2 + TLS control-plane mock so the production
//! `comms → policy_eval` path is exercised end-to-end, not just
//! at the wiring layer.
//!
//! Each test runs against the real:
//!
//!  * [`Supervisor`](sng_core::Supervisor) spawn / drain loop,
//!  * `tokio-rustls` TLS 1.3 + h2 ALPN handshake,
//!  * `sng-comms` `PolicyPuller` (signature verification,
//!    `If-None-Match` conditional, downgrade protection),
//!  * `sng-policy-eval` `PolicyEngine::swap` (atomic bundle
//!    rotation, `graph_version` monotonicity check).
//!
//! The only mocks are the external subprocess shells already
//! mocked in the per-subsystem unit tests (Suricata, Envoy,
//! nftables) and the control plane itself — every Rust subsystem
//! runs the same code path the production binary would.
//!
//! Tests:
//!
//!  * [`full_stack_boots_pulls_bundle_then_drains_cleanly`] —
//!    Task 25: boot all 10 subsystems, observe a fresh bundle
//!    pull land on the policy engine, then drain inside budget.
//!  * [`supervisor_drain_under_continuous_load_within_budget`] —
//!    Task 27a: drive a sustained bundle-pull cycle, fire
//!    shutdown mid-loop, assert every subsystem exits inside
//!    its per-subsystem drain budget (regression cover for the
//!    wave-1 backoff-vs-shutdown race fix at the supervisor
//!    runtime tier).
//!  * [`comms_reconnects_after_control_plane_transient_outage`]
//!    — Task 27b: simulate a control-plane outage (200 → 503
//!    → 200), assert `pulls_fresh` advances past the outage
//!    rather than getting stuck on the bad response.

use bytes::Bytes;
use clap::Parser;
use ed25519_dalek::{Signer as _, SigningKey};
use http::{Request, Response, StatusCode};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Serialize;
use sng_core::ids::{DeviceId, PolicySigningKeyId, SiteId, TenantId};
use sng_core::policy::BundleTarget;
use sng_edge::config::{
    CommsConfig, DnsConfig, EdgeConfig, EdgeMode, FwConfig, HaConfig, IdentityConfig, IpsConfig,
    PolicyConfig, PopConfig, SdwanConfig, SupervisorConfig, SwgConfig, TelemetryConfig,
    UpdaterConfig, ZtnaConfig,
};
use sng_edge::{BuiltEdge, Cli, build_edge};
use std::path::PathBuf;
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
    // Same as sng-comms/tests/integration.rs::mk_pki — the
    // process-global rustls crypto provider must be installed
    // exactly once. `install_ring_provider` is idempotent (it
    // ignores `CryptoProvider::install_default` errors after
    // the first install) so multiple tests in the same binary
    // do not collide.
    sng_comms::tls::install_ring_provider();

    let root_key = KeyPair::generate_for(&PKCS_ED25519).expect("root key");
    let mut root_params = CertificateParams::new(vec!["sng-edge-e2e-root".into()]).expect("params");
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

/// Mint a fresh client-identity PEM pair (Ed25519 self-signed
/// cert + key). Matches `edge_supervisor.rs::mint_identity_pem`
/// shape but written into its own function to keep the two test
/// files independent.
fn mint_client_pem() -> (Vec<u8>, Vec<u8>) {
    let key = KeyPair::generate_for(&PKCS_ED25519).expect("ed25519 key");
    let mut params = CertificateParams::new(vec!["edge-e2e-test".into()]).expect("rcgen params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "edge-e2e-test");
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

/// Counters the test asserts against.
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

/// Routing decision returned by the test's request handler.
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

/// Build a response for a single request, advancing the
/// per-counter atomics. Returns the wire response a handler
/// will hand to h2.
fn dispatch(stats: &ControlPlaneStats, request: &Request<()>, bundle_state: &BundleState) -> Resp {
    let path = request.uri().path();
    if path.contains("/policy/bundles/") && request.method() == http::Method::GET {
        stats.bundle_pulls_total.fetch_add(1, Ordering::Relaxed);
        // Conditional 304 only if the client's `If-None-Match`
        // matches the current bundle etag AND a previous 200
        // was served. The puller stamps `If-None-Match` from
        // its cache; the first pull has none, so it always
        // gets a 200.
        // 503 is checked BEFORE the If-None-Match / 304 path
        // on purpose: a real control plane returning 503 is
        // signalling "I am unhealthy", and it does not engage
        // in etag negotiation in that state. If we let the
        // 304 path run first, a puller that already cached an
        // etag from a prior 200 would never observe the 503
        // outage — every subsequent request would short-circuit
        // to 304 and the test's "comms saw the outage"
        // assertion would never trip.
        if bundle_state.return_503.load(Ordering::Acquire) {
            stats.bundle_pulls_503.fetch_add(1, Ordering::Relaxed);
            return Resp::Bundle503;
        }
        let inm = request
            .headers()
            .get(http::header::IF_NONE_MATCH)
            .and_then(|v| v.to_str().ok());
        if let Some(want) = inm
            && want == bundle_state.etag
            && bundle_state.served_at_least_once.load(Ordering::Acquire)
        {
            stats.bundle_pulls_304.fetch_add(1, Ordering::Relaxed);
            return Resp::Bundle304;
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

/// State of the test's signed bundle. The `return_503` flag is
/// flipped by the recovery test to simulate a control-plane
/// outage between two healthy windows.
struct BundleState {
    body: Bytes,
    sig_b64: String,
    kid: String,
    etag: String,
    served_at_least_once: AtomicBool,
    return_503: AtomicBool,
}

/// Spawn the in-process control plane h2 server. Returns the
/// `host:port` it bound to and a shutdown handle that joins the
/// accept loop when dropped or signalled.
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
        // Best-effort wait so the listener releases the port
        // before the next test rebinds.
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
                            // Drain the request body so the
                            // peer can release flow-control
                            // credit (the supervisor sends
                            // small bodies but real bundles
                            // are MB-scale; honouring
                            // flow-control here keeps the
                            // mock honest).
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
// Bundle fixture
// ---------------------------------------------------------------------------

/// The wire-shape struct both `sng-comms`'s
/// `PolicyBundleClaims::from_body` and `sng-policy-eval`'s
/// `LoadedBundle::from_body` decode out of the signed bundle
/// body. The Go compiler emits MessagePack with the short
/// field tags (`v`, `t`, `g`, …) and serialises the graph
/// id as a MessagePack string carrying the canonical 36-char
/// hyphenated UUID. Both decoders on this side type
/// `graph_id` as `String` (see
/// [`sng_core::policy::PolicyBundleClaims`] for the rationale
/// — keeping the field free-form ensures the claims verifier
/// here and the full-bundle decoder in `sng-policy-eval`
/// agree on the same body bit-for-bit).
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

/// Produce a signed test bundle the puller will accept and the
/// policy engine will swap in. The `graph_id` argument is
/// passed straight onto the wire as a MessagePack string so
/// both decoders (`PolicyBundleClaims` in `sng-comms` and
/// `RawBundle` in `sng-policy-eval`) read the same field.
/// Both sides type the field as `String` because the Go
/// compiler emits the canonical 36-char hyphenated UUID as a
/// MessagePack string.
fn build_signed_bundle(
    target: BundleTarget,
    graph_id: &str,
    graph_version: i64,
) -> (Bytes, String, String, SigningKey, PolicySigningKeyId) {
    // Deterministic seed so failures are bit-reproducible.
    let mut seed = [0u8; 32];
    seed[0] = 0xE1;
    seed[1] = u8::try_from(graph_version & 0xFF).expect("byte");
    let signing = SigningKey::from_bytes(&seed);

    let wire = WireBundle {
        schema_version: 1,
        target,
        graph_id,
        graph_version,
        compiler: "sng-edge-e2e",
        default_action: "deny",
        rules_json: b"[]",
        steering_json: b"",
        compiled_at: chrono::Utc::now(),
    };
    let body = rmp_serde::to_vec_named(&wire).expect("encode bundle");
    let sig = signing.sign(&body);
    let sig_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());
    let etag = format!("\"sng-edge-e2e-{graph_version}\"");
    let kid_str = format!("sng-edge-e2e-{graph_version}");
    let key_id = PolicySigningKeyId::new(&kid_str).expect("kid");
    (Bytes::from(body), sig_b64, etag, signing, key_id)
}

// ---------------------------------------------------------------------------
// Config + CLI fixtures
// ---------------------------------------------------------------------------

/// Build a fresh edge config wired to the supplied control-plane
/// endpoint + on-disk PKI artefacts. Intervals are kept short so
/// the bundle pull cycle completes inside a few hundred ms of
/// wall-clock.
fn fresh_config_wired_to(endpoint: &str, pki: &OnDiskPki) -> EdgeConfig {
    EdgeConfig {
        identity: IdentityConfig {
            tenant_id: TenantId::from_uuid(Uuid::from_u128(0xA11C_E001)),
            device_id: DeviceId::from_uuid(Uuid::from_u128(0xDEAD_BEEF)),
            site_id: SiteId::from_uuid(Uuid::from_u128(0x517E_0001)),
        },
        comms: CommsConfig {
            endpoint: endpoint.to_string(),
            // Mock cert is issued for `localhost`; the endpoint
            // is `127.0.0.1:{port}` so SNI must be set
            // explicitly.
            server_name: Some("localhost".into()),
            client_cert: pki.client_cert.clone(),
            client_key: pki.client_key.clone(),
            trust_roots: Some(pki.trust_roots.clone()),
            backoff_initial: Duration::from_millis(25),
            backoff_max: Duration::from_millis(250),
        },
        // Reuse the PKI tempdir as the data root so the storage
        // probe in the commodity preflight measures a real, existing
        // path rather than the absent default `/var/lib/sng`.
        data_dir: pki
            .client_cert
            .parent()
            .expect("pki cert has a parent dir")
            .to_path_buf(),
        policy: PolicyConfig {
            path_override: None,
            pull_interval: Duration::from_millis(50),
        },
        telemetry: TelemetryConfig {
            tick_interval: Duration::from_millis(50),
            ..TelemetryConfig::default()
        },
        dns: DnsConfig::default(),
        fw: FwConfig::default(),
        // IPS / SWG default to `enable = true`, which makes
        // their start tasks fork the real `suricata` / `envoy`
        // binaries. Those subprocesses don't exist on a CI
        // runner; with `enable = true` the subsystems return
        // `SubsystemError` and the supervisor enters drain
        // before the policy bundle pull has had a chance to
        // land. Disable them here so the supervisor stays up
        // for the duration of the bundle round-trip; the
        // subsystems still register, the supervisor still
        // iterates them, and they idle on `shutdown.wait()`
        // until the drain trigger fires. The hot-enable path
        // is covered by their own unit tests.
        ips: IpsConfig {
            enable: false,
            ..IpsConfig::default()
        },
        swg: SwgConfig {
            enable: false,
            ..SwgConfig::default()
        },
        ztna: ZtnaConfig::default(),
        sdwan: SdwanConfig::default(),
        ha: HaConfig::default(),
        updater: UpdaterConfig::default(),
        supervisor: SupervisorConfig::default(),
        mode: EdgeMode::default(),
        pop: PopConfig::default(),
    }
}

fn fresh_cli() -> Cli {
    Cli::try_parse_from(["sng-edge", "--config", "/dev/null"]).expect("parse")
}

/// Idempotent tracing init. Honours `RUST_LOG`; defaults to
/// `warn` so a passing test does not flood the log. Tests that
/// fail print the diagnostic block built inside the test.
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

/// Poll `f` every 10 ms up to `budget`. Returns `Ok(())` if the
/// predicate ever returned `true`, else `Err` with the budget so
/// the assertion message is informative.
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

/// **Task 25** — drive the composed edge supervisor against an
/// in-process control plane and verify the policy bundle pull
/// lands on the policy engine, telemetry batches reach the
/// control plane, and the whole stack drains cleanly inside its
/// per-subsystem budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stack_boots_pulls_bundle_then_drains_cleanly() {
    init_test_tracing();
    let pki = Arc::new(mk_pki());
    let on_disk = write_pki_to_disk(&pki);

    let graph_id_uuid = Uuid::from_u128(0xC0DE_C0DE);
    let graph_id_str = graph_id_uuid.to_string();
    let (body, sig_b64, etag, signing, kid) =
        build_signed_bundle(BundleTarget::Edge, &graph_id_str, 7);
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
    let built = build_edge(&cli, &cfg).expect("build_edge");

    // Seed the trust store *before* the supervisor spawns the
    // comms task so the first pull's signature check passes.
    built
        .comms
        .puller()
        .trust_store()
        .insert_key(&kid, &pubkey_bytes)
        .expect("seed trust key");

    // Extract everything we need to observe post-spawn (stats
    // handles, the policy engine, the shutdown trigger), then
    // destructure `built` so every `Arc<...Subsystem>` clone
    // it owns is dropped before `supervisor.run()` takes over.
    // Without this, every subsystem field on `built` would
    // keep its inner producer-channel halves (e.g. the
    // `PipelineHandle` inside `TelemetrySubsystem`) alive for
    // the full lifetime of the test \u2014 the telemetry
    // pipeline would never observe channel closure and the
    // supervisor would deadlock on drain.
    let trigger = built.supervisor.shutdown_trigger();
    let stats_for_assert = Arc::clone(built.comms.stats());
    let policy_engine = Arc::clone(built.policy_eval.engine());
    // Full destructure (no `..`) is required: under `..` Rust
    // retains ownership of the unbound fields for the rest of
    // the enclosing scope (they have no explicit binding, so
    // they drop at scope-end, not at the destructure
    // statement). Naming every field with a `_x` binding
    // lets `drop(_x)` release each subsystem Arc *here* —
    // before `supervisor.run()` takes over — so the only
    // remaining strong references to each subsystem are the
    // ones the supervisor and health aggregator own, both
    // of which the supervisor's drain shape is designed to
    // release.
    let BuiltEdge {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        dns,
        fw,
        ips,
        swg,
        ext_authz: _,
        ztna,
        sdwan,
        ha,
        updater,
        datapath: _,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(dns);
    drop(fw);
    drop(ips);
    drop(swg);
    drop(ztna);
    drop(sdwan);
    drop(ha);
    drop(updater);

    let supervisor_handle = tokio::spawn(supervisor.run());

    // 1. Wait for at least one fresh bundle pull to land on
    //    policy_eval.
    let probe = wait_until(
        "policy_eval received the test bundle",
        Duration::from_secs(5),
        || {
            stats_for_assert.pulls_fresh.load(Ordering::Relaxed) >= 1
                && policy_engine.current_bundle().graph_version == 7
        },
    )
    .await;
    if probe.is_err() {
        eprintln!(
            "comms.stats = pulls={} pulls_fresh={} pulls_not_modified={} \
             pull_failures={} connects={} connect_failures={} publish_failures={}",
            stats_for_assert.pulls.load(Ordering::Relaxed),
            stats_for_assert.pulls_fresh.load(Ordering::Relaxed),
            stats_for_assert.pulls_not_modified.load(Ordering::Relaxed),
            stats_for_assert.pull_failures.load(Ordering::Relaxed),
            stats_for_assert.connects.load(Ordering::Relaxed),
            stats_for_assert.connect_failures.load(Ordering::Relaxed),
            stats_for_assert.publish_failures.load(Ordering::Relaxed),
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

    // 2. Bundle id round-tripped through the engine. The graph
    //    id encoded above must come out the other side of the
    //    bundle decoder unchanged — proves the wire shape
    //    matches `sng-policy-eval::bundle::LoadedBundle`.
    let loaded = policy_engine.current_bundle();
    assert_eq!(
        loaded.graph_version, 7,
        "graph_version round-trip failed; got {}, expected 7",
        loaded.graph_version
    );
    // Bundle id round-trips through the wire decoder. The Go
    // wire shape encodes the graph id as the canonical
    // hyphenated UUID string; `LoadedBundle` keeps it as the
    // raw string so the comparison is against the same form.
    assert_eq!(
        loaded.graph_id, graph_id_str,
        "graph_id round-trip failed; got {:?}, expected {graph_id_str}",
        loaded.graph_id,
    );

    // 3. At least one 200 reached the control plane (and not
    //    just a stuck 503 / failure path).
    assert!(
        stats.bundle_pulls_200.load(Ordering::Relaxed) >= 1,
        "control plane saw no 200 bundle pulls",
    );

    // 4. Drive shutdown and assert clean drain. The supervisor
    //    drain budget is 30 s; with all subsystems idle the
    //    drain completes in <1 s on a warm CI runner.
    trigger.fire();
    let report = timeout(Duration::from_secs(15), supervisor_handle)
        .await
        .expect("supervisor.run did not exit within 15s")
        .expect("join")
        .expect("supervisor.run returned Err");

    assert!(
        report.all_clean(),
        "supervisor drained dirty; results: {:#?}",
        report.drain_results,
    );

    server.stop().await;
    // `kid` is named with the same value as the local var so
    // suppress the unused-binding lint without `_kid`.
    let _ = bundle;
}

/// **Task 27a** — supervisor drain under continuous load. The
/// edge runs against a fast (50 ms) pull cycle for ~250 ms,
/// then a shutdown is fired. Every subsystem MUST exit inside
/// its drain budget — proves the wave-1 fix (`tokio::select!`
/// race between reconnect-backoff sleep and shutdown signal)
/// holds at the integration tier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn supervisor_drain_under_continuous_load_within_budget() {
    init_test_tracing();
    let pki = Arc::new(mk_pki());
    let on_disk = write_pki_to_disk(&pki);

    let graph_id_uuid = Uuid::from_u128(0xCAFE_F00D);
    let graph_id_str = graph_id_uuid.to_string();
    let (body, sig_b64, etag, signing, kid) =
        build_signed_bundle(BundleTarget::Edge, &graph_id_str, 1);
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
    let built = build_edge(&cli, &cfg).expect("build_edge");
    built
        .comms
        .puller()
        .trust_store()
        .insert_key(&kid, &pubkey_bytes)
        .expect("seed trust key");

    let trigger = built.supervisor.shutdown_trigger();
    let stats_for_assert = Arc::clone(built.comms.stats());
    // Explicit drop of every subsystem Arc on `built` before
    // we hand `supervisor` off to its run loop. See the long
    // comment in `full_stack_boots_pulls_bundle_then_drains_cleanly`
    // for why a `..` pattern is not safe here.
    let BuiltEdge {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        dns,
        fw,
        ips,
        swg,
        ext_authz: _,
        ztna,
        sdwan,
        ha,
        updater,
        datapath: _,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(dns);
    drop(fw);
    drop(ips);
    drop(swg);
    drop(ztna);
    drop(sdwan);
    drop(ha);
    drop(updater);
    let supervisor_handle = tokio::spawn(supervisor.run());

    // Let the pull loop turn at least 3 cycles so we know the
    // subsystem is in a steady state (re-entering the
    // `select!` over `ticker`/`shutdown` each iteration).
    wait_until(
        "comms steady-state: 3+ pulls",
        Duration::from_secs(5),
        || stats_for_assert.pulls.load(Ordering::Relaxed) >= 3,
    )
    .await
    .expect("comms did not reach steady state");

    // Fire shutdown mid-loop and time the drain.
    let drain_start = Instant::now();
    trigger.fire();
    let report = timeout(Duration::from_secs(10), supervisor_handle)
        .await
        .expect("supervisor.run did not exit within 10s")
        .expect("join")
        .expect("supervisor.run returned Err");
    let drain_elapsed = drain_start.elapsed();

    // Drain budget is 30s per subsystem; in practice this
    // should be well under 1s with all subsystems idle and
    // healthy. A regression of the wave-1 backoff-vs-shutdown
    // race would land us back near the 30s upper bound.
    assert!(
        drain_elapsed < Duration::from_secs(5),
        "drain took {drain_elapsed:?}, expected < 5s — wave-1 backoff-vs-shutdown race may have regressed",
    );
    assert!(
        report.all_clean(),
        "supervisor drained dirty under load; results: {:#?}",
        report.drain_results,
    );

    server.stop().await;
}

/// **Task 27b** — comms reconnect after transient control-plane
/// outage. We let one 200 land, then flip the control plane to
/// return 503 for ~150 ms, then restore the 200 response. The
/// comms subsystem MUST observe a successful pull AFTER the
/// outage — proves the reconnect path advances rather than
/// getting stuck on the failure (the wave-1 fix is exercised
/// indirectly by needing a clean drain at the end too).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn comms_reconnects_after_control_plane_transient_outage() {
    init_test_tracing();
    let pki = Arc::new(mk_pki());
    let on_disk = write_pki_to_disk(&pki);

    let graph_id_uuid = Uuid::from_u128(0xFADE_FADE);
    let graph_id_str = graph_id_uuid.to_string();
    let (body, sig_b64, etag, signing, kid) =
        build_signed_bundle(BundleTarget::Edge, &graph_id_str, 3);
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
    let built = build_edge(&cli, &cfg).expect("build_edge");
    built
        .comms
        .puller()
        .trust_store()
        .insert_key(&kid, &pubkey_bytes)
        .expect("seed trust key");

    let trigger = built.supervisor.shutdown_trigger();
    let stats_for_assert = Arc::clone(built.comms.stats());
    // Explicit drop of every subsystem Arc on `built` before
    // we hand `supervisor` off to its run loop. See the long
    // comment in `full_stack_boots_pulls_bundle_then_drains_cleanly`
    // for why a `..` pattern is not safe here.
    let BuiltEdge {
        supervisor,
        telemetry,
        comms,
        policy_eval,
        dns,
        fw,
        ips,
        swg,
        ext_authz: _,
        ztna,
        sdwan,
        ha,
        updater,
        datapath: _,
    } = built;
    drop(telemetry);
    drop(comms);
    drop(policy_eval);
    drop(dns);
    drop(fw);
    drop(ips);
    drop(swg);
    drop(ztna);
    drop(sdwan);
    drop(ha);
    drop(updater);
    let supervisor_handle = tokio::spawn(supervisor.run());

    // Phase 1: wait for the first 200 to land.
    wait_until("first 200 lands", Duration::from_secs(5), || {
        stats_for_assert.pulls_fresh.load(Ordering::Relaxed) >= 1
    })
    .await
    .expect("phase-1 pull stalled");

    let phase1_fresh = stats_for_assert.pulls_fresh.load(Ordering::Relaxed);

    // Phase 2: flip to 503 for a window long enough for at
    // least one pull to land in the failure branch.
    bundle.return_503.store(true, Ordering::Release);
    wait_until("at least one 503", Duration::from_secs(5), || {
        stats.bundle_pulls_503.load(Ordering::Relaxed) >= 1
    })
    .await
    .expect("phase-2 503 never observed");
    let pull_failures_during_outage = stats_for_assert.pull_failures.load(Ordering::Relaxed);
    assert!(
        pull_failures_during_outage >= 1,
        "comms did not classify the 503 as a pull_failure",
    );

    // Phase 3: clear the 503 flag. The unchanged bundle bytes
    // stay in BundleState, so subsequent pulls hit
    // `If-None-Match` against the cached etag and the mock
    // returns 304 NotModified — proving the connection is
    // alive and the comms loop is making progress past the
    // outage.
    //
    // We deliberately do NOT rotate the bundle to a higher
    // `graph_version` here, even though that would also
    // satisfy the "comms recovered" check. `BundleState`'s
    // body / sig / etag / kid fields are not Mutex-guarded
    // (the handler task reads them lock-free), and rotating
    // them in-flight would require either Mutex-ing every
    // field or restarting the listener on a new port — both
    // are more complexity than the test needs to demonstrate
    // recovery. The 304 path is sufficient because the
    // puller surfaces it through `pulls_not_modified` (which
    // the assertion below watches) and the recovery only
    // requires that the comms loop *makes progress* past the
    // outage, not that it observes a NEW bundle.
    bundle.return_503.store(false, Ordering::Release);

    wait_until("post-outage 304 or 200", Duration::from_secs(5), || {
        let post_fresh = stats_for_assert.pulls_fresh.load(Ordering::Relaxed);
        let post_not_modified = stats_for_assert.pulls_not_modified.load(Ordering::Relaxed);
        post_fresh > phase1_fresh
            || post_not_modified >= 1
            || stats.bundle_pulls_304.load(Ordering::Relaxed) >= 1
    })
    .await
    .expect("comms did not advance past outage");

    // Drain.
    trigger.fire();
    let report = timeout(Duration::from_secs(10), supervisor_handle)
        .await
        .expect("supervisor.run did not exit within 10s")
        .expect("join")
        .expect("supervisor.run returned Err");
    assert!(
        report.all_clean(),
        "supervisor drained dirty after outage recovery; results: {:#?}",
        report.drain_results,
    );

    server.stop().await;
}

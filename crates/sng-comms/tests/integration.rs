// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//! Integration tests for `sng-comms`. Each test spins up a
//! real rustls TLS server with rcgen-generated certificates,
//! negotiates TLS 1.3 + h2 ALPN, and drives HTTP/2 requests
//! through the production `ControlPlaneClient`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode, header};
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, PKCS_ED25519};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sng_comms::{ControlPlaneClient, RequestBody, RequestPath, ResponseClass, build_client_config};
use std::sync::Arc;
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

struct TestPki {
    /// Root DER — trusted by the client.
    root_der: CertificateDer<'static>,
    /// Server TLS config — presents a server cert signed by root.
    server_config: Arc<rustls::ServerConfig>,
}

fn mk_pki() -> TestPki {
    sng_comms::tls::install_ring_provider();

    // Root CA.
    let root_key = KeyPair::generate_for(&PKCS_ED25519).expect("root key");
    let mut root_params = CertificateParams::new(vec!["test-ca".into()]).expect("root params");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let root_cert = root_params.self_signed(&root_key).expect("root cert");
    let root_der = CertificateDer::from(root_cert.der().to_vec());

    // Server cert signed by root.
    let server_key = KeyPair::generate_for(&PKCS_ED25519).expect("server key");
    let mut server_params =
        CertificateParams::new(vec!["localhost".into()]).expect("server params");
    server_params.is_ca = IsCa::NoCa;
    let server_cert = server_params
        .signed_by(&server_key, &root_cert, &root_key)
        .expect("server cert");
    let server_der = CertificateDer::from(server_cert.der().to_vec());

    let mut roots = rustls::RootCertStore::empty();
    roots.add(root_der.clone()).expect("add root");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_der],
            PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
                server_key.serialize_der(),
            )),
        )
        .expect("server tls config");
    let mut sc = server_config;
    sc.alpn_protocols = vec![b"h2".to_vec()];

    TestPki {
        root_der,
        server_config: Arc::new(sc),
    }
}

// ---------------------------------------------------------------------------
// Mock h2 server
// ---------------------------------------------------------------------------

/// Spin up a TLS+h2 server on a random port. Returns the address
/// and a JoinHandle that serves exactly one connection. The
/// `handler` closure is called for each h2 request and must
/// return (StatusCode, headers, body).
async fn serve_one<F>(pki: &TestPki, handler: F) -> (String, tokio::task::JoinHandle<()>)
where
    F: Fn(Request<()>, Bytes) -> (StatusCode, Vec<(String, String)>, Bytes) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let addr_str = format!("127.0.0.1:{}", addr.port());
    let sc = pki.server_config.clone();
    let handler = Arc::new(handler);

    let handle = tokio::spawn(async move {
        let (tcp, _peer) = listener.accept().await.expect("accept");
        let acceptor = tokio_rustls::TlsAcceptor::from(sc);
        let tls = acceptor.accept(tcp).await.expect("server tls handshake");

        let mut h2 = h2::server::Builder::new();
        h2.initial_window_size(1024 * 1024);
        let mut conn = h2.handshake(tls).await.expect("h2 server handshake");

        while let Some(result) = conn.accept().await {
            let (request, mut respond) = result.expect("accept h2 request");
            let (parts, mut recv_body) = request.into_parts();

            // Collect request body.
            let mut body = Vec::new();
            while let Some(chunk) = recv_body.data().await {
                let bytes = chunk.expect("recv body");
                let len = bytes.len();
                body.extend_from_slice(&bytes);
                let _ = recv_body.flow_control().release_capacity(len);
            }

            let request_rebuilt = Request::from_parts(parts, ());
            let (status, hdrs, resp_body) = (handler)(request_rebuilt, Bytes::from(body));

            let mut response = Response::builder().status(status);
            for (k, v) in &hdrs {
                response = response.header(k.as_str(), v.as_str());
            }
            let response = response.body(()).expect("build response");
            let mut send = respond
                .send_response(response, resp_body.is_empty())
                .expect("send response");
            if !resp_body.is_empty() {
                send.send_data(resp_body, true).expect("send body");
            }
        }
    });

    (addr_str, handle)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tls_h2_round_trip_get_200() {
    let pki = mk_pki();
    let (addr, _server) = serve_one(&pki, |req, _body| {
        assert_eq!(req.method(), &http::Method::GET);
        assert_eq!(req.uri().path(), "/api/v1/healthz");
        (
            StatusCode::OK,
            vec![("x-test".into(), "passed".into())],
            Bytes::from_static(b"OK"),
        )
    })
    .await;

    let tls_config =
        build_client_config(vec![pki.root_der.clone()], None).expect("client tls config");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ControlPlaneClient::new(&addr, server_name, Arc::new(tls_config)).expect("client");
    let conn = client.connect().await.expect("connect");

    let resp = conn
        .send_request(RequestPath::get("/api/v1/healthz"), RequestBody::Empty)
        .await
        .expect("request");

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body.as_ref(), b"OK");
    assert_eq!(
        resp.headers.get("x-test").map(HeaderValue::as_bytes),
        Some(b"passed".as_ref()),
    );
}

#[tokio::test]
async fn tls_h2_post_with_body() {
    let pki = mk_pki();
    let (addr, _server) = serve_one(&pki, |req, body| {
        assert_eq!(req.method(), &http::Method::POST);
        assert_eq!(req.uri().path(), "/api/v1/agents/telemetry/batches");
        // Echo the body length in the response.
        let len = body.len();
        (
            StatusCode::OK,
            vec![],
            Bytes::from(format!("{{\"seq\":1,\"len\":{len}}}")),
        )
    })
    .await;

    let tls_config = build_client_config(vec![pki.root_der.clone()], None).expect("tls config");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ControlPlaneClient::new(&addr, server_name, Arc::new(tls_config)).expect("client");
    let conn = client.connect().await.expect("connect");

    let payload = Bytes::from(vec![0u8; 1024]);
    let resp = conn
        .send_request(
            RequestPath::post("/api/v1/agents/telemetry/batches").with_header(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/msgpack"),
            ),
            RequestBody::Bytes(payload),
        )
        .await
        .expect("request");

    assert_eq!(resp.status, StatusCode::OK);
    assert!(
        resp.body.starts_with(b"{\"seq\":1"),
        "body: {:?}",
        String::from_utf8_lossy(&resp.body),
    );
}

#[tokio::test]
async fn policy_pull_200_then_304() {
    use ed25519_dalek::{Signer, SigningKey};
    use sng_comms::{BundlePullOutcome, PolicyPuller, PolicyPullerConfig, PolicyTrustStore};
    use sng_core::ids::{PolicyGraphId, PolicySigningKeyId, TenantId};
    use sng_core::policy::{BundleTarget, PolicyBundleClaims};

    let pki = mk_pki();

    // Build a signed policy bundle.
    let mut seed = [0u8; 32];
    seed[0] = 0xab;
    let signing = SigningKey::from_bytes(&seed);
    let kid = PolicySigningKeyId::new("test-key-001").expect("kid");
    let pubk = signing.verifying_key().to_bytes();

    let tenant = TenantId::new_v4();
    let claims = PolicyBundleClaims {
        schema_version: 1,
        target: BundleTarget::Edge,
        graph_id: PolicyGraphId::new_v4().into_uuid().to_string(),
        graph_version: 10,
        compiler: "integration-test".into(),
        default_action: "deny".into(),
        compiled_at: chrono::Utc::now(),
    };
    // `to_vec_named` matches the Go control plane's wire shape —
    // see `crates/sng-comms/src/telemetry.rs::encode_batch` for
    // the canonical contract. Encoding-asymmetric bugs would
    // otherwise pass this test because the fixture signs the same
    // bytes it verifies.
    let body_bytes = rmp_serde::to_vec_named(&claims).expect("encode claims");
    let sig = signing.sign(&body_bytes);
    let sig_b64 =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes());

    let body_for_handler = Bytes::from(body_bytes.clone());
    let sig_for_handler = sig_b64.clone();
    let kid_for_handler = kid.as_str().to_string();

    let etag = "\"bundle-v10\"";
    let etag_for_handler = etag.to_string();

    // Request counter: first = 200, second = 304.
    let request_count = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let count = request_count.clone();

    let (addr, _server) = serve_one(&pki, move |_req, _body| {
        let n = count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n == 0 {
            // 200 with body + signature headers.
            (
                StatusCode::OK,
                vec![
                    ("x-sng-policy-signature".into(), sig_for_handler.clone()),
                    ("x-sng-policy-key-id".into(), kid_for_handler.clone()),
                    ("etag".into(), etag_for_handler.clone()),
                ],
                body_for_handler.clone(),
            )
        } else {
            // 304 Not Modified.
            (StatusCode::NOT_MODIFIED, vec![], Bytes::new())
        }
    })
    .await;

    let tls_config = build_client_config(vec![pki.root_der.clone()], None).expect("tls config");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ControlPlaneClient::new(&addr, server_name, Arc::new(tls_config)).expect("client");
    let conn = client.connect().await.expect("connect");

    let trust_store = Arc::new(PolicyTrustStore::new());
    trust_store.insert_key(&kid, &pubk).expect("insert key");

    let puller = PolicyPuller::new(
        PolicyPullerConfig {
            tenant_id: tenant,
            target: BundleTarget::Edge,
            path_override: Some("/api/v1/bundles".into()),
        },
        trust_store,
    );

    // First pull — expect 200 + Updated.
    let outcome = puller.pull(&conn).await.expect("first pull");
    match outcome {
        BundlePullOutcome::Updated(cached) => {
            assert_eq!(cached.claims.graph_version, 10);
        }
        BundlePullOutcome::NotModified => panic!("expected Updated, got NotModified"),
    }

    // Second pull — expect 304 + NotModified.
    let outcome = puller.pull(&conn).await.expect("second pull");
    assert!(
        matches!(outcome, BundlePullOutcome::NotModified),
        "expected NotModified, got {outcome:?}",
    );

    assert_eq!(request_count.load(std::sync::atomic::Ordering::Relaxed), 2,);
}

#[tokio::test]
async fn server_error_classifies_as_retryable() {
    let pki = mk_pki();
    let (addr, _server) = serve_one(&pki, |_req, _body| {
        (StatusCode::INTERNAL_SERVER_ERROR, vec![], Bytes::new())
    })
    .await;

    let tls_config = build_client_config(vec![pki.root_der.clone()], None).expect("tls config");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ControlPlaneClient::new(&addr, server_name, Arc::new(tls_config)).expect("client");
    let conn = client.connect().await.expect("connect");

    let resp = conn
        .send_request(RequestPath::get("/api/v1/healthz"), RequestBody::Empty)
        .await
        .expect("request");

    assert_eq!(resp.classify(), ResponseClass::ServerError);
    assert!(resp.classify().is_retryable());
}

#[tokio::test]
async fn response_body_cap_aborts_oversize_response() {
    // Server returns a 4 KiB body; client is configured with a
    // 1 KiB cap. The response collection MUST error rather than
    // grow the buffer past the cap. This is the test for the
    // defence-in-depth hardening against a compromised control
    // plane sending an arbitrarily large response.
    let pki = mk_pki();
    let oversize_body = Bytes::from(vec![0xABu8; 4 * 1024]);
    let body_for_server = oversize_body.clone();
    let (addr, _server) = serve_one(&pki, move |_req, _body| {
        (StatusCode::OK, vec![], body_for_server.clone())
    })
    .await;

    let tls_config = build_client_config(vec![pki.root_der.clone()], None).expect("tls config");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ControlPlaneClient::new(&addr, server_name, Arc::new(tls_config))
        .expect("client")
        .with_max_response_bytes(1024);
    let conn = client.connect().await.expect("connect");

    let err = conn
        .send_request(RequestPath::get("/api/v1/healthz"), RequestBody::Empty)
        .await
        .expect_err("expected body-cap rejection");

    match err {
        sng_comms::CommsError::Http2(msg) => {
            assert!(
                msg.contains("byte limit") || msg.contains("1024"),
                "unexpected error message: {msg}",
            );
        }
        other => panic!("expected Http2 error, got: {other:?}"),
    }
}

#[tokio::test]
async fn response_body_under_cap_succeeds() {
    // Sanity: a body smaller than the cap still passes through.
    // Catches a regression where the cap check incorrectly fires
    // on under-limit responses (e.g. an off-by-one in the
    // saturating_add comparison).
    let pki = mk_pki();
    let small_body = Bytes::from(vec![0xCDu8; 512]);
    let body_for_server = small_body.clone();
    let (addr, _server) = serve_one(&pki, move |_req, _body| {
        (StatusCode::OK, vec![], body_for_server.clone())
    })
    .await;

    let tls_config = build_client_config(vec![pki.root_der.clone()], None).expect("tls config");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let client = ControlPlaneClient::new(&addr, server_name, Arc::new(tls_config))
        .expect("client")
        .with_max_response_bytes(1024);
    let conn = client.connect().await.expect("connect");

    let resp = conn
        .send_request(RequestPath::get("/api/v1/healthz"), RequestBody::Empty)
        .await
        .expect("request");

    assert_eq!(resp.status, StatusCode::OK);
    assert_eq!(resp.body.len(), 512);
}

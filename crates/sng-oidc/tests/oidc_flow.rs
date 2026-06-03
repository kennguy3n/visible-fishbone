//! End-to-end OIDC flow against an in-process mock provider.
//!
//! Exercises discovery → authorization-URL build → (mock)
//! `AuthSurface` callback → code→token exchange → ID-token
//! validation against the served JWKS → session refresh. There
//! are no real network calls: `wiremock` stands up the provider
//! on loopback.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use sng_oidc::auth_surface::{AuthSurface, AuthSurfaceError, CallbackUrl};
use sng_oidc::authorize::AuthorizationRequest;
use sng_oidc::discovery::DiscoveryClient;
use sng_oidc::pkce::PkceChallenge;
use sng_oidc::session::{OidcSession, SessionConfig};
use sng_oidc::token::{CodeExchange, TokenClient, TokenResponse};
use sng_oidc::validation::{IdTokenValidator, JwksClient};
use url::Url;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_RSA_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
MIIEowIBAAKCAQEAvMTG1HiwHybKITBL4mlsLrcgl4fugXlMeH3HO2FdoT1+8NLa\n\
4Xlv4Dhy4xYjlDHuQB0ivLWMzqDcsfj3GisNVI809Q8Dj0zWCGdohFv84Jl4YVVS\n\
RLIFL7zxfYgS38XZ4zPkezrBYduvN2Xmd5z8igG9m0U7FuM3EHv+E5atQ1B6VyiV\n\
Ipca+Zeycw1Ufznn6igf5VREg23sOlCObW3WNFmmi2w4lq/SprA5PDsZqhTjM+Cb\n\
7FluoK2DKPWLjraIgu/OfuKP+jK/Gs6xsRj1fw7wvuRO7spfGTRUnTwcUrOALOV1\n\
feTXSScV5xI+DVZWjuWKoRUOLAZAwrVDSyovXQIDAQABAoIBAFbF5dhZuiw3uobT\n\
Gq7zYyV+TN8bP0oJJlvlBaaINXAfQrEVXER1fDYH/Nfin2xKH4kdW5B/rEB3tbui\n\
BITk8XXDdsaHpk1DNsgaMPNXDcF5CttDS1QEuVmecywPVw3Cd0x32DnFYovHXp4K\n\
m4y0f2o5Lp2nj2gP/on3VW5Pv0nHc/V898oOh1UM+uMhIQAiVXf4ADa1vpOKNBzM\n\
wJF/vErIKGUhokSfLhL4XGO4CHOXkUmLHvMwaUWnD9KY6H5thMmcVM+6RITOCriB\n\
BeTF2a6K7SiSCFCCMF6ylVYjHSPlEeDDm2jf7XXRkFkKaYN8W5XueG7ZYQAypZuI\n\
gaaHC4kCgYEA7+FTu01vTBQaKHvlDu+fT0y97/ygbXKfMWphuoLLJOmb5UEQqibw\n\
dIMbXZPxqQB3Wyv/HbOITYMHi3eIGtwztcE2pIJh/0TI8shpGHjQSkTjEN7Y8vqK\n\
DwqhoX3fi55MXIb/NUfke469yeiWsGmL6MfZJ43pIjZL7F6IbKH+2LsCgYEAyXQs\n\
zsKPWUI2yb9yVgkgN2qRxIJ+QpEh36ZFJvhqhl/cz/r9SeRxHZKXSza4hRO71+7k\n\
8FwSEH5vAl53oMyzXlRVBjGacm5RNcGH/lxMjpHg/u4J0nUn/Ckg6nytyrfRMRe8\n\
/BtTDfW7sEcy8dhKTyqj6fSMM4fW3cvyiN1WwscCgYBd1WKPjgbPV72zwGMlqI5E\n\
0twpmESZC5FCHz8DWk5krg0RbJY8OOcubGqz/D83wLrvqxIsaCIVUAAPij5vY1vG\n\
6UGasHXtCNciQUr7C6dOpgu8ea+bvG1s3NfE+BwN3Wo5d4U1Ll4uBvQumxD3CRJ1\n\
iFdlpZlgjKS+XWw4MlYiKQKBgCPwof3RIBnggj3D9fX7cs/wJ0lTrorZsZ1g4H1v\n\
XDHU8GP6dy2zn6qS+ILmpEy5lI2VhSqMgnyG0e8uQ1Fgs69khDayqsc3fy2D9Wsf\n\
tFjLFcTlWsM9O4D1JXYwACFmYd/MSF8B0PNwn6d3TFNxLvCovs2CX3DiDydKt15L\n\
fqsJAoGBAKASHx8L9w9TSPSIDqtzokn37S6Tl8tmoQCoRPbxIBnNe2fPScRXuzC/\n\
hCBbUiUPyiI4+pZBK9PBJSBfb5sOrlQX+yxgfK+mk0sZSTls/fhKGJmeNCKrIKIX\n\
W6hfl/TTkpSnVaa+z8hT842lIfS+Nk+7VWTjBSJSpwn3/rO6yfGu\n\
-----END RSA PRIVATE KEY-----\n";

const TEST_RSA_N: &str = "vMTG1HiwHybKITBL4mlsLrcgl4fugXlMeH3HO2FdoT1-8NLa4Xlv4Dhy4xYjlDHuQB0ivLWMzqDcsfj3GisNVI809Q8Dj0zWCGdohFv84Jl4YVVSRLIFL7zxfYgS38XZ4zPkezrBYduvN2Xmd5z8igG9m0U7FuM3EHv-E5atQ1B6VyiVIpca-Zeycw1Ufznn6igf5VREg23sOlCObW3WNFmmi2w4lq_SprA5PDsZqhTjM-Cb7FluoK2DKPWLjraIgu_OfuKP-jK_Gs6xsRj1fw7wvuRO7spfGTRUnTwcUrOALOV1feTXSScV5xI-DVZWjuWKoRUOLAZAwrVDSyovXQ";
const TEST_RSA_E: &str = "AQAB";
const TEST_KID: &str = "test-key-1";
const CLIENT_ID: &str = "integration-client";
const NONCE: &str = "integration-nonce";

/// A scripted `AuthSurface` that returns a fixed callback as if
/// the user had completed the browser flow, echoing back the
/// `state` from the presented URL.
#[derive(Debug)]
struct ScriptedAuthSurface {
    code: String,
}

#[async_trait]
impl AuthSurface for ScriptedAuthSurface {
    async fn present_auth_url(&self, url: &Url) -> Result<CallbackUrl, AuthSurfaceError> {
        let state = url
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.into_owned())
            .ok_or_else(|| AuthSurfaceError::InvalidCallback("no state in auth url".to_owned()))?;
        let callback = format!(
            "com.example.app:/oauth2redirect?code={}&state={state}",
            self.code
        );
        CallbackUrl::parse(&callback)
    }
}

fn sign_id_token(issuer: &str, exp: i64) -> String {
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": "subject-99",
        "aud": CLIENT_ID,
        "exp": exp,
        "iat": chrono::Utc::now().timestamp(),
        "nonce": NONCE,
        "email": "person@example.com",
        "name": "Integration Person",
        "groups": ["engineering", "oncall"]
    });
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(TEST_KID.to_owned());
    let key = EncodingKey::from_rsa_pem(TEST_RSA_PEM.as_bytes()).expect("test PEM parses");
    encode(&header, &claims, &key).expect("sign id token")
}

fn loopback_http_client() -> reqwest::Client {
    // The mock server speaks plain HTTP on loopback, so this test
    // client must not force https_only.
    reqwest::Client::builder()
        .build()
        .expect("build test http client")
}

async fn mount_provider(server: &MockServer) {
    let base = server.uri();
    let metadata = serde_json::json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/authorize"),
        "token_endpoint": format!("{base}/token"),
        "jwks_uri": format!("{base}/jwks"),
        "scopes_supported": ["openid", "email", "profile"],
        "id_token_signing_alg_values_supported": ["RS256"]
    });
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(metadata))
        .mount(server)
        .await;

    let jwks = serde_json::json!({
        "keys": [{
            "kty": "RSA",
            "kid": TEST_KID,
            "alg": "RS256",
            "use": "sig",
            "n": TEST_RSA_N,
            "e": TEST_RSA_E
        }]
    });
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
        .mount(server)
        .await;

    let id_token = sign_id_token(&base, chrono::Utc::now().timestamp() + 3600);
    let exchange_body = serde_json::json!({
        "access_token": "access-initial",
        "token_type": "Bearer",
        "id_token": id_token,
        "refresh_token": "refresh-initial",
        "expires_in": 1,
        "scope": "openid email profile"
    });
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=authorization_code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(exchange_body))
        .mount(server)
        .await;

    let refresh_body = serde_json::json!({
        "access_token": "access-refreshed",
        "token_type": "Bearer",
        "expires_in": 3600
    });
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(refresh_body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn full_oidc_flow_discovery_authorize_exchange_validate_refresh() {
    let server = MockServer::start().await;
    mount_provider(&server).await;
    let http = loopback_http_client();

    // 1. Discovery.
    let discovery = DiscoveryClient::with_client(http.clone(), Duration::from_secs(60));
    let discovery_url = format!("{}/.well-known/openid-configuration", server.uri());
    let metadata = discovery.discover(&discovery_url).await.expect("discovery");
    assert_eq!(metadata.issuer, server.uri());
    assert_eq!(metadata.token_endpoint, format!("{}/token", server.uri()));

    // 2. PKCE + authorization URL.
    let pkce = PkceChallenge::generate();
    let auth_request = AuthorizationRequest::new(
        CLIENT_ID,
        "com.example.app:/oauth2redirect",
        "openid email profile",
        &pkce,
    )
    .with_nonce(NONCE);
    let auth_url = auth_request
        .to_url(&metadata.authorization_endpoint)
        .expect("auth url");
    assert_eq!(
        auth_url
            .query_pairs()
            .find(|(k, _)| k == "code_challenge_method")
            .map(|(_, v)| v.into_owned())
            .as_deref(),
        Some("S256")
    );

    // 3. Platform presents the URL and returns the callback.
    let surface = ScriptedAuthSurface {
        code: "auth-code-1".to_owned(),
    };
    let callback = surface.present_auth_url(&auth_url).await.expect("callback");
    assert_eq!(
        callback.state().as_deref(),
        Some(auth_request.state.as_str())
    );
    let code = callback.code().expect("callback carries a code");

    // 4. Code → token exchange.
    let token_client = TokenClient::with_client(http.clone());
    let tokens = token_client
        .exchange_code(
            &metadata.token_endpoint,
            &CodeExchange {
                client_id: CLIENT_ID.to_owned(),
                code,
                redirect_uri: "com.example.app:/oauth2redirect".to_owned(),
                code_verifier: pkce.verifier().to_owned(),
                client_secret: None,
            },
        )
        .await
        .expect("token exchange");
    assert_eq!(tokens.access_token, "access-initial");
    let id_token = tokens.id_token.clone().expect("id token present");

    // 5. ID-token validation against the served JWKS.
    let jwks_client = JwksClient::with_client(http.clone(), Duration::from_secs(60));
    let jwks = jwks_client.fetch(&metadata.jwks_uri).await.expect("jwks");
    let validator = IdTokenValidator::new(metadata.issuer.clone(), CLIENT_ID).with_nonce(NONCE);
    let claims = validator
        .validate_with_jwks(&id_token, &jwks)
        .expect("id token validates");
    assert_eq!(claims.sub, "subject-99");
    assert_eq!(
        claims.groups,
        vec!["engineering".to_owned(), "oncall".to_owned()]
    );

    // 6. Session refresh: expires_in was 1s, so the session is
    // immediately within the 60s refresh window and access_token()
    // transparently refreshes.
    let config = SessionConfig::new(metadata.token_endpoint.clone(), CLIENT_ID);
    let session = OidcSession::start(token_client, config, &tokens, Some(&claims));
    assert_eq!(session.sub().as_deref(), Some("subject-99"));
    assert!(session.needs_refresh());
    let refreshed = session.access_token().await.expect("refresh");
    assert_eq!(refreshed, "access-refreshed");
}

#[tokio::test]
async fn token_endpoint_oauth_error_is_surfaced() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "authorization code expired"
        })))
        .mount(&server)
        .await;

    let token_client = TokenClient::with_client(loopback_http_client());
    let err = token_client
        .exchange_code(
            &format!("{}/token", server.uri()),
            &CodeExchange {
                client_id: CLIENT_ID.to_owned(),
                code: "expired".to_owned(),
                redirect_uri: "com.example.app:/oauth2redirect".to_owned(),
                code_verifier: "verifier".to_owned(),
                client_secret: None,
            },
        )
        .await
        .expect_err("expired code should error");
    assert!(matches!(err, sng_oidc::OidcError::Token(_)));
}

/// Regression test for the concurrent-refresh (TOCTOU) guard:
/// when many tasks call [`OidcSession::access_token`] at once on
/// an about-to-expire session, exactly one refresh-token grant
/// must reach the provider. Without serialization every caller
/// would fire its own grant and, with rotating refresh tokens,
/// all but the first would fail `invalid_grant`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_access_token_calls_trigger_a_single_refresh() {
    let server = MockServer::start().await;
    let refresh_body = serde_json::json!({
        "access_token": "access-refreshed",
        "token_type": "Bearer",
        "expires_in": 3600
    });
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .respond_with(
            ResponseTemplate::new(200)
                // A small delay widens the window so concurrent
                // callers pile up on the refresh lock.
                .set_delay(Duration::from_millis(100))
                .set_body_json(refresh_body),
        )
        // The whole point of the test: one grant, not sixteen.
        .expect(1)
        .mount(&server)
        .await;

    let initial = TokenResponse {
        access_token: "access-initial".to_owned(),
        token_type: "Bearer".to_owned(),
        id_token: None,
        refresh_token: Some("refresh-initial".to_owned()),
        expires_in: Some(1),
        scope: None,
    };
    let config = SessionConfig::new(format!("{}/token", server.uri()), CLIENT_ID);
    let token_client = TokenClient::with_client(loopback_http_client());
    let session = Arc::new(OidcSession::start(token_client, config, &initial, None));
    assert!(session.needs_refresh());

    let mut handles = Vec::new();
    for _ in 0..16 {
        let session = Arc::clone(&session);
        handles.push(tokio::spawn(async move { session.access_token().await }));
    }
    for handle in handles {
        let token = handle.await.expect("task joins").expect("access token");
        assert_eq!(token, "access-refreshed");
    }
    // `expect(1)` is verified when `server` drops: a single
    // refresh grant served all 16 concurrent callers.
}

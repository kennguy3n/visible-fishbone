//! OpenID Connect Discovery (RFC 8414 / OIDC Discovery 1.0).
//!
//! [`DiscoveryClient`] fetches a provider's
//! `/.well-known/openid-configuration`, validates the required
//! endpoints, and caches the parsed [`ProviderMetadata`] with a
//! TTL so a long-lived process does not re-fetch the document on
//! every sign-in.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Deserialize;

use crate::error::{OidcError, Result};

/// The subset of the OpenID Provider Metadata this crate consumes.
///
/// Unknown fields are ignored; the four endpoint fields plus
/// `issuer` are required and validated on parse.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    /// The issuer identifier (`iss`) — must exactly match the
    /// `iss` claim in issued ID tokens.
    pub issuer: String,
    /// The authorization endpoint the user agent is sent to.
    pub authorization_endpoint: String,
    /// The token endpoint used for the code → token exchange and
    /// for refresh.
    pub token_endpoint: String,
    /// The JWKS document URL used to verify ID-token signatures.
    pub jwks_uri: String,
    /// The OPTIONAL UserInfo endpoint.
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    /// Scopes the provider advertises support for.
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Claims the provider advertises support for.
    #[serde(default)]
    pub claims_supported: Vec<String>,
    /// ID-token signing algorithms the provider advertises.
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Vec<String>,
}

impl ProviderMetadata {
    /// Validate the required fields are present and well-formed.
    fn validate(&self) -> Result<()> {
        if self.issuer.trim().is_empty() {
            return Err(OidcError::Discovery("issuer is empty".to_owned()));
        }
        // OIDC Discovery 1.0 §3: the issuer MUST be an https URL
        // with no query or fragment. Enforcing it here means a
        // non-URL issuer is rejected at discovery time rather than
        // silently never matching the ID token `iss` claim later.
        let issuer_url = url::Url::parse(&self.issuer)
            .map_err(|e| OidcError::Discovery(format!("issuer is not a valid URL: {e}")))?;
        if !is_secure_endpoint(&issuer_url) {
            return Err(OidcError::Discovery(
                "issuer must be https (or http on loopback for testing)".to_owned(),
            ));
        }
        if issuer_url.query().is_some() || issuer_url.fragment().is_some() {
            return Err(OidcError::Discovery(
                "issuer must not contain a query or fragment component".to_owned(),
            ));
        }
        for (field, value) in [
            ("authorization_endpoint", &self.authorization_endpoint),
            ("token_endpoint", &self.token_endpoint),
            ("jwks_uri", &self.jwks_uri),
        ] {
            let parsed = url::Url::parse(value)
                .map_err(|e| OidcError::Discovery(format!("{field} is not a valid URL: {e}")))?;
            if !is_secure_endpoint(&parsed) {
                return Err(OidcError::Discovery(format!(
                    "{field} must be https (or http on loopback for testing)"
                )));
            }
        }
        Ok(())
    }
}

/// Whether `url` is an acceptable endpoint: `https`, or `http`
/// limited to loopback hosts so tests can run against an
/// in-process mock server. Real providers are always `https`.
pub(crate) fn is_secure_endpoint(url: &url::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1")),
        _ => false,
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    metadata: Arc<ProviderMetadata>,
    fetched_at: Instant,
}

/// Caching OpenID Connect discovery client.
#[derive(Debug)]
pub struct DiscoveryClient {
    http: reqwest::Client,
    ttl: Duration,
    cache: Mutex<HashMap<String, CacheEntry>>,
}

impl DiscoveryClient {
    /// Default cache TTL (1 hour). Discovery documents are stable
    /// and providers expect clients to cache them.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(3600);

    /// Build a discovery client with the [`Self::DEFAULT_TTL`]
    /// and a fresh rustls-backed HTTP client.
    pub fn new() -> Result<Self> {
        Self::with_ttl(Self::DEFAULT_TTL)
    }

    /// Build a discovery client with an explicit cache TTL.
    pub fn with_ttl(ttl: Duration) -> Result<Self> {
        let http = build_http_client()?;
        Ok(Self::with_client(http, ttl))
    }

    /// Build a discovery client around a caller-supplied
    /// [`reqwest::Client`] (e.g. to share a connection pool).
    #[must_use]
    pub fn with_client(http: reqwest::Client, ttl: Duration) -> Self {
        Self {
            http,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Fetch (or return a cached copy of) the provider metadata at
    /// `discovery_url`.
    ///
    /// A cached entry younger than the TTL is returned without a
    /// network call. Otherwise the document is fetched, validated,
    /// cached, and returned.
    pub async fn discover(&self, discovery_url: &str) -> Result<Arc<ProviderMetadata>> {
        if let Some(hit) = self.cached(discovery_url) {
            return Ok(hit);
        }

        let response = self
            .http
            .get(discovery_url)
            .send()
            .await
            .map_err(|e| OidcError::http("discovery", e))?;
        if !response.status().is_success() {
            return Err(OidcError::HttpStatus {
                context: "discovery",
                status: response.status().as_u16(),
            });
        }
        let body = response
            .text()
            .await
            .map_err(|e| OidcError::http("discovery", e))?;
        let metadata: ProviderMetadata =
            serde_json::from_str(&body).map_err(|e| OidcError::decode("discovery", e))?;
        metadata.validate()?;

        let metadata = Arc::new(metadata);
        self.cache.lock().insert(
            discovery_url.to_owned(),
            CacheEntry {
                metadata: Arc::clone(&metadata),
                fetched_at: Instant::now(),
            },
        );
        Ok(metadata)
    }

    /// Return a live (non-expired) cache entry, if any. The lock
    /// is released before the caller awaits anything.
    fn cached(&self, discovery_url: &str) -> Option<Arc<ProviderMetadata>> {
        let mut cache = self.cache.lock();
        let entry = cache.get(discovery_url)?;
        if entry.fetched_at.elapsed() < self.ttl {
            Some(Arc::clone(&entry.metadata))
        } else {
            // Drop the stale entry instead of leaving it to
            // accumulate; a long-lived process that rotates
            // through many issuers would otherwise retain every
            // expired document until each is fetched again.
            cache.remove(discovery_url);
            None
        }
    }
}

/// Build the shared rustls-only HTTP client used by every stage.
///
/// `reqwest` is compiled `default-features = false` at the
/// workspace level, so this is rustls + ring with no OpenSSL.
///
/// The client is `https_only`, so it refuses *all* `http://`
/// requests — including loopback. This is deliberately stricter
/// than [`is_secure_endpoint`], which permits `http` on loopback:
/// that allowance exists only so a test (or a caller pointing at a
/// local mock IdP) can pass validation while supplying its own
/// permissive client via the `with_client` constructors. The
/// default clients built here are the production posture and never
/// talk plain HTTP.
pub(crate) fn build_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .use_rustls_tls()
        .https_only(true)
        .build()
        .map_err(|e| OidcError::http("client-init", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample(issuer: &str) -> ProviderMetadata {
        ProviderMetadata {
            issuer: issuer.to_owned(),
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            jwks_uri: "https://idp.example.com/jwks".to_owned(),
            userinfo_endpoint: None,
            scopes_supported: Vec::new(),
            claims_supported: Vec::new(),
            id_token_signing_alg_values_supported: Vec::new(),
        }
    }

    #[test]
    fn valid_metadata_passes_validation() {
        assert!(sample("https://idp.example.com").validate().is_ok());
    }

    #[test]
    fn empty_issuer_is_rejected() {
        let err = sample("").validate().unwrap_err();
        assert!(matches!(err, OidcError::Discovery(_)));
    }

    #[test]
    fn non_url_issuer_is_rejected() {
        let err = sample("not-a-url").validate().unwrap_err();
        assert!(matches!(err, OidcError::Discovery(_)));
    }

    #[test]
    fn non_https_issuer_is_rejected() {
        let err = sample("http://idp.example.com").validate().unwrap_err();
        assert!(matches!(err, OidcError::Discovery(_)));
    }

    #[test]
    fn issuer_with_query_or_fragment_is_rejected() {
        assert!(sample("https://idp.example.com/?x=1").validate().is_err());
        assert!(sample("https://idp.example.com/#f").validate().is_err());
    }

    #[test]
    fn non_https_endpoint_is_rejected() {
        let mut meta = sample("https://idp.example.com");
        meta.token_endpoint = "http://idp.example.com/token".to_owned();
        let err = meta.validate().unwrap_err();
        assert!(matches!(err, OidcError::Discovery(_)));
    }

    #[test]
    fn metadata_parses_and_ignores_unknown_fields() {
        let json = r#"{
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
            "jwks_uri": "https://idp.example.com/jwks",
            "scopes_supported": ["openid", "email", "profile"],
            "something_unknown": 42
        }"#;
        let meta: ProviderMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.issuer, "https://idp.example.com");
        assert_eq!(meta.scopes_supported.len(), 3);
        assert!(meta.validate().is_ok());
    }
}

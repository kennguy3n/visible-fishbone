//! Authorization-request construction (OIDC Core §3.1.2.1).
//!
//! [`AuthorizationRequest`] assembles the query the user agent is
//! redirected to: `response_type=code`, the client id, redirect
//! URI, scope, an opaque `state` (CSRF), a `nonce` (ID-token
//! replay binding), the PKCE `code_challenge` /
//! `code_challenge_method`, and any provider-specific extras
//! (Google `hd`, Microsoft `domain_hint`).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore as _;
use rand::rngs::OsRng;
use url::Url;

use crate::discovery::is_secure_endpoint;
use crate::error::{OidcError, Result};
use crate::pkce::PkceChallenge;

/// Generate an opaque, URL-safe, 256-bit random token suitable
/// for a `state` or `nonce` value.
#[must_use]
pub fn random_token() -> String {
    let mut rng = OsRng;
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A fully-specified OpenID Connect authorization request.
///
/// Build one with [`AuthorizationRequest::new`], attach the PKCE
/// pair, set `state` / `nonce` (or let them default to fresh
/// random tokens), add any provider params, then render the final
/// URL with [`AuthorizationRequest::to_url`].
#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    /// OAuth2 client identifier.
    pub client_id: String,
    /// Redirect URI registered with the provider.
    pub redirect_uri: String,
    /// Space-delimited scope string (must include `openid`).
    pub scope: String,
    /// Opaque CSRF token echoed back on the callback.
    pub state: String,
    /// Replay-binding nonce echoed into the ID token.
    pub nonce: String,
    /// PKCE `S256` code challenge.
    pub code_challenge: String,
    /// Additional provider-specific query parameters (e.g.
    /// `("hd", "example.com")` or `("domain_hint", "…")`).
    pub extra_params: Vec<(String, String)>,
}

impl AuthorizationRequest {
    /// Begin a request with fresh random `state` and `nonce`
    /// values and the supplied PKCE challenge.
    #[must_use]
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        scope: impl Into<String>,
        pkce: &PkceChallenge,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            scope: scope.into(),
            state: random_token(),
            nonce: random_token(),
            code_challenge: pkce.challenge().to_owned(),
            extra_params: Vec::new(),
        }
    }

    /// Override the CSRF `state`.
    #[must_use]
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = state.into();
        self
    }

    /// Override the `nonce`.
    #[must_use]
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = nonce.into();
        self
    }

    /// Append a provider-specific query parameter.
    #[must_use]
    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_params.push((key.into(), value.into()));
        self
    }

    /// Request a specific OIDC `prompt` behaviour (OIDC Core
    /// §3.1.2.1). For MFA step-up the value is `login`, which
    /// forces the IdP to re-authenticate the user even if it holds
    /// a live SSO session, so the resulting token reflects a fresh
    /// (and, with `acr_values`, MFA-satisfied) authentication
    /// rather than replaying the existing session's `amr`.
    #[must_use]
    pub fn with_prompt(self, prompt: impl Into<String>) -> Self {
        self.with_param("prompt", prompt)
    }

    /// Request one or more Authentication Context Class References
    /// (`acr_values`, OIDC Core §3.1.2.1). iam-core's
    /// universal-login interprets the MFA acr as "challenge the
    /// user for a second factor", so combining this with
    /// [`Self::with_prompt`]`("login")` is how ShieldNet drives an
    /// MFA step-up without inventing a verify endpoint.
    #[must_use]
    pub fn with_acr_values(self, acr_values: impl Into<String>) -> Self {
        self.with_param("acr_values", acr_values)
    }

    /// Render the absolute authorization URL by appending the
    /// query to `authorization_endpoint`.
    ///
    /// Existing query parameters already present on the endpoint
    /// (rare, but legal) are preserved; the OIDC parameters are
    /// appended after them.
    pub fn to_url(&self, authorization_endpoint: &str) -> Result<Url> {
        let mut url = Url::parse(authorization_endpoint)?;
        if !is_secure_endpoint(&url) {
            return Err(OidcError::Discovery(
                "authorization_endpoint must be https".to_owned(),
            ));
        }
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", &self.redirect_uri)
                .append_pair("scope", &self.scope)
                .append_pair("state", &self.state)
                .append_pair("nonce", &self.nonce)
                .append_pair("code_challenge", &self.code_challenge)
                .append_pair("code_challenge_method", "S256");
            for (key, value) in &self.extra_params {
                query.append_pair(key, value);
            }
        }
        Ok(url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn query_map(url: &Url) -> HashMap<String, String> {
        url.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn builds_url_with_all_required_oidc_parameters() {
        let pkce = PkceChallenge::generate();
        let req = AuthorizationRequest::new(
            "client-123",
            "com.example.app:/oauth2redirect",
            "openid email profile",
            &pkce,
        )
        .with_state("state-xyz")
        .with_nonce("nonce-abc");

        let url = req.to_url("https://idp.example.com/authorize").unwrap();
        let q = query_map(&url);

        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("idp.example.com"));
        assert_eq!(url.path(), "/authorize");
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], "client-123");
        assert_eq!(q["redirect_uri"], "com.example.app:/oauth2redirect");
        assert_eq!(q["scope"], "openid email profile");
        assert_eq!(q["state"], "state-xyz");
        assert_eq!(q["nonce"], "nonce-abc");
        assert_eq!(q["code_challenge"], pkce.challenge());
        assert_eq!(q["code_challenge_method"], "S256");
    }

    #[test]
    fn extra_params_are_appended() {
        let pkce = PkceChallenge::generate();
        let url = AuthorizationRequest::new("c", "r", "openid", &pkce)
            .with_param("hd", "example.com")
            .to_url("https://idp.example.com/authorize")
            .unwrap();
        let q = query_map(&url);
        assert_eq!(q["hd"], "example.com");
    }

    #[test]
    fn default_state_and_nonce_are_random_and_distinct() {
        let pkce = PkceChallenge::generate();
        let req = AuthorizationRequest::new("c", "r", "openid", &pkce);
        assert_ne!(req.state, req.nonce);
        assert!(req.state.len() >= 43);
    }

    #[test]
    fn non_https_endpoint_is_rejected() {
        let pkce = PkceChallenge::generate();
        let err = AuthorizationRequest::new("c", "r", "openid", &pkce)
            .to_url("http://idp.example.com/authorize")
            .unwrap_err();
        assert!(matches!(err, OidcError::Discovery(_)));
    }
}

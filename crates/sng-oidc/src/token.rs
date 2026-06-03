//! Token endpoint: code exchange + refresh (OIDC Core §3.1.3,
//! OAuth2 RFC 6749 §4.1.3 / §6).
//!
//! [`TokenClient`] POSTs the `application/x-www-form-urlencoded`
//! body to the provider's token endpoint and parses either a
//! [`TokenResponse`] or a structured [`OauthErrorResponse`].

use std::fmt;

use serde::Deserialize;

use crate::discovery::build_http_client;
use crate::error::{OidcError, Result};

/// A successful token-endpoint response.
///
/// `access_token` and the optional `id_token` / `refresh_token`
/// are secrets; the custom [`fmt::Debug`] redacts them.
#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    /// The OAuth2 access token.
    pub access_token: String,
    /// Token type — `Bearer` for every provider this crate
    /// targets.
    #[serde(default = "default_token_type")]
    pub token_type: String,
    /// The OpenID Connect ID token (a signed JWT), present on the
    /// initial exchange and, for some providers, on refresh.
    #[serde(default)]
    pub id_token: Option<String>,
    /// The refresh token, present when `offline_access` was
    /// granted.
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// Access-token lifetime in seconds.
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// The scope actually granted, if it differs from the request.
    #[serde(default)]
    pub scope: Option<String>,
}

fn default_token_type() -> String {
    "Bearer".to_owned()
}

impl fmt::Debug for TokenResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenResponse")
            .field("access_token", &"<redacted>")
            .field("token_type", &self.token_type)
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish()
    }
}

/// A structured OAuth2 error response (RFC 6749 §5.2).
#[derive(Debug, Clone, Deserialize)]
pub struct OauthErrorResponse {
    /// The machine-readable error code (`invalid_grant`,
    /// `invalid_client`, …).
    pub error: String,
    /// Human-readable description.
    #[serde(default)]
    pub error_description: Option<String>,
    /// URI of a human-readable error page.
    #[serde(default)]
    pub error_uri: Option<String>,
}

impl fmt::Display for OauthErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)?;
        if let Some(description) = &self.error_description {
            write!(f, ": {description}")?;
        }
        Ok(())
    }
}

impl std::error::Error for OauthErrorResponse {}

/// Parameters for the authorization-code → token exchange.
///
/// `code`, `code_verifier`, and `client_secret` are secrets; the
/// custom [`fmt::Debug`] redacts them.
#[derive(Clone)]
pub struct CodeExchange {
    /// OAuth2 client identifier.
    pub client_id: String,
    /// The authorization code returned on the callback.
    pub code: String,
    /// The exact redirect URI used on the authorization request.
    pub redirect_uri: String,
    /// The PKCE code verifier matching the challenge that was
    /// sent on the authorization request.
    pub code_verifier: String,
    /// Optional client secret (confidential clients only; native
    /// apps leave this [`None`] and rely on PKCE).
    pub client_secret: Option<String>,
}

/// Parameters for a refresh-token grant.
///
/// `refresh_token` and `client_secret` are secrets; the custom
/// [`fmt::Debug`] redacts them.
#[derive(Clone)]
pub struct RefreshRequest {
    /// OAuth2 client identifier.
    pub client_id: String,
    /// The refresh token previously issued.
    pub refresh_token: String,
    /// Optional narrowed scope.
    pub scope: Option<String>,
    /// Optional client secret (confidential clients only).
    pub client_secret: Option<String>,
}

impl fmt::Debug for CodeExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CodeExchange")
            .field("client_id", &self.client_id)
            .field("code", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &"<redacted>")
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl fmt::Debug for RefreshRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RefreshRequest")
            .field("client_id", &self.client_id)
            .field("refresh_token", &"<redacted>")
            .field("scope", &self.scope)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Token-endpoint HTTP client.
#[derive(Debug)]
pub struct TokenClient {
    http: reqwest::Client,
}

impl TokenClient {
    /// Build a token client with a fresh rustls-backed HTTP
    /// client.
    pub fn new() -> Result<Self> {
        Ok(Self {
            http: build_http_client()?,
        })
    }

    /// Build a token client around a caller-supplied client.
    #[must_use]
    pub fn with_client(http: reqwest::Client) -> Self {
        Self { http }
    }

    /// Exchange an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        token_endpoint: &str,
        request: &CodeExchange,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", request.code.as_str()),
            ("redirect_uri", request.redirect_uri.as_str()),
            ("client_id", request.client_id.as_str()),
            ("code_verifier", request.code_verifier.as_str()),
        ];
        if let Some(secret) = &request.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        self.post_form(token_endpoint, &form).await
    }

    /// Exchange a refresh token for a fresh access (and possibly
    /// ID / refresh) token.
    pub async fn refresh(
        &self,
        token_endpoint: &str,
        request: &RefreshRequest,
    ) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", request.refresh_token.as_str()),
            ("client_id", request.client_id.as_str()),
        ];
        if let Some(scope) = &request.scope {
            form.push(("scope", scope.as_str()));
        }
        if let Some(secret) = &request.client_secret {
            form.push(("client_secret", secret.as_str()));
        }
        self.post_form(token_endpoint, &form).await
    }

    /// POST a form body and parse the success or OAuth2-error
    /// response.
    async fn post_form(
        &self,
        token_endpoint: &str,
        form: &[(&str, &str)],
    ) -> Result<TokenResponse> {
        let response = self
            .http
            .post(token_endpoint)
            .form(form)
            .send()
            .await
            .map_err(|e| OidcError::http("token", e))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| OidcError::http("token", e))?;

        if status.is_success() {
            return serde_json::from_str(&body).map_err(|e| OidcError::decode("token", e));
        }

        // A non-2xx status should carry a structured OAuth2 error;
        // fall back to a status error if the body is not parseable.
        match serde_json::from_str::<OauthErrorResponse>(&body) {
            Ok(oauth_error) => Err(OidcError::Token(oauth_error)),
            Err(_) => Err(OidcError::HttpStatus {
                context: "token",
                status: status.as_u16(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn parses_full_token_response() {
        let json = r#"{
            "access_token": "at-value",
            "token_type": "Bearer",
            "id_token": "idt-value",
            "refresh_token": "rt-value",
            "expires_in": 3600,
            "scope": "openid email"
        }"#;
        let parsed: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.access_token, "at-value");
        assert_eq!(parsed.token_type, "Bearer");
        assert_eq!(parsed.id_token.as_deref(), Some("idt-value"));
        assert_eq!(parsed.refresh_token.as_deref(), Some("rt-value"));
        assert_eq!(parsed.expires_in, Some(3600));
        assert_eq!(parsed.scope.as_deref(), Some("openid email"));
    }

    #[test]
    fn parses_minimal_token_response_with_defaults() {
        let json = r#"{"access_token": "at-only"}"#;
        let parsed: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.access_token, "at-only");
        assert_eq!(parsed.token_type, "Bearer");
        assert!(parsed.id_token.is_none());
        assert!(parsed.refresh_token.is_none());
        assert!(parsed.expires_in.is_none());
    }

    #[test]
    fn parses_oauth_error_response() {
        let json = r#"{"error": "invalid_grant", "error_description": "code expired"}"#;
        let parsed: OauthErrorResponse = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.error, "invalid_grant");
        assert_eq!(format!("{parsed}"), "invalid_grant: code expired");
    }

    #[test]
    fn debug_redacts_secret_tokens() {
        let parsed: TokenResponse = serde_json::from_str(
            r#"{"access_token":"secret-at","id_token":"secret-idt","refresh_token":"secret-rt"}"#,
        )
        .unwrap();
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("secret-at"));
        assert!(!rendered.contains("secret-idt"));
        assert!(!rendered.contains("secret-rt"));
        assert!(rendered.contains("<redacted>"));
    }
}

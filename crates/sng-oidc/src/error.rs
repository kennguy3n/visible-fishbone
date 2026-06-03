//! Crate error taxonomy.
//!
//! Every fallible surface in `sng-oidc` returns
//! [`Result<T>`](crate::error::Result) which is
//! `std::result::Result<T, OidcError>`. The variants are
//! deliberately coarse — they bucket failures by *stage* (HTTP
//! transport, discovery parse, token-endpoint OAuth2 error,
//! ID-token validation) so a caller can branch on "retryable
//! transport" vs "permanent protocol error" without matching a
//! sprawling enum.

use crate::token::OauthErrorResponse;
use thiserror::Error;

/// Convenience alias for results produced by this crate.
pub type Result<T> = std::result::Result<T, OidcError>;

/// All errors produced by the OIDC client.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OidcError {
    /// A network / HTTP transport failure occurred while talking
    /// to a provider endpoint (DNS, TLS, connection reset,
    /// timeout). The `context` names the call site
    /// (`"discovery"`, `"jwks"`, `"token"`, …) so a log line
    /// identifies which stage failed without a backtrace.
    #[error("http transport error during {context}: {source}")]
    Http {
        /// Stage label for the failing request.
        context: &'static str,
        /// Underlying transport error.
        #[source]
        source: reqwest::Error,
    },

    /// A provider endpoint returned a non-success HTTP status
    /// that is not a structured OAuth2 error (e.g. a `500` from
    /// the discovery or JWKS endpoint).
    #[error("unexpected http status {status} during {context}")]
    HttpStatus {
        /// Stage label for the request.
        context: &'static str,
        /// The HTTP status code received.
        status: u16,
    },

    /// A JSON document returned by the provider could not be
    /// deserialized into the expected shape.
    #[error("failed to decode {context} response: {source}")]
    Decode {
        /// Stage label for the document being parsed.
        context: &'static str,
        /// Underlying serde error.
        #[source]
        source: serde_json::Error,
    },

    /// The OIDC discovery document was missing a required field
    /// or carried a value that does not satisfy the spec (e.g. an
    /// `authorization_endpoint` that is not an absolute URL).
    #[error("invalid discovery document: {0}")]
    Discovery(String),

    /// The token endpoint returned a structured OAuth2 error
    /// response (RFC 6749 §5.2).
    #[error("token endpoint error: {0}")]
    Token(#[from] OauthErrorResponse),

    /// ID-token validation failed for a reason other than a raw
    /// signature mismatch — a missing/mismatched `iss`, `aud`,
    /// `nonce`, or `azp`, an expired token, or an unusable JWKS.
    #[error("id token validation failed: {0}")]
    Validation(String),

    /// The JWT library rejected the ID token (signature
    /// mismatch, malformed header, unsupported algorithm).
    #[error("id token signature/format invalid: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// A returned `state` parameter did not match the value the
    /// client generated — a possible CSRF / session-fixation
    /// attempt. The authorization response is rejected.
    #[error("state mismatch: authorization response failed CSRF check")]
    StateMismatch,

    /// The authorization callback URL carried neither an
    /// authorization `code` nor a structured error, or could not
    /// be parsed.
    #[error("invalid authorization callback: {0}")]
    Callback(String),

    /// A URL could not be parsed or joined.
    #[error("url error: {0}")]
    Url(#[from] url::ParseError),

    /// The injected [`AuthSurface`](crate::auth_surface::AuthSurface)
    /// failed to present the authorization URL or capture the
    /// callback.
    #[error("auth surface error: {0}")]
    AuthSurface(String),

    /// The injected [`TokenStorage`](crate::storage::TokenStorage)
    /// failed to persist or load tokens.
    #[error("token storage error: {0}")]
    Storage(String),

    /// A session-lifecycle precondition was not met (e.g. an
    /// auto-refresh was requested but the session holds no refresh
    /// token).
    #[error("session error: {0}")]
    Session(String),
}

impl OidcError {
    /// Construct an [`OidcError::Http`] for the given stage.
    pub(crate) fn http(context: &'static str, source: reqwest::Error) -> Self {
        Self::Http { context, source }
    }

    /// Construct an [`OidcError::Decode`] for the given stage.
    pub(crate) fn decode(context: &'static str, source: serde_json::Error) -> Self {
        Self::Decode { context, source }
    }
}

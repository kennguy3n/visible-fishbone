//! Platform browser-presentation contract.
//!
//! This module defines the single seam between the
//! platform-independent OIDC core and the OS. The iOS and Android
//! PALs (built in later sessions) implement [`AuthSurface`] over
//! `ASWebAuthenticationSession` and Android Custom Tabs
//! respectively. **Keep this trait stable, object-safe, and
//! documented** — it is a contract those sessions depend on.

use async_trait::async_trait;
use url::Url;

/// Errors an [`AuthSurface`] implementation may return.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthSurfaceError {
    /// The user dismissed / cancelled the browser before the flow
    /// completed.
    #[error("authentication cancelled by user")]
    Cancelled,
    /// The platform timed out waiting for the redirect callback.
    #[error("authentication timed out")]
    Timeout,
    /// The platform could not present the authorization URL
    /// (no foreground activity / view controller, browser
    /// unavailable, etc.).
    #[error("failed to present authorization URL: {0}")]
    Presentation(String),
    /// The captured callback URL was malformed or did not match
    /// the expected redirect scheme.
    #[error("invalid callback URL: {0}")]
    InvalidCallback(String),
}

/// The redirect callback URL captured by the platform after the
/// user authenticates.
///
/// Wraps the raw [`Url`] and exposes the OAuth2 / OIDC response
/// parameters (`code`, `state`, `error`) the core needs to
/// continue the flow.
#[derive(Debug, Clone)]
pub struct CallbackUrl(Url);

impl CallbackUrl {
    /// Wrap a captured redirect URL.
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self(url)
    }

    /// Parse a captured redirect URL from a string.
    pub fn parse(raw: &str) -> Result<Self, AuthSurfaceError> {
        Url::parse(raw)
            .map(Self)
            .map_err(|e| AuthSurfaceError::InvalidCallback(e.to_string()))
    }

    /// The underlying URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.0
    }

    /// The first query parameter matching `name`, if present.
    fn query(&self, name: &str) -> Option<String> {
        self.0
            .query_pairs()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.into_owned())
    }

    /// The `code` authorization-code parameter, if present.
    #[must_use]
    pub fn code(&self) -> Option<String> {
        self.query("code")
    }

    /// The `state` CSRF parameter, if present.
    #[must_use]
    pub fn state(&self) -> Option<String> {
        self.query("state")
    }

    /// The `error` parameter, present when the IdP returned an
    /// error instead of a code.
    #[must_use]
    pub fn error(&self) -> Option<String> {
        self.query("error")
    }

    /// The human-readable `error_description`, if present.
    #[must_use]
    pub fn error_description(&self) -> Option<String> {
        self.query("error_description")
    }
}

/// Platform contract for presenting an authorization URL and
/// capturing the redirect callback.
///
/// The implementation opens `url` in a system browser / web
/// authentication session, waits for the IdP to redirect to the
/// app's registered redirect URI, and returns the captured
/// [`CallbackUrl`]. It MUST NOT inspect or validate the query
/// parameters — `state` / `code` verification is the core's
/// responsibility.
///
/// The trait is object-safe (`Arc<dyn AuthSurface>`); it has a
/// single async method and uses no generics or associated types.
/// `Debug` is required (mirroring [`TokenStorage`](crate::storage::TokenStorage))
/// so a surface can be embedded in a higher-level type's derived
/// `Debug` without leaking anything sensitive.
#[async_trait]
pub trait AuthSurface: Send + Sync + std::fmt::Debug {
    /// Present `url` to the user and resolve with the redirect
    /// [`CallbackUrl`] once the flow completes.
    async fn present_auth_url(&self, url: &Url) -> Result<CallbackUrl, AuthSurfaceError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn extracts_code_and_state() {
        let cb = CallbackUrl::parse("com.example.app:/cb?code=auth-code&state=st-1").unwrap();
        assert_eq!(cb.code().as_deref(), Some("auth-code"));
        assert_eq!(cb.state().as_deref(), Some("st-1"));
        assert!(cb.error().is_none());
    }

    #[test]
    fn extracts_error() {
        let cb =
            CallbackUrl::parse("com.example.app:/cb?error=access_denied&error_description=nope")
                .unwrap();
        assert_eq!(cb.error().as_deref(), Some("access_denied"));
        assert_eq!(cb.error_description().as_deref(), Some("nope"));
        assert!(cb.code().is_none());
    }

    #[test]
    fn rejects_unparseable_callback() {
        let err = CallbackUrl::parse("not a url").unwrap_err();
        assert!(matches!(err, AuthSurfaceError::InvalidCallback(_)));
    }

    // Compile-time proof the trait is object-safe.
    #[allow(dead_code)]
    fn assert_object_safe(_: &dyn AuthSurface) {}
}

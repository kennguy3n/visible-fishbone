//! Token-lifecycle session.
//!
//! [`OidcSession`] owns the access / refresh / id tokens for one
//! authenticated user and keeps the access token fresh: when it
//! is within the refresh skew (plus a per-session random jitter,
//! to avoid a fleet of agents all refreshing on the same second)
//! of expiry, [`OidcSession::access_token`] transparently runs a
//! refresh-token grant before returning. The session also exposes
//! the `sub` + `groups` the ZTNA broker binds an access decision
//! to.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rand::RngCore as _;
use rand::rngs::OsRng;
use tokio::sync::Mutex as AsyncMutex;

use crate::error::{OidcError, Result};
use crate::storage::StoredTokens;
use crate::token::{RefreshRequest, TokenClient, TokenResponse};
use crate::validation::IdTokenClaims;

/// Static configuration for an [`OidcSession`].
///
/// `client_secret` is a secret; the custom [`fmt::Debug`] redacts
/// it so it never lands in a log line.
#[derive(Clone)]
pub struct SessionConfig {
    /// The provider token endpoint used for refresh grants.
    pub token_endpoint: String,
    /// OAuth2 client identifier.
    pub client_id: String,
    /// Optional client secret (confidential clients only).
    pub client_secret: Option<String>,
    /// How long before expiry the access token is proactively
    /// refreshed.
    pub refresh_skew: Duration,
}

impl SessionConfig {
    /// Default refresh skew (refresh 60s before expiry).
    pub const DEFAULT_REFRESH_SKEW: Duration = Duration::from_secs(60);

    /// Build a config with the default refresh skew and no client
    /// secret.
    #[must_use]
    pub fn new(token_endpoint: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            token_endpoint: token_endpoint.into(),
            client_id: client_id.into(),
            client_secret: None,
            refresh_skew: Self::DEFAULT_REFRESH_SKEW,
        }
    }
}

impl fmt::Debug for SessionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionConfig")
            .field("token_endpoint", &self.token_endpoint)
            .field("client_id", &self.client_id)
            .field(
                "client_secret",
                &self.client_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("refresh_skew", &self.refresh_skew)
            .finish()
    }
}

#[derive(Debug)]
struct SessionState {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    sub: Option<String>,
    groups: Vec<String>,
}

impl SessionState {
    fn apply(&mut self, response: &TokenResponse) {
        self.access_token.clone_from(&response.access_token);
        self.expires_at = expires_at_from(response.expires_in);
        if let Some(id_token) = &response.id_token {
            self.id_token = Some(id_token.clone());
        }
        // Providers may rotate the refresh token; keep the old one
        // when the response omits a new one.
        if let Some(refresh_token) = &response.refresh_token {
            self.refresh_token = Some(refresh_token.clone());
        }
    }
}

/// Compute an absolute expiry instant from a relative
/// `expires_in` (seconds).
fn expires_at_from(expires_in: Option<i64>) -> Option<DateTime<Utc>> {
    expires_in
        .and_then(chrono::Duration::try_seconds)
        .map(|delta| Utc::now() + delta)
}

/// A live OIDC session with automatic, jittered token refresh.
pub struct OidcSession {
    token_client: TokenClient,
    config: SessionConfig,
    jitter: Duration,
    state: Mutex<SessionState>,
    /// Serializes refresh-token grants. Concurrent callers that
    /// all observe an about-to-expire token would otherwise each
    /// fire a parallel grant; with rotating refresh tokens
    /// (RFC 6749 §6) only the first would succeed and the rest
    /// would fail `invalid_grant`. Holding this async lock across
    /// the grant (and re-checking under it) collapses the herd
    /// into a single refresh. `state` is never held across the
    /// `.await`, so the synchronous `parking_lot` mutex is fine.
    refresh_lock: AsyncMutex<()>,
}

impl OidcSession {
    /// Start a session from the initial token response and the
    /// validated identity claims.
    ///
    /// `identity` supplies the `sub` + `groups` for ZTNA binding;
    /// pass [`None`] if the ID token was not retained (the session
    /// still manages access/refresh tokens, it just cannot emit an
    /// identity).
    #[must_use]
    pub fn start(
        token_client: TokenClient,
        config: SessionConfig,
        tokens: &TokenResponse,
        identity: Option<&IdTokenClaims>,
    ) -> Self {
        let state = SessionState {
            access_token: tokens.access_token.clone(),
            refresh_token: tokens.refresh_token.clone(),
            id_token: tokens.id_token.clone(),
            expires_at: expires_at_from(tokens.expires_in),
            sub: identity.map(|c| c.sub.clone()),
            groups: identity.map(|c| c.groups.clone()).unwrap_or_default(),
        };
        Self {
            token_client,
            jitter: random_jitter(config.refresh_skew),
            config,
            state: Mutex::new(state),
            refresh_lock: AsyncMutex::new(()),
        }
    }

    /// The subject identifier bound to this session, if known.
    #[must_use]
    pub fn sub(&self) -> Option<String> {
        self.state.lock().sub.clone()
    }

    /// The group / role membership bound to this session.
    #[must_use]
    pub fn groups(&self) -> Vec<String> {
        self.state.lock().groups.clone()
    }

    /// The current access-token expiry, if known.
    #[must_use]
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        self.state.lock().expires_at
    }

    /// Whether the access token is within the refresh window
    /// (skew + jitter) of expiry. Sessions with no known expiry
    /// never auto-refresh.
    #[must_use]
    pub fn needs_refresh(&self) -> bool {
        let expires_at = self.state.lock().expires_at;
        match expires_at {
            Some(expiry) => {
                let window = self.config.refresh_skew + self.jitter;
                let threshold = chrono::Duration::from_std(window)
                    .unwrap_or_else(|_| chrono::Duration::seconds(i64::MAX));
                Utc::now() + threshold >= expiry
            }
            None => false,
        }
    }

    /// Return a valid access token, refreshing first if the
    /// current one is within the refresh window.
    ///
    /// Refreshes are serialized: if several tasks call this at
    /// once they queue on [`Self::refresh_lock`], and each
    /// re-checks [`Self::needs_refresh`] after acquiring it, so a
    /// single grant satisfies the whole batch instead of each
    /// task firing its own.
    pub async fn access_token(&self) -> Result<String> {
        if self.needs_refresh() {
            let _guard = self.refresh_lock.lock().await;
            // Another task may have refreshed while we waited for
            // the guard; only refresh if it is still warranted.
            if self.needs_refresh() {
                self.refresh_locked().await?;
            }
        }
        Ok(self.state.lock().access_token.clone())
    }

    /// Force a refresh-token grant now, regardless of expiry.
    ///
    /// Takes the same [`Self::refresh_lock`] as the auto-refresh
    /// path, so a forced refresh never races a concurrent
    /// auto-refresh.
    pub async fn refresh(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_locked().await
    }

    /// Perform the refresh-token grant. The caller MUST already
    /// hold [`Self::refresh_lock`].
    async fn refresh_locked(&self) -> Result<()> {
        // Snapshot the refresh token and release the state lock
        // before the await — never hold the sync mutex across
        // `.await`.
        let refresh_token = {
            let state = self.state.lock();
            state.refresh_token.clone()
        };
        let Some(refresh_token) = refresh_token else {
            return Err(OidcError::Session(
                "auto-refresh requested but session holds no refresh token".to_owned(),
            ));
        };

        let request = RefreshRequest {
            client_id: self.config.client_id.clone(),
            refresh_token,
            scope: None,
            client_secret: self.config.client_secret.clone(),
        };
        let response = self
            .token_client
            .refresh(&self.config.token_endpoint, &request)
            .await?;

        self.state.lock().apply(&response);
        tracing::debug!(client_id = %self.config.client_id, "oidc session refreshed access token");
        Ok(())
    }

    /// Snapshot the current tokens for persistence through a
    /// [`TokenStorage`](crate::storage::TokenStorage).
    #[must_use]
    pub fn to_stored_tokens(&self) -> StoredTokens {
        let state = self.state.lock();
        StoredTokens {
            access_token: state.access_token.clone(),
            refresh_token: state.refresh_token.clone(),
            id_token: state.id_token.clone(),
            expires_at: state.expires_at.map(|dt| dt.timestamp()),
        }
    }
}

impl fmt::Debug for OidcSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.state.lock();
        f.debug_struct("OidcSession")
            .field("client_id", &self.config.client_id)
            .field("token_endpoint", &self.config.token_endpoint)
            .field("has_refresh_token", &state.refresh_token.is_some())
            .field("expires_at", &state.expires_at)
            .field("sub", &state.sub)
            .field("groups", &state.groups)
            .finish_non_exhaustive()
    }
}

/// Pick a random jitter in `[0, skew/2]` so concurrent sessions
/// do not all refresh on the same instant.
fn random_jitter(skew: Duration) -> Duration {
    let half_ms = u64::try_from(skew.as_millis() / 2).unwrap_or(u64::MAX);
    if half_ms == 0 {
        return Duration::ZERO;
    }
    let mut rng = OsRng;
    Duration::from_millis(rng.next_u64() % (half_ms + 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn token_response(expires_in: Option<i64>, refresh: Option<&str>) -> TokenResponse {
        TokenResponse {
            access_token: "at-1".to_owned(),
            token_type: "Bearer".to_owned(),
            id_token: None,
            refresh_token: refresh.map(ToOwned::to_owned),
            expires_in,
            scope: None,
        }
    }

    fn identity() -> IdTokenClaims {
        serde_json::from_value(serde_json::json!({
            "iss": "https://idp.example.com",
            "sub": "user-7",
            "aud": "client-1",
            "exp": 0,
            "groups": ["eng", "sec"]
        }))
        .unwrap()
    }

    fn session(expires_in: Option<i64>, refresh: Option<&str>) -> OidcSession {
        let client = TokenClient::new().expect("client builds");
        let config = SessionConfig::new("https://idp.example.com/token", "client-1");
        OidcSession::start(
            client,
            config,
            &token_response(expires_in, refresh),
            Some(&identity()),
        )
    }

    #[test]
    fn binds_identity_for_ztna() {
        let s = session(Some(3600), Some("rt"));
        assert_eq!(s.sub().as_deref(), Some("user-7"));
        assert_eq!(s.groups(), vec!["eng".to_owned(), "sec".to_owned()]);
    }

    #[test]
    fn fresh_token_does_not_need_refresh() {
        let s = session(Some(3600), Some("rt"));
        assert!(!s.needs_refresh());
    }

    #[test]
    fn expired_token_needs_refresh() {
        let s = session(Some(-10), Some("rt"));
        assert!(s.needs_refresh());
    }

    #[test]
    fn session_without_expiry_never_auto_refreshes() {
        let s = session(None, Some("rt"));
        assert!(!s.needs_refresh());
    }

    #[tokio::test]
    async fn access_token_without_refresh_token_errors_when_expired() {
        let s = session(Some(-10), None);
        let err = s.access_token().await.unwrap_err();
        assert!(matches!(err, OidcError::Session(_)));
    }

    #[test]
    fn stored_tokens_snapshot_roundtrips_expiry() {
        let s = session(Some(3600), Some("rt"));
        let stored = s.to_stored_tokens();
        assert_eq!(stored.access_token, "at-1");
        assert_eq!(stored.refresh_token.as_deref(), Some("rt"));
        assert!(stored.expires_at.is_some());
    }

    #[test]
    fn debug_does_not_leak_tokens() {
        let s = session(Some(3600), Some("super-secret-rt"));
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("super-secret-rt"));
        assert!(!rendered.contains("at-1"));
    }
}

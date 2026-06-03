//! OIDC auth-session trait surface + token-lifecycle types.
//!
//! The mobile agent core does **not** implement an OIDC client
//! itself — the concrete authorization-code-with-PKCE + refresh
//! implementation lives in the dedicated `sng-oidc` crate (built in
//! parallel, integrated in a later session). This module defines:
//!
//! * the [`AuthSession`] trait the agent depends on (and `sng-oidc`
//!   / the PAL will implement),
//! * the [`TokenStorage`] trait the auth layer delegates secure
//!   persistence to (iOS Keychain / Android EncryptedSharedPrefs),
//! * the token-lifecycle value types ([`TokenSet`], [`AccessToken`],
//!   …) — all of which **zeroize their secret material on drop** so
//!   a heap snapshot cannot recover a bearer token after it falls
//!   out of scope, and
//! * the pure [`refresh_delay`] scheduler that spreads refreshes
//!   with jitter so a fleet does not stampede the IdP token
//!   endpoint.
//!
//! A working in-memory [`InMemoryTokenStorage`] is provided as a
//! reference implementation for host-app development and tests; the
//! production PAL backs [`TokenStorage`] with the platform secure
//! enclave.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::config::AuthConfig;

/// A bearer access token. Wraps the secret in a buffer that is
/// wiped on drop; [`fmt::Debug`] is redacted so the token never
/// lands in a log line.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AccessToken(String);

/// An OIDC refresh token. Same zeroize-on-drop / redacted-debug
/// posture as [`AccessToken`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RefreshToken(String);

/// An OIDC ID token (JWT). Same zeroize-on-drop / redacted-debug
/// posture as [`AccessToken`].
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdToken(String);

macro_rules! secret_token {
    ($name:ident) => {
        impl $name {
            /// Wrap a raw secret string.
            #[must_use]
            pub fn new(raw: impl Into<String>) -> Self {
                Self(raw.into())
            }

            /// Borrow the underlying secret. Call this only at the
            /// point of use (e.g. building the `Authorization`
            /// header) so the secret's lifetime stays as short as
            /// possible.
            #[must_use]
            pub fn expose_secret(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(***redacted***)"))
            }
        }
    };
}

secret_token!(AccessToken);
secret_token!(RefreshToken);
secret_token!(IdToken);

/// A full set of OIDC tokens plus the metadata the refresh
/// scheduler needs. The secret members self-zeroize on drop; the
/// non-secret metadata (`expires_at`, `scopes`, `token_type`) does
/// not need wiping.
#[derive(Clone)]
pub struct TokenSet {
    /// Short-lived access token presented to resource servers.
    pub access_token: AccessToken,
    /// Long-lived refresh token, if the IdP issued one
    /// (`offline_access` scope). Absent for implicit / device
    /// flows that do not grant refresh.
    pub refresh_token: Option<RefreshToken>,
    /// ID token (JWT) carrying the authenticated subject claims.
    pub id_token: Option<IdToken>,
    /// Absolute expiry of [`Self::access_token`].
    pub expires_at: DateTime<Utc>,
    /// Token type as returned by the IdP (typically `Bearer`).
    pub token_type: String,
    /// Scopes actually granted (may be a subset of those asked).
    pub scopes: Vec<String>,
}

impl TokenSet {
    /// Whether the access token is expired (or will be within
    /// `skew`) as of `now`.
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>, skew: Duration) -> bool {
        let skew = chrono::Duration::from_std(skew).unwrap_or_else(|_| chrono::Duration::zero());
        now + skew >= self.expires_at
    }
}

impl fmt::Debug for TokenSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenSet")
            .field("access_token", &self.access_token)
            .field("refresh_token", &self.refresh_token)
            .field("id_token", &self.id_token)
            .field("expires_at", &self.expires_at)
            .field("token_type", &self.token_type)
            .field("scopes", &self.scopes)
            .finish()
    }
}

/// Coarse, secret-free snapshot of an [`AuthSession`]'s state,
/// suitable for health reporting and telemetry (it carries no
/// token material).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthState {
    /// No usable credential is held; the user must authenticate.
    Unauthenticated,
    /// A valid access token is held, expiring at the given instant.
    Authenticated {
        /// Absolute expiry of the held access token.
        expires_at: DateTime<Utc>,
    },
    /// The access token has expired but a refresh may recover it.
    Expired,
    /// A refresh is in flight.
    Refreshing,
}

impl AuthState {
    /// Whether the session currently holds a usable access token.
    #[must_use]
    pub fn is_authenticated(self) -> bool {
        matches!(self, Self::Authenticated { .. })
    }
}

/// Failure modes of the [`AuthSession`] surface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No credential held and none could be acquired silently —
    /// the host app must drive an interactive sign-in.
    #[error("not authenticated")]
    Unauthenticated,
    /// A refresh was requested but no refresh token is held.
    #[error("no refresh token; interactive re-authentication required")]
    MissingRefreshToken,
    /// The IdP token endpoint rejected the refresh grant.
    #[error("refresh rejected: {0}")]
    RefreshRejected(String),
    /// Persisting / loading the token set failed.
    #[error(transparent)]
    Storage(#[from] TokenStorageError),
    /// Any other provider-side failure (network, discovery, …).
    #[error("auth provider: {0}")]
    Provider(String),
}

/// Failure modes of the [`TokenStorage`] surface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenStorageError {
    /// The underlying secure store rejected the operation.
    #[error("token storage backend: {0}")]
    Backend(String),
    /// A stored token blob could not be decoded back into a
    /// [`TokenSet`].
    #[error("stored token is corrupt: {0}")]
    Corrupt(String),
}

/// Secure persistence for the OIDC [`TokenSet`].
///
/// Object-safe so the agent holds it as `Arc<dyn TokenStorage>`.
/// The PAL implements it over the platform secure enclave (iOS
/// Keychain with `kSecAttrAccessibleAfterFirstUnlock`, Android
/// `EncryptedSharedPreferences` / Keystore-wrapped blob).
#[async_trait]
pub trait TokenStorage: Send + Sync {
    /// Load the persisted token set, or `None` if the device has
    /// never authenticated.
    async fn load(&self) -> Result<Option<TokenSet>, TokenStorageError>;
    /// Persist `tokens`, replacing any previously stored set.
    async fn store(&self, tokens: &TokenSet) -> Result<(), TokenStorageError>;
    /// Remove any persisted token set (sign-out / de-enrolment).
    async fn clear(&self) -> Result<(), TokenStorageError>;
}

/// The authenticated OIDC session the agent depends on.
///
/// Object-safe so the agent holds it as `Arc<dyn AuthSession>`.
/// The concrete implementation (`sng-oidc`, integrated later) owns
/// the refresh loop, PKCE exchange, and discovery; the agent only
/// ever asks it for a currently-valid token.
#[async_trait]
pub trait AuthSession: Send + Sync {
    /// Return a currently-valid access token, performing a silent
    /// refresh first if the held token is expired. Returns
    /// [`AuthError::Unauthenticated`] if no token can be produced
    /// without interactive sign-in.
    async fn access_token(&self) -> Result<AccessToken, AuthError>;
    /// Force a refresh of the access token using the held refresh
    /// token, regardless of current expiry.
    async fn refresh(&self) -> Result<(), AuthError>;
    /// Current secret-free state snapshot for health / telemetry.
    fn state(&self) -> AuthState;
    /// Whether a usable access token is currently held.
    fn is_authenticated(&self) -> bool;
}

/// Compute the delay until the next proactive token refresh.
///
/// The refresh is scheduled `skew` *before* the token's real
/// expiry so an in-flight request never races the expiry boundary,
/// then a deterministic share of `jitter` (selected by
/// `jitter_permille`, parts-per-thousand in `0..=1000`) is added so
/// a fleet that all refreshed in the same MDM-push window spreads
/// its next refresh across a `jitter`-wide window instead of
/// hammering the IdP simultaneously.
///
/// Kept pure (jitter injected rather than drawn internally) so it
/// is exhaustively unit-testable; [`schedule_refresh`] is the
/// randomized wrapper the agent actually calls.
#[must_use]
pub fn refresh_delay(
    now: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    skew: Duration,
    jitter: Duration,
    jitter_permille: u32,
) -> Duration {
    let skew = chrono::Duration::from_std(skew).unwrap_or_else(|_| chrono::Duration::zero());
    let target = expires_at - skew;
    let base_ms = (target - now).num_milliseconds().max(0).unsigned_abs();
    let permille = u128::from(jitter_permille.min(1000));
    let jitter_ms = jitter.as_millis().saturating_mul(permille) / 1000;
    let total_ms = u128::from(base_ms).saturating_add(jitter_ms);
    Duration::from_millis(u64::try_from(total_ms).unwrap_or(u64::MAX))
}

/// Randomized wrapper around [`refresh_delay`] that draws the
/// jitter share from the thread RNG. This is the scheduler the
/// agent's auth-refresh timer uses.
#[must_use]
pub fn schedule_refresh(now: DateTime<Utc>, expires_at: DateTime<Utc>, cfg: &AuthConfig) -> Duration {
    use rand::Rng;
    let permille = rand::thread_rng().gen_range(0..=1000);
    refresh_delay(now, expires_at, cfg.refresh_skew, cfg.refresh_jitter, permille)
}

/// In-memory [`TokenStorage`] reference implementation.
///
/// Holds the token set behind a [`Mutex`]; suitable for host-app
/// development, tests, and as a worked example for PAL teams. **Not**
/// for production — it does not persist across process restarts and
/// keeps tokens in plain process memory (the production PAL backs
/// the trait with the platform secure enclave).
#[derive(Debug, Default)]
pub struct InMemoryTokenStorage {
    inner: Mutex<Option<TokenSet>>,
}

impl InMemoryTokenStorage {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TokenStorage for InMemoryTokenStorage {
    async fn load(&self) -> Result<Option<TokenSet>, TokenStorageError> {
        Ok(self.inner.lock().clone())
    }

    async fn store(&self, tokens: &TokenSet) -> Result<(), TokenStorageError> {
        *self.inner.lock() = Some(tokens.clone());
        Ok(())
    }

    async fn clear(&self) -> Result<(), TokenStorageError> {
        *self.inner.lock() = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn token_set(expires_at: DateTime<Utc>) -> TokenSet {
        TokenSet {
            access_token: AccessToken::new("access-secret"),
            refresh_token: Some(RefreshToken::new("refresh-secret")),
            id_token: Some(IdToken::new("id-secret")),
            expires_at,
            token_type: "Bearer".into(),
            scopes: vec!["openid".into()],
        }
    }

    #[test]
    fn debug_redacts_secret() {
        let t = AccessToken::new("super-secret-value");
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("super-secret-value"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn token_set_debug_redacts_secrets() {
        let t = token_set(Utc::now());
        let rendered = format!("{t:?}");
        assert!(!rendered.contains("access-secret"));
        assert!(!rendered.contains("refresh-secret"));
    }

    #[test]
    fn expiry_respects_skew() {
        let now = Utc::now();
        let t = token_set(now + chrono::Duration::seconds(30));
        assert!(!t.is_expired(now, Duration::from_secs(10)));
        // With a 40s skew the 30s-out token is already "expired".
        assert!(t.is_expired(now, Duration::from_secs(40)));
    }

    #[test]
    fn refresh_delay_subtracts_skew() {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(300);
        let d = refresh_delay(now, expires_at, Duration::from_secs(60), Duration::ZERO, 0);
        assert_eq!(d, Duration::from_secs(240));
    }

    #[test]
    fn refresh_delay_adds_jitter_share() {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(300);
        let d = refresh_delay(
            now,
            expires_at,
            Duration::from_secs(60),
            Duration::from_secs(40),
            500,
        );
        // 240s base + 50% of 40s jitter = 260s.
        assert_eq!(d, Duration::from_secs(260));
    }

    #[test]
    fn refresh_delay_floors_at_zero_when_already_expired() {
        let now = Utc::now();
        let expires_at = now - chrono::Duration::seconds(10);
        let d = refresh_delay(now, expires_at, Duration::from_secs(60), Duration::ZERO, 0);
        assert_eq!(d, Duration::ZERO);
    }

    #[tokio::test]
    async fn in_memory_storage_roundtrips() {
        let store = InMemoryTokenStorage::new();
        assert!(store.load().await.unwrap().is_none());

        let t = token_set(Utc::now());
        store.store(&t).await.unwrap();
        let loaded = store.load().await.unwrap().expect("token present");
        assert_eq!(loaded.access_token.expose_secret(), "access-secret");

        store.clear().await.unwrap();
        assert!(store.load().await.unwrap().is_none());
    }
}

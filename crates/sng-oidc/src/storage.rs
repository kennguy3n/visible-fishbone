//! Token persistence abstraction.
//!
//! [`TokenStorage`] is the contract a platform keystore (iOS
//! Keychain, Android Keystore-wrapped storage, or a test
//! in-memory map) implements so the OIDC client can persist a
//! user's tokens across process restarts without knowing how the
//! platform secures them. The crate ships an in-memory
//! [`MemoryTokenStorage`] for tests and host runs.

use std::collections::HashMap;
use std::fmt;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors a [`TokenStorage`] implementation may return.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The backing keystore was unavailable (locked device, IPC
    /// failure, etc.).
    #[error("token storage backend unavailable: {0}")]
    Backend(String),
    /// Stored bytes could not be (de)serialized.
    #[error("token storage (de)serialization failed: {0}")]
    Serde(String),
}

/// A persisted token bundle for one identity.
///
/// `expires_at` is stored as a Unix timestamp (seconds) so the
/// representation is platform- and timezone-independent. The
/// access / refresh / id tokens are secrets; the custom
/// [`fmt::Debug`] redacts them.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredTokens {
    /// The OAuth2 access token.
    pub access_token: String,
    /// The refresh token, if one was granted.
    pub refresh_token: Option<String>,
    /// The most recent ID token, if retained.
    pub id_token: Option<String>,
    /// Access-token expiry as a Unix timestamp (seconds).
    pub expires_at: Option<i64>,
}

impl fmt::Debug for StoredTokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredTokens")
            .field("access_token", &"<redacted>")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "<redacted>"),
            )
            .field("id_token", &self.id_token.as_ref().map(|_| "<redacted>"))
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Persistence contract for OIDC tokens.
///
/// Implementations are injected by the platform PAL and delegate
/// to the OS keystore. The trait is object-safe so it can be held
/// as `Arc<dyn TokenStorage>`.
#[async_trait]
pub trait TokenStorage: Send + Sync + fmt::Debug {
    /// Persist `tokens` under `key` (typically the issuer + `sub`
    /// or the account identifier), overwriting any prior value.
    async fn store(&self, key: &str, tokens: &StoredTokens) -> Result<(), StorageError>;

    /// Retrieve the tokens stored under `key`, or [`None`] if
    /// absent.
    async fn retrieve(&self, key: &str) -> Result<Option<StoredTokens>, StorageError>;

    /// Delete any tokens stored under `key` (idempotent).
    async fn delete(&self, key: &str) -> Result<(), StorageError>;
}

/// An in-memory [`TokenStorage`] for tests and host runs.
///
/// Not suitable for production: tokens live only in process
/// memory and are not encrypted at rest.
#[derive(Debug, Default)]
pub struct MemoryTokenStorage {
    inner: Mutex<HashMap<String, StoredTokens>>,
}

impl MemoryTokenStorage {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TokenStorage for MemoryTokenStorage {
    async fn store(&self, key: &str, tokens: &StoredTokens) -> Result<(), StorageError> {
        self.inner.lock().insert(key.to_owned(), tokens.clone());
        Ok(())
    }

    async fn retrieve(&self, key: &str) -> Result<Option<StoredTokens>, StorageError> {
        Ok(self.inner.lock().get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.inner.lock().remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn sample() -> StoredTokens {
        StoredTokens {
            access_token: "at".to_owned(),
            refresh_token: Some("rt".to_owned()),
            id_token: Some("idt".to_owned()),
            expires_at: Some(1_700_000_000),
        }
    }

    #[tokio::test]
    async fn store_retrieve_delete_roundtrip() {
        let store = MemoryTokenStorage::new();
        assert!(store.retrieve("k").await.unwrap().is_none());

        store.store("k", &sample()).await.unwrap();
        let got = store.retrieve("k").await.unwrap().unwrap();
        assert_eq!(got.access_token, "at");
        assert_eq!(got.refresh_token.as_deref(), Some("rt"));

        store.delete("k").await.unwrap();
        assert!(store.retrieve("k").await.unwrap().is_none());
    }

    #[test]
    fn debug_redacts_tokens() {
        let rendered = format!("{:?}", sample());
        assert!(!rendered.contains("\"at\""));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn stored_tokens_serde_roundtrip() {
        let json = serde_json::to_string(&sample()).unwrap();
        let back: StoredTokens = serde_json::from_str(&json).unwrap();
        assert_eq!(back.access_token, "at");
        assert_eq!(back.expires_at, Some(1_700_000_000));
    }
}

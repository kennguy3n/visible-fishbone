//! Device-bound secure key storage.
//!
//! Every SNG endpoint binds an Ed25519 keypair to the device's
//! secure element (TPM 2.0 on Windows, Secure Enclave on macOS,
//! kernel keyring + TPM on Linux). The private key is generated
//! inside the secure element and never leaves it; signing
//! operations call into the element. This trait defines the
//! cross-OS surface; per-OS implementations land in PR 10 when
//! `sng-ztna` consumes them.
//!
//! For PR 2 we ship the trait + an in-memory backend used by
//! the rest of the workspace's tests (e.g. policy verification,
//! enrolment-flow integration tests). The in-memory backend is
//! gated behind a `dev-` feature so it can never accidentally
//! ship into a production binary.

use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// Opaque handle to a key inside the secure element.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyHandle(pub String);

/// Keystore error.
#[derive(Debug, Error)]
pub enum KeyStoreError {
    /// Backend not available on this OS / build.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// No key matches the supplied handle.
    #[error("unknown key: {0}")]
    UnknownKey(String),
    /// The signing operation failed inside the secure element.
    #[error("sign: {0}")]
    Sign(String),
    /// Key-generation failure.
    #[error("generate: {0}")]
    Generate(String),
}

/// Secure-element-backed Ed25519 signing surface.
#[async_trait]
pub trait SecureKeyStore: Send + Sync {
    /// Generate a fresh Ed25519 keypair, return its handle.
    async fn generate_ed25519(&self) -> Result<KeyHandle, KeyStoreError>;

    /// Return the 32-byte Ed25519 public key matching `handle`.
    async fn public_key(&self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError>;

    /// Sign `message` with the key behind `handle`. Returns the
    /// 64-byte Ed25519 signature.
    async fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<[u8; 64], KeyStoreError>;
}

/// In-memory keystore. Keys live in process memory only — never
/// use this in a production binary. The struct is private to
/// tests in the dependent crates and the few enrolment fixtures
/// in this workspace.
#[derive(Clone, Default)]
pub struct InMemoryKeyStore {
    inner: Arc<Mutex<HashMap<KeyHandle, SigningKey>>>,
}

impl std::fmt::Debug for InMemoryKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Don't dump the keys.
        f.debug_struct("InMemoryKeyStore").finish()
    }
}

impl InMemoryKeyStore {
    /// Construct an empty keystore.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a known signing key under a specific handle. Used
    /// by tests that need to reproduce a fixed key value (e.g.
    /// to assert that signatures match a Go-side fixture).
    pub async fn insert(&self, handle: KeyHandle, key: SigningKey) {
        self.inner.lock().await.insert(handle, key);
    }

    /// Convenience accessor — return the verifying key matching
    /// a stored signing key.
    pub async fn verifying_key(&self, handle: &KeyHandle) -> Option<VerifyingKey> {
        self.inner
            .lock()
            .await
            .get(handle)
            .map(SigningKey::verifying_key)
    }
}

#[async_trait]
impl SecureKeyStore for InMemoryKeyStore {
    async fn generate_ed25519(&self) -> Result<KeyHandle, KeyStoreError> {
        // The in-memory backend uses OsRng so the keys are
        // genuinely random; this keeps the dev experience close
        // to the production secure-element path.
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let handle = KeyHandle(uuid::Uuid::new_v4().to_string());
        self.inner.lock().await.insert(handle.clone(), key);
        Ok(handle)
    }

    async fn public_key(&self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
        let map = self.inner.lock().await;
        let key = map
            .get(handle)
            .ok_or_else(|| KeyStoreError::UnknownKey(handle.0.clone()))?;
        Ok(key.verifying_key().to_bytes())
    }

    async fn sign(&self, handle: &KeyHandle, message: &[u8]) -> Result<[u8; 64], KeyStoreError> {
        let map = self.inner.lock().await;
        let key = map
            .get(handle)
            .ok_or_else(|| KeyStoreError::UnknownKey(handle.0.clone()))?;
        Ok(key.sign(message).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[tokio::test]
    async fn signs_and_verifies_round_trip() {
        let ks = InMemoryKeyStore::new();
        let h = ks.generate_ed25519().await.expect("gen");
        let pub_bytes = ks.public_key(&h).await.expect("pub");
        let pubkey = VerifyingKey::from_bytes(&pub_bytes).expect("parse");
        let msg = b"hello SNG";
        let sig_bytes = ks.sign(&h, msg).await.expect("sign");
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        pubkey.verify(msg, &sig).expect("verify");
    }

    #[tokio::test]
    async fn unknown_handle_errors() {
        let ks = InMemoryKeyStore::new();
        let err = ks
            .public_key(&KeyHandle("nope".into()))
            .await
            .expect_err("err");
        assert!(matches!(err, KeyStoreError::UnknownKey(_)));
    }

    #[tokio::test]
    async fn insert_lets_tests_pin_a_known_key() {
        let ks = InMemoryKeyStore::new();
        let key = SigningKey::from_bytes(&[42_u8; 32]);
        let handle = KeyHandle("fixture".into());
        ks.insert(handle.clone(), key.clone()).await;
        let pub_bytes = ks.public_key(&handle).await.expect("pub");
        assert_eq!(pub_bytes, key.verifying_key().to_bytes());
    }
}

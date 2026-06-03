// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! [`IosSecureKeyStore`] — the iOS [`SecureKeyStore`] backend.
//!
//! ## Design: Ed25519 in the Keychain (not the Secure Enclave)
//!
//! The control plane's enrolment protocol expects an **Ed25519**
//! device key (it returns an Ed25519 [`VerifyingKey`] and verifies
//! Ed25519 [`Signature`]s — see `sng_mobile_core::enrollment`). The
//! Apple Secure Enclave only generates / holds **NIST P-256** keys, so
//! it cannot natively store the Ed25519 enrolment key the core mandates.
//!
//! We therefore keep the key type the core expects and protect it the
//! next-strongest way iOS offers: the 32-byte Ed25519 seed is stored as
//! a **Keychain** generic-password item with a [`SecAccessControl`]
//! built from
//! [`ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly`]. That
//! gives a non-exportable, this-device-only, after-first-unlock item —
//! the same posture `sng-agent` documents for desktop key material —
//! without silently changing the key type to P-256.
//!
//! The Ed25519 maths (seed → verifying key, signing) is platform
//! independent and is exercised by the host unit tests; only the
//! Keychain persistence is `#[cfg(target_os = "ios")]`. The host
//! fallback returns [`KeyStoreError::Backend`] carrying an
//! [`IosPalError::UnsupportedPlatform`].

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use sng_mobile_core::{KeyStoreError, SecureKeyStore};

/// Keychain service (`kSecAttrService`) under which every SNG device
/// key is filed. The per-key `label` becomes the item's account
/// (`kSecAttrAccount`).
pub const KEYCHAIN_SERVICE: &str = "com.shieldnet.sng.mobile.keystore";

/// iOS [`SecureKeyStore`] backed by the Keychain.
///
/// Holds only the (non-secret) service name; the secret seeds live in
/// the Keychain, never in this struct. Cheap to clone and safe to share
/// as `Arc<dyn SecureKeyStore>`.
#[derive(Debug, Clone)]
pub struct IosSecureKeyStore {
    service: String,
}

impl Default for IosSecureKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl IosSecureKeyStore {
    /// Construct a store filing keys under [`KEYCHAIN_SERVICE`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_owned(),
        }
    }

    /// Construct a store filing keys under a custom Keychain service
    /// (useful to namespace per-tenant or in host integration tests).
    #[must_use]
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// The Keychain service this store files items under.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

/// Zeroize-on-drop wrapper around a 32-byte Ed25519 seed.
///
/// Compiled on iOS (where the Keychain backend uses it) and under
/// `test` (where the host tests exercise the platform-independent
/// Ed25519 maths). The plain Linux library build needs none of it, so
/// it is gated out there to keep the `-D warnings` build free of
/// dead-code.
#[cfg(any(target_os = "ios", test))]
mod seed {
    use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
    use zeroize::Zeroizing;

    use crate::error::IosPalError;

    /// Length of an Ed25519 seed / `SigningKey` in bytes.
    pub(crate) const SEED_LEN: usize = 32;

    /// A 32-byte Ed25519 seed whose buffer is wiped on drop.
    pub(crate) struct KeySeed(Zeroizing<[u8; SEED_LEN]>);

    impl KeySeed {
        /// Generate a fresh seed from the OS CSPRNG.
        pub(crate) fn generate() -> Self {
            let signing_key = SigningKey::generate(&mut rand_core::OsRng);
            Self(Zeroizing::new(signing_key.to_bytes()))
        }

        /// Reconstruct a seed from raw Keychain bytes, validating the
        /// length so a corrupt / truncated item is a typed error
        /// rather than a panic.
        pub(crate) fn from_slice(raw: &[u8]) -> Result<Self, IosPalError> {
            let bytes: [u8; SEED_LEN] = raw.try_into().map_err(|_| {
                IosPalError::Key(format!(
                    "device key seed must be {SEED_LEN} bytes, found {}",
                    raw.len()
                ))
            })?;
            Ok(Self(Zeroizing::new(bytes)))
        }

        /// Borrow the raw seed bytes for handing to the Keychain.
        pub(crate) fn expose(&self) -> &[u8; SEED_LEN] {
            &self.0
        }

        fn signing_key(&self) -> SigningKey {
            SigningKey::from_bytes(&self.0)
        }

        /// The public half of the keypair.
        pub(crate) fn verifying_key(&self) -> VerifyingKey {
            self.signing_key().verifying_key()
        }

        /// Sign `message` with the seed's private key.
        pub(crate) fn sign(&self, message: &[u8]) -> Signature {
            self.signing_key().sign(message)
        }
    }
}

// ---------------------------------------------------------------------
// iOS backend
// ---------------------------------------------------------------------
#[cfg(target_os = "ios")]
mod keychain {
    use super::seed::KeySeed;
    use crate::error::IosPalError;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    /// `errSecItemNotFound`; spelled out so we need no extra
    /// `security-framework-sys` dependency just for one constant.
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    fn options(service: &str, account: &str) -> PasswordOptions {
        PasswordOptions::new_generic_password(service, account)
    }

    /// Persist `seed` under `service`/`account`, creating or replacing
    /// the item, protected this-device-only after first unlock.
    pub(super) fn store(service: &str, account: &str, seed: &KeySeed) -> Result<(), IosPalError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(|e| IosPalError::Keychain(format!("access-control: {e}")))?;
        let mut opts = options(service, account);
        opts.set_access_control(access);
        set_generic_password_options(seed.expose(), opts)
            .map_err(|e| IosPalError::Keychain(e.to_string()))
    }

    /// Load the seed under `service`/`account`, or `None` if absent.
    pub(super) fn load(service: &str, account: &str) -> Result<Option<KeySeed>, IosPalError> {
        match generic_password(options(service, account)) {
            Ok(bytes) => Ok(Some(KeySeed::from_slice(&bytes)?)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(IosPalError::Keychain(e.to_string())),
        }
    }

    /// Delete the item, treating "already absent" as success
    /// (idempotent de-enrolment).
    pub(super) fn delete(service: &str, account: &str) -> Result<(), IosPalError> {
        match delete_generic_password(service, account) {
            Ok(()) => Ok(()),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(e) => Err(IosPalError::Keychain(e.to_string())),
        }
    }
}

#[cfg(target_os = "ios")]
#[async_trait]
impl SecureKeyStore for IosSecureKeyStore {
    async fn generate_keypair(&self, label: &str) -> Result<VerifyingKey, KeyStoreError> {
        if keychain::load(&self.service, label)?.is_some() {
            return Err(KeyStoreError::AlreadyExists(label.to_owned()));
        }
        let seed = seed::KeySeed::generate();
        let verifying_key = seed.verifying_key();
        keychain::store(&self.service, label, &seed)?;
        Ok(verifying_key)
    }

    async fn public_key(&self, label: &str) -> Result<VerifyingKey, KeyStoreError> {
        let seed = keychain::load(&self.service, label)?
            .ok_or_else(|| KeyStoreError::NotFound(label.to_owned()))?;
        Ok(seed.verifying_key())
    }

    async fn sign(&self, label: &str, message: &[u8]) -> Result<Signature, KeyStoreError> {
        let seed = keychain::load(&self.service, label)?
            .ok_or_else(|| KeyStoreError::NotFound(label.to_owned()))?;
        Ok(seed.sign(message))
    }

    async fn contains(&self, label: &str) -> Result<bool, KeyStoreError> {
        Ok(keychain::load(&self.service, label)?.is_some())
    }

    async fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        keychain::delete(&self.service, label)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Host fallback (Linux CI / desktop dev): typed "unsupported".
// ---------------------------------------------------------------------
#[cfg(not(target_os = "ios"))]
#[async_trait]
impl SecureKeyStore for IosSecureKeyStore {
    async fn generate_keypair(&self, _label: &str) -> Result<VerifyingKey, KeyStoreError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("generate_keypair".into()).into())
    }

    async fn public_key(&self, _label: &str) -> Result<VerifyingKey, KeyStoreError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("public_key".into()).into())
    }

    async fn sign(&self, _label: &str, _message: &[u8]) -> Result<Signature, KeyStoreError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("sign".into()).into())
    }

    async fn contains(&self, _label: &str) -> Result<bool, KeyStoreError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("contains".into()).into())
    }

    async fn delete(&self, _label: &str) -> Result<(), KeyStoreError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("delete".into()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::seed::{KeySeed, SEED_LEN};
    use super::*;
    use ed25519_dalek::Verifier;
    use pretty_assertions::assert_eq;

    #[test]
    fn seed_roundtrips_through_keychain_bytes() {
        let seed = KeySeed::generate();
        let bytes = *seed.expose();
        let restored = KeySeed::from_slice(&bytes).unwrap();
        // Same seed => same public key.
        assert_eq!(
            seed.verifying_key().to_bytes(),
            restored.verifying_key().to_bytes()
        );
    }

    #[test]
    fn generated_key_signs_and_verifies() {
        let seed = KeySeed::generate();
        let vk = seed.verifying_key();
        let msg = b"enrolment-challenge";
        let sig = seed.sign(msg);
        assert!(vk.verify(msg, &sig).is_ok());
        // A different message must not verify against the signature.
        assert!(vk.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn from_slice_rejects_wrong_length() {
        let result = KeySeed::from_slice(&[0u8; SEED_LEN - 1]);
        assert!(result.is_err());
        let msg = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("must be 32 bytes"));
        assert!(KeySeed::from_slice(&[0u8; SEED_LEN]).is_ok());
    }

    #[test]
    fn default_store_uses_documented_service() {
        assert_eq!(IosSecureKeyStore::new().service(), KEYCHAIN_SERVICE);
        assert_eq!(IosSecureKeyStore::default().service(), KEYCHAIN_SERVICE);
        assert_eq!(
            IosSecureKeyStore::with_service("custom.svc").service(),
            "custom.svc"
        );
    }

    // On the Linux CI host the trait is the typed-unsupported fallback.
    #[cfg(not(target_os = "ios"))]
    #[tokio::test]
    async fn host_fallback_is_unsupported_not_panic() {
        let store = IosSecureKeyStore::new();
        assert!(matches!(
            store.generate_keypair("l").await,
            Err(KeyStoreError::Backend(_))
        ));
        assert!(matches!(
            store.public_key("l").await,
            Err(KeyStoreError::Backend(_))
        ));
        assert!(matches!(
            store.sign("l", b"m").await,
            Err(KeyStoreError::Backend(_))
        ));
        assert!(matches!(
            store.contains("l").await,
            Err(KeyStoreError::Backend(_))
        ));
        assert!(matches!(
            store.delete("l").await,
            Err(KeyStoreError::Backend(_))
        ));
    }
}

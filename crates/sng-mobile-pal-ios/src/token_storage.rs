// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! [`IosTokenStorage`] — the iOS [`TokenStorage`] backend.
//!
//! The OIDC [`TokenSet`] is persisted as a single JSON blob in a
//! Keychain generic-password item, protected
//! this-device-only-after-first-unlock (the same posture as the device
//! key in [`crate::keystore`]). [`TokenSet`]'s secret members
//! (`access_token`, `refresh_token`, `id_token`) are zeroize-on-drop
//! and deliberately do **not** derive `Serialize`, so the
//! platform-independent [`StoredTokenSet`] DTO below mediates between
//! the in-memory [`TokenSet`] and the on-disk JSON. The transient
//! serialized buffer is wiped after the Keychain write.
//!
//! Both the JSON (de)serialization round-trip and its conversions are
//! exercised by host unit tests; only the Keychain I/O is
//! `#[cfg(target_os = "ios")]`. The host fallback returns
//! [`TokenStorageError::Backend`] carrying an
//! [`IosPalError::UnsupportedPlatform`].

use async_trait::async_trait;
use sng_mobile_core::{TokenSet, TokenStorage, TokenStorageError};

/// Keychain service under which the OIDC token set is filed.
pub const KEYCHAIN_SERVICE: &str = "com.shieldnet.sng.mobile.tokens";

/// Keychain account (there is a single token set per app install).
pub const KEYCHAIN_ACCOUNT: &str = "oidc.token-set";

/// iOS [`TokenStorage`] backed by the Keychain.
#[derive(Debug, Clone)]
pub struct IosTokenStorage {
    service: String,
    // Read only by the iOS Keychain path; the host fallback returns
    // `Unsupported` before touching it.
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    account: String,
}

impl Default for IosTokenStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl IosTokenStorage {
    /// Construct a storage filing the token set under the documented
    /// [`KEYCHAIN_SERVICE`] / [`KEYCHAIN_ACCOUNT`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            service: KEYCHAIN_SERVICE.to_owned(),
            account: KEYCHAIN_ACCOUNT.to_owned(),
        }
    }

    /// Construct a storage with a custom Keychain service / account
    /// (useful to namespace per-tenant or in host integration tests).
    #[must_use]
    pub fn with_keychain(service: impl Into<String>, account: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            account: account.into(),
        }
    }

    /// The Keychain service this storage files the token set under.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }
}

/// Platform-independent JSON (de)serialization of a [`TokenSet`].
///
/// Compiled on iOS (used by the Keychain backend) and under `test`
/// (exercised by the host round-trip tests); gated out of the plain
/// Linux library build to keep `-D warnings` free of dead-code.
#[cfg(any(target_os = "ios", test))]
mod codec {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use sng_mobile_core::{AccessToken, IdToken, RefreshToken, TokenSet};
    use zeroize::Zeroizing;

    use crate::error::IosPalError;

    /// Serializable mirror of [`TokenSet`]. Exists only transiently
    /// while (de)serializing; the long-lived secrets stay in the
    /// zeroize-on-drop [`TokenSet`] wrappers.
    #[derive(Serialize, Deserialize)]
    pub(super) struct StoredTokenSet {
        access_token: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        refresh_token: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id_token: Option<String>,
        expires_at: DateTime<Utc>,
        token_type: String,
        #[serde(default)]
        scopes: Vec<String>,
    }

    impl From<&TokenSet> for StoredTokenSet {
        fn from(t: &TokenSet) -> Self {
            Self {
                access_token: t.access_token.expose_secret().to_owned(),
                refresh_token: t
                    .refresh_token
                    .as_ref()
                    .map(|r| r.expose_secret().to_owned()),
                id_token: t.id_token.as_ref().map(|i| i.expose_secret().to_owned()),
                expires_at: t.expires_at,
                token_type: t.token_type.clone(),
                scopes: t.scopes.clone(),
            }
        }
    }

    impl From<StoredTokenSet> for TokenSet {
        fn from(s: StoredTokenSet) -> Self {
            TokenSet {
                access_token: AccessToken::new(s.access_token),
                refresh_token: s.refresh_token.map(RefreshToken::new),
                id_token: s.id_token.map(IdToken::new),
                expires_at: s.expires_at,
                token_type: s.token_type,
                scopes: s.scopes,
            }
        }
    }

    /// Serialize a [`TokenSet`] to a JSON byte buffer that is wiped on
    /// drop.
    pub(super) fn encode(tokens: &TokenSet) -> Result<Zeroizing<Vec<u8>>, IosPalError> {
        let dto = StoredTokenSet::from(tokens);
        let bytes = serde_json::to_vec(&dto).map_err(|e| IosPalError::Codec(e.to_string()))?;
        Ok(Zeroizing::new(bytes))
    }

    /// Parse a stored JSON blob back into a [`TokenSet`].
    pub(super) fn decode(blob: &[u8]) -> Result<TokenSet, IosPalError> {
        let dto: StoredTokenSet =
            serde_json::from_slice(blob).map_err(|e| IosPalError::Codec(e.to_string()))?;
        Ok(dto.into())
    }
}

// ---------------------------------------------------------------------
// iOS backend
// ---------------------------------------------------------------------
#[cfg(target_os = "ios")]
mod keychain {
    use crate::error::IosPalError;
    use security_framework::access_control::{ProtectionMode, SecAccessControl};
    use security_framework::passwords::{
        delete_generic_password, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;

    pub(super) fn store(service: &str, account: &str, blob: &[u8]) -> Result<(), IosPalError> {
        let access = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleAfterFirstUnlockThisDeviceOnly),
            0,
        )
        .map_err(|e| IosPalError::Keychain(format!("access-control: {e}")))?;
        let mut opts = PasswordOptions::new_generic_password(service, account);
        opts.set_access_control(access);
        set_generic_password_options(blob, opts).map_err(|e| IosPalError::Keychain(e.to_string()))
    }

    pub(super) fn load(service: &str, account: &str) -> Result<Option<Vec<u8>>, IosPalError> {
        match generic_password(PasswordOptions::new_generic_password(service, account)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(e) => Err(IosPalError::Keychain(e.to_string())),
        }
    }

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
impl TokenStorage for IosTokenStorage {
    async fn load(&self) -> Result<Option<TokenSet>, TokenStorageError> {
        match keychain::load(&self.service, &self.account)? {
            Some(blob) => Ok(Some(codec::decode(&blob)?)),
            None => Ok(None),
        }
    }

    async fn store(&self, tokens: &TokenSet) -> Result<(), TokenStorageError> {
        let blob = codec::encode(tokens)?;
        keychain::store(&self.service, &self.account, &blob)?;
        Ok(())
    }

    async fn clear(&self) -> Result<(), TokenStorageError> {
        keychain::delete(&self.service, &self.account)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Host fallback (Linux CI / desktop dev): typed "unsupported".
// ---------------------------------------------------------------------
#[cfg(not(target_os = "ios"))]
#[async_trait]
impl TokenStorage for IosTokenStorage {
    async fn load(&self) -> Result<Option<TokenSet>, TokenStorageError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("token load".into()).into())
    }

    async fn store(&self, _tokens: &TokenSet) -> Result<(), TokenStorageError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("token store".into()).into())
    }

    async fn clear(&self) -> Result<(), TokenStorageError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("token clear".into()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::codec;
    use super::*;
    use chrono::{TimeZone, Utc};
    use pretty_assertions::assert_eq;
    use sng_mobile_core::{AccessToken, IdToken, RefreshToken};

    fn sample() -> TokenSet {
        TokenSet {
            access_token: AccessToken::new("access-secret"),
            refresh_token: Some(RefreshToken::new("refresh-secret")),
            id_token: Some(IdToken::new("id-secret")),
            expires_at: Utc.with_ymd_and_hms(2030, 1, 2, 3, 4, 5).unwrap(),
            token_type: "Bearer".into(),
            scopes: vec!["openid".into(), "offline_access".into()],
        }
    }

    #[test]
    fn token_set_json_roundtrips() {
        let original = sample();
        let blob = codec::encode(&original).unwrap();
        let restored = codec::decode(&blob).unwrap();

        assert_eq!(
            restored.access_token.expose_secret(),
            original.access_token.expose_secret()
        );
        assert_eq!(
            restored
                .refresh_token
                .as_ref()
                .map(|r| r.expose_secret().to_owned()),
            Some("refresh-secret".to_owned())
        );
        assert_eq!(
            restored
                .id_token
                .as_ref()
                .map(|i| i.expose_secret().to_owned()),
            Some("id-secret".to_owned())
        );
        assert_eq!(restored.expires_at, original.expires_at);
        assert_eq!(restored.token_type, "Bearer");
        assert_eq!(restored.scopes, original.scopes);
    }

    #[test]
    fn token_set_without_optional_tokens_roundtrips() {
        let original = TokenSet {
            access_token: AccessToken::new("only-access"),
            refresh_token: None,
            id_token: None,
            expires_at: Utc.with_ymd_and_hms(2031, 6, 7, 8, 9, 10).unwrap(),
            token_type: "Bearer".into(),
            scopes: vec![],
        };
        let blob = codec::encode(&original).unwrap();
        let restored = codec::decode(&blob).unwrap();
        assert!(restored.refresh_token.is_none());
        assert!(restored.id_token.is_none());
        assert_eq!(restored.access_token.expose_secret(), "only-access");
    }

    #[test]
    fn corrupt_blob_is_a_typed_codec_error() {
        let err = codec::decode(b"this is not json").unwrap_err();
        // Routes onto TokenStorageError::Corrupt via the From impl.
        assert!(matches!(
            TokenStorageError::from(err),
            TokenStorageError::Corrupt(_)
        ));
    }

    #[test]
    fn default_storage_uses_documented_keychain_ids() {
        let s = IosTokenStorage::new();
        assert_eq!(s.service(), KEYCHAIN_SERVICE);
        assert_eq!(IosTokenStorage::default().service(), KEYCHAIN_SERVICE);
    }

    #[cfg(not(target_os = "ios"))]
    #[tokio::test]
    async fn host_fallback_is_unsupported_not_panic() {
        let s = IosTokenStorage::new();
        assert!(matches!(s.load().await, Err(TokenStorageError::Backend(_))));
        assert!(matches!(
            s.store(&sample()).await,
            Err(TokenStorageError::Backend(_))
        ));
        assert!(matches!(
            s.clear().await,
            Err(TokenStorageError::Backend(_))
        ));
    }
}

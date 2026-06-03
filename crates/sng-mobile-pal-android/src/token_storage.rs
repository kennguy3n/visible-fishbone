//! [`AndroidTokenStorage`] — Jetpack `EncryptedSharedPreferences`
//! backing for [`TokenStorage`].
//!
//! The OIDC [`TokenSet`] is persisted as a single JSON blob under
//! one key in an `EncryptedSharedPreferences` file. Jetpack
//! Security encrypts both the key and the value at rest with an
//! AES master key held in the Android Keystore
//! (`MasterKey.KeyScheme.AES256_GCM`), so the bearer/refresh tokens
//! never touch disk in cleartext.
//!
//! ## Serialization seam (host-testable)
//!
//! The core [`TokenSet`] deliberately does **not** implement
//! `Serialize` — its token fields are `zeroize`-on-drop secret
//! wrappers. This module owns the explicit, reviewable mapping to a
//! JSON blob via [`serialize_token_set`] / [`deserialize_token_set`],
//! exposing the secrets only at the moment of (de)serialization.
//! Those two functions are the platform-independent core of this
//! backend and are covered by host unit tests (round-trip,
//! corrupt-blob handling) without an Android device.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sng_mobile_core::{
    AccessToken, IdToken, RefreshToken, TokenSet, TokenStorage, TokenStorageError,
};

use crate::error::AndroidPalError;

/// Default `EncryptedSharedPreferences` file name.
pub const DEFAULT_PREFS_FILE: &str = "sng_secure_tokens";
/// Preference key the serialized [`TokenSet`] is stored under.
pub const TOKEN_SET_KEY: &str = "oidc_token_set";

/// JSON-serializable mirror of [`TokenSet`]. Lives only between an
/// `expose_secret()` read and the encrypted write (or the decrypted
/// read and the wrapper reconstruction); it is not held longer than
/// the (de)serialization call.
#[derive(Serialize, Deserialize)]
struct StoredTokenBlob {
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

/// Serialize a [`TokenSet`] into the JSON blob persisted in
/// `EncryptedSharedPreferences`.
pub fn serialize_token_set(tokens: &TokenSet) -> Result<String, AndroidPalError> {
    let blob = StoredTokenBlob {
        access_token: tokens.access_token.expose_secret().to_owned(),
        refresh_token: tokens
            .refresh_token
            .as_ref()
            .map(|t| t.expose_secret().to_owned()),
        id_token: tokens
            .id_token
            .as_ref()
            .map(|t| t.expose_secret().to_owned()),
        expires_at: tokens.expires_at,
        token_type: tokens.token_type.clone(),
        scopes: tokens.scopes.clone(),
    };
    serde_json::to_string(&blob)
        .map_err(|e| AndroidPalError::Encoding(format!("serialize TokenSet: {e}")))
}

/// Reconstruct a [`TokenSet`] from the persisted JSON blob.
pub fn deserialize_token_set(raw: &str) -> Result<TokenSet, AndroidPalError> {
    let blob: StoredTokenBlob = serde_json::from_str(raw)
        .map_err(|e| AndroidPalError::Encoding(format!("deserialize TokenSet: {e}")))?;
    Ok(TokenSet {
        access_token: AccessToken::new(blob.access_token),
        refresh_token: blob.refresh_token.map(RefreshToken::new),
        id_token: blob.id_token.map(IdToken::new),
        expires_at: blob.expires_at,
        token_type: blob.token_type,
        scopes: blob.scopes,
    })
}

/// `EncryptedSharedPreferences`-backed [`TokenStorage`].
///
/// Cheap to clone; addresses a single prefs file + key. The
/// constructor exists on every target so the UniFFI binding layer
/// can build it regardless of build host.
#[derive(Clone, Debug)]
pub struct AndroidTokenStorage {
    prefs_file: String,
    key: String,
}

impl Default for AndroidTokenStorage {
    fn default() -> Self {
        Self {
            prefs_file: DEFAULT_PREFS_FILE.to_owned(),
            key: TOKEN_SET_KEY.to_owned(),
        }
    }
}

impl AndroidTokenStorage {
    /// Construct a storage using the default prefs file + key.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a storage using a custom prefs file name (e.g. to
    /// isolate tokens per tenant / per user profile).
    #[must_use]
    pub fn with_prefs_file(prefs_file: impl Into<String>) -> Self {
        Self {
            prefs_file: prefs_file.into(),
            key: TOKEN_SET_KEY.to_owned(),
        }
    }

    /// The `EncryptedSharedPreferences` file name this storage uses.
    #[must_use]
    pub fn prefs_file(&self) -> &str {
        &self.prefs_file
    }
}

#[async_trait]
impl TokenStorage for AndroidTokenStorage {
    async fn load(&self) -> Result<Option<TokenSet>, TokenStorageError> {
        Ok(imp::load(&self.prefs_file, &self.key)?)
    }

    async fn store(&self, tokens: &TokenSet) -> Result<(), TokenStorageError> {
        let blob = serialize_token_set(tokens)?;
        Ok(imp::store(&self.prefs_file, &self.key, &blob)?)
    }

    async fn clear(&self) -> Result<(), TokenStorageError> {
        Ok(imp::clear(&self.prefs_file, &self.key)?)
    }
}

/// Host (non-Android) fallback: no `EncryptedSharedPreferences`
/// exists, so every operation reports
/// [`AndroidPalError::UnsupportedPlatform`].
#[cfg(not(target_os = "android"))]
mod imp {
    use sng_mobile_core::TokenSet;

    use crate::error::AndroidPalError;

    pub(super) fn load(_prefs_file: &str, _key: &str) -> Result<Option<TokenSet>, AndroidPalError> {
        Err(AndroidPalError::unsupported("AndroidTokenStorage::load"))
    }

    pub(super) fn store(_prefs_file: &str, _key: &str, _blob: &str) -> Result<(), AndroidPalError> {
        Err(AndroidPalError::unsupported("AndroidTokenStorage::store"))
    }

    pub(super) fn clear(_prefs_file: &str, _key: &str) -> Result<(), AndroidPalError> {
        Err(AndroidPalError::unsupported("AndroidTokenStorage::clear"))
    }
}

/// Android implementation over Jetpack
/// `EncryptedSharedPreferences` + `MasterKey`.
#[cfg(target_os = "android")]
mod imp {
    use jni::objects::{JObject, JString, JValue};

    use super::deserialize_token_set;
    use crate::error::AndroidPalError;
    use crate::jni_bridge::{android_context, with_env};
    use sng_mobile_core::TokenSet;

    /// Build (or open) the `EncryptedSharedPreferences` instance for
    /// `prefs_file`, creating an AES-256-GCM `MasterKey` in the
    /// Android Keystore on first use.
    fn open_prefs<'l>(
        env: &mut jni::JNIEnv<'l>,
        prefs_file: &str,
    ) -> Result<JObject<'l>, AndroidPalError> {
        let context = android_context();

        // MasterKey master = new MasterKey.Builder(context)
        //     .setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build();
        let builder = env
            .new_object(
                "androidx/security/crypto/MasterKey$Builder",
                "(Landroid/content/Context;)V",
                &[JValue::Object(&context)],
            )
            .map_err(|e| AndroidPalError::Jni(format!("MasterKey.Builder: {e}")))?;
        let key_scheme = env
            .get_static_field(
                "androidx/security/crypto/MasterKey$KeyScheme",
                "AES256_GCM",
                "Landroidx/security/crypto/MasterKey$KeyScheme;",
            )
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("MasterKey.KeyScheme.AES256_GCM: {e}")))?;
        env.call_method(
            &builder,
            "setKeyScheme",
            "(Landroidx/security/crypto/MasterKey$KeyScheme;)Landroidx/security/crypto/MasterKey$Builder;",
            &[JValue::Object(&key_scheme)],
        )
        .map_err(|e| AndroidPalError::Jni(format!("MasterKey.Builder.setKeyScheme: {e}")))?;
        let master_key = env
            .call_method(
                &builder,
                "build",
                "()Landroidx/security/crypto/MasterKey;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("MasterKey.Builder.build: {e}")))?;

        let file = env
            .new_string(prefs_file)
            .map_err(|e| AndroidPalError::Jni(format!("new_string(prefs_file): {e}")))?;
        let key_enc = env
            .get_static_field(
                "androidx/security/crypto/EncryptedSharedPreferences$PrefKeyEncryptionScheme",
                "AES256_SIV",
                "Landroidx/security/crypto/EncryptedSharedPreferences$PrefKeyEncryptionScheme;",
            )
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("PrefKeyEncryptionScheme: {e}")))?;
        let value_enc = env
            .get_static_field(
                "androidx/security/crypto/EncryptedSharedPreferences$PrefValueEncryptionScheme",
                "AES256_GCM",
                "Landroidx/security/crypto/EncryptedSharedPreferences$PrefValueEncryptionScheme;",
            )
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("PrefValueEncryptionScheme: {e}")))?;

        let prefs = env
            .call_static_method(
                "androidx/security/crypto/EncryptedSharedPreferences",
                "create",
                "(Landroid/content/Context;Ljava/lang/String;Landroidx/security/crypto/MasterKey;\
                 Landroidx/security/crypto/EncryptedSharedPreferences$PrefKeyEncryptionScheme;\
                 Landroidx/security/crypto/EncryptedSharedPreferences$PrefValueEncryptionScheme;)\
                 Landroid/content/SharedPreferences;",
                &[
                    JValue::Object(&context),
                    JValue::Object(&file),
                    JValue::Object(&master_key),
                    JValue::Object(&key_enc),
                    JValue::Object(&value_enc),
                ],
            )
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Jni(format!("EncryptedSharedPreferences.create: {e}")))?;
        Ok(prefs)
    }

    pub(super) fn load(prefs_file: &str, key: &str) -> Result<Option<TokenSet>, AndroidPalError> {
        with_env(|env| {
            let prefs = open_prefs(env, prefs_file)?;
            let jkey = env
                .new_string(key)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(key): {e}")))?;
            let value = env
                .call_method(
                    &prefs,
                    "getString",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
                    &[JValue::Object(&jkey), JValue::Object(&JObject::null())],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Jni(format!("SharedPreferences.getString: {e}")))?;
            if value.is_null() {
                return Ok(None);
            }
            let raw: String = env
                .get_string(&JString::from(value))
                .map_err(|e| AndroidPalError::Jni(format!("get_string: {e}")))?
                .into();
            Ok(Some(deserialize_token_set(&raw)?))
        })
    }

    pub(super) fn store(prefs_file: &str, key: &str, blob: &str) -> Result<(), AndroidPalError> {
        with_env(|env| {
            let prefs = open_prefs(env, prefs_file)?;
            let editor = env
                .call_method(
                    &prefs,
                    "edit",
                    "()Landroid/content/SharedPreferences$Editor;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Jni(format!("SharedPreferences.edit: {e}")))?;
            let jkey = env
                .new_string(key)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(key): {e}")))?;
            let jval = env
                .new_string(blob)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(value): {e}")))?;
            env.call_method(
                &editor,
                "putString",
                "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
                &[JValue::Object(&jkey), JValue::Object(&jval)],
            )
            .map_err(|e| AndroidPalError::Jni(format!("Editor.putString: {e}")))?;
            commit_editor(env, &editor)
        })
    }

    pub(super) fn clear(prefs_file: &str, key: &str) -> Result<(), AndroidPalError> {
        with_env(|env| {
            let prefs = open_prefs(env, prefs_file)?;
            let editor = env
                .call_method(
                    &prefs,
                    "edit",
                    "()Landroid/content/SharedPreferences$Editor;",
                    &[],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Jni(format!("SharedPreferences.edit: {e}")))?;
            let jkey = env
                .new_string(key)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(key): {e}")))?;
            env.call_method(
                &editor,
                "remove",
                "(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;",
                &[JValue::Object(&jkey)],
            )
            .map_err(|e| AndroidPalError::Jni(format!("Editor.remove: {e}")))?;
            commit_editor(env, &editor)
        })
    }

    /// Durably flush a `SharedPreferences.Editor` with `commit()`
    /// (synchronous) instead of `apply()` (asynchronous). Token
    /// material is security-sensitive, so a write that does not reach
    /// disk must surface as an error rather than being silently lost
    /// if the process is killed right after the call — `commit()`
    /// returns a boolean we map to a `Backend` error, whereas
    /// `apply()` returns `void` and swallows failures.
    fn commit_editor(
        env: &mut jni::JNIEnv<'_>,
        editor: &JObject<'_>,
    ) -> Result<(), AndroidPalError> {
        let committed = env
            .call_method(editor, "commit", "()Z", &[])
            .and_then(|v| v.z())
            .map_err(|e| AndroidPalError::Jni(format!("Editor.commit: {e}")))?;
        if committed {
            Ok(())
        } else {
            Err(AndroidPalError::Jni(
                "Editor.commit returned false (token write not persisted)".to_owned(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TokenSet {
        TokenSet {
            access_token: AccessToken::new("access-abc"),
            refresh_token: Some(RefreshToken::new("refresh-def")),
            id_token: Some(IdToken::new("id-ghi")),
            expires_at: DateTime::parse_from_rfc3339("2030-01-02T03:04:05Z")
                .expect("parse")
                .with_timezone(&Utc),
            token_type: "Bearer".to_owned(),
            scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        }
    }

    #[test]
    fn token_set_round_trips_through_blob() {
        let original = sample();
        let raw = serialize_token_set(&original).expect("serialize");
        let restored = deserialize_token_set(&raw).expect("deserialize");
        assert_eq!(
            restored.access_token.expose_secret(),
            original.access_token.expose_secret()
        );
        assert_eq!(
            restored
                .refresh_token
                .as_ref()
                .map(RefreshToken::expose_secret),
            original
                .refresh_token
                .as_ref()
                .map(RefreshToken::expose_secret)
        );
        assert_eq!(
            restored.id_token.as_ref().map(IdToken::expose_secret),
            original.id_token.as_ref().map(IdToken::expose_secret)
        );
        assert_eq!(restored.expires_at, original.expires_at);
        assert_eq!(restored.token_type, original.token_type);
        assert_eq!(restored.scopes, original.scopes);
    }

    #[test]
    fn serialized_blob_omits_absent_refresh_and_id() {
        let tokens = TokenSet {
            access_token: AccessToken::new("a"),
            refresh_token: None,
            id_token: None,
            expires_at: Utc::now(),
            token_type: "Bearer".to_owned(),
            scopes: vec![],
        };
        let raw = serialize_token_set(&tokens).expect("serialize");
        assert!(!raw.contains("refresh_token"));
        assert!(!raw.contains("id_token"));
        let restored = deserialize_token_set(&raw).expect("deserialize");
        assert!(restored.refresh_token.is_none());
        assert!(restored.id_token.is_none());
    }

    #[test]
    fn corrupt_blob_reports_encoding_error() {
        let err = deserialize_token_set("{not json").expect_err("corrupt");
        assert!(matches!(err, AndroidPalError::Encoding(_)));
    }

    #[tokio::test]
    async fn host_fallback_reports_unsupported() {
        let storage = AndroidTokenStorage::new();
        assert_eq!(storage.prefs_file(), DEFAULT_PREFS_FILE);
        assert!(matches!(
            storage.load().await,
            Err(TokenStorageError::Backend(_))
        ));
        assert!(storage.store(&sample()).await.is_err());
        assert!(storage.clear().await.is_err());
    }
}

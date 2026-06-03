//! [`AndroidSecureKeyStore`] — the Android Keystore / StrongBox
//! backing for [`SecureKeyStore`].
//!
//! The device enrolment key is an **Ed25519** keypair (the curve
//! the core's `VerifyingKey` / `Signature` are fixed to, matching
//! the Go control plane's `crypto/ed25519`). The private half is
//! generated *inside* the Android Keystore under a caller-supplied
//! alias (`label`) and never leaves it — `sign` calls into the
//! Keystore and `public_key` reads back only the public half.
//!
//! ## Key-storage decision (Ed25519 on Android)
//!
//! The Android Keystore gained first-class Ed25519 (`"Ed25519"`)
//! key support in **API 33 (Android 13)**, with StrongBox-backed
//! Ed25519 following on supported hardware. This backend targets
//! that path: `KeyPairGenerator.getInstance("Ed25519",
//! "AndroidKeyStore")` with a `KeyGenParameterSpec` requesting
//! `PURPOSE_SIGN | PURPOSE_VERIFY` and, when
//! `setIsStrongBoxBacked(true)` is honoured by the hardware, a
//! StrongBox-resident key.
//!
//! For **API < 33** the platform Keystore cannot host an Ed25519
//! key directly. The documented fallback (not wired here, because
//! it is a product decision about the minimum supported API level)
//! is to generate the Ed25519 seed in-process, wrap it with a
//! Keystore-held AES key, and persist the wrapped blob in
//! [`EncryptedSharedPreferences`](crate::token_storage) — signing
//! then unwraps transiently and zeroizes. Crucially, **either path
//! keeps the key type the core expects**: callers always receive an
//! `ed25519_dalek::VerifyingKey` and an `ed25519_dalek::Signature`.
//!
//! ## Encoding seam (host-testable)
//!
//! Android returns a generated public key as an X.509
//! `SubjectPublicKeyInfo` (SPKI) DER blob via
//! `Certificate.getPublicKey().getEncoded()`, and an Ed25519
//! `Signature.sign()` as the raw 64-byte signature. The pure
//! [`verifying_key_from_spki`] / [`signature_from_raw`] helpers do
//! that decode; they are exercised by the host unit tests so the
//! mapping is verified without an Android device.

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use sng_mobile_core::{KeyStoreError, SecureKeyStore};

use crate::error::AndroidPalError;

/// The 12-byte X.509 `SubjectPublicKeyInfo` prefix that precedes
/// the 32-byte raw key in a DER-encoded Ed25519 public key
/// (`AlgorithmIdentifier` = `id-Ed25519` / OID 1.3.101.112, then a
/// 33-byte BIT STRING). Android's
/// `PublicKey.getEncoded()` returns exactly this 44-byte form for
/// an Ed25519 key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Decode an Ed25519 public key the platform handed back.
///
/// Accepts either the 44-byte X.509 SPKI DER form (what
/// `PublicKey.getEncoded()` returns) or the bare 32-byte raw form,
/// and validates it parses to a real curve point.
pub fn verifying_key_from_spki(encoded: &[u8]) -> Result<VerifyingKey, AndroidPalError> {
    let raw = match encoded.len() {
        32 => encoded,
        44 if encoded[..12] == ED25519_SPKI_PREFIX => &encoded[12..],
        other => {
            return Err(AndroidPalError::Encoding(format!(
                "unexpected Ed25519 public-key encoding ({other} bytes); \
                 expected a 44-byte X.509 SPKI or a 32-byte raw key"
            )));
        }
    };
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| AndroidPalError::Encoding("Ed25519 public key must be 32 bytes".to_owned()))?;
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| AndroidPalError::Encoding(format!("invalid Ed25519 public key: {e}")))
}

/// Wrap the raw 64-byte signature an Android Ed25519
/// `Signature.sign()` returns into an `ed25519_dalek::Signature`.
pub fn signature_from_raw(raw: &[u8]) -> Result<Signature, AndroidPalError> {
    Signature::from_slice(raw).map_err(|e| {
        AndroidPalError::Encoding(format!(
            "invalid Ed25519 signature ({} bytes): {e}",
            raw.len()
        ))
    })
}

/// Fully-qualified Java class name `KeyPairGenerator.generateKeyPair`
/// throws when a StrongBox-backed key is requested on a device whose
/// hardware has no StrongBox.
pub const STRONGBOX_UNAVAILABLE_EXCEPTION: &str =
    "android.security.keystore.StrongBoxUnavailableException";

/// Decide whether a failed StrongBox-backed key-generation attempt
/// should be retried on the TEE-backed Keystore.
///
/// Returns `true` only when StrongBox was actually requested *and* the
/// Java exception that aborted the attempt is
/// [`StrongBoxUnavailableException`](STRONGBOX_UNAVAILABLE_EXCEPTION)
/// (matched by class name). Any other failure — including a thrown
/// exception of a different class, or no pending exception at all —
/// propagates unchanged, so an unrelated keystore error is never
/// masked behind a silent TEE downgrade. This is the platform-
/// independent core of the fallback, exercised by host unit tests
/// without an Android device.
#[must_use]
pub fn should_retry_without_strongbox(
    strongbox_requested: bool,
    exception_class: Option<&str>,
) -> bool {
    strongbox_requested
        && exception_class.is_some_and(|class| class == STRONGBOX_UNAVAILABLE_EXCEPTION)
}

/// Outcome of a key-generation request.
///
/// Lets the `imp` layer fold the alias-existence check into the
/// *same* `with_env` round-trip as `generateKeyPair` (so the
/// check-then-act TOCTOU window is a single JNI attach rather than
/// two), while the trait layer still surfaces the typed
/// [`KeyStoreError::AlreadyExists`] for an occupied alias.
///
/// The variants are only constructed by the Android `imp`; on the
/// host fallback `generate_keypair` always errors before producing
/// one, so they are dead there.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
#[derive(Debug)]
enum GenerateOutcome {
    /// A fresh key was generated; carries its public half.
    Created(VerifyingKey),
    /// The alias already held a key; nothing was generated or
    /// overwritten.
    AlreadyExists,
}

/// Android Keystore / StrongBox-backed [`SecureKeyStore`].
///
/// Holds no key material itself — every operation addresses the
/// Keystore by `label` (the key alias). Cheap to clone and
/// construct, and the constructor exists on every target so the
/// UniFFI binding layer can name and build it regardless of build
/// host.
#[derive(Clone, Debug)]
pub struct AndroidSecureKeyStore {
    /// StrongBox preference. When `true`, key generation requests a
    /// StrongBox-resident key and falls back to TEE if the hardware
    /// lacks a StrongBox (`StrongBoxUnavailableException`).
    prefer_strongbox: bool,
}

impl Default for AndroidSecureKeyStore {
    /// Defaults to the secure posture: prefer StrongBox. Kept in
    /// sync with [`AndroidSecureKeyStore::new`] so `Default::default()`
    /// (struct-update syntax, generic code, derives) never silently
    /// downgrades to a TEE-only keystore.
    fn default() -> Self {
        Self {
            prefer_strongbox: true,
        }
    }
}

impl AndroidSecureKeyStore {
    /// Construct a keystore that prefers a StrongBox-backed key and
    /// falls back to the TEE-backed Keystore when no StrongBox is
    /// present.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a keystore with an explicit StrongBox preference.
    /// Pass `false` on devices/tests where only the TEE-backed
    /// Keystore should be used.
    #[must_use]
    pub fn with_strongbox(prefer_strongbox: bool) -> Self {
        Self { prefer_strongbox }
    }

    /// Whether this keystore requests StrongBox-backed keys.
    #[must_use]
    pub fn prefers_strongbox(&self) -> bool {
        self.prefer_strongbox
    }
}

#[async_trait]
impl SecureKeyStore for AndroidSecureKeyStore {
    async fn generate_keypair(&self, label: &str) -> Result<VerifyingKey, KeyStoreError> {
        // Contract: `SecureKeyStore::generate_keypair` must reject a
        // label that already holds a key with `AlreadyExists` rather
        // than overwriting it. `KeyPairGenerator.generateKeyPair`
        // silently overwrites an occupied alias, which would destroy
        // the device's enrolment key and break
        // `EnrollmentService::ensure_key` (it relies on `AlreadyExists`
        // to stay idempotent). The existence check is performed inside
        // the same `with_env` attach as generation (see `imp`), so the
        // unavoidable check-then-act window — the Android Keystore has
        // no atomic check-and-generate — is as narrow as the platform
        // allows. The `From<AndroidPalError>` mapping only yields
        // `Backend`, so the typed variant is returned here directly.
        match imp::generate_keypair(self.prefer_strongbox, label)? {
            GenerateOutcome::Created(public_key) => Ok(public_key),
            GenerateOutcome::AlreadyExists => Err(KeyStoreError::AlreadyExists(label.to_owned())),
        }
    }

    async fn public_key(&self, label: &str) -> Result<VerifyingKey, KeyStoreError> {
        Ok(imp::public_key(label)?)
    }

    async fn sign(&self, label: &str, message: &[u8]) -> Result<Signature, KeyStoreError> {
        Ok(imp::sign(label, message)?)
    }

    async fn contains(&self, label: &str) -> Result<bool, KeyStoreError> {
        Ok(imp::contains(label)?)
    }

    async fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        Ok(imp::delete(label)?)
    }
}

/// Host (non-Android) fallback. Every operation reports
/// [`AndroidPalError::UnsupportedPlatform`] — there is no Android
/// Keystore to talk to. Keeps the workspace building and tests
/// runnable on the Linux CI host.
#[cfg(not(target_os = "android"))]
mod imp {
    use super::{GenerateOutcome, Signature, VerifyingKey};
    use crate::error::AndroidPalError;

    pub(super) fn generate_keypair(
        _strongbox: bool,
        _label: &str,
    ) -> Result<GenerateOutcome, AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidSecureKeyStore::generate_keypair",
        ))
    }

    pub(super) fn public_key(_label: &str) -> Result<VerifyingKey, AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidSecureKeyStore::public_key",
        ))
    }

    pub(super) fn sign(_label: &str, _message: &[u8]) -> Result<Signature, AndroidPalError> {
        Err(AndroidPalError::unsupported("AndroidSecureKeyStore::sign"))
    }

    pub(super) fn contains(_label: &str) -> Result<bool, AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidSecureKeyStore::contains",
        ))
    }

    pub(super) fn delete(_label: &str) -> Result<(), AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidSecureKeyStore::delete",
        ))
    }
}

/// Android Keystore implementation. Drives
/// `java.security.KeyStore` / `KeyPairGenerator` /
/// `java.security.Signature` over JNI through the safe `jni`
/// surface.
#[cfg(target_os = "android")]
mod imp {
    use ed25519_dalek::{Signature, VerifyingKey};
    use jni::objects::{JByteArray, JObject, JString, JValue};

    use super::{
        GenerateOutcome, should_retry_without_strongbox, signature_from_raw,
        verifying_key_from_spki,
    };
    use crate::error::AndroidPalError;
    use crate::jni_bridge::with_env;

    const ANDROID_KEYSTORE: &str = "AndroidKeyStore";
    const ED25519: &str = "Ed25519";
    // KeyProperties.PURPOSE_SIGN (4) | PURPOSE_VERIFY (8).
    const PURPOSE_SIGN_VERIFY: i32 = 4 | 8;

    /// One failed `generateKeyPair` attempt. `exception_class` carries
    /// the Java class name of the exception that aborted the
    /// `generateKeyPair` call (when one was pending), so the caller can
    /// decide — via [`should_retry_without_strongbox`] — whether to
    /// retry on the TEE. It is `None` for failures at any earlier step
    /// (spec build, provider lookup, initialize), which are never
    /// retried.
    #[derive(Debug)]
    struct GenFailure {
        error: AndroidPalError,
        exception_class: Option<String>,
    }

    impl GenFailure {
        /// A non-retryable failure (no StrongBox decision to make).
        fn other(error: AndroidPalError) -> Self {
            Self {
                error,
                exception_class: None,
            }
        }
    }

    pub(super) fn generate_keypair(
        strongbox: bool,
        label: &str,
    ) -> Result<GenerateOutcome, AndroidPalError> {
        with_env(|env| {
            // Alias-existence check and generation share this single
            // `with_env` attach, so the unavoidable check-then-act
            // window (the Keystore has no atomic check-and-generate) is
            // as narrow as the platform allows: an occupied alias is
            // reported as `AlreadyExists` and `generateKeyPair` — which
            // would silently overwrite it — is never reached.
            if contains_alias(env, label)? {
                return Ok(GenerateOutcome::AlreadyExists);
            }
            let public_key = match attempt_generate(env, strongbox, label) {
                Ok(public_key) => public_key,
                Err(failure) => {
                    if should_retry_without_strongbox(strongbox, failure.exception_class.as_deref())
                    {
                        // Documented behaviour: StrongBox was requested
                        // but the hardware has none, so fall back to the
                        // TEE-backed Keystore exactly once. Surface the
                        // downgrade in telemetry.
                        tracing::warn!(
                            alias = label,
                            "Android Keystore reported StrongBox unavailable; \
                             retrying Ed25519 key generation on the TEE-backed Keystore"
                        );
                        attempt_generate(env, false, label).map_err(|f| f.error)?
                    } else {
                        return Err(failure.error);
                    }
                }
            };
            Ok(GenerateOutcome::Created(public_key))
        })
    }

    /// Run a single key-generation attempt with the given StrongBox
    /// preference. On failure of the `generateKeyPair` call itself, the
    /// pending Java exception's class name is captured (and cleared) so
    /// the caller can decide whether to retry without StrongBox.
    fn attempt_generate(
        env: &mut jni::JNIEnv<'_>,
        strongbox: bool,
        label: &str,
    ) -> Result<VerifyingKey, GenFailure> {
        // KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN | PURPOSE_VERIFY)
        let alias = env.new_string(label).map_err(|e| {
            GenFailure::other(AndroidPalError::Jni(format!("new_string(alias): {e}")))
        })?;
        let builder = env
            .new_object(
                "android/security/keystore/KeyGenParameterSpec$Builder",
                "(Ljava/lang/String;I)V",
                &[JValue::Object(&alias), JValue::Int(PURPOSE_SIGN_VERIFY)],
            )
            .map_err(|e| {
                GenFailure::other(AndroidPalError::Jni(format!(
                    "KeyGenParameterSpec.Builder: {e}"
                )))
            })?;
        if strongbox {
            // .setIsStrongBoxBacked(true) — best-effort. Clear any
            // exception it leaves pending (jni 0.21 reports
            // `JavaException` from `ExceptionCheck` without clearing),
            // so a thrown setter does not abort the `build` call below.
            let _ = env.call_method(
                &builder,
                "setIsStrongBoxBacked",
                "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[JValue::Bool(u8::from(true))],
            );
            let _ = env.exception_clear();
        }
        let spec = env
            .call_method(
                &builder,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| {
                GenFailure::other(AndroidPalError::Jni(format!(
                    "KeyGenParameterSpec.build: {e}"
                )))
            })?;

        // KeyPairGenerator.getInstance("Ed25519", "AndroidKeyStore")
        let algo = env.new_string(ED25519).map_err(|e| {
            GenFailure::other(AndroidPalError::Jni(format!("new_string(algo): {e}")))
        })?;
        let provider = env.new_string(ANDROID_KEYSTORE).map_err(|e| {
            GenFailure::other(AndroidPalError::Jni(format!("new_string(provider): {e}")))
        })?;
        let kpg = env
            .call_static_method(
                "java/security/KeyPairGenerator",
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljava/security/KeyPairGenerator;",
                &[JValue::Object(&algo), JValue::Object(&provider)],
            )
            .and_then(|v| v.l())
            .map_err(|e| {
                GenFailure::other(AndroidPalError::Keystore(format!(
                    "KeyPairGenerator.getInstance: {e}"
                )))
            })?;

        // kpg.initialize(spec); kpg.generateKeyPair()
        env.call_method(
            &kpg,
            "initialize",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[JValue::Object(&spec)],
        )
        .map_err(|e| {
            GenFailure::other(AndroidPalError::Keystore(format!(
                "KeyPairGenerator.initialize: {e}"
            )))
        })?;
        let pair = match env
            .call_method(&kpg, "generateKeyPair", "()Ljava/security/KeyPair;", &[])
            .and_then(|v| v.l())
        {
            Ok(pair) => pair,
            Err(e) => {
                // Capture (and clear) the pending exception so the
                // class name drives the StrongBox-fallback decision and
                // a retry starts from a clean JNI state.
                let exception_class = take_pending_exception_class(env);
                return Err(GenFailure {
                    error: AndroidPalError::Keystore(format!("generateKeyPair: {e}")),
                    exception_class,
                });
            }
        };
        let public = env
            .call_method(&pair, "getPublic", "()Ljava/security/PublicKey;", &[])
            .and_then(|v| v.l())
            .map_err(|e| {
                GenFailure::other(AndroidPalError::Keystore(format!("KeyPair.getPublic: {e}")))
            })?;
        public_key_bytes(env, &public).map_err(GenFailure::other)
    }

    /// Read and clear the currently-pending Java exception, returning
    /// its fully-qualified class name (e.g.
    /// `android.security.keystore.StrongBoxUnavailableException`).
    ///
    /// Clearing is mandatory: jni 0.21 reports `Error::JavaException`
    /// purely from `ExceptionCheck` and never clears the exception, so
    /// a left-pending throwable would abort the very next JNI call
    /// (including the TEE retry).
    fn take_pending_exception_class(env: &mut jni::JNIEnv<'_>) -> Option<String> {
        if !env.exception_check().unwrap_or(false) {
            return None;
        }
        let throwable = env.exception_occurred().ok()?;
        // Clear before any further JNI call (the class-name lookup
        // below would otherwise fail with the same pending exception).
        let _ = env.exception_clear();
        if throwable.is_null() {
            return None;
        }
        let class = env.get_object_class(&throwable).ok()?;
        let name = env
            .call_method(&class, "getName", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .ok()?;
        let name: String = env.get_string(&JString::from(name)).ok()?.into();
        Some(name)
    }

    pub(super) fn public_key(label: &str) -> Result<VerifyingKey, AndroidPalError> {
        with_env(|env| {
            let ks = load_keystore(env)?;
            let alias = env
                .new_string(label)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(alias): {e}")))?;
            let cert = env
                .call_method(
                    &ks,
                    "getCertificate",
                    "(Ljava/lang/String;)Ljava/security/cert/Certificate;",
                    &[JValue::Object(&alias)],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Keystore(format!("KeyStore.getCertificate: {e}")))?;
            if cert.is_null() {
                return Err(AndroidPalError::Keystore(format!(
                    "no key under alias {label:?}"
                )));
            }
            let public = env
                .call_method(&cert, "getPublicKey", "()Ljava/security/PublicKey;", &[])
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Keystore(format!("Certificate.getPublicKey: {e}")))?;
            public_key_bytes(env, &public)
        })
    }

    pub(super) fn sign(label: &str, message: &[u8]) -> Result<Signature, AndroidPalError> {
        with_env(|env| {
            let ks = load_keystore(env)?;
            let alias = env
                .new_string(label)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(alias): {e}")))?;
            // KeyStore.getKey(alias, null) -> PrivateKey
            let key = env
                .call_method(
                    &ks,
                    "getKey",
                    "(Ljava/lang/String;[C)Ljava/security/Key;",
                    &[JValue::Object(&alias), JValue::Object(&JObject::null())],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Keystore(format!("KeyStore.getKey: {e}")))?;
            if key.is_null() {
                return Err(AndroidPalError::Keystore(format!(
                    "no key under alias {label:?}"
                )));
            }
            // Signature.getInstance("Ed25519")
            let algo = env
                .new_string(ED25519)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(algo): {e}")))?;
            let sig = env
                .call_static_method(
                    "java/security/Signature",
                    "getInstance",
                    "(Ljava/lang/String;)Ljava/security/Signature;",
                    &[JValue::Object(&algo)],
                )
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Keystore(format!("Signature.getInstance: {e}")))?;
            env.call_method(
                &sig,
                "initSign",
                "(Ljava/security/PrivateKey;)V",
                &[JValue::Object(&key)],
            )
            .map_err(|e| AndroidPalError::Keystore(format!("Signature.initSign: {e}")))?;
            let payload = env
                .byte_array_from_slice(message)
                .map_err(|e| AndroidPalError::Jni(format!("byte_array_from_slice: {e}")))?;
            env.call_method(
                &sig,
                "update",
                "([B)V",
                &[JValue::Object(&JObject::from(payload))],
            )
            .map_err(|e| AndroidPalError::Keystore(format!("Signature.update: {e}")))?;
            let out = env
                .call_method(&sig, "sign", "()[B", &[])
                .and_then(|v| v.l())
                .map_err(|e| AndroidPalError::Keystore(format!("Signature.sign: {e}")))?;
            let bytes = env
                .convert_byte_array(JByteArray::from(out))
                .map_err(|e| AndroidPalError::Jni(format!("convert_byte_array: {e}")))?;
            signature_from_raw(&bytes)
        })
    }

    pub(super) fn contains(label: &str) -> Result<bool, AndroidPalError> {
        with_env(|env| contains_alias(env, label))
    }

    /// `KeyStore.containsAlias(label)` on an already-attached `env`.
    ///
    /// Factored out of [`contains`] so `generate_keypair` can run the
    /// existence check and generation under a single `with_env` attach,
    /// narrowing the check-then-act window.
    fn contains_alias(env: &mut jni::JNIEnv<'_>, label: &str) -> Result<bool, AndroidPalError> {
        let ks = load_keystore(env)?;
        let alias = env
            .new_string(label)
            .map_err(|e| AndroidPalError::Jni(format!("new_string(alias): {e}")))?;
        env.call_method(
            &ks,
            "containsAlias",
            "(Ljava/lang/String;)Z",
            &[JValue::Object(&alias)],
        )
        .and_then(|v| v.z())
        .map_err(|e| AndroidPalError::Keystore(format!("KeyStore.containsAlias: {e}")))
    }

    pub(super) fn delete(label: &str) -> Result<(), AndroidPalError> {
        with_env(|env| {
            let ks = load_keystore(env)?;
            let alias = env
                .new_string(label)
                .map_err(|e| AndroidPalError::Jni(format!("new_string(alias): {e}")))?;
            env.call_method(
                &ks,
                "deleteEntry",
                "(Ljava/lang/String;)V",
                &[JValue::Object(&alias)],
            )
            .map_err(|e| AndroidPalError::Keystore(format!("KeyStore.deleteEntry: {e}")))?;
            Ok(())
        })
    }

    /// `KeyStore.getInstance("AndroidKeyStore"); ks.load(null)`.
    fn load_keystore<'l>(env: &mut jni::JNIEnv<'l>) -> Result<JObject<'l>, AndroidPalError> {
        let provider = env
            .new_string(ANDROID_KEYSTORE)
            .map_err(|e| AndroidPalError::Jni(format!("new_string(provider): {e}")))?;
        let ks = env
            .call_static_method(
                "java/security/KeyStore",
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[JValue::Object(&provider)],
            )
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Keystore(format!("KeyStore.getInstance: {e}")))?;
        env.call_method(
            &ks,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[JValue::Object(&JObject::null())],
        )
        .map_err(|e| AndroidPalError::Keystore(format!("KeyStore.load: {e}")))?;
        Ok(ks)
    }

    /// `publicKey.getEncoded()` -> decode SPKI -> `VerifyingKey`.
    fn public_key_bytes(
        env: &mut jni::JNIEnv<'_>,
        public: &JObject<'_>,
    ) -> Result<VerifyingKey, AndroidPalError> {
        let encoded = env
            .call_method(public, "getEncoded", "()[B", &[])
            .and_then(|v| v.l())
            .map_err(|e| AndroidPalError::Keystore(format!("PublicKey.getEncoded: {e}")))?;
        let bytes = env
            .convert_byte_array(JByteArray::from(encoded))
            .map_err(|e| AndroidPalError::Jni(format!("convert_byte_array: {e}")))?;
        verifying_key_from_spki(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Build the 44-byte X.509 SPKI form of a raw Ed25519 key, the
    /// way Android's `PublicKey.getEncoded()` would.
    fn spki(raw: &[u8; 32]) -> Vec<u8> {
        let mut der = ED25519_SPKI_PREFIX.to_vec();
        der.extend_from_slice(raw);
        der
    }

    #[test]
    fn decodes_x509_spki_public_key() {
        let vk = fixed_signing_key().verifying_key();
        let der = spki(&vk.to_bytes());
        let decoded = verifying_key_from_spki(&der).expect("decode SPKI");
        assert_eq!(decoded.to_bytes(), vk.to_bytes());
    }

    #[test]
    fn decodes_raw_32_byte_public_key() {
        let vk = fixed_signing_key().verifying_key();
        let decoded = verifying_key_from_spki(&vk.to_bytes()).expect("decode raw");
        assert_eq!(decoded, vk);
    }

    #[test]
    fn rejects_wrong_length_public_key() {
        let err = verifying_key_from_spki(&[0u8; 20]).expect_err("too short");
        assert!(matches!(err, AndroidPalError::Encoding(_)));
    }

    #[test]
    fn rejects_spki_with_bad_prefix() {
        let mut der = spki(&[1u8; 32]);
        der[0] = 0x00; // corrupt the DER SEQUENCE tag
        let err = verifying_key_from_spki(&der).expect_err("bad prefix");
        assert!(matches!(err, AndroidPalError::Encoding(_)));
    }

    #[test]
    fn signature_round_trips_through_raw_bytes() {
        let sk = fixed_signing_key();
        let sig = sk.sign(b"enrolment-challenge");
        let raw = sig.to_bytes();
        let decoded = signature_from_raw(&raw).expect("decode signature");
        assert_eq!(decoded, sig);
        // And it verifies against the matching public key.
        sk.verifying_key()
            .verify_strict(b"enrolment-challenge", &decoded)
            .expect("verify");
    }

    #[test]
    fn rejects_wrong_length_signature() {
        let err = signature_from_raw(&[0u8; 10]).expect_err("too short");
        assert!(matches!(err, AndroidPalError::Encoding(_)));
    }

    #[test]
    fn retries_without_strongbox_only_on_strongbox_unavailable() {
        // Retry only when StrongBox was requested AND the hardware
        // threw StrongBoxUnavailableException.
        assert!(should_retry_without_strongbox(
            true,
            Some(STRONGBOX_UNAVAILABLE_EXCEPTION)
        ));
        // An unrelated exception class must propagate, not downgrade.
        assert!(!should_retry_without_strongbox(
            true,
            Some("java.security.ProviderException")
        ));
        // No pending exception → no retry.
        assert!(!should_retry_without_strongbox(true, None));
        // StrongBox never requested → nothing to fall back from.
        assert!(!should_retry_without_strongbox(
            false,
            Some(STRONGBOX_UNAVAILABLE_EXCEPTION)
        ));
    }

    #[test]
    fn default_matches_new_and_prefers_strongbox() {
        // `Default::default()` must agree with `new()` so struct-update
        // syntax / generic code never silently downgrades to TEE-only.
        assert!(AndroidSecureKeyStore::default().prefers_strongbox());
        assert_eq!(
            AndroidSecureKeyStore::default().prefers_strongbox(),
            AndroidSecureKeyStore::new().prefers_strongbox()
        );
        assert!(!AndroidSecureKeyStore::with_strongbox(false).prefers_strongbox());
    }

    #[tokio::test]
    async fn host_fallback_reports_unsupported() {
        let ks = AndroidSecureKeyStore::new();
        assert!(ks.prefers_strongbox());
        let err = ks.generate_keypair("sng.device").await.expect_err("host");
        assert!(matches!(err, KeyStoreError::Backend(_)));
        assert!(err.to_string().contains("unsupported"));
        assert!(ks.contains("sng.device").await.is_err());
        assert!(ks.sign("sng.device", b"x").await.is_err());
        assert!(ks.delete("sng.device").await.is_err());
    }
}

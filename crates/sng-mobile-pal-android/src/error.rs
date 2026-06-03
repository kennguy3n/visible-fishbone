//! The Android PAL error taxonomy.
//!
//! Every backend in this crate funnels its failures through
//! [`AndroidPalError`], then maps that into the relevant
//! `sng-mobile-core` / `sng-oidc` trait error at the trait
//! boundary (the core traits each define their own error enum, so
//! the PAL cannot return [`AndroidPalError`] directly). The
//! [`From`] impls below are the single place those mappings live.
//!
//! [`AndroidPalError::UnsupportedPlatform`] is the variant the
//! host (non-Android) fallback returns: the workspace CI compiles
//! and tests this crate on a Linux x86_64 host where no Android
//! framework exists, so every trait method has a
//! `cfg(not(target_os = "android"))` arm that returns this variant
//! rather than panicking or faking success.

use sng_mobile_core::{KeyStoreError, PostureError, TokenStorageError, TunnelError};
use sng_oidc::AuthSurfaceError;
use thiserror::Error;

/// Failure modes shared by every Android PAL backend.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AndroidPalError {
    /// The operation is not supported on the current build target.
    ///
    /// Returned by every backend on a non-Android host (the build
    /// CI exercises) so the crate compiles and its
    /// platform-independent logic stays unit-testable without an
    /// emulator. Carries the operation name for diagnostics.
    #[error("operation unsupported on this platform (non-Android host build): {0}")]
    UnsupportedPlatform(String),

    /// A JNI call into the Android framework failed (attach,
    /// method lookup, invocation, or a pending Java exception).
    #[error("JNI: {0}")]
    Jni(String),

    /// The Android Keystore / `KeyPairGenerator` rejected a
    /// key-management operation.
    #[error("Android Keystore: {0}")]
    Keystore(String),

    /// A value handed back by the platform could not be decoded
    /// into the type the core trait expects (e.g. an Ed25519
    /// public key that was not a well-formed X.509 SPKI, or a
    /// signature of the wrong length).
    #[error("encoding: {0}")]
    Encoding(String),

    /// The caller supplied an input the PAL rejected before it
    /// ever reached the platform (e.g. an endpoint string with no
    /// port).
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl AndroidPalError {
    /// Construct an [`AndroidPalError::UnsupportedPlatform`] for
    /// `operation`. Keeps the host-fallback arms terse and their
    /// messages consistent across modules.
    #[must_use]
    pub fn unsupported(operation: &str) -> Self {
        Self::UnsupportedPlatform(operation.to_owned())
    }
}

impl From<AndroidPalError> for KeyStoreError {
    fn from(err: AndroidPalError) -> Self {
        // `KeyStoreError` has no dedicated "unsupported" variant;
        // `Backend` is the catch-all the core uses for any
        // platform-side rejection, so every Android PAL keystore
        // failure (including the host-fallback unsupported case)
        // surfaces as a backend error carrying the message.
        KeyStoreError::Backend(err.to_string())
    }
}

impl From<AndroidPalError> for TokenStorageError {
    fn from(err: AndroidPalError) -> Self {
        match err {
            AndroidPalError::Encoding(msg) => TokenStorageError::Corrupt(msg),
            other => TokenStorageError::Backend(other.to_string()),
        }
    }
}

impl From<AndroidPalError> for PostureError {
    fn from(err: AndroidPalError) -> Self {
        match err {
            AndroidPalError::Encoding(msg) => PostureError::Encode(msg),
            other => PostureError::Unavailable(other.to_string()),
        }
    }
}

impl From<AndroidPalError> for TunnelError {
    fn from(err: AndroidPalError) -> Self {
        match err {
            AndroidPalError::InvalidInput(msg) | AndroidPalError::Encoding(msg) => {
                TunnelError::Config(msg)
            }
            other => TunnelError::Backend(other.to_string()),
        }
    }
}

impl From<AndroidPalError> for AuthSurfaceError {
    fn from(err: AndroidPalError) -> Self {
        match err {
            AndroidPalError::Encoding(msg) => AuthSurfaceError::InvalidCallback(msg),
            other => AuthSurfaceError::Presentation(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_maps_to_keystore_backend() {
        let err: KeyStoreError = AndroidPalError::unsupported("generate_keypair").into();
        assert!(matches!(err, KeyStoreError::Backend(_)));
        assert!(err.to_string().contains("generate_keypair"));
    }

    #[test]
    fn encoding_maps_to_storage_corrupt() {
        let err: TokenStorageError = AndroidPalError::Encoding("bad blob".into()).into();
        assert!(matches!(err, TokenStorageError::Corrupt(_)));
    }

    #[test]
    fn unsupported_maps_to_storage_backend() {
        let err: TokenStorageError = AndroidPalError::unsupported("load").into();
        assert!(matches!(err, TokenStorageError::Backend(_)));
    }

    #[test]
    fn encoding_maps_to_posture_encode_and_other_to_unavailable() {
        let enc: PostureError = AndroidPalError::Encoding("x".into()).into();
        assert!(matches!(enc, PostureError::Encode(_)));
        let other: PostureError = AndroidPalError::unsupported("collect").into();
        assert!(matches!(other, PostureError::Unavailable(_)));
    }

    #[test]
    fn invalid_input_maps_to_tunnel_config() {
        let err: TunnelError = AndroidPalError::InvalidInput("no port".into()).into();
        assert!(matches!(err, TunnelError::Config(_)));
        let backend: TunnelError = AndroidPalError::unsupported("start_tunnel").into();
        assert!(matches!(backend, TunnelError::Backend(_)));
    }

    #[test]
    fn auth_surface_mapping() {
        let enc: AuthSurfaceError = AndroidPalError::Encoding("bad url".into()).into();
        assert!(matches!(enc, AuthSurfaceError::InvalidCallback(_)));
        let pres: AuthSurfaceError = AndroidPalError::unsupported("present_auth_url").into();
        assert!(matches!(pres, AuthSurfaceError::Presentation(_)));
    }
}

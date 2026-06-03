// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Crate-internal error taxonomy + mapping into the core trait errors.
//!
//! Each trait this PAL implements declares its own `#[non_exhaustive]`
//! error type in `sng-mobile-core` / `sng-oidc` (which this crate must
//! not modify). [`IosPalError`] is the single internal error the iOS
//! and host code paths raise; the `From` impls below funnel it into the
//! closest existing variant of each trait's error so the public trait
//! surfaces stay byte-for-byte the ones the core defined.
//!
//! The [`IosPalError::UnsupportedPlatform`] variant is what every
//! `#[cfg(not(target_os = "ios"))]` host fallback returns — it maps to a
//! real, typed error on each trait surface rather than a panic or a
//! fabricated success.

use sng_mobile_core::{KeyStoreError, PostureError, TokenStorageError, TunnelError};
use sng_oidc::AuthSurfaceError;
use thiserror::Error;

/// Errors raised by the iOS PAL backends (and their host fallbacks).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IosPalError {
    /// The operation requires an Apple platform and was invoked on a
    /// non-iOS build (the Linux CI host, a desktop dev build, …). The
    /// payload names the operation for the operator log.
    #[error("operation not supported on this platform (requires iOS): {0}")]
    UnsupportedPlatform(String),

    /// A Keychain (`SecItem*`) operation failed.
    #[error("keychain: {0}")]
    Keychain(String),

    /// A `LAContext` biometric / passcode evaluation failed.
    #[error("local-authentication: {0}")]
    Biometric(String),

    /// A `NetworkExtension` (`NETunnelProviderManager`) operation
    /// failed.
    #[error("network-extension: {0}")]
    NetworkExtension(String),

    /// An `ASWebAuthenticationSession` presentation failed.
    #[error("auth-session: {0}")]
    AuthSession(String),

    /// Key material could not be encoded / decoded / parsed.
    #[error("key material: {0}")]
    Key(String),

    /// A stored blob could not be (de)serialized.
    #[error("codec: {0}")]
    Codec(String),
}

impl From<IosPalError> for KeyStoreError {
    fn from(e: IosPalError) -> Self {
        KeyStoreError::Backend(e.to_string())
    }
}

impl From<IosPalError> for TokenStorageError {
    fn from(e: IosPalError) -> Self {
        match e {
            IosPalError::Codec(msg) => TokenStorageError::Corrupt(msg),
            other => TokenStorageError::Backend(other.to_string()),
        }
    }
}

impl From<IosPalError> for PostureError {
    fn from(e: IosPalError) -> Self {
        match e {
            IosPalError::Codec(msg) => PostureError::Encode(msg),
            other => PostureError::Unavailable(other.to_string()),
        }
    }
}

impl From<IosPalError> for TunnelError {
    fn from(e: IosPalError) -> Self {
        match e {
            IosPalError::Key(msg) => TunnelError::Key(msg),
            other => TunnelError::Backend(other.to_string()),
        }
    }
}

impl From<IosPalError> for AuthSurfaceError {
    fn from(e: IosPalError) -> Self {
        match e {
            IosPalError::UnsupportedPlatform(msg) => AuthSurfaceError::Presentation(msg),
            other => AuthSurfaceError::Presentation(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_maps_into_each_trait_error() {
        let mk = || IosPalError::UnsupportedPlatform("collect".into());

        // KeyStore + Tunnel land on their `Backend` variant.
        assert!(matches!(
            KeyStoreError::from(mk()),
            KeyStoreError::Backend(_)
        ));
        assert!(matches!(TunnelError::from(mk()), TunnelError::Backend(_)));

        // TokenStorage + Posture land on their backend / unavailable
        // variant (not their corrupt / encode variant).
        assert!(matches!(
            TokenStorageError::from(mk()),
            TokenStorageError::Backend(_)
        ));
        assert!(matches!(
            PostureError::from(mk()),
            PostureError::Unavailable(_)
        ));

        // AuthSurface maps unsupported onto `Presentation`.
        assert!(matches!(
            AuthSurfaceError::from(mk()),
            AuthSurfaceError::Presentation(_)
        ));
    }

    #[test]
    fn codec_maps_to_corrupt_and_encode() {
        assert!(matches!(
            TokenStorageError::from(IosPalError::Codec("bad json".into())),
            TokenStorageError::Corrupt(_)
        ));
        assert!(matches!(
            PostureError::from(IosPalError::Codec("bad json".into())),
            PostureError::Encode(_)
        ));
    }

    #[test]
    fn key_maps_to_tunnel_key_variant() {
        assert!(matches!(
            TunnelError::from(IosPalError::Key("short".into())),
            TunnelError::Key(_)
        ));
    }

    #[test]
    fn unsupported_message_names_the_operation() {
        let rendered = IosPalError::UnsupportedPlatform("sign".into()).to_string();
        assert!(rendered.contains("sign"));
        assert!(rendered.contains("iOS"));
    }
}

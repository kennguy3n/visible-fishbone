// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Typed-Unsupported host fallback (Linux / macOS / Windows CI).
//!
//! The real platform backings live in `sng-mobile-pal-ios` /
//! `sng-mobile-pal-android` and only enter the build graph under
//! `cfg(target_os = "ios" | "android")` (see this crate's
//! `Cargo.toml` `[target.…]` tables). On any other target — the
//! Linux CI host above all — there is no Keychain, no Android
//! Keystore, no `NEPacketTunnelProvider`, no Custom Tabs. Rather
//! than fake those, this module supplies the **same typed-Unsupported
//! fallback pattern the PAL crates themselves use**: every trait
//! method exists and compiles, and every call returns the trait's
//! own error variant carrying a clear "unsupported on this platform"
//! message. Nothing here ever fakes a success.
//!
//! This keeps the whole workspace compiling, clippy-clean, and
//! unit-testable on the Linux CI host while guaranteeing that a
//! desktop build can never silently behave as if it had a secure
//! enclave or a tunnel. These impls are compiled **only** when the
//! target is neither iOS nor Android.
#![cfg(not(any(target_os = "ios", target_os = "android")))]

use async_trait::async_trait;
use ed25519_dalek::{Signature, VerifyingKey};
use sng_mobile_core::{
    KeyStoreError, MobilePostureCollector, MobilePostureSnapshot, PostureError, SecureKeyStore,
    TunnelConfig, TunnelError, TunnelStatus,
};
use sng_oidc::{AuthSurface, AuthSurfaceError, CallbackUrl};
use url::Url;

/// Message every host-fallback operation reports, naming the
/// operation so a CI / desktop log pinpoints which platform call was
/// attempted.
fn unsupported(op: &str) -> String {
    format!("{op} is unsupported on this platform (no iOS/Android backing on the host build)")
}

/// Host-fallback [`SecureKeyStore`]: no secure enclave on the host.
#[derive(Debug, Default)]
pub struct HostSecureKeyStore;

#[async_trait]
impl SecureKeyStore for HostSecureKeyStore {
    async fn generate_keypair(&self, _label: &str) -> Result<VerifyingKey, KeyStoreError> {
        Err(KeyStoreError::Backend(unsupported("generate_keypair")))
    }
    async fn public_key(&self, _label: &str) -> Result<VerifyingKey, KeyStoreError> {
        Err(KeyStoreError::Backend(unsupported("public_key")))
    }
    async fn sign(&self, _label: &str, _message: &[u8]) -> Result<Signature, KeyStoreError> {
        Err(KeyStoreError::Backend(unsupported("sign")))
    }
    async fn contains(&self, _label: &str) -> Result<bool, KeyStoreError> {
        Err(KeyStoreError::Backend(unsupported("contains")))
    }
    async fn delete(&self, _label: &str) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::Backend(unsupported("delete")))
    }
}

/// Host-fallback [`MobilePostureCollector`]: no device posture
/// source on the host.
#[derive(Debug, Default)]
pub struct HostPostureCollector;

#[async_trait]
impl MobilePostureCollector for HostPostureCollector {
    async fn collect(&self) -> Result<MobilePostureSnapshot, PostureError> {
        Err(PostureError::Unavailable(unsupported("collect")))
    }
}

/// Host-fallback [`MobileTunnelProvider`]: no data-plane tunnel on
/// the host.
#[derive(Debug, Default)]
pub struct HostTunnelProvider;

#[async_trait]
impl sng_mobile_core::MobileTunnelProvider for HostTunnelProvider {
    async fn start_tunnel(&self, _config: TunnelConfig) -> Result<(), TunnelError> {
        Err(TunnelError::Backend(unsupported("start_tunnel")))
    }
    async fn stop_tunnel(&self) -> Result<(), TunnelError> {
        Err(TunnelError::Backend(unsupported("stop_tunnel")))
    }
    async fn status(&self) -> TunnelStatus {
        // `status` is infallible in the trait; the honest host
        // answer is "no tunnel is up", which `Down` expresses
        // without fabricating an `Up` state.
        TunnelStatus::Down
    }
}

/// Host-fallback [`AuthSurface`]: no browser presentation surface
/// (no `ASWebAuthenticationSession` / Custom Tabs) on the host, so
/// the interactive sign-in leg cannot run.
#[derive(Debug, Default)]
pub struct HostAuthSurface;

#[async_trait]
impl AuthSurface for HostAuthSurface {
    async fn present_auth_url(&self, _url: &Url) -> Result<CallbackUrl, AuthSurfaceError> {
        Err(AuthSurfaceError::Presentation(unsupported(
            "present_auth_url",
        )))
    }
}

#[cfg(test)]
mod tests {
    use sng_mobile_core::MobileTunnelProvider;

    use super::*;

    #[tokio::test]
    async fn key_store_never_fakes_an_enclave() {
        let store = HostSecureKeyStore;
        assert!(matches!(
            store.sign("device", b"payload").await,
            Err(KeyStoreError::Backend(_))
        ));
        assert!(matches!(
            store.generate_keypair("device").await,
            Err(KeyStoreError::Backend(_))
        ));
    }

    #[tokio::test]
    async fn posture_is_unavailable() {
        assert!(matches!(
            HostPostureCollector.collect().await,
            Err(PostureError::Unavailable(_))
        ));
    }

    #[tokio::test]
    async fn tunnel_reports_down_without_fabricating_an_up_state() {
        // `status` is infallible; the honest host answer is `Down`,
        // never a fabricated `Up`. The fallible start/stop legs
        // return `TunnelError::Backend` (exercised via the SDK).
        assert_eq!(HostTunnelProvider.status().await, TunnelStatus::Down);
    }

    #[tokio::test]
    async fn auth_surface_cannot_present() {
        let url = Url::parse("https://idp.example.com/authorize").expect("url");
        assert!(matches!(
            HostAuthSurface.present_auth_url(&url).await,
            Err(AuthSurfaceError::Presentation(_))
        ));
    }
}

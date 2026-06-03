//! ShieldNet Gateway — Android Platform Abstraction Layer (PAL).
//!
//! Concrete Android implementations of the mobile traits defined in
//! [`sng_mobile_core`] plus the Android auth surface for
//! [`sng_oidc`]. Each backend talks to the Android framework over
//! JNI, so the real code lives behind `#[cfg(target_os = "android")]`.
//!
//! | Trait (crate)                         | Implementation              | Module          |
//! |---------------------------------------|-----------------------------|-----------------|
//! | [`SecureKeyStore`] (`sng-mobile-core`)| [`AndroidSecureKeyStore`]   | [`keystore`]    |
//! | [`TokenStorage`] (`sng-mobile-core`)  | [`AndroidTokenStorage`]     | [`token_storage`] |
//! | [`MobilePostureCollector`] (core)     | [`AndroidPostureCollector`] | [`posture`]     |
//! | [`MobileTunnelProvider`] (core)       | [`AndroidTunnelProvider`]   | [`tunnel`]      |
//! | [`AuthSurface`] (`sng-oidc`)          | [`AndroidAuthSurface`]      | [`auth_surface`] |
//!
//! ## Host vs Android (the CI constraint)
//!
//! Workspace CI compiles, clippy-lints, and unit-tests this crate
//! on a **Linux x86_64 host** — there is no Android target in CI.
//! Every backend is therefore split in two:
//!
//! * `#[cfg(target_os = "android")]` — the real JNI implementation.
//!   The Android-only crates (`jni`, `ndk-context`) are declared
//!   under `[target.'cfg(target_os = "android")'.dependencies]` so
//!   they never enter the host build graph that CI / cargo-deny
//!   audit.
//! * `#[cfg(not(target_os = "android"))]` — a host fallback whose
//!   trait methods return
//!   [`AndroidPalError::UnsupportedPlatform`] (mapped into the
//!   relevant core trait error). It never panics and never fakes
//!   success.
//!
//! The public types, constructors, and trait impls exist on **all**
//! targets, so `cargo build --workspace` succeeds on the host and a
//! later UniFFI layer can name them regardless of target.
//!
//! All the platform-independent logic — SPKI / signature decoding,
//! token-blob (de)serialization, posture-signal mapping, tunnel
//! config translation, and callback-URL interpretation — is
//! factored into pure functions that the host unit tests exercise
//! directly without an emulator.
//!
//! ## JNI bootstrap
//!
//! On Android the backends obtain the process `JavaVM` and the app
//! `Context` through `ndk-context` (populated by the host app at
//! startup), wrapped in the [`jni_bridge`] module. That module is
//! the *only* place raw-pointer conversions live; it locally
//! relaxes `unsafe_code` with a documented rationale while the rest
//! of the crate stays on the workspace's `unsafe_code = "deny"`
//! posture.

// Test modules use `.unwrap()` / `.expect()` / `assert!` for
// fast-failing fixtures; mirror the per-test allow block the rest of
// the workspace (`sng-mobile-core`, `sng-pal`) uses so those calls
// don't trip the workspace's `clippy::unwrap_used` / `expect_used` /
// `panic` warnings under `-D warnings`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod error;

pub mod auth_surface;
pub mod keystore;
pub mod posture;
pub mod token_storage;
pub mod tunnel;

// Raw-pointer JNI bootstrap — only needed (and only compiled) on
// Android.
#[cfg(target_os = "android")]
mod jni_bridge;

pub use error::AndroidPalError;

pub use auth_surface::{AndroidAuthSurface, DEFAULT_AUTH_TIMEOUT, interpret_callback};
pub use keystore::{
    AndroidSecureKeyStore, STRONGBOX_UNAVAILABLE_EXCEPTION, should_retry_without_strongbox,
    signature_from_raw, verifying_key_from_spki,
};
pub use posture::{
    AndroidPostureCollector, RawPostureSignals, assemble_snapshot, biometric_ready_from_code,
    root_signal,
};
pub use token_storage::{
    AndroidTokenStorage, DEFAULT_PREFS_FILE, TOKEN_SET_KEY, deserialize_token_set,
    serialize_token_set,
};
pub use tunnel::{AndroidTunnelProvider, VpnServiceConfig, translate_config};

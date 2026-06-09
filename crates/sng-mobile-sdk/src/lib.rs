// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! # `sng-mobile-sdk` — the SNG mobile UniFFI binding layer
//!
//! This crate is the single foreign-function interface an iOS
//! (Swift) or Android (Kotlin) app links against to drive the
//! ShieldNet Gateway mobile agent. It is **glue + FFI only**: it
//! composes the already-built mobile pieces and exposes them through
//! UniFFI, adding no new agent behaviour.
//!
//! * [`sng_mobile_core`] — the platform-agnostic agent brain
//!   ([`MobileAgent`](sng_mobile_core::MobileAgent), lifecycle,
//!   enrolment, posture, telemetry, ZTNA).
//! * `sng-mobile-pal-ios` / `sng-mobile-pal-android` — the concrete
//!   [`SecureKeyStore`](sng_mobile_core::SecureKeyStore),
//!   [`TokenStorage`](sng_mobile_core::TokenStorage),
//!   [`MobilePostureCollector`](sng_mobile_core::MobilePostureCollector),
//!   [`MobileTunnelProvider`](sng_mobile_core::MobileTunnelProvider),
//!   and `AuthSurface` backings. They enter the build graph only
//!   under `cfg(target_os = "ios" | "android")`.
//! * [`sng_oidc`] — the pure-Rust OIDC client wired into an
//!   [`AuthSession`](sng_mobile_core::AuthSession) by
//!   [`oidc::OidcAuthSession`].
//!
//! ## Architecture
//!
//! ```text
//!   Swift / Kotlin app
//!          │  (UniFFI bindings)
//!          ▼
//!   ┌──────────────────────┐
//!   │  sng-mobile-sdk      │  this crate: FFI surface + assembly
//!   │  ┌────────────────┐  │
//!   │  │   MobileSdk    │  │  opaque UniFFI Object
//!   │  └───────┬────────┘  │
//!   └──────────┼───────────┘
//!              ▼
//!     sng-mobile-core::MobileAgent
//!        ▲          ▲          ▲
//!        │          │          │
//!    PAL traits   sng-oidc   PolicyTrustStore
//!  (ios/android/  (AuthSession)
//!   host fallback)
//! ```
//!
//! ## Platform selection & the Linux host fallback
//!
//! [`deps::assemble`] picks the iOS PAL on
//! `cfg(target_os = "ios")`, the Android PAL on
//! `cfg(target_os = "android")`, and the typed-Unsupported
//! [`host`] fallback on every other target. The host fallback
//! implements every platform trait but returns each trait's own
//! "unsupported on this platform" error — never a fake success — so
//! the whole workspace compiles, clippy-passes, and unit-tests on
//! the Linux CI host while a desktop build can never behave as if it
//! had a secure enclave or a tunnel.
//!
//! ## `unsafe_code` posture
//!
//! The crate inherits the workspace `unsafe_code = "deny"` lint and
//! adds **no** `#[allow(unsafe_code)]` overrides. UniFFI's
//! procedural-macro mode (selected here via
//! [`uniffi::setup_scaffolding!`] plus `#[uniffi::export]`
//! attributes — no UDL, no `build.rs`) emits its FFI scaffolding
//! with all `unsafe` confined inside the macro-generated code, which
//! carries its own `#[allow(unsafe_code)]`; the binding metadata is
//! embedded into the compiled `cdylib` and read back by the
//! sibling `sng-uniffi-bindgen` binary via `generate --library`.
//! The crate's own source is entirely `unsafe`-free, so no scoped
//! exception is needed (verified under
//! `cargo clippy --all-targets -- -D warnings`).

// `.unwrap()` / `.expect()` are idiomatic fast-fail assertions in
// test scaffolding, and the workspace CI runs
// `cargo clippy --all-targets -- -D warnings`. Allowing them under
// `#[cfg(test)]` only keeps the workspace `unwrap_used` /
// `expect_used` / `panic` lints active for production code without a
// per-test allow, mirroring `sng-mobile-core` / `sng-core`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod config;
pub mod deps;
pub mod error;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod host;
pub mod oidc;
pub mod sdk;
pub mod types;

pub use config::{SdkAuthConfig, SdkMobileConfig, SdkPlatform, SdkTrustAnchor};
pub use error::MobileSdkError;
pub use oidc::OidcAuthSession;
pub use sdk::MobileSdk;
pub use types::{
    SdkAgentHealth, SdkAuthState, SdkEnrollmentOutcome, SdkLifecycleState, SdkPostureSnapshot,
    SdkPowerState, SdkTunnelStatus,
};

uniffi::setup_scaffolding!();

// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! # `sng-mobile-pal-ios`
//!
//! The **iOS Platform Abstraction Layer (PAL)** for the ShieldNet
//! Gateway (SNG) mobile agent. It provides the concrete,
//! Apple-platform implementations of the traits the platform-agnostic
//! [`sng_mobile_core`] "brain" depends on, plus the iOS auth-surface
//! implementation of [`sng_oidc::AuthSurface`].
//!
//! | This crate | implements | backing |
//! |------------|------------|---------|
//! | [`IosSecureKeyStore`] | [`sng_mobile_core::SecureKeyStore`] | Keychain item (Ed25519 seed) |
//! | [`IosTokenStorage`] | [`sng_mobile_core::TokenStorage`] | Keychain item (OIDC token set) |
//! | [`IosPostureCollector`] | [`sng_mobile_core::MobilePostureCollector`] | `LAContext` / `NSProcessInfo` / jailbreak heuristics |
//! | [`IosTunnelProvider`] | [`sng_mobile_core::MobileTunnelProvider`] | `NETunnelProviderManager` (control side of `NEPacketTunnelProvider`) |
//! | [`IosAuthSurface`] | [`sng_oidc::AuthSurface`] | `ASWebAuthenticationSession` |
//!
//! ## How the iOS / host split works
//!
//! CI builds and tests this workspace on a **Linux x86_64 host** with
//! no iOS target. To keep the crate green there while still shipping
//! real Apple-platform code, every module follows the same shape (the
//! same one `crates/sng-pal` uses for its per-OS backends):
//!
//! * The platform-independent **logic** — posture-signal mapping,
//!   callback-URL handling, Ed25519 key encoding, token (de)serialization,
//!   WireGuard tunnel-config translation, error mapping — lives in code
//!   compiled on **every** target and exercised by host unit tests.
//! * The genuine Apple-framework calls live behind
//!   `#[cfg(target_os = "ios")]` (Apple-only crates are declared under a
//!   `[target.'cfg(target_os = "ios")'.dependencies]` table so they never
//!   enter the Linux build graph).
//! * A `#[cfg(not(target_os = "ios"))]` **host fallback** implements the
//!   same trait but returns a typed *unsupported-on-this-platform* error
//!   (never a fake success). The public types, impl structs, and
//!   constructors exist on all targets so `cargo build --workspace`
//!   compiles and the UniFFI layer (Session 7) can name them.
//!
//! The crate is `unsafe`-free except for the small, documented
//! Objective-C bridge call-sites in the iOS-only modules, which carry a
//! scoped `#[allow(unsafe_code)]` exactly as `crates/sng-pal`'s
//! `sysinfo` backends do (the workspace sets `unsafe_code = "deny"`, not
//! `forbid`, precisely to permit such audited leaf exceptions). The
//! safe wrapper crates (`security-framework`, `objc2-*`) contain most of
//! the unsafe for us.

// `.unwrap()` / `.expect()` / `panic!` are idiomatic fast-fail
// assertions in test scaffolding; the workspace CI runs
// `cargo clippy --all-targets -D warnings`. Allowing them under
// `#[cfg(test)]` only keeps the workspace `unwrap_used` / `expect_used`
// / `panic` lints active for production code without a per-test allow,
// mirroring `sng-mobile-core` / `sng-pal`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic,))]

pub mod auth_surface;
pub mod error;
pub mod keystore;
pub mod posture;
pub mod token_storage;
pub mod tunnel;

pub use auth_surface::IosAuthSurface;
pub use error::IosPalError;
pub use keystore::IosSecureKeyStore;
pub use posture::IosPostureCollector;
pub use token_storage::IosTokenStorage;
pub use tunnel::{IosTunnelProvider, WireGuardSettings};

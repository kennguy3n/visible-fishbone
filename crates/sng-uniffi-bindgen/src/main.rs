// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Workspace-local UniFFI binding generator.
//!
//! This binary is a one-line wrapper around
//! [`uniffi::uniffi_bindgen_main`] — the very entry point the
//! upstream `uniffi-bindgen` CLI uses. Vendoring it as a workspace
//! member (rather than relying on a separately-installed
//! `uniffi-bindgen`) guarantees the generator version always equals
//! the `uniffi` version compiled into `sng-mobile-sdk`'s cdylib, so
//! the generated Swift / Kotlin bindings can never drift from the
//! embedded scaffolding's ABI.
//!
//! ## Usage
//!
//! Build the SDK cdylib, then generate from the compiled library
//! (the `--library` mode reads the binding metadata UniFFI embeds in
//! the artifact, so no UDL is involved):
//!
//! ```sh
//! cargo build -p sng-mobile-sdk --release
//!
//! # Swift
//! cargo run -p sng-uniffi-bindgen -- generate \
//!     --library target/release/libsng_mobile_sdk.so \
//!     --language swift --out-dir bindings/swift
//!
//! # Kotlin
//! cargo run -p sng-uniffi-bindgen -- generate \
//!     --library target/release/libsng_mobile_sdk.so \
//!     --language kotlin --out-dir bindings/kotlin
//! ```

fn main() {
    uniffi::uniffi_bindgen_main();
}

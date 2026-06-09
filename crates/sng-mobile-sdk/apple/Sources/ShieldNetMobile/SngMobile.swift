// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

// Hand-written Swift surface for the ShieldNet Gateway mobile SDK.
//
// The bulk of this module — the `MobileSdk` object, the `Sdk*`
// records/enums, and `MobileSdkError` — is the UniFFI-generated
// `sng_mobile_sdk.swift`, which `build-xcframework.sh` copies into
// this directory alongside this file (it is git-ignored; never
// hand-edit or commit it). Keep hand-written Swift ergonomics here.
//
// This file intentionally references no generated symbols so the
// package directory stays tracked and this source stays independently
// valid even before the bindings are generated.

/// Caseless namespace for package-level metadata.
public enum SngMobile {
    /// The `sng-mobile-sdk` crate version this Swift surface is built
    /// against. Kept in step with the crate's `Cargo.toml` `version`
    /// (workspace-pinned) by `build-xcframework.sh`, which fails the
    /// build if the two drift.
    public static let version = "0.1.0"
}

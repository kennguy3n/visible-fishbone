// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
#![doc = include_str!("../README.md")]
// See the matching block in `crates/sng-core/src/lib.rs`. The
// per-test allow set is duplicated here because Rust attributes
// do not span crate boundaries and the dev-experience cost of a
// shared macro is higher than maintaining the short list in two
// places.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::float_cmp,
    )
)]

//! Trait definitions are at the crate root so consumers do not
//! have to care which OS the agent is running on. Per-OS
//! implementations live behind `cfg(target_os = "…")` in the
//! sibling modules.

pub mod budget;
pub mod keystore;
pub mod posture;
pub mod sysinfo;
pub mod traffic;
pub mod tunnel;

pub use budget::{CpuBudget, MemoryBudget, ResourceBudgetReport};
pub use keystore::{KeyHandle, KeyStoreError, SecureKeyStore};
pub use posture::{
    DiskEncryptionState, FirewallState, PostureCollector, PostureSnapshot, ScreenLockState,
};
pub use sysinfo::{OsRelease, SystemInfo, SystemInfoError};
pub use traffic::{PacketRecord, TrafficCapture, TrafficCaptureError};
pub use tunnel::{TunnelConfig, TunnelHandle, TunnelProvider, TunnelProviderError};

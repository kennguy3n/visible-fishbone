// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
#![doc = include_str!("../README.md")]
// Test-only allows: the test modules use `.unwrap()` / `.expect()` /
// `panic!` for fast-failing fixture assertions, and exercise numeric
// conversions that are bounded in-range at the call site. The workspace
// lints keep these denied on production paths; CI runs
// `cargo clippy --tests -D warnings` so the relaxation is scoped to
// `#[cfg(test)]` only.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_lossless,
    )
)]

//! `sng-ebpf` — eBPF/XDP fast-path data plane for the SNG edge VM.
//!
//! The default packet path is nftables + conntrack (`sng-fw`). This
//! crate is the opt-in fast path ARCHITECTURE.md §4.1 reserves for "the
//! point where measured throughput demand justifies the operational
//! cost": an XDP ingress program that classifies and L3/L4-filters
//! packets at the earliest kernel hook, a TC egress program that steers
//! flows onto the right underlay, and the BPF maps that carry per-flow
//! state, connection tracking, and a policy verdict cache between them.
//!
//! # Userspace vs. kernel split
//!
//! The kernel-space programs are a separate `no_std` compilation unit
//! built for a BPF target by the appliance image pipeline — *not* by
//! `cargo build --workspace`. This crate is the **userspace half**: the
//! types, classification / rule-evaluation logic, map models, and the
//! control plane that loads, pins, and updates the kernel programs and
//! maps.
//!
//! Everything here compiles and unit-tests on any target without an eBPF
//! toolchain or a Linux kernel. The real kernel loader is behind the
//! `xdp` feature (Linux-only); with the feature off, the control plane
//! runs over a [`loader::NoopLoader`] that models every map in userspace
//! — the "graceful fallback" that keeps the workspace build green in
//! environments without eBPF support and lets the firewall crate's
//! `EbpfBackend` be exercised end-to-end in CI.
//!
//! # Module map
//!
//! * [`class`] — the six [`TrafficClass`] steering tiers and the XDP
//!   classifier that assigns them.
//! * [`firewall`] — the hot-path L3/L4 rule set the XDP program walks.
//! * [`maps`] — `#[repr(C)]` map key/value layouts and the TTL verdict
//!   cache.
//! * [`tc`] — the TC egress steering table.
//! * [`loader`] — the [`loader::ProgramLoader`] abstraction, the no-op
//!   model, and the feature-gated `aya` kernel loader.
//! * [`control`] — [`control::XdpControlPlane`], the handle the firewall
//!   crate drives.

pub mod class;
pub mod control;
pub mod error;
pub mod firewall;
pub mod loader;
pub mod maps;
pub mod tc;

pub use class::{ClassRule, ClassVerdict, Classifier, XdpAction, verdict_for};
pub use control::{AttachOutcome, XdpCapabilities, XdpControlPlane, XdpStats};
pub use error::EbpfError;
pub use firewall::{PortRange, XdpDecision, XdpRule, XdpRuleAction, XdpRuleSet};
pub use loader::{NoopLoader, ProgramLoader, XdpMode, detect_xdp_capable};
pub use maps::{
    ConntrackEntry, ConntrackState, FlowKey, FlowState, PolicyVerdictCache, VerdictCacheEntry,
};
pub use tc::{EgressSteeringTable, SteeringAction, SteeringTarget};

#[cfg(all(feature = "xdp", target_os = "linux"))]
pub use loader::AyaLoader;

// Re-export the foundation type so a caller can match on classification
// verdicts without depending on sng-core directly.
pub use sng_core::TrafficClass;

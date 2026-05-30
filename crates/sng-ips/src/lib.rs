//! IPS subsystem for the ShieldNet Gateway agent / edge.
//!
//! `sng-ips` is the **signature-based intrusion prevention
//! brain**. It sits next to [`sng_fw`] in the stack: where
//! the firewall makes per-flow allow/deny decisions on
//! (5-tuple, app-id, policy), the IPS scans the payload of
//! permitted flows against a compiled signature set and
//! produces alerts / blocks on pattern hits.
//!
//! Like `sng-fw`, this crate is the brain, not the datapath:
//! it accepts `PayloadObservation`s from the forwarding
//! layer and returns `InspectionDecision`s. The data path
//! stays in C/eBPF/PAL.
//!
//! ### Module layout
//!
//! - [`error`] — [`IpsError`] mapped to
//!   [`sng_core::error::ErrorCode`].
//! - [`signature`] — typed [`signature::Signature`],
//!   [`signature::Pattern`], [`signature::Severity`],
//!   [`signature::Action`].
//! - [`matcher`] — compiled [`matcher::SignatureSet`]:
//!   Aho-Corasick for literals + `regex::bytes` for
//!   regex. Returns [`matcher::IpsHit`]s.
//! - [`reassembly`] — per-flow TCP segment reassembly
//!   buffer ([`reassembly::ReassemblyBuffer`]) and the
//!   flow-keyed [`reassembly::ReassemblyTable`] that
//!   holds them.
//! - [`stats`] — atomic counters surfaced to ops
//!   dashboards.
//! - [`service`] — [`service::IpsService`] orchestrator
//!   tying matcher, reassembly, telemetry, and stats
//!   together.
//!
//! ### Concurrency model
//!
//! The [`matcher::SignatureSet`] is immutable after
//! compile; hot-swaps go through an `ArcSwap` inside
//! [`service::IpsService`] so the data path never blocks
//! on a policy reload. The reassembly table uses a
//! parking_lot Mutex with short critical sections; the
//! per-flow buffer is an `Arc<ReassemblyBuffer>` so the
//! scan runs outside the table lock.
//!
//! Telemetry submission uses `try_send` so the data path
//! never blocks on a saturated pipeline — drops are
//! credited to a counter the operator can see.

// Test-only allows mirror the sister sng-fw / sng-dns
// crates so the workspace lints stay consistent.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::match_wildcard_for_single_variants,
        clippy::too_many_lines
    )
)]

pub mod error;
pub mod matcher;
pub mod reassembly;
pub mod service;
pub mod signature;
pub mod stats;

pub use error::IpsError;
pub use matcher::{IpsHit, ScanContext, SharedSignatureSet, SignatureKey, SignatureSet};
pub use reassembly::{Direction, ReassemblyBuffer, ReassemblyConfig, ReassemblyTable};
pub use service::{InspectionDecision, IpsService, IpsServiceConfig, PayloadObservation};
pub use signature::{Action, Anchor, Pattern, PortFilter, Severity, Signature};
pub use stats::{IpsStats, IpsStatsSnapshot};

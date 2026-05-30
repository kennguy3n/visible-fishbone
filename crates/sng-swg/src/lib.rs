//! Secure Web Gateway brain for the ShieldNet Gateway.
//!
//! `sng-swg` is the **policy and verdict brain** that
//! the L7 proxy (Envoy, sng-edge) talks to per HTTP
//! transaction. The brain does no I/O: it owns the
//! per-tenant URL category cache, the reputation feed
//! snapshot, the malware verdict trait, and the per-
//! category posture map, then converts an
//! [`HttpObservation`] into a [`SwgDecision`].
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     observation     ┌─────────────────┐
//! │  Envoy /    │  ──────────────────▶│   SwgService    │
//! │  sng-edge   │                     │                 │
//! │  (data path)│  ◀──── decision ────│  category /     │
//! └─────────────┘                     │  reputation /   │
//!                                     │  malware /      │
//!                                     │  policy holder  │
//!                                     └─────┬───────────┘
//!                                           │try_send
//!                                           ▼
//!                                ┌──────────────────────┐
//!                                │  sng-telemetry       │
//!                                │  PipelineHandle      │
//!                                └──────────────────────┘
//! ```
//!
//! ## Hot-path properties
//!
//! - **No async, no I/O.** The observe call is a sync
//!   function; providers are expected to keep their
//!   tables in-process and refresh them off the request
//!   path.
//! - **Lock-free policy reads.** The policy holder wraps
//!   the active [`SwgPolicy`] in an
//!   [`arc_swap::ArcSwap`]; observe reads with one
//!   atomic load.
//! - **Telemetry never blocks.** Egress goes through
//!   [`tokio::sync::mpsc::Sender::try_send`]; saturated
//!   pipelines drop events and credit
//!   [`SwgStats::record_telemetry_drop`].
//!
//! ## Crate layout
//!
//! - [`error`] — [`SwgError`] taxonomy mapped to
//!   [`sng_core::error::ErrorCode`].
//! - [`category`] — [`Category`] enum + suffix-walking
//!   in-memory [`StaticCategoryProvider`].
//! - [`reputation`] — clamped [`ReputationScore`] +
//!   in-memory [`StaticReputationProvider`].
//! - [`malware`] — [`MalwareVerdict`] tri-state +
//!   [`StaticMalwareProvider`] keyed on SHA-256.
//! - [`policy`] — per-category [`Posture`] map +
//!   reputation upgrades + malware overrides.
//! - [`request`] — [`HttpObservation`] /
//!   [`ObservationPhase`].
//! - [`stats`] — atomic counter bank +
//!   [`SwgStatsSnapshot`].
//! - [`service`] — [`SwgService`] orchestrator.

// Test-only allows mirror the sister sng-fw / sng-dns /
// sng-ips crates so the workspace lints stay consistent.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::float_cmp,
        clippy::useless_vec,
        clippy::explicit_iter_loop,
        clippy::single_match_else,
        clippy::match_wildcard_for_single_variants,
        clippy::too_many_lines
    )
)]

pub mod category;
pub mod error;
pub mod malware;
pub mod policy;
pub mod reputation;
pub mod request;
pub mod service;
pub mod stats;

pub use category::{Category, CategoryProvider, StaticCategoryProvider};
pub use error::SwgError;
pub use malware::{MalwareProvider, MalwareVerdict, ScanRequest, StaticMalwareProvider};
pub use policy::{DecisionInputs, Posture, SwgPolicy, SwgPolicyHolder, evaluate_policy};
pub use reputation::{ReputationProvider, ReputationScore, StaticReputationProvider};
pub use request::{HttpObservation, ObservationPhase};
pub use service::{
    SwgDecision, SwgService, SwgServiceBuilder, SwgServiceConfig, posture_to_verdict,
};
pub use stats::{SwgStats, SwgStatsSnapshot};

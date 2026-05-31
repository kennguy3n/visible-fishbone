//! SD-WAN steering brain for the ShieldNet Gateway.
//!
//! `sng-sdwan` is the **path-selection brain** that the
//! data path consults for every steerable flow. Given a
//! [`SteeringRequest`] (tenant, traffic class, flow id),
//! the brain joins three signals:
//!
//! 1. **Path catalog** ([`PathProvider`]) — the static
//!    set of underlay paths available to this tenant
//!    (MPLS, internet-A, internet-B, LTE, etc.) with
//!    their `traffic_class` eligibility.
//! 2. **Liveness probes** ([`ProbeProvider`]) — the
//!    most-recent [`PathProbe`] for each candidate path,
//!    carrying observed latency / loss / jitter and an
//!    epoch-millisecond timestamp.
//! 3. **Policy** ([`SdwanPolicy`]) — the score weight
//!    vector, the per-metric SLO floors, and the
//!    operator-configured probe freshness budget.
//!
//! The brain computes a weighted composite score for each
//! candidate path (lower = better), picks the lowest-
//! scoring fresh path, and returns a
//! [`SteeringDecision`] carrying the selected path id,
//! the score, and a structured [`SteeringReason`].
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐    SteeringRequest    ┌─────────────────┐
//! │   sng-edge  │  ──────────────────▶  │   SdwanService  │
//! │  (data path)│                       │                 │
//! │             │ ◀── SteeringDecision ─│  path /         │
//! └─────────────┘                       │  probe /        │
//!                                       │  policy holder  │
//!                                       └─────┬───────────┘
//!                                             │try_send
//!                                             ▼
//!                                  ┌──────────────────────┐
//!                                  │  sng-telemetry       │
//!                                  │  PipelineHandle      │
//!                                  └──────────────────────┘
//! ```
//!
//! ## Invariants
//!
//! 1. **Stale-probe-is-deny.** A path whose most-recent
//!    probe is older than the policy's freshness budget
//!    is treated as unknown — it never wins selection,
//!    even if its last-observed metrics were excellent.
//! 2. **No-path-is-deny.** If zero paths are eligible
//!    for the requested traffic class (or every eligible
//!    path is stale), the brain returns
//!    [`SteeringReason::NoAvailablePath`] /
//!    [`SteeringReason::AllProbesStale`] respectively —
//!    *not* a silent best-effort pick. The data path is
//!    expected to map this to a deny verdict, not to a
//!    fallthrough.
//! 3. **Lock-free policy reads.** The policy holder wraps
//!    the active [`SdwanPolicy`] in an
//!    [`arc_swap::ArcSwap`]; `evaluate` reads with one
//!    atomic load.
//! 4. **Telemetry never blocks.** Egress goes through
//!    [`tokio::sync::mpsc::Sender::try_send`]; saturated
//!    pipelines drop events and credit
//!    [`SdwanStats::record_telemetry_drop`].
//!
//! ## Crate layout
//!
//! - [`error`] — [`SdwanError`] taxonomy mapped to
//!   [`sng_core::error::ErrorCode`].
//! - [`path`] — [`Path`] / [`PathId`] +
//!   [`PathProvider`] / [`StaticPathProvider`].
//! - [`probe`] — [`PathProbe`] +
//!   [`ProbeProvider`] / [`StaticProbeProvider`].
//! - [`score`] — pure [`score_path`] function over
//!   [`ScoreWeights`] producing a [`ScoreBreakdown`].
//! - [`policy`] — [`SdwanPolicy`] / [`ScoreWeights`] /
//!   [`SdwanPolicyHolder`] with `try_new` / `try_replace`.
//! - [`request`] — [`SteeringRequest`].
//! - [`decision`] — [`SteeringDecision`] +
//!   [`SteeringReason`].
//! - [`stats`] — atomic counter bank + snapshot.
//! - [`service`] — [`SdwanService`] orchestrator +
//!   [`SdwanServiceBuilder`].

// Test-only allows mirror the sister sng-swg / sng-ztna
// crates so the workspace lints stay consistent across
// the L3-L7 brains.
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

pub mod decision;
pub mod error;
pub mod path;
pub mod policy;
pub mod probe;
pub mod request;
pub mod score;
pub mod service;
pub mod stats;

pub use decision::{SteeringDecision, SteeringReason};
pub use error::SdwanError;
pub use path::{Path, PathId, PathProvider, StaticPathProvider, TrafficClass};
pub use policy::{ScoreWeights, SdwanPolicy, SdwanPolicyHolder};
pub use probe::{PathProbe, ProbeProvider, StaticProbeProvider};
pub use request::SteeringRequest;
pub use score::{ScoreBreakdown, score_path};
pub use service::{SdwanService, SdwanServiceBuilder, SdwanServiceConfig};
pub use stats::{SdwanStats, SdwanStatsSnapshot};

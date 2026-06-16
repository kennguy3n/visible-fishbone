//! Lightweight Digital Experience Monitoring (DEM) probe engine for
//! the ShieldNet Gateway.
//!
//! `sng-dem` is the **edge/agent half** of DEM — a Zscaler ZDX-style
//! end-to-end user-experience signal. Where [`sng_sdwan`] is the
//! *path-selection brain* that consumes probe data to steer flows,
//! `sng-dem` is the *experience probe* that measures how reachable
//! and fast a small set of critical SaaS targets actually are from
//! where the user sits.
//!
//! Given a set of [`Target`]s, a [`ProbeEngine`] runs cheap synthetic
//! probes — DNS resolution, TCP connect, and HTTP(S) TTFB / total
//! latency — and emits one structured [`ProbeResult`] per target. The
//! control-plane service `internal/service/dem` ingests those
//! results, rolls them into per-tenant per-target **experience
//! scores**, and raises degradation alerts.
//!
//! ## Design goals
//!
//! * **Bounded cost at fleet scale.** Designed for 5,000 no-ops SME
//!   tenants: a concurrency ceiling, a per-sweep target cap, hard
//!   per-probe timeouts, and startup jitter keep a fleet from
//!   synchronising into a probe storm. See [`EngineConfig`] and
//!   [`ProbeEngine::probe_all`].
//! * **Graceful degradation.** An unreachable target is a first-class
//!   signal (`success == false`), never a crash or an aborted sweep.
//! * **Deterministic tests.** DNS resolution goes through a pluggable
//!   [`Resolver`] so the engine can be exercised end-to-end against
//!   loopback listeners and in-process HTTP mocks with no live
//!   network — including the timeout path under a paused clock.
//! * **No `openssl`.** HTTP(S) probing uses `reqwest` with `rustls`,
//!   honouring the workspace `cargo-deny` ban on `native-tls`.
//!
//! ## Crate layout
//!
//! - [`error`] — [`DemError`] taxonomy mapped to
//!   [`sng_core::error::ErrorCode`].
//! - [`target`] — [`Target`], [`ProbeKind`], and the [`EngineConfig`]
//!   cost model.
//! - [`result`] — [`ProbeResult`] / [`ProbeErrorKind`], the wire
//!   contract with the Go ingest endpoint.
//! - [`resolver`] — the pluggable [`Resolver`] + [`SystemResolver`].
//! - [`probe`] — the [`ProbeEngine`].
//! - [`score`] — [`network_score`], an optional per-probe diagnostic
//!   reusing [`sng_sdwan`]'s public cost-model scorer.

// Test-only allows mirror the sister sng-sdwan crate so the workspace
// lints stay consistent across the data-plane crates.
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

pub mod error;
pub mod probe;
pub mod resolver;
pub mod result;
pub mod score;
pub mod target;

pub use error::DemError;
pub use probe::ProbeEngine;
pub use resolver::{Resolver, SystemResolver};
pub use result::{ProbeErrorKind, ProbeResult};
pub use score::network_score;
pub use target::{EngineConfig, MAX_TIMEOUT_MS, MIN_TIMEOUT_MS, ProbeKind, Target};

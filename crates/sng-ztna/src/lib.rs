//! # sng-ztna — Zero-Trust Network Access subsystem
//!
//! ZTNA is the per-application access broker. Where the
//! firewall (`sng-fw`) decides whether a 5-tuple may pass
//! and the SWG (`sng-swg`) decides what a web request may
//! retrieve, ZTNA decides whether a *specific identity on
//! a specific device* may reach a *specific application*.
//!
//! Conceptually each access attempt is a join of three
//! providers:
//!
//! - **App catalog** ([`app::AppCatalogProvider`]) — what
//!   apps does this tenant publish, what are their URL /
//!   host patterns, what *minimum* posture do they
//!   require, what groups are entitled.
//! - **Identity** ([`identity::IdentityProvider`]) — given
//!   a verified user id (`sub` from the IdP or the SPIFFE
//!   ID from the mTLS chain), what groups does the user
//!   belong to, and is MFA still fresh.
//! - **Device trust** ([`device::DeviceTrustProvider`]) —
//!   given a device id (the certificate fingerprint that
//!   passed mTLS), is the device enrolled, what is its
//!   live posture snapshot, when was it last attested.
//!
//! [`service::ZtnaService::evaluate`] is the brain's entry
//! point. The path is:
//!
//! 1. Resolve the app from `app_id` (deny + `unknown_app`
//!    if not found).
//! 2. Resolve the device trust + posture snapshot
//!    (deny + `device_unknown` / `device_not_enrolled`).
//! 3. Resolve the identity groups + MFA freshness
//!    (deny + `identity_unverified` /
//!    `mfa_stale`).
//! 4. Run the policy ([`policy::evaluate_policy`]):
//!    join the three signals into an
//!    [`policy::ZtnaDecision`].
//! 5. Emit one [`sng_core::events::ZtnaEvent`] via the
//!    telemetry channel — `try_send`, never blocking.
//!
//! The whole entry point is **sync** — no I/O. Providers
//! are expected to do their I/O off the request path
//! (downloader tasks refresh in-process tables;
//! producer-side caches sit in front of remote APIs).
//!
//! ## Hot-path properties
//!
//! - **Sync evaluate call**: providers keep their tables
//!   in-process and refresh off the request path.
//! - **Lock-free policy reads**: the policy holder wraps
//!   the active [`policy::ZtnaPolicy`] in
//!   `arc_swap::ArcSwap`; evaluate reads with one atomic
//!   load.
//! - **Telemetry never blocks**: egress uses
//!   `tokio::sync::mpsc::Sender::try_send`; saturated
//!   pipelines drop events and credit
//!   [`stats::ZtnaStats::record_telemetry_drop`].
//!
//! ## Crate layout
//!
//! - [`error`]  — taxonomy of `ZtnaError`s mapped to
//!   [`sng_core::error::ErrorCode`].
//! - [`app`]    — `App`, `AppCatalogProvider`, the
//!   in-process `StaticAppCatalog`.
//! - [`device`] — `DevicePosture`, `DeviceTrust`,
//!   `DeviceTrustProvider`, `StaticDeviceTrustProvider`.
//! - [`identity`] — `UserIdentity`, `IdentityProvider`,
//!   `StaticIdentityProvider`.
//! - [`policy`] — `ZtnaPolicy` (per-app posture
//!   requirements + group entitlements) +
//!   `evaluate_policy` decision function +
//!   `ZtnaPolicyHolder` (ArcSwap wrapper).
//! - [`request`] — `AccessRequest` input type.
//! - [`stats`]  — atomic counters + serializable
//!   snapshot.
//! - [`service`] — `ZtnaService` orchestrator +
//!   `ZtnaServiceBuilder`.

// Test-only allows mirror the sister sng-fw / sng-dns /
// sng-ips / sng-swg crates so the workspace lints stay
// consistent.
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
        clippy::too_many_lines,
        clippy::fn_params_excessive_bools,
        clippy::struct_excessive_bools,
        clippy::missing_panics_doc,
        clippy::missing_errors_doc
    )
)]

pub mod app;
pub mod device;
pub mod error;
pub mod identity;
pub mod policy;
pub mod request;
pub mod service;
pub mod stats;

pub use app::{App, AppCatalogProvider, StaticAppCatalog};
pub use device::{
    ArcSwapDeviceTrustProvider, DevicePosture, DeviceTrust, DeviceTrustProvider,
    StaticDeviceTrustProvider,
};
pub use error::ZtnaError;
pub use identity::{IdentityProvider, StaticIdentityProvider, UserIdentity};
pub use policy::{
    AccessConditions, PostureRequirement, RevocationProvider, StaticRevocationList, TagCondition,
    TagOp, TimeWindow, ZtnaDecision, ZtnaDecisionReason, ZtnaPolicy, ZtnaPolicyHolder,
    evaluate_policy,
};
pub use request::{AccessRequest, NetworkType};
pub use service::{ZtnaService, ZtnaServiceBuilder, ZtnaServiceConfig};
pub use stats::{ZtnaStats, ZtnaStatsSnapshot};

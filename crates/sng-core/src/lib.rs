// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
#![doc = include_str!("../README.md")]
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding and CI runs `cargo clippy --tests -D warnings`
// across the workspace. Allowing them in `#[cfg(test)]` only
// keeps the workspace-wide lints active for production code
// without producing dozens of per-test allow attributes.
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

//! `sng-core` is the foundation crate of the ShieldNet Gateway
//! endpoint / edge workspace. Every other crate (`sng-comms`,
//! `sng-policy-eval`, `sng-telemetry`, `sng-dns`, `sng-fw`,
//! `sng-ips`, `sng-swg`, `sng-ztna`, `sng-sdwan`, `sng-updater`
//! and the two binary crates `sng-edge` / `sng-agent`) depends on
//! the primitives published from here:
//!
//! * **Identifier types** — strongly-typed UUID newtypes for
//!   tenants, devices, sites, policy bundles, policy graphs,
//!   policy signing keys, claim tokens, and event ids. The
//!   newtypes are what stop a `DeviceId` being passed where a
//!   `TenantId` is required at compile time, which is the single
//!   most common bug class in a multi-tenant control plane.
//!
//! * **Traffic class enum** — the closed set of six per-flow
//!   steering tiers (`trusted_direct`, `trusted_media_bypass`,
//!   `inspect_lite`, `inspect_full`, `tunnel_private`, `block`).
//!   Wire-compatible with the Go side
//!   ([`repository.TrafficClass`](../../../internal/repository/app_registry.go))
//!   so the edge agent emits the same values the control plane
//!   stores in Postgres / ClickHouse.
//!
//! * **Policy bundle target enum** — one of `edge`, `endpoint`,
//!   `cloud`, `mobile`. Matches
//!   [`repository.PolicyBundleTarget`](../../../internal/repository/types.go).
//!
//! * **Event envelope** — MessagePack-encoded envelope plus
//!   typed per-class payloads. Field-tagged so the bytes a Rust
//!   producer emits round-trip byte-identical through the Go
//!   schema validator, which is the wire-compatibility test that
//!   protects the NATS JetStream pipeline.
//!
//! * **Policy bundle verification** — Ed25519 signature
//!   verification of MessagePack-encoded bundles signed by the
//!   control plane (`crypto/ed25519` Go side, `ed25519-dalek`
//!   Rust side; same curve, same byte layout). Includes
//!   bundle version metadata, target type, and the verifier's
//!   key trust store.
//!
//! * **Error taxonomy** — [`error::SngError`] is the workspace
//!   error type. Each variant carries a stable `code()` string
//!   that matches the Go control plane's error schema so SRE
//!   dashboards and runbooks can correlate failures across the
//!   stack without per-language code translation.
//!
//! * **Configuration loader** — env + optional file layered
//!   config via `figment`, validated at startup. The single
//!   `Config::load()` entry point is the boundary that turns
//!   operator intent (env vars, /etc/sng/config.toml) into the
//!   typed struct the rest of the workspace consumes.
//!
//! * **Lifecycle plumbing** — [`lifecycle::ShutdownSignal`] +
//!   [`lifecycle::Health`] + [`lifecycle::HealthCheck`]: the
//!   trait + signal pair every long-running module in the
//!   workspace plugs into so a single `Ctrl-C` /
//!   `systemctl stop sng-agent` drains every subsystem in
//!   bounded time. The [`supervisor`] module then composes
//!   those primitives into a runnable [`supervisor::Supervisor`]
//!   that the two binary crates (`sng-edge`, `sng-agent`) and
//!   the integration-test harness use as their `main`-level
//!   orchestrator.
//!
//! The crate is `#![forbid(unsafe_code)]` and ships under the
//! same workspace-pedantic-clippy lint profile as the rest of the
//! tree.

pub mod config;
pub mod envelope;
pub mod error;
pub mod events;
pub mod ids;
pub mod lifecycle;
pub mod policy;
pub mod restart;
pub mod supervisor;
pub mod traffic_class;

pub use config::{AgentMode, Config, ConfigError};
pub use envelope::{
    Envelope, EventClass, Marshal, Platform, SCHEMA_VERSION, Verdict, WireError, pack_payload,
    unpack_payload, wrap_flow_event,
};
pub use error::{ErrorCode, SngError, SngResult};
pub use events::{
    AgentEvent, DlpAction, DlpEvent, DlpFinding, DlpFindingKind, DnsEvent, FlowEvent, HttpEvent,
    IpsEvent, SdwanEvent, SubsystemRestart,
    SubsystemRestartOutcome, SubsystemRestartReason, ZtnaEvent,
};
pub use ids::{
    ClaimTokenId, DeviceId, EventId, InvalidPolicySigningKeyId, PolicyBundleId, PolicyGraphId,
    PolicySigningKeyId, SiteId, TenantId,
};
pub use lifecycle::{
    DrainTimeout, Health, HealthCheck, HealthStatus, ShutdownSignal, ShutdownTrigger,
    SubsystemHealth,
};
pub use policy::{
    AddKeyError, BundleSignature, BundleTarget, PolicyBundle, PolicyBundleClaims, PolicyVerifier,
    UnknownBundleTarget, VerificationError,
};
pub use restart::{NoopRestartSink, SubsystemRestartSink};
pub use supervisor::{
    DEFAULT_DRAIN_BUDGET, DEFAULT_HEALTH_INTERVAL, DEFAULT_HEALTH_PROBE_BUDGET, DrainOutcome,
    DrainResult, Subsystem, SubsystemError, SubsystemHandle, Supervisor, SupervisorBuilder,
    SupervisorExit, SupervisorReport, SupervisorRunError,
};
pub use traffic_class::TrafficClass;

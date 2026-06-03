//! # `sng-mobile-core`
//!
//! The platform-agnostic **mobile agent core** for the ShieldNet
//! Gateway (SNG). This crate is the "brain" that the iOS
//! (`NEPacketTunnelProvider`) and Android (`VpnService`) Platform
//! Abstraction Layers (PALs) plug into through a UniFFI binding
//! layer built on top of it.
//!
//! It is pure Rust with no FFI of its own — `#![forbid(unsafe_code)]`
//! is enforced crate-wide — and it performs no direct filesystem,
//! keychain, or platform-API access. Everything platform-specific
//! is expressed as a **trait** the PAL implements and hands in as an
//! `Arc<dyn …>`:
//!
//! | Trait | Responsibility | iOS / Android backing |
//! |-------|----------------|-----------------------|
//! | [`SecureKeyStore`] | Ed25519 enrolment-key keygen / sign / store | Secure Enclave / StrongBox + Keystore |
//! | [`TokenStorage`] | Persist the OIDC token set | Keychain / `EncryptedSharedPreferences` |
//! | [`AuthSession`] | Acquire + refresh OIDC tokens | `sng-oidc` (Session 7) |
//! | [`MobilePostureCollector`] | Snapshot device security posture | `LAContext` / Play Integrity |
//! | [`MobileTunnelProvider`] | Bring the data-plane tunnel up / down | `NEPacketTunnelProvider` / `VpnService` |
//!
//! The [`MobileAgent`] ties these together behind an explicit
//! [`LifecycleState`] machine and a coalescing [`Scheduler`] that
//! keeps periodic work down to a single timer wakeup per cycle, in
//! service of the sub-0.5%-idle-CPU mobile power budget. Sensitive
//! material (tokens, private keys) is held in `zeroize`-on-drop
//! wrappers so it does not linger in a heap snapshot.
//!
//! ## Subsystems
//!
//! * [`enrollment`] — claim-token device enrolment (mirrors the
//!   desktop `sng-agent` flow).
//! * [`auth`] — OIDC token-lifecycle state + refresh scheduling.
//! * [`posture`] — device posture snapshot model + collector trait.
//! * [`tunnel`] — WireGuard-class tunnel key lifecycle + provider
//!   trait.
//! * [`ztna`] — per-app ZTNA evaluation over the local policy
//!   bundle (reuses [`sng_ztna`]).
//! * [`telemetry`] — metadata-only mobile telemetry events spooled
//!   + batch-uploaded via [`sng_comms`].

#![forbid(unsafe_code)]
// `.unwrap()` / `.expect()` are idiomatic fast-fail assertions in
// test scaffolding, and the workspace CI runs
// `cargo clippy --all-targets -D warnings`. Allowing them under
// `#[cfg(test)]` only keeps the workspace `unwrap_used` / `expect_used`
// / `panic` lints active for production code without a per-test allow,
// mirroring `sng-core` / `sng-comms` / `sng-ztna`.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod agent;
pub mod auth;
pub mod config;
pub mod enrollment;
pub mod error;
pub mod posture;
pub mod telemetry;
pub mod tunnel;
pub mod ztna;

pub use agent::{
    AgentHealth, AgentLifecycle, LifecycleState, MobileAgent, MobileAgentDeps, ScheduledTask,
    Scheduler,
};
pub use auth::{
    AccessToken, AuthError, AuthSession, AuthState, IdToken, InMemoryTokenStorage, RefreshToken,
    TokenSet, TokenStorage, TokenStorageError, refresh_delay, schedule_refresh,
};
pub use config::{AuthConfig, MobileAgentConfig, MobilePlatform};
pub use enrollment::{
    DEFAULT_DEVICE_KEY_LABEL, Enroller, EnrollmentOutcome, InMemorySecureKeyStore, KeyStoreError,
    SecureKeyStore,
};
pub use error::{MobileError, MobileResult};
pub use posture::{MobilePostureCollector, MobilePostureSnapshot, PostureError};
pub use telemetry::{EnvelopeContext, MobileTelemetry, MobileTelemetryEvent};
pub use tunnel::{
    MobileTunnelProvider, TUNNEL_KEY_LEN, TunnelConfig, TunnelError, TunnelKeypair,
    TunnelPrivateKey, TunnelPublicKey, TunnelStatus,
};
pub use ztna::{AppAccessState, MobileZtnaManager};

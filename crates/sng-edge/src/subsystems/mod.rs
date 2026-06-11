// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Subsystem adapters.
//!
//! Each module wraps one library crate's concrete service in a
//! [`sng_core::Subsystem`] + [`sng_core::HealthCheck`] pair. The
//! supervisor sees only the trait surface — the library crate's
//! specific types stay encapsulated behind the adapter.
//!
//! Wiring discipline:
//!
//! * Adapters take their config slice by value (the binary's
//!   [`crate::EdgeConfig`] is cloned-into-pieces at boot, so each
//!   subsystem holds only what it actually needs).
//! * Adapters take external trait deps (e.g. `Arc<dyn NftablesBackend>`)
//!   as constructor arguments — the binary's supervisor wiring
//!   in [`crate::supervisor`] decides which concrete impl is in
//!   play. This keeps the adapters testable without dragging the
//!   integration-test harness into per-adapter test files.
//! * Adapters never `unwrap` — every failure surface returns
//!   [`sng_core::SubsystemError`] (boxed) so the supervisor can
//!   surface it through [`sng_core::DrainResult`].

pub mod comms;
pub mod dns;
pub mod extauthz;
pub mod fw;
pub mod ha;
pub mod ips;
pub mod policy_eval;
pub mod sdwan;
pub mod swg;
pub mod telemetry;
pub mod updater;
pub mod ztna;
pub mod ztna_reeval;

pub use comms::CommsSubsystem;
pub use dns::DnsSubsystem;
pub use extauthz::ExtAuthzSubsystem;
pub use fw::FwSubsystem;
pub use ha::HaSubsystem;
pub use ips::IpsSubsystem;
pub use policy_eval::PolicyEvalSubsystem;
pub use sdwan::SdwanSubsystem;
pub use swg::SwgSubsystem;
pub use telemetry::TelemetrySubsystem;
pub use updater::UpdaterSubsystem;
pub use ztna::ZtnaSubsystem;
pub use ztna_reeval::ZtnaReevalSubsystem;

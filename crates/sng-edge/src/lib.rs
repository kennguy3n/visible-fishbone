// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding; CI runs `cargo clippy --tests -D warnings` across
// the workspace. Allow them in `#[cfg(test)]` only — production
// code paths still get the workspace-level warning.
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

//! ShieldNet Gateway edge appliance (`sng-edge`).
//!
//! `sng-edge` is the branch / site VM the operator boots on the
//! customer's network edge. It composes every Phase-2 library
//! crate behind the [`sng_core::supervisor::Supervisor`] harness:
//!
//! * [`subsystems::comms`] — [`sng_comms::ControlPlaneClient`]
//!   for talking to the control plane (mTLS, h2, MessagePack).
//! * [`subsystems::policy_eval`] — [`sng_policy_eval::PolicyEngine`]
//!   evaluating compiled policy bundles for the `Edge` target.
//! * [`subsystems::telemetry`] — [`sng_telemetry::pipeline::Pipeline`]
//!   running the dedup / redact / enrich / egress stages.
//! * [`subsystems::dns`] — [`sng_dns::DnsService`] driving a
//!   reputation / category / sinkhole filter chain.
//! * [`subsystems::fw`] — [`sng_fw::FirewallEngine`] pushing
//!   compiled L3/L4 + L7 rules through [`sng_fw::ShellNftables`].
//! * [`subsystems::ips`] — [`sng_ips::IpsManager`] managing the
//!   Suricata subprocess.
//! * [`subsystems::swg`] — [`sng_swg::SwgManager`] managing the
//!   Envoy SWG subprocess.
//! * [`subsystems::ztna`] — [`sng_ztna::ZtnaService`] evaluating
//!   `AccessRequest`s against the ZTNA policy graph.
//! * [`subsystems::sdwan`] — [`sng_sdwan::SdwanService`]
//!   selecting underlays per probe + policy.
//! * [`subsystems::updater`] — [`sng_updater::UpdaterService`]
//!   handling the self-update state machine.
//!
//! # Library vs binary split
//!
//! This crate exposes a `lib` target alongside the `bin` so the
//! integration tests in `tests/*.rs` can construct + drive the
//! supervisor stack without spawning a child process or going
//! through OS signals. The `main.rs` binary entry point is a
//! thin wrapper around [`run_from_args`].

pub mod cli;
pub mod commodity;
pub mod config;
pub mod hardware;
pub mod pop;
pub mod subsystems;
pub mod supervisor;
pub mod tracing_init;

pub use cli::{Cli, DataPathSelection, PalBackend, UpdaterBackend};
pub use commodity::{
    AffinityError, AffinityPlan, BufferPoolError, COMMODITY_BASELINE, CommodityProfile,
    DataPathProfile, Frame, HostTopology, MinSpec, MmapBufferPool, NumaNode, SpecAssessment,
    WorkerAffinity,
};
pub use config::{ConfigError, EdgeConfig, EdgeMode, PopConfig};
pub use hardware::{AttestationReport, HardwareAccelerator, HardwareDescriptor};
pub use pop::{AtCapacity, CapacityReport, ConnGuard, PoPRouter, RouteError, TenantSelector};
pub use supervisor::{BuiltEdge, EdgeBuildError, build_edge, run_edge};

use anyhow::Result;
use std::ffi::OsString;

/// Binary entry point, factored out of `main.rs` so the
/// integration tests can call it with synthetic argv.
///
/// # Errors
///
/// Returns the underlying [`anyhow::Error`] for any failure
/// during CLI parse, config load, subsystem build, or supervisor
/// run. The binary's `main` converts the error to an exit code.
pub async fn run_from_args<I, T>(argv: I) -> Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = <Cli as clap::Parser>::parse_from(argv);
    tracing_init::init(&cli)?;
    let cfg = config::load_from_path(&cli.config)?;
    let report = run_edge(cli, cfg).await?;
    if !report.all_clean() {
        // Surface as a non-zero exit so the OS supervisor knows
        // a subsystem misbehaved on drain even though the
        // supervisor itself returned cleanly. Test harnesses
        // inspect the report directly via build_edge / run_edge
        // and don't hit this path.
        anyhow::bail!(
            "supervisor drained with non-clean outcomes: {:?}",
            report
                .drain_results
                .iter()
                .filter(|r| r.outcome.is_err())
                .map(|r| &r.name)
                .collect::<Vec<_>>(),
        );
    }
    Ok(())
}

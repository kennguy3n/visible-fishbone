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

//! `sng-agent` — endpoint-side agent binary library half.
//!
//! Mirrors `sng_edge` structurally: the library half exposes the
//! [`run_from_args`] entry point so integration tests can drive
//! the supervisor stack in-process without spawning a child
//! process. The binary half (`src/main.rs`) is a thin wrapper
//! around [`run_from_args`].
//!
//! The endpoint agent composes a strict subset of the Phase-2
//! subsystems used by `sng-edge`:
//!
//! - `comms` (control-plane client, smaller pool than edge)
//! - `policy_eval` (target = [`sng_policy_eval::BundleTarget::Endpoint`])
//! - `telemetry` (single sink, no spool)
//! - `ztna` (per-flow access evaluation)
//! - `pal_steering` (capture → eval → action loop)
//! - `pal_posture` (collector cadence → telemetry)
//! - `pal_tunnel` (tunnel up/down driven by policy verdicts)

pub mod cli;
pub mod config;
pub mod posture_map;
pub mod subsystems;
pub mod supervisor;
pub mod tracing_init;

use std::ffi::OsString;

pub use cli::{Cli, PalBackend};
pub use config::{AgentConfig, ConfigError};
pub use posture_map::merge_posture_snapshot;
pub use supervisor::{AgentBuildError, BuiltAgent, build_agent, run_agent};

/// Run the agent binary from a command-line argument vector.
///
/// This is the canonical entry point: the binary half (`main.rs`)
/// calls it with [`std::env::args_os`] and the integration tests
/// call it with synthetic argv vectors so they can drive the
/// supervisor stack without forking.
///
/// # Errors
///
/// Returns the underlying error if CLI parsing, tracing
/// initialisation, config loading, supervisor construction, or
/// the supervisor's run loop fails. A non-clean drain (any
/// subsystem panicked, failed, or timed out) is also surfaced
/// as an error so a wrapping shell-level supervisor (systemd,
/// k8s liveness) can restart the process.
pub async fn run_from_args<I, T>(argv: I) -> anyhow::Result<()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = <Cli as clap::Parser>::parse_from(argv);
    tracing_init::init(&cli)?;
    let cfg = config::load_from_path(&cli.config)?;
    let report = run_agent(cli, cfg).await?;
    if !report.all_clean() {
        anyhow::bail!(
            "supervisor drained with non-clean outcomes: {:?}",
            report.drain_results
        );
    }
    Ok(())
}

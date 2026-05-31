// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-agent` binary entry point. Thin wrapper around
//! [`sng_agent::run_from_args`].

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match sng_agent::run_from_args(std::env::args_os()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Tracing may not yet be initialised at this point
            // (e.g. CLI parse failure or tracing_init::init
            // returned an error); fall back to stderr so the
            // operator still sees the cause.
            eprintln!("sng-agent: fatal: {e:#}");
            ExitCode::from(1)
        }
    }
}

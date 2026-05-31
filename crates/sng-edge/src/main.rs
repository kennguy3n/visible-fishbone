// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-edge` binary entry point.
//!
//! The binary itself is intentionally tiny — the real work lives
//! in the library half of the crate ([`sng_edge`]) so the
//! integration tests can call into it without going through
//! `std::env::args` or `tokio::main!`.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match sng_edge::run_from_args(std::env::args_os()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // tracing may already be initialised at this point;
            // emit the error through both tracing (structured
            // log line for log aggregators) AND stderr (so
            // operators still see the message when the binary
            // bails out before tracing init).
            eprintln!("sng-edge: {e:#}");
            tracing::error!(error = %e, "sng-edge fatal");
            ExitCode::FAILURE
        }
    }
}

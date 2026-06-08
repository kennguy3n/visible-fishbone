// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! tracing-subscriber initialisation.
//!
//! Real init — the binary is unusable without structured logs.
//! Layered output: `tracing_subscriber::fmt` with either the
//! human-readable line format or the JSON formatter, gated on
//! [`crate::Cli::log_json`].
//!
//! Filtering is driven by `EnvFilter`. The precedence is:
//!
//! 1. `--log-filter` CLI flag (also accepts `SNG_EDGE_LOG_FILTER`
//!    env var via clap).
//! 2. `RUST_LOG` env var (canonical tracing-subscriber path).
//! 3. The compiled-in default: `info,sng_edge=info`.
//!
//! Init is idempotent — the integration tests in `tests/` can
//! call it once per process without tripping the "global default
//! already set" panic. The library exposes
//! [`init_for_tests`] for tests that want a fresh JSON sink per
//! test.

use anyhow::{Context, Result};
use std::sync::OnceLock;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

static INIT: OnceLock<()> = OnceLock::new();

/// Initialise tracing. Idempotent — repeated calls are no-ops
/// after the first successful init.
///
/// # Errors
///
/// Returns an error only if the `EnvFilter` string the operator
/// supplied is malformed. Failing to install the global
/// subscriber is treated as a no-op (typically another
/// `init()` call from a test harness won the race).
pub fn init(cli: &crate::Cli) -> Result<()> {
    let mut already = true;
    let mut filter_str_err: Option<String> = None;
    INIT.get_or_init(|| {
        already = false;
        let filter_str = pick_filter_directive(cli);
        let filter = match EnvFilter::try_new(&filter_str) {
            Ok(f) => f,
            Err(e) => {
                filter_str_err = Some(format!("invalid log filter `{filter_str}`: {e}"));
                EnvFilter::new("info,sng_edge=info")
            }
        };
        if cli.log_json {
            let layer = fmt::layer().json().with_current_span(true);
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .try_init();
        } else {
            let layer = fmt::layer().with_target(true);
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(layer)
                .try_init();
        }
    });
    if !already && let Some(msg) = filter_str_err {
        return Err(anyhow::anyhow!(msg)).context("tracing init");
    }
    Ok(())
}

fn pick_filter_directive(cli: &crate::Cli) -> String {
    if let Some(custom) = cli.log_filter.as_deref() {
        return custom.into();
    }
    if let Ok(env) = std::env::var("RUST_LOG")
        && !env.is_empty()
    {
        return env;
    }
    "info,sng_edge=info".into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, DataPathSelection, PalBackend, UpdaterBackend};
    use std::path::PathBuf;

    fn synthetic_cli(filter: Option<&str>) -> Cli {
        Cli {
            config: PathBuf::from("/dev/null"),
            health_bind: None,
            updater_backend: UpdaterBackend::InMemory,
            pal_backend: PalBackend::InMemory,
            datapath: DataPathSelection::Auto,
            log_filter: filter.map(String::from),
            log_json: false,
        }
    }

    #[test]
    fn init_is_idempotent() {
        let cli = synthetic_cli(Some("debug"));
        init(&cli).unwrap();
        // Second call must not panic.
        init(&cli).unwrap();
    }

    #[test]
    fn pick_filter_directive_prefers_cli_flag() {
        let cli = synthetic_cli(Some("warn"));
        assert_eq!(pick_filter_directive(&cli), "warn");
    }

    #[test]
    fn pick_filter_directive_falls_back_to_default() {
        let cli = synthetic_cli(None);
        // Snapshot RUST_LOG so the test is hermetic.
        let saved = std::env::var("RUST_LOG").ok();
        // SAFETY: tests in a single test binary run on
        // separate threads, but we're modifying a process-
        // wide env var. The other tests in this module use
        // either an explicit cli.log_filter (which short-
        // circuits before env lookup) or this guarded path.
        // `cargo test` runs this test binary single-threaded
        // unless we say otherwise, and our other tests in
        // the same module do not touch RUST_LOG.
        #[allow(unsafe_code)]
        unsafe {
            std::env::remove_var("RUST_LOG");
        }
        let got = pick_filter_directive(&cli);
        // Restore before asserting so a later test isn't
        // affected by an assertion failure.
        if let Some(v) = saved {
            #[allow(unsafe_code)]
            unsafe {
                std::env::set_var("RUST_LOG", v);
            }
        }
        assert_eq!(got, "info,sng_edge=info");
    }
}

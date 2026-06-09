// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-edge` CLI surface.
//!
//! Parsed with `clap::Parser`. Flags surfacing the deliberate
//! scope cuts (`--updater-backend`, `--pal-backend`) are kept
//! visible at the top level so the operator sees them in
//! `--help` and the binary refuses to silently swap a real
//! production backend for an in-memory one.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Command-line arguments for `sng-edge`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "sng-edge",
    version,
    about = "ShieldNet Gateway edge appliance (branch / site VM).",
    long_about = "Edge appliance binary. Composes every Phase-2 \
        library crate behind the sng-core::supervisor harness. \
        See --config for the TOML schema (sng_edge::EdgeConfig)."
)]
pub struct Cli {
    /// Path to the TOML config file. See [`crate::config::EdgeConfig`]
    /// for the schema. Required; the binary refuses to boot
    /// with a default-only config because the operator must
    /// at minimum specify a control-plane endpoint.
    #[arg(long, env = "SNG_EDGE_CONFIG")]
    pub config: PathBuf,

    /// `host:port` for the operator-facing health endpoint
    /// exposed by the supervisor's health aggregator. When
    /// omitted, the health endpoint is not exposed (operator
    /// must rely on log scraping). Default OFF because the
    /// operator typically front-fronts the binary with a
    /// reverse proxy that owns its own port binding.
    #[arg(long, env = "SNG_EDGE_HEALTH_BIND")]
    pub health_bind: Option<String>,

    /// Updater backend. `in-memory` is the default — the
    /// disk-backed bank writer / EFI bootloader is shipped as
    /// a separate crate and not part of this PR. Requesting
    /// `disk` here fails fast at boot with a clear
    /// `EdgeBuildError::UnsupportedUpdaterBackend` so the
    /// operator knows to upgrade their build, instead of
    /// silently running with the test backend.
    #[arg(long, env = "SNG_EDGE_UPDATER_BACKEND", value_enum, default_value_t = UpdaterBackend::InMemory)]
    pub updater_backend: UpdaterBackend,

    /// PAL backend. The edge VM does not actually need any of
    /// the endpoint-only PAL surface (traffic capture, tunnel
    /// provider, posture collector); the flag is exposed for
    /// shape-parity with `sng-agent`'s CLI so operator
    /// configuration management can use the same template
    /// for both binaries.
    #[arg(long, env = "SNG_EDGE_PAL_BACKEND", value_enum, default_value_t = PalBackend::InMemory)]
    pub pal_backend: PalBackend,

    /// Data-path backend for firewall enforcement. `auto`
    /// (default) probes for an XDP-capable kernel and uses the
    /// eBPF fast path when available, falling back to nftables
    /// otherwise. `nftables` forces the classic slow path;
    /// `ebpf` (alias `xdp`) forces the fast path (the eBPF backend
    /// keeps an nftables fallback for the L7 / inspect / steer
    /// verdicts XDP cannot express). See STREAM B /
    /// ARCHITECTURE.md §4.1.
    #[arg(long, env = "SNG_EDGE_DATAPATH", value_enum, default_value_t = DataPathSelection::Auto)]
    pub datapath: DataPathSelection,

    /// Override the tracing-subscriber `EnvFilter` directive.
    /// Equivalent to setting `RUST_LOG=…` before the binary
    /// starts. Useful for ad-hoc debug runs without
    /// touching the systemd unit file.
    #[arg(long, env = "SNG_EDGE_LOG_FILTER")]
    pub log_filter: Option<String>,

    /// Emit logs as JSON instead of the default human-readable
    /// fmt formatter. The systemd / containerd manifest
    /// typically sets this to `true` so the log aggregator
    /// can parse structured fields.
    #[arg(long, env = "SNG_EDGE_LOG_JSON")]
    pub log_json: bool,
}

/// Updater backend selector. See [`Cli::updater_backend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum UpdaterBackend {
    /// In-memory bank writer + bootloader. Real production
    /// state machine (signed manifests, dual-bank install,
    /// rollback) — only the on-disk persistence is mocked.
    /// Used by the integration-test harness AND surfaced to
    /// the operator at boot via a log line so it's never
    /// silently active in production.
    #[value(name = "in-memory")]
    InMemory,
    /// Disk-backed bank writer + EFI bootloader. Shipped as
    /// a separate crate (PR 14 / PR 15) — this binary refuses
    /// to boot in this mode until that crate lands.
    Disk,
}

/// PAL backend selector. See [`Cli::pal_backend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PalBackend {
    /// In-memory PAL adapters
    /// ([`sng_pal::traffic::InMemoryCapture`] etc.). Identical
    /// to the integration-test path.
    #[value(name = "in-memory")]
    InMemory,
    /// Native PAL adapters (WFP / Network Extension / nftables
    /// TPROXY / TPM key store). Shipped as a separate set of
    /// crates (PR 14 / PR 15) — this binary refuses to boot
    /// in this mode until those crates land.
    Native,
}

/// Firewall data-path backend selector. See [`Cli::datapath`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum DataPathSelection {
    /// Probe the kernel for XDP support
    /// ([`sng_ebpf::detect_xdp_capable`]) and pick the eBPF fast
    /// path when available, nftables otherwise. The default —
    /// an operator who does nothing gets the fastest path their
    /// kernel can run with no risk of a boot failure on an
    /// XDP-incapable box.
    #[default]
    Auto,
    /// Force the classic nftables slow path regardless of kernel
    /// capability.
    Nftables,
    /// Force the eBPF/XDP fast path. The backend still keeps an
    /// nftables fallback for the verdicts XDP cannot express, so
    /// this never loses L7 enforcement; on an XDP-incapable
    /// kernel the userspace control-plane model is used and the
    /// fallback carries all traffic.
    ///
    /// Accepts `xdp` as an alias so operators can select the fast
    /// path by the kernel hook it attaches (`--datapath=xdp`) as
    /// well as by the technology name (`--datapath=ebpf`).
    #[value(name = "ebpf", alias = "xdp")]
    Ebpf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use pretty_assertions::assert_eq;

    #[test]
    fn cli_help_renders() {
        // Pure smoke test: clap's derive macro emits a stable
        // help string. If a future flag is renamed, this test
        // forces an explicit acknowledgement that the operator-
        // visible surface changed.
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("--config"));
        assert!(help.contains("--health-bind"));
        assert!(help.contains("--updater-backend"));
        assert!(help.contains("--pal-backend"));
    }

    #[test]
    fn defaults_match_documented_safe_defaults() {
        let cli = Cli::parse_from(["sng-edge", "--config", "/etc/sng/edge.toml"]);
        assert_eq!(cli.updater_backend, UpdaterBackend::InMemory);
        assert_eq!(cli.pal_backend, PalBackend::InMemory);
        assert_eq!(cli.datapath, DataPathSelection::Auto);
        assert!(cli.health_bind.is_none());
        assert!(!cli.log_json);
    }

    #[test]
    fn datapath_accepts_xdp_alias_and_canonical_names() {
        // Operators may select the fast path either by technology
        // name (`ebpf`) or by the kernel hook it attaches (`xdp`);
        // both must resolve to the same backend selection.
        for token in ["ebpf", "xdp"] {
            let cli = Cli::parse_from([
                "sng-edge",
                "--config",
                "/etc/sng/edge.toml",
                "--datapath",
                token,
            ]);
            assert_eq!(cli.datapath, DataPathSelection::Ebpf, "token {token}");
        }

        let nft = Cli::parse_from([
            "sng-edge",
            "--config",
            "/etc/sng/edge.toml",
            "--datapath",
            "nftables",
        ]);
        assert_eq!(nft.datapath, DataPathSelection::Nftables);
    }
}

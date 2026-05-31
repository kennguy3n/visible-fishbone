// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-agent` CLI surface.
//!
//! Parsed with `clap::Parser`. Flag shape matches `sng-edge` so
//! the operator's configuration management can drive both
//! binaries with one template; the `PalBackend` enum is the
//! load-bearing one for the agent (the endpoint host actually
//! needs the PAL surface) and is widened with the per-sub-
//! adapter selectors that `sng-edge` does not need (capture,
//! posture collector, tunnel provider).

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// Command-line arguments for `sng-agent`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "sng-agent",
    version,
    about = "ShieldNet Gateway endpoint agent (laptop / VM).",
    long_about = "Endpoint agent binary. Composes the comms / \
        policy_eval / telemetry / ztna / pal subsystems behind \
        the sng-core::supervisor harness. See --config for the \
        TOML schema (sng_agent::AgentConfig)."
)]
pub struct Cli {
    /// Path to the TOML config file. See [`crate::config::AgentConfig`]
    /// for the schema. Required; the binary refuses to boot
    /// with a default-only config because the operator must
    /// at minimum specify a control-plane endpoint and the
    /// device's enrollment identity.
    #[arg(long, env = "SNG_AGENT_CONFIG")]
    pub config: PathBuf,

    /// PAL backend selector.
    ///
    /// `in-memory` is the default. The native backends
    /// (WFP / Network Extension / nftables-TPROXY for
    /// capture; TPM / Secure Enclave / kwallet for the key
    /// store; BoringTun / kernel WireGuard /
    /// `NEPacketTunnelProvider` for the tunnel) are shipped
    /// as a separate set of per-OS crates and not part of
    /// this PR. Requesting `native` here fails fast at boot
    /// with [`crate::supervisor::AgentBuildError::UnsupportedPalBackend`]
    /// so the operator knows to upgrade their build instead
    /// of silently running with the test backend.
    #[arg(long, env = "SNG_AGENT_PAL_BACKEND", value_enum, default_value_t = PalBackend::InMemory)]
    pub pal_backend: PalBackend,

    /// Traffic-capture backend selector. Independent from
    /// [`Self::pal_backend`] so an operator can pin one
    /// sub-adapter to a native impl while leaving the
    /// others on in-memory (typical during native-backend
    /// rollout: ship capture first, then posture, then
    /// tunnel). Defaults to the unified
    /// [`Self::pal_backend`] selection.
    #[arg(long, env = "SNG_AGENT_CAPTURE_BACKEND", value_enum)]
    pub capture_backend: Option<PalBackend>,

    /// Posture-collector backend selector. See
    /// [`Self::capture_backend`] for the rationale on the
    /// per-sub-adapter override.
    #[arg(long, env = "SNG_AGENT_POSTURE_BACKEND", value_enum)]
    pub posture_backend: Option<PalBackend>,

    /// Tunnel-provider backend selector. See
    /// [`Self::capture_backend`] for the rationale on the
    /// per-sub-adapter override.
    #[arg(long, env = "SNG_AGENT_TUNNEL_BACKEND", value_enum)]
    pub tunnel_backend: Option<PalBackend>,

    /// Override the tracing-subscriber `EnvFilter` directive.
    /// Equivalent to setting `RUST_LOG=…` before the binary
    /// starts. Useful for ad-hoc debug runs without
    /// touching the launchd / systemd unit file.
    #[arg(long, env = "SNG_AGENT_LOG_FILTER")]
    pub log_filter: Option<String>,

    /// Emit logs as JSON instead of the default human-readable
    /// fmt formatter. The launchd / systemd manifest
    /// typically sets this to `true` so the OS log
    /// aggregator can parse structured fields.
    #[arg(long, env = "SNG_AGENT_LOG_JSON")]
    pub log_json: bool,
}

impl Cli {
    /// Resolve the effective traffic-capture backend selection,
    /// preferring the per-sub-adapter override when set.
    #[must_use]
    pub fn effective_capture_backend(&self) -> PalBackend {
        self.capture_backend.unwrap_or(self.pal_backend)
    }

    /// Resolve the effective posture-collector backend
    /// selection, preferring the per-sub-adapter override
    /// when set.
    #[must_use]
    pub fn effective_posture_backend(&self) -> PalBackend {
        self.posture_backend.unwrap_or(self.pal_backend)
    }

    /// Resolve the effective tunnel-provider backend
    /// selection, preferring the per-sub-adapter override
    /// when set.
    #[must_use]
    pub fn effective_tunnel_backend(&self) -> PalBackend {
        self.tunnel_backend.unwrap_or(self.pal_backend)
    }
}

/// PAL backend selector. See [`Cli::pal_backend`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PalBackend {
    /// In-memory PAL adapters
    /// ([`sng_pal::traffic::InMemoryCapture`],
    /// [`sng_pal::posture::UnknownPostureCollector`],
    /// [`sng_pal::tunnel::InMemoryTunnelProvider`]).
    /// Identical to the integration-test path.
    #[value(name = "in-memory")]
    InMemory,
    /// Native PAL adapters (WFP / Network Extension /
    /// nftables-TPROXY for capture; per-OS keystore;
    /// BoringTun / kernel WireGuard /
    /// `NEPacketTunnelProvider` for the tunnel). Shipped
    /// as a separate set of crates — this binary refuses
    /// to boot in this mode until those crates land.
    Native,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use pretty_assertions::assert_eq;

    #[test]
    fn cli_help_renders() {
        // Smoke test: clap's derive macro emits a stable
        // help string. If a future flag is renamed, this
        // test forces an explicit acknowledgement that the
        // operator-visible surface changed.
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("--config"));
        assert!(help.contains("--pal-backend"));
        assert!(help.contains("--capture-backend"));
        assert!(help.contains("--posture-backend"));
        assert!(help.contains("--tunnel-backend"));
        assert!(help.contains("--log-filter"));
        assert!(help.contains("--log-json"));
    }

    #[test]
    fn cli_parses_minimal_argv() {
        let cli =
            Cli::try_parse_from(["sng-agent", "--config", "/etc/sng/agent.toml"]).expect("parse");
        assert_eq!(cli.pal_backend, PalBackend::InMemory);
        assert_eq!(cli.capture_backend, None);
        assert_eq!(cli.posture_backend, None);
        assert_eq!(cli.tunnel_backend, None);
        assert!(!cli.log_json);
        assert_eq!(cli.config, PathBuf::from("/etc/sng/agent.toml"));
    }

    #[test]
    fn effective_backends_fall_back_to_unified_selector() {
        let cli =
            Cli::try_parse_from(["sng-agent", "--config", "/c", "--pal-backend", "in-memory"])
                .expect("parse");
        assert_eq!(cli.effective_capture_backend(), PalBackend::InMemory);
        assert_eq!(cli.effective_posture_backend(), PalBackend::InMemory);
        assert_eq!(cli.effective_tunnel_backend(), PalBackend::InMemory);
    }

    #[test]
    fn effective_backends_prefer_per_subsystem_override() {
        let cli = Cli::try_parse_from([
            "sng-agent",
            "--config",
            "/c",
            "--pal-backend",
            "in-memory",
            "--capture-backend",
            "native",
        ])
        .expect("parse");
        assert_eq!(cli.effective_capture_backend(), PalBackend::Native);
        assert_eq!(cli.effective_posture_backend(), PalBackend::InMemory);
        assert_eq!(cli.effective_tunnel_backend(), PalBackend::InMemory);
    }

    #[test]
    fn cli_rejects_missing_config_flag() {
        let err = Cli::try_parse_from(["sng-agent"]).expect_err("missing --config");
        let rendered = err.to_string();
        assert!(rendered.contains("--config"));
    }
}

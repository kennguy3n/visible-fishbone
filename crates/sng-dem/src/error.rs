//! DEM probe-engine error taxonomy.
//!
//! These errors cover *engine setup and configuration* failures —
//! a malformed [`crate::Target`], an HTTP client that could not be
//! built, or a serialization fault. They map onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and ops
//! dashboards bucket DEM faults into the same dotted-lowercase
//! namespace as every other subsystem.
//!
//! A *probe* that fails to reach its target is **not** a [`DemError`]:
//! an unreachable target is a first-class experience signal, captured
//! in a [`crate::ProbeResult`] with `success == false` and a
//! [`crate::ProbeErrorKind`]. The engine therefore never aborts a
//! probe sweep because one target is down.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced while configuring or driving the probe engine.
#[derive(Debug, Error)]
pub enum DemError {
    /// A [`crate::Target`] (or [`crate::EngineConfig`]) failed
    /// value-domain validation — e.g. an empty host, a missing port
    /// for a TCP probe, an unparseable URL, or a timeout outside the
    /// accepted bound. The offending target is skipped; the sweep
    /// continues.
    #[error("invalid configuration: {0}")]
    Config(String),

    /// The shared [`reqwest::Client`] could not be constructed (e.g.
    /// the TLS backend failed to initialise). The engine cannot run
    /// HTTP(S) probes without it, so construction fails closed.
    #[error("http client build: {0}")]
    Build(String),

    /// A probe result could not be serialised to its wire form for
    /// egress to the control plane.
    #[error("encode probe result: {0}")]
    Encode(String),
}

impl DemError {
    /// Map to the stable workspace error code.
    ///
    /// `Config` is a value-domain mismatch (`config.invalid`); `Build`
    /// is an I/O-shaped initialisation failure; `Encode` is a
    /// wire-encoding fault.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Config(_) => ErrorCode::ConfigInvalid,
            Self::Build(_) => ErrorCode::Io,
            Self::Encode(_) => ErrorCode::WireEncoding,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn config_maps_to_config_invalid() {
        assert_eq!(
            DemError::Config("port required".into()).code(),
            ErrorCode::ConfigInvalid
        );
    }

    #[test]
    fn build_maps_to_io() {
        assert_eq!(DemError::Build("tls init".into()).code(), ErrorCode::Io);
    }

    #[test]
    fn encode_maps_to_wire_encoding() {
        assert_eq!(
            DemError::Encode("serde".into()).code(),
            ErrorCode::WireEncoding
        );
    }

    #[test]
    fn display_carries_context() {
        let e = DemError::Config("empty host".into());
        assert!(format!("{e}").contains("empty host"));
    }
}

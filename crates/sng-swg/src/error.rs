//! SWG subsystem error taxonomy.
//!
//! Each variant maps onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and
//! ops dashboards bucket SWG failures into the same
//! dotted-lowercase namespace as every other subsystem.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the SWG subsystem.
#[derive(Debug, Error)]
pub enum SwgError {
    /// The request URL could not be parsed. Callers should
    /// fail-closed on the affected request and surface a
    /// counter; a malformed URL coming from the data path is
    /// almost always an upstream parser bug, not user input.
    #[error("invalid url: {0}")]
    InvalidUrl(String),

    /// The bundle adapter could not decode the SWG section
    /// of a policy bundle (missing required field, malformed
    /// MessagePack). The SWG engine fails closed on this and
    /// keeps running with the previously-loaded ruleset (if
    /// any).
    #[error("bundle decode: {0}")]
    BundleDecode(String),

    /// A category / reputation / malware provider returned
    /// an error. The orchestrator's fail-policy (open vs
    /// closed) decides whether the request is allowed or
    /// blocked; the variant exists so the supervisor can
    /// distinguish "provider down" from "policy denied".
    #[error("provider {provider}: {reason}")]
    ProviderFailure {
        /// Provider name — surfaced to ops logs as a label.
        provider: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The egress channel into the telemetry pipeline
    /// rejected the [`sng_core::events::HttpEvent`] — most
    /// commonly because the pipeline task has been shut down
    /// or the channel is at capacity.
    #[error("telemetry: {0}")]
    Telemetry(String),

    /// A request was rejected because the SWG's session
    /// table is full and could not allocate state for a new
    /// connection. Operators tune
    /// [`crate::service::SwgServiceConfig::max_sessions`] up.
    #[error("session table full ({pressure_pct}% utilised)")]
    SessionTableFull {
        /// Utilisation at the time the insert failed, as a
        /// percentage (0..=100).
        pressure_pct: u8,
    },
}

impl SwgError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidUrl(_) | Self::BundleDecode(_) => ErrorCode::WireSchema,
            Self::ProviderFailure { .. } | Self::Telemetry(_) | Self::SessionTableFull { .. } => {
                ErrorCode::Io
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_url_maps_to_wire_schema() {
        assert_eq!(
            SwgError::InvalidUrl("ht!tp://bad".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn bundle_decode_maps_to_wire_schema() {
        assert_eq!(
            SwgError::BundleDecode("missing rev".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn provider_failure_maps_to_io() {
        assert_eq!(
            SwgError::ProviderFailure {
                provider: "urlcat".into(),
                reason: "timeout".into(),
            }
            .code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn telemetry_maps_to_io() {
        assert_eq!(SwgError::Telemetry("closed".into()).code(), ErrorCode::Io);
    }

    #[test]
    fn session_table_full_maps_to_io() {
        assert_eq!(
            SwgError::SessionTableFull { pressure_pct: 99 }.code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn invalid_url_display_includes_input() {
        let e = SwgError::InvalidUrl("not-a-url".into());
        assert!(format!("{e}").contains("not-a-url"));
    }

    #[test]
    fn provider_failure_display_includes_provider_and_reason() {
        let e = SwgError::ProviderFailure {
            provider: "verdictapi".into(),
            reason: "503".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("verdictapi"));
        assert!(s.contains("503"));
    }

    #[test]
    fn session_table_full_display_includes_pressure() {
        let e = SwgError::SessionTableFull { pressure_pct: 99 };
        assert!(format!("{e}").contains("99"));
    }
}

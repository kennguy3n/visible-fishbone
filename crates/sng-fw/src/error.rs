//! Firewall subsystem error taxonomy.
//!
//! Every error produced by this crate maps onto an
//! [`sng_core::error::ErrorCode`] so the supervisor can bucket
//! failures into the same dotted-lowercase namespace the rest of
//! the workspace uses (`io`, `wire.schema`, `policy.*`, etc.).

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the firewall subsystem.
#[derive(Debug, Error)]
pub enum FwError {
    /// A packet metadata blob handed to the service failed
    /// validation before any policy lookup happened — most
    /// commonly a zero-length payload sniff, an obviously
    /// invalid 5-tuple (zero source port on a TCP flow), or
    /// a port number the protocol doesn't support.
    #[error("flow invalid: {0}")]
    FlowInvalid(String),

    /// SNI / ALPN / first-bytes sniff failed because the
    /// payload was not a TLS ClientHello, was truncated, or
    /// carried a length field that exceeded the buffer. Lifted
    /// from [`crate::appid`].
    #[error("application identification: {0}")]
    AppId(String),

    /// The conntrack table is full and the eviction policy did
    /// not free a slot in time. Indicates the table is undersized
    /// relative to the offered load — operators tune
    /// [`crate::conntrack::ConnTableConfig::max_entries`] up.
    #[error("conntrack full ({pressure_pct}% utilised)")]
    ConntrackFull {
        /// Utilisation at the time the insert failed, as a
        /// percentage (0..=100). Surfaced on the telemetry
        /// envelope so dashboards can correlate the drop with
        /// the underlying pressure.
        pressure_pct: u8,
    },

    /// The policy evaluator returned without producing a
    /// verdict — almost always means the bundle was unloaded
    /// out from under us during a reconfig race. The caller
    /// fails the flow closed and re-queries on the next packet.
    #[error("policy unavailable: {0}")]
    PolicyUnavailable(String),

    /// The egress channel into the telemetry pipeline rejected
    /// the [`sng_core::FlowEvent`] — most commonly because the
    /// pipeline task has been shut down or the channel is at
    /// capacity. The variant exists so the supervisor can
    /// distinguish "no telemetry" from "firewall enforcement
    /// failed".
    #[error("telemetry: {0}")]
    Telemetry(String),
}

impl FwError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::FlowInvalid(_) | Self::AppId(_) => ErrorCode::WireSchema,
            // ConntrackFull is a runtime-resource problem, not
            // a schema problem — but it doesn't have a more
            // specific bucket in the workspace error code
            // taxonomy. `Io` is the canonical fallback for
            // "a resource the host owns failed", and a full
            // conntrack table is exactly that.
            Self::ConntrackFull { .. } | Self::Telemetry(_) => ErrorCode::Io,
            Self::PolicyUnavailable(_) => ErrorCode::ResourceMissing,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_invalid_maps_to_wire_schema() {
        assert_eq!(
            FwError::FlowInvalid("no source port".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn appid_maps_to_wire_schema() {
        // App-id sniff failures are schema-level: the bytes the
        // sniffer was handed didn't match the protocol it was
        // told to decode.
        assert_eq!(
            FwError::AppId("truncated client hello".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn conntrack_full_maps_to_io() {
        assert_eq!(
            FwError::ConntrackFull { pressure_pct: 100 }.code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn policy_unavailable_maps_to_resource_missing() {
        // A flow that arrives during a bundle reload race
        // should bucket alongside the "no bundle loaded yet"
        // case from `sng-policy-eval`, not under generic IO.
        assert_eq!(
            FwError::PolicyUnavailable("no bundle loaded".into()).code(),
            ErrorCode::ResourceMissing
        );
    }

    #[test]
    fn telemetry_maps_to_io() {
        assert_eq!(
            FwError::Telemetry("pipeline closed".into()).code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn display_format_includes_diagnostic_text() {
        let e = FwError::FlowInvalid("zero source port".into());
        let s = format!("{e}");
        assert!(s.contains("zero source port"));
        assert!(s.contains("flow invalid"));
    }

    #[test]
    fn conntrack_full_display_includes_pressure() {
        let e = FwError::ConntrackFull { pressure_pct: 87 };
        let s = format!("{e}");
        assert!(s.contains("87"));
    }
}

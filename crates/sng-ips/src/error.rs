//! IPS subsystem error taxonomy.
//!
//! Every error produced by this crate maps onto an
//! [`sng_core::error::ErrorCode`] so the supervisor can bucket
//! failures into the same dotted-lowercase namespace the rest
//! of the workspace uses.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the IPS subsystem.
#[derive(Debug, Error)]
pub enum IpsError {
    /// A signature could not be compiled — most commonly an
    /// invalid regex, an empty literal pattern, or an
    /// unsupported anchor combination. The compile happens
    /// once at bundle-load time so the data path never
    /// returns this variant; callers see it from
    /// [`crate::signature::SignatureSet::compile`].
    #[error("invalid signature {sid}: {reason}")]
    InvalidSignature {
        /// Suricata-style SID (numeric) for the failed signature.
        sid: u32,
        /// Human-readable reason — surfaced to ops logs.
        reason: String,
    },

    /// The bundle adapter could not decode the IPS section of
    /// a policy bundle (missing required field, malformed
    /// MessagePack). The IPS engine fails closed on this and
    /// keeps running with the previously-loaded signature set
    /// (if any).
    #[error("bundle decode: {0}")]
    BundleDecode(String),

    /// The egress channel into the telemetry pipeline
    /// rejected the [`sng_core::events::IpsEvent`] — most
    /// commonly because the pipeline task has been shut down
    /// or the channel is at capacity. The variant exists so
    /// the supervisor can distinguish "no IPS telemetry"
    /// from "IPS pattern matching failed".
    #[error("telemetry: {0}")]
    Telemetry(String),

    /// The inspection state table is full and could not
    /// allocate state for a new flow. Indicates the table is
    /// undersized relative to offered load — operators tune
    /// [`crate::service::IpsServiceConfig::max_flows`] up.
    #[error("inspection table full ({pressure_pct}% utilised)")]
    InspectionTableFull {
        /// Utilisation at the time the insert failed, as a
        /// percentage (0..=100).
        pressure_pct: u8,
    },
}

impl IpsError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidSignature { .. } | Self::BundleDecode(_) => ErrorCode::WireSchema,
            Self::Telemetry(_) | Self::InspectionTableFull { .. } => ErrorCode::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_signature_maps_to_wire_schema() {
        assert_eq!(
            IpsError::InvalidSignature {
                sid: 1001,
                reason: "unbalanced bracket".into(),
            }
            .code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn bundle_decode_maps_to_wire_schema() {
        assert_eq!(
            IpsError::BundleDecode("missing rev field".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn telemetry_maps_to_io() {
        assert_eq!(
            IpsError::Telemetry("pipeline closed".into()).code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn inspection_table_full_maps_to_io() {
        assert_eq!(
            IpsError::InspectionTableFull { pressure_pct: 100 }.code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn invalid_signature_display_includes_sid_and_reason() {
        let e = IpsError::InvalidSignature {
            sid: 1234,
            reason: "unbalanced bracket".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("1234"));
        assert!(s.contains("unbalanced bracket"));
    }

    #[test]
    fn inspection_table_full_display_includes_pressure() {
        let e = IpsError::InspectionTableFull { pressure_pct: 92 };
        assert!(format!("{e}").contains("92"));
    }
}

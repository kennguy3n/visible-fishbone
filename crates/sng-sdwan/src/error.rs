//! SD-WAN subsystem error taxonomy.
//!
//! Each variant maps onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and
//! ops dashboards bucket SD-WAN failures into the same
//! dotted-lowercase namespace as every other subsystem.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the SD-WAN subsystem.
#[derive(Debug, Error)]
pub enum SdwanError {
    /// The bundle adapter could not decode the SD-WAN
    /// section of a policy bundle. The engine fails closed
    /// on this and keeps running with the previously-loaded
    /// ruleset (if any).
    #[error("bundle decode: {0}")]
    BundleDecode(String),

    /// The candidate [`crate::policy::SdwanPolicy`] failed
    /// value-domain validation — e.g. a score weight that
    /// is negative or non-finite (would invert the
    /// comparison or produce `NaN` in `score_path`), or a
    /// probe-freshness budget of zero (would mark every
    /// probe stale immediately). Distinct from
    /// `BundleDecode` (wire-format) so dashboards can
    /// distinguish "bundle parsed but logically incoherent"
    /// from "bundle bytes are corrupt". The policy holder
    /// returns this on `try_replace` and the previously-
    /// loaded ruleset stays active.
    #[error("invalid policy: {0}")]
    InvalidPolicy(String),

    /// A provider returned an error. The orchestrator's
    /// fail-policy decides whether the request is allowed
    /// or blocked; the variant exists so the supervisor
    /// can distinguish "provider down" from "policy
    /// denied".
    #[error("provider {provider}: {reason}")]
    ProviderFailure {
        /// Provider name — surfaced to ops logs as a
        /// label.
        provider: String,
        /// Human-readable reason.
        reason: String,
    },

    /// The egress channel into the telemetry pipeline
    /// rejected the [`sng_core::events::SdwanEvent`].
    /// The orchestrator never blocks on telemetry — this
    /// variant is surfaced for ops visibility but the
    /// caller's verdict is unaffected.
    #[error("telemetry: {0}")]
    Telemetry(String),
}

impl SdwanError {
    /// Map to the stable workspace error code.
    ///
    /// `BundleDecode` and `InvalidPolicy` both map to
    /// [`ErrorCode::WireSchema`] — bundle-shape problems
    /// in the wire/parse layer or the value-domain
    /// validation layer respectively. `ProviderFailure`
    /// and `Telemetry` are I/O-shaped failures.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::BundleDecode(_) | Self::InvalidPolicy(_) => ErrorCode::WireSchema,
            Self::ProviderFailure { .. } | Self::Telemetry(_) => ErrorCode::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn invalid_policy_maps_to_wire_schema() {
        // InvalidPolicy is "bundle parsed but logically
        // incoherent" — the wire-schema namespace is the
        // right bucket because it signals a producer-side
        // mismatch with the receiver's value-domain
        // expectations, not an I/O failure.
        assert_eq!(
            SdwanError::InvalidPolicy("weight is NaN".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn bundle_decode_maps_to_wire_schema() {
        assert_eq!(
            SdwanError::BundleDecode("bad msgpack".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn provider_failure_maps_to_io() {
        assert_eq!(
            SdwanError::ProviderFailure {
                provider: "probe-store".into(),
                reason: "shard 3 unreachable".into(),
            }
            .code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn telemetry_maps_to_io() {
        assert_eq!(
            SdwanError::Telemetry("channel closed".into()).code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn display_includes_provider_label_and_reason() {
        let e = SdwanError::ProviderFailure {
            provider: "probe-store".into(),
            reason: "shard 3 unreachable".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("probe-store"));
        assert!(s.contains("shard 3 unreachable"));
    }
}

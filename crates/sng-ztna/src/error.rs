//! ZTNA subsystem error taxonomy.
//!
//! Each variant maps onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and
//! ops dashboards bucket ZTNA failures into the same
//! dotted-lowercase namespace as every other subsystem.

use sng_core::error::ErrorCode;
use thiserror::Error;

/// Errors produced by the ZTNA subsystem.
#[derive(Debug, Error)]
pub enum ZtnaError {
    /// The access request referenced an `app_id` that
    /// the active app catalog does not contain. Distinct
    /// from a policy-deny so dashboards can distinguish
    /// "user tried to reach a non-existent app" (typo,
    /// stale link, removed app) from "user was actively
    /// denied".
    #[error("unknown app: {app_id}")]
    UnknownApp {
        /// The app id from the request that could not be
        /// resolved.
        app_id: String,
    },

    /// The device id on the request is not enrolled in
    /// the device-trust provider. Distinct from a stale
    /// posture (which is an `IdentityRejected`) so the
    /// ops dashboards can call out unmanaged devices.
    #[error("device not enrolled: {device_id}")]
    DeviceNotEnrolled {
        /// The device id (mTLS cert fingerprint or
        /// SPIFFE ID) that could not be resolved.
        device_id: String,
    },

    /// The user identity on the request is not registered
    /// with the identity provider. Either the IdP didn't
    /// recognise the `sub` claim or the user isn't
    /// onboarded for this tenant yet.
    #[error("identity not found: {user_id}")]
    IdentityNotFound {
        /// The user id (`sub` claim or SPIFFE ID) that
        /// could not be resolved.
        user_id: String,
    },

    /// The bundle adapter could not decode the ZTNA
    /// section of a policy bundle. ZTNA engine fails
    /// closed on this and keeps running with the
    /// previously-loaded ruleset (if any).
    #[error("bundle decode: {0}")]
    BundleDecode(String),

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
    /// rejected the [`sng_core::events::ZtnaEvent`].
    #[error("telemetry: {0}")]
    Telemetry(String),
}

impl ZtnaError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::BundleDecode(_) => ErrorCode::WireSchema,
            Self::UnknownApp { .. }
            | Self::DeviceNotEnrolled { .. }
            | Self::IdentityNotFound { .. } => ErrorCode::IdentityRejected,
            Self::ProviderFailure { .. } | Self::Telemetry(_) => ErrorCode::Io,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn unknown_app_maps_to_identity_rejected() {
        assert_eq!(
            ZtnaError::UnknownApp {
                app_id: "missing".into()
            }
            .code(),
            ErrorCode::IdentityRejected
        );
    }

    #[test]
    fn device_not_enrolled_maps_to_identity_rejected() {
        assert_eq!(
            ZtnaError::DeviceNotEnrolled {
                device_id: "dev-1".into()
            }
            .code(),
            ErrorCode::IdentityRejected
        );
    }

    #[test]
    fn identity_not_found_maps_to_identity_rejected() {
        assert_eq!(
            ZtnaError::IdentityNotFound {
                user_id: "alice".into()
            }
            .code(),
            ErrorCode::IdentityRejected
        );
    }

    #[test]
    fn bundle_decode_maps_to_wire_schema() {
        assert_eq!(
            ZtnaError::BundleDecode("bad".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn provider_failure_maps_to_io() {
        assert_eq!(
            ZtnaError::ProviderFailure {
                provider: "device".into(),
                reason: "timeout".into(),
            }
            .code(),
            ErrorCode::Io
        );
    }

    #[test]
    fn telemetry_maps_to_io() {
        assert_eq!(ZtnaError::Telemetry("closed".into()).code(), ErrorCode::Io);
    }

    #[test]
    fn display_includes_payload() {
        let err = ZtnaError::UnknownApp {
            app_id: "wiki".into(),
        };
        assert_eq!(format!("{err}"), "unknown app: wiki");
    }
}

//! ZTNA subsystem error taxonomy.
//!
//! Each variant maps onto the workspace-wide
//! [`sng_core::error::ErrorCode`] so the supervisor and
//! ops dashboards bucket ZTNA failures into the same
//! dotted-lowercase namespace as every other subsystem.

use sng_core::error::ErrorCode;
use thiserror::Error;

use crate::policy::ZtnaDecisionReason;

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

    /// The candidate [`crate::policy::ZtnaPolicy`] failed
    /// value-domain validation (e.g. a freshness budget
    /// of zero, which would mark every MFA / posture
    /// signal stale). Distinct from `BundleDecode`
    /// (wire-format) so dashboards can distinguish
    /// "bundle parsed but logically incoherent" from
    /// "bundle bytes are corrupt". The policy holder
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
    /// rejected the [`sng_core::events::ZtnaEvent`].
    #[error("telemetry: {0}")]
    Telemetry(String),
}

impl ZtnaError {
    /// Map to the stable workspace error code.
    ///
    /// `UnknownApp` maps to
    /// [`ErrorCode::ResourceMissing`] (the user may be
    /// fully authenticated but is requesting a resource
    /// that is not in the active catalog — the failure is
    /// resource-shaped, not identity-shaped).
    ///
    /// `DeviceNotEnrolled` and `IdentityNotFound` map to
    /// [`ErrorCode::IdentityRejected`] — the proxy's
    /// mTLS + IdP chain may have produced a client cert
    /// or `sub` claim, but the ZTNA brain itself has no
    /// record for that identity, which from the
    /// supervisor's perspective is functionally
    /// indistinguishable from an mTLS-level rejection.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::BundleDecode(_) | Self::InvalidPolicy(_) => ErrorCode::WireSchema,
            Self::UnknownApp { .. } => ErrorCode::ResourceMissing,
            Self::DeviceNotEnrolled { .. } | Self::IdentityNotFound { .. } => {
                ErrorCode::IdentityRejected
            }
            Self::ProviderFailure { .. } | Self::Telemetry(_) => ErrorCode::Io,
        }
    }

    /// Map a *provider-resolution* error from
    /// [`crate::service::ZtnaService::evaluate`] to the deny
    /// [`ZtnaDecisionReason`] it is equivalent to.
    ///
    /// `evaluate` returns `Err` only for the three resolution
    /// misses — `UnknownApp`, `DeviceNotEnrolled`,
    /// `IdentityNotFound` — each of which is a genuine deny cause
    /// for a *live* session (the app was de-listed, the device was
    /// offboarded, or the user record was removed). The continuous
    /// re-evaluation loop uses this to treat those errors as a
    /// verdict flip to deny rather than as "still allowed", mapping
    /// each to its decision-reason twin.
    ///
    /// The remaining variants (`BundleDecode`, `InvalidPolicy`,
    /// `ProviderFailure`, `Telemetry`) are never produced by
    /// `evaluate` — they originate at bundle-load / telemetry time.
    /// Should one ever reach this mapping it is treated as a
    /// fail-closed [`ZtnaDecisionReason::Revoked`]: a session that
    /// cannot be positively re-affirmed must not be kept alive.
    #[must_use]
    pub fn as_decision_reason(&self) -> ZtnaDecisionReason {
        match self {
            Self::UnknownApp { .. } => ZtnaDecisionReason::UnknownApp,
            Self::DeviceNotEnrolled { .. } => ZtnaDecisionReason::DeviceNotEnrolled,
            Self::IdentityNotFound { .. } => ZtnaDecisionReason::IdentityNotFound,
            Self::BundleDecode(_)
            | Self::InvalidPolicy(_)
            | Self::ProviderFailure { .. }
            | Self::Telemetry(_) => ZtnaDecisionReason::Revoked,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn unknown_app_maps_to_resource_missing() {
        // `UnknownApp` is "user is fine, the resource isn't" —
        // distinct from identity-rejection and modelled as
        // `ResourceMissing` so dashboards bucket it next to
        // other resource-not-found failures (missing policy
        // bundle, missing device record, missing signing key)
        // rather than next to authn / authz rejections.
        assert_eq!(
            ZtnaError::UnknownApp {
                app_id: "missing".into()
            }
            .code(),
            ErrorCode::ResourceMissing
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
    fn invalid_policy_maps_to_wire_schema() {
        // `InvalidPolicy` joins `BundleDecode` under
        // `wire.schema` — both surface "the bundle that
        // arrived was structurally unusable" to ops
        // dashboards, even though `InvalidPolicy` catches
        // value-domain failures (zero freshness budget)
        // and `BundleDecode` catches byte-level failures.
        assert_eq!(
            ZtnaError::InvalidPolicy("mfa_max_age_ms must be > 0".into()).code(),
            ErrorCode::WireSchema
        );
    }

    #[test]
    fn invalid_policy_display_includes_reason() {
        let err = ZtnaError::InvalidPolicy("mfa_max_age_ms must be > 0".into());
        assert!(format!("{err}").contains("mfa_max_age_ms"));
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

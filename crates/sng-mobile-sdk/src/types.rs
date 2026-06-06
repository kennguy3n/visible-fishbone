// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! FFI-safe mirrors of the agent core's domain types.
//!
//! The core's public types carry payloads UniFFI cannot marshal
//! directly — `chrono::DateTime<Utc>`, `usize`, secret-zeroizing
//! token wrappers. Each type here is the **owned, plain-data**
//! projection that crosses the boundary: timestamps become
//! `i64` epoch-milliseconds (unambiguous and language-neutral),
//! counts become `u64`, and no secret material is ever included.
//! `From` impls do the one-way core → FFI conversion at the
//! boundary.

use chrono::{DateTime, Utc};
use sng_mobile_core::{
    AccessRequest, AgentHealth, AuthState, EnrollmentOutcome, LifecycleState,
    MobilePostureSnapshot, TunnelStatus, ZtnaDecision,
};

/// Convert a `chrono` UTC timestamp to epoch milliseconds for the
/// FFI boundary.
fn to_epoch_ms(ts: DateTime<Utc>) -> i64 {
    ts.timestamp_millis()
}

/// The agent's lifecycle phase, FFI-safe mirror of
/// [`sng_mobile_core::LifecycleState`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SdkLifecycleState {
    /// Constructed, not yet enrolled.
    Init,
    /// Claim-token enrolment in flight.
    Enrolling,
    /// Enrolled and steady-state.
    Connected,
    /// Backgrounded / network lost.
    Suspended,
    /// Torn down (terminal).
    Terminated,
}

impl From<LifecycleState> for SdkLifecycleState {
    fn from(value: LifecycleState) -> Self {
        match value {
            LifecycleState::Init => Self::Init,
            LifecycleState::Enrolling => Self::Enrolling,
            LifecycleState::Connected => Self::Connected,
            LifecycleState::Suspended => Self::Suspended,
            LifecycleState::Terminated => Self::Terminated,
        }
    }
}

/// Coarse, secret-free auth-session state, FFI-safe mirror of
/// [`sng_mobile_core::AuthState`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SdkAuthState {
    /// No usable credential is held.
    Unauthenticated,
    /// A valid access token is held.
    Authenticated {
        /// Absolute expiry of the held access token, epoch
        /// milliseconds.
        expires_at_epoch_ms: i64,
    },
    /// The access token expired; a refresh may recover it.
    Expired,
    /// A refresh is in flight.
    Refreshing,
}

impl From<AuthState> for SdkAuthState {
    fn from(value: AuthState) -> Self {
        match value {
            AuthState::Unauthenticated => Self::Unauthenticated,
            AuthState::Authenticated { expires_at } => Self::Authenticated {
                expires_at_epoch_ms: to_epoch_ms(expires_at),
            },
            AuthState::Expired => Self::Expired,
            AuthState::Refreshing => Self::Refreshing,
        }
    }
}

/// Secret-free health snapshot, FFI-safe mirror of
/// [`sng_mobile_core::AgentHealth`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SdkAgentHealth {
    /// Current lifecycle phase.
    pub lifecycle: SdkLifecycleState,
    /// Whether the auth session holds a usable token.
    pub authenticated: bool,
    /// Number of apps currently in the allowed state.
    pub allowed_apps: u64,
}

impl From<AgentHealth> for SdkAgentHealth {
    fn from(value: AgentHealth) -> Self {
        Self {
            lifecycle: value.lifecycle.into(),
            authenticated: value.authenticated,
            allowed_apps: u64::try_from(value.allowed_apps).unwrap_or(u64::MAX),
        }
    }
}

/// Device posture snapshot, FFI-safe mirror of
/// [`sng_mobile_core::MobilePostureSnapshot`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SdkPostureSnapshot {
    /// OS version string. Empty when unknown.
    pub os_version: String,
    /// Reporting agent version. Empty when unset.
    pub agent_version: String,
    /// When the snapshot was collected, epoch milliseconds.
    pub collected_at_epoch_ms: Option<i64>,
    /// Whether a device passcode / screen lock is set.
    pub passcode_set: Option<bool>,
    /// iOS: whether the device appears jailbroken.
    pub jailbroken: Option<bool>,
    /// Android: whether the device appears rooted.
    pub root_detected: Option<bool>,
    /// Whether biometric auth is enrolled and ready.
    pub biometric_ready: Option<bool>,
    /// Whether the device is enrolled in an MDM.
    pub mdm_enrolled: Option<bool>,
    /// Convenience flag: jailbroken or rooted. The authoritative
    /// posture verdict still belongs to the control-plane
    /// evaluator; this mirrors
    /// [`MobilePostureSnapshot::is_compromised`] for quick host-UI
    /// gating.
    pub compromised: bool,
}

impl From<MobilePostureSnapshot> for SdkPostureSnapshot {
    fn from(value: MobilePostureSnapshot) -> Self {
        let compromised = value.is_compromised();
        Self {
            os_version: value.os_version,
            agent_version: value.agent_version,
            collected_at_epoch_ms: value.collected_at.map(to_epoch_ms),
            passcode_set: value.passcode_set,
            jailbroken: value.jailbroken,
            root_detected: value.root_detected,
            biometric_ready: value.biometric_ready,
            mdm_enrolled: value.mdm_enrolled,
            compromised,
        }
    }
}

/// Data-plane tunnel status, FFI-safe mirror of
/// [`sng_mobile_core::TunnelStatus`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SdkTunnelStatus {
    /// No tunnel is established.
    Down,
    /// A tunnel is being established.
    Connecting,
    /// The tunnel is up.
    Up {
        /// When the tunnel reached the up state, epoch
        /// milliseconds.
        since_epoch_ms: i64,
    },
    /// The tunnel failed.
    Failed {
        /// Operator-readable reason.
        reason: String,
    },
}

impl From<TunnelStatus> for SdkTunnelStatus {
    fn from(value: TunnelStatus) -> Self {
        match value {
            TunnelStatus::Down => Self::Down,
            TunnelStatus::Connecting => Self::Connecting,
            TunnelStatus::Up { since } => Self::Up {
                since_epoch_ms: to_epoch_ms(since),
            },
            TunnelStatus::Failed { reason } => Self::Failed { reason },
        }
    }
}

/// Outcome of a successful claim-token enrolment, FFI-safe mirror
/// of [`sng_mobile_core::EnrollmentOutcome`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SdkEnrollmentOutcome {
    /// Device id the control plane bound the enrolment to (UUID
    /// string).
    pub device_id: String,
    /// Tenant the device is enrolled under (UUID string).
    pub tenant_id: String,
    /// Enrolment status string returned by the control plane.
    pub status: String,
    /// PEM-encoded certificate chain issued to the device.
    pub cert_chain_pem: String,
    /// When the issued certificate expires, epoch milliseconds.
    pub cert_expires_at_epoch_ms: i64,
}

impl From<EnrollmentOutcome> for SdkEnrollmentOutcome {
    fn from(value: EnrollmentOutcome) -> Self {
        Self {
            device_id: value.device_id.to_string(),
            tenant_id: value.tenant_id.to_string(),
            status: value.status,
            cert_chain_pem: value.cert_chain_pem,
            cert_expires_at_epoch_ms: to_epoch_ms(value.cert_expires_at),
        }
    }
}

/// A ZTNA per-application access attempt, FFI-safe input mirror of
/// [`sng_ztna::AccessRequest`].
///
/// The host supplies the identifiers it already holds; the network
/// context the on-device evaluator does not see (source IP / GeoIP
/// country) is intentionally omitted — those are proxy-derived and
/// gated server-side.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SdkAccessRequest {
    /// The application the request targets.
    pub app_id: String,
    /// The enrolled device making the request.
    pub device_id: String,
    /// The user making the request (`sub` claim).
    pub user_id: String,
    /// Monotonic millisecond timestamp the host observed the
    /// request at (used for posture / MFA freshness budgets).
    pub now_ms: u64,
}

impl From<SdkAccessRequest> for AccessRequest {
    fn from(value: SdkAccessRequest) -> Self {
        Self::new(value.app_id, value.device_id, value.user_id, value.now_ms)
    }
}

/// A ZTNA access decision, FFI-safe output mirror of
/// [`sng_ztna::ZtnaDecision`].
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct SdkAccessDecision {
    /// Whether access is granted.
    pub allow: bool,
    /// Stable reason label (e.g. `allow`, `tenant_mismatch`,
    /// `device_posture_insufficient`).
    pub reason: String,
    /// Posture sub-verdict label (`pass` / `fail` / `degraded`).
    pub posture_result: String,
}

impl From<ZtnaDecision> for SdkAccessDecision {
    fn from(value: ZtnaDecision) -> Self {
        Self {
            allow: value.allow,
            reason: value.reason.as_str().to_owned(),
            posture_result: value.posture_result.as_str().to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone as _;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn lifecycle_maps_every_variant() {
        let pairs = [
            (LifecycleState::Init, SdkLifecycleState::Init),
            (LifecycleState::Enrolling, SdkLifecycleState::Enrolling),
            (LifecycleState::Connected, SdkLifecycleState::Connected),
            (LifecycleState::Suspended, SdkLifecycleState::Suspended),
            (LifecycleState::Terminated, SdkLifecycleState::Terminated),
        ];
        for (core, sdk) in pairs {
            assert_eq!(SdkLifecycleState::from(core), sdk);
        }
    }

    #[test]
    fn auth_state_authenticated_carries_expiry_in_epoch_ms() {
        let expires_at = Utc.timestamp_opt(1_700_000_000, 0).single().expect("ts");
        let sdk = SdkAuthState::from(AuthState::Authenticated { expires_at });
        assert_eq!(
            sdk,
            SdkAuthState::Authenticated {
                expires_at_epoch_ms: 1_700_000_000_000
            }
        );
    }

    #[test]
    fn posture_compromised_tracks_jailbroken_flag() {
        let snap = MobilePostureSnapshot {
            jailbroken: Some(true),
            ..Default::default()
        };
        let sdk = SdkPostureSnapshot::from(snap);
        assert!(sdk.compromised);
        assert_eq!(sdk.jailbroken, Some(true));
    }

    #[test]
    fn tunnel_up_carries_since_in_epoch_ms() {
        let since = Utc.timestamp_opt(1_700_000_000, 0).single().expect("ts");
        let sdk = SdkTunnelStatus::from(TunnelStatus::Up { since });
        assert_eq!(
            sdk,
            SdkTunnelStatus::Up {
                since_epoch_ms: 1_700_000_000_000
            }
        );
    }
}

//! Typed error taxonomy for the mobile agent core.
//!
//! [`MobileError`] is the single error type the crate's public
//! orchestration surface ([`crate::MobileAgent`]) converges on.
//! The trait surfaces that the iOS / Android Platform Abstraction
//! Layers implement carry their own narrow error types
//! ([`crate::KeyStoreError`], [`crate::AuthError`],
//! [`crate::TokenStorageError`], [`crate::PostureError`],
//! [`crate::TunnelError`]) so a PAL implementer only has to reason
//! about the failure modes of the one trait they are implementing;
//! `MobileError` then aggregates them with `#[from]` so the agent
//! loop can propagate any of them through a single `?`.
//!
//! No variant carries a panic path — every fallible operation in
//! the crate returns one of these instead of `unwrap`/`expect`, in
//! line with the workspace's `clippy::unwrap_used = warn` /
//! `panic = warn` lint posture.

use std::time::Duration;

use thiserror::Error;

use crate::auth::{AuthError, TokenStorageError};
use crate::enrollment::KeyStoreError;
use crate::posture::PostureError;
use crate::tunnel::TunnelError;

/// Convenience result alias for the crate's public API.
pub type MobileResult<T> = Result<T, MobileError>;

/// Aggregate error type for the mobile agent core.
///
/// `#[non_exhaustive]` so adding a new failure class as the agent
/// grows (e.g. an attestation step) is an additive, non-breaking
/// change for downstream PAL crates.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MobileError {
    /// [`crate::MobileAgentConfig`] failed validation.
    #[error("config invalid: {0}")]
    Config(String),

    /// The claim-token enrolment flow failed for a reason that is
    /// neither a key-store fault (covered by [`Self::KeyStore`])
    /// nor a transport fault (covered by [`Self::Comms`]) — e.g.
    /// the control plane returned a malformed device record or
    /// rejected the claim token.
    #[error("enrolment failed: {0}")]
    Enrollment(String),

    /// The platform secure key store rejected a keygen / sign /
    /// load request. Surfaced from the [`crate::SecureKeyStore`]
    /// PAL implementation.
    #[error("secure key store: {0}")]
    KeyStore(#[from] KeyStoreError),

    /// OIDC auth-session lifecycle failure (no usable token,
    /// refresh rejected, …). Surfaced from the
    /// [`crate::AuthSession`] implementation.
    #[error("auth session: {0}")]
    Auth(#[from] AuthError),

    /// Persisting / loading the OIDC token set failed. Surfaced
    /// from the [`crate::TokenStorage`] implementation.
    #[error("token storage: {0}")]
    TokenStorage(#[from] TokenStorageError),

    /// The platform posture collector failed to produce a
    /// snapshot. Surfaced from the [`crate::MobilePostureCollector`]
    /// implementation.
    #[error("posture collection: {0}")]
    Posture(#[from] PostureError),

    /// The platform tunnel provider rejected a start / stop /
    /// rekey request. Surfaced from the
    /// [`crate::MobileTunnelProvider`] implementation.
    #[error("tunnel provider: {0}")]
    Tunnel(#[from] TunnelError),

    /// A ZTNA access evaluation failed (as opposed to evaluating
    /// to a clean deny — that is a successful evaluation that
    /// returns [`sng_ztna::ZtnaDecision::allow`] = `false`).
    #[error("ztna evaluation: {0}")]
    Ztna(#[from] sng_ztna::ZtnaError),

    /// Control-plane transport failure (TLS / HTTP/2 / response
    /// classification). Reuses the shared [`sng_comms`] taxonomy.
    #[error("control plane: {0}")]
    Comms(#[from] sng_comms::CommsError),

    /// A signed policy bundle failed verification.
    #[error("policy bundle: {0}")]
    Policy(#[from] sng_core::policy::VerificationError),

    /// Telemetry envelope encode / decode / validation failure.
    #[error("wire: {0}")]
    Wire(#[from] sng_core::envelope::WireError),

    /// A bounded network operation exceeded its deadline. Carries
    /// the budget that elapsed so the caller can log it.
    #[error("operation timed out after {0:?}")]
    Timeout(Duration),

    /// A lifecycle transition was requested that the agent's
    /// current [`crate::LifecycleState`] does not permit.
    #[error("lifecycle: {0}")]
    Lifecycle(String),
}

impl MobileError {
    /// Whether retrying the operation after a backoff could
    /// plausibly succeed without operator intervention.
    ///
    /// Transport faults and timeouts are transient; a malformed
    /// config, a rejected credential, or a signature failure is
    /// permanent under the current inputs and retrying only burns
    /// battery and radio time — a property that matters on the
    /// sub-0.5%-idle-CPU mobile budget.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Timeout(_) => true,
            Self::Comms(e) => comms_is_retryable(e),
            Self::Config(_)
            | Self::Enrollment(_)
            | Self::KeyStore(_)
            | Self::Auth(_)
            | Self::TokenStorage(_)
            | Self::Posture(_)
            | Self::Tunnel(_)
            | Self::Ztna(_)
            | Self::Policy(_)
            | Self::Wire(_)
            | Self::Lifecycle(_) => false,
        }
    }
}

/// Classify a [`sng_comms::CommsError`] as transient or permanent.
///
/// A connect / I/O / HTTP-2 fault is transient — the next
/// reconnect cycle may land on a healthy control-plane replica. A
/// `4xx` response, an ALPN mismatch, or a bad-config fault is
/// permanent under the current credentials / build and must not be
/// hammered on a tight loop.
fn comms_is_retryable(err: &sng_comms::CommsError) -> bool {
    use sng_comms::{CommsError, ResponseClass};
    match err {
        CommsError::Connect(_) | CommsError::Io(_) | CommsError::Http2(_) => true,
        CommsError::Server { class, .. } => {
            matches!(class, ResponseClass::RateLimited | ResponseClass::ServerError)
        }
        _ => false,
    }
}

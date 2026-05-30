//! ZTNA access-request type.
//!
//! The [`AccessRequest`] is the single input to
//! [`crate::service::ZtnaService::evaluate`]. It carries
//! the four signals the brain needs to make a
//! per-application access decision:
//!
//! - **`app_id`** — the application the request is
//!   targeting.
//! - **`device_id`** — the device making the request, as
//!   identified by the mTLS certificate fingerprint the
//!   proxy observed.
//! - **`user_id`** — the user making the request, as
//!   verified by the upstream IdP (`sub` claim from an
//!   OIDC token, or a SPIFFE ID).
//! - **`now_ms`** — monotonic millisecond timestamp the
//!   producer captured when the request arrived. Used
//!   for the MFA + posture freshness checks.
//!
//! The producer is responsible for verifying the user
//! and device IDs (mTLS + IdP), so the brain trusts
//! these strings as ground truth.

use serde::{Deserialize, Serialize};

/// One per-application access attempt.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AccessRequest {
    /// The application the request is targeting.
    pub app_id: String,
    /// The device making the request (mTLS cert
    /// fingerprint or SPIFFE ID).
    pub device_id: String,
    /// The user making the request (`sub` claim from
    /// OIDC or a SPIFFE ID).
    pub user_id: String,
    /// Monotonic millisecond timestamp when the producer
    /// observed the request.
    pub now_ms: u64,
}

impl AccessRequest {
    /// Convenience constructor for tests.
    #[must_use]
    pub fn new(
        app_id: impl Into<String>,
        device_id: impl Into<String>,
        user_id: impl Into<String>,
        now_ms: u64,
    ) -> Self {
        Self {
            app_id: app_id.into(),
            device_id: device_id.into(),
            user_id: user_id.into(),
            now_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn new_sets_fields() {
        let r = AccessRequest::new("wiki", "dev-1", "alice", 1_000);
        assert_eq!(r.app_id, "wiki");
        assert_eq!(r.device_id, "dev-1");
        assert_eq!(r.user_id, "alice");
        assert_eq!(r.now_ms, 1_000);
    }

    #[test]
    fn serde_roundtrips_through_json() {
        let r = AccessRequest::new("wiki", "dev-1", "alice", 1_000);
        let json = serde_json::to_string(&r).unwrap();
        let back: AccessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn equality_is_per_field() {
        let r1 = AccessRequest::new("wiki", "dev-1", "alice", 1_000);
        let r2 = AccessRequest::new("wiki", "dev-1", "alice", 1_000);
        assert_eq!(r1, r2);
        let r3 = AccessRequest::new("wiki", "dev-2", "alice", 1_000);
        assert_ne!(r1, r3);
    }
}

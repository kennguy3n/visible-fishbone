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

/// Classification of the network path the request
/// arrived on, derived by the proxy from the source IP
/// (corporate CIDR allow-list, VPN concentrator pool,
/// everything else public). Used by
/// [`crate::policy::AccessConditions`] to gate apps to a
/// network class (e.g. "this app is corporate-network
/// only").
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkType {
    /// Source IP is inside a tenant-declared corporate
    /// CIDR.
    Corporate,
    /// Source IP belongs to the VPN concentrator pool.
    Vpn,
    /// Any routable address that is neither corporate nor
    /// VPN.
    Public,
    /// The proxy could not classify the source (no
    /// GeoIP / CIDR match, or the field was absent).
    Unknown,
}

impl NetworkType {
    /// Stable wire string, matching the serde rename so
    /// non-serde call sites (dashboards, logs) get the
    /// same label without round-tripping through
    /// `serde_json`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Corporate => "corporate",
            Self::Vpn => "vpn",
            Self::Public => "public",
            Self::Unknown => "unknown",
        }
    }
}

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
    /// Caller's source IP as observed by the proxy.
    /// `None` when the producer did not forward it.
    /// Carried for telemetry / audit; the evaluator
    /// gates on [`Self::source_country`] and
    /// [`Self::network_type`], which the proxy derives
    /// from this address.
    #[serde(default)]
    pub source_ip: Option<String>,
    /// ISO 3166-1 alpha-2 country the proxy resolved
    /// from the source IP via GeoIP. `None` when no
    /// GeoIP lookup was performed or it failed.
    #[serde(default)]
    pub source_country: Option<String>,
    /// Network class the request arrived on. `None`
    /// when the producer did not classify it (treated
    /// as [`NetworkType::Unknown`] by the evaluator).
    #[serde(default)]
    pub network_type: Option<NetworkType>,
}

impl AccessRequest {
    /// Convenience constructor for tests. The network-
    /// context fields ([`Self::source_ip`],
    /// [`Self::source_country`], [`Self::network_type`])
    /// default to `None`; use [`Self::with_network`] to
    /// set them.
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
            source_ip: None,
            source_country: None,
            network_type: None,
        }
    }

    /// Builder-style setter for the network-context
    /// fields. Returns `self` so it chains off
    /// [`Self::new`].
    #[must_use]
    pub fn with_network(
        mut self,
        source_ip: Option<String>,
        source_country: Option<String>,
        network_type: Option<NetworkType>,
    ) -> Self {
        self.source_ip = source_ip;
        self.source_country = source_country;
        self.network_type = network_type;
        self
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

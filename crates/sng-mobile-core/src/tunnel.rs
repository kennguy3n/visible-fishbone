//! Mobile data-plane tunnel: the provider trait + WireGuard-class
//! key-lifecycle types.
//!
//! The agent core does not move packets itself — on iOS that is the
//! Network Extension (`NEPacketTunnelProvider`) and on Android the
//! `VpnService`, both of which own a real WireGuard-class data
//! plane. [`MobileTunnelProvider`] is the trait those bridges
//! implement; the agent drives it (start / stop / observe) from its
//! ZTNA decisions.
//!
//! The key-lifecycle types ([`TunnelPrivateKey`],
//! [`TunnelPublicKey`], [`TunnelKeypair`]) model the rotation
//! *schedule* of the 32-byte Curve25519 static keys WireGuard uses.
//! The actual curve arithmetic (deriving a public key from a
//! private key) happens in the platform crypto inside the provider;
//! this crate only holds the material, wipes the private half on
//! drop, and tracks when a rotation is due.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length in bytes of a Curve25519 WireGuard key.
pub const TUNNEL_KEY_LEN: usize = 32;

/// A WireGuard-class public key (32-byte Curve25519 point).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct TunnelPublicKey([u8; TUNNEL_KEY_LEN]);

impl TunnelPublicKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TUNNEL_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; TUNNEL_KEY_LEN] {
        &self.0
    }

    /// Standard-base64 encoding (the form WireGuard config files
    /// and the control plane use).
    #[must_use]
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// Parse a standard-base64 WireGuard public key.
    pub fn from_base64(s: &str) -> Result<Self, TunnelError> {
        let raw = base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(|e| TunnelError::Key(format!("invalid base64: {e}")))?;
        let bytes: [u8; TUNNEL_KEY_LEN] = raw
            .try_into()
            .map_err(|_| TunnelError::Key("public key must be 32 bytes".into()))?;
        Ok(Self(bytes))
    }
}

impl fmt::Debug for TunnelPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public keys are not secret, but render the short base64
        // form rather than a 32-element byte array for readable logs.
        f.debug_tuple("TunnelPublicKey").field(&self.to_base64()).finish()
    }
}

/// A WireGuard-class private key (32-byte Curve25519 scalar seed).
/// Wiped on drop; [`fmt::Debug`] is redacted.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct TunnelPrivateKey([u8; TUNNEL_KEY_LEN]);

impl TunnelPrivateKey {
    /// Wrap raw key bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; TUNNEL_KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Generate a fresh 32-byte private key from the OS CSPRNG. A
    /// WireGuard private key is exactly 32 random bytes (the
    /// daemon clamps them on use), so this is a complete, usable
    /// private key; the matching public key is derived by the
    /// platform crypto in the [`MobileTunnelProvider`].
    #[must_use]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; TUNNEL_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Borrow the raw secret bytes. Use only at the point of
    /// handing the key to the platform tunnel backend.
    #[must_use]
    pub fn expose_bytes(&self) -> &[u8; TUNNEL_KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for TunnelPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TunnelPrivateKey(***redacted***)")
    }
}

/// A tunnel static keypair plus the instant it was created, so the
/// agent can enforce a rotation interval.
#[derive(Clone, Debug)]
pub struct TunnelKeypair {
    /// Public half (safe to send to the control plane).
    pub public_key: TunnelPublicKey,
    /// Private half (wiped on drop).
    pub private_key: TunnelPrivateKey,
    /// When this keypair was generated.
    pub created_at: DateTime<Utc>,
}

impl TunnelKeypair {
    /// Assemble a keypair from its parts. The public key is
    /// expected to have been derived from `private_key` by the
    /// platform crypto.
    #[must_use]
    pub fn new(
        public_key: TunnelPublicKey,
        private_key: TunnelPrivateKey,
        created_at: DateTime<Utc>,
    ) -> Self {
        Self {
            public_key,
            private_key,
            created_at,
        }
    }

    /// Age of the keypair as of `now` (saturating at zero for a
    /// clock that ran backwards).
    #[must_use]
    pub fn age(&self, now: DateTime<Utc>) -> Duration {
        (now - self.created_at).to_std().unwrap_or(Duration::ZERO)
    }

    /// Whether the keypair is older than `max_age` and should be
    /// rotated.
    #[must_use]
    pub fn needs_rotation(&self, now: DateTime<Utc>, max_age: Duration) -> bool {
        self.age(now) >= max_age
    }
}

/// A WireGuard-class tunnel configuration handed to
/// [`MobileTunnelProvider::start_tunnel`].
#[derive(Clone, Debug)]
pub struct TunnelConfig {
    /// This device's tunnel private key.
    pub interface_private_key: TunnelPrivateKey,
    /// The gateway peer's public key.
    pub peer_public_key: TunnelPublicKey,
    /// Gateway endpoint as `host:port`.
    pub endpoint: String,
    /// Prefixes routed into the tunnel.
    pub allowed_ips: Vec<IpNet>,
    /// DNS resolvers to use while the tunnel is up.
    pub dns: Vec<IpAddr>,
    /// Keepalive interval for NAT traversal, if set.
    pub persistent_keepalive: Option<Duration>,
    /// Tunnel MTU, if the host app pins one.
    pub mtu: Option<u16>,
}

impl TunnelConfig {
    /// Validate the config before handing it to the platform
    /// backend: a tunnel with no endpoint or no routed prefixes is
    /// a misconfiguration the provider would reject anyway.
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.endpoint.trim().is_empty() {
            return Err(TunnelError::Config("endpoint must not be empty".into()));
        }
        if self.allowed_ips.is_empty() {
            return Err(TunnelError::Config(
                "allowed_ips must route at least one prefix".into(),
            ));
        }
        Ok(())
    }
}

/// Observable state of the data-plane tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TunnelStatus {
    /// No tunnel is established.
    Down,
    /// A tunnel is being established.
    Connecting,
    /// The tunnel is up; carries the instant it came up.
    Up {
        /// When the tunnel reached the up state.
        since: DateTime<Utc>,
    },
    /// The tunnel failed; carries an operator-readable reason.
    Failed {
        /// Why the tunnel is not up.
        reason: String,
    },
}

impl TunnelStatus {
    /// Whether the tunnel is currently carrying traffic.
    #[must_use]
    pub fn is_up(&self) -> bool {
        matches!(self, Self::Up { .. })
    }
}

/// Failure modes of the [`MobileTunnelProvider`] surface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TunnelError {
    /// The supplied [`TunnelConfig`] was rejected.
    #[error("tunnel config: {0}")]
    Config(String),
    /// A tunnel key could not be parsed / encoded.
    #[error("tunnel key: {0}")]
    Key(String),
    /// The platform tunnel backend failed to start / stop the
    /// tunnel.
    #[error("tunnel backend: {0}")]
    Backend(String),
}

/// The platform data-plane tunnel.
///
/// Object-safe so the agent holds it as
/// `Arc<dyn MobileTunnelProvider>`. Implemented by the iOS
/// `NEPacketTunnelProvider` bridge and the Android `VpnService`
/// bridge.
#[async_trait]
pub trait MobileTunnelProvider: Send + Sync {
    /// Bring the tunnel up with `config`. Idempotent: starting an
    /// already-up tunnel with an equivalent config should succeed
    /// without tearing it down.
    async fn start_tunnel(&self, config: TunnelConfig) -> Result<(), TunnelError>;
    /// Tear the tunnel down. Idempotent on an already-down tunnel.
    async fn stop_tunnel(&self) -> Result<(), TunnelError>;
    /// Current tunnel status.
    async fn status(&self) -> TunnelStatus;
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn public_key_base64_roundtrips() {
        let key = TunnelPublicKey::from_bytes([7u8; TUNNEL_KEY_LEN]);
        let b64 = key.to_base64();
        let back = TunnelPublicKey::from_base64(&b64).unwrap();
        assert_eq!(key, back);
    }

    #[test]
    fn public_key_from_bad_base64_errors() {
        assert!(TunnelPublicKey::from_base64("not base64!!!").is_err());
        // Valid base64 but wrong length.
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 8]);
        assert!(TunnelPublicKey::from_base64(&short).is_err());
    }

    #[test]
    fn generated_private_keys_differ() {
        let a = TunnelPrivateKey::generate();
        let b = TunnelPrivateKey::generate();
        assert_ne!(a.expose_bytes(), b.expose_bytes());
    }

    #[test]
    fn private_key_debug_is_redacted() {
        let k = TunnelPrivateKey::from_bytes([9u8; TUNNEL_KEY_LEN]);
        assert!(!format!("{k:?}").contains('9'));
        assert!(format!("{k:?}").contains("redacted"));
    }

    #[test]
    fn keypair_rotation_is_age_based() {
        let created = Utc::now() - chrono::Duration::hours(2);
        let kp = TunnelKeypair::new(
            TunnelPublicKey::from_bytes([1u8; TUNNEL_KEY_LEN]),
            TunnelPrivateKey::from_bytes([2u8; TUNNEL_KEY_LEN]),
            created,
        );
        let now = Utc::now();
        assert!(kp.needs_rotation(now, Duration::from_secs(3600)));
        assert!(!kp.needs_rotation(now, Duration::from_secs(36_000)));
    }

    #[test]
    fn config_validation_rejects_empty_endpoint_and_routes() {
        let mut cfg = TunnelConfig {
            interface_private_key: TunnelPrivateKey::from_bytes([0u8; TUNNEL_KEY_LEN]),
            peer_public_key: TunnelPublicKey::from_bytes([0u8; TUNNEL_KEY_LEN]),
            endpoint: String::new(),
            allowed_ips: vec!["10.0.0.0/8".parse().unwrap()],
            dns: vec![],
            persistent_keepalive: None,
            mtu: None,
        };
        assert!(cfg.validate().is_err());
        cfg.endpoint = "gw.example.com:51820".into();
        assert!(cfg.validate().is_ok());
        cfg.allowed_ips.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn status_is_up_only_when_up() {
        assert!(TunnelStatus::Up { since: Utc::now() }.is_up());
        assert!(!TunnelStatus::Down.is_up());
        assert!(!TunnelStatus::Connecting.is_up());
    }
}

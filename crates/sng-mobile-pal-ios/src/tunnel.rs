// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! [`IosTunnelProvider`] — the iOS [`MobileTunnelProvider`] backend.
//!
//! ## Modeling: control side of an `NEPacketTunnelProvider`
//!
//! A library crate cannot itself be the Network Extension process — the
//! packet-tunnel runs in a separate app extension the host app ships.
//! This type is therefore the **control side**: it
//!
//! 1. validates + translates a [`TunnelConfig`] into a
//!    [`WireGuardSettings`] and a `wg-quick`-style configuration string
//!    (the form the WireGuardKit packet-tunnel extension consumes), and
//! 2. on iOS, publishes that string as the `providerConfiguration` of a
//!    `NETunnelProviderProtocol` on a `NETunnelProviderManager`, then
//!    asks the VPN connection to start; while
//! 3. tracking the [`TunnelStatus`] the agent observes.
//!
//! The validation + translation (the security-relevant part) is pure
//! and host-tested. Only the NetworkExtension calls are
//! `#[cfg(target_os = "ios")]`; the host fallback returns
//! [`TunnelError::Backend`] and never reports a fake "up".

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine as _;
use sng_mobile_core::{MobileTunnelProvider, TunnelConfig, TunnelError, TunnelStatus};
use tokio::sync::Mutex;

/// `providerConfiguration` key under which the packet-tunnel extension
/// reads the `wg-quick` configuration string.
pub const WG_QUICK_CONFIG_KEY: &str = "wg_quick_config";

/// The WireGuard parameters translated out of a [`TunnelConfig`], ready
/// to hand to the packet-tunnel extension.
///
/// [`fmt::Debug`](std::fmt::Debug) is hand-written to redact the
/// interface private key so it never lands in logs.
#[derive(Clone, PartialEq, Eq)]
pub struct WireGuardSettings {
    /// Interface (device) private key, standard-base64.
    interface_private_key_base64: String,
    /// Peer (gateway) public key, standard-base64.
    peer_public_key_base64: String,
    /// Gateway endpoint, `host:port`.
    endpoint: String,
    /// Prefixes routed into the tunnel, in CIDR text.
    allowed_ips: Vec<String>,
    /// DNS resolvers to use while up.
    dns: Vec<String>,
    /// NAT-keepalive interval in whole seconds, if set.
    persistent_keepalive_secs: Option<u64>,
    /// Pinned tunnel MTU, if set.
    mtu: Option<u16>,
}

impl std::fmt::Debug for WireGuardSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardSettings")
            .field("interface_private_key_base64", &"***redacted***")
            .field("peer_public_key_base64", &self.peer_public_key_base64)
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .field("dns", &self.dns)
            .field("persistent_keepalive_secs", &self.persistent_keepalive_secs)
            .field("mtu", &self.mtu)
            .finish()
    }
}

impl WireGuardSettings {
    /// Validate and translate a [`TunnelConfig`] into WireGuard
    /// settings. Returns [`TunnelError::Config`] for a rejected config.
    pub fn from_config(config: &TunnelConfig) -> Result<Self, TunnelError> {
        config.validate()?;
        Ok(Self {
            interface_private_key_base64: base64::engine::general_purpose::STANDARD
                .encode(config.interface_private_key.expose_bytes()),
            peer_public_key_base64: config.peer_public_key.to_base64(),
            endpoint: config.endpoint.clone(),
            allowed_ips: config.allowed_ips.iter().map(ToString::to_string).collect(),
            dns: config.dns.iter().map(ToString::to_string).collect(),
            persistent_keepalive_secs: config.persistent_keepalive.map(|d| d.as_secs()),
            mtu: config.mtu,
        })
    }

    /// The gateway endpoint (`host:port`).
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Render the canonical `wg-quick` INI the packet-tunnel extension
    /// consumes. The `[Interface]` `Address` line is intentionally
    /// omitted: the device's tunnel IP is assigned by the extension
    /// from the gateway handshake, not pinned here.
    #[must_use]
    pub fn to_wg_quick(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("[Interface]\n");
        // Writing to a String is infallible; ignore the formatter Result.
        let _ = writeln!(out, "PrivateKey = {}", self.interface_private_key_base64);
        if let Some(mtu) = self.mtu {
            let _ = writeln!(out, "MTU = {mtu}");
        }
        if !self.dns.is_empty() {
            let _ = writeln!(out, "DNS = {}", self.dns.join(", "));
        }
        out.push_str("\n[Peer]\n");
        let _ = writeln!(out, "PublicKey = {}", self.peer_public_key_base64);
        let _ = writeln!(out, "Endpoint = {}", self.endpoint);
        let _ = writeln!(out, "AllowedIPs = {}", self.allowed_ips.join(", "));
        if let Some(secs) = self.persistent_keepalive_secs {
            let _ = writeln!(out, "PersistentKeepalive = {secs}");
        }
        out
    }
}

/// iOS [`MobileTunnelProvider`] — control side of an
/// `NEPacketTunnelProvider`.
#[derive(Debug, Clone)]
pub struct IosTunnelProvider {
    /// Bundle identifier of the packet-tunnel app extension, required at
    /// runtime to bind the `NETunnelProviderProtocol` to the host app's
    /// extension. Unused on the host build.
    #[cfg_attr(not(target_os = "ios"), allow(dead_code))]
    provider_bundle_id: Option<String>,
    status: Arc<Mutex<TunnelStatus>>,
}

impl Default for IosTunnelProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl IosTunnelProvider {
    /// Construct a provider with no extension bundle id set. A bundle id
    /// is required for a real start on device; use
    /// [`Self::with_provider_bundle_id`] there.
    #[must_use]
    pub fn new() -> Self {
        Self {
            provider_bundle_id: None,
            status: Arc::new(Mutex::new(TunnelStatus::Down)),
        }
    }

    /// Construct a provider bound to the host app's packet-tunnel
    /// extension bundle identifier.
    #[must_use]
    pub fn with_provider_bundle_id(bundle_id: impl Into<String>) -> Self {
        Self {
            provider_bundle_id: Some(bundle_id.into()),
            status: Arc::new(Mutex::new(TunnelStatus::Down)),
        }
    }
}

// ---------------------------------------------------------------------
// iOS backend
// ---------------------------------------------------------------------
#[cfg(target_os = "ios")]
mod network_extension {
    use super::{WG_QUICK_CONFIG_KEY, WireGuardSettings};
    use crate::error::IosPalError;
    use objc2::runtime::AnyObject;
    use objc2_foundation::{NSDictionary, NSString};
    use objc2_network_extension::{NETunnelProviderManager, NETunnelProviderProtocol};

    /// Build the single-entry `providerConfiguration` dictionary
    /// (`{ wg_quick_config: <ini> }`) the extension reads.
    fn provider_configuration(
        settings: &WireGuardSettings,
    ) -> objc2::rc::Retained<NSDictionary<NSString, AnyObject>> {
        let key = NSString::from_str(WG_QUICK_CONFIG_KEY);
        let value = NSString::from_str(&settings.to_wg_quick());
        let value: &AnyObject = &value;
        NSDictionary::from_slices(&[&*key], &[value])
    }

    /// Configure a manager + protocol from `settings` and ask the VPN
    /// connection to start. Any Apple error is mapped onto a typed
    /// [`IosPalError`].
    ///
    /// # Safety
    /// All calls are objc2 message sends to freshly constructed
    /// NetworkExtension objects with no aliasing; inputs are owned
    /// Foundation objects built just above.
    #[allow(unsafe_code)]
    pub(super) fn start(
        settings: &WireGuardSettings,
        provider_bundle_id: Option<&str>,
    ) -> Result<(), IosPalError> {
        let config = provider_configuration(settings);
        unsafe {
            let proto = NETunnelProviderProtocol::new();
            proto.setProviderConfiguration(Some(&config));
            proto.setServerAddress(Some(&NSString::from_str(settings.endpoint())));
            if let Some(bundle_id) = provider_bundle_id {
                proto.setProviderBundleIdentifier(Some(&NSString::from_str(bundle_id)));
            }
            let manager = NETunnelProviderManager::new();
            manager.setProtocolConfiguration(Some(&proto));
            manager.setEnabled(true);
            manager
                .connection()
                .startVPNTunnelAndReturnError()
                .map_err(|e| IosPalError::NetworkExtension(e.localizedDescription().to_string()))
        }
    }

    /// Stop the active VPN connection.
    ///
    /// # Safety
    /// `stopVPNTunnel` is a no-argument message send with no
    /// preconditions on a freshly loaded manager's connection.
    #[allow(unsafe_code)]
    pub(super) fn stop() -> Result<(), IosPalError> {
        unsafe {
            NETunnelProviderManager::new().connection().stopVPNTunnel();
        }
        Ok(())
    }
}

#[cfg(target_os = "ios")]
#[async_trait]
impl MobileTunnelProvider for IosTunnelProvider {
    async fn start_tunnel(&self, config: TunnelConfig) -> Result<(), TunnelError> {
        let settings = WireGuardSettings::from_config(&config)?;
        {
            let mut status = self.status.lock().await;
            *status = TunnelStatus::Connecting;
        }
        match network_extension::start(&settings, self.provider_bundle_id.as_deref()) {
            Ok(()) => {
                *self.status.lock().await = TunnelStatus::Up {
                    since: chrono::Utc::now(),
                };
                Ok(())
            }
            Err(e) => {
                *self.status.lock().await = TunnelStatus::Down;
                Err(e.into())
            }
        }
    }

    async fn stop_tunnel(&self) -> Result<(), TunnelError> {
        network_extension::stop()?;
        *self.status.lock().await = TunnelStatus::Down;
        Ok(())
    }

    async fn status(&self) -> TunnelStatus {
        self.status.lock().await.clone()
    }
}

// ---------------------------------------------------------------------
// Host fallback (Linux CI / desktop dev): typed "unsupported".
// ---------------------------------------------------------------------
#[cfg(not(target_os = "ios"))]
#[async_trait]
impl MobileTunnelProvider for IosTunnelProvider {
    async fn start_tunnel(&self, config: TunnelConfig) -> Result<(), TunnelError> {
        // Still validate + translate so config errors surface uniformly
        // across platforms; then report the platform is unsupported
        // rather than faking a tunnel.
        let _settings = WireGuardSettings::from_config(&config)?;
        Err(crate::error::IosPalError::UnsupportedPlatform("tunnel start".into()).into())
    }

    async fn stop_tunnel(&self) -> Result<(), TunnelError> {
        Err(crate::error::IosPalError::UnsupportedPlatform("tunnel stop".into()).into())
    }

    async fn status(&self) -> TunnelStatus {
        self.status.lock().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use sng_mobile_core::{TunnelPrivateKey, TunnelPublicKey};
    use std::time::Duration;

    fn sample_config() -> TunnelConfig {
        TunnelConfig {
            interface_private_key: TunnelPrivateKey::from_bytes([3u8; 32]),
            peer_public_key: TunnelPublicKey::from_bytes([5u8; 32]),
            endpoint: "gw.example.com:51820".into(),
            allowed_ips: vec![
                "10.0.0.0/8".parse().unwrap(),
                "192.168.1.0/24".parse().unwrap(),
            ],
            dns: vec!["1.1.1.1".parse().unwrap()],
            persistent_keepalive: Some(Duration::from_secs(25)),
            mtu: Some(1380),
        }
    }

    #[test]
    fn translation_encodes_keys_and_routes() {
        let settings = WireGuardSettings::from_config(&sample_config()).unwrap();
        // Peer public key uses the core's canonical base64.
        assert_eq!(
            settings.peer_public_key_base64,
            TunnelPublicKey::from_bytes([5u8; 32]).to_base64()
        );
        // Private key is base64 of the 32 raw bytes.
        assert_eq!(
            settings.interface_private_key_base64,
            base64::engine::general_purpose::STANDARD.encode([3u8; 32])
        );
        assert_eq!(settings.allowed_ips, vec!["10.0.0.0/8", "192.168.1.0/24"]);
        assert_eq!(settings.dns, vec!["1.1.1.1"]);
        assert_eq!(settings.persistent_keepalive_secs, Some(25));
        assert_eq!(settings.mtu, Some(1380));
    }

    #[test]
    fn wg_quick_contains_expected_sections() {
        let settings = WireGuardSettings::from_config(&sample_config()).unwrap();
        let ini = settings.to_wg_quick();
        assert!(ini.contains("[Interface]"));
        assert!(ini.contains("[Peer]"));
        assert!(ini.contains("MTU = 1380"));
        assert!(ini.contains("DNS = 1.1.1.1"));
        assert!(ini.contains("Endpoint = gw.example.com:51820"));
        assert!(ini.contains("AllowedIPs = 10.0.0.0/8, 192.168.1.0/24"));
        assert!(ini.contains("PersistentKeepalive = 25"));
        assert!(ini.contains(&settings.peer_public_key_base64));
    }

    #[test]
    fn optional_fields_are_omitted_when_unset() {
        let mut cfg = sample_config();
        cfg.mtu = None;
        cfg.dns.clear();
        cfg.persistent_keepalive = None;
        let ini = WireGuardSettings::from_config(&cfg).unwrap().to_wg_quick();
        assert!(!ini.contains("MTU"));
        assert!(!ini.contains("DNS"));
        assert!(!ini.contains("PersistentKeepalive"));
    }

    #[test]
    fn invalid_config_is_rejected_before_any_platform_call() {
        let mut cfg = sample_config();
        cfg.endpoint = String::new();
        assert!(matches!(
            WireGuardSettings::from_config(&cfg),
            Err(TunnelError::Config(_))
        ));
    }

    #[test]
    fn debug_redacts_private_key() {
        let settings = WireGuardSettings::from_config(&sample_config()).unwrap();
        let dbg = format!("{settings:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&settings.interface_private_key_base64));
    }

    #[tokio::test]
    async fn provider_starts_down() {
        let p = IosTunnelProvider::new();
        assert!(matches!(p.status().await, TunnelStatus::Down));
        assert!(!p.status().await.is_up());
    }

    #[cfg(not(target_os = "ios"))]
    #[tokio::test]
    async fn host_fallback_is_unsupported_and_stays_down() {
        let p = IosTunnelProvider::with_provider_bundle_id("com.example.tunnel");
        // Valid config still surfaces unsupported (not fake success).
        assert!(matches!(
            p.start_tunnel(sample_config()).await,
            Err(TunnelError::Backend(_))
        ));
        // Invalid config surfaces a config error uniformly.
        let mut bad = sample_config();
        bad.allowed_ips.clear();
        assert!(matches!(
            p.start_tunnel(bad).await,
            Err(TunnelError::Config(_))
        ));
        // Never transitioned to Up.
        assert!(matches!(p.status().await, TunnelStatus::Down));
        assert!(matches!(
            p.stop_tunnel().await,
            Err(TunnelError::Backend(_))
        ));
    }
}

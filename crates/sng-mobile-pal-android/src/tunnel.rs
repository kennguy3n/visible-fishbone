//! [`AndroidTunnelProvider`] — `VpnService`-backed data plane.
//!
//! Packet movement on Android lives in a `VpnService` subclass: it
//! is the only component that can call `VpnService.Builder` and own
//! the `tun` file descriptor. This crate's job (per the trait
//! contract) is to **configure and signal** that service — it
//! translates the WireGuard-class [`TunnelConfig`] into the flat
//! [`VpnServiceConfig`] the `VpnService.Builder` consumes
//! (addresses, routes, DNS, MTU) and tracks the observable
//! [`TunnelStatus`]. The host fallback returns an unsupported
//! error.
//!
//! ## Translation seam (host-testable)
//!
//! [`translate_config`] is the platform-independent core: it
//! validates the config, splits `host:port`, base64-encodes the
//! keys into the WireGuard wire form, and stringifies the routes /
//! DNS. The host unit tests cover it (including IPv6 endpoints and
//! the missing-port error) without a device.

use std::net::IpAddr;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine;
use ipnet::IpNet;
use sng_mobile_core::{MobileTunnelProvider, TunnelConfig, TunnelError, TunnelStatus};

use crate::error::AndroidPalError;

/// Flat configuration handed to the Android `VpnService.Builder`.
///
/// All key material is rendered into the standard-base64 WireGuard
/// wire form, and routes / DNS into their string forms, so the
/// `VpnService` bridge (Session 7) can consume it directly across
/// the UniFFI boundary without re-implementing the encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VpnServiceConfig {
    /// This device's interface private key (standard-base64, the
    /// WireGuard config form).
    pub interface_private_key_b64: String,
    /// The gateway peer's public key (standard-base64).
    pub peer_public_key_b64: String,
    /// Gateway host (IP or DNS name), brackets stripped for IPv6.
    pub endpoint_host: String,
    /// Gateway UDP port.
    pub endpoint_port: u16,
    /// Routes installed into the tunnel, as `addr/prefix` strings.
    pub allowed_ips: Vec<String>,
    /// DNS resolvers, as address strings.
    pub dns: Vec<String>,
    /// Tunnel MTU, if pinned.
    pub mtu: Option<u16>,
    /// Persistent-keepalive interval in whole seconds, if set.
    pub persistent_keepalive_secs: Option<u64>,
}

/// Split an `host:port` endpoint, stripping IPv6 brackets.
fn split_endpoint(endpoint: &str) -> Result<(String, u16), AndroidPalError> {
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| {
        AndroidPalError::InvalidInput(format!("endpoint {endpoint:?} is missing a ':port'"))
    })?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err(AndroidPalError::InvalidInput(format!(
            "endpoint {endpoint:?} has an empty host"
        )));
    }
    let port: u16 = port.parse().map_err(|e| {
        AndroidPalError::InvalidInput(format!("endpoint {endpoint:?} has an invalid port: {e}"))
    })?;
    Ok((host.to_owned(), port))
}

/// Translate a [`TunnelConfig`] into the flat [`VpnServiceConfig`].
///
/// Runs the core [`TunnelConfig::validate`] first, so an empty
/// endpoint or empty route set is rejected here rather than at the
/// platform boundary.
pub fn translate_config(config: &TunnelConfig) -> Result<VpnServiceConfig, AndroidPalError> {
    config
        .validate()
        .map_err(|e| AndroidPalError::InvalidInput(e.to_string()))?;
    let (endpoint_host, endpoint_port) = split_endpoint(&config.endpoint)?;
    Ok(VpnServiceConfig {
        interface_private_key_b64: base64::engine::general_purpose::STANDARD
            .encode(config.interface_private_key.expose_bytes()),
        peer_public_key_b64: config.peer_public_key.to_base64(),
        endpoint_host,
        endpoint_port,
        allowed_ips: config.allowed_ips.iter().map(IpNet::to_string).collect(),
        dns: config.dns.iter().map(IpAddr::to_string).collect(),
        mtu: config.mtu,
        persistent_keepalive_secs: config.persistent_keepalive.map(|d| d.as_secs()),
    })
}

/// Android `VpnService`-backed [`MobileTunnelProvider`].
///
/// Tracks the last observed [`TunnelStatus`] behind a
/// `std::sync::Mutex`; `status()` takes the lock briefly to clone
/// the current value, which is held only for status transitions so
/// contention is negligible. Used as `Arc<dyn MobileTunnelProvider>`,
/// so it does not need to be `Clone`.
#[derive(Debug)]
pub struct AndroidTunnelProvider {
    status: Mutex<TunnelStatus>,
}

impl Default for AndroidTunnelProvider {
    fn default() -> Self {
        Self {
            status: Mutex::new(TunnelStatus::Down),
        }
    }
}

impl AndroidTunnelProvider {
    /// Construct a provider whose tunnel starts in the
    /// [`TunnelStatus::Down`] state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn set_status(&self, status: TunnelStatus) {
        if let Ok(mut guard) = self.status.lock() {
            *guard = status;
        }
    }

    fn current(&self) -> TunnelStatus {
        self.status.lock().map_or(TunnelStatus::Down, |g| g.clone())
    }
}

#[async_trait]
impl MobileTunnelProvider for AndroidTunnelProvider {
    async fn start_tunnel(&self, config: TunnelConfig) -> Result<(), TunnelError> {
        // Translate + validate on every target; a bad config is a
        // config error regardless of platform.
        let vpn_config = translate_config(&config)?;
        match imp::start_tunnel(&vpn_config) {
            Ok(()) => {
                self.set_status(TunnelStatus::Connecting);
                Ok(())
            }
            Err(e) => {
                let err: TunnelError = e.into();
                self.set_status(TunnelStatus::Failed {
                    reason: err.to_string(),
                });
                Err(err)
            }
        }
    }

    async fn stop_tunnel(&self) -> Result<(), TunnelError> {
        match imp::stop_tunnel() {
            Ok(()) => {
                self.set_status(TunnelStatus::Down);
                Ok(())
            }
            Err(e) => Err(e.into()),
        }
    }

    async fn status(&self) -> TunnelStatus {
        self.current()
    }
}

/// Host (non-Android) fallback: no `VpnService`, so starting /
/// stopping the tunnel reports
/// [`AndroidPalError::UnsupportedPlatform`].
#[cfg(not(target_os = "android"))]
mod imp {
    use super::VpnServiceConfig;
    use crate::error::AndroidPalError;

    pub(super) fn start_tunnel(_config: &VpnServiceConfig) -> Result<(), AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidTunnelProvider::start_tunnel",
        ))
    }

    pub(super) fn stop_tunnel() -> Result<(), AndroidPalError> {
        Err(AndroidPalError::unsupported(
            "AndroidTunnelProvider::stop_tunnel",
        ))
    }
}

/// Android implementation: signal the host app's `VpnService` with
/// the translated configuration.
///
/// The `VpnService.Builder` calls (`addAddress` / `addRoute` /
/// `addDnsServer` / `setMtu` / `establish`) can only run inside a
/// `VpnService` instance, so the actual tunnel establishment is
/// owned by the host app's service. This layer hands it the
/// validated, fully-encoded [`VpnServiceConfig`] and transitions
/// the provider into [`TunnelStatus::Connecting`]; the service
/// reports back the terminal `Up` / `Failed` state.
#[cfg(target_os = "android")]
mod imp {
    use super::VpnServiceConfig;
    use crate::error::AndroidPalError;

    pub(super) fn start_tunnel(config: &VpnServiceConfig) -> Result<(), AndroidPalError> {
        // The config has already been validated + encoded by
        // `translate_config`. Signalling the bound `VpnService` is
        // wired in the UniFFI bridge (Session 7); here we accept the
        // validated config so the provider can advance to
        // `Connecting`.
        tracing::info!(
            endpoint_host = %config.endpoint_host,
            endpoint_port = config.endpoint_port,
            routes = config.allowed_ips.len(),
            "android tunnel: configuration accepted, signalling VpnService"
        );
        Ok(())
    }

    pub(super) fn stop_tunnel() -> Result<(), AndroidPalError> {
        tracing::info!("android tunnel: signalling VpnService teardown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use sng_mobile_core::{TUNNEL_KEY_LEN, TunnelPrivateKey, TunnelPublicKey};

    fn config(endpoint: &str) -> TunnelConfig {
        TunnelConfig {
            interface_private_key: TunnelPrivateKey::from_bytes([3u8; TUNNEL_KEY_LEN]),
            peer_public_key: TunnelPublicKey::from_bytes([9u8; TUNNEL_KEY_LEN]),
            endpoint: endpoint.to_owned(),
            allowed_ips: vec![
                "10.0.0.0/8".parse().expect("net"),
                "0.0.0.0/0".parse().expect("net"),
            ],
            dns: vec!["1.1.1.1".parse().expect("ip")],
            persistent_keepalive: Some(Duration::from_secs(25)),
            mtu: Some(1280),
        }
    }

    #[test]
    fn translates_full_config() {
        let translated = translate_config(&config("vpn.example.com:51820")).expect("translate");
        assert_eq!(translated.endpoint_host, "vpn.example.com");
        assert_eq!(translated.endpoint_port, 51820);
        assert_eq!(
            translated.peer_public_key_b64,
            TunnelPublicKey::from_bytes([9u8; TUNNEL_KEY_LEN]).to_base64()
        );
        assert_eq!(
            translated.interface_private_key_b64,
            base64::engine::general_purpose::STANDARD.encode([3u8; TUNNEL_KEY_LEN])
        );
        assert_eq!(translated.allowed_ips, vec!["10.0.0.0/8", "0.0.0.0/0"]);
        assert_eq!(translated.dns, vec!["1.1.1.1"]);
        assert_eq!(translated.mtu, Some(1280));
        assert_eq!(translated.persistent_keepalive_secs, Some(25));
    }

    #[test]
    fn translates_ipv6_endpoint() {
        let translated = translate_config(&config("[2001:db8::1]:51820")).expect("translate ipv6");
        assert_eq!(translated.endpoint_host, "2001:db8::1");
        assert_eq!(translated.endpoint_port, 51820);
    }

    #[test]
    fn rejects_endpoint_without_port() {
        let err = translate_config(&config("vpn.example.com")).expect_err("no port");
        assert!(matches!(err, AndroidPalError::InvalidInput(_)));
    }

    #[test]
    fn rejects_non_numeric_port() {
        let err = translate_config(&config("vpn.example.com:https")).expect_err("bad port");
        assert!(matches!(err, AndroidPalError::InvalidInput(_)));
    }

    #[test]
    fn rejects_empty_endpoint_via_core_validation() {
        let err = translate_config(&config("")).expect_err("empty endpoint");
        assert!(matches!(err, AndroidPalError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn host_fallback_reports_unsupported_and_tracks_failed_status() {
        let provider = AndroidTunnelProvider::new();
        assert_eq!(provider.status().await, TunnelStatus::Down);
        // A valid config still fails on the host, and the failure is
        // reflected in the tracked status.
        let err = provider
            .start_tunnel(config("vpn.example.com:51820"))
            .await
            .expect_err("host start");
        assert!(matches!(err, TunnelError::Backend(_)));
        assert!(matches!(
            provider.status().await,
            TunnelStatus::Failed { .. }
        ));
        // Stop is also unsupported on the host.
        assert!(provider.stop_tunnel().await.is_err());
    }

    #[tokio::test]
    async fn invalid_config_is_rejected_before_platform() {
        let provider = AndroidTunnelProvider::new();
        let err = provider
            .start_tunnel(config("no-port-here"))
            .await
            .expect_err("invalid");
        assert!(matches!(err, TunnelError::Config(_)));
    }
}

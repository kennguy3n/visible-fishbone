//! Tunnel provider trait.
//!
//! The agent / edge connect to the SNG cloud (or to a tenant
//! edge VM) over a WireGuard-class tunnel. The trait is
//! intentionally generic over backend so the same higher-layer
//! code drives boringtun (userspace), the kernel WireGuard
//! module, or NEPacketTunnelProvider on macOS / iOS.

use async_trait::async_trait;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// Tunnel configuration handed to a [`TunnelProvider`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelConfig {
    /// Tunnel identifier (stable for the lifetime of the
    /// tunnel; the control plane echoes this on every health
    /// probe).
    pub id: String,
    /// Remote peer endpoint.
    pub endpoint: SocketAddr,
    /// Public key of the peer (32-byte WireGuard public key,
    /// base64-encoded in the config wire form).
    pub peer_public_key_b64: String,
    /// Persistent-keepalive interval in seconds. 0 = disabled.
    pub keepalive_seconds: u32,
    /// Allowed-IPs prefix list.
    pub allowed_ips: Vec<IpNet>,
}

/// Opaque handle returned by [`TunnelProvider::start`]. Drop or
/// pass to [`TunnelProvider::stop`] to tear the tunnel down.
#[derive(Clone, Debug)]
pub struct TunnelHandle {
    /// Stable id matching the config.
    pub id: String,
}

/// Tunnel-provider error.
#[derive(Debug, Error)]
pub enum TunnelProviderError {
    /// Backend not available on this OS / build.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// Tunnel could not be brought up (invalid config, peer
    /// unreachable, key mismatch).
    #[error("startup: {0}")]
    Startup(String),
    /// No tunnel matches the supplied handle.
    #[error("unknown tunnel: {0}")]
    UnknownTunnel(String),
}

/// Tunnel provider. Each call to [`Self::start`] brings up an
/// independent tunnel; an agent typically has just one, but the
/// trait does not assume that — the edge VM brings up multiple
/// for SD-WAN.
#[async_trait]
pub trait TunnelProvider: Send + Sync {
    /// Bring up a tunnel for the supplied config. Returns a
    /// handle the caller stores; passing the handle back to
    /// [`Self::stop`] tears the tunnel down.
    async fn start(&self, config: TunnelConfig) -> Result<TunnelHandle, TunnelProviderError>;

    /// Tear down a tunnel by handle.
    async fn stop(&self, handle: TunnelHandle) -> Result<(), TunnelProviderError>;

    /// List active tunnels by id.
    async fn list(&self) -> Result<Vec<String>, TunnelProviderError>;
}

/// In-memory provider used by tests. Records the configs it is
/// asked to start; never touches the kernel.
#[derive(Clone, Debug, Default)]
pub struct InMemoryTunnelProvider {
    inner: Arc<Mutex<HashSet<String>>>,
}

impl InMemoryTunnelProvider {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TunnelProvider for InMemoryTunnelProvider {
    async fn start(&self, config: TunnelConfig) -> Result<TunnelHandle, TunnelProviderError> {
        let id = config.id.clone();
        self.inner.lock().await.insert(id.clone());
        Ok(TunnelHandle { id })
    }

    async fn stop(&self, handle: TunnelHandle) -> Result<(), TunnelProviderError> {
        let removed = self.inner.lock().await.remove(&handle.id);
        if removed {
            Ok(())
        } else {
            Err(TunnelProviderError::UnknownTunnel(handle.id))
        }
    }

    async fn list(&self) -> Result<Vec<String>, TunnelProviderError> {
        Ok(self.inner.lock().await.iter().cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn cfg(id: &str) -> TunnelConfig {
        TunnelConfig {
            id: id.into(),
            endpoint: "1.2.3.4:51820".parse().expect("addr"),
            peer_public_key_b64: "A".repeat(43) + "=",
            keepalive_seconds: 25,
            allowed_ips: vec![IpNet::from_str("0.0.0.0/0").expect("net")],
        }
    }

    #[tokio::test]
    async fn in_memory_provider_round_trips_start_stop_list() {
        let p = InMemoryTunnelProvider::new();
        let h1 = p.start(cfg("t1")).await.expect("start");
        let h2 = p.start(cfg("t2")).await.expect("start");
        let mut list = p.list().await.expect("list");
        list.sort();
        assert_eq!(list, vec!["t1".to_owned(), "t2".to_owned()]);
        p.stop(h1).await.expect("stop");
        let list = p.list().await.expect("list");
        assert_eq!(list, vec!["t2".to_owned()]);
        p.stop(h2.clone()).await.expect("stop");
        let err = p.stop(h2).await.expect_err("double stop");
        assert!(matches!(err, TunnelProviderError::UnknownTunnel(_)));
    }
}

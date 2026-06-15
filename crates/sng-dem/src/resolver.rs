//! Pluggable DNS resolution.
//!
//! The probe engine resolves names through a [`Resolver`] rather than
//! calling [`tokio::net::lookup_host`] directly so the DNS phase can
//! be driven deterministically in tests (a mock resolver that returns
//! a loopback address, an empty set, or sleeps to exercise the
//! timeout path) with no dependence on live network.

use std::future::Future;
use std::net::SocketAddr;

use crate::error::DemError;

/// Resolves a host + port to one or more socket addresses.
///
/// Implementations must be cheap to [`Clone`] (the engine clones the
/// resolver into each spawned probe task) and `Send + Sync + 'static`.
pub trait Resolver: Clone + Send + Sync + 'static {
    /// Resolve `host:port`. An empty result is an error
    /// ([`DemError::Config`] is *not* used here — resolution failures
    /// are surfaced to the caller, which records them as a `dns`
    /// probe failure rather than a config fault).
    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = Result<Vec<SocketAddr>, DemError>> + Send;
}

/// The production resolver: the OS resolver via
/// [`tokio::net::lookup_host`].
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, DemError> {
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| DemError::Build(format!("resolve {host}:{port}: {e}")))?
            .collect();
        if addrs.is_empty() {
            return Err(DemError::Build(format!(
                "resolve {host}:{port}: no addresses"
            )));
        }
        Ok(addrs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn system_resolver_resolves_localhost() {
        let addrs = SystemResolver.resolve("localhost", 443).await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 443));
    }

    #[tokio::test]
    async fn system_resolver_resolves_dotted_quad() {
        let addrs = SystemResolver.resolve("127.0.0.1", 8080).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0].ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(addrs[0].port(), 8080);
    }
}

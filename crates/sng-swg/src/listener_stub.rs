// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Non-Unix stub for the ext-authz listener.
//!
//! The real listener binds a Unix domain socket that Envoy's
//! ext-authz filter dials. On non-Unix targets (Windows) the
//! socket transport does not exist, so this stub provides the
//! same public API surface with `bind` returning an error. This
//! lets the crate compile and run its library-level tests on
//! Windows for development; production deployments are Linux-only.

use std::path::PathBuf;
use std::time::Duration;

use crate::auth::ExtAuthzHandler;
use crate::error::SwgError;

pub const DEFAULT_SOCKET_PATH: &str = "/var/run/sng/ext_authz.sock";

#[derive(Clone, Debug)]
pub struct ExtAuthzListenerConfig {
    pub socket_path: PathBuf,
    pub max_body_bytes: usize,
    pub read_timeout: Duration,
    pub max_connections: usize,
}

impl ExtAuthzListenerConfig {
    #[must_use]
    pub fn with_socket(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_body_bytes: 64 * 1024 * 1024,
            read_timeout: Duration::from_secs(10),
            max_connections: 1024,
        }
    }
}

impl Default for ExtAuthzListenerConfig {
    fn default() -> Self {
        Self::with_socket(DEFAULT_SOCKET_PATH)
    }
}

#[derive(Debug)]
pub struct ExtAuthzListener {
    _private: (),
}

impl ExtAuthzListener {
    pub fn bind(
        _cfg: &ExtAuthzListenerConfig,
        _handler: ExtAuthzHandler,
    ) -> Result<Self, SwgError> {
        Err(SwgError::Io(
            "ext_authz Unix socket listener is not available on this platform".into(),
        ))
    }

    #[must_use]
    pub fn socket_path(&self) -> &std::path::Path {
        std::path::Path::new("")
    }

    pub async fn run<F>(self, _shutdown: F)
    where
        F: std::future::Future<Output = ()>,
    {
    }
}

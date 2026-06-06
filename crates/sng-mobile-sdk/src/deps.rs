// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Per-platform dependency assembly.
//!
//! [`assemble`] is the single place that selects the concrete
//! backings the agent runs on: the iOS PAL under
//! `cfg(target_os = "ios")`, the Android PAL under
//! `cfg(target_os = "android")`, and the typed-Unsupported
//! [`crate::host`] fallback on every other target (the Linux CI host
//! above all). Exactly one of the three `cfg` blocks compiles per
//! target; each populates the same five trait objects plus the OIDC
//! [`AuthSession`], so the rest of the SDK is platform-agnostic.
//!
//! No agent behaviour is implemented here — only the wiring that
//! hands `sng-mobile-core` its `Arc<dyn …>` dependencies.

use std::sync::Arc;

use sng_mobile_core::{
    AuthSession, MobileAgentConfig, MobileAgentDeps, MobilePostureCollector, MobileTunnelProvider,
    SecureKeyStore,
};
use sng_oidc::AuthSurface;

use crate::config::SdkMobileConfig;
use crate::error::MobileSdkError;
use crate::oidc::OidcAuthSession;

/// The assembled dependencies plus a typed handle to the OIDC
/// session, so the SDK object can both build the agent and later
/// drive the interactive sign-in flow on the very same session.
pub(crate) struct Assembled {
    /// The dependency bundle handed to [`sng_mobile_core::MobileAgent::new`].
    pub deps: MobileAgentDeps,
    /// The concrete OIDC session (also held inside `deps.auth` as a
    /// trait object), retained so [`OidcAuthSession::sign_in`] is
    /// reachable from the FFI surface.
    pub auth: Arc<OidcAuthSession>,
}

/// Assemble the platform dependencies for `sdk_config` / `core_config`.
///
/// `core_config` is the already-validated core configuration (its
/// `auth` block seeds the OIDC session); `sdk_config` supplies the
/// FFI-only fields (trust anchors, the OIDC redirect URI).
pub(crate) fn assemble(
    sdk_config: &SdkMobileConfig,
    core_config: &MobileAgentConfig,
) -> Result<Assembled, MobileSdkError> {
    if sdk_config.oidc_redirect_uri.trim().is_empty() {
        return Err(MobileSdkError::invalid_config(
            "oidc_redirect_uri must not be empty",
        ));
    }
    // Reject a malformed redirect URI up front on *every* platform so
    // the failure surfaces at assembly time, not midway through an
    // interactive sign-in. (iOS additionally needs the parsed scheme
    // below; Android/host only need the well-formedness guarantee.)
    if let Err(e) = url::Url::parse(&sdk_config.oidc_redirect_uri) {
        return Err(MobileSdkError::invalid_config(format!(
            "oidc_redirect_uri: {e}"
        )));
    }
    let policy_trust = sdk_config.build_trust_store()?;
    let redirect_uri = sdk_config.oidc_redirect_uri.clone();

    // Exactly one of the following three blocks compiles per target.
    // Each binds the same four names so the assembly below is
    // platform-agnostic. (The agent's `MobileAgentDeps` takes the
    // key store, posture collector, tunnel provider, and auth
    // session; the OIDC `AuthSurface` is consumed by the auth
    // session built below.)
    let key_store: Arc<dyn SecureKeyStore>;
    let posture: Arc<dyn MobilePostureCollector>;
    let tunnel: Arc<dyn MobileTunnelProvider>;
    let surface: Arc<dyn AuthSurface>;

    #[cfg(target_os = "ios")]
    {
        use sng_mobile_pal_ios::{
            IosAuthSurface, IosPostureCollector, IosSecureKeyStore, IosTunnelProvider,
        };
        // `ASWebAuthenticationSession` takes the callback *scheme*,
        // not the full redirect URI; derive it from the configured
        // redirect (validated non-empty above).
        let scheme = url::Url::parse(&redirect_uri)
            .map_err(|e| MobileSdkError::invalid_config(format!("oidc_redirect_uri: {e}")))?
            .scheme()
            .to_owned();
        key_store = Arc::new(IosSecureKeyStore::new());
        posture = Arc::new(IosPostureCollector::new());
        tunnel = Arc::new(IosTunnelProvider::new());
        surface = Arc::new(IosAuthSurface::new(scheme));
    }

    #[cfg(target_os = "android")]
    {
        use sng_mobile_pal_android::{
            AndroidAuthSurface, AndroidPostureCollector, AndroidSecureKeyStore,
            AndroidTunnelProvider,
        };
        key_store = Arc::new(AndroidSecureKeyStore::new());
        posture = Arc::new(AndroidPostureCollector::new(env!("CARGO_PKG_VERSION")));
        tunnel = Arc::new(AndroidTunnelProvider::new());
        surface = Arc::new(AndroidAuthSurface::new(redirect_uri.clone()));
    }

    #[cfg(not(any(target_os = "ios", target_os = "android")))]
    {
        use crate::host::{
            HostAuthSurface, HostPostureCollector, HostSecureKeyStore, HostTunnelProvider,
        };
        key_store = Arc::new(HostSecureKeyStore);
        posture = Arc::new(HostPostureCollector);
        tunnel = Arc::new(HostTunnelProvider);
        surface = Arc::new(HostAuthSurface);
    }

    // Bind the OIDC session to the device's enrolled tenant so
    // sign-in is fail-closed on the token's `tenant_id` claim: a
    // user from another tenant can never establish a session on
    // this device, and there is no `X-Tenant-ID` fallback.
    let auth = Arc::new(OidcAuthSession::new(
        core_config.auth.clone(),
        redirect_uri,
        surface,
        Some(core_config.tenant_id.to_string()),
    )?);
    let auth_session: Arc<dyn AuthSession> = auth.clone();

    let deps = MobileAgentDeps {
        key_store,
        auth: auth_session,
        posture,
        tunnel,
        policy_trust,
    };

    Ok(Assembled { deps, auth })
}

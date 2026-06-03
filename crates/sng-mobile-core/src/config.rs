//! Mobile agent configuration + validation.
//!
//! [`MobileAgentConfig`] is the typed, validated input the host
//! application hands [`crate::MobileAgent::new`]. It is built by the
//! PAL layer (iOS / Android) from whatever platform-native config
//! surface the host app uses (MDM-pushed plist, `SharedPreferences`,
//! a baked-in build constant, …) — this crate does not read files
//! or env vars itself so it stays free of any host filesystem
//! assumptions.
//!
//! Every interval / timeout is a [`Duration`] rather than a raw
//! integer so the unit is unambiguous at the call site, and
//! [`MobileAgentConfig::validate`] rejects the degenerate values
//! (zero intervals, empty identifiers, a non-`https` control-plane
//! URL) up front so the agent fails fast at construction rather
//! than on the first network wakeup.

use std::time::Duration;

use sng_core::envelope::Platform;
use sng_core::{DeviceId, TenantId};

use crate::error::MobileError;

/// The mobile OS the agent core is running on. A strict subset of
/// [`sng_core::envelope::Platform`] — the desktop variants are not
/// representable here so a mobile build cannot mis-tag its
/// telemetry as `windows` / `macos` / `linux`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum MobilePlatform {
    /// Apple iOS / iPadOS.
    Ios,
    /// Google Android (AOSP + GMS).
    Android,
}

impl MobilePlatform {
    /// Map to the workspace-wide [`Platform`] used on telemetry
    /// envelopes so a mobile event carries the same `plt` wire tag
    /// the Go control plane stores in `devices.platform`.
    #[must_use]
    pub const fn as_platform(self) -> Platform {
        match self {
            Self::Ios => Platform::Ios,
            Self::Android => Platform::Android,
        }
    }

    /// The lowercase wire string (`ios` / `android`) the
    /// `POST /devices/enroll` body's `platform` field expects.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.as_platform().as_str()
    }
}

/// OIDC configuration for the [`crate::AuthSession`] layer.
///
/// This crate only models the *configuration* of the OIDC flow —
/// the concrete token acquisition / refresh implementation lands in
/// the dedicated `sng-oidc` crate (built in parallel, Session 7) and
/// plugs in through the [`crate::AuthSession`] trait. The fields
/// here are what that implementation will need to drive an
/// authorization-code-with-PKCE flow against the tenant IdP.
#[derive(Clone, Debug)]
pub struct AuthConfig {
    /// OIDC issuer base URL (the `iss` claim / discovery origin).
    pub issuer: String,
    /// Public client identifier registered with the IdP.
    pub client_id: String,
    /// Requested scopes (e.g. `openid`, `profile`, `offline_access`).
    pub scopes: Vec<String>,
    /// Refresh the access token this long *before* it actually
    /// expires, so a request never races a mid-flight expiry. Must
    /// be shorter than the shortest token lifetime the IdP issues.
    pub refresh_skew: Duration,
    /// Upper bound on the random jitter added to each scheduled
    /// refresh so a fleet of devices that all enrolled in the same
    /// MDM push window do not stampede the IdP token endpoint at
    /// the same instant.
    pub refresh_jitter: Duration,
}

impl AuthConfig {
    /// Validate the OIDC config in isolation.
    fn validate(&self) -> Result<(), MobileError> {
        if self.issuer.trim().is_empty() {
            return Err(MobileError::Config("auth.issuer must not be empty".into()));
        }
        if !(self.issuer.starts_with("https://") || self.issuer.starts_with("http://")) {
            return Err(MobileError::Config(
                "auth.issuer must be an http(s) URL".into(),
            ));
        }
        if self.client_id.trim().is_empty() {
            return Err(MobileError::Config(
                "auth.client_id must not be empty".into(),
            ));
        }
        if self.refresh_skew.is_zero() {
            return Err(MobileError::Config(
                "auth.refresh_skew must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

/// Validated runtime configuration for a [`crate::MobileAgent`].
#[derive(Clone, Debug)]
pub struct MobileAgentConfig {
    /// Control-plane base URL, e.g. `https://cp.example.com:443`.
    /// Must be `https` in production; the host + port are parsed
    /// out of it for the mTLS dial via [`Self::control_plane_addr`].
    pub control_plane_url: String,
    /// Tenant this device is enrolled under.
    pub tenant_id: TenantId,
    /// This device's stable identifier. Assigned by the control
    /// plane at enrolment and persisted by the host app.
    pub device_id: DeviceId,
    /// Mobile OS the agent is running on.
    pub platform: MobilePlatform,
    /// Human-readable device name sent in the enrolment request
    /// (shown in the operator console device list).
    pub device_name: String,
    /// OIDC auth configuration.
    pub auth: AuthConfig,
    /// Cadence at which the agent pulls the mobile policy bundle
    /// ([`sng_core::policy::BundleTarget::Mobile`]).
    pub poll_interval: Duration,
    /// Cadence at which the agent flushes its telemetry spool to
    /// the control plane.
    pub telemetry_interval: Duration,
    /// Cadence at which the agent collects a fresh posture
    /// snapshot from the PAL.
    pub posture_interval: Duration,
    /// Per-request deadline applied to every control-plane round
    /// trip. Kept aggressive so a stalled radio link cannot pin a
    /// wakeup open and drain the battery.
    pub request_timeout: Duration,
    /// Deadline for the initial TLS + HTTP/2 connect.
    pub connect_timeout: Duration,
}

impl MobileAgentConfig {
    /// Validate the whole config. Called by
    /// [`crate::MobileAgent::new`]; also useful for a host app that
    /// wants to surface a config error in its own UI before
    /// constructing the agent.
    pub fn validate(&self) -> Result<(), MobileError> {
        let url = url::Url::parse(&self.control_plane_url)
            .map_err(|e| MobileError::Config(format!("control_plane_url is not a URL: {e}")))?;
        if url.scheme() != "https" {
            return Err(MobileError::Config(
                "control_plane_url must use the https scheme".into(),
            ));
        }
        if url.host_str().is_none() {
            return Err(MobileError::Config(
                "control_plane_url must contain a host".into(),
            ));
        }
        if self.tenant_id.is_nil() {
            return Err(MobileError::Config("tenant_id must not be nil".into()));
        }
        if self.device_id.is_nil() {
            return Err(MobileError::Config("device_id must not be nil".into()));
        }
        if self.device_name.trim().is_empty() {
            return Err(MobileError::Config("device_name must not be empty".into()));
        }
        for (name, value) in [
            ("poll_interval", self.poll_interval),
            ("telemetry_interval", self.telemetry_interval),
            ("posture_interval", self.posture_interval),
            ("request_timeout", self.request_timeout),
            ("connect_timeout", self.connect_timeout),
        ] {
            if value.is_zero() {
                return Err(MobileError::Config(format!(
                    "{name} must be greater than zero"
                )));
            }
        }
        self.auth.validate()?;
        Ok(())
    }

    /// The `host:port` dial string parsed out of
    /// [`Self::control_plane_url`], suitable for
    /// [`sng_comms::ControlPlaneClient::new`]. Defaults the port to
    /// `443` when the URL omits it.
    pub fn control_plane_addr(&self) -> Result<String, MobileError> {
        let url = url::Url::parse(&self.control_plane_url)
            .map_err(|e| MobileError::Config(format!("control_plane_url is not a URL: {e}")))?;
        let host = url
            .host_str()
            .ok_or_else(|| MobileError::Config("control_plane_url must contain a host".into()))?;
        let port = url.port().unwrap_or(443);
        Ok(format!("{host}:{port}"))
    }

    /// The SNI / certificate-validation server name parsed out of
    /// [`Self::control_plane_url`].
    pub fn server_name(&self) -> Result<String, MobileError> {
        let url = url::Url::parse(&self.control_plane_url)
            .map_err(|e| MobileError::Config(format!("control_plane_url is not a URL: {e}")))?;
        url.host_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| MobileError::Config("control_plane_url must contain a host".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn valid_auth() -> AuthConfig {
        AuthConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "sng-mobile".into(),
            scopes: vec!["openid".into(), "offline_access".into()],
            refresh_skew: Duration::from_secs(60),
            refresh_jitter: Duration::from_secs(30),
        }
    }

    fn valid_config() -> MobileAgentConfig {
        MobileAgentConfig {
            control_plane_url: "https://cp.example.com:8443".into(),
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            platform: MobilePlatform::Ios,
            device_name: "iPhone 15".into(),
            auth: valid_auth(),
            poll_interval: Duration::from_secs(300),
            telemetry_interval: Duration::from_secs(60),
            posture_interval: Duration::from_secs(900),
            request_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn addr_and_server_name_parse_out_of_url() {
        let cfg = valid_config();
        assert_eq!(cfg.control_plane_addr().unwrap(), "cp.example.com:8443");
        assert_eq!(cfg.server_name().unwrap(), "cp.example.com");
    }

    #[test]
    fn addr_defaults_port_to_443() {
        let mut cfg = valid_config();
        cfg.control_plane_url = "https://cp.example.com".into();
        assert_eq!(cfg.control_plane_addr().unwrap(), "cp.example.com:443");
    }

    #[test]
    fn ipv6_addr_stays_bracketed() {
        // `url::Url::host_str` already returns IPv6 literals in their
        // bracketed `[..]` form, so `control_plane_addr` yields the
        // RFC-3986 `[host]:port` shape that `sng_comms`'s
        // `parse_host_port` requires — never an ambiguous, unbracketed
        // `host:port` that would be split at the wrong colon.
        let mut cfg = valid_config();
        cfg.control_plane_url = "https://[2001:db8::1]:8443".into();
        assert!(cfg.validate().is_ok());
        assert_eq!(cfg.control_plane_addr().unwrap(), "[2001:db8::1]:8443");
    }

    #[test]
    fn non_https_url_rejected() {
        let mut cfg = valid_config();
        cfg.control_plane_url = "http://cp.example.com".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_interval_rejected() {
        let mut cfg = valid_config();
        cfg.poll_interval = Duration::ZERO;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn empty_device_name_rejected() {
        let mut cfg = valid_config();
        cfg.device_name = "   ".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn nil_tenant_rejected() {
        let mut cfg = valid_config();
        cfg.tenant_id = TenantId::nil();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn auth_issuer_must_not_be_empty() {
        let mut cfg = valid_config();
        cfg.auth.issuer = String::new();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn platform_maps_to_wire_string() {
        assert_eq!(MobilePlatform::Ios.as_str(), "ios");
        assert_eq!(MobilePlatform::Android.as_str(), "android");
    }
}

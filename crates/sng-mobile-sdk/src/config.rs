// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! FFI config records and their mapping onto the agent core's
//! strongly-typed configuration.
//!
//! Everything crossing the FFI boundary is plain owned data: the
//! foreign app passes durations as integer seconds / milliseconds
//! (UniFFI has no `Duration` type), ids as their canonical string
//! form, and the policy trust anchors as `(key_id, base64-key)`
//! pairs. [`SdkMobileConfig::into_core`] performs every fallible
//! conversion up front — UUID parsing, base64 decode, key-length
//! check — so a malformed value surfaces as a typed
//! [`MobileSdkError::InvalidConfig`] before the agent is built,
//! rather than as a late failure deep inside an operation.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sng_comms::PolicyTrustStore;
use sng_core::{DeviceId, PolicySigningKeyId, TenantId};
use sng_mobile_core::{AuthConfig, MobileAgentConfig, MobilePlatform};

use crate::error::MobileSdkError;

/// The mobile OS the agent runs on. Mirrors
/// [`sng_mobile_core::MobilePlatform`] as an FFI-safe enum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum SdkPlatform {
    /// Apple iOS / iPadOS.
    Ios,
    /// Google Android.
    Android,
}

impl From<SdkPlatform> for MobilePlatform {
    fn from(value: SdkPlatform) -> Self {
        match value {
            SdkPlatform::Ios => Self::Ios,
            SdkPlatform::Android => Self::Android,
        }
    }
}

/// OIDC configuration the agent needs to drive an
/// authorization-code-with-PKCE flow against the tenant IdP.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SdkAuthConfig {
    /// OIDC issuer base URL (the `iss` claim / discovery origin).
    pub issuer: String,
    /// Public client identifier registered with the IdP.
    pub client_id: String,
    /// Requested scopes (e.g. `openid`, `profile`, `offline_access`).
    pub scopes: Vec<String>,
    /// Refresh the access token this many seconds *before* it
    /// expires. Must be greater than zero.
    pub refresh_skew_secs: u64,
}

impl From<SdkAuthConfig> for AuthConfig {
    fn from(value: SdkAuthConfig) -> Self {
        Self {
            issuer: value.issuer,
            client_id: value.client_id,
            scopes: value.scopes,
            refresh_skew: Duration::from_secs(value.refresh_skew_secs),
            // The SDK drives refresh lazily through `OidcSession`'s
            // own internal stampede-jitter (derived from
            // `refresh_skew`); the core's `schedule_refresh` helper —
            // the sole consumer of `refresh_jitter` — is never invoked
            // on this path, so there is no FFI knob for it. Leave it
            // disabled rather than expose a field with no effect.
            refresh_jitter: Duration::ZERO,
        }
    }
}

/// A trusted policy-bundle signer key the host seeds into the
/// agent's trust store. The control plane signs mobile policy
/// bundles with Ed25519; the agent rejects any bundle whose signing
/// key id is not present here.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SdkTrustAnchor {
    /// The signing key id (matches the bundle's `key_id` header).
    pub key_id: String,
    /// The Ed25519 public key, standard-base64-encoded (32 raw
    /// bytes once decoded).
    pub public_key_b64: String,
}

/// Validated runtime configuration for the mobile agent, in
/// FFI-safe form.
#[derive(Clone, Debug, uniffi::Record)]
pub struct SdkMobileConfig {
    /// Control-plane base URL, e.g. `https://cp.example.com:443`.
    /// Must use the `https` scheme.
    pub control_plane_url: String,
    /// Tenant this device is enrolled under (UUID string).
    pub tenant_id: String,
    /// This device's stable identifier (UUID string).
    pub device_id: String,
    /// Mobile OS the agent is running on.
    pub platform: SdkPlatform,
    /// Human-readable device name shown in the operator console.
    pub device_name: String,
    /// OIDC auth configuration.
    pub auth: SdkAuthConfig,
    /// The OAuth2 redirect URI registered with the IdP and
    /// intercepted by the platform `AuthSurface` (an app custom
    /// scheme such as `com.example.app://oauth/callback`, or an
    /// `https` App Link on Android). Used both to build the
    /// authorization request and to construct the platform browser
    /// surface; must not be empty.
    pub oidc_redirect_uri: String,
    /// Policy-bundle poll cadence, in seconds.
    pub poll_interval_secs: u64,
    /// Telemetry flush cadence, in seconds.
    pub telemetry_interval_secs: u64,
    /// Posture collection cadence, in seconds.
    pub posture_interval_secs: u64,
    /// Factor by which every periodic cadence is stretched while the
    /// device is in low-power / battery-saver mode (see
    /// [`MobileSdk::set_power_state`](crate::MobileSdk::set_power_state)).
    /// `1` disables stretching; must be `>= 1`.
    pub low_power_multiplier: u32,
    /// Per-request deadline applied to every control-plane round
    /// trip, in milliseconds.
    pub request_timeout_ms: u64,
    /// Deadline for the initial TLS + HTTP/2 connect, in
    /// milliseconds.
    pub connect_timeout_ms: u64,
    /// Trusted policy-bundle signer keys seeded into the agent.
    pub trust_anchors: Vec<SdkTrustAnchor>,
}

impl SdkMobileConfig {
    /// Convert into the agent core's [`MobileAgentConfig`], parsing
    /// and validating every foreign-supplied value.
    pub(crate) fn into_core(self) -> Result<MobileAgentConfig, MobileSdkError> {
        let tenant_id: TenantId = self
            .tenant_id
            .parse()
            .map_err(|e| MobileSdkError::invalid_config(format!("tenant_id: {e}")))?;
        let device_id: DeviceId = self
            .device_id
            .parse()
            .map_err(|e| MobileSdkError::invalid_config(format!("device_id: {e}")))?;

        Ok(MobileAgentConfig {
            control_plane_url: self.control_plane_url,
            tenant_id,
            device_id,
            platform: self.platform.into(),
            device_name: self.device_name,
            auth: self.auth.into(),
            poll_interval: Duration::from_secs(self.poll_interval_secs),
            telemetry_interval: Duration::from_secs(self.telemetry_interval_secs),
            posture_interval: Duration::from_secs(self.posture_interval_secs),
            low_power_multiplier: self.low_power_multiplier,
            request_timeout: Duration::from_millis(self.request_timeout_ms),
            connect_timeout: Duration::from_millis(self.connect_timeout_ms),
        })
    }

    /// Build the policy trust store from the configured anchors.
    ///
    /// Forwards each `(key_id, public_key)` to
    /// [`PolicyTrustStore::insert_key`], which applies sng-core's
    /// canonical key-id / key-byte rejection rules. A malformed
    /// base64 string, a wrong-length key, or a rejected id becomes
    /// a typed [`MobileSdkError::InvalidConfig`].
    pub(crate) fn build_trust_store(&self) -> Result<Arc<PolicyTrustStore>, MobileSdkError> {
        let store = PolicyTrustStore::new();
        for anchor in &self.trust_anchors {
            let key_id = PolicySigningKeyId::new(anchor.key_id.clone())
                .map_err(|e| MobileSdkError::invalid_config(format!("trust anchor key_id: {e}")))?;
            let raw = BASE64
                .decode(anchor.public_key_b64.as_bytes())
                .map_err(|e| {
                    MobileSdkError::invalid_config(format!(
                        "trust anchor {key_id} public key is not valid base64: {e}"
                    ))
                })?;
            let key: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] =
                raw.try_into().map_err(|v: Vec<u8>| {
                    MobileSdkError::invalid_config(format!(
                        "trust anchor {key_id} public key must be {} bytes, got {}",
                        ed25519_dalek::PUBLIC_KEY_LENGTH,
                        v.len()
                    ))
                })?;
            store.insert_key(&key_id, &key).map_err(|e| {
                MobileSdkError::invalid_config(format!("trust anchor {key_id}: {e}"))
            })?;
        }
        Ok(Arc::new(store))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use pretty_assertions::assert_eq;

    use super::*;

    /// A fully-valid config the agent core accepts. Tests mutate a
    /// clone of this to exercise a single failure at a time.
    pub(crate) fn valid_config() -> SdkMobileConfig {
        SdkMobileConfig {
            control_plane_url: "https://cp.example.com:8443".into(),
            tenant_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            device_id: "550e8400-e29b-41d4-a716-446655440001".into(),
            platform: SdkPlatform::Ios,
            device_name: "Test Device".into(),
            auth: SdkAuthConfig {
                issuer: "https://idp.example.com".into(),
                client_id: "client-123".into(),
                scopes: vec!["openid".into(), "profile".into()],
                refresh_skew_secs: 60,
            },
            oidc_redirect_uri: "com.example.app://oauth/callback".into(),
            poll_interval_secs: 900,
            telemetry_interval_secs: 300,
            posture_interval_secs: 600,
            low_power_multiplier: 4,
            request_timeout_ms: 30_000,
            connect_timeout_ms: 10_000,
            trust_anchors: Vec::new(),
        }
    }

    #[test]
    fn into_core_maps_every_field() {
        let core = valid_config().into_core().expect("valid config");
        assert_eq!(core.control_plane_url, "https://cp.example.com:8443");
        assert_eq!(core.device_name, "Test Device");
        assert_eq!(core.platform, MobilePlatform::Ios);
        assert_eq!(core.poll_interval, Duration::from_secs(900));
        assert_eq!(core.low_power_multiplier, 4);
        // 30_000 ms == 30 s; assert in seconds to satisfy the
        // duration-unit lint while still proving the ms field maps.
        assert_eq!(core.request_timeout, Duration::from_secs(30));
        assert_eq!(core.auth.refresh_skew, Duration::from_secs(60));
        assert_eq!(core.auth.scopes, vec!["openid", "profile"]);
        // The mapped config must pass the core's own validation.
        core.validate().expect("core validates");
    }

    #[test]
    fn non_uuid_tenant_is_invalid_config() {
        let mut cfg = valid_config();
        cfg.tenant_id = "not-a-uuid".into();
        let err = cfg.into_core().expect_err("must reject");
        assert!(
            matches!(err, MobileSdkError::InvalidConfig { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn trust_anchor_round_trips_a_valid_key() {
        // A real, decompressible Ed25519 public key derived from a
        // fixed signing seed (an arbitrary 32-byte value is not a
        // valid curve point, which `insert_key` correctly rejects).
        let verifying = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        let mut cfg = valid_config();
        cfg.trust_anchors = vec![SdkTrustAnchor {
            key_id: "policy-key-1".into(),
            public_key_b64: BASE64.encode(verifying.to_bytes()),
        }];
        let store = cfg.build_trust_store().expect("valid anchor");
        // The key is now present in the verifier snapshot.
        let key_id = PolicySigningKeyId::new("policy-key-1".to_owned()).expect("valid id");
        assert!(store.snapshot().has_key(&key_id));
    }

    #[test]
    fn trust_anchor_bad_base64_is_invalid_config() {
        let mut cfg = valid_config();
        cfg.trust_anchors = vec![SdkTrustAnchor {
            key_id: "policy-key-1".into(),
            public_key_b64: "!!!not base64!!!".into(),
        }];
        let err = cfg.build_trust_store().expect_err("must reject");
        assert!(
            matches!(err, MobileSdkError::InvalidConfig { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn trust_anchor_wrong_length_is_invalid_config() {
        let mut cfg = valid_config();
        cfg.trust_anchors = vec![SdkTrustAnchor {
            key_id: "policy-key-1".into(),
            // 16 bytes, not 32.
            public_key_b64: BASE64.encode([1u8; 16]),
        }];
        let err = cfg.build_trust_store().expect_err("must reject");
        assert!(
            matches!(err, MobileSdkError::InvalidConfig { .. }),
            "{err:?}"
        );
    }
}

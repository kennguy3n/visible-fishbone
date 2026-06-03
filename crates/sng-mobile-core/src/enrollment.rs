//! Claim-token device enrolment + the secure key-store trait.
//!
//! Enrolment mirrors the desktop `sng-agent` flow: the device
//! generates an Ed25519 keypair inside the platform secure store
//! (never exporting the private half), presents the public key plus
//! a one-time claim token to the control plane's public
//! `POST /api/v1/enroll` endpoint, and receives back a signed
//! certificate chain it then uses for mTLS on every subsequent
//! control-plane call.
//!
//! [`SecureKeyStore`] is the trait the PAL implements over the
//! platform key store (iOS Secure Enclave / Keychain, Android
//! Keystore / StrongBox). A working in-memory
//! [`InMemorySecureKeyStore`] is provided for host-app development
//! and tests — its private keys are wiped on drop but it is **not**
//! hardware-backed and must not be used in production.

use std::collections::HashMap;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use sng_comms::{ControlPlaneConnection, RequestBody, RequestPath};
use sng_core::{DeviceId, TenantId};

use crate::error::MobileError;

/// The default secure-store label under which the device's
/// enrolment keypair is stored.
pub const DEFAULT_DEVICE_KEY_LABEL: &str = "sng.device.enrolment.ed25519";

/// Failure modes of the [`SecureKeyStore`] surface.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeyStoreError {
    /// No key exists under the requested label.
    #[error("no key under label {0:?}")]
    NotFound(String),
    /// A key already exists under the label a generate targeted.
    #[error("a key already exists under label {0:?}")]
    AlreadyExists(String),
    /// The platform key store backend rejected the operation.
    #[error("secure key store backend: {0}")]
    Backend(String),
}

/// Ed25519 keygen / sign / store backed by the platform secure
/// enclave.
///
/// Object-safe so the agent holds it as `Arc<dyn SecureKeyStore>`.
/// The private key never leaves the store: callers get the public
/// key and ask the store to sign on their behalf.
#[async_trait]
pub trait SecureKeyStore: Send + Sync {
    /// Generate a new Ed25519 keypair under `label`, persisting the
    /// private half in the secure store, and return the public
    /// key. Errors with [`KeyStoreError::AlreadyExists`] if a key
    /// already lives under `label`.
    async fn generate_keypair(&self, label: &str) -> Result<VerifyingKey, KeyStoreError>;
    /// Return the public key of the keypair stored under `label`.
    async fn public_key(&self, label: &str) -> Result<VerifyingKey, KeyStoreError>;
    /// Sign `message` with the private key stored under `label`.
    async fn sign(&self, label: &str, message: &[u8]) -> Result<Signature, KeyStoreError>;
    /// Whether a keypair exists under `label`.
    async fn contains(&self, label: &str) -> Result<bool, KeyStoreError>;
    /// Delete the keypair stored under `label` (de-enrolment).
    async fn delete(&self, label: &str) -> Result<(), KeyStoreError>;
}

/// In-memory [`SecureKeyStore`] reference implementation.
///
/// Stores each private key as a zeroize-on-drop 32-byte seed behind
/// a [`Mutex`]. Suitable for development, tests, and as a worked
/// example for PAL implementers. **Not** hardware-backed and does
/// not persist across restarts — production uses the platform
/// secure enclave.
#[derive(Default)]
pub struct InMemorySecureKeyStore {
    keys: Mutex<HashMap<String, Zeroizing<[u8; 32]>>>,
}

impl std::fmt::Debug for InMemorySecureKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render seed material; report only how many keys are held.
        f.debug_struct("InMemorySecureKeyStore")
            .field("key_count", &self.keys.lock().len())
            .finish()
    }
}

impl InMemorySecureKeyStore {
    /// Construct an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn signing_key(&self, label: &str) -> Result<SigningKey, KeyStoreError> {
        let guard = self.keys.lock();
        let seed = guard
            .get(label)
            .ok_or_else(|| KeyStoreError::NotFound(label.to_owned()))?;
        Ok(SigningKey::from_bytes(seed))
    }
}

#[async_trait]
impl SecureKeyStore for InMemorySecureKeyStore {
    async fn generate_keypair(&self, label: &str) -> Result<VerifyingKey, KeyStoreError> {
        let mut guard = self.keys.lock();
        if guard.contains_key(label) {
            return Err(KeyStoreError::AlreadyExists(label.to_owned()));
        }
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        guard.insert(label.to_owned(), Zeroizing::new(signing_key.to_bytes()));
        Ok(verifying_key)
    }

    async fn public_key(&self, label: &str) -> Result<VerifyingKey, KeyStoreError> {
        Ok(self.signing_key(label)?.verifying_key())
    }

    async fn sign(&self, label: &str, message: &[u8]) -> Result<Signature, KeyStoreError> {
        Ok(self.signing_key(label)?.sign(message))
    }

    async fn contains(&self, label: &str) -> Result<bool, KeyStoreError> {
        Ok(self.keys.lock().contains_key(label))
    }

    async fn delete(&self, label: &str) -> Result<(), KeyStoreError> {
        self.keys.lock().remove(label);
        Ok(())
    }
}

/// JSON body of `POST /api/v1/enroll`. Field names match the Go
/// `handler.EnrollDeviceRequest`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EnrollmentRequestBody {
    claim_token: String,
    tenant_id: String,
    device_id: String,
    public_key_ed25519: String,
}

/// JSON response of `POST /api/v1/enroll`. Field names match the Go
/// `handler.EnrollDeviceResponse`.
#[derive(Debug, Clone, Deserialize)]
struct EnrollmentResponseBody {
    device_id: String,
    tenant_id: String,
    status: String,
    cert_pem: String,
    expires_at: String,
}

/// Result of a successful enrolment.
#[derive(Debug, Clone)]
pub struct EnrollmentOutcome {
    /// Device id the control plane bound the enrolment to.
    pub device_id: DeviceId,
    /// Tenant the device is enrolled under.
    pub tenant_id: TenantId,
    /// Enrolment status string returned by the control plane.
    pub status: String,
    /// PEM-encoded certificate chain issued to the device, used
    /// for mTLS on every subsequent control-plane call.
    pub cert_chain_pem: String,
    /// When the issued certificate expires.
    pub cert_expires_at: DateTime<Utc>,
}

/// Drives the claim-token enrolment flow.
#[derive(Debug, Clone)]
pub struct Enroller {
    tenant_id: TenantId,
    device_id: DeviceId,
    key_label: String,
}

impl Enroller {
    /// Construct an enroller for `tenant_id` / `device_id`, storing
    /// the enrolment keypair under `key_label` (use
    /// [`DEFAULT_DEVICE_KEY_LABEL`] unless the host app needs a
    /// custom one).
    #[must_use]
    pub fn new(tenant_id: TenantId, device_id: DeviceId, key_label: impl Into<String>) -> Self {
        Self {
            tenant_id,
            device_id,
            key_label: key_label.into(),
        }
    }

    /// The secure-store label this enroller uses.
    #[must_use]
    pub fn key_label(&self) -> &str {
        &self.key_label
    }

    /// Ensure an enrolment keypair exists in `keystore`, generating
    /// one if absent, and return its public key.
    async fn ensure_key(&self, keystore: &dyn SecureKeyStore) -> Result<VerifyingKey, MobileError> {
        if keystore.contains(&self.key_label).await? {
            Ok(keystore.public_key(&self.key_label).await?)
        } else {
            Ok(keystore.generate_keypair(&self.key_label).await?)
        }
    }

    /// Build the enrolment request body for `public_key` + `claim_token`.
    fn build_request_body(&self, public_key: &VerifyingKey, claim_token: &str) -> EnrollmentRequestBody {
        EnrollmentRequestBody {
            claim_token: claim_token.to_owned(),
            tenant_id: self.tenant_id.to_string(),
            device_id: self.device_id.to_string(),
            public_key_ed25519: base64::engine::general_purpose::STANDARD
                .encode(public_key.to_bytes()),
        }
    }

    /// Run the enrolment flow against an established control-plane
    /// connection: ensure the keypair exists, POST the public key +
    /// claim token, and parse the issued certificate chain.
    ///
    /// The connection is expected to be a server-auth-only TLS
    /// connection (the device has no client cert yet); the agent
    /// builds it via
    /// [`sng_comms::build_client_config_with_webpki_roots`] with no
    /// identity.
    pub async fn enroll(
        &self,
        keystore: &dyn SecureKeyStore,
        conn: &ControlPlaneConnection,
        claim_token: &str,
    ) -> Result<EnrollmentOutcome, MobileError> {
        if claim_token.trim().is_empty() {
            return Err(MobileError::Enrollment("claim token is empty".into()));
        }
        let public_key = self.ensure_key(keystore).await?;
        let body = self.build_request_body(&public_key, claim_token);
        let json = serde_json::to_vec(&body)
            .map_err(|e| MobileError::Enrollment(format!("encode request: {e}")))?;

        let path = RequestPath::post("/api/v1/enroll").with_header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        );
        let response = conn
            .send_request(path, RequestBody::Bytes(Bytes::from(json)))
            .await?;
        parse_response(response.status, &response.body)
    }
}

/// Parse the control plane's enrolment response into an
/// [`EnrollmentOutcome`], mapping a non-success status to a typed
/// error. Pulled out as a free function so it is unit-testable
/// without a live connection.
fn parse_response(
    status: http::StatusCode,
    body: &[u8],
) -> Result<EnrollmentOutcome, MobileError> {
    if !status.is_success() {
        let detail = String::from_utf8_lossy(body);
        return Err(MobileError::Enrollment(format!(
            "control plane returned {status}: {detail}"
        )));
    }
    let parsed: EnrollmentResponseBody = serde_json::from_slice(body)
        .map_err(|e| MobileError::Enrollment(format!("decode response: {e}")))?;
    let device_id = parsed
        .device_id
        .parse::<DeviceId>()
        .map_err(|e| MobileError::Enrollment(format!("device_id not a uuid: {e}")))?;
    let tenant_id = parsed
        .tenant_id
        .parse::<TenantId>()
        .map_err(|e| MobileError::Enrollment(format!("tenant_id not a uuid: {e}")))?;
    let cert_expires_at = DateTime::parse_from_rfc3339(&parsed.expires_at)
        .map_err(|e| MobileError::Enrollment(format!("expires_at not RFC3339: {e}")))?
        .with_timezone(&Utc);
    Ok(EnrollmentOutcome {
        device_id,
        tenant_id,
        status: parsed.status,
        cert_chain_pem: parsed.cert_pem,
        cert_expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn keystore_generate_sign_verify_roundtrip() {
        let store = InMemorySecureKeyStore::new();
        let label = "test.key";
        assert!(!store.contains(label).await.unwrap());

        let vk = store.generate_keypair(label).await.unwrap();
        assert!(store.contains(label).await.unwrap());
        assert_eq!(store.public_key(label).await.unwrap(), vk);

        let msg = b"enrol me";
        let sig = store.sign(label, msg).await.unwrap();
        assert!(vk.verify_strict(msg, &sig).is_ok());
    }

    #[tokio::test]
    async fn keystore_generate_twice_is_already_exists() {
        let store = InMemorySecureKeyStore::new();
        store.generate_keypair("k").await.unwrap();
        let err = store.generate_keypair("k").await.unwrap_err();
        assert!(matches!(err, KeyStoreError::AlreadyExists(_)));
    }

    #[tokio::test]
    async fn keystore_sign_missing_is_not_found() {
        let store = InMemorySecureKeyStore::new();
        let err = store.sign("absent", b"x").await.unwrap_err();
        assert!(matches!(err, KeyStoreError::NotFound(_)));
    }

    #[tokio::test]
    async fn keystore_delete_removes_key() {
        let store = InMemorySecureKeyStore::new();
        store.generate_keypair("k").await.unwrap();
        store.delete("k").await.unwrap();
        assert!(!store.contains("k").await.unwrap());
    }

    #[test]
    fn request_body_encodes_public_key_base64() {
        let tenant = TenantId::new_v4();
        let device = DeviceId::new_v4();
        let enroller = Enroller::new(tenant, device, DEFAULT_DEVICE_KEY_LABEL);
        let vk = SigningKey::from_bytes(&[3u8; 32]).verifying_key();
        let body = enroller.build_request_body(&vk, "claim-123");
        assert_eq!(body.claim_token, "claim-123");
        assert_eq!(body.tenant_id, tenant.to_string());
        assert_eq!(body.device_id, device.to_string());
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.public_key_ed25519.as_bytes())
            .unwrap();
        assert_eq!(decoded.as_slice(), vk.to_bytes().as_slice());
    }

    #[test]
    fn parse_response_success() {
        let device = DeviceId::new_v4();
        let tenant = TenantId::new_v4();
        let json = format!(
            r#"{{"device_id":"{device}","tenant_id":"{tenant}","status":"active","cert_pem":"-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----","expires_at":"2030-01-02T03:04:05Z"}}"#
        );
        let outcome = parse_response(http::StatusCode::CREATED, json.as_bytes()).unwrap();
        assert_eq!(outcome.device_id, device);
        assert_eq!(outcome.tenant_id, tenant);
        assert_eq!(outcome.status, "active");
        assert!(outcome.cert_chain_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(outcome.cert_expires_at.to_rfc3339(), "2030-01-02T03:04:05+00:00");
    }

    #[test]
    fn parse_response_non_success_is_error() {
        let err = parse_response(http::StatusCode::BAD_REQUEST, b"bad token").unwrap_err();
        assert!(matches!(err, MobileError::Enrollment(_)));
    }

    #[test]
    fn parse_response_bad_uuid_is_error() {
        let json = r#"{"device_id":"not-a-uuid","tenant_id":"also-bad","status":"active","cert_pem":"x","expires_at":"2030-01-02T03:04:05Z"}"#;
        assert!(parse_response(http::StatusCode::OK, json.as_bytes()).is_err());
    }
}

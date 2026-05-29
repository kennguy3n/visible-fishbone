//! Signed policy bundle verification.
//!
//! The control plane compiles the typed policy graph into a
//! MessagePack-encoded "bundle" and Ed25519-signs it with the
//! tenant's active signing key. Bundles are then distributed to
//! the edge VMs and endpoint agents over the
//! `/tenants/{tenant_id}/policy/bundles/{target_type}/payload`
//! HTTP endpoint (see `internal/handler/policy.go` on the Go
//! side).
//!
//! This module is what consumes a bundle on the agent / edge
//! side. The flow is:
//!
//! 1. Pull bundle bytes + signature from the control plane via
//!    `sng-comms` (Phase 3).
//! 2. Decode the bundle header (small, fixed-size prefix).
//! 3. Look up the signing key by `key_id` in the operator-
//!    provided trust store.
//! 4. Verify the Ed25519 signature against the bundle bytes.
//! 5. Sanity-check the bundle's claimed target matches the
//!    target the agent was asked to load.
//! 6. Hand the verified bundle bytes to `sng-policy-eval` for
//!    parsing into a rule table.
//!
//! All five steps are gated by this module. A bundle that fails
//! any step is rejected — the agent never falls back to an
//! unsigned or unverified bundle, no matter how the upstream
//! deployment is configured.
//!
//! Wire compatibility: the SHA-256 digest and the Ed25519
//! signature byte layouts match `internal/repository/postgres/policy.go`
//! (the Go side that signs the bundles). The Go `crypto/ed25519`
//! and Rust `ed25519-dalek` libraries produce identical
//! signature bytes for the same message and key, which is what
//! makes the wire compatibility work.

use crate::error::ErrorCode;
use crate::ids::{PolicyBundleId, PolicyGraphId, PolicySigningKeyId, TenantId};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// The four enforcement targets a bundle may be compiled for.
/// Mirrors `internal/repository/types.go::PolicyBundleTarget`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BundleTarget {
    /// Edge VM appliance.
    Edge,
    /// Endpoint agent.
    Endpoint,
    /// Cloud connector.
    Cloud,
    /// Mobile endpoint.
    Mobile,
}

impl BundleTarget {
    /// Canonical lowercase wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Edge => "edge",
            Self::Endpoint => "endpoint",
            Self::Cloud => "cloud",
            Self::Mobile => "mobile",
        }
    }
}

impl fmt::Display for BundleTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by [`BundleTarget::from_str`].
#[derive(Debug, Error, PartialEq, Eq)]
#[error("unknown bundle target: {0:?}")]
pub struct UnknownBundleTarget(pub String);

impl FromStr for BundleTarget {
    type Err = UnknownBundleTarget;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "edge" => Ok(Self::Edge),
            "endpoint" => Ok(Self::Endpoint),
            "cloud" => Ok(Self::Cloud),
            "mobile" => Ok(Self::Mobile),
            other => Err(UnknownBundleTarget(other.to_owned())),
        }
    }
}

/// Ed25519 signature over the policy bundle bytes.
///
/// The wire form is the 64-byte signature value emitted by
/// `ed25519_dalek::SigningKey::sign` and accepted by
/// `crypto/ed25519.Verify` on the Go side. Stored as base64 in
/// JSON for human-readable transport; the on-the-wire MessagePack
/// form is the raw 64-byte bytestring.
#[derive(Clone, PartialEq, Eq)]
pub struct BundleSignature {
    /// Raw 64-byte Ed25519 signature.
    pub bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH],
}

impl fmt::Debug for BundleSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Don't dump the full 64 bytes in trace logs; the
        // signature is not a secret, but the noise is rarely
        // useful. Show base64 prefix + suffix.
        let b64 = B64.encode(self.bytes);
        if b64.len() > 16 {
            write!(
                f,
                "BundleSignature({}…{})",
                &b64[..8],
                &b64[b64.len() - 4..]
            )
        } else {
            write!(f, "BundleSignature({b64})")
        }
    }
}

impl Serialize for BundleSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // MessagePack: raw 64-byte string.
        s.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for BundleSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <serde_bytes::ByteBuf>::deserialize(d)?;
        let bytes = bytes.into_vec();
        let len = bytes.len();
        let arr: [u8; ed25519_dalek::SIGNATURE_LENGTH] = bytes.try_into().map_err(|_| {
            serde::de::Error::custom(format!(
                "ed25519 signature must be {} bytes, got {}",
                ed25519_dalek::SIGNATURE_LENGTH,
                len
            ))
        })?;
        Ok(Self { bytes: arr })
    }
}

/// Serde adapter that encodes / decodes a fixed-size `[u8; 32]`
/// as a MessagePack byte-string (`bin` family) rather than the
/// default array-of-integers encoding `serde` would otherwise
/// pick for fixed-size arrays. Mirrors how the Go side
/// (`vmihailenco/msgpack/v5`) encodes a `[]byte` and keeps the
/// digest bytes interoperable with any Go consumer that ends up
/// reading the same on-wire bundle envelope. Also significantly
/// more compact (35 bytes vs. ~96 bytes for a 32-byte digest).
mod sha256_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    /// SHA-256 digests are always exactly 32 bytes. Keep the
    /// constant local so any future re-use (e.g. a `Sha256Digest`
    /// newtype) does not silently desync from this module.
    pub(super) const SHA256_LEN: usize = 32;

    pub(super) fn serialize<S: Serializer>(
        bytes: &[u8; SHA256_LEN],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<[u8; SHA256_LEN], D::Error> {
        let raw = <serde_bytes::ByteBuf>::deserialize(d)?;
        let raw = raw.into_vec();
        let len = raw.len();
        raw.try_into().map_err(|_| {
            serde::de::Error::custom(format!(
                "sha256 digest must be {SHA256_LEN} bytes, got {len}"
            ))
        })
    }
}

/// Header that prefixes the on-wire policy bundle. Pulled
/// separately from the payload so the verifier can check the
/// target / version / key-id before deciding to spend cycles on
/// the (potentially large) bundle body.
///
/// Wire layout mirrors `internal/repository/types.go::PolicyBundle`
/// — same field names, same MessagePack tags.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundleHeader {
    /// Bundle identifier.
    #[serde(rename = "id")]
    pub id: PolicyBundleId,
    /// Source policy graph identifier.
    #[serde(rename = "graph")]
    pub graph_id: PolicyGraphId,
    /// Tenant scope.
    #[serde(rename = "tid")]
    pub tenant_id: TenantId,
    /// Target enforcement surface.
    #[serde(rename = "tgt")]
    pub target: BundleTarget,
    /// Monotonic version number. Higher is newer; the verifier
    /// rejects a bundle whose version is below the currently-
    /// loaded one (downgrade / replay protection).
    #[serde(rename = "ver")]
    pub version: u64,
    /// Compilation timestamp.
    #[serde(rename = "ts", with = "chrono::serde::ts_milliseconds")]
    pub compiled_at: DateTime<Utc>,
    /// Identifier of the Ed25519 key that signed [`PolicyBundle::body`].
    #[serde(rename = "kid")]
    pub signing_key_id: PolicySigningKeyId,
}

/// A verified policy bundle. Once you hold one of these, the
/// signature has been checked against the trust store and the
/// target type has been confirmed; the `body` bytes are safe to
/// hand to `sng-policy-eval`.
///
/// Header fields are inlined directly rather than nested behind
/// a `#[serde(flatten)] header: PolicyBundleHeader`: `flatten`
/// requires the deserializer to buffer the input map and replay
/// it against the inner struct, which is documented as
/// problematic for non-self-describing formats like MessagePack
/// (duplicate-key / ordering edge cases, extra allocations).
/// Flat layout also matches the Go-side
/// `internal/repository/types.go::PolicyBundle` shape exactly.
/// Callers that need just the header view (e.g. an HTTP HEAD
/// response that ships header fields out-of-band) can build a
/// [`PolicyBundleHeader`] via [`PolicyBundle::header`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Bundle identifier.
    #[serde(rename = "id")]
    pub id: PolicyBundleId,
    /// Source policy graph identifier.
    #[serde(rename = "graph")]
    pub graph_id: PolicyGraphId,
    /// Tenant scope.
    #[serde(rename = "tid")]
    pub tenant_id: TenantId,
    /// Target enforcement surface.
    #[serde(rename = "tgt")]
    pub target: BundleTarget,
    /// Monotonic version number. Higher is newer; the verifier
    /// rejects a bundle whose version is below the currently-
    /// loaded one (downgrade / replay protection).
    #[serde(rename = "ver")]
    pub version: u64,
    /// Compilation timestamp.
    #[serde(rename = "ts", with = "chrono::serde::ts_milliseconds")]
    pub compiled_at: DateTime<Utc>,
    /// Identifier of the Ed25519 key that signed [`PolicyBundle::body`].
    #[serde(rename = "kid")]
    pub signing_key_id: PolicySigningKeyId,
    /// MessagePack-encoded compiled rule table. Opaque to this
    /// module — `sng-policy-eval` is responsible for parsing it
    /// into a usable form.
    #[serde(rename = "body", with = "serde_bytes")]
    pub body: Vec<u8>,
    /// SHA-256 of `body`. Carried separately so the verifier
    /// can short-circuit a digest mismatch without re-hashing.
    /// Must equal `sha256(body)`. Encoded on the wire as a
    /// MessagePack byte-string (see [`sha256_serde`]).
    #[serde(rename = "sha", with = "sha256_serde")]
    pub sha256: [u8; 32],
    /// Ed25519 signature over `sha256` (NOT over the raw bytes
    /// of `body` — signing the digest keeps the signature
    /// computation O(1) regardless of body size). Matches the
    /// Go-side scheme at `internal/repository/postgres/policy.go`.
    #[serde(rename = "sig")]
    pub signature: BundleSignature,
}

impl PolicyBundle {
    /// Construct a lightweight header view of this bundle. Used
    /// by HEAD / metadata-only paths (e.g. the agent-pull
    /// `If-None-Match` short-circuit) where the body bytes are
    /// not yet loaded.
    #[must_use]
    pub fn header(&self) -> PolicyBundleHeader {
        PolicyBundleHeader {
            id: self.id,
            graph_id: self.graph_id,
            tenant_id: self.tenant_id,
            target: self.target,
            version: self.version,
            compiled_at: self.compiled_at,
            signing_key_id: self.signing_key_id,
        }
    }
}

/// Verification error returned by [`PolicyVerifier::verify`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    /// The bundle's claimed signing key id is not in the trust
    /// store. Either the operator forgot to install the key, or
    /// the bundle was signed by a foreign key.
    #[error("signing key {0} is not in the trust store")]
    UnknownSigningKey(PolicySigningKeyId),
    /// Signature verification against the matching trust-store
    /// key failed.
    #[error("signature verification failed for bundle {0}")]
    SignatureInvalid(PolicyBundleId),
    /// The bundle's body digest does not match the SHA-256 we
    /// computed locally.
    #[error("body digest mismatch for bundle {0}")]
    DigestMismatch(PolicyBundleId),
    /// The bundle was signed for a different target than the
    /// verifier was asked to load.
    #[error("bundle {bundle_id} targets {actual}, verifier requested {expected}")]
    TargetMismatch {
        bundle_id: PolicyBundleId,
        actual: BundleTarget,
        expected: BundleTarget,
    },
    /// The bundle's version is older than the version currently
    /// active. Replay / downgrade attempt.
    #[error("bundle {bundle_id} version {found} is older than current {current}")]
    Stale {
        bundle_id: PolicyBundleId,
        found: u64,
        current: u64,
    },
}

impl VerificationError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownSigningKey(_) => ErrorCode::PolicyBundleSigningKeyUnknown,
            Self::SignatureInvalid(_) | Self::DigestMismatch(_) => {
                ErrorCode::PolicyBundleSignatureInvalid
            }
            Self::TargetMismatch { .. } => ErrorCode::PolicyBundleTargetMismatch,
            Self::Stale { .. } => ErrorCode::PolicyBundleStale,
        }
    }
}

/// Verifier-side trust store: map of operator-provisioned
/// signing key id → public key. Built at agent startup from the
/// control-plane key directory.
#[derive(Clone, Debug, Default)]
pub struct PolicyVerifier {
    keys: HashMap<PolicySigningKeyId, VerifyingKey>,
}

impl PolicyVerifier {
    /// Build an empty verifier. Add keys with [`Self::add_key`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a trusted signing key. The agent loads these from
    /// the control plane's published key directory at startup
    /// (and on rotation). `key_bytes` must be the 32-byte
    /// raw Ed25519 public key — the same form
    /// `crypto/ed25519.PublicKey` produces on the Go side.
    pub fn add_key(
        &mut self,
        id: PolicySigningKeyId,
        key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let key = VerifyingKey::from_bytes(key_bytes)?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Returns true if the verifier has a key with the given id.
    #[must_use]
    pub fn has_key(&self, id: &PolicySigningKeyId) -> bool {
        self.keys.contains_key(id)
    }

    /// Verify a fully-decoded [`PolicyBundle`] against the
    /// trust store and the caller-supplied invariants.
    ///
    /// * `expected_target` — the target this verifier was asked
    ///   to load. Bundles intended for a different target are
    ///   rejected even if the signature is otherwise valid.
    /// * `current_version` — the version of the bundle the
    ///   agent already has loaded. Pass `None` if this is the
    ///   first bundle since startup; otherwise pass the active
    ///   version so a downgrade attempt is rejected.
    pub fn verify(
        &self,
        bundle: &PolicyBundle,
        expected_target: BundleTarget,
        current_version: Option<u64>,
    ) -> Result<(), VerificationError> {
        // 1. Target sanity check. Cheapest check first so a
        //    misrouted bundle costs nothing.
        if bundle.target != expected_target {
            return Err(VerificationError::TargetMismatch {
                bundle_id: bundle.id,
                actual: bundle.target,
                expected: expected_target,
            });
        }
        // 2. Downgrade / replay rejection.
        if let Some(current) = current_version {
            if bundle.version < current {
                return Err(VerificationError::Stale {
                    bundle_id: bundle.id,
                    found: bundle.version,
                    current,
                });
            }
        }
        // 3. Digest match. The signature is over the digest, so
        //    a digest mismatch makes the signature meaningless
        //    even if it verifies — fail fast.
        let mut hasher = Sha256::new();
        hasher.update(&bundle.body);
        let computed: [u8; 32] = hasher.finalize().into();
        if computed != bundle.sha256 {
            return Err(VerificationError::DigestMismatch(bundle.id));
        }
        // 4. Key lookup.
        let key = self
            .keys
            .get(&bundle.signing_key_id)
            .ok_or(VerificationError::UnknownSigningKey(bundle.signing_key_id))?;
        // 5. Signature verification over the digest. Matches
        //    the Go-side `crypto/ed25519.Verify(pub, digest, sig)`
        //    call shape.
        let sig = Signature::from_bytes(&bundle.signature.bytes);
        key.verify(&bundle.sha256, &sig)
            .map_err(|_| VerificationError::SignatureInvalid(bundle.id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;

    fn signed_bundle(
        target: BundleTarget,
        version: u64,
        signing_key: &SigningKey,
        key_id: PolicySigningKeyId,
        body: Vec<u8>,
    ) -> PolicyBundle {
        let mut hasher = Sha256::new();
        hasher.update(&body);
        let sha256: [u8; 32] = hasher.finalize().into();
        let signature = signing_key.sign(&sha256);
        // The wire format encodes `compiled_at` with
        // `chrono::serde::ts_milliseconds` to stay byte-stable
        // with the Go `vmihailenco/msgpack/v5` time.Time marshaller,
        // which also drops sub-millisecond precision. We truncate
        // the fixture timestamp at construction time so the
        // round-trip equality test is meaningful — otherwise the
        // local nanos would not survive the marshal step.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let compiled_at =
            chrono::DateTime::from_timestamp_millis(now_ms).expect("ms timestamp in range");
        PolicyBundle {
            id: PolicyBundleId::new_v4(),
            graph_id: PolicyGraphId::new_v4(),
            tenant_id: TenantId::new_v4(),
            target,
            version,
            compiled_at,
            signing_key_id: key_id,
            body,
            sha256,
            signature: BundleSignature {
                bytes: signature.to_bytes(),
            },
        }
    }

    fn fixture_keypair() -> (SigningKey, PolicySigningKeyId, VerifyingKey) {
        // Deterministic seed for reproducible test fixtures —
        // the value is arbitrary, just stable.
        let seed = [7_u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let verify = signing.verifying_key();
        (signing, PolicySigningKeyId::new_v4(), verify)
    }

    #[test]
    fn verify_accepts_a_correctly_signed_bundle() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(
            BundleTarget::Edge,
            42,
            &signing,
            key_id,
            b"rules-msgpack-blob".to_vec(),
        );
        verifier
            .verify(&bundle, BundleTarget::Edge, Some(41))
            .expect("valid bundle");
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        let mut bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id, b"rules".to_vec());
        // Tamper with the body without re-hashing or re-signing.
        bundle.body.extend_from_slice(b"-MITM");
        let err = verifier
            .verify(&bundle, BundleTarget::Edge, None)
            .expect_err("tampered body must fail");
        assert!(matches!(err, VerificationError::DigestMismatch(_)));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        let mut bundle = signed_bundle(
            BundleTarget::Endpoint,
            1,
            &signing,
            key_id,
            b"rules".to_vec(),
        );
        // Flip a bit in the signature.
        bundle.signature.bytes[0] ^= 0x01;
        let err = verifier
            .verify(&bundle, BundleTarget::Endpoint, None)
            .expect_err("tampered signature must fail");
        assert!(matches!(err, VerificationError::SignatureInvalid(_)));
    }

    #[test]
    fn verify_rejects_unknown_signing_key() {
        let (signing, key_id, _verify) = fixture_keypair();
        // Don't add the key to the trust store.
        let verifier = PolicyVerifier::new();
        let bundle = signed_bundle(BundleTarget::Cloud, 1, &signing, key_id, b"rules".to_vec());
        let err = verifier
            .verify(&bundle, BundleTarget::Cloud, None)
            .expect_err("unknown key must fail");
        assert!(matches!(err, VerificationError::UnknownSigningKey(_)));
        assert_eq!(err.code(), ErrorCode::PolicyBundleSigningKeyUnknown);
    }

    #[test]
    fn verify_rejects_target_mismatch() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id, b"rules".to_vec());
        let err = verifier
            .verify(&bundle, BundleTarget::Endpoint, None)
            .expect_err("target mismatch must fail");
        assert!(matches!(err, VerificationError::TargetMismatch { .. }));
    }

    #[test]
    fn verify_rejects_stale_version() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(BundleTarget::Edge, 5, &signing, key_id, b"rules".to_vec());
        let err = verifier
            .verify(&bundle, BundleTarget::Edge, Some(7))
            .expect_err("stale version must fail");
        assert!(matches!(err, VerificationError::Stale { .. }));
    }

    #[test]
    fn verify_accepts_same_version_as_current() {
        // Equality is NOT considered stale — re-applying the
        // currently-active bundle must be a no-op success, not
        // a rejection.
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(
            BundleTarget::Endpoint,
            5,
            &signing,
            key_id,
            b"rules".to_vec(),
        );
        verifier
            .verify(&bundle, BundleTarget::Endpoint, Some(5))
            .expect("equal version is acceptable");
    }

    #[test]
    fn bundle_round_trips_through_msgpack() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 9, &signing, key_id, b"rules".to_vec());
        let bytes = rmp_serde::to_vec_named(&bundle).expect("encode");
        let back: PolicyBundle = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(bundle, back);
    }

    /// Regression: the `sha256` field must encode as a
    /// MessagePack `bin` (byte-string) family, not as a 32-element
    /// array of u8 integers. The Go side
    /// (`vmihailenco/msgpack/v5`) encodes `[]byte` as `bin`, so
    /// the wire bytes must agree for cross-language consumers.
    /// `bin 8` (marker `0xc4`) takes 35 bytes for 32 bytes of
    /// digest; the default `[u8; 32]` array encoding would emit
    /// ~96 bytes (marker `0xdc` + length + 32×u8 markers).
    #[test]
    fn sha256_field_encodes_as_msgpack_bin() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id, b"rules".to_vec());
        let bytes = rmp_serde::to_vec_named(&bundle).expect("encode");
        // Locate the 32-byte digest in the encoded stream. The
        // digest never appears as a literal substring elsewhere
        // (it's a sha256 of the body), so a search is safe.
        let needle = bundle.sha256;
        let pos = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("digest bytes must appear in encoded stream");
        // The byte immediately preceding the digest must be the
        // `bin 8` length byte (`0x20` = 32), and the byte before
        // that must be the `bin 8` marker (`0xc4`).
        assert!(pos >= 2, "digest must be prefixed by bin marker + length");
        assert_eq!(
            bytes[pos - 2],
            0xc4,
            "sha256 must be MessagePack bin family, got marker {:#x}",
            bytes[pos - 2]
        );
        assert_eq!(
            bytes[pos - 1],
            32,
            "sha256 bin length must be 32, got {}",
            bytes[pos - 1]
        );
    }

    /// Regression: deserialisation must reject a sha256 field
    /// whose length is not exactly 32 bytes, so a malformed or
    /// truncated digest cannot quietly turn into a different
    /// type after the round-trip.
    #[test]
    fn sha256_field_rejects_wrong_length() {
        // Build a tiny synthetic msgpack map with a 16-byte
        // `sha` value (half the expected length). Use the
        // `with`-aware deserializer path by piggybacking on
        // `PolicyBundle`'s real shape so we only break the one
        // field under test.
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id, b"rules".to_vec());
        // Encode the good bundle, then surgically rewrite the
        // 32-byte digest into a 16-byte one with a fresh `bin 8`
        // length prefix. This keeps the rest of the map intact
        // so any error must come from the sha256 length check.
        let good = rmp_serde::to_vec_named(&bundle).expect("encode");
        let digest = bundle.sha256;
        let digest_pos = good
            .windows(digest.len())
            .position(|w| w == digest)
            .expect("digest in encoded stream");
        // Truncate to 16 bytes.
        let mut bad = Vec::with_capacity(good.len() - 16);
        bad.extend_from_slice(&good[..digest_pos - 1]); // up to length byte
        bad.push(16); // new bin length
        bad.extend_from_slice(&digest[..16]);
        bad.extend_from_slice(&good[digest_pos + 32..]);
        let err = rmp_serde::from_slice::<PolicyBundle>(&bad)
            .expect_err("16-byte sha256 must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("sha256 digest must be 32 bytes"),
            "error must call out the length mismatch, got: {msg}"
        );
    }

    /// `PolicyBundle::header()` must produce a `PolicyBundleHeader`
    /// whose fields match the bundle's inlined fields exactly.
    /// This is the contract the HEAD / metadata-pull path relies
    /// on once `sng-comms` lands in PR 3.
    #[test]
    fn header_view_matches_inline_fields() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(
            BundleTarget::Endpoint,
            42,
            &signing,
            key_id,
            b"rules".to_vec(),
        );
        let header = bundle.header();
        assert_eq!(header.id, bundle.id);
        assert_eq!(header.graph_id, bundle.graph_id);
        assert_eq!(header.tenant_id, bundle.tenant_id);
        assert_eq!(header.target, bundle.target);
        assert_eq!(header.version, bundle.version);
        assert_eq!(header.compiled_at, bundle.compiled_at);
        assert_eq!(header.signing_key_id, bundle.signing_key_id);
    }

    #[test]
    fn bundle_target_round_trips_through_str() {
        for tgt in [
            BundleTarget::Edge,
            BundleTarget::Endpoint,
            BundleTarget::Cloud,
            BundleTarget::Mobile,
        ] {
            let parsed: BundleTarget = tgt.as_str().parse().expect("parse");
            assert_eq!(parsed, tgt);
        }
    }

    #[test]
    fn bundle_target_rejects_unknown() {
        let err = "satellite".parse::<BundleTarget>().unwrap_err();
        assert_eq!(err.0, "satellite");
    }
}

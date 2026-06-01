//! Signed policy bundle verification.
//!
//! The control plane compiles the typed policy graph into a
//! MessagePack-encoded "bundle payload" and Ed25519-signs the
//! raw payload bytes with the tenant's active signing key. The
//! agent / edge then pulls the bundle via
//! `GET /tenants/{tenant_id}/policy/bundles/{target_type}/payload`
//! (see `internal/handler/policy.go`), which returns:
//!
//! * **HTTP body**: the raw signed payload bytes (= the Go
//!   compiler's `internal/service/policy/service.go::bundlePayload`
//!   MessagePack-encoded).
//! * **`X-Sng-Policy-Signature` header**: base64-encoded Ed25519
//!   signature over the body bytes.
//! * **`X-Sng-Policy-Key-Id` header**: short identifier of the
//!   signing key the verifier should look up in the trust store.
//! * **`ETag` / `Last-Modified` / `X-Sng-Policy-Bundle-Id` /
//!   `X-Sng-Policy-Graph-Id` headers**: transport-level metadata.
//!   **NOT authenticated** by the signature — receivers must treat
//!   anything they care about for security (target, version,
//!   graph id) as the values inside the signed body, not the
//!   advisory header echo.
//!
//! `sng-comms` (PR 3) builds the [`PolicyBundle`] from those
//! pieces; this module does the cryptographic + invariant checks
//! the agent performs before handing the bytes to `sng-policy-eval`
//! (PR 4):
//!
//! 1. Look up the signing key by [`PolicyBundle::signing_key_id`]
//!    in the operator-provided trust store.
//! 2. Verify the Ed25519 signature against
//!    [`PolicyBundle::body`] — **the raw body bytes**, matching
//!    the Go side's `ed25519.Sign(priv, payload)` at
//!    `internal/service/policy/service.go::Compile` (no extra
//!    digest layer; signing the body bytes directly is what
//!    makes the signature byte-for-byte interoperable with the
//!    Go signer and authenticates **every** byte of the body,
//!    including the inlined target / graph-id / version / compiled-at).
//! 3. Decode the authenticated header claims out of the verified
//!    body via [`PolicyBundleClaims::from_body`].
//! 4. Compare the decoded claims against the caller-supplied
//!    expectations ([`PolicyBundleClaims::check_target`] /
//!    [`PolicyBundleClaims::check_not_stale`]) — these checks run
//!    against fields the signature has already vouched for, so a
//!    network attacker who tries to swap target / version cannot
//!    pass them without forging the signature.
//! 5. Hand the verified body to `sng-policy-eval` for full
//!    rule-table parsing.
//!
//! A bundle that fails any step is rejected — the agent never
//! falls back to an unsigned or partially-verified bundle.
//!
//! Wire compatibility: the Ed25519 signature byte layout matches
//! `internal/service/policy/service.go` (the Go side that signs
//! the bundles). The Go `crypto/ed25519` and Rust `ed25519-dalek`
//! libraries produce identical signature bytes for the same
//! message and key, which is what makes the wire compatibility
//! work.

use crate::error::ErrorCode;
#[cfg(test)]
use crate::ids::PolicyGraphId;
use crate::ids::{PolicyBundleId, PolicySigningKeyId};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

/// The four enforcement targets a bundle may be compiled for.
/// Mirrors `internal/repository/types.go::PolicyBundleTarget` and
/// the `"t"` field on the Go compiler's `bundlePayload`.
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
/// `crypto/ed25519.Verify` on the Go side. On the agent-pull
/// transport (`internal/handler/policy.go::downloadBundle`) the
/// signature is carried base64-encoded in the
/// `X-Sng-Policy-Signature` HTTP response header; when bundles
/// are passed around within the agent as a single MessagePack
/// envelope (the [`PolicyBundle`] shape below), the same 64
/// bytes are emitted as a MessagePack `bin` byte-string. This
/// type never participates in a JSON wire format — the agent
/// stack is MessagePack end-to-end.
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
        // MessagePack: raw 64-byte string (bin 8 family). Matches
        // `[]byte` emitted by `vmihailenco/msgpack/v5` on the Go
        // side, so the on-the-wire bytes are byte-identical.
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

/// On-the-wire signed policy bundle: the cryptographic unit the
/// agent verifies.
///
/// Three fields, by design:
///
/// * [`Self::body`] — the **signed** bytes. Opaque at this layer
///   (parsing happens in `sng-policy-eval`). The signed body
///   itself contains the authoritative header fields
///   (target / graph-id / graph-version / compiled-at — see
///   [`PolicyBundleClaims`]); they are authenticated transitively
///   through the signature.
/// * [`Self::signature`] — Ed25519 over [`Self::body`] bytes,
///   matching the Go-side `ed25519.Sign(priv, payload)` call
///   at `internal/service/policy/service.go::Compile`.
/// * [`Self::signing_key_id`] — out-of-band identifier the
///   verifier uses to look up the trusted public key.
///   Substituting this field on a captured bundle does not
///   weaken security: pointing the lookup at a different key
///   produces a verification failure because the signature was
///   produced by a different private key.
///
/// What is intentionally **not** modelled here: the HTTP
/// transport-level metadata (`ETag`, `Last-Modified`,
/// `X-Sng-Policy-Bundle-Id`, `X-Sng-Policy-Graph-Id`) is advisory
/// and unauthenticated. `sng-comms` may carry it alongside the
/// bundle for cache control and operator-side cross-checks, but
/// nothing in this module trusts those headers — the source of
/// truth for security-relevant claims is always the signed body.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// MessagePack-encoded compiled bundle payload — the bytes
    /// the Go compiler emits at
    /// `internal/service/policy/service.go::encodeBundlePayloadFor`
    /// and signs at the same site. Opaque to this module;
    /// [`PolicyBundleClaims::from_body`] decodes the
    /// authenticated header view, and `sng-policy-eval` (PR 4)
    /// decodes the full rule table.
    #[serde(rename = "body", with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Ed25519 signature over [`Self::body`] bytes. The Go side
    /// calls `ed25519.Sign(priv, body)` directly — signing the
    /// raw bytes (not a digest) is what authenticates **every**
    /// byte of the body, header claims included.
    #[serde(rename = "sig")]
    pub signature: BundleSignature,
    /// Identifier of the Ed25519 key that produced
    /// [`Self::signature`]. Carried over the agent-pull
    /// transport as the `X-Sng-Policy-Key-Id` HTTP response
    /// header. Used by [`PolicyVerifier::verify`] to look up
    /// the trusted public key.
    #[serde(rename = "kid")]
    pub signing_key_id: PolicySigningKeyId,
}

/// Authenticated header claims decoded from
/// [`PolicyBundle::body`]. Mirrors the Go compiler's
/// `internal/service/policy/service.go::bundlePayload` struct
/// field-for-field for the metadata it carries; the rule table
/// itself (`r`) and steering snapshot (`st`) are intentionally
/// not modelled here — `sng-policy-eval` (PR 4) owns the body
/// shape beyond these claims.
///
/// Because these fields live inside the signed body, every
/// value here has been authenticated by [`PolicyVerifier::verify`]
/// before the caller obtains them via
/// [`PolicyBundleClaims::from_body`]. A network attacker who
/// flips any field invalidates the signature and is rejected
/// before this struct is ever constructed.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct PolicyBundleClaims {
    /// Wire-format schema version. Matches the Go
    /// `bundlePayload.SchemaVersion` field (tag `v`).
    #[serde(rename = "v")]
    pub schema_version: u8,
    /// Enforcement target this bundle was compiled for.
    /// Authenticated. Matches Go `bundlePayload.Target` (`t`).
    #[serde(rename = "t")]
    pub target: BundleTarget,
    /// Source policy graph this bundle was compiled from.
    /// Matches Go `bundlePayload.GraphID` (`g`). The Go
    /// compiler emits the canonical 36-char hyphenated UUID as
    /// a MessagePack string (NOT a 16-byte binary blob — see
    /// `sng-policy-eval::bundle::RawBundle.graph_id` which is
    /// also typed as `String` and decodes the SAME bundle body
    /// bytes downstream of this verifier). Kept free-form
    /// (`String`) instead of a typed `PolicyGraphId` so the
    /// wire codec matches the Go side bit-for-bit and the two
    /// decoders (claims here, full bundle in
    /// `sng-policy-eval`) agree on the same body. Parse this
    /// into a [`PolicyGraphId`] at the call site if a typed id
    /// is needed for downstream telemetry.
    #[serde(rename = "g")]
    pub graph_id: String,
    /// Monotonic graph version. Higher is newer; receivers reject
    /// a bundle whose version is below the currently-loaded one
    /// (replay / downgrade protection, see
    /// [`Self::check_not_stale`]). Stored as `i64` to match the
    /// Go `int` on a 64-bit build.
    #[serde(rename = "gv")]
    pub graph_version: i64,
    /// Compiler version that produced this bundle. Echoed back
    /// in telemetry so operator dashboards can spot a partial
    /// upgrade fleet-wide. Matches Go `bundlePayload.Compiler`
    /// (`c`).
    #[serde(rename = "c")]
    pub compiler: String,
    /// Default action when no rule matches. Matches Go
    /// `bundlePayload.DefaultAction` (`d`). Free-form string at
    /// this layer (e.g. "deny", "allow", "inspect"); the typed
    /// enum lives in `sng-policy-eval`.
    #[serde(rename = "d")]
    pub default_action: String,
    /// Compile timestamp. Matches Go `bundlePayload.CompiledAt`
    /// (`ts`), wire shape is RFC 3339 nano-precision string.
    #[serde(rename = "ts")]
    pub compiled_at: DateTime<Utc>,
}

impl PolicyBundleClaims {
    /// Decode the authenticated claims out of a verified
    /// [`PolicyBundle::body`].
    ///
    /// **MUST only be called after
    /// [`PolicyVerifier::verify`] has accepted the bundle** —
    /// the claims are only meaningful against a body whose
    /// signature has been validated.
    ///
    /// Uses [`rmp_serde::from_slice`] so the wire bytes are
    /// decoded exactly as the Go compiler emits them. Unknown
    /// fields (e.g. the rule table `r` and steering snapshot
    /// `st`) are silently ignored — `sng-policy-eval` decodes
    /// those separately.
    pub fn from_body(body: &[u8]) -> Result<Self, VerificationError> {
        rmp_serde::from_slice(body)
            .map_err(|e| VerificationError::BodySchema(format!("decode claims: {e}")))
    }

    /// Check that the bundle was compiled for the target the
    /// agent expects. Defends against a misrouted (but
    /// otherwise valid) bundle being applied to the wrong
    /// enforcement surface. The check runs against the
    /// authenticated `target` field inside the signed body —
    /// flipping it on the wire would have already invalidated
    /// the signature.
    pub fn check_target(
        &self,
        bundle_id: PolicyBundleId,
        expected: BundleTarget,
    ) -> Result<(), VerificationError> {
        if self.target == expected {
            Ok(())
        } else {
            Err(VerificationError::TargetMismatch {
                bundle_id,
                actual: self.target,
                expected,
            })
        }
    }

    /// Check that the bundle's graph version is not older than
    /// what the agent already has loaded. Defends against a
    /// captured-and-replayed older bundle (e.g. one with a
    /// pre-revocation rule the operator has since fixed).
    /// `current` is the version of the bundle the agent
    /// currently has loaded; pass `None` on the cold-start path
    /// where there is nothing to compare against.
    pub fn check_not_stale(
        &self,
        bundle_id: PolicyBundleId,
        current: Option<i64>,
    ) -> Result<(), VerificationError> {
        let Some(current) = current else {
            return Ok(());
        };
        if self.graph_version >= current {
            Ok(())
        } else {
            Err(VerificationError::Stale {
                bundle_id,
                found: self.graph_version,
                current,
            })
        }
    }
}

/// Verification error returned by [`PolicyVerifier::verify`] and
/// the [`PolicyBundleClaims`] invariant-check methods.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VerificationError {
    /// The bundle's claimed signing key id is not in the trust
    /// store. Either the operator forgot to install the key, or
    /// the bundle was signed by a foreign key.
    #[error("signing key {0} is not in the trust store")]
    UnknownSigningKey(PolicySigningKeyId),
    /// The bundle carries the [`PolicySigningKeyId::ephemeral`]
    /// sentinel id. Production receivers must reject these —
    /// there is no key to verify against. Used by the Go-side
    /// `EphemeralSigner` for in-process compiler tests only.
    #[error("bundle carries ephemeral key id; production bundles must use a persisted key")]
    EphemeralSigningKey,
    /// Signature verification against the matching trust-store
    /// key failed. The bundle was tampered with, signed by a
    /// different (untrusted) key, or pointed at the wrong
    /// signing key id.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// Decoding the signed body as [`PolicyBundleClaims`]
    /// failed. The bundle's signature verified but the body is
    /// not a well-formed `bundlePayload` MessagePack map.
    /// Either the agent and the control plane disagree on the
    /// bundle schema version or the body bytes were truncated.
    #[error("bundle body schema: {0}")]
    BodySchema(String),
    /// The bundle was signed for a different target than the
    /// verifier was asked to load. Detected by
    /// [`PolicyBundleClaims::check_target`].
    #[error("bundle {bundle_id} targets {actual}, verifier requested {expected}")]
    TargetMismatch {
        /// Bundle whose claim was rejected. Logged for operator
        /// triage.
        bundle_id: PolicyBundleId,
        /// Target the body claims to enforce.
        actual: BundleTarget,
        /// Target the verifier was asked to load.
        expected: BundleTarget,
    },
    /// The bundle's graph version is older than the version
    /// currently loaded. Detected by
    /// [`PolicyBundleClaims::check_not_stale`].
    #[error("bundle {bundle_id} version {found} is older than current {current}")]
    Stale {
        /// Bundle whose claim was rejected. Logged for operator
        /// triage.
        bundle_id: PolicyBundleId,
        /// Graph version on the rejected bundle.
        found: i64,
        /// Graph version currently loaded.
        current: i64,
    },
}

impl VerificationError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownSigningKey(_) | Self::EphemeralSigningKey => {
                ErrorCode::PolicyBundleSigningKeyUnknown
            }
            Self::SignatureInvalid => ErrorCode::PolicyBundleSignatureInvalid,
            Self::BodySchema(_) => ErrorCode::WireSchema,
            Self::TargetMismatch { .. } => ErrorCode::PolicyBundleTargetMismatch,
            Self::Stale { .. } => ErrorCode::PolicyBundleStale,
        }
    }
}

/// Trust-store-backed bundle verifier: map of operator-provisioned
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
    /// Adding the ephemeral sentinel id is rejected: there is
    /// no operator-provisioned key for it and accepting one
    /// would only ever create a foot-gun.
    pub fn add_key(
        &mut self,
        id: PolicySigningKeyId,
        key_bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
    ) -> Result<(), AddKeyError> {
        if id.is_ephemeral() {
            return Err(AddKeyError::EphemeralSigningKey);
        }
        let key = VerifyingKey::from_bytes(key_bytes).map_err(AddKeyError::InvalidKey)?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Returns true if the verifier has a key with the given id.
    #[must_use]
    pub fn has_key(&self, id: &PolicySigningKeyId) -> bool {
        self.keys.contains_key(id)
    }

    /// Verify a [`PolicyBundle`]'s Ed25519 signature against the
    /// trust store.
    ///
    /// The signature is checked over [`PolicyBundle::body`]
    /// bytes directly, matching the Go-side
    /// `ed25519.Sign(priv, body)` at
    /// `internal/service/policy/service.go::Compile`. Because
    /// the body itself carries the authoritative header fields
    /// (target, graph id, version, compiled-at), this single
    /// signature transitively authenticates every header claim
    /// — any tampering of the inlined header values would
    /// invalidate this check.
    ///
    /// After this returns `Ok`, decode the authenticated claims
    /// with [`PolicyBundleClaims::from_body`] and run the
    /// per-claim invariant checks
    /// ([`PolicyBundleClaims::check_target`] /
    /// [`PolicyBundleClaims::check_not_stale`]) before handing
    /// the body to `sng-policy-eval`.
    pub fn verify(&self, bundle: &PolicyBundle) -> Result<(), VerificationError> {
        if bundle.signing_key_id.is_ephemeral() {
            return Err(VerificationError::EphemeralSigningKey);
        }
        let key = self
            .keys
            .get(&bundle.signing_key_id)
            .ok_or_else(|| VerificationError::UnknownSigningKey(bundle.signing_key_id.clone()))?;
        let sig = Signature::from_bytes(&bundle.signature.bytes);
        key.verify(&bundle.body, &sig)
            .map_err(|_| VerificationError::SignatureInvalid)
    }
}

/// Error returned by [`PolicyVerifier::add_key`].
#[derive(Debug, Error)]
pub enum AddKeyError {
    /// Cannot install a key under the ephemeral sentinel id.
    #[error("cannot install a trusted key under the ephemeral signing-key id")]
    EphemeralSigningKey,
    /// The supplied public-key bytes were not a valid Ed25519
    /// point.
    #[error("invalid ed25519 public key: {0}")]
    InvalidKey(#[source] ed25519_dalek::SignatureError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;

    /// Build a real signed bundle the way the Go compiler does:
    /// encode the claims into a `bundlePayload`-shaped
    /// MessagePack body, then sign the body bytes with
    /// `ed25519.Sign(priv, body)`. The receiver-side flow under
    /// test then decodes the same bytes and verifies them.
    fn signed_bundle(
        target: BundleTarget,
        graph_version: i64,
        signing_key: &SigningKey,
        key_id: PolicySigningKeyId,
    ) -> PolicyBundle {
        // The Go side encodes its `CompiledAt` as an RFC 3339
        // nano-precision string. `chrono`'s default DateTime
        // serde adapter emits RFC 3339 too, so the round-trip
        // is byte-stable.
        let compiled_at = chrono::Utc::now();
        let claims = PolicyBundleClaims {
            schema_version: 1,
            target,
            graph_id: PolicyGraphId::new_v4().into_uuid().to_string(),
            graph_version,
            compiler: "sng-test/0".to_owned(),
            default_action: "deny".to_owned(),
            compiled_at,
        };
        // `to_vec_named` emits the named-map shape the Go
        // `vmihailenco/msgpack/v5` produces by default. The Go
        // signer signs THIS body shape; the Rust verifier
        // verifies the same bytes.
        let body = rmp_serde::to_vec_named(&claims).expect("encode body");
        let signature = signing_key.sign(&body);
        PolicyBundle {
            body,
            signature: BundleSignature {
                bytes: signature.to_bytes(),
            },
            signing_key_id: key_id,
        }
    }

    fn fixture_keypair() -> (SigningKey, PolicySigningKeyId, VerifyingKey) {
        // Deterministic seed for reproducible test fixtures —
        // the value is arbitrary, just stable.
        let seed = [7_u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let verify = signing.verifying_key();
        let key_id = PolicySigningKeyId::new("0a1b2c3d4e5f6071").expect("valid key id shape");
        (signing, key_id, verify)
    }

    #[test]
    fn verify_accepts_a_correctly_signed_bundle() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id.clone(), verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(BundleTarget::Edge, 42, &signing, key_id);
        verifier.verify(&bundle).expect("valid bundle");
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id.clone(), verify.as_bytes())
            .expect("add key");
        let mut bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        // Tamper with the body without re-signing. Even a
        // single byte change invalidates the ed25519 signature
        // because the signature is over the raw body bytes.
        bundle.body.push(0xFF);
        let err = verifier
            .verify(&bundle)
            .expect_err("tampered body must fail");
        assert_eq!(err, VerificationError::SignatureInvalid);
        assert_eq!(err.code(), ErrorCode::PolicyBundleSignatureInvalid);
    }

    /// Regression for finding 4 (architectural): flipping the
    /// header `target` inside the signed body must be detected
    /// by the signature check, not by a downstream non-crypto
    /// check. The previous design signed only `sha256(body)`
    /// and only checked target via a string compare, so a
    /// network attacker could re-header an existing bundle.
    /// Now the body bytes are signed directly: any flip of any
    /// authenticated field — `t`, `g`, `gv`, `d`, `ts` — breaks
    /// the signature.
    #[test]
    fn verify_rejects_target_swap_inside_signed_body() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id.clone(), verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        // Decode the body, swap the target, re-encode (matching
        // shape, only the value flips), and reinsert into the
        // bundle. Signature stays the same; the verifier MUST
        // reject this.
        let mut claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode claims");
        claims.target = BundleTarget::Endpoint;
        let tampered_body = rmp_serde::to_vec_named(&claims).expect("re-encode");
        let tampered = PolicyBundle {
            body: tampered_body,
            ..bundle
        };
        let err = verifier
            .verify(&tampered)
            .expect_err("target swap must fail");
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    /// Regression for finding 4 (architectural): flipping the
    /// header `graph_version` inside the signed body must also
    /// be caught by the signature check. The previous design
    /// would have accepted a re-headered bundle whose version
    /// claim was bumped to a giant number to suppress future
    /// legitimate bundles.
    #[test]
    fn verify_rejects_version_swap_inside_signed_body() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id.clone(), verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        let mut claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode claims");
        claims.graph_version = i64::MAX;
        let tampered_body = rmp_serde::to_vec_named(&claims).expect("re-encode");
        let tampered = PolicyBundle {
            body: tampered_body,
            ..bundle
        };
        let err = verifier
            .verify(&tampered)
            .expect_err("version swap must fail");
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id.clone(), verify.as_bytes())
            .expect("add key");
        let mut bundle = signed_bundle(BundleTarget::Endpoint, 1, &signing, key_id);
        // Flip a bit in the signature.
        bundle.signature.bytes[0] ^= 0x01;
        let err = verifier
            .verify(&bundle)
            .expect_err("tampered signature must fail");
        assert_eq!(err, VerificationError::SignatureInvalid);
    }

    #[test]
    fn verify_rejects_unknown_signing_key() {
        let (signing, key_id, _verify) = fixture_keypair();
        // Don't add the key to the trust store.
        let verifier = PolicyVerifier::new();
        let bundle = signed_bundle(BundleTarget::Cloud, 1, &signing, key_id);
        let err = verifier.verify(&bundle).expect_err("unknown key must fail");
        assert!(matches!(err, VerificationError::UnknownSigningKey(_)));
        assert_eq!(err.code(), ErrorCode::PolicyBundleSigningKeyUnknown);
    }

    #[test]
    fn verify_rejects_ephemeral_signing_key_on_the_bundle() {
        let (signing, _kid, verify) = fixture_keypair();
        let key_id = PolicySigningKeyId::new("0a1b2c3d4e5f6071").expect("valid key id");
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id, verify.as_bytes())
            .expect("add key");
        // Now build a bundle whose envelope claims to use the
        // ephemeral sentinel. The verifier rejects without ever
        // touching the signature.
        let bundle = signed_bundle(
            BundleTarget::Edge,
            1,
            &signing,
            PolicySigningKeyId::ephemeral(),
        );
        let err = verifier
            .verify(&bundle)
            .expect_err("ephemeral bundle must fail");
        assert_eq!(err, VerificationError::EphemeralSigningKey);
        assert_eq!(err.code(), ErrorCode::PolicyBundleSigningKeyUnknown);
    }

    #[test]
    fn add_key_rejects_the_ephemeral_id() {
        let (_signing, _kid, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        let err = verifier
            .add_key(PolicySigningKeyId::ephemeral(), verify.as_bytes())
            .expect_err("ephemeral install must fail");
        assert!(matches!(err, AddKeyError::EphemeralSigningKey));
    }

    #[test]
    fn claims_check_target_accepts_matching_target() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        let claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode claims");
        claims
            .check_target(PolicyBundleId::new_v4(), BundleTarget::Edge)
            .expect("matching target");
    }

    #[test]
    fn claims_check_target_rejects_mismatch() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        let claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode claims");
        let bid = PolicyBundleId::new_v4();
        let err = claims
            .check_target(bid, BundleTarget::Endpoint)
            .expect_err("mismatch must fail");
        assert!(matches!(
            err,
            VerificationError::TargetMismatch {
                bundle_id, actual: BundleTarget::Edge, expected: BundleTarget::Endpoint,
            } if bundle_id == bid
        ));
        assert_eq!(err.code(), ErrorCode::PolicyBundleTargetMismatch);
    }

    #[test]
    fn claims_check_not_stale_allows_newer_and_equal() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Endpoint, 5, &signing, key_id);
        let claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode claims");
        // Equal version is acceptable — re-applying the active
        // bundle is a no-op success, not a rejection.
        claims
            .check_not_stale(PolicyBundleId::new_v4(), Some(5))
            .expect("equal version is acceptable");
        // Newer version is the common refresh path.
        claims
            .check_not_stale(PolicyBundleId::new_v4(), Some(4))
            .expect("newer than current");
        // Cold-start has nothing to compare against.
        claims
            .check_not_stale(PolicyBundleId::new_v4(), None)
            .expect("cold start always accepts");
    }

    #[test]
    fn claims_check_not_stale_rejects_older() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 5, &signing, key_id);
        let claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode claims");
        let bid = PolicyBundleId::new_v4();
        let err = claims
            .check_not_stale(bid, Some(7))
            .expect_err("stale must fail");
        assert!(matches!(
            err,
            VerificationError::Stale {
                bundle_id, found: 5, current: 7,
            } if bundle_id == bid
        ));
        assert_eq!(err.code(), ErrorCode::PolicyBundleStale);
    }

    /// End-to-end: verify the signature, decode the
    /// authenticated claims, then run the per-claim invariant
    /// checks. This is the exact sequence the agent runs.
    #[test]
    fn full_verification_chain_accepts_authentic_bundle() {
        let (signing, key_id, verify) = fixture_keypair();
        let mut verifier = PolicyVerifier::new();
        verifier
            .add_key(key_id.clone(), verify.as_bytes())
            .expect("add key");
        let bundle = signed_bundle(BundleTarget::Endpoint, 11, &signing, key_id);
        verifier.verify(&bundle).expect("signature");
        let claims = PolicyBundleClaims::from_body(&bundle.body).expect("decode");
        claims
            .check_target(PolicyBundleId::new_v4(), BundleTarget::Endpoint)
            .expect("target");
        claims
            .check_not_stale(PolicyBundleId::new_v4(), Some(10))
            .expect("not stale");
    }

    #[test]
    fn bundle_round_trips_through_msgpack() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 9, &signing, key_id);
        let bytes = rmp_serde::to_vec_named(&bundle).expect("encode");
        let back: PolicyBundle = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(bundle, back);
    }

    /// The bundle envelope's `kid` field must serialise as a
    /// MessagePack `str`, not as a struct or array. The Go side
    /// stores key ids as `string` and any divergence would break
    /// cross-language interop.
    #[test]
    fn signing_key_id_encodes_as_msgpack_string() {
        let (signing, key_id, _verify) = fixture_keypair();
        let kid_str = key_id.as_str().to_owned();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        let bytes = rmp_serde::to_vec_named(&bundle).expect("encode");
        // The 16-char key id appears once verbatim in the
        // encoded stream, prefixed by a msgpack `fixstr` length
        // marker (0xa0 + len). 16-char id ⇒ 0xb0 marker.
        let pos = bytes
            .windows(kid_str.len())
            .position(|w| w == kid_str.as_bytes())
            .expect("kid in encoded stream");
        assert!(pos >= 1, "kid must be prefixed by a marker byte");
        let marker = bytes[pos - 1];
        // Either `fixstr` (0xa0..0xc0 with 5-bit length) or
        // `str 8` (0xd9 + 1-byte length). Both are valid str
        // family markers; the verifier must reject a `bin` /
        // array marker.
        assert!(
            (0xa0..0xc0).contains(&marker) || marker == 0xd9,
            "kid must be MessagePack str family, got marker {marker:#x}"
        );
    }

    #[test]
    fn signature_encodes_as_msgpack_bin() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        let bytes = rmp_serde::to_vec_named(&bundle).expect("encode");
        // The 64-byte signature appears verbatim once in the
        // stream. The Go `[]byte` map value is encoded as `bin
        // 8` (0xc4 + 1-byte length) for ≤255-byte payloads.
        let pos = bytes
            .windows(bundle.signature.bytes.len())
            .position(|w| w == bundle.signature.bytes)
            .expect("signature bytes in encoded stream");
        assert!(
            pos >= 2,
            "signature must be prefixed by bin marker + length"
        );
        assert_eq!(
            bytes[pos - 2],
            0xc4,
            "signature must be MessagePack bin family, got marker {:#x}",
            bytes[pos - 2]
        );
        assert_eq!(
            bytes[pos - 1],
            64,
            "signature bin length must be 64, got {}",
            bytes[pos - 1]
        );
    }

    /// Regression: deserialisation must reject a signature
    /// whose length is not exactly 64 bytes, so a malformed or
    /// truncated signature cannot quietly turn into a different
    /// type after the round-trip.
    #[test]
    fn signature_field_rejects_wrong_length() {
        let (signing, key_id, _verify) = fixture_keypair();
        let bundle = signed_bundle(BundleTarget::Edge, 1, &signing, key_id);
        let good = rmp_serde::to_vec_named(&bundle).expect("encode");
        let sig = bundle.signature.bytes;
        // Surgically rewrite the 64-byte signature into a
        // 32-byte one with a fresh `bin 8` length prefix. This
        // keeps the rest of the map intact so any error must
        // come from the signature length check.
        let sig_pos = good
            .windows(sig.len())
            .position(|w| w == sig)
            .expect("sig in encoded stream");
        let mut bad = Vec::with_capacity(good.len() - 32);
        bad.extend_from_slice(&good[..sig_pos - 1]); // up to length byte
        bad.push(32); // new bin length
        bad.extend_from_slice(&sig[..32]);
        bad.extend_from_slice(&good[sig_pos + 64..]);
        let err = rmp_serde::from_slice::<PolicyBundle>(&bad)
            .expect_err("32-byte signature must be rejected");
        let msg = err.to_string();
        assert!(
            msg.contains("ed25519 signature must be 64 bytes"),
            "error must call out the length mismatch, got: {msg}"
        );
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

    /// Decoding the claims fails clean when the body is empty
    /// or junk. The verifier wrapper passes this through as
    /// `BodySchema` so observability sees a stable code.
    #[test]
    fn claims_from_body_rejects_garbage() {
        let err = PolicyBundleClaims::from_body(b"not msgpack").expect_err("garbage rejected");
        assert!(matches!(err, VerificationError::BodySchema(_)));
        assert_eq!(err.code(), ErrorCode::WireSchema);
    }

    /// Regression: the Go compiler's `bundlePayload` carries
    /// rule and steering tables (`r`, `st`) that `sng-core`'s
    /// `PolicyBundleClaims` intentionally does NOT model — the
    /// typed enforcement engine in `sng-policy-eval` (PR 4)
    /// owns those shapes. `rmp-serde`'s named-map decode skips
    /// keys not present on the target struct by default, so this
    /// works today; the test pins that behaviour so a future
    /// `#[serde(deny_unknown_fields)]` slip-up would surface as
    /// a hard test failure rather than as silent claim-decode
    /// failures in the field.
    ///
    /// Build a body that includes a populated `r` map and a
    /// populated `st` map (matching what the Go compiler emits
    /// for a non-trivial graph) and confirm the metadata claims
    /// still decode byte-stable.
    #[test]
    fn claims_decode_ignores_rules_and_steering_fields() {
        // Take a real signed-bundle body (which already has the
        // shape `sng-policy-eval` decodes against), surgically
        // splice in extra `r` and `st` map keys via `rmpv`, then
        // confirm `PolicyBundleClaims::from_body` still decodes
        // the metadata cleanly. Building the body via the same
        // signer the Go side uses pins UUID / DateTime wire shapes
        // to what `PolicyBundleClaims` actually expects, instead
        // of hand-coding them (and getting the encoding wrong).
        let (signing, key_id, _verify) = fixture_keypair();
        let original = signed_bundle(BundleTarget::Edge, 42, &signing, key_id);
        let mut map_value: rmpv::Value =
            rmp_serde::from_slice(&original.body).expect("decode body as Value");
        let rmpv::Value::Map(ref mut entries) = map_value else {
            panic!("body must decode as a msgpack map");
        };
        // Inject the two fields `sng-core` intentionally ignores
        // (`r` = rules table, `st` = steering snapshot). The Go
        // compiler emits both for any non-trivial graph; the
        // claims decoder must skip them silently.
        entries.push((
            rmpv::Value::String("r".into()),
            rmpv::Value::Map(vec![
                (
                    rmpv::Value::String("rule-1".into()),
                    rmpv::Value::String("inspect".into()),
                ),
                (
                    rmpv::Value::String("rule-2".into()),
                    rmpv::Value::String("deny".into()),
                ),
            ]),
        ));
        entries.push((
            rmpv::Value::String("st".into()),
            rmpv::Value::Map(vec![(
                rmpv::Value::String("trusted_direct".into()),
                rmpv::Value::Integer(1u8.into()),
            )]),
        ));
        let mut augmented = Vec::new();
        rmpv::encode::write_value(&mut augmented, &map_value).expect("encode augmented body");
        let claims = PolicyBundleClaims::from_body(&augmented).expect("decode despite r / st keys");
        assert_eq!(claims.target, BundleTarget::Edge);
        assert_eq!(claims.graph_version, 42);
    }
}

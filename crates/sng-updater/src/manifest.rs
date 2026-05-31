//! Update manifest model.
//!
//! An *update manifest* is the operator-signed promise that the
//! bytes published at a particular URL constitute a valid release
//! of a particular `sng-edge` / `sng-agent` build for a
//! particular target. It carries everything the updater needs to
//! decide whether to install the bytes *before* the bytes
//! themselves are fetched (target match, version monotonicity,
//! signing-key trust) and everything needed to verify the bytes
//! *as they arrive* (the SHA-256 hash, the declared size).
//!
//! Two shapes are exposed:
//!
//! * [`UpdateManifest`] — the **plaintext** payload the operator
//!   composes and the updater consumes after verification. This
//!   is the type policy code reasons about.
//! * [`SignedManifest`] — the **wire** envelope: the MessagePack-
//!   encoded body bytes (signed under the same byte stream the
//!   Go side signs at release time), the Ed25519 signature over
//!   those bytes, and the signing-key id used to look up the
//!   trusted public key. This is the type the network layer
//!   produces and the verifier consumes.
//!
//! The split mirrors `sng_core::policy::PolicyBundle` /
//! `PolicyBundleClaims`: the body is signed once, the claims are
//! decoded from the same signed bytes, every field is
//! transitively authenticated through the body signature, and
//! tampering with any claim invalidates the envelope. We re-use
//! `sng_core::policy::BundleSignature`'s 64-byte shape (and the
//! same serde adapter) because the wire bytes ARE the same shape:
//! the Go-side release service signs both kinds of artifact with
//! `crypto/ed25519.Sign(priv, body)` over a MessagePack body.

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ed25519_dalek::{SIGNATURE_LENGTH, Signature};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use url::Url;

/// Maximum length of a signing-key identifier on the wire.
/// Mirrors `PolicySigningKeyId`'s 64-char cap so dashboards can
/// flow either id through the same column-width-bounded label.
pub const MAX_SIGNING_KEY_ID_LEN: usize = 64;

/// Update target — which appliance class this manifest publishes
/// for. The updater rejects a manifest whose target does not
/// match the running binary's compiled-in target up front, before
/// any download.
///
/// Serialised as a lowercase string for symmetry with the Go side
/// (`internal/release/manifest.go::Target`). Adding a new target
/// is a breaking wire change that must be coordinated with the
/// control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateTarget {
    /// Edge appliance — `sng-edge` binary on the per-tenant VM.
    Edge,
    /// Endpoint client — `sng-agent` binary on user devices.
    Agent,
    /// Cloud-PoP appliance — `sng-edge` flavoured for the
    /// cloud-delivered SWG / DNS / ZTNA path.
    CloudPop,
}

impl fmt::Display for UpdateTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Edge => "edge",
            Self::Agent => "agent",
            Self::CloudPop => "cloud_pop",
        })
    }
}

/// Release channel — `stable`, `beta`, `nightly`. Operators may
/// pin a target to a single channel; the updater rejects a
/// manifest whose channel does not match the pin. Surfaced on
/// telemetry so the control plane can correlate per-channel
/// roll-out posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    /// Production-grade release; default for all targets.
    Stable,
    /// Pre-production canary channel; operators must opt in.
    Beta,
    /// Continuous-integration channel; operators must opt in
    /// and accept that breakage is the channel's purpose.
    Nightly,
}

impl fmt::Display for ReleaseChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
            Self::Nightly => "nightly",
        })
    }
}

/// Semantic version triple (major, minor, patch). We do NOT
/// re-use `semver::Version` from the third-party crate because
/// the wire shape we need is exactly three `u32`s with no pre-
/// release or build-metadata noise — pre-release tags belong on
/// the [`ReleaseChannel`], not on the version triple, and we
/// want byte-stable Ord on the wire that the Go side can produce
/// without pulling in a parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ImageVersion {
    /// Major version. Increments on breaking change.
    pub major: u32,
    /// Minor version. Increments on additive change.
    pub minor: u32,
    /// Patch version. Increments on backwards-compatible fix.
    pub patch: u32,
}

impl ImageVersion {
    /// Construct an explicit version triple.
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Returns `true` iff `self` is strictly newer than `other`.
    /// Convenience wrapper around `Ord` — used in the version-
    /// monotonicity check on the verifier hot path so the
    /// intent reads naturally at the call site.
    #[must_use]
    pub fn is_strictly_newer_than(self, other: Self) -> bool {
        self > other
    }
}

impl fmt::Display for ImageVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// SHA-256 hash of the published image bytes, exactly 32 bytes.
///
/// The wire form is the raw 32-byte digest emitted by Go's
/// `crypto/sha256.Sum256` and accepted by Rust's
/// `sha2::Sha256::finalize`. We carry it as a fixed-length array
/// (not a `Vec<u8>`) so the size-validation invariant is in the
/// type system — the deserializer rejects anything that does not
/// fit.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ImageHash {
    /// Raw 32-byte SHA-256 digest.
    pub bytes: [u8; 32],
}

impl ImageHash {
    /// Construct from raw bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    /// Render as lowercase hex — the wire form on the
    /// human-readable error path (e.g. on
    /// [`crate::error::UpdaterError::ImageHashMismatch`]).
    #[must_use]
    pub fn as_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parse from a lowercase or uppercase hex string. Useful
    /// for ingesting operator-typed hashes in CLI tooling and
    /// in test fixtures.
    pub fn from_hex(s: &str) -> Result<Self, ImageHashParseError> {
        let bytes = hex::decode(s).map_err(|_| ImageHashParseError::InvalidHex)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| ImageHashParseError::InvalidLength(v.len()))?;
        Ok(Self { bytes: arr })
    }
}

impl fmt::Debug for ImageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ImageHash({})", self.as_hex())
    }
}

impl fmt::Display for ImageHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}

impl Serialize for ImageHash {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        // MessagePack: raw 32-byte string (bin 8 family),
        // matching `[]byte` emitted by `vmihailenco/msgpack/v5`
        // on the Go side. JSON: lowercase hex string for
        // operator-readable surfaces (CLI, audit log).
        if s.is_human_readable() {
            s.serialize_str(&self.as_hex())
        } else {
            s.serialize_bytes(&self.bytes)
        }
    }
}

impl<'de> Deserialize<'de> for ImageHash {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl serde::de::Visitor<'_> for Visitor {
            type Value = ImageHash;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("32-byte SHA-256 digest as 32 raw bytes or 64-char lowercase hex")
            }

            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<ImageHash, E> {
                let arr: [u8; 32] = v.try_into().map_err(|_| {
                    serde::de::Error::custom(format!(
                        "sha256 digest must be 32 bytes, got {}",
                        v.len()
                    ))
                })?;
                Ok(ImageHash { bytes: arr })
            }

            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<ImageHash, E> {
                self.visit_bytes(&v)
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ImageHash, E> {
                ImageHash::from_hex(v).map_err(|e| serde::de::Error::custom(format!("{e}")))
            }
        }
        d.deserialize_any(Visitor)
    }
}

/// Parse failure for [`ImageHash::from_hex`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImageHashParseError {
    /// The input string was not valid hex.
    #[error("not a hex string")]
    InvalidHex,
    /// The decoded byte string was the wrong length (must be
    /// exactly 32 bytes).
    #[error("decoded length {0} is not 32 bytes")]
    InvalidLength(usize),
}

/// Identifier for the Ed25519 signing key that signed a
/// [`SignedManifest`]. Mirrors `PolicySigningKeyId` from
/// `sng-core`: an opaque non-empty string of bounded length, with
/// a reserved sentinel for the in-process compiler tests that
/// production receivers must reject.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ManifestSigningKeyId(String);

impl ManifestSigningKeyId {
    /// The reserved sentinel id used by the in-process release
    /// signer in compiler tests. Production receivers MUST
    /// reject manifests carrying this id — there is no
    /// operator-provisioned key for it.
    pub const EPHEMERAL: &'static str = "ephemeral";

    /// Construct a key id from a string. Returns `Err` for empty
    /// strings, over-length strings, or the ephemeral sentinel.
    /// The verifier's `add_key` separately enforces the
    /// ephemeral rejection at insertion time — checking on both
    /// sides means neither a buggy caller nor a tampered
    /// manifest can sneak it through.
    pub fn new(id: impl Into<String>) -> Result<Self, ManifestSigningKeyIdError> {
        let id: String = id.into();
        if id.is_empty() {
            return Err(ManifestSigningKeyIdError::Empty);
        }
        if id.len() > MAX_SIGNING_KEY_ID_LEN {
            return Err(ManifestSigningKeyIdError::TooLong {
                len: id.len(),
                max: MAX_SIGNING_KEY_ID_LEN,
            });
        }
        if id == Self::EPHEMERAL {
            return Err(ManifestSigningKeyIdError::Ephemeral);
        }
        Ok(Self(id))
    }

    /// The reserved ephemeral sentinel — only used in unit /
    /// integration tests, never accepted by the verifier.
    #[must_use]
    pub fn ephemeral() -> Self {
        Self(Self::EPHEMERAL.to_owned())
    }

    /// `true` when this id equals the reserved sentinel. The
    /// verifier short-circuits on this before doing any key
    /// lookup.
    #[must_use]
    pub fn is_ephemeral(&self) -> bool {
        self.0 == Self::EPHEMERAL
    }

    /// Borrow the underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ManifestSigningKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ManifestSigningKeyId({})", self.0)
    }
}

impl fmt::Display for ManifestSigningKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Construction failures for [`ManifestSigningKeyId::new`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestSigningKeyIdError {
    /// Empty string supplied.
    #[error("signing-key id must not be empty")]
    Empty,
    /// Over-length string supplied.
    #[error("signing-key id is {len} bytes long, exceeds maximum {max}")]
    TooLong {
        /// Observed length.
        len: usize,
        /// Maximum permitted length.
        max: usize,
    },
    /// Caller tried to construct the reserved ephemeral
    /// sentinel via `new`.
    #[error(
        "signing-key id collides with the reserved ephemeral sentinel; use `ephemeral()` if you really mean the sentinel"
    )]
    Ephemeral,
}

/// Ed25519 signature over the manifest body bytes.
///
/// Shape and serde adapter are intentionally identical to
/// `sng_core::policy::BundleSignature` — the same 64-byte wire
/// shape, the same MessagePack `bin` family, and the same
/// `signature::Verifier` semantics on the receiver side. We do
/// not re-export the core type because a manifest signature and
/// a bundle signature are domain-distinct concepts that we
/// deliberately do not want operators to confuse on telemetry —
/// a `ManifestSignature` in a log line should never be
/// interpreted as a bundle signature.
#[derive(Clone, PartialEq, Eq)]
pub struct ManifestSignature {
    /// Raw 64-byte Ed25519 signature.
    pub bytes: [u8; SIGNATURE_LENGTH],
}

impl ManifestSignature {
    /// Construct from raw signature bytes.
    #[must_use]
    pub const fn new(bytes: [u8; SIGNATURE_LENGTH]) -> Self {
        Self { bytes }
    }

    /// Convert to an ed25519-dalek `Signature` for verification.
    /// Pure type conversion; no validation happens here.
    #[must_use]
    pub fn to_signature(&self) -> Signature {
        Signature::from_bytes(&self.bytes)
    }
}

impl fmt::Debug for ManifestSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b64 = base64::engine::general_purpose::STANDARD.encode(self.bytes);
        if b64.len() > 16 {
            write!(
                f,
                "ManifestSignature({}…{})",
                &b64[..8],
                &b64[b64.len() - 4..]
            )
        } else {
            write!(f, "ManifestSignature({b64})")
        }
    }
}

impl Serialize for ManifestSignature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(&self.bytes)
    }
}

impl<'de> Deserialize<'de> for ManifestSignature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let bytes = <serde_bytes::ByteBuf>::deserialize(d)?;
        let bytes = bytes.into_vec();
        let len = bytes.len();
        let arr: [u8; SIGNATURE_LENGTH] = bytes.try_into().map_err(|_| {
            serde::de::Error::custom(format!(
                "ed25519 signature must be {SIGNATURE_LENGTH} bytes, got {len}"
            ))
        })?;
        Ok(Self { bytes: arr })
    }
}

/// The plaintext manifest payload.
///
/// This is what the updater reasons about after the envelope
/// signature has been verified. The fields are MessagePack-
/// encoded with `to_vec_named` (named map; matches the Go side's
/// default `vmihailenco/msgpack/v5` map shape) so a new field can
/// be added on either side without breaking the other.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateManifest {
    /// Schema version of this manifest envelope. Bumped on any
    /// wire-incompatible change; the verifier rejects manifests
    /// carrying an unknown schema version up front.
    #[serde(rename = "v")]
    pub schema_version: u8,
    /// Appliance class this release targets.
    #[serde(rename = "t")]
    pub target: UpdateTarget,
    /// Release channel — operators can pin a target to a
    /// specific channel.
    #[serde(rename = "ch")]
    pub channel: ReleaseChannel,
    /// Semantic version triple of the release.
    #[serde(rename = "ver")]
    pub version: ImageVersion,
    /// SHA-256 of the bytes served at [`Self::image_url`]. Used
    /// by [`crate::download::StreamingHasher`] to authenticate
    /// the image as it is fetched.
    #[serde(rename = "sha")]
    pub image_sha256: ImageHash,
    /// Declared size of the image, in bytes. The download
    /// adapter uses this as a hard upper bound on bytes read
    /// so a misbehaving upstream cannot exhaust local disk
    /// before the hash check has a chance to run.
    #[serde(rename = "sz")]
    pub image_size_bytes: u64,
    /// HTTPS URL from which to fetch the image bytes. The
    /// updater does not itself perform DNS resolution; the
    /// [`crate::download::ImageDownloader`] trait that consumes
    /// the URL is the layer that talks to the network.
    #[serde(rename = "u", with = "url_serde")]
    pub image_url: Url,
    /// Human-readable release notes — surfaced to operators in
    /// the changelog UI, never used by enforcement code.
    /// Trimmed (whitespace at start / end stripped) by the
    /// composer before signing, so signature verification is
    /// stable across cosmetic edits.
    #[serde(rename = "rn")]
    pub release_notes: String,
    /// Timestamp the manifest was signed at. Carried for
    /// telemetry only; the verifier does not gate on it (a
    /// future enhancement could enforce a maximum age, but
    /// downgrades are already prevented through the version
    /// monotonicity check).
    #[serde(rename = "ts")]
    pub signed_at: DateTime<Utc>,
}

/// Wire envelope: the signed bytes + the signature over those
/// bytes + the key id used to look up the trusted public key.
///
/// The [`Self::body`] field is the MessagePack-encoded
/// [`UpdateManifest`] payload — encoded exactly once at release
/// time and signed once. The receiver decodes it back into an
/// `UpdateManifest` after verifying the signature.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedManifest {
    /// MessagePack-encoded [`UpdateManifest`] bytes — the bytes
    /// that were signed.
    #[serde(rename = "body", with = "serde_bytes")]
    pub body: Vec<u8>,
    /// Ed25519 signature over [`Self::body`].
    #[serde(rename = "sig")]
    pub signature: ManifestSignature,
    /// Identifier of the Ed25519 key that produced the
    /// signature — looked up against the trust store at
    /// verification time.
    #[serde(rename = "kid")]
    pub signing_key_id: ManifestSigningKeyId,
}

impl SignedManifest {
    /// Compose a signed envelope by encoding the manifest as the
    /// canonical body shape and copying the signature + key id
    /// in. The body is encoded with `to_vec_named` so the
    /// receiver, the Go side, and the in-process round-trip
    /// tests all agree on byte-for-byte representation.
    ///
    /// This is the function the in-process test fixtures and the
    /// `sng-edge` release-tooling shim go through; the wire
    /// shape (Ed25519 signature + msgpack body) is constructed
    /// in one place so the byte-stability invariants live in
    /// one place.
    pub fn compose(
        manifest: &UpdateManifest,
        signature: ManifestSignature,
        signing_key_id: ManifestSigningKeyId,
    ) -> Result<Self, ManifestEncodeError> {
        let body = rmp_serde::to_vec_named(manifest)
            .map_err(|e| ManifestEncodeError::Body(format!("{e}")))?;
        Ok(Self {
            body,
            signature,
            signing_key_id,
        })
    }
}

/// Failure on the encode side. Decode failures are surfaced as
/// [`crate::error::UpdaterError::BodyDecode`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestEncodeError {
    /// MessagePack encoding of the body failed. Effectively
    /// only possible on a serde adapter bug, not on real data —
    /// surfaced for completeness so test code can assert on it.
    #[error("encode body: {0}")]
    Body(String),
}

/// Serde adapter that lets us serialise `Url` through the
/// MessagePack pipeline. `url::Url` has its own serde adapter
/// behind a feature but it serialises to a plain string, which
/// is exactly what we want — we just need it as an adapter
/// because `#[serde(with = ...)]` does not pick up the
/// blanket impl on inner types.
mod url_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use url::Url;

    pub(super) fn serialize<S: Serializer>(u: &Url, s: S) -> Result<S::Ok, S::Error> {
        u.as_str().serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Url, D::Error> {
        let raw = String::deserialize(d)?;
        Url::parse(&raw).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn fixture_manifest(target: UpdateTarget, version: ImageVersion) -> UpdateManifest {
        UpdateManifest {
            schema_version: 1,
            target,
            channel: ReleaseChannel::Stable,
            version,
            image_sha256: ImageHash::new([0x11_u8; 32]),
            image_size_bytes: 12_345,
            image_url: Url::parse("https://releases.example.invalid/edge-1.2.3.tar.gz")
                .expect("valid url fixture"),
            release_notes: "fixture release".into(),
            signed_at: chrono::DateTime::<Utc>::from_timestamp(1_700_000_000, 0)
                .expect("epoch fits"),
        }
    }

    #[test]
    fn image_version_orders_lexicographically() {
        // Lexicographic on (major, minor, patch). This is the
        // contract the monotonicity check depends on — a patch
        // bump on a lower minor is still strictly newer in
        // semver but NOT in this ordering, which is intentional:
        // out-of-order patches on stale minors are exactly what
        // the downgrade-prevention check is supposed to catch.
        assert!(ImageVersion::new(1, 0, 0) > ImageVersion::new(0, 99, 99));
        assert!(ImageVersion::new(1, 2, 3) > ImageVersion::new(1, 2, 2));
        assert!(ImageVersion::new(1, 2, 3) > ImageVersion::new(1, 1, 9));
        assert_eq!(ImageVersion::new(1, 2, 3), ImageVersion::new(1, 2, 3));
        assert!(!ImageVersion::new(1, 2, 3).is_strictly_newer_than(ImageVersion::new(1, 2, 3)));
    }

    #[test]
    fn image_version_displays_as_dotted_triple() {
        assert_eq!(ImageVersion::new(2, 3, 4).to_string(), "2.3.4");
    }

    #[test]
    fn image_hash_round_trips_through_hex() {
        let raw = [0xAB_u8; 32];
        let h = ImageHash::new(raw);
        let parsed = ImageHash::from_hex(&h.as_hex()).expect("round-trip");
        assert_eq!(h, parsed);
    }

    #[test]
    fn image_hash_rejects_wrong_length_hex() {
        let err = ImageHash::from_hex("ab").expect_err("short hex");
        assert_eq!(err, ImageHashParseError::InvalidLength(1));
    }

    #[test]
    fn image_hash_rejects_non_hex_string() {
        let err = ImageHash::from_hex("not hex!").expect_err("bad hex");
        assert_eq!(err, ImageHashParseError::InvalidHex);
    }

    #[test]
    fn image_hash_msgpack_round_trips_as_bytes() {
        // Wire shape on the MessagePack pipeline is a 32-byte
        // `bin` value (matches `[]byte` on the Go side). The
        // round-trip must be byte-identical so the signature
        // verification on the envelope, which signs the encoded
        // bytes, stays stable.
        let h = ImageHash::new([0x42_u8; 32]);
        let bytes = rmp_serde::to_vec(&h).expect("encode");
        let h2: ImageHash = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(h, h2);
    }

    #[test]
    fn image_hash_json_round_trips_as_hex() {
        // JSON is the operator-readable surface (audit log,
        // CLI), so the hex shape is what we want there. Round
        // trip must also be stable.
        let h = ImageHash::new([0x99_u8; 32]);
        let json = serde_json::to_string(&h).expect("encode");
        let h2: ImageHash = serde_json::from_str(&json).expect("decode");
        assert_eq!(h, h2);
        assert!(json.contains(&"99".repeat(32)));
    }

    #[test]
    fn signing_key_id_rejects_empty() {
        let err = ManifestSigningKeyId::new("").expect_err("empty");
        assert_eq!(err, ManifestSigningKeyIdError::Empty);
    }

    #[test]
    fn signing_key_id_rejects_too_long() {
        let id = "x".repeat(MAX_SIGNING_KEY_ID_LEN + 1);
        let err = ManifestSigningKeyId::new(&id).expect_err("too long");
        assert_eq!(
            err,
            ManifestSigningKeyIdError::TooLong {
                len: MAX_SIGNING_KEY_ID_LEN + 1,
                max: MAX_SIGNING_KEY_ID_LEN
            }
        );
    }

    #[test]
    fn signing_key_id_rejects_ephemeral_sentinel_via_new() {
        // `new()` MUST refuse the sentinel so a buggy caller
        // cannot construct a "trusted" id that points at no
        // real key. `ephemeral()` is the only path that
        // produces a sentinel-shaped id, and the verifier
        // refuses it at add-key and at verify-time.
        let err = ManifestSigningKeyId::new(ManifestSigningKeyId::EPHEMERAL).expect_err("eph");
        assert_eq!(err, ManifestSigningKeyIdError::Ephemeral);
        let eph = ManifestSigningKeyId::ephemeral();
        assert!(eph.is_ephemeral());
    }

    #[test]
    fn manifest_signature_msgpack_round_trips_as_64_bytes() {
        let sig = ManifestSignature::new([0x7A_u8; SIGNATURE_LENGTH]);
        let bytes = rmp_serde::to_vec(&sig).expect("encode");
        let sig2: ManifestSignature = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(sig, sig2);
    }

    #[test]
    fn manifest_signature_debug_redacts_middle() {
        // The debug shape elides the middle of the base64
        // signature so trace logs don't fill with 88-char
        // signatures every line. Pure cosmetics — but
        // operators reading logs at 3am do appreciate it.
        let sig = ManifestSignature::new([0xAA_u8; SIGNATURE_LENGTH]);
        let dbg = format!("{sig:?}");
        assert!(dbg.contains('…'));
    }

    #[test]
    fn signed_manifest_compose_round_trips_through_body() {
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(1, 0, 0));
        let sig = ManifestSignature::new([0x01_u8; SIGNATURE_LENGTH]);
        let kid = ManifestSigningKeyId::new("k1").expect("valid id");
        let signed = SignedManifest::compose(&mfst, sig, kid.clone()).expect("compose");

        let decoded: UpdateManifest = rmp_serde::from_slice(&signed.body).expect("decode");
        assert_eq!(decoded, mfst);
        assert_eq!(signed.signing_key_id, kid);
    }

    #[test]
    fn update_target_display_is_snake_case() {
        assert_eq!(UpdateTarget::Edge.to_string(), "edge");
        assert_eq!(UpdateTarget::Agent.to_string(), "agent");
        assert_eq!(UpdateTarget::CloudPop.to_string(), "cloud_pop");
    }

    #[test]
    fn release_channel_serialises_as_snake_case() {
        // The JSON shape is the operator-readable surface
        // (audit log, CLI). All three variants must round-trip
        // through their lowercase wire spelling.
        for (ch, wire) in [
            (ReleaseChannel::Stable, "\"stable\""),
            (ReleaseChannel::Beta, "\"beta\""),
            (ReleaseChannel::Nightly, "\"nightly\""),
        ] {
            let j = serde_json::to_string(&ch).expect("encode channel");
            assert_eq!(j, wire);
            let back: ReleaseChannel = serde_json::from_str(&j).expect("decode channel");
            assert_eq!(back, ch);
        }
    }

    #[test]
    fn update_manifest_round_trips_through_msgpack() {
        // The wire shape is what the signature is computed over,
        // so a round-trip break would break verification. The
        // verifier-side test re-uses this fixture.
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 1, 0));
        let bytes = rmp_serde::to_vec_named(&mfst).expect("encode");
        let back: UpdateManifest = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(mfst, back);
    }
}

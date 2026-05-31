//! Manifest verification.
//!
//! [`ManifestVerifier`] is the trust-store-backed checker that
//! decides whether a [`SignedManifest`] is admissible: the
//! Ed25519 body signature must validate against an operator-
//! provisioned public key, the decoded manifest's schema version
//! must be one we know, the target must match the running
//! binary, and the version must be strictly newer than the
//! committed image.
//!
//! The verifier is intentionally **pure**: no I/O, no clock
//! reads, no global state. The orchestrator threads the
//! current-version pin in on every call so we can drive every
//! decision point from a unit test without touching the disk.

use crate::error::UpdaterError;
use crate::manifest::{
    ImageVersion, ManifestSigningKeyId, SignedManifest, UpdateManifest, UpdateTarget,
};
use ed25519_dalek::{PUBLIC_KEY_LENGTH, Verifier, VerifyingKey};
use std::collections::HashMap;
use thiserror::Error;
use tracing::warn;

/// Maximum manifest schema version the engine knows how to
/// handle. Bumping this is a coordinated change with the
/// release pipeline. The verifier rejects manifests with a
/// higher version with a [`UpdaterError::BodyDecode`] so the
/// dashboard alert points at "release pipeline got ahead of
/// the agent fleet", which is the right operator response.
pub const MAX_KNOWN_MANIFEST_SCHEMA_VERSION: u8 = 1;

/// Decision returned by the version monotonicity check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionMonotonicity {
    /// `manifest_version > current_version` — the manifest is
    /// strictly newer and the install may proceed.
    Newer,
    /// `manifest_version == current_version` — the manifest is
    /// re-publishing the currently-committed image. Treated as a
    /// stale manifest because the engine has nothing to do.
    SameAsCurrent,
    /// `manifest_version < current_version` — the manifest is a
    /// downgrade. Rejected up front.
    Older,
}

impl VersionMonotonicity {
    /// Returns true when the install may proceed.
    #[must_use]
    pub fn is_admissible(self) -> bool {
        matches!(self, Self::Newer)
    }
}

/// Trust-store-backed manifest verifier.
///
/// Owns a `HashMap<ManifestSigningKeyId, VerifyingKey>` populated
/// at agent enrolment time. Reads happen on the hot install path
/// and are read-only; the orchestrator hot-swaps the entire
/// verifier under `ArcSwap` rather than locking individual keys.
#[derive(Clone, Debug, Default)]
pub struct ManifestVerifier {
    keys: HashMap<ManifestSigningKeyId, VerifyingKey>,
    /// Compiled-in expected target. Set at engine construction
    /// and never mutated — a target rebuild produces a new
    /// binary with a different value.
    expected_target: Option<UpdateTarget>,
}

impl ManifestVerifier {
    /// Construct an empty verifier with no expected target.
    /// The orchestrator usually calls [`Self::with_target`]
    /// because every binary that consumes manifests is built
    /// for exactly one target.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a verifier pinned to the given target.
    #[must_use]
    pub fn with_target(expected_target: UpdateTarget) -> Self {
        Self {
            keys: HashMap::new(),
            expected_target: Some(expected_target),
        }
    }

    /// Add (or replace) a trusted Ed25519 public key.
    ///
    /// The caller MUST have validated the id shape via
    /// [`ManifestSigningKeyId::new`]; we additionally refuse
    /// the ephemeral sentinel here so an ill-formed update to
    /// the trust store can never make the ephemeral id
    /// trusted by accident.
    pub fn add_key(
        &mut self,
        id: ManifestSigningKeyId,
        key_bytes: &[u8; PUBLIC_KEY_LENGTH],
    ) -> Result<(), AddManifestKeyError> {
        if id.is_ephemeral() {
            return Err(AddManifestKeyError::EphemeralSigningKey);
        }
        let key = VerifyingKey::from_bytes(key_bytes).map_err(AddManifestKeyError::InvalidKey)?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Remove a key by id. Returns true iff a key was removed.
    /// Used at trust-store rotation time.
    pub fn remove_key(&mut self, id: &ManifestSigningKeyId) -> bool {
        self.keys.remove(id).is_some()
    }

    /// Returns true iff the trust store contains a key with
    /// the given id.
    #[must_use]
    pub fn has_key(&self, id: &ManifestSigningKeyId) -> bool {
        self.keys.contains_key(id)
    }

    /// Number of trusted keys currently installed.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Expected target this verifier was constructed for.
    #[must_use]
    pub fn expected_target(&self) -> Option<UpdateTarget> {
        self.expected_target
    }

    /// Verify a signed manifest envelope end-to-end.
    ///
    /// Steps, in order:
    ///
    /// 1. Reject the ephemeral signing-key sentinel up front.
    /// 2. Look up the signing key in the trust store.
    /// 3. Verify the Ed25519 signature over the body bytes.
    /// 4. Decode the body into an [`UpdateManifest`].
    /// 5. Check that the manifest's `schema_version` is one
    ///    the engine knows.
    /// 6. Check the manifest's target against the verifier's
    ///    expected target (if one is pinned).
    /// 7. Check version monotonicity against the supplied
    ///    `current_version` pin.
    ///
    /// Returns the decoded [`UpdateManifest`] on success — the
    /// orchestrator hands it to the downloader. On any failure,
    /// the previous image stays committed.
    ///
    /// `current_version` is the version of the currently-
    /// committed image; pass `None` on the cold-start path
    /// where there is nothing to compare against.
    pub fn verify(
        &self,
        envelope: &SignedManifest,
        current_version: Option<ImageVersion>,
    ) -> Result<UpdateManifest, UpdaterError> {
        if envelope.signing_key_id.is_ephemeral() {
            warn!(
                signing_key_id = %envelope.signing_key_id,
                "manifest carries ephemeral signing-key sentinel; refusing"
            );
            return Err(UpdaterError::EphemeralSigningKey);
        }
        let key = self
            .keys
            .get(&envelope.signing_key_id)
            .ok_or_else(|| UpdaterError::UnknownSigningKey(envelope.signing_key_id.clone()))?;
        let sig = envelope.signature.to_signature();
        key.verify(&envelope.body, &sig).map_err(|e| {
            warn!(error = %e, "manifest signature verification failed");
            UpdaterError::SignatureInvalid
        })?;
        let manifest: UpdateManifest = rmp_serde::from_slice(&envelope.body)
            .map_err(|e| UpdaterError::BodyDecode(format!("decode manifest: {e}")))?;

        if manifest.schema_version == 0
            || manifest.schema_version > MAX_KNOWN_MANIFEST_SCHEMA_VERSION
        {
            return Err(UpdaterError::BodyDecode(format!(
                "unsupported schema_version {}, agent supports 1..={}",
                manifest.schema_version, MAX_KNOWN_MANIFEST_SCHEMA_VERSION
            )));
        }
        if let Some(expected) = self.expected_target
            && manifest.target != expected
        {
            return Err(UpdaterError::TargetMismatch {
                actual: manifest.target,
                expected,
            });
        }
        if let Some(current) = current_version {
            match Self::compare_versions(manifest.version, current) {
                VersionMonotonicity::Newer => {}
                VersionMonotonicity::SameAsCurrent | VersionMonotonicity::Older => {
                    return Err(UpdaterError::ManifestStale {
                        found: manifest.version,
                        current,
                    });
                }
            }
        }
        Ok(manifest)
    }

    /// Pure version-comparison helper, exposed for tests and
    /// for callers that want to pre-screen a candidate version
    /// without re-doing the Ed25519 verification.
    #[must_use]
    pub fn compare_versions(candidate: ImageVersion, current: ImageVersion) -> VersionMonotonicity {
        match candidate.cmp(&current) {
            std::cmp::Ordering::Greater => VersionMonotonicity::Newer,
            std::cmp::Ordering::Equal => VersionMonotonicity::SameAsCurrent,
            std::cmp::Ordering::Less => VersionMonotonicity::Older,
        }
    }
}

/// Error returned by [`ManifestVerifier::add_key`].
#[derive(Debug, Error)]
pub enum AddManifestKeyError {
    /// Caller tried to install a key under the ephemeral
    /// sentinel id.
    #[error("cannot install a trusted key under the ephemeral signing-key id")]
    EphemeralSigningKey,
    /// The supplied bytes were not a valid Ed25519 point.
    #[error("invalid ed25519 public key: {0}")]
    InvalidKey(#[source] ed25519_dalek::SignatureError),
}

/// Verification failure shapes that the orchestrator wants to
/// surface for telemetry without dropping the structured
/// information. Mirrors `sng_core::policy::VerificationError`'s
/// shape so dashboards can render either with the same
/// breakdown.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestVerifyError {
    /// Body would not decode after signature passed. Either the
    /// manifest is from a future schema or the bytes were
    /// truncated below the minimum size MessagePack requires.
    #[error("manifest body decode: {0}")]
    BodyDecode(String),
    /// Manifest carries the ephemeral sentinel.
    #[error("manifest carries ephemeral signing-key sentinel")]
    EphemeralSigningKey,
    /// Signing key id is not in the trust store.
    #[error("signing key {0} is not in the trust store")]
    UnknownSigningKey(ManifestSigningKeyId),
    /// Ed25519 signature did not verify.
    #[error("signature verification failed")]
    SignatureInvalid,
    /// Decoded manifest's target does not match the verifier's
    /// pinned target.
    #[error("manifest target {actual} does not match expected {expected}")]
    TargetMismatch {
        /// Target on the manifest.
        actual: UpdateTarget,
        /// Target the verifier was constructed for.
        expected: UpdateTarget,
    },
    /// Decoded manifest's version was not strictly newer than
    /// the committed version pin.
    #[error("manifest version {found} is not strictly newer than committed {current}")]
    Stale {
        /// Version on the manifest.
        found: ImageVersion,
        /// Version currently committed.
        current: ImageVersion,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::{
        ImageHash, ManifestSignature, ReleaseChannel, SignedManifest, UpdateManifest, UpdateTarget,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;
    use url::Url;

    fn fixture_signing_key() -> (SigningKey, ManifestSigningKeyId, VerifyingKey) {
        let seed = [0x42_u8; 32];
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        let id = ManifestSigningKeyId::new("k1").expect("valid id shape");
        (sk, id, vk)
    }

    fn fixture_manifest(target: UpdateTarget, version: ImageVersion) -> UpdateManifest {
        UpdateManifest {
            schema_version: 1,
            target,
            channel: ReleaseChannel::Stable,
            version,
            image_sha256: ImageHash::new([0x11_u8; 32]),
            image_size_bytes: 2_048,
            image_url: Url::parse("https://releases.example.invalid/img.tar.gz").expect("url"),
            release_notes: "fixture".into(),
            signed_at: chrono::Utc::now(),
        }
    }

    fn sign(
        manifest: &UpdateManifest,
        sk: &SigningKey,
        id: ManifestSigningKeyId,
    ) -> SignedManifest {
        let body = rmp_serde::to_vec_named(manifest).expect("encode");
        let sig = sk.sign(&body);
        SignedManifest {
            body,
            signature: ManifestSignature::new(sig.to_bytes()),
            signing_key_id: id,
        }
    }

    #[test]
    fn verify_accepts_correctly_signed_manifest() {
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        let env = sign(&mfst, &sk, id);
        let got = v
            .verify(&env, Some(ImageVersion::new(1, 5, 0)))
            .expect("verify ok");
        assert_eq!(got, mfst);
    }

    #[test]
    fn verify_rejects_tampered_body() {
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        let mut env = sign(&mfst, &sk, id);
        env.body[0] ^= 0xff;
        let err = v.verify(&env, None).expect_err("tampered body");
        assert!(matches!(err, UpdaterError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        let mut env = sign(&mfst, &sk, id);
        env.signature.bytes[0] ^= 0xff;
        let err = v.verify(&env, None).expect_err("tampered sig");
        assert!(matches!(err, UpdaterError::SignatureInvalid));
    }

    #[test]
    fn verify_rejects_unknown_key_id() {
        let (sk, id, _vk) = fixture_signing_key();
        let v = ManifestVerifier::with_target(UpdateTarget::Edge); // no keys installed
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        let env = sign(&mfst, &sk, id.clone());
        let err = v.verify(&env, None).expect_err("unknown key");
        match err {
            UpdaterError::UnknownSigningKey(got) => assert_eq!(got, id),
            other => panic!("expected UnknownSigningKey, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_ephemeral_sentinel_on_envelope() {
        let v = ManifestVerifier::with_target(UpdateTarget::Edge);
        let env = SignedManifest {
            body: vec![],
            signature: ManifestSignature::new([0_u8; 64]),
            signing_key_id: ManifestSigningKeyId::ephemeral(),
        };
        let err = v.verify(&env, None).expect_err("ephemeral");
        assert!(matches!(err, UpdaterError::EphemeralSigningKey));
    }

    #[test]
    fn add_key_refuses_ephemeral_sentinel() {
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        let (_, _id, vk) = fixture_signing_key();
        let err = v
            .add_key(ManifestSigningKeyId::ephemeral(), vk.as_bytes())
            .expect_err("eph");
        assert!(matches!(err, AddManifestKeyError::EphemeralSigningKey));
    }

    #[test]
    fn add_key_refuses_invalid_public_key_bytes() {
        // The Ed25519 encoded form is a 32-byte compressed
        // little-endian Edwards y-coordinate. The decoder
        // first reduces y mod p (= 2^255 - 19) and then
        // attempts to recover x by solving the curve
        // equation; that recovery fails when (y^2 - 1) /
        // (d*y^2 + 1) is a quadratic non-residue. Empirically
        // (verified by an exhaustive search across small y
        // values), `y = 2` is the smallest y that hits the
        // non-residue branch — `VerifyingKey::from_bytes`
        // returns Err(PointDecompressionError) for the
        // encoded form `[2, 0, ..., 0]`. We use that as the
        // smallest reproducible fixture for the InvalidKey
        // path so the test isn't dependent on randomised
        // search.
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        let mut bad = [0_u8; PUBLIC_KEY_LENGTH];
        bad[0] = 2;
        let err = v
            .add_key(ManifestSigningKeyId::new("k2").expect("id"), &bad)
            .expect_err("bad key");
        assert!(matches!(err, AddManifestKeyError::InvalidKey(_)));
    }

    #[test]
    fn verify_rejects_target_mismatch() {
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Agent, ImageVersion::new(2, 0, 0));
        let env = sign(&mfst, &sk, id);
        let err = v.verify(&env, None).expect_err("target mismatch");
        match err {
            UpdaterError::TargetMismatch { actual, expected } => {
                assert_eq!(actual, UpdateTarget::Agent);
                assert_eq!(expected, UpdateTarget::Edge);
            }
            other => panic!("expected TargetMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_downgrade() {
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(1, 0, 0));
        let env = sign(&mfst, &sk, id);
        let err = v
            .verify(&env, Some(ImageVersion::new(1, 2, 3)))
            .expect_err("downgrade");
        match err {
            UpdaterError::ManifestStale { found, current } => {
                assert_eq!(found, ImageVersion::new(1, 0, 0));
                assert_eq!(current, ImageVersion::new(1, 2, 3));
            }
            other => panic!("expected ManifestStale, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_equal_version() {
        // Re-publishing the same version is treated as a stale
        // manifest: the engine has nothing to do. Surfacing
        // it as `Stale` (and not as a no-op success) makes the
        // operator dashboard call out a misconfigured release
        // pipeline rather than silently swallowing the cycle.
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(1, 2, 3));
        let env = sign(&mfst, &sk, id);
        let err = v
            .verify(&env, Some(ImageVersion::new(1, 2, 3)))
            .expect_err("same version");
        assert!(matches!(err, UpdaterError::ManifestStale { .. }));
    }

    #[test]
    fn verify_allows_cold_start_with_no_current_pin() {
        // Cold start: nothing is committed yet, so the
        // monotonicity check must not gate on a phantom `current`.
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(0, 1, 0));
        let env = sign(&mfst, &sk, id);
        v.verify(&env, None).expect("cold start ok");
    }

    #[test]
    fn verify_rejects_future_schema_version() {
        // A manifest from a future schema is a sign of a
        // release pipeline that got ahead of the agent fleet.
        // Fail closed and surface the version on the dashboard
        // so operators can correlate with the release.
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mut mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        mfst.schema_version = MAX_KNOWN_MANIFEST_SCHEMA_VERSION + 1;
        let env = sign(&mfst, &sk, id);
        let err = v.verify(&env, None).expect_err("future schema");
        match err {
            UpdaterError::BodyDecode(msg) => assert!(msg.contains("schema_version")),
            other => panic!("expected BodyDecode, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_zero_schema_version() {
        // schema_version = 0 is reserved as "unset" — bumping
        // the wire integer to start at 1 means a default-init
        // manifest is detectable as malformed.
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mut mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        mfst.schema_version = 0;
        let env = sign(&mfst, &sk, id);
        let err = v.verify(&env, None).expect_err("zero schema");
        assert!(matches!(err, UpdaterError::BodyDecode(_)));
    }

    #[test]
    fn verify_works_with_no_target_pin_on_verifier() {
        // A target-agnostic verifier accepts any target on the
        // manifest. The orchestrator never constructs one of
        // these in production (every binary pins a target at
        // build time) but the type-level configuration is
        // useful for tooling.
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::new();
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        let mfst = fixture_manifest(UpdateTarget::Agent, ImageVersion::new(2, 0, 0));
        let env = sign(&mfst, &sk, id);
        v.verify(&env, None).expect("no-target verifier accepts");
    }

    #[test]
    fn remove_key_makes_future_verifies_fail() {
        let (sk, id, vk) = fixture_signing_key();
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        v.add_key(id.clone(), vk.as_bytes()).expect("add key");
        assert!(v.has_key(&id));
        let mfst = fixture_manifest(UpdateTarget::Edge, ImageVersion::new(2, 0, 0));
        let env = sign(&mfst, &sk, id.clone());
        v.verify(&env, None).expect("verify ok before remove");
        assert!(v.remove_key(&id));
        assert!(!v.has_key(&id));
        let err = v.verify(&env, None).expect_err("after remove");
        assert!(matches!(err, UpdaterError::UnknownSigningKey(_)));
    }

    #[test]
    fn compare_versions_returns_all_three_branches() {
        assert_eq!(
            ManifestVerifier::compare_versions(
                ImageVersion::new(2, 0, 0),
                ImageVersion::new(1, 9, 9),
            ),
            VersionMonotonicity::Newer
        );
        assert_eq!(
            ManifestVerifier::compare_versions(
                ImageVersion::new(1, 2, 3),
                ImageVersion::new(1, 2, 3),
            ),
            VersionMonotonicity::SameAsCurrent
        );
        assert_eq!(
            ManifestVerifier::compare_versions(
                ImageVersion::new(1, 0, 0),
                ImageVersion::new(2, 0, 0),
            ),
            VersionMonotonicity::Older
        );
        assert!(VersionMonotonicity::Newer.is_admissible());
        assert!(!VersionMonotonicity::SameAsCurrent.is_admissible());
        assert!(!VersionMonotonicity::Older.is_admissible());
    }

    #[test]
    fn key_count_reflects_inserts_and_removes() {
        let mut v = ManifestVerifier::with_target(UpdateTarget::Edge);
        assert_eq!(v.key_count(), 0);
        let (_sk, id, vk) = fixture_signing_key();
        v.add_key(id.clone(), vk.as_bytes()).expect("add");
        assert_eq!(v.key_count(), 1);
        v.add_key(id.clone(), vk.as_bytes()).expect("replace");
        assert_eq!(v.key_count(), 1);
        v.remove_key(&id);
        assert_eq!(v.key_count(), 0);
    }
}

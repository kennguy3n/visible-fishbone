//! Signed IPS rule bundles + the staging lifecycle.
//!
//! Suricata rules are operator-distributed (Emerging Threats,
//! Talos OPEN, Suricata-Update bundles, custom org rules). The
//! control plane re-signs a chosen bundle with the same Ed25519
//! key infrastructure that signs policy bundles and ships it to
//! the agent over `sng-comms`.
//!
//! On receipt the manager:
//!
//! 1. Verifies the Ed25519 signature against the trust store.
//! 2. Decodes the body and rejects stale (≤ current) versions.
//! 3. Stages the rule text to a temp file, runs `suricata -T` to
//!    validate the syntax, and only then atomically swaps the
//!    file into the path the running Suricata reads on `SIGHUP`.
//!
//! The verification surface intentionally mirrors
//! [`sng_core::policy::PolicyVerifier`] so operators have one
//! trust store to provision. The staging surface is split into a
//! [`RuleStager`] trait + a default [`FsRuleStager`] so unit
//! tests can drive the swap-and-validate dance against an
//! in-memory fake without spawning `suricata -T`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;

use crate::error::IpsError;

/// Fixed-size 64-byte Ed25519 signature on a rule bundle body.
/// Wire-compatible with [`sng_core::policy::BundleSignature`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpsRuleSignature {
    /// Raw 64-byte signature.
    pub bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH],
}

/// Stable identifier for an Ed25519 signing key. A hex-encoded
/// 8-byte prefix of the public key, e.g. `0a1b2c3d4e5f6071`.
/// The struct is intentionally newtyped so a typo (string vs id)
/// is a compile error.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IpsSigningKeyId(String);

impl IpsSigningKeyId {
    /// Construct, validating the shape (16 lowercase hex chars).
    pub fn new(s: impl Into<String>) -> Result<Self, IpsError> {
        let s = s.into();
        if s.len() != 16 {
            return Err(IpsError::RuleBodyDecode(format!(
                "signing key id must be 16 hex chars, got {} ({s:?})",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(IpsError::RuleBodyDecode(format!(
                "signing key id must be lowercase hex: {s:?}"
            )));
        }
        Ok(Self(s))
    }

    /// Borrow the raw hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The signed bundle envelope as it arrives over `sng-comms`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpsRuleBundle {
    /// MessagePack-encoded [`IpsRuleBundleClaims`] body bytes —
    /// the exact bytes signed by the control plane.
    pub body: Vec<u8>,
    /// Signature over `body`.
    pub signature: IpsRuleSignature,
    /// Which signing key in the trust store produced the
    /// signature.
    pub signing_key_id: IpsSigningKeyId,
}

/// Decoded payload of an [`IpsRuleBundle`]. Wire-format
/// compatible with the Go side's `bundlePayload` shape (named
/// MessagePack map).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpsRuleBundleClaims {
    /// Schema version (1 today).
    #[serde(rename = "v")]
    pub schema_version: u8,
    /// Monotonically increasing version. The verifier rejects
    /// any bundle with `version` <= the currently installed
    /// version.
    #[serde(rename = "rev")]
    pub version: u64,
    /// Free-form compiler identifier (`"sng-control/0.3"` etc.).
    /// Surfaced on telemetry; not security relevant.
    #[serde(rename = "comp")]
    pub compiler: String,
    /// Total rule text. UTF-8; line-separated Suricata rules.
    /// Held inline so the bundle is self-contained.
    #[serde(rename = "rules")]
    pub rules_text: String,
}

impl IpsRuleBundleClaims {
    /// Decode a body from MessagePack bytes.
    pub fn from_body(body: &[u8]) -> Result<Self, IpsError> {
        rmp_serde::from_slice(body).map_err(|e| IpsError::RuleBodyDecode(e.to_string()))
    }

    /// Encode a claims body to MessagePack bytes (named-map shape
    /// so the Go side's `msgpack/v5` reads it without remapping).
    ///
    /// Returns [`IpsError::RuleBodyEncode`] on a serializer failure
    /// so dashboards filtering on `ips.rule.body.encode` see the
    /// outbound encode path distinctly from the inbound
    /// [`Self::from_body`] decode path.
    pub fn encode(&self) -> Result<Vec<u8>, IpsError> {
        rmp_serde::to_vec_named(self).map_err(|e| IpsError::RuleBodyEncode(e.to_string()))
    }
}

/// Trust store keyed by signing key id. Built at agent startup
/// from the control plane key directory; reuses the same shape
/// as [`sng_core::policy::PolicyVerifier`] so one trust store
/// covers both policy and rule bundles.
#[derive(Clone, Debug, Default)]
pub struct IpsRuleVerifier {
    keys: HashMap<IpsSigningKeyId, VerifyingKey>,
}

impl IpsRuleVerifier {
    /// Empty verifier — add keys with [`Self::add_key`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a trusted Ed25519 public key under the supplied
    /// id. Returns an error if the bytes are not a valid
    /// Ed25519 point.
    pub fn add_key(&mut self, id: IpsSigningKeyId, key_bytes: &[u8; 32]) -> Result<(), IpsError> {
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| IpsError::RuleSignatureUnknownKey(e.to_string()))?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Number of installed keys — useful for boot diagnostics.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify the bundle signature against the trust store, then
    /// decode the body. The combined call avoids the temptation
    /// to decode-without-verifying which would create a TOCTOU
    /// hole on the staged rule text.
    pub fn verify_and_decode(
        &self,
        bundle: &IpsRuleBundle,
    ) -> Result<IpsRuleBundleClaims, IpsError> {
        let key = self.keys.get(&bundle.signing_key_id).ok_or_else(|| {
            IpsError::RuleSignatureUnknownKey(bundle.signing_key_id.as_str().to_owned())
        })?;
        let sig = Signature::from_bytes(&bundle.signature.bytes);
        key.verify(&bundle.body, &sig)
            .map_err(|_| IpsError::RuleSignatureInvalid)?;
        IpsRuleBundleClaims::from_body(&bundle.body)
    }
}

/// Per-stager configuration. Decoupled from the trait so callers
/// can swap implementations without re-wiring the staging policy.
#[derive(Clone, Debug)]
pub struct RuleStagerConfig {
    /// Final path the running Suricata reads on SIGHUP. The
    /// stager writes a sibling temp file, validates it via the
    /// supplied `validator`, then renames into place.
    pub final_path: PathBuf,
    /// Where the temporary staged file lives between
    /// write-and-validate and the atomic rename.
    pub staging_dir: PathBuf,
    /// Path to the `suricata.yaml` the validator should evaluate
    /// the staged rule file against. `suricata -T` requires a
    /// configuration file; if we omit it, the binary falls back
    /// to `/etc/suricata/suricata.yaml`, which on the SNG
    /// appliance image does not exist — every validate call
    /// would then fail with a missing-config error and the
    /// stager would refuse to install otherwise-valid rule
    /// bundles. Plumbing the path through `RuleStagerConfig`
    /// keeps the validator contract honest: a `RuleValidator`
    /// receives both the staged rule file and the live config
    /// it should validate against.
    pub config_path: PathBuf,
}

/// Pluggable rule validator. Production wires this to
/// [`SuricataValidator`] which shells out to `suricata -T`;
/// tests use [`AlwaysValidValidator`] (or a custom mock) to drive
/// the swap path without launching the IDS.
///
/// Implementations receive *both* the staged rule file and the
/// live `suricata.yaml` the running daemon is bound to. The
/// config file is mandatory for any validator that has to load
/// app-layer parsers, address-group vars, or other rule
/// dependencies declared in the YAML; passing it on the trait
/// surface (rather than holding it on the implementor) means
/// the same validator instance can be reused across multiple
/// staging environments (e.g. a per-tenant manager).
#[async_trait]
pub trait RuleValidator: Send + Sync + std::fmt::Debug {
    /// Validate the supplied staged file using the supplied
    /// `suricata.yaml`. Implementations should return a
    /// structured [`IpsError::RuleValidate`] on syntax error so
    /// the manager can surface the failure as a telemetry event.
    async fn validate(&self, staged_path: &Path, config_path: &Path) -> Result<(), IpsError>;
}

/// `suricata -T` validator. Shells out to the IDS binary in
/// "test mode" against the staged rule file. Production default.
#[derive(Clone, Debug)]
pub struct SuricataValidator {
    /// Path to the `suricata` binary; defaults to PATH lookup.
    pub binary: PathBuf,
}

impl SuricataValidator {
    /// New validator using `suricata` from PATH.
    #[must_use]
    pub fn new() -> Self {
        Self {
            binary: PathBuf::from("suricata"),
        }
    }

    /// Override the binary path (matches [`crate::process::ShellSuricata::with_binary`]).
    #[must_use]
    pub fn with_binary(mut self, binary: impl Into<PathBuf>) -> Self {
        self.binary = binary.into();
        self
    }
}

impl Default for SuricataValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RuleValidator for SuricataValidator {
    async fn validate(&self, staged_path: &Path, config_path: &Path) -> Result<(), IpsError> {
        // `suricata -T` loads the supplied YAML to resolve
        // app-layer parsers and address-group vars before it
        // can syntax-check the rule file. Without `-c` it falls
        // back to `/etc/suricata/suricata.yaml`, which on the
        // SNG appliance image does not exist and would cause
        // every validate call to fail with a missing-config
        // error rather than a real rule-syntax error.
        let out = tokio::process::Command::new(&self.binary)
            .arg("-T")
            .arg("-c")
            .arg(config_path)
            .arg("-S")
            .arg(staged_path)
            .output()
            .await
            .map_err(|e| IpsError::Process(format!("spawn suricata -T: {e}")))?;
        if !out.status.success() {
            return Err(IpsError::RuleValidate(
                String::from_utf8_lossy(&out.stderr).into_owned(),
            ));
        }
        Ok(())
    }
}

/// Test-only validator that accepts every staged file. Lives in
/// the production tree (not behind cfg(test)) so downstream
/// crates' integration tests can use it too.
#[derive(Clone, Debug, Default)]
pub struct AlwaysValidValidator;

#[async_trait]
impl RuleValidator for AlwaysValidValidator {
    async fn validate(&self, _staged_path: &Path, _config_path: &Path) -> Result<(), IpsError> {
        Ok(())
    }
}

/// Trait for the actual stage-validate-swap dance. Implemented
/// once for real on-disk staging (see [`FsRuleStager`]); tests
/// implement a record-only variant when they need to assert on
/// the swap sequence without touching the filesystem.
#[async_trait]
pub trait RuleStager: Send + Sync + std::fmt::Debug {
    /// Stage the supplied rule text, validate it, and atomically
    /// swap it into place. Returns the version that is now
    /// installed.
    async fn stage_and_swap(&self, claims: &IpsRuleBundleClaims) -> Result<u64, IpsError>;
    /// The currently installed version — `None` if no bundle has
    /// ever been installed.
    async fn current_version(&self) -> Option<u64>;
}

/// Production stager: writes to a tempfile in `staging_dir`,
/// validates via the supplied [`RuleValidator`], then
/// `tokio::fs::rename`s atomically into `final_path`.
///
/// Concurrency contract: every `stage_and_swap` call serialises
/// behind `swap_lock`. Two simultaneous bundle pushes could
/// otherwise race in three observable ways:
///
/// 1. Both pass the staleness check against the same
///    `installed` snapshot, both succeed, and the *older* of
///    the two completes its `rename` last — silently demoting
///    the running rule set to the older version.
/// 2. Both write the same staging tempfile name
///    (`<final>.staging-<version>`), corrupting each other's
///    on-disk bytes mid-write.
/// 3. The `installed = Some(version)` book-keeping at the end
///    is not paired with the file-on-disk under the same lock,
///    so a reader of `current_version` could see a version
///    number that does not match what is actually live.
///
/// Holding an async mutex across the full sequence (staleness
/// → write → validate → rename → version cell update) makes the
/// whole operation atomic from any caller's perspective. The
/// validator call may be slow, so we deliberately use
/// `tokio::sync::Mutex` instead of `parking_lot::Mutex` —
/// blocking the executor would defeat the back-pressure
/// strategy.
#[derive(Clone, Debug)]
pub struct FsRuleStager {
    config: RuleStagerConfig,
    validator: Arc<dyn RuleValidator>,
    installed: Arc<Mutex<Option<u64>>>,
    swap_lock: Arc<AsyncMutex<()>>,
}

impl FsRuleStager {
    /// Build a stager from config + validator.
    #[must_use]
    pub fn new(config: RuleStagerConfig, validator: Arc<dyn RuleValidator>) -> Self {
        Self {
            config,
            validator,
            installed: Arc::new(Mutex::new(None)),
            swap_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Pre-seed the installed version. Useful at boot to seed
    /// the staleness check from the manifest pinned to the
    /// last-known good config.
    pub fn set_installed_version(&self, v: u64) {
        *self.installed.lock() = Some(v);
    }
}

#[async_trait]
impl RuleStager for FsRuleStager {
    async fn stage_and_swap(&self, claims: &IpsRuleBundleClaims) -> Result<u64, IpsError> {
        // Serialise every concurrent stage_and_swap. The guard
        // is held across the full IO + validate + rename + state
        // update so two simultaneous pushes can never interleave
        // and reach an inconsistent state. See the type-level
        // doc comment for the race we are preventing.
        let _guard = self.swap_lock.lock().await;
        // Staleness check first — no point staging anything that
        // would be rejected on version compare. Reading the
        // version cell inside the swap lock guarantees that the
        // value we compare against is exactly the one that any
        // *previous* swap committed (the writer updates the cell
        // before releasing `swap_lock`).
        if let Some(current) = *self.installed.lock() {
            if claims.version <= current {
                return Err(IpsError::RuleStale {
                    incoming: claims.version,
                    current,
                });
            }
        }
        tokio::fs::create_dir_all(&self.config.staging_dir)
            .await
            .map_err(|e| IpsError::Io(format!("create staging dir: {e}")))?;
        let file_name = self
            .config
            .final_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or("sng.rules");
        let staged = self
            .config
            .staging_dir
            .join(format!("{file_name}.staging-{}", claims.version));
        tokio::fs::write(&staged, claims.rules_text.as_bytes())
            .await
            .map_err(|e| IpsError::Io(format!("write staged file {}: {e}", staged.display())))?;
        // Validate against the live `suricata.yaml`; if it
        // fails, leave the staged file in place for operator
        // inspection but never swap it in. Passing the config
        // path is mandatory — see RuleStagerConfig::config_path
        // for the failure mode `suricata -T` without `-c` hits.
        self.validator
            .validate(&staged, &self.config.config_path)
            .await?;
        // Ensure the parent of the final path exists before the
        // atomic rename.
        if let Some(parent) = self.config.final_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                IpsError::Io(format!(
                    "create final-path parent {}: {e}",
                    parent.display()
                ))
            })?;
        }
        // `rename` is atomic on POSIX as long as src and dst
        // are on the same filesystem. Operators are expected to
        // co-locate `staging_dir` and `final_path` on the same
        // mount; we surface the kernel's error if they don't.
        tokio::fs::rename(&staged, &self.config.final_path)
            .await
            .map_err(|e| {
                IpsError::Io(format!(
                    "rename {} -> {}: {e}",
                    staged.display(),
                    self.config.final_path.display()
                ))
            })?;
        *self.installed.lock() = Some(claims.version);
        Ok(claims.version)
    }

    async fn current_version(&self) -> Option<u64> {
        *self.installed.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;

    fn deterministic_keypair() -> (SigningKey, IpsSigningKeyId) {
        // Deterministic seed → reproducible test fixture.
        let seed = [11_u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let id = IpsSigningKeyId::new("0123456789abcdef").unwrap();
        (signing, id)
    }

    fn sample_claims(version: u64) -> IpsRuleBundleClaims {
        IpsRuleBundleClaims {
            schema_version: 1,
            version,
            compiler: "sng-test/0".into(),
            rules_text: r#"alert tcp any any -> any 80 (msg:"http traffic"; sid:1000001; rev:1;)"#
                .into(),
        }
    }

    fn make_bundle(version: u64, signing: &SigningKey, id: IpsSigningKeyId) -> IpsRuleBundle {
        let claims = sample_claims(version);
        let body = claims.encode().unwrap();
        let sig = signing.sign(&body);
        IpsRuleBundle {
            body,
            signature: IpsRuleSignature {
                bytes: sig.to_bytes(),
            },
            signing_key_id: id,
        }
    }

    #[test]
    fn signing_key_id_rejects_uppercase_hex() {
        let err = IpsSigningKeyId::new("0123456789ABCDEF").unwrap_err();
        assert!(matches!(err, IpsError::RuleBodyDecode(_)));
    }

    #[test]
    fn signing_key_id_rejects_wrong_length() {
        let err = IpsSigningKeyId::new("0123abcd").unwrap_err();
        assert!(matches!(err, IpsError::RuleBodyDecode(_)));
    }

    #[test]
    fn signing_key_id_rejects_non_hex() {
        let err = IpsSigningKeyId::new("0123abcdg123abcd").unwrap_err();
        assert!(matches!(err, IpsError::RuleBodyDecode(_)));
    }

    #[test]
    fn signing_key_id_accepts_canonical_form() {
        let id = IpsSigningKeyId::new("0123456789abcdef").unwrap();
        assert_eq!(id.as_str(), "0123456789abcdef");
    }

    #[test]
    fn claims_round_trip_via_messagepack() {
        let c = sample_claims(7);
        let bytes = c.encode().unwrap();
        let back = IpsRuleBundleClaims::from_body(&bytes).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn claims_from_body_rejects_garbage() {
        let err = IpsRuleBundleClaims::from_body(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert!(matches!(err, IpsError::RuleBodyDecode(_)));
    }

    #[test]
    fn verifier_accepts_correctly_signed_bundle() {
        let (signing, id) = deterministic_keypair();
        let mut v = IpsRuleVerifier::new();
        v.add_key(id.clone(), signing.verifying_key().as_bytes())
            .unwrap();
        let b = make_bundle(1, &signing, id);
        let claims = v.verify_and_decode(&b).unwrap();
        assert_eq!(claims.version, 1);
        assert_eq!(claims.compiler, "sng-test/0");
    }

    #[test]
    fn verifier_rejects_tampered_body() {
        let (signing, id) = deterministic_keypair();
        let mut v = IpsRuleVerifier::new();
        v.add_key(id.clone(), signing.verifying_key().as_bytes())
            .unwrap();
        let mut b = make_bundle(1, &signing, id);
        // Flip a byte in the body — signature no longer matches.
        b.body[0] ^= 0x01;
        let err = v.verify_and_decode(&b).unwrap_err();
        assert!(matches!(err, IpsError::RuleSignatureInvalid));
    }

    #[test]
    fn verifier_rejects_unknown_signing_key() {
        let (signing, id) = deterministic_keypair();
        let v = IpsRuleVerifier::new();
        let b = make_bundle(1, &signing, id);
        let err = v.verify_and_decode(&b).unwrap_err();
        assert!(matches!(err, IpsError::RuleSignatureUnknownKey(_)));
    }

    #[test]
    fn verifier_rejects_signature_signed_with_wrong_key() {
        // Trust store knows key A, bundle is signed with key B
        // but claims key A's id → signature does not verify.
        let id = IpsSigningKeyId::new("aaaaaaaaaaaaaaaa").unwrap();
        let trusted = SigningKey::from_bytes(&[1_u8; 32]);
        let attacker = SigningKey::from_bytes(&[2_u8; 32]);
        let mut v = IpsRuleVerifier::new();
        v.add_key(id.clone(), trusted.verifying_key().as_bytes())
            .unwrap();
        let b = make_bundle(1, &attacker, id);
        assert!(matches!(
            v.verify_and_decode(&b),
            Err(IpsError::RuleSignatureInvalid)
        ));
    }

    #[test]
    fn verifier_add_key_accepts_real_public_key_and_then_verifies_signatures() {
        // ed25519-dalek's `VerifyingKey::from_bytes` does not
        // reject non-canonical compressed encodings (RFC 8032
        // does not strictly require this either). The trust
        // store is built from public keys the control plane
        // emitted via the same library, so the practical
        // invariant we want to pin is: a key derived from a
        // real SigningKey installs successfully, and a bundle
        // signed by that key verifies. The previous version of
        // this test asserted `0xFF * 32` would be rejected,
        // which is library-dependent and not a property we
        // depend on.
        let (signing, id) = deterministic_keypair();
        let mut v = IpsRuleVerifier::new();
        v.add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        assert_eq!(v.key_count(), 1);
        let bundle = make_bundle(1, &signing, id);
        let claims = v.verify_and_decode(&bundle).unwrap();
        assert_eq!(claims.version, 1);
    }

    #[tokio::test]
    async fn fs_stager_writes_and_swaps_under_validator() {
        let tmp = tempfile::tempdir().unwrap();
        let final_path = tmp.path().join("sng.rules");
        let staging_dir = tmp.path().join("staging");
        let cfg = RuleStagerConfig {
            final_path: final_path.clone(),
            staging_dir,
            config_path: tmp.path().join("suricata.yaml"),
        };
        let stager = FsRuleStager::new(cfg, Arc::new(AlwaysValidValidator));
        let v = stager
            .stage_and_swap(&sample_claims(42))
            .await
            .expect("swap");
        assert_eq!(v, 42);
        // Final file contains the rule text.
        let body = tokio::fs::read_to_string(&final_path).await.unwrap();
        assert!(body.contains("sid:1000001"));
        // Installed version updated.
        assert_eq!(stager.current_version().await, Some(42));
    }

    #[tokio::test]
    async fn fs_stager_rejects_stale_version_before_writing_anything() {
        let tmp = tempfile::tempdir().unwrap();
        let final_path = tmp.path().join("sng.rules");
        let cfg = RuleStagerConfig {
            final_path: final_path.clone(),
            staging_dir: tmp.path().join("staging"),
            config_path: tmp.path().join("suricata.yaml"),
        };
        let stager = FsRuleStager::new(cfg, Arc::new(AlwaysValidValidator));
        stager.set_installed_version(10);
        let err = stager.stage_and_swap(&sample_claims(10)).await.unwrap_err();
        match err {
            IpsError::RuleStale { incoming, current } => {
                assert_eq!(incoming, 10);
                assert_eq!(current, 10);
            }
            other => panic!("expected RuleStale, got {other:?}"),
        }
        // Final path was not touched.
        assert!(!final_path.exists());
    }

    #[tokio::test]
    async fn fs_stager_rejects_downgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = RuleStagerConfig {
            final_path: tmp.path().join("sng.rules"),
            staging_dir: tmp.path().join("staging"),
            config_path: tmp.path().join("suricata.yaml"),
        };
        let stager = FsRuleStager::new(cfg, Arc::new(AlwaysValidValidator));
        stager.stage_and_swap(&sample_claims(5)).await.unwrap();
        let err = stager.stage_and_swap(&sample_claims(3)).await.unwrap_err();
        assert!(matches!(err, IpsError::RuleStale { .. }));
    }

    /// Validator that always fails — used to assert the stager
    /// leaves the final file untouched on validation failure.
    #[derive(Debug, Default)]
    struct RejectValidator;

    #[async_trait]
    impl RuleValidator for RejectValidator {
        async fn validate(&self, _staged: &Path, _config: &Path) -> Result<(), IpsError> {
            Err(IpsError::RuleValidate("synthetic failure".into()))
        }
    }

    #[tokio::test]
    async fn fs_stager_leaves_final_path_untouched_on_validation_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let final_path = tmp.path().join("sng.rules");
        // Pre-seed the final path so we can assert that it is
        // not overwritten by a failed swap.
        tokio::fs::write(&final_path, b"old content").await.unwrap();
        let cfg = RuleStagerConfig {
            final_path: final_path.clone(),
            staging_dir: tmp.path().join("staging"),
            config_path: tmp.path().join("suricata.yaml"),
        };
        let stager = FsRuleStager::new(cfg, Arc::new(RejectValidator));
        let err = stager.stage_and_swap(&sample_claims(1)).await.unwrap_err();
        assert!(matches!(err, IpsError::RuleValidate(_)));
        assert_eq!(
            tokio::fs::read_to_string(&final_path).await.unwrap(),
            "old content"
        );
        assert_eq!(stager.current_version().await, None);
    }

    #[tokio::test]
    async fn fs_stager_creates_staging_dir_on_demand() {
        let tmp = tempfile::tempdir().unwrap();
        let staging_dir = tmp.path().join("nested/staging/dir");
        let cfg = RuleStagerConfig {
            final_path: tmp.path().join("sng.rules"),
            staging_dir: staging_dir.clone(),
            config_path: tmp.path().join("suricata.yaml"),
        };
        let stager = FsRuleStager::new(cfg, Arc::new(AlwaysValidValidator));
        stager.stage_and_swap(&sample_claims(1)).await.unwrap();
        assert!(staging_dir.exists());
    }

    /// Pin the suricata invocation contract: `-T -c <config> -S
    /// <rules>` in that order. The previous version of this
    /// validator omitted `-c`, which made `suricata -T` fall
    /// back to `/etc/suricata/suricata.yaml` (which the SNG
    /// appliance image does not ship) and reject every
    /// otherwise-valid rule file with a missing-config error.
    /// This test uses a tiny shell stand-in for `suricata` that
    /// echoes its argv so we can assert the exact flag layout.
    #[cfg(unix)]
    #[tokio::test]
    async fn suricata_validator_passes_config_path_with_dash_c() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let argv_log = tmp.path().join("argv.log");
        let fake_bin = tmp.path().join("suricata");
        // Print every argument on its own line so the assertion
        // can pattern-match against an exact slice. `set -e` so
        // the script bubbles up failures from `printf` itself.
        let script = format!(
            "#!/bin/sh\nset -e\nfor a in \"$@\"; do printf '%s\\n' \"$a\" >> {}\ndone\nexit 0\n",
            argv_log.display()
        );
        tokio::fs::write(&fake_bin, script).await.unwrap();
        tokio::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        let staged = tmp.path().join("staged.rules");
        tokio::fs::write(&staged, b"alert ip any any -> any any (sid:1;)")
            .await
            .unwrap();
        let config = tmp.path().join("suricata.yaml");
        tokio::fs::write(&config, b"%YAML 1.1\n---\n")
            .await
            .unwrap();
        let validator = SuricataValidator::new().with_binary(&fake_bin);
        validator.validate(&staged, &config).await.unwrap();
        let recorded = tokio::fs::read_to_string(&argv_log).await.unwrap();
        let args: Vec<&str> = recorded.lines().collect();
        // Exact layout: -T -c <config> -S <staged>. Anything
        // else (e.g. missing -c, swapped order) breaks the
        // contract the running daemon relies on.
        assert_eq!(
            args,
            vec![
                "-T",
                "-c",
                config.to_str().unwrap(),
                "-S",
                staged.to_str().unwrap(),
            ],
            "unexpected suricata argv: {args:?}"
        );
    }

    /// Round-trip the failure path: a non-zero exit from the
    /// validator binary surfaces as `IpsError::RuleValidate`
    /// carrying the stderr payload, so an operator can see the
    /// underlying parse error in the telemetry stream.
    #[cfg(unix)]
    #[tokio::test]
    async fn suricata_validator_surfaces_stderr_on_failure() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let fake_bin = tmp.path().join("suricata");
        let script = "#!/bin/sh\nprintf 'rule parse error: synthetic\\n' >&2\nexit 1\n".to_owned();
        tokio::fs::write(&fake_bin, script).await.unwrap();
        tokio::fs::set_permissions(&fake_bin, std::fs::Permissions::from_mode(0o755))
            .await
            .unwrap();
        let staged = tmp.path().join("staged.rules");
        tokio::fs::write(&staged, b"garbage").await.unwrap();
        let config = tmp.path().join("suricata.yaml");
        tokio::fs::write(&config, b"---\n").await.unwrap();
        let validator = SuricataValidator::new().with_binary(&fake_bin);
        let err = validator.validate(&staged, &config).await.unwrap_err();
        match err {
            IpsError::RuleValidate(msg) => {
                assert!(
                    msg.contains("rule parse error"),
                    "stderr should pass through, got {msg:?}"
                );
            }
            other => panic!("expected RuleValidate, got {other:?}"),
        }
    }
}

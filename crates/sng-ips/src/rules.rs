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

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// Provenance of this bundle's rules (Emerging Threats,
    /// Suricata-Update, custom org feed). Defaults to
    /// [`RuleSource::CustomOrg`] when the field is absent so an
    /// older control plane that signs bundles without it still
    /// decodes — the field is purely for telemetry / per-source
    /// stats and is not security relevant (the signature covers
    /// the body either way).
    #[serde(rename = "src", default)]
    pub source: RuleSource,
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
        if let Some(current) = *self.installed.lock()
            && claims.version <= current
        {
            return Err(IpsError::RuleStale {
                incoming: claims.version,
                current,
            });
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

// ===========================================================================
// Multi-source rule management: provenance, threat categorisation, per-tenant
// category enablement, and automatic feed-update scheduling.
//
// The control plane re-signs rule sets it pulls from upstream feeds (Emerging
// Threats, Suricata-Update) alongside operator-authored custom rules, all under
// the one Ed25519 trust store above. This section adds the vocabulary and the
// pure transforms the edge applies on top of a verified bundle:
//
//   * [`RuleSource`]  — where a bundle's rules came from (telemetry / stats).
//   * [`RuleCategory`] — the threat class a single rule belongs to, derived
//     from its Suricata `classtype:` / `msg:` so dashboards and per-tenant
//     enablement can group rules without a hand-maintained sid→category map.
//   * [`CategorySelection`] — the set of enabled categories. The Go control
//     plane stores one per tenant and compiles a tenant-specific bundle; the
//     edge applies an org-global selection to drop categories wholesale.
//   * [`filter_rules_by_category`] / [`rule_stats`] — the pure transforms that
//     enforce a selection and produce per-category counts.
//   * [`RuleFeed`] / [`RuleFeedFetcher`] / [`RuleUpdateScheduler`] — the daily
//     pull → verify → merge → filter → stage → reload lifecycle, with the
//     network transport injected behind a trait so it is unit-testable.
// ===========================================================================

/// Provenance of a Suricata rule set.
///
/// Bundles are signed by the control plane regardless of source, so this is
/// not a trust signal — it drives per-source telemetry / stats and lets the
/// merge step in [`RuleUpdateScheduler`] order feeds deterministically.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    /// Proofpoint Emerging Threats OPEN ruleset.
    EmergingThreats,
    /// `suricata-update` managed index (Talos OPEN + others).
    SuricataUpdate,
    /// Operator-authored rules specific to one org.
    #[default]
    CustomOrg,
}

impl RuleSource {
    /// Stable lowercase identifier used on telemetry and stats.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmergingThreats => "emerging_threats",
            Self::SuricataUpdate => "suricata_update",
            Self::CustomOrg => "custom_org",
        }
    }

    /// Every source, in a stable order. Used by callers that need
    /// to enumerate sources (e.g. seeding per-source counters).
    #[must_use]
    pub fn all() -> [Self; 3] {
        [Self::EmergingThreats, Self::SuricataUpdate, Self::CustomOrg]
    }
}

/// The threat class a single Suricata rule belongs to.
///
/// Derived from the rule's `classtype:` (and `msg:` keywords as a fallback,
/// since Suricata's stock classtypes do not distinguish lateral movement or
/// exfiltration). Used for per-category enablement and hit stats.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    /// Trojans, droppers, coin-miners, ransomware payload delivery.
    Malware,
    /// Exploitation of a software vulnerability (exploit kits,
    /// shellcode, web-application attacks, admin/user privilege
    /// escalation attempts).
    Exploit,
    /// Internal-to-internal movement (SMB/RDP/WinRM/PsExec abuse).
    LateralMovement,
    /// Command-and-control beacons and check-ins.
    C2,
    /// Data exfiltration / theft channels.
    Exfiltration,
    /// Denial-of-service / volumetric attacks.
    Dos,
    /// Anything that does not fit a more specific class.
    Other,
}

impl RuleCategory {
    /// Stable lowercase identifier. Matches the `serde` rename so
    /// the on-wire string and the telemetry string never diverge.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malware => "malware",
            Self::Exploit => "exploit",
            Self::LateralMovement => "lateral_movement",
            Self::C2 => "c2",
            Self::Exfiltration => "exfiltration",
            Self::Dos => "dos",
            Self::Other => "other",
        }
    }

    /// Parse a category from its stable string id. Returns `None`
    /// for an unknown string so a caller (e.g. the Go API decoding
    /// a per-tenant selection) can reject it explicitly rather than
    /// silently coercing to `Other`.
    #[must_use]
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "malware" => Some(Self::Malware),
            "exploit" => Some(Self::Exploit),
            "lateral_movement" => Some(Self::LateralMovement),
            "c2" => Some(Self::C2),
            "exfiltration" => Some(Self::Exfiltration),
            "dos" => Some(Self::Dos),
            "other" => Some(Self::Other),
            _ => None,
        }
    }

    /// Every category an operator can enable/disable, in a stable
    /// order. `Other` is included so a selection can choose to drop
    /// uncategorised rules too.
    #[must_use]
    pub fn all() -> [Self; 7] {
        [
            Self::Malware,
            Self::Exploit,
            Self::LateralMovement,
            Self::C2,
            Self::Exfiltration,
            Self::Dos,
            Self::Other,
        ]
    }

    /// Classify a single Suricata rule line.
    ///
    /// Precedence is deliberate: `msg:` keywords that name a tactic Suricata's
    /// stock `classtype` vocabulary cannot express (lateral movement,
    /// exfiltration, explicit C2) win first, because feed authors encode that
    /// intent in the message text (e.g. `ET LATERAL ...`, `ET EXFIL ...`). Only
    /// then do we fall back to the `classtype:` mapping, and finally to a
    /// keyword sweep over the whole line. A line we cannot place is `Other`,
    /// never silently dropped.
    #[must_use]
    pub fn classify(rule_line: &str) -> Self {
        let lower = rule_line.to_ascii_lowercase();
        let msg = extract_rule_option(&lower, "msg").unwrap_or_default();
        let classtype = extract_rule_option(&lower, "classtype").unwrap_or_default();

        // 1. msg-encoded tactics that classtype cannot express.
        // Single-token signals are matched on whole words (see
        // `msg_has_word`) so a tactic keyword embedded in an unrelated
        // word does not misclassify the rule: "lateral" must not fire
        // on "collateral"/"bilateral", and "c2" must not fire on a
        // cipher name like "rc2". Multi-word phrases stay substring
        // matches since they are already specific.
        if msg_has_word(&msg, "exfil")
            || msg_has_word(&msg, "exfiltration")
            || msg.contains("data theft")
            || msg.contains("data leak")
        {
            return Self::Exfiltration;
        }
        if msg_has_word(&msg, "lateral") {
            return Self::LateralMovement;
        }
        if msg_has_word(&msg, "c2")
            || msg_has_word(&msg, "cnc")
            || msg.contains("command and control")
        {
            return Self::C2;
        }

        // 2. classtype mapping — the primary signal.
        match classtype.as_str() {
            "command-and-control" => return Self::C2,
            "trojan-activity" | "malware-cnc" | "coin-mining" | "domain-c2" => {
                // trojan-activity is overwhelmingly C2 beaconing in the ET
                // ruleset; but coin-mining/malware payloads also use it.
                // Bias to Malware unless the msg already named C2 (handled
                // above), since "is this malware?" is the coarser, safer
                // grouping for the default deny posture.
                return Self::Malware;
            }
            "denial-of-service" | "attempted-dos" => return Self::Dos,
            "web-application-attack"
            | "attempted-admin"
            | "attempted-user"
            | "shellcode-detect"
            | "exploit-kit"
            | "attempted-recon" => return Self::Exploit,
            _ => {}
        }

        // 3. whole-line keyword fallback.
        if lower.contains("ransomware") || lower.contains("trojan") || lower.contains("malware") {
            return Self::Malware;
        }
        if lower.contains("exploit") || lower.contains("cve-") {
            return Self::Exploit;
        }
        Self::Other
    }
}

/// Extract the value of a Suricata rule option (`key:value;`) from an
/// already-lowercased rule line. Handles the quoted form Suricata uses for
/// `msg:"..."` by stripping the surrounding quotes. Returns `None` when the
/// option is absent. Pure + allocation-light (one `String` for the value).
fn extract_rule_option(lower_line: &str, key: &str) -> Option<String> {
    // Options live inside the trailing `( ... )`. Search for `key:`
    // preceded by a boundary (start, `(`, `;`, or whitespace) so a
    // substring like `xclasstype:` does not match `classtype:`.
    let needle = format!("{key}:");
    let mut search_from = 0;
    while let Some(rel) = lower_line[search_from..].find(&needle) {
        let at = search_from + rel;
        let boundary_ok =
            at == 0 || matches!(lower_line.as_bytes()[at - 1], b'(' | b';' | b' ' | b'\t');
        if boundary_ok {
            let rest = &lower_line[at + needle.len()..];
            let rest = rest.trim_start();
            let value = if let Some(stripped) = rest.strip_prefix('"') {
                // Quoted: read to the closing quote.
                stripped.split('"').next().unwrap_or("")
            } else {
                // Unquoted: read to the option terminator `;`.
                rest.split(';').next().unwrap_or("").trim()
            };
            return Some(value.to_string());
        }
        search_from = at + needle.len();
    }
    None
}

/// Whether `msg` contains `word` as a complete token, where token
/// boundaries are any non-alphanumeric character (space, slash,
/// punctuation). This keeps the tactic keywords in
/// [`RuleCategory::classify`] precise: `"lateral"` matches
/// `"ET LATERAL PsExec"` but not `"collateral"`, and `"c2"` matches
/// `"Win32 C2 checkin"` but not the cipher name `"rc2"`. `msg` is
/// expected to already be lowercased (as `classify` produces it);
/// `word` must be lowercase alphanumeric.
fn msg_has_word(msg: &str, word: &str) -> bool {
    msg.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == word)
}

/// Whether a line is an actual Suricata rule (vs a comment or blank).
/// Suricata rule actions are a fixed set; anything else (a `#` comment,
/// a blank line, a `%YAML` directive) is preserved verbatim by the
/// category filter but never counted in [`rule_stats`].
fn is_rule_line(line: &str) -> bool {
    let t = line.trim_start();
    if t.is_empty() || t.starts_with('#') {
        return false;
    }
    let action = t.split_whitespace().next().unwrap_or("");
    matches!(
        action,
        "alert" | "drop" | "reject" | "rejectsrc" | "rejectdst" | "pass" | "log"
    )
}

/// The set of [`RuleCategory`] values currently enabled.
///
/// The Go control plane persists one selection per tenant (migration
/// `050_ips_rule_categories`) and compiles a tenant-specific bundle by passing
/// the selection to [`filter_rules_by_category`]; the edge can additionally
/// hold an org-global selection to drop a category fleet-wide. Defaults to
/// every category enabled (fail-open: a fresh tenant gets full coverage).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CategorySelection {
    enabled: BTreeSet<RuleCategory>,
}

impl Default for CategorySelection {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl CategorySelection {
    /// Every category enabled — the safe default.
    #[must_use]
    pub fn all_enabled() -> Self {
        Self {
            enabled: RuleCategory::all().into_iter().collect(),
        }
    }

    /// No category enabled. Mainly useful as a base to `.enable()` onto.
    #[must_use]
    pub fn none_enabled() -> Self {
        Self {
            enabled: BTreeSet::new(),
        }
    }

    /// Build from an explicit set of enabled categories.
    #[must_use]
    pub fn from_enabled<I: IntoIterator<Item = RuleCategory>>(iter: I) -> Self {
        Self {
            enabled: iter.into_iter().collect(),
        }
    }

    /// Enable a category. Idempotent.
    pub fn enable(&mut self, c: RuleCategory) {
        self.enabled.insert(c);
    }

    /// Disable a category. Idempotent.
    pub fn disable(&mut self, c: RuleCategory) {
        self.enabled.remove(&c);
    }

    /// Whether a category is enabled.
    #[must_use]
    pub fn is_enabled(&self, c: RuleCategory) -> bool {
        self.enabled.contains(&c)
    }

    /// The enabled categories, sorted.
    #[must_use]
    pub fn enabled_categories(&self) -> Vec<RuleCategory> {
        self.enabled.iter().copied().collect()
    }
}

/// Per-category rule counts for a rule set. Drives the operator
/// "rules by category" view and the stats the Go API surfaces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuleStats {
    /// Count of rule lines per category (categories with zero
    /// rules are omitted).
    pub per_category: BTreeMap<RuleCategory, usize>,
    /// Total rule lines (sum of `per_category`). Excludes comments
    /// and blank lines.
    pub total: usize,
}

impl RuleStats {
    /// Count for one category (0 when absent).
    #[must_use]
    pub fn count(&self, c: RuleCategory) -> usize {
        self.per_category.get(&c).copied().unwrap_or(0)
    }
}

/// Compute per-category counts for a Suricata rule set. Comments
/// and blank lines are ignored; every rule line is classified.
#[must_use]
pub fn rule_stats(rules_text: &str) -> RuleStats {
    let mut stats = RuleStats::default();
    for line in rules_text.lines() {
        if !is_rule_line(line) {
            continue;
        }
        let cat = RuleCategory::classify(line);
        *stats.per_category.entry(cat).or_insert(0) += 1;
        stats.total += 1;
    }
    stats
}

/// Drop every rule whose category is not enabled by `selection`,
/// preserving comments, blank lines, and the relative order of the
/// surviving rules. Returns the filtered rule text and the stats of
/// what was *kept*.
///
/// This is the single enforcement point for per-tenant / per-org
/// category enablement: the Go control plane calls the equivalent
/// logic at compile time, and the edge applies it again on a hot
/// swap, so the two never drift.
#[must_use]
pub fn filter_rules_by_category(
    rules_text: &str,
    selection: &CategorySelection,
) -> (String, RuleStats) {
    let mut kept = String::with_capacity(rules_text.len());
    let mut stats = RuleStats::default();
    for line in rules_text.lines() {
        if !is_rule_line(line) {
            // Preserve comments / blanks verbatim so the staged file
            // stays human-diffable against the upstream feed.
            kept.push_str(line);
            kept.push('\n');
            continue;
        }
        let cat = RuleCategory::classify(line);
        if selection.is_enabled(cat) {
            kept.push_str(line);
            kept.push('\n');
            *stats.per_category.entry(cat).or_insert(0) += 1;
            stats.total += 1;
        }
    }
    (kept, stats)
}

/// A configured upstream rule feed the scheduler pulls on a timer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleFeed {
    /// Operator-facing feed name (`"et-open"`, `"talos"`, `"org-custom"`).
    pub name: String,
    /// URL the [`RuleFeedFetcher`] pulls the signed bundle from.
    pub url: String,
    /// Provenance recorded on the resulting rules.
    pub source: RuleSource,
    /// Trust-store key id the fetched bundle must be signed with.
    pub signing_key_id: IpsSigningKeyId,
}

/// Fetches a signed rule bundle for a feed.
///
/// The HTTP (or file, or `sng-comms`) transport lives behind this trait so the
/// scheduler — and its merge/verify/stage logic — is unit-testable without a
/// network. Production wires a concrete implementation at the agent's I/O edge;
/// this crate intentionally does not pull in an HTTP client (matching the
/// existing boundary where rule pulls arrive over `sng-comms`).
#[async_trait]
pub trait RuleFeedFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch the current signed bundle for `feed`. Returns
    /// [`IpsError::RuleFeedFetch`] on a transport failure so the
    /// scheduler can record a per-feed miss and continue.
    async fn fetch(&self, feed: &RuleFeed) -> Result<IpsRuleBundle, IpsError>;
}

/// Outcome of pulling one feed during a scheduler run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedOutcome {
    /// The feed name this outcome is for.
    pub feed: String,
    /// `Ok(version)` when the feed was fetched + verified; `Err`
    /// message when it failed (fetch error, bad signature, decode).
    pub result: Result<u64, String>,
}

/// Summary of one [`RuleUpdateScheduler::run_once`] pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleUpdateReport {
    /// Per-feed fetch/verify outcomes, in feed-config order.
    pub feeds: Vec<FeedOutcome>,
    /// Whether the merged rule set changed and was staged this run.
    /// `false` means every reachable feed was byte-identical to the
    /// installed set (no swap, no Suricata reload).
    pub installed: bool,
    /// The merged revision that is now staged (the scheduler's own
    /// monotonic counter, independent of any single feed version).
    /// `None` when nothing has ever been installed.
    pub revision: Option<u64>,
    /// Per-category counts of the merged + filtered rule set that is
    /// now live (empty when nothing was installed this run).
    pub stats: RuleStats,
}

/// Drives the daily pull → verify → merge → filter → stage → reload
/// lifecycle across all configured feeds.
///
/// ## Merge + revision model
///
/// A single Suricata instance reads one rule file, so the scheduler merges all
/// feeds into one set (feeds applied in config order; exact-duplicate rule
/// lines de-duplicated, first occurrence wins). The merged set is then filtered
/// through the org-global [`CategorySelection`].
///
/// The staleness guard on [`RuleStager`] is keyed on a single monotonic
/// version, but per-feed versions can move independently, so the scheduler does
/// **not** forward a feed version to the stager. Instead it hashes the merged +
/// filtered text and keeps its own `revision` counter: the counter increments
/// (and a swap happens) only when the merged content actually changes. This
/// means a bump in *any* feed triggers exactly one reload, and a run where
/// nothing changed is a cheap no-op — neither of which a max-of-feed-versions
/// scheme gets right.
///
/// ## Failure isolation
///
/// One unreachable or badly-signed feed does not abort the run: its
/// [`FeedOutcome`] records the error and the merge proceeds with the feeds that
/// did verify. A run where *every* feed failed makes no change (the installed
/// set is retained), matching the fail-static posture the rest of the IPS
/// subsystem uses.
#[derive(Clone)]
pub struct RuleUpdateScheduler {
    feeds: Vec<RuleFeed>,
    fetcher: Arc<dyn RuleFeedFetcher>,
    verifier: IpsRuleVerifier,
    stager: Arc<dyn RuleStager>,
    selection: Arc<arc_swap::ArcSwap<CategorySelection>>,
    interval: Duration,
    // The merged-content fingerprint of the last successful install,
    // and the scheduler's own monotonic revision. Guarded together
    // so a reader never sees a revision that does not match the hash.
    state: Arc<Mutex<MergeState>>,
}

#[derive(Debug, Default)]
struct MergeState {
    last_hash: Option<[u8; 32]>,
    revision: u64,
}

impl std::fmt::Debug for RuleUpdateScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleUpdateScheduler")
            .field("feeds", &self.feeds.len())
            .field("interval", &self.interval)
            .field("revision", &self.state.lock().revision)
            .finish_non_exhaustive()
    }
}

impl RuleUpdateScheduler {
    /// Build a scheduler. `interval` is the pull cadence the
    /// [`Self::run_forever`] loop uses (typically 24h); `run_once`
    /// ignores it so tests drive pulls directly.
    #[must_use]
    pub fn new(
        feeds: Vec<RuleFeed>,
        fetcher: Arc<dyn RuleFeedFetcher>,
        verifier: IpsRuleVerifier,
        stager: Arc<dyn RuleStager>,
        selection: CategorySelection,
        interval: Duration,
    ) -> Self {
        Self {
            feeds,
            fetcher,
            verifier,
            stager,
            selection: Arc::new(arc_swap::ArcSwap::from_pointee(selection)),
            interval,
            state: Arc::new(Mutex::new(MergeState::default())),
        }
    }

    /// Hot-swap the org-global category selection. The next
    /// [`Self::run_once`] re-filters the merged set against it; if the
    /// filtered text changes, the new set is staged and reloaded.
    pub fn set_selection(&self, selection: CategorySelection) {
        self.selection.store(Arc::new(selection));
    }

    /// The scheduler's current merged revision (0 before the first
    /// successful install).
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.state.lock().revision
    }

    /// Pull every feed once, merge + verify + filter, and stage the
    /// result if it changed. Returns a [`RuleUpdateReport`].
    ///
    /// Never errors at the top level: transport / signature failures are
    /// captured per-feed in the report. A hard error is only returned if the
    /// stager itself fails to swap a set that *did* change (validation failure,
    /// disk error) — that is a real install failure the caller must surface.
    pub async fn run_once(&self) -> Result<RuleUpdateReport, IpsError> {
        let mut outcomes = Vec::with_capacity(self.feeds.len());
        // (source-config-order index, rule text) for feeds that verified.
        let mut verified: Vec<String> = Vec::new();

        for feed in &self.feeds {
            match self.fetch_and_verify(feed).await {
                Ok(claims) => {
                    outcomes.push(FeedOutcome {
                        feed: feed.name.clone(),
                        result: Ok(claims.version),
                    });
                    verified.push(claims.rules_text);
                }
                Err(e) => {
                    outcomes.push(FeedOutcome {
                        feed: feed.name.clone(),
                        result: Err(e.to_string()),
                    });
                }
            }
        }

        // Nothing verified → keep the installed set untouched.
        if verified.is_empty() {
            return Ok(RuleUpdateReport {
                feeds: outcomes,
                installed: false,
                revision: self.installed_revision(),
                stats: RuleStats::default(),
            });
        }

        let merged = merge_rule_texts(&verified);
        let selection = self.selection.load();
        let (filtered, stats) = filter_rules_by_category(&merged, &selection);
        let hash = sha256_bytes(filtered.as_bytes());

        // Unchanged merged content → no swap, no reload.
        {
            let guard = self.state.lock();
            if guard.last_hash == Some(hash) {
                return Ok(RuleUpdateReport {
                    feeds: outcomes,
                    installed: false,
                    revision: Some(guard.revision),
                    stats,
                });
            }
        }

        // Content changed: pick the next revision, stage it, and only
        // commit the hash + revision once the swap succeeds. We hold
        // the next revision as `current + 1`; the stager's own
        // staleness guard then accepts it monotonically.
        let next_rev = self.state.lock().revision + 1;
        let claims = IpsRuleBundleClaims {
            schema_version: 1,
            version: next_rev,
            compiler: "sng-ips/rule-update-scheduler".to_string(),
            rules_text: filtered,
            source: RuleSource::CustomOrg,
        };
        let installed_rev = self.stager.stage_and_swap(&claims).await?;
        {
            let mut guard = self.state.lock();
            guard.last_hash = Some(hash);
            guard.revision = installed_rev;
        }
        Ok(RuleUpdateReport {
            feeds: outcomes,
            installed: true,
            revision: Some(installed_rev),
            stats,
        })
    }

    /// Run [`Self::run_once`] immediately, then every `interval`
    /// thereafter until `shutdown` resolves. Install errors from a
    /// single pass are logged and the loop continues — a transient
    /// disk/validation failure must not kill the daily updater.
    ///
    /// The loop is `select!`-driven so a shutdown signal is honoured
    /// promptly even mid-interval.
    pub async fn run_forever(self, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let mut ticker = tokio::time::interval(self.interval);
        // Skip missed ticks rather than bursting after a long pause.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.run_once().await {
                        tracing::warn!(error = %e, "ips rule update pass failed");
                    }
                }
                res = shutdown.changed() => {
                    // Sender dropped or signalled true → stop.
                    if res.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
    }

    /// Fetch one feed and verify its signature + decode its claims,
    /// asserting the signing key id matches what the feed config
    /// pins (a feed must not be able to ship a bundle signed by a
    /// different — though still trusted — key than the operator
    /// configured for it).
    async fn fetch_and_verify(&self, feed: &RuleFeed) -> Result<IpsRuleBundleClaims, IpsError> {
        let bundle = self.fetcher.fetch(feed).await?;
        if bundle.signing_key_id != feed.signing_key_id {
            return Err(IpsError::RuleSignatureUnknownKey(format!(
                "feed {} expected key {}, bundle signed with {}",
                feed.name,
                feed.signing_key_id.as_str(),
                bundle.signing_key_id.as_str()
            )));
        }
        self.verifier.verify_and_decode(&bundle)
    }

    fn installed_revision(&self) -> Option<u64> {
        let r = self.state.lock().revision;
        if r == 0 { None } else { Some(r) }
    }
}

/// Merge rule texts from multiple feeds: concatenate in order,
/// dropping exact-duplicate rule lines (first occurrence wins) so two
/// feeds shipping the same community rule do not double-load it.
/// Comments and blank lines are preserved per source.
fn merge_rule_texts(texts: &[String]) -> String {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = String::new();
    for text in texts {
        for line in text.lines() {
            if is_rule_line(line) {
                let key = line.trim().to_string();
                if !seen.insert(key) {
                    continue; // duplicate rule line
                }
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// SHA-256 of a byte slice as a fixed 32-byte array.
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
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
            source: RuleSource::CustomOrg,
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

    // ---------------------------------------------------------------------
    // Step 2: multi-source / categorisation / scheduler tests.
    // ---------------------------------------------------------------------

    #[test]
    fn rule_source_strings_and_serde_default() {
        assert_eq!(RuleSource::EmergingThreats.as_str(), "emerging_threats");
        assert_eq!(RuleSource::SuricataUpdate.as_str(), "suricata_update");
        assert_eq!(RuleSource::CustomOrg.as_str(), "custom_org");
        assert_eq!(RuleSource::default(), RuleSource::CustomOrg);
    }

    #[test]
    fn claims_decode_defaults_source_when_absent() {
        // A bundle body written by an older control plane that has no
        // `src` key must still decode, defaulting to CustomOrg. We
        // build such a body by serializing a struct that omits the
        // field via a serde_json round-trip into msgpack of the older
        // shape is awkward; instead assert the serde default attribute
        // by decoding a map missing the key.
        #[derive(Serialize)]
        struct OldClaims {
            #[serde(rename = "v")]
            schema_version: u8,
            #[serde(rename = "rev")]
            version: u64,
            #[serde(rename = "comp")]
            compiler: String,
            #[serde(rename = "rules")]
            rules_text: String,
        }
        let old = OldClaims {
            schema_version: 1,
            version: 7,
            compiler: "old/0".into(),
            rules_text: "# empty\n".into(),
        };
        let body = rmp_serde::to_vec_named(&old).unwrap();
        let decoded = IpsRuleBundleClaims::from_body(&body).unwrap();
        assert_eq!(decoded.version, 7);
        assert_eq!(decoded.source, RuleSource::CustomOrg);
    }

    #[test]
    fn claims_roundtrip_preserves_source() {
        let mut c = sample_claims(3);
        c.source = RuleSource::EmergingThreats;
        let body = c.encode().unwrap();
        let back = IpsRuleBundleClaims::from_body(&body).unwrap();
        assert_eq!(back.source, RuleSource::EmergingThreats);
    }

    #[test]
    fn extract_option_handles_quoted_and_unquoted() {
        let line = r#"alert tcp any any -> any 80 (msg:"ET MALWARE bad"; classtype:trojan-activity; sid:1; rev:2;)"#
            .to_ascii_lowercase();
        assert_eq!(
            extract_rule_option(&line, "msg").as_deref(),
            Some("et malware bad")
        );
        assert_eq!(
            extract_rule_option(&line, "classtype").as_deref(),
            Some("trojan-activity")
        );
        assert_eq!(extract_rule_option(&line, "sid").as_deref(), Some("1"));
        assert_eq!(extract_rule_option(&line, "nope"), None);
    }

    #[test]
    fn extract_option_respects_token_boundary() {
        // `xclasstype:` must not satisfy a search for `classtype:`.
        let line = "alert ip any any -> any any (xclasstype:foo; sid:9;)".to_ascii_lowercase();
        assert_eq!(extract_rule_option(&line, "classtype"), None);
    }

    #[test]
    fn classify_covers_every_category() {
        let cases = [
            (
                r#"alert http any any -> any any (msg:"ET MALWARE Win32/Trojan"; classtype:trojan-activity; sid:1;)"#,
                RuleCategory::Malware,
            ),
            (
                r#"alert tcp any any -> any any (msg:"ET EXPLOIT Apache Struts RCE CVE-2017-5638"; classtype:web-application-attack; sid:2;)"#,
                RuleCategory::Exploit,
            ),
            (
                r#"alert smb any any -> any any (msg:"ET LATERAL PsExec service install"; sid:3;)"#,
                RuleCategory::LateralMovement,
            ),
            (
                r#"alert dns any any -> any any (msg:"ET CNC beacon"; classtype:command-and-control; sid:4;)"#,
                RuleCategory::C2,
            ),
            (
                r#"alert tls any any -> any any (msg:"ET EXFIL data theft over TLS"; sid:5;)"#,
                RuleCategory::Exfiltration,
            ),
            (
                r#"alert udp any any -> any any (msg:"ET DOS amplification"; classtype:attempted-dos; sid:6;)"#,
                RuleCategory::Dos,
            ),
            (
                r#"alert tcp any any -> any any (msg:"benign traffic note"; classtype:not-suspicious; sid:7;)"#,
                RuleCategory::Other,
            ),
        ];
        for (line, want) in cases {
            assert_eq!(RuleCategory::classify(line), want, "misclassified: {line}");
        }
    }

    #[test]
    fn classify_msg_keywords_match_whole_words_only() {
        // A tactic keyword embedded in an unrelated word must NOT
        // trip the msg-tactic precedence; the rule should fall through
        // to its classtype / fallback instead.
        let cases = [
            // "collateral" must not be read as "lateral".
            (
                r#"alert tcp any any -> any any (msg:"ET POLICY collateral data observed"; classtype:trojan-activity; sid:10;)"#,
                RuleCategory::Malware,
            ),
            // "rc2" (a cipher) must not be read as "c2".
            (
                r#"alert tls any any -> any any (msg:"ET POLICY weak RC2 cipher negotiated"; classtype:not-suspicious; sid:11;)"#,
                RuleCategory::Other,
            ),
            // Genuine whole-word tactics still classify as before.
            (
                r#"alert smb any any -> any any (msg:"ET LATERAL PsExec service install"; classtype:trojan-activity; sid:12;)"#,
                RuleCategory::LateralMovement,
            ),
            (
                r#"alert dns any any -> any any (msg:"ET MALWARE Win32 C2 checkin"; sid:13;)"#,
                RuleCategory::C2,
            ),
        ];
        for (line, want) in cases {
            assert_eq!(RuleCategory::classify(line), want, "misclassified: {line}");
        }
    }

    #[test]
    fn category_from_str_roundtrips() {
        for c in RuleCategory::all() {
            assert_eq!(RuleCategory::from_str_opt(c.as_str()), Some(c));
        }
        assert_eq!(RuleCategory::from_str_opt("bogus"), None);
    }

    #[test]
    fn category_selection_enable_disable() {
        let mut sel = CategorySelection::all_enabled();
        assert!(sel.is_enabled(RuleCategory::Malware));
        sel.disable(RuleCategory::Dos);
        assert!(!sel.is_enabled(RuleCategory::Dos));
        sel.enable(RuleCategory::Dos);
        assert!(sel.is_enabled(RuleCategory::Dos));

        let none = CategorySelection::none_enabled();
        assert!(RuleCategory::all().iter().all(|c| !none.is_enabled(*c)));

        let some = CategorySelection::from_enabled([RuleCategory::C2, RuleCategory::Malware]);
        assert_eq!(
            some.enabled_categories(),
            vec![RuleCategory::Malware, RuleCategory::C2]
        );
    }

    const SAMPLE_RULES: &str = r#"# header comment
alert http any any -> any any (msg:"ET MALWARE trojan"; classtype:trojan-activity; sid:1;)
alert tcp any any -> any any (msg:"ET EXPLOIT CVE-2021-44228 log4j"; classtype:attempted-admin; sid:2;)
alert dns any any -> any any (msg:"ET CNC check-in"; classtype:command-and-control; sid:3;)

alert udp any any -> any any (msg:"ET DOS flood"; classtype:attempted-dos; sid:4;)
"#;

    #[test]
    fn rule_stats_counts_by_category_ignoring_comments() {
        let stats = rule_stats(SAMPLE_RULES);
        assert_eq!(stats.total, 4);
        assert_eq!(stats.count(RuleCategory::Malware), 1);
        assert_eq!(stats.count(RuleCategory::Exploit), 1);
        assert_eq!(stats.count(RuleCategory::C2), 1);
        assert_eq!(stats.count(RuleCategory::Dos), 1);
        assert_eq!(stats.count(RuleCategory::Other), 0);
    }

    #[test]
    fn filter_drops_disabled_categories_keeps_comments() {
        let mut sel = CategorySelection::all_enabled();
        sel.disable(RuleCategory::Dos);
        sel.disable(RuleCategory::C2);
        let (filtered, stats) = filter_rules_by_category(SAMPLE_RULES, &sel);
        assert_eq!(stats.total, 2);
        assert!(filtered.contains("# header comment"));
        assert!(filtered.contains("sid:1;")); // malware kept
        assert!(filtered.contains("sid:2;")); // exploit kept
        assert!(!filtered.contains("sid:3;")); // c2 dropped
        assert!(!filtered.contains("sid:4;")); // dos dropped
    }

    #[test]
    fn merge_dedups_identical_rule_lines() {
        let a = "alert tcp any any -> any 1 (msg:\"x\"; sid:1;)\n".to_string();
        let b = "alert tcp any any -> any 1 (msg:\"x\"; sid:1;)\nalert tcp any any -> any 2 (msg:\"y\"; sid:2;)\n".to_string();
        let merged = merge_rule_texts(&[a, b]);
        assert_eq!(merged.matches("sid:1;").count(), 1);
        assert_eq!(merged.matches("sid:2;").count(), 1);
    }

    // ---- Scheduler tests ----

    #[derive(Debug)]
    struct MapFetcher {
        bundles: Mutex<HashMap<String, IpsRuleBundle>>,
        fail: Mutex<BTreeSet<String>>,
    }

    impl MapFetcher {
        fn new() -> Self {
            Self {
                bundles: Mutex::new(HashMap::new()),
                fail: Mutex::new(BTreeSet::new()),
            }
        }
        fn set(&self, feed: &str, bundle: IpsRuleBundle) {
            self.bundles.lock().insert(feed.to_string(), bundle);
        }
        fn set_failing(&self, feed: &str) {
            self.fail.lock().insert(feed.to_string());
        }
    }

    #[async_trait]
    impl RuleFeedFetcher for MapFetcher {
        async fn fetch(&self, feed: &RuleFeed) -> Result<IpsRuleBundle, IpsError> {
            if self.fail.lock().contains(&feed.name) {
                return Err(IpsError::RuleFeedFetch(format!("{} down", feed.name)));
            }
            self.bundles
                .lock()
                .get(&feed.name)
                .cloned()
                .ok_or_else(|| IpsError::RuleFeedFetch(format!("{} has no bundle", feed.name)))
        }
    }

    fn signed_bundle(
        version: u64,
        rules_text: &str,
        source: RuleSource,
        signing: &SigningKey,
        id: IpsSigningKeyId,
    ) -> IpsRuleBundle {
        let claims = IpsRuleBundleClaims {
            schema_version: 1,
            version,
            compiler: "feed/0".into(),
            rules_text: rules_text.into(),
            source,
        };
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

    fn scheduler_harness(
        feeds: Vec<RuleFeed>,
        fetcher: Arc<MapFetcher>,
        verifier: IpsRuleVerifier,
        selection: CategorySelection,
        tmp: &tempfile::TempDir,
    ) -> RuleUpdateScheduler {
        let cfg = RuleStagerConfig {
            final_path: tmp.path().join("sng.rules"),
            staging_dir: tmp.path().join("staging"),
            config_path: tmp.path().join("suricata.yaml"),
        };
        let stager = Arc::new(FsRuleStager::new(cfg, Arc::new(AlwaysValidValidator)));
        RuleUpdateScheduler::new(
            feeds,
            fetcher,
            verifier,
            stager,
            selection,
            Duration::from_secs(86_400),
        )
    }

    #[tokio::test]
    async fn scheduler_pulls_merges_and_installs() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = IpsRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let fetcher = Arc::new(MapFetcher::new());
        fetcher.set(
            "et",
            signed_bundle(
                10,
                "alert http any any -> any any (msg:\"ET MALWARE x\"; classtype:trojan-activity; sid:1;)\n",
                RuleSource::EmergingThreats,
                &signing,
                id.clone(),
            ),
        );
        fetcher.set(
            "org",
            signed_bundle(
                3,
                "alert udp any any -> any any (msg:\"ET DOS y\"; classtype:attempted-dos; sid:2;)\n",
                RuleSource::CustomOrg,
                &signing,
                id.clone(),
            ),
        );
        let feeds = vec![
            RuleFeed {
                name: "et".into(),
                url: "https://feeds.example/et".into(),
                source: RuleSource::EmergingThreats,
                signing_key_id: id.clone(),
            },
            RuleFeed {
                name: "org".into(),
                url: "https://feeds.example/org".into(),
                source: RuleSource::CustomOrg,
                signing_key_id: id.clone(),
            },
        ];
        let tmp = tempfile::tempdir().unwrap();
        let sched = scheduler_harness(
            feeds,
            fetcher.clone(),
            verifier,
            CategorySelection::all_enabled(),
            &tmp,
        );

        let report = sched.run_once().await.unwrap();
        assert!(report.installed);
        assert_eq!(report.revision, Some(1));
        assert_eq!(report.stats.total, 2);
        assert!(report.feeds.iter().all(|f| f.result.is_ok()));
        let on_disk = tokio::fs::read_to_string(tmp.path().join("sng.rules"))
            .await
            .unwrap();
        assert!(on_disk.contains("sid:1;") && on_disk.contains("sid:2;"));

        // Second identical run: no change → no install, same revision.
        let report2 = sched.run_once().await.unwrap();
        assert!(!report2.installed);
        assert_eq!(report2.revision, Some(1));
    }

    #[tokio::test]
    async fn scheduler_reinstalls_when_a_feed_bumps() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = IpsRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let fetcher = Arc::new(MapFetcher::new());
        fetcher.set(
            "et",
            signed_bundle(
                10,
                "alert http any any -> any any (msg:\"a\"; sid:1;)\n",
                RuleSource::EmergingThreats,
                &signing,
                id.clone(),
            ),
        );
        let feeds = vec![RuleFeed {
            name: "et".into(),
            url: "u".into(),
            source: RuleSource::EmergingThreats,
            signing_key_id: id.clone(),
        }];
        let tmp = tempfile::tempdir().unwrap();
        let sched = scheduler_harness(
            feeds,
            fetcher.clone(),
            verifier,
            CategorySelection::all_enabled(),
            &tmp,
        );
        assert!(sched.run_once().await.unwrap().installed);
        assert_eq!(sched.revision(), 1);

        // Feed ships new content → merged hash changes → reinstall.
        fetcher.set(
            "et",
            signed_bundle(
                11,
                "alert http any any -> any any (msg:\"a\"; sid:1;)\nalert http any any -> any any (msg:\"b\"; sid:2;)\n",
                RuleSource::EmergingThreats,
                &signing,
                id.clone(),
            ),
        );
        let report = sched.run_once().await.unwrap();
        assert!(report.installed);
        assert_eq!(report.revision, Some(2));
    }

    #[tokio::test]
    async fn scheduler_isolates_a_failing_feed() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = IpsRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let fetcher = Arc::new(MapFetcher::new());
        fetcher.set(
            "ok",
            signed_bundle(
                1,
                "alert http any any -> any any (msg:\"a\"; sid:1;)\n",
                RuleSource::EmergingThreats,
                &signing,
                id.clone(),
            ),
        );
        fetcher.set_failing("down");
        let feeds = vec![
            RuleFeed {
                name: "ok".into(),
                url: "u".into(),
                source: RuleSource::EmergingThreats,
                signing_key_id: id.clone(),
            },
            RuleFeed {
                name: "down".into(),
                url: "u".into(),
                source: RuleSource::SuricataUpdate,
                signing_key_id: id.clone(),
            },
        ];
        let tmp = tempfile::tempdir().unwrap();
        let sched = scheduler_harness(
            feeds,
            fetcher,
            verifier,
            CategorySelection::all_enabled(),
            &tmp,
        );
        let report = sched.run_once().await.unwrap();
        // The good feed still installed; the bad feed is recorded as an error.
        assert!(report.installed);
        let down = report.feeds.iter().find(|f| f.feed == "down").unwrap();
        assert!(down.result.is_err());
        let ok = report.feeds.iter().find(|f| f.feed == "ok").unwrap();
        assert!(ok.result.is_ok());
    }

    #[tokio::test]
    async fn scheduler_rejects_feed_key_mismatch() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = IpsRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let other_id = IpsSigningKeyId::new("ffffffffffffffff").unwrap();
        let fetcher = Arc::new(MapFetcher::new());
        // Bundle signed key id differs from the feed's pinned key id.
        fetcher.set(
            "et",
            signed_bundle(
                1,
                "alert http any any -> any any (msg:\"a\"; sid:1;)\n",
                RuleSource::EmergingThreats,
                &signing,
                other_id,
            ),
        );
        let feeds = vec![RuleFeed {
            name: "et".into(),
            url: "u".into(),
            source: RuleSource::EmergingThreats,
            signing_key_id: id.clone(),
        }];
        let tmp = tempfile::tempdir().unwrap();
        let sched = scheduler_harness(
            feeds,
            fetcher,
            verifier,
            CategorySelection::all_enabled(),
            &tmp,
        );
        let report = sched.run_once().await.unwrap();
        assert!(!report.installed);
        assert!(report.feeds[0].result.is_err());
    }

    #[tokio::test]
    async fn scheduler_applies_selection_change_on_next_run() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = IpsRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let fetcher = Arc::new(MapFetcher::new());
        fetcher.set(
            "et",
            signed_bundle(
                1,
                "alert http any any -> any any (msg:\"ET MALWARE x\"; classtype:trojan-activity; sid:1;)\nalert udp any any -> any any (msg:\"ET DOS y\"; classtype:attempted-dos; sid:2;)\n",
                RuleSource::EmergingThreats,
                &signing,
                id.clone(),
            ),
        );
        let feeds = vec![RuleFeed {
            name: "et".into(),
            url: "u".into(),
            source: RuleSource::EmergingThreats,
            signing_key_id: id.clone(),
        }];
        let tmp = tempfile::tempdir().unwrap();
        let sched = scheduler_harness(
            feeds,
            fetcher,
            verifier,
            CategorySelection::all_enabled(),
            &tmp,
        );
        assert_eq!(sched.run_once().await.unwrap().stats.total, 2);

        // Disable DoS → next run re-filters, drops sid:2, reinstalls.
        let mut sel = CategorySelection::all_enabled();
        sel.disable(RuleCategory::Dos);
        sched.set_selection(sel);
        let report = sched.run_once().await.unwrap();
        assert!(report.installed);
        assert_eq!(report.stats.total, 1);
        let on_disk = tokio::fs::read_to_string(tmp.path().join("sng.rules"))
            .await
            .unwrap();
        assert!(on_disk.contains("sid:1;") && !on_disk.contains("sid:2;"));
    }
}

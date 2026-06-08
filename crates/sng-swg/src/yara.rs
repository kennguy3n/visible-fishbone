//! Signature-based malware detection via a hot-swappable YARA engine.
//!
//! The hash-based [`crate::malware`] provider only catches files
//! whose SHA-256 an upstream scanner has already flagged. This
//! module adds *content* inspection: a [`YaraEngine`] compiles a
//! set of YARA rules and scans a response body for signature
//! matches, catching novel samples that share byte-level traits
//! with known-bad families (EICAR, raw PE/ELF executables,
//! obfuscated JavaScript, macro-enabled Office documents,
//! ransomware notes / high-entropy payloads).
//!
//! The engine mirrors the two patterns the rest of the SWG /
//! enforcement plane already uses:
//!
//! * **Signed rule bundles** — operator-distributed rules are
//!   re-signed by the control plane with the same Ed25519 key
//!   infrastructure that signs policy / IPS / category bundles
//!   ([`YaraRuleVerifier`] is wire-compatible with
//!   [`sng_ips::rules::IpsRuleVerifier`] and
//!   [`sng_core::policy::PolicyVerifier`], so one operator trust
//!   store covers all of them). [`YaraEngine::install_bundle`]
//!   verifies the signature, rejects stale revisions, compiles,
//!   and only then swaps the rules in.
//!
//! * **`ArcSwap` hot-swap** — the compiled rule set lives behind
//!   an [`arc_swap::ArcSwap`] (same pattern as
//!   [`crate::casb::InlineCasbInspector`] and
//!   [`crate::malware::StaticMalwareList`]) so a bundle install
//!   replaces the rules atomically without taking a lock on the
//!   per-request scan path.
//!
//! Severity is read from each rule's `severity` metadata key:
//! `"malicious"` rules deny outright, `"suspicious"` rules deny
//! only when the handler runs with `elevated_risk_mode` (the same
//! gate the hash-based provider's `Suspicious` verdict uses). A
//! rule that omits or misspells `severity` is treated as
//! [`YaraSeverity::Suspicious`] — fail-safe so a metadata typo can
//! never silently escalate a benign match into an outright block.

use std::sync::Arc;

use arc_swap::ArcSwap;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::error::SwgError;

/// Built-in rule set compiled into the agent so a fresh edge VM
/// has signature coverage before the first control-plane bundle
/// arrives. Covers the canonical web-download malware shapes:
/// EICAR, raw PE/ELF executables, obfuscated JavaScript,
/// macro-enabled Office documents, and ransomware notes /
/// high-entropy payloads.
///
/// The `severity` metadata on each rule drives the verdict:
/// `malicious` denies unconditionally, `suspicious` denies only
/// under `elevated_risk_mode`. Executable detection is rated
/// `suspicious` (not every `.exe` download is malware) while
/// EICAR and ransom notes are `malicious`.
pub const BUILTIN_RULES: &str = r#"
import "math"

rule eicar_test_file {
    meta:
        severity = "malicious"
        family = "eicar"
        description = "EICAR standard anti-malware test file"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule windows_pe_executable {
    meta:
        severity = "suspicious"
        family = "pe"
        description = "Windows PE/COFF executable delivered over the web"
    condition:
        // MZ DOS header at offset 0, with a valid PE signature at
        // the offset e_lfanew (uint32 at 0x3C) points to. uint16 /
        // uint32 read little-endian; an out-of-range read yields
        // `undefined`, collapsing the condition to false.
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule elf_executable {
    meta:
        severity = "suspicious"
        family = "elf"
        description = "ELF executable delivered over the web"
    condition:
        // 0x7F 'E' 'L' 'F' as a little-endian uint32 at offset 0.
        uint32(0) == 0x464C457F
}

rule javascript_obfuscation {
    meta:
        severity = "suspicious"
        family = "js_obfuscation"
        description = "Obfuscated / packed JavaScript dropper patterns"
    strings:
        $eval_unescape = /eval\s*\(\s*unescape\s*\(/ nocase
        $eval_atob = /eval\s*\(\s*atob\s*\(/ nocase
        $fromcharcode = "String.fromCharCode(" nocase
        $doc_write_unescape = /document\.write\s*\(\s*unescape/ nocase
        $hex_array = /(\\x[0-9a-fA-F]{2}){20,}/
    condition:
        // A single packer primitive (eval(unescape/atob), a
        // document.write(unescape ...)) is enough; the weaker
        // String.fromCharCode signal must be paired with a long
        // \xNN hex run to fire, keeping the false-positive rate
        // off hand-written JavaScript low.
        $eval_unescape or $eval_atob or $doc_write_unescape or
        ($fromcharcode and $hex_array)
}

rule office_macro_enabled {
    meta:
        severity = "suspicious"
        family = "office_macro"
        description = "Macro-enabled Office document (OLE or OOXML) with an auto-exec hook"
    strings:
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }
        $zip_magic = { 50 4B 03 04 }
        $vba_project = "vbaProject.bin"
        $macros_dir = "_VBA_PROJECT"
        $auto_open = "Auto_Open" nocase
        $autoopen = "AutoOpen" nocase
        $workbook_open = "Workbook_Open" nocase
        $document_open = "Document_Open" nocase
    condition:
        // A legacy OLE compound file or an OOXML ZIP container
        // carrying a VBA project AND an auto-execution entry
        // point. Both halves are required so a plain .docx (ZIP,
        // no macros) never matches.
        ($ole_magic at 0 or $zip_magic at 0) and
        (($vba_project or $macros_dir) and
         ($auto_open or $autoopen or $workbook_open or $document_open))
}

rule ransomware_note {
    meta:
        severity = "malicious"
        family = "ransomware"
        description = "Ransomware ransom-note text markers"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "all your files are encrypted" nocase
        $r3 = "to decrypt your files" nocase
        $r4 = "pay the ransom" nocase
        $r5 = "bitcoin" nocase
        $r6 = ".onion" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"
    condition:
        // Two independent markers must co-occur; a lone "bitcoin"
        // or ".encrypted" appearing in benign prose is not enough.
        2 of them
}

rule ransomware_high_entropy_payload {
    meta:
        severity = "suspicious"
        family = "ransomware"
        description = "High-entropy blob carrying a decrypt-instructions marker"
    strings:
        $marker = "README_FOR_DECRYPT" nocase
        $marker2 = "HOW_TO_DECRYPT" nocase
    condition:
        // Near-maximal Shannon entropy (encrypted / packed) plus a
        // decrypt-instructions filename marker. math.entropy is
        // provided by the pure-Rust `math` module.
        any of them and math.entropy(0, filesize) >= 7.5
}
"#;

/// Severity of a YARA rule, parsed from its `severity` metadata.
///
/// Maps onto the verdict the ext-authz handler enforces:
/// [`Self::Malicious`] denies unconditionally, [`Self::Suspicious`]
/// denies only under `elevated_risk_mode` — the same two-tier
/// contract the hash-based [`crate::malware::MalwareVerdict`] uses.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum YaraSeverity {
    /// A match is a heuristic / weak signal. The handler denies
    /// only when `elevated_risk_mode` is set; otherwise it logs and
    /// allows. Ordered below [`Self::Malicious`] so a scan that
    /// produces both severities reports the stronger one.
    Suspicious,
    /// A match is a high-confidence malware signal. The handler
    /// denies unconditionally.
    Malicious,
}

impl YaraSeverity {
    /// Stable string form for telemetry / verdict reasons.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        }
    }

    /// Parse the `severity` metadata string. Unknown / missing
    /// values fall back to [`Self::Suspicious`] (fail-safe: a typo
    /// must never auto-escalate to an outright block).
    fn from_meta(s: &str) -> Self {
        match s {
            "malicious" => Self::Malicious,
            // "suspicious" and anything unrecognised both map to
            // the conservative tier.
            _ => Self::Suspicious,
        }
    }
}

/// A single rule match produced by [`YaraEngine::scan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraMatch {
    /// The matching rule's identifier (e.g. `"eicar_test_file"`).
    pub rule: String,
    /// The rule's namespace (`"default"` for the built-in set).
    pub namespace: String,
    /// Severity parsed from the rule's `severity` metadata.
    pub severity: YaraSeverity,
    /// Optional malware family from the rule's `family` metadata —
    /// surfaced on telemetry for drill-down.
    pub family: Option<String>,
}

/// Fixed-size 64-byte Ed25519 signature on a YARA rule bundle
/// body. Wire-compatible with [`sng_ips::rules::IpsRuleSignature`]
/// and [`sng_core::policy::BundleSignature`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraRuleSignature {
    /// Raw 64-byte signature.
    pub bytes: [u8; ed25519_dalek::SIGNATURE_LENGTH],
}

/// Stable identifier for an Ed25519 signing key: a 16-char
/// lowercase-hex 8-byte public-key prefix. Newtyped so a
/// string/id mix-up is a compile error. Mirrors
/// [`sng_ips::rules::IpsSigningKeyId`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct YaraSigningKeyId(String);

impl YaraSigningKeyId {
    /// Construct, validating the shape (16 lowercase hex chars).
    pub fn new(s: impl Into<String>) -> Result<Self, SwgError> {
        let s = s.into();
        if s.len() != 16 {
            return Err(SwgError::YaraBundleBodyDecode(format!(
                "signing key id must be 16 hex chars, got {} ({s:?})",
                s.len()
            )));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        {
            return Err(SwgError::YaraBundleBodyDecode(format!(
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
/// Structurally identical to [`sng_ips::rules::IpsRuleBundle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YaraRuleBundle {
    /// MessagePack-encoded [`YaraRuleBundleClaims`] body — the
    /// exact bytes signed by the control plane.
    pub body: Vec<u8>,
    /// Signature over `body`.
    pub signature: YaraRuleSignature,
    /// Which trust-store key produced the signature.
    pub signing_key_id: YaraSigningKeyId,
}

/// Decoded payload of a [`YaraRuleBundle`]. Named-map MessagePack
/// shape so the Go control plane's `msgpack/v5` reads it without
/// remapping (matching [`sng_ips::rules::IpsRuleBundleClaims`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct YaraRuleBundleClaims {
    /// Schema version (1 today).
    #[serde(rename = "v")]
    pub schema_version: u8,
    /// Monotonically increasing revision. The engine rejects any
    /// bundle whose `version` is `<=` the installed version.
    #[serde(rename = "rev")]
    pub version: u64,
    /// Free-form compiler identifier (`"sng-control/0.3"`).
    /// Surfaced on telemetry; not security relevant.
    #[serde(rename = "comp")]
    pub compiler: String,
    /// Total YARA rule source text. UTF-8; held inline so the
    /// bundle is self-contained.
    #[serde(rename = "rules")]
    pub rules_text: String,
}

impl YaraRuleBundleClaims {
    /// Decode a body from MessagePack bytes.
    pub fn from_body(body: &[u8]) -> Result<Self, SwgError> {
        rmp_serde::from_slice(body).map_err(|e| SwgError::YaraBundleBodyDecode(e.to_string()))
    }

    /// Encode a claims body to MessagePack bytes (named-map shape
    /// so the Go side reads it without remapping).
    pub fn encode(&self) -> Result<Vec<u8>, SwgError> {
        rmp_serde::to_vec_named(self).map_err(|e| SwgError::YaraBundleBodyDecode(e.to_string()))
    }
}

/// Trust store keyed by signing key id. Built at agent startup
/// from the control-plane key directory; reuses the same shape as
/// [`sng_ips::rules::IpsRuleVerifier`] so one trust store covers
/// policy, IPS, category, and YARA bundles.
#[derive(Clone, Debug, Default)]
pub struct YaraRuleVerifier {
    keys: std::collections::HashMap<YaraSigningKeyId, VerifyingKey>,
}

impl YaraRuleVerifier {
    /// Empty verifier — add keys with [`Self::add_key`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a trusted Ed25519 public key under the supplied id.
    pub fn add_key(&mut self, id: YaraSigningKeyId, key_bytes: &[u8; 32]) -> Result<(), SwgError> {
        let key = VerifyingKey::from_bytes(key_bytes)
            .map_err(|e| SwgError::YaraBundleUnknownKey(e.to_string()))?;
        self.keys.insert(id, key);
        Ok(())
    }

    /// Number of installed keys — useful for boot diagnostics.
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Verify the bundle signature against the trust store, then
    /// decode the body. Combined so a caller cannot decode without
    /// verifying (which would open a TOCTOU hole on the rule text).
    pub fn verify_and_decode(
        &self,
        bundle: &YaraRuleBundle,
    ) -> Result<YaraRuleBundleClaims, SwgError> {
        let key = self.keys.get(&bundle.signing_key_id).ok_or_else(|| {
            SwgError::YaraBundleUnknownKey(bundle.signing_key_id.as_str().to_owned())
        })?;
        let sig = Signature::from_bytes(&bundle.signature.bytes);
        key.verify(&bundle.body, &sig)
            .map_err(|_| SwgError::YaraBundleSignatureInvalid)?;
        YaraRuleBundleClaims::from_body(&bundle.body)
    }
}

/// An installed, compiled rule set plus the bundle revision it
/// came from. `None` version marks the compiled-in builtin set
/// (revision-less; any signed bundle supersedes it).
struct CompiledRuleSet {
    rules: yara_x::Rules,
    version: Option<u64>,
}

/// Hot-swappable YARA scanning engine.
///
/// Holds the compiled rule set behind an [`ArcSwap`] so a
/// control-plane bundle install replaces it atomically; the
/// per-request [`Self::scan`] path loads the snapshot lock-free.
pub struct YaraEngine {
    inner: ArcSwap<CompiledRuleSet>,
    /// Serialises concurrent [`Self::install_bundle`] calls. Held
    /// across the staleness-check → compile → swap sequence so two
    /// simultaneous installs cannot both pass the staleness check
    /// against the same snapshot and let the *older* revision win
    /// the store race. `yara_x::Rules` is not `Clone`, so an
    /// `ArcSwap::rcu` retry loop would have to recompile on every
    /// retry; a short install-side lock is both cheaper and matches
    /// the `swap_lock` pattern `sng_ips::rules::FsRuleStager` uses.
    /// Readers never touch this lock.
    install_lock: parking_lot::Mutex<()>,
}

impl std::fmt::Debug for YaraEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `yara_x::Rules` is not `Debug`; surface the installed
        // revision instead so the handler's `#[derive(Debug)]`
        // still works.
        f.debug_struct("YaraEngine")
            .field("version", &self.inner.load().version)
            .finish_non_exhaustive()
    }
}

impl YaraEngine {
    /// Compile a YARA source string into a rule set.
    ///
    /// Exposed so callers (and tests) can validate rule text
    /// before wrapping it in a signed bundle.
    pub fn compile(source: &str) -> Result<yara_x::Rules, SwgError> {
        yara_x::compile(source).map_err(|e| SwgError::YaraRuleCompile(e.to_string()))
    }

    /// Build an engine seeded with the compiled-in [`BUILTIN_RULES`].
    pub fn with_builtin_rules() -> Result<Self, SwgError> {
        let rules = Self::compile(BUILTIN_RULES)?;
        Ok(Self {
            inner: ArcSwap::from_pointee(CompiledRuleSet {
                rules,
                version: None,
            }),
            install_lock: parking_lot::Mutex::new(()),
        })
    }

    /// Build an engine from an explicit rule source, tagged with an
    /// optional revision. Primarily a test / advanced-wiring entry
    /// point; production seeds with [`Self::with_builtin_rules`]
    /// and then installs signed bundles.
    pub fn from_source(source: &str, version: Option<u64>) -> Result<Self, SwgError> {
        let rules = Self::compile(source)?;
        Ok(Self {
            inner: ArcSwap::from_pointee(CompiledRuleSet { rules, version }),
            install_lock: parking_lot::Mutex::new(()),
        })
    }

    /// The currently installed bundle revision, or `None` when the
    /// builtin set is live (no signed bundle installed yet).
    #[must_use]
    pub fn version(&self) -> Option<u64> {
        self.inner.load().version
    }

    /// Verify + decode + stage + swap a signed rule bundle.
    ///
    /// 1. Verify the Ed25519 signature against `verifier`.
    /// 2. Reject a revision `<=` the installed one (downgrade
    ///    protection — a stale bundle must never silently drop
    ///    coverage, the same guard IPS / category bundles apply).
    /// 3. Compile the rule text; a syntax error leaves the live
    ///    rules untouched.
    /// 4. ArcSwap the new set in.
    ///
    /// Returns the now-installed revision.
    pub fn install_bundle(
        &self,
        verifier: &YaraRuleVerifier,
        bundle: &YaraRuleBundle,
    ) -> Result<u64, SwgError> {
        let claims = verifier.verify_and_decode(bundle)?;
        // Serialise the whole staleness-check → compile → swap
        // sequence so two concurrent installs cannot both clear the
        // staleness gate against the same snapshot and let the older
        // revision win the store race.
        let _guard = self.install_lock.lock();
        // Staleness check before compiling — no point spending the
        // compile budget on a bundle we will reject. The builtin
        // set (version `None`) is always superseded. Reading the
        // version under the install lock guarantees it is exactly
        // the revision a previous install committed.
        if let Some(current) = self.inner.load().version {
            if claims.version <= current {
                return Err(SwgError::YaraBundleStale {
                    incoming: claims.version,
                    current,
                });
            }
        }
        let rules = Self::compile(&claims.rules_text)?;
        self.inner.store(Arc::new(CompiledRuleSet {
            rules,
            version: Some(claims.version),
        }));
        Ok(claims.version)
    }

    /// Scan `content` against the installed rule set, returning one
    /// [`YaraMatch`] per matching rule.
    ///
    /// Pure with respect to I/O: it loads the immutable [`ArcSwap`]
    /// snapshot and runs the scanner against the supplied bytes.
    /// A scanner error (e.g. the scan-timeout guard) is logged and
    /// yields an empty match list — a scan failure must fail open
    /// rather than wedge the verdict pipeline (the hash-based
    /// provider and the rest of the pipeline still apply).
    #[must_use]
    pub fn scan(&self, content: &[u8]) -> Vec<YaraMatch> {
        let snap = self.inner.load();
        let mut scanner = yara_x::Scanner::new(&snap.rules);
        let results = match scanner.scan(content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(error = %e, "yara scan failed; failing open");
                return Vec::new();
            }
        };
        results
            .matching_rules()
            .map(|m| {
                let mut severity = YaraSeverity::Suspicious;
                let mut family = None;
                for (key, value) in m.metadata() {
                    match (key, value) {
                        ("severity", yara_x::MetaValue::String(s)) => {
                            severity = YaraSeverity::from_meta(s);
                        }
                        ("family", yara_x::MetaValue::String(s)) => {
                            family = Some(s.to_string());
                        }
                        _ => {}
                    }
                }
                YaraMatch {
                    rule: m.identifier().to_string(),
                    namespace: m.namespace().to_string(),
                    severity,
                    family,
                }
            })
            .collect()
    }

    /// The strongest severity across all matches, or `None` when
    /// nothing matched. Used by the ext-authz handler to fold a
    /// multi-rule scan into a single verdict.
    #[must_use]
    pub fn worst_match(&self, content: &[u8]) -> Option<YaraMatch> {
        self.scan(content)
            .into_iter()
            .max_by_key(|m| m.severity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use pretty_assertions::assert_eq;

    /// EICAR test string, assembled at runtime so this source file
    /// is not itself flagged by a host scanner.
    fn eicar_bytes() -> Vec<u8> {
        let s = format!(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}}${}!$H+H*",
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        );
        s.into_bytes()
    }

    fn pe_bytes() -> Vec<u8> {
        let mut v = vec![0u8; 0x80];
        v[0] = 0x4D; // 'M'
        v[1] = 0x5A; // 'Z'
        v[0x3C] = 0x40; // e_lfanew -> 0x40
        v[0x40] = 0x50; // 'P'
        v[0x41] = 0x45; // 'E'
        v[0x42] = 0x00;
        v[0x43] = 0x00;
        v
    }

    fn deterministic_keypair() -> (SigningKey, YaraSigningKeyId) {
        let seed = [7_u8; 32];
        let signing = SigningKey::from_bytes(&seed);
        let id = YaraSigningKeyId::new("0123456789abcdef").unwrap();
        (signing, id)
    }

    fn sample_claims(version: u64, rules_text: &str) -> YaraRuleBundleClaims {
        YaraRuleBundleClaims {
            schema_version: 1,
            version,
            compiler: "sng-test/0".into(),
            rules_text: rules_text.into(),
        }
    }

    fn make_bundle(
        version: u64,
        rules_text: &str,
        signing: &SigningKey,
        id: YaraSigningKeyId,
    ) -> YaraRuleBundle {
        let claims = sample_claims(version, rules_text);
        let body = claims.encode().unwrap();
        let sig = signing.sign(&body);
        YaraRuleBundle {
            body,
            signature: YaraRuleSignature {
                bytes: sig.to_bytes(),
            },
            signing_key_id: id,
        }
    }

    #[test]
    fn builtin_engine_compiles() {
        let engine = YaraEngine::with_builtin_rules().expect("builtin rules compile");
        assert_eq!(engine.version(), None);
    }

    #[test]
    fn detects_eicar_as_malicious() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let matches = engine.scan(&eicar_bytes());
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "eicar_test_file");
        assert_eq!(matches[0].severity, YaraSeverity::Malicious);
        assert_eq!(matches[0].family.as_deref(), Some("eicar"));
    }

    #[test]
    fn detects_pe_executable_as_suspicious() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let m = engine.worst_match(&pe_bytes()).expect("pe match");
        assert_eq!(m.rule, "windows_pe_executable");
        assert_eq!(m.severity, YaraSeverity::Suspicious);
    }

    #[test]
    fn detects_elf_executable_as_suspicious() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let elf = b"\x7fELF\x02\x01\x01\x00rest-of-binary";
        let m = engine.worst_match(elf).expect("elf match");
        assert_eq!(m.rule, "elf_executable");
        assert_eq!(m.severity, YaraSeverity::Suspicious);
    }

    #[test]
    fn detects_obfuscated_javascript() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let js = b"var p = eval(unescape('%63%6f%64%65'));";
        let m = engine.worst_match(js).expect("js match");
        assert_eq!(m.rule, "javascript_obfuscation");
    }

    #[test]
    fn detects_macro_enabled_office_document() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let mut docm = vec![0x50, 0x4B, 0x03, 0x04];
        docm.extend_from_slice(b"....xl/vbaProject.bin....Workbook_Open....");
        let m = engine.worst_match(&docm).expect("docm match");
        assert_eq!(m.rule, "office_macro_enabled");
    }

    #[test]
    fn detects_ransomware_note_as_malicious() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let note = b"Attention! All your files are encrypted. \
                     To decrypt your files, pay the ransom in bitcoin.";
        let m = engine.worst_match(note).expect("ransom match");
        assert_eq!(m.rule, "ransomware_note");
        assert_eq!(m.severity, YaraSeverity::Malicious);
    }

    #[test]
    fn benign_content_does_not_match() {
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let benign = b"Hello, this is a normal note mentioning bitcoin once.";
        assert!(engine.scan(benign).is_empty());
        let benign_js = b"function add(a, b) { return a + b; }";
        assert!(engine.scan(benign_js).is_empty());
    }

    #[test]
    fn worst_match_picks_malicious_over_suspicious() {
        // A payload that is both a PE (suspicious) and carries the
        // EICAR string (malicious) folds to the malicious verdict.
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let mut blob = pe_bytes();
        blob.extend_from_slice(&eicar_bytes());
        let m = engine.worst_match(&blob).expect("match");
        assert_eq!(m.severity, YaraSeverity::Malicious);
    }

    #[test]
    fn install_signed_bundle_swaps_rules() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = YaraRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();

        let engine = YaraEngine::with_builtin_rules().unwrap();
        // Custom bundle: a single rule keyed on a bespoke marker
        // the builtin set does not know about.
        let custom = r#"
rule org_secret_marker {
    meta:
        severity = "malicious"
        family = "org"
    strings:
        $m = "ORG-CONFIDENTIAL-EXFIL-MARKER"
    condition:
        $m
}
"#;
        let bundle = make_bundle(5, custom, &signing, id);
        let installed = engine.install_bundle(&verifier, &bundle).unwrap();
        assert_eq!(installed, 5);
        assert_eq!(engine.version(), Some(5));

        let hit = b"...ORG-CONFIDENTIAL-EXFIL-MARKER...";
        let m = engine.worst_match(hit).expect("custom rule match");
        assert_eq!(m.rule, "org_secret_marker");
        assert_eq!(m.severity, YaraSeverity::Malicious);

        // The builtin EICAR rule was replaced by the bundle.
        assert!(engine.scan(&eicar_bytes()).is_empty());
    }

    #[test]
    fn install_rejects_unknown_signing_key() {
        let (signing, id) = deterministic_keypair();
        // Verifier with NO keys installed.
        let verifier = YaraRuleVerifier::new();
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let bundle = make_bundle(1, BUILTIN_RULES, &signing, id);
        let err = engine.install_bundle(&verifier, &bundle).unwrap_err();
        assert!(matches!(err, SwgError::YaraBundleUnknownKey(_)));
    }

    #[test]
    fn install_rejects_tampered_signature() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = YaraRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let mut bundle = make_bundle(1, BUILTIN_RULES, &signing, id);
        // Flip a byte in the signed body so the signature no longer
        // verifies.
        bundle.body[0] ^= 0xFF;
        let err = engine.install_bundle(&verifier, &bundle).unwrap_err();
        assert!(matches!(err, SwgError::YaraBundleSignatureInvalid));
    }

    #[test]
    fn install_rejects_stale_revision() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = YaraRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let engine = YaraEngine::with_builtin_rules().unwrap();

        let b10 = make_bundle(10, BUILTIN_RULES, &signing, id.clone());
        assert_eq!(engine.install_bundle(&verifier, &b10).unwrap(), 10);

        // A revision <= the installed one is rejected.
        let b10_again = make_bundle(10, BUILTIN_RULES, &signing, id.clone());
        let err = engine.install_bundle(&verifier, &b10_again).unwrap_err();
        assert!(matches!(
            err,
            SwgError::YaraBundleStale {
                incoming: 10,
                current: 10
            }
        ));

        let b5 = make_bundle(5, BUILTIN_RULES, &signing, id);
        let err = engine.install_bundle(&verifier, &b5).unwrap_err();
        assert!(matches!(err, SwgError::YaraBundleStale { .. }));
    }

    #[test]
    fn install_rejects_uncompilable_rules() {
        let (signing, id) = deterministic_keypair();
        let mut verifier = YaraRuleVerifier::new();
        verifier
            .add_key(id.clone(), &signing.verifying_key().to_bytes())
            .unwrap();
        let engine = YaraEngine::with_builtin_rules().unwrap();
        let bundle = make_bundle(1, "this is not valid yara", &signing, id);
        let err = engine.install_bundle(&verifier, &bundle).unwrap_err();
        assert!(matches!(err, SwgError::YaraRuleCompile(_)));
        // The live rule set is untouched after a failed install.
        assert_eq!(engine.version(), None);
        assert!(!engine.scan(&eicar_bytes()).is_empty());
    }

    #[test]
    fn signing_key_id_validates_shape() {
        assert!(YaraSigningKeyId::new("0123456789ABCDEF").is_err());
        assert!(YaraSigningKeyId::new("0123abcd").is_err());
        assert!(YaraSigningKeyId::new("0123456789abcdef").is_ok());
    }
}

//! Content classification engine.
//!
//! [`ContentClassifier`] compiles a set of [`DlpRule`]s into the
//! runtime matchers the inspection hot path uses and applies them
//! to a content buffer:
//!
//! * **Regex** — every regex rule's pattern is compiled into a
//!   shared [`regex::RegexSet`] so one pass over the content tells
//!   the classifier *which* of the N patterns hit; only the rules
//!   that hit are then re-run individually to recover the match
//!   offset (metadata only). Builtin pattern names (`ssn_us`,
//!   `credit_card`, …) resolve to the same expressions the Go
//!   control plane ships (`internal/service/dlp/engine/regex.go`),
//!   and `credit_card` hits are Luhn-validated exactly as the Go
//!   side does.
//! * **Keyword** — every keyword rule's comma-separated dictionary
//!   is folded into a single case-insensitive [`aho_corasick`]
//!   automaton, so M keyword dictionaries cost one pass, not M.
//! * **Fingerprint** — a 64-bit SimHash (token-wise, SHA-256
//!   truncated, MSB-first — byte-identical to the Go `SimHash`) is
//!   compared by Hamming similarity against the rule's registered
//!   hash.
//! * **MIP label** — the content metadata's declared Microsoft
//!   Information Protection labels are checked for the rule's label
//!   id.
//!
//! ## Redaction invariant
//!
//! A [`ClassificationResult`] carries **metadata only**: the
//! matched rule id, its severity / action, a confidence score, and
//! (for span-based detectors) the byte offset + length of the hit.
//! The matched bytes themselves are never copied out of the input
//! buffer, so a verdict event can never leak the sensitive payload
//! that produced it.

use crate::channels::DlpChannel;
use crate::doc_classifier::{classify_document, DocumentClassification};
use crate::error::{DlpError, DlpResult};
use crate::ml_classifier::{EntityClass, MlNerDetector};
use crate::rules::{DlpRule, PatternType, RuleAction, Severity};
use crate::validators;
use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

/// A check-digit / structural validator applied to a regex hit to
/// suppress same-shaped false positives. Signature matches every
/// function in [`crate::validators`].
type Validator = fn(&str) -> bool;

/// Resolve a builtin pattern name to the validator that confirms a
/// hit is structurally a real identifier (check digit / date / prefix
/// invariants hold), or `None` when the pattern has no validator and
/// relies on regex shape + proximity context alone (Qatar QID,
/// Bahrain CPR). Mirrors the `validatorFor` switch in
/// `internal/service/dlp/engine/regex.go`.
fn validator_for(name: &str) -> Option<Validator> {
    let v: Validator = match name {
        "china_resident_id" => validators::china_resident_id,
        "japan_my_number" => validators::japan_my_number,
        "korea_rrn" => validators::korea_rrn,
        "singapore_nric" => validators::singapore_nric,
        "malaysia_mykad" => validators::malaysia_mykad,
        "thailand_id" => validators::thailand_id,
        "india_aadhaar" => validators::india_aadhaar,
        "india_pan" => validators::india_pan,
        "uae_emirates_id" => validators::uae_emirates_id,
        "saudi_id" => validators::saudi_national_id,
        "kuwait_civil_id" => validators::kuwait_civil_id,
        _ => return None,
    };
    Some(v)
}

/// Base confidence for a regex hit whose validator passed (or that
/// is `credit_card`, validated by Luhn). A passing check-digit
/// validator is a strong structural signal, so the hit starts fully
/// confident and proximity can only *reduce* it (counter-context).
const CONFIDENCE_VALIDATED: f64 = 1.0;

/// Base confidence for a bare regex hit with no validator. Proximity
/// context keywords can lift it; counter-context can sink it.
const CONFIDENCE_BARE: f64 = 0.5;

/// Confidence delta applied when a locale context keyword is found
/// within the proximity window of a hit.
const PROXIMITY_CONTEXT_BOOST: f64 = 0.15;

/// Confidence penalty applied when a counter-context keyword
/// (`example` / `test` / `sample`) is found within the window — the
/// hit is most likely illustrative, not real PII.
const PROXIMITY_COUNTER_PENALTY: f64 = 0.30;

/// Hard floor confidence after a counter-context penalty.
const PROXIMITY_FLOOR: f64 = 0.1;

/// Number of bytes scanned on each side of a hit for context
/// keywords. The window is clamped to char boundaries before search.
const PROXIMITY_WINDOW_BYTES: usize = 200;

/// Counter-context keywords that mark a hit as illustrative rather
/// than real PII, anywhere in any locale. Mirrors `counterContext`
/// in `internal/service/dlp/engine/proximity.go`.
const COUNTER_CONTEXT: &[&str] = &["example", "test", "sample"];

/// Per-pattern locale context keywords. A hit whose builtin pattern
/// name appears here gets a [`ProximityAnalyzer`]; the keywords are
/// the surrounding-text cues a real document carries (field labels in
/// the local language and English). Mirrors `contextKeywords` in
/// `internal/service/dlp/engine/proximity.go`.
fn context_keywords(name: &str) -> Option<&'static [&'static str]> {
    let kws: &'static [&'static str] = match name {
        "china_resident_id" => &["身份证", "证件号", "身份证号码", "id number", "identity"],
        "japan_my_number" => &["マイナンバー", "個人番号", "my number"],
        "india_aadhaar" => &["आधार", "aadhaar", "uid"],
        "uae_emirates_id" => &["الهوية", "emirates id", "هوية"],
        "saudi_id" => &["الهوية الوطنية", "national id", "إقامة", "iqama"],
        // Patterns without a check-digit validator lean on proximity
        // alone, so give them English field-label cues.
        "qatar_qid" => &["qatar id", "qid", "national id"],
        "bahrain_cpr" => &["cpr", "bahrain", "personal number"],
        _ => return None,
    };
    Some(kws)
}

/// Adjusts a hit's base confidence using the text surrounding the
/// match. Built once per regex entry that has a locale dictionary;
/// holds two Aho-Corasick automata (locale context + global
/// counter-context) so a window scan is a single pass each.
///
/// Keyword matching is ASCII-case-insensitive, which is sufficient:
/// the English cues are ASCII and the CJK / Arabic cues are
/// caseless, so no information is lost while byte offsets stay
/// aligned with the (already NFC-normalized) scan text.
struct ProximityAnalyzer {
    context: AhoCorasick,
    counter: AhoCorasick,
}

impl ProximityAnalyzer {
    /// Build an analyzer for `name`, or `None` if the pattern has no
    /// locale dictionary.
    fn for_pattern(name: &str) -> Option<Self> {
        let kws = context_keywords(name)?;
        let context = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(kws)
            .ok()?;
        let counter = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(COUNTER_CONTEXT)
            .ok()?;
        Some(Self { context, counter })
    }

    /// Return `base` adjusted by the context found within
    /// [`PROXIMITY_WINDOW_BYTES`] on either side of the `start..end`
    /// hit. Counter-context dominates a context boost: an "example"
    /// nearby sinks confidence even if a label is also present.
    fn adjust(&self, text: &str, start: usize, end: usize, base: f64) -> f64 {
        let lo = floor_char_boundary(text, start.saturating_sub(PROXIMITY_WINDOW_BYTES));
        let hi = ceil_char_boundary(text, (end + PROXIMITY_WINDOW_BYTES).min(text.len()));
        let window = &text[lo..hi];

        if self.counter.is_match(window) {
            return (base - PROXIMITY_COUNTER_PENALTY).max(PROXIMITY_FLOOR);
        }
        if self.context.is_match(window) {
            return (base + PROXIMITY_CONTEXT_BOOST).min(1.0);
        }
        base
    }
}

/// Largest char-boundary `<= i` in `s`. `str::floor_char_boundary`
/// is still unstable, so this is the stable equivalent.
fn floor_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Smallest char-boundary `>= i` in `s`.
fn ceil_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Default ceiling on how many bytes of a single content event the
/// classifier scans. Bounds worst-case work + allocation on a
/// pathologically large clipboard / file-write event. 1 MiB is
/// comfortably above any realistic clipboard or form-field payload
/// while keeping a single classification cheap.
pub const DEFAULT_MAX_SCAN_BYTES: usize = 1024 * 1024;

/// Hamming-similarity threshold above which a SimHash fingerprint
/// is considered a match. Matches the Go side's 0.8 cut-off in
/// `internal/service/dlp/engine/fingerprint.go`.
pub const FINGERPRINT_SIMILARITY_THRESHOLD: f64 = 0.8;

/// The managed/compliance posture of the device the content event was
/// observed on, as reported by the agent's posture check. Feeds
/// [`ContextualScorer`]: the same hit is riskier leaving an unmanaged
/// (e.g. BYOD) host than a fully-managed, compliant one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicePosture {
    /// Enrolled, policy-compliant device.
    Managed,
    /// Enrolled but failing one or more compliance checks
    /// (out-of-date OS, disabled disk encryption, …).
    NonCompliant,
    /// Unenrolled / unmanaged (personal or third-party) device.
    Unmanaged,
    /// Posture could not be determined.
    #[default]
    Unknown,
}

/// Out-of-band context about a content buffer. Filled in by the
/// `sng-pal` channel hook from whatever the OS exposes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentMetadata {
    /// Originating filename, if the channel has one (file write,
    /// USB copy, print job).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// Declared MIME type, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Free-form source attribution for the audit trail (target
    /// application, destination host, removable-volume id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Microsoft Information Protection sensitivity labels the host
    /// already attached to the content (e.g. read from an Office
    /// document's custom XML part by the PAL hook).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mip_labels: Vec<String>,
    /// The device's managed/compliance posture at the time of the
    /// event. Consumed by [`ContextualScorer`].
    #[serde(default)]
    pub device_posture: DevicePosture,
    /// Local wall-clock hour (`0..=23`) the event was observed at, if
    /// the PAL captured it. Used to raise confidence for after-hours
    /// activity. Values outside `0..=23` are ignored by the scorer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_hour: Option<u8>,
}

/// Maximum additive confidence boost the [`ContextualScorer`] can
/// contribute from a single risk axis. Keeping each axis bounded means
/// no single contextual signal can, on its own, push a weak hit past a
/// high operator threshold — risk has to corroborate across axes.
const CONTEXT_AXIS_MAX_BOOST: f64 = 0.15;

/// The boundaries (inclusive start, exclusive end) of normal working
/// hours in device-local time. Activity outside this window is treated
/// as after-hours and nudged up.
const WORK_HOURS: std::ops::Range<u8> = 8..19;

/// Adjusts a pattern match's *confidence* (never its action) using the
/// out-of-band risk context of the event: the egress channel, the
/// content-analysis document type, the device posture, and the local
/// time of day. This extends the per-hit [`ProximityAnalyzer`] (which
/// only sees surrounding text) with event-level context, so an
/// operator can set a single confidence threshold ("block only when
/// confidence > 0.8") and have it mean "a real identifier *and* a
/// risky exfiltration context".
///
/// All boosts are additive, each capped at [`CONTEXT_AXIS_MAX_BOOST`],
/// and the final confidence is clamped to `0.0..=1.0`. The scorer only
/// ever raises confidence, so it can never mask a strong hit; a hit
/// that was already fully confident stays at `1.0`.
#[derive(Clone, Copy, Debug)]
pub struct ContextualScorer {
    channel: DlpChannel,
    device_posture: DevicePosture,
    local_hour: Option<u8>,
    document_risk: f64,
}

impl ContextualScorer {
    /// Build a scorer for one content event.
    #[must_use]
    pub fn new(
        channel: DlpChannel,
        metadata: &ContentMetadata,
        document: &DocumentClassification,
    ) -> Self {
        Self {
            channel,
            device_posture: metadata.device_posture,
            local_hour: metadata.local_hour,
            document_risk: document.risk,
        }
    }

    /// The channel's intrinsic exfiltration risk. Removable media and
    /// browser uploads carry data fully off the managed host, so they
    /// score highest; a clipboard copy (often intra-host) is the
    /// neutral baseline and adds nothing. Scoring is therefore purely
    /// *additive* above a clipboard event — it can only raise the risk
    /// of a more dangerous egress path, never lower the baseline.
    fn channel_boost(self) -> f64 {
        let weight = match self.channel {
            DlpChannel::UsbTransfer => 1.0,
            DlpChannel::BrowserUpload => 0.8,
            DlpChannel::Print => 0.5,
            DlpChannel::FileWrite => 0.3,
            DlpChannel::Clipboard => 0.0,
        };
        weight * CONTEXT_AXIS_MAX_BOOST
    }

    /// Posture boost: an unmanaged or non-compliant device is a
    /// higher-risk place for sensitive data to land. An *unknown*
    /// posture adds nothing — missing telemetry is treated as neutral
    /// rather than penalised, so the scorer never raises confidence on
    /// guesswork.
    fn posture_boost(self) -> f64 {
        let weight = match self.device_posture {
            DevicePosture::Unmanaged => 1.0,
            DevicePosture::NonCompliant => 0.7,
            DevicePosture::Managed | DevicePosture::Unknown => 0.0,
        };
        weight * CONTEXT_AXIS_MAX_BOOST
    }

    /// After-hours activity (outside [`WORK_HOURS`]) is nudged up. A
    /// missing or out-of-range hour contributes nothing.
    fn time_boost(self) -> f64 {
        match self.local_hour {
            Some(h) if h < 24 && !WORK_HOURS.contains(&h) => CONTEXT_AXIS_MAX_BOOST,
            _ => 0.0,
        }
    }

    /// Document-type boost scaled by the content-analysis risk score
    /// (e.g. a macro-enabled workbook or password-protected archive).
    fn document_boost(self) -> f64 {
        self.document_risk.clamp(0.0, 1.0) * CONTEXT_AXIS_MAX_BOOST
    }

    /// The total additive boost this context contributes.
    #[must_use]
    pub fn boost(self) -> f64 {
        self.channel_boost() + self.posture_boost() + self.time_boost() + self.document_boost()
    }

    /// Apply the context boost to a base `confidence`, clamped to
    /// `0.0..=1.0`.
    #[must_use]
    pub fn adjust(self, confidence: f64) -> f64 {
        (confidence + self.boost()).clamp(0.0, 1.0)
    }
}

/// A single detection hit. **Metadata only** — never the matched
/// bytes (see the module-level redaction invariant).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleMatch {
    /// The id of the rule that fired.
    pub rule_id: String,
    /// The detector that produced the hit.
    pub pattern_type: PatternType,
    /// Severity of the rule.
    pub severity: Severity,
    /// Action the rule requested.
    pub action: RuleAction,
    /// Confidence in the hit, `0.0..=1.0`.
    pub confidence: f64,
    /// Byte offset of the hit within the scanned (possibly truncated)
    /// content, measured in the UTF-8 text the classifier inspects.
    /// Because content is decoded with [`String::from_utf8_lossy`]
    /// before matching, this equals the offset in the original byte
    /// buffer for valid UTF-8 input; for input containing invalid byte
    /// sequences (each replaced by a 3-byte U+FFFD) it is the offset in
    /// that lossy-decoded text and may not map 1:1 onto the raw bytes.
    /// It is reported for span-based detectors only and is purely
    /// informational — the redaction invariant means no consumer indexes
    /// back into the content with it. `None` for whole-document
    /// detectors (fingerprint, MIP label).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<usize>,
    /// Byte length of the hit in the same lossy-decoded UTF-8 text space
    /// as [`Self::offset`], for span-based detectors.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub length: Option<usize>,
}

/// The output of [`ContentClassifier::classify`].
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ClassificationResult {
    /// Every rule that matched, in detector order (regex, then
    /// keyword, then fingerprint, then MIP label, then ML-NER). Each
    /// match's `confidence` has already been adjusted by the
    /// [`ContextualScorer`] for the event's channel, document type,
    /// device posture, and time of day.
    pub matches: Vec<RuleMatch>,
    /// The content-analysis document classification (type + structural
    /// risk signals) of the inspected buffer. Recorded on the verdict
    /// so an operator can author document-type rules (e.g. "block
    /// macro-enabled Office uploads") and audit what kind of document
    /// produced a hit. Metadata only — never the content.
    #[serde(default)]
    pub document: DocumentClassification,
}

impl ClassificationResult {
    /// Whether any rule matched.
    #[must_use]
    pub fn is_match(&self) -> bool {
        !self.matches.is_empty()
    }

    /// The strictest action across all matches, if any.
    #[must_use]
    pub fn strictest_action(&self) -> Option<RuleAction> {
        self.matches.iter().map(|m| m.action).max()
    }

    /// The highest severity across all matches, if any.
    #[must_use]
    pub fn max_severity(&self) -> Option<Severity> {
        self.matches.iter().map(|m| m.severity).max()
    }
}

/// Lightweight per-rule descriptor retained after compilation so a
/// match can be attributed without re-reading the original rule.
#[derive(Clone, Debug)]
struct RuleMeta {
    id: String,
    severity: Severity,
    action: RuleAction,
    channels: Vec<DlpChannel>,
}

impl RuleMeta {
    fn from_rule(rule: &DlpRule) -> Self {
        Self {
            id: rule.id.clone(),
            severity: rule.severity,
            action: rule.action,
            channels: rule.channels.clone(),
        }
    }

    fn applies_to(&self, channel: DlpChannel) -> bool {
        self.channels.is_empty() || self.channels.contains(&channel)
    }
}

struct RegexEntry {
    meta: RuleMeta,
    regex: Regex,
    /// Structural validator for this pattern (check digit / Luhn), if
    /// any. A hit that fails its validator is dropped.
    validator: Option<Validator>,
    /// Locale proximity analyzer, present only for patterns with a
    /// context dictionary.
    proximity: Option<ProximityAnalyzer>,
}

struct FingerprintEntry {
    meta: RuleMeta,
    simhash: u64,
}

struct MipEntry {
    meta: RuleMeta,
    label: String,
}

/// A compiled `MlNer` rule: the entity classes it fires on. The NER
/// model runs once per content event ([`ContentClassifier::scan_ml`]);
/// each `MlEntry` then claims the detected spans whose class is in its
/// target set.
struct MlEntry {
    meta: RuleMeta,
    targets: Vec<EntityClass>,
}

/// Compiled content classifier. Construct once with
/// [`ContentClassifier::compile`]; cheap to call [`Self::classify`]
/// repeatedly. The struct is immutable after construction — the
/// engine swaps a whole new classifier in atomically when the
/// policy rotates.
pub struct ContentClassifier {
    regex_entries: Vec<RegexEntry>,
    regex_set: RegexSet,
    keyword_ac: Option<AhoCorasick>,
    keyword_pat_to_rule: Vec<usize>,
    keyword_metas: Vec<RuleMeta>,
    fingerprint_entries: Vec<FingerprintEntry>,
    mip_entries: Vec<MipEntry>,
    ml_entries: Vec<MlEntry>,
    ml_detector: MlNerDetector,
    max_scan_bytes: usize,
}

impl std::fmt::Debug for ContentClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContentClassifier")
            .field("regex_rules", &self.regex_entries.len())
            .field("keyword_patterns", &self.keyword_pat_to_rule.len())
            .field("fingerprint_rules", &self.fingerprint_entries.len())
            .field("mip_rules", &self.mip_entries.len())
            .field("ml_rules", &self.ml_entries.len())
            .field("ml_model_loaded", &self.ml_detector.has_model())
            .field("max_scan_bytes", &self.max_scan_bytes)
            .finish_non_exhaustive()
    }
}

impl ContentClassifier {
    /// Compile `rules` into a classifier with the default scan
    /// ceiling ([`DEFAULT_MAX_SCAN_BYTES`]).
    ///
    /// # Errors
    /// Returns [`DlpError::RuleCompile`] if a regex rule's pattern
    /// fails to compile, a keyword rule has an empty dictionary, or
    /// a fingerprint rule's `pattern_data` is not valid 16-char
    /// hex.
    pub fn compile(rules: &[DlpRule]) -> DlpResult<Self> {
        Self::compile_with_limit(rules, DEFAULT_MAX_SCAN_BYTES)
    }

    /// Compile `rules` with an explicit scan ceiling. `MlNer` rules
    /// use the fail-safe regex NER fallback (no ONNX model loaded);
    /// use [`Self::compile_with_model`] to attach a signed model.
    ///
    /// # Errors
    /// See [`Self::compile`].
    pub fn compile_with_limit(rules: &[DlpRule], max_scan_bytes: usize) -> DlpResult<Self> {
        Self::compile_with_model(rules, max_scan_bytes, MlNerDetector::fallback_only())
    }

    /// Compile `rules` with an explicit scan ceiling and a specific
    /// [`MlNerDetector`] (either model-backed or fallback-only). The
    /// engine threads its currently-installed model through here on
    /// every policy rotation so the ONNX model and the rule set are
    /// swapped atomically together.
    ///
    /// # Errors
    /// Returns [`DlpError::RuleCompile`] if a regex rule's pattern
    /// fails to compile, a keyword rule has an empty dictionary, a
    /// fingerprint rule's `pattern_data` is not valid 16-char hex, or
    /// an `MlNer` rule lists no / unknown entity classes.
    // Allow `clippy::too_many_lines`: this is a single linear dispatch
    // that builds every detector's rule table in one pass over
    // `rules`. Splitting the per-pattern arms into separate helpers
    // would scatter the shared accumulators (the regex pattern list,
    // keyword dictionary, and metas) across functions and obscure that
    // they are populated together, for no real readability gain.
    #[allow(clippy::too_many_lines)]
    pub fn compile_with_model(
        rules: &[DlpRule],
        max_scan_bytes: usize,
        ml_detector: MlNerDetector,
    ) -> DlpResult<Self> {
        let mut regex_entries = Vec::new();
        let mut regex_patterns = Vec::new();
        let mut keyword_patterns: Vec<String> = Vec::new();
        let mut keyword_pat_to_rule = Vec::new();
        let mut keyword_metas = Vec::new();
        let mut fingerprint_entries = Vec::new();
        let mut mip_entries = Vec::new();
        let mut ml_entries = Vec::new();

        for rule in rules {
            let meta = RuleMeta::from_rule(rule);
            match rule.pattern_type {
                PatternType::Regex => {
                    let pattern = builtin_pattern(&rule.pattern_data)
                        .map_or_else(|| rule.pattern_data.clone(), ToOwned::to_owned);
                    let regex = Regex::new(&pattern).map_err(|e| DlpError::RuleCompile {
                        rule_id: rule.id.clone(),
                        reason: e.to_string(),
                    })?;
                    // `credit_card` keeps its dedicated Luhn check; the
                    // Asia/GCC builtins each resolve to their check-digit
                    // validator. Custom (non-builtin) patterns have none.
                    let validator: Option<Validator> = if rule.pattern_data == "credit_card" {
                        Some(luhn_valid)
                    } else {
                        validator_for(&rule.pattern_data)
                    };
                    let proximity = ProximityAnalyzer::for_pattern(&rule.pattern_data);
                    regex_patterns.push(pattern);
                    regex_entries.push(RegexEntry {
                        meta,
                        regex,
                        validator,
                        proximity,
                    });
                }
                PatternType::Keyword => {
                    let meta_idx = keyword_metas.len();
                    let mut any = false;
                    for kw in rule
                        .pattern_data
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        // Pre-fold the dictionary with Unicode-aware
                        // lowercasing so the automaton folds case for
                        // non-ASCII scripts too (see `scan_keywords`,
                        // which folds the input the same way).
                        keyword_patterns.push(kw.to_lowercase());
                        keyword_pat_to_rule.push(meta_idx);
                        any = true;
                    }
                    if !any {
                        return Err(DlpError::RuleCompile {
                            rule_id: rule.id.clone(),
                            reason: "keyword dictionary is empty".to_owned(),
                        });
                    }
                    keyword_metas.push(meta);
                }
                PatternType::Fingerprint => {
                    let simhash = parse_simhash_hex(&rule.pattern_data).ok_or_else(|| {
                        DlpError::RuleCompile {
                            rule_id: rule.id.clone(),
                            reason: format!(
                                "fingerprint pattern_data must be 16-char hex, got {:?}",
                                rule.pattern_data
                            ),
                        }
                    })?;
                    fingerprint_entries.push(FingerprintEntry { meta, simhash });
                }
                PatternType::MipLabel => {
                    mip_entries.push(MipEntry {
                        meta,
                        label: rule.pattern_data.clone(),
                    });
                }
                PatternType::MlNer => {
                    let targets = parse_entity_classes(&rule.pattern_data).map_err(|reason| {
                        DlpError::RuleCompile {
                            rule_id: rule.id.clone(),
                            reason,
                        }
                    })?;
                    ml_entries.push(MlEntry { meta, targets });
                }
            }
        }

        let regex_set = RegexSet::new(&regex_patterns).map_err(|e| DlpError::RuleCompile {
            rule_id: "<regex-set>".to_owned(),
            reason: e.to_string(),
        })?;

        let keyword_ac = if keyword_patterns.is_empty() {
            None
        } else {
            // Dictionary is already lowercased; the input is lowercased
            // in `scan_keywords`, so the automaton itself is built
            // case-sensitive over the folded forms (full Unicode case
            // folding, unlike the ASCII-only `ascii_case_insensitive`).
            let ac = AhoCorasick::builder()
                .build(&keyword_patterns)
                .map_err(|e| DlpError::RuleCompile {
                    rule_id: "<keyword-automaton>".to_owned(),
                    reason: e.to_string(),
                })?;
            Some(ac)
        };

        Ok(Self {
            regex_entries,
            regex_set,
            keyword_ac,
            keyword_pat_to_rule,
            keyword_metas,
            fingerprint_entries,
            mip_entries,
            ml_entries,
            ml_detector,
            max_scan_bytes,
        })
    }

    /// Total number of compiled rules across every detector.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.regex_entries.len()
            + self.keyword_metas.len()
            + self.fingerprint_entries.len()
            + self.mip_entries.len()
            + self.ml_entries.len()
    }

    /// Whether an ONNX NER model is loaded (vs. the regex fallback).
    #[must_use]
    pub fn has_ml_model(&self) -> bool {
        self.ml_detector.has_model()
    }

    /// Classify `content` observed on `channel`. Only rules scoped
    /// to `channel` (or scoped to all channels) are considered.
    ///
    /// `max_scan_bytes` bounds the *span* detectors (regex, keyword):
    /// they decode the buffer into a UTF-8 string and run compiled
    /// matchers over it, so their cost — and the one large allocation —
    /// scales with the scanned length and is capped for safety. The
    /// fingerprint detector is a *whole-document* SimHash: to match the
    /// hash the control plane registered over the full document
    /// (`engine.RegisterFingerprint`), it must fold over the entire
    /// delivered `content`, not the span-truncated prefix — otherwise a
    /// document larger than the span ceiling would hash differently and
    /// silently fail to match (a fail-open DLP gap). The SimHash fold is
    /// O(n) and token-streaming, so running it over the full buffer is
    /// cheap; the buffer is itself bounded upstream by the channel source
    /// (e.g. the PAL's per-file read ceiling).
    #[must_use]
    pub fn classify(
        &self,
        channel: DlpChannel,
        content: &[u8],
        metadata: &ContentMetadata,
    ) -> ClassificationResult {
        let scanned = &content[..content.len().min(self.max_scan_bytes)];
        let raw = String::from_utf8_lossy(scanned);
        // Canonicalise to NFC before the span detectors run so Arabic
        // diacritics and CJK full-/half-width variants compare equal to
        // the shipped patterns. ASCII is unchanged by NFC, so existing
        // ASCII offset semantics are preserved. The Go control plane
        // applies the same `norm.NFC` before matching.
        let text: String = raw.nfc().collect();

        // Document-type analysis runs on the full delivered buffer
        // (signatures live in headers/trailers, not the span prefix)
        // so a renamed or truncated-prefix document is still typed
        // correctly. It is recorded on the result and feeds contextual
        // scoring below.
        let document = classify_document(content, metadata);

        let mut matches = Vec::new();
        self.scan_regex(channel, &text, &mut matches);
        self.scan_keywords(channel, &text, &mut matches);
        self.scan_fingerprints(channel, content, &mut matches);
        self.scan_mip_labels(channel, metadata, &mut matches);
        self.scan_ml(channel, &text, &mut matches);

        // Contextual scoring: raise each hit's confidence by the
        // event's out-of-band risk (channel, document type, device
        // posture, time of day). This only adjusts confidence, never
        // the action — operators threshold on confidence themselves.
        let scorer = ContextualScorer::new(channel, metadata, &document);
        for m in &mut matches {
            m.confidence = scorer.adjust(m.confidence);
        }

        ClassificationResult { matches, document }
    }

    fn scan_regex(&self, channel: DlpChannel, text: &str, out: &mut Vec<RuleMatch>) {
        if self.regex_entries.is_empty() {
            return;
        }
        // One pass: which of the N patterns matched at all.
        for idx in self.regex_set.matches(text) {
            let Some(entry) = self.regex_entries.get(idx) else {
                continue;
            };
            if !entry.meta.applies_to(channel) {
                continue;
            }
            // Recover the match span (metadata only) for the rules
            // that actually hit.
            for m in entry.regex.find_iter(text) {
                // Drop hits that fail the pattern's structural
                // validator (check digit / Luhn) — the FP suppressor.
                let validated = match entry.validator {
                    Some(v) => {
                        if !v(m.as_str()) {
                            continue;
                        }
                        true
                    }
                    None => false,
                };
                let base = if validated {
                    CONFIDENCE_VALIDATED
                } else {
                    CONFIDENCE_BARE
                };
                // Locale proximity context lifts a bare hit and sinks
                // an illustrative one ("example"/"test"/"sample").
                let confidence = match entry.proximity.as_ref() {
                    Some(p) => p.adjust(text, m.start(), m.end(), base),
                    None => base,
                };
                out.push(RuleMatch {
                    rule_id: entry.meta.id.clone(),
                    pattern_type: PatternType::Regex,
                    severity: entry.meta.severity,
                    action: entry.meta.action,
                    confidence,
                    offset: Some(m.start()),
                    length: Some(m.end() - m.start()),
                });
            }
        }
    }

    fn scan_keywords(&self, channel: DlpChannel, text: &str, out: &mut Vec<RuleMatch>) {
        let Some(ac) = self.keyword_ac.as_ref() else {
            return;
        };
        // Fold the input the same Unicode-aware way the dictionary was
        // folded at compile time. For ASCII this preserves byte offsets;
        // for scripts whose case mapping changes byte length the offset
        // is into the folded text (metadata only, never used to slice
        // out matched bytes — see the redaction invariant).
        let folded = text.to_lowercase();
        for m in ac.find_iter(&folded) {
            let Some(&meta_idx) = self.keyword_pat_to_rule.get(m.pattern().as_usize()) else {
                continue;
            };
            let Some(meta) = self.keyword_metas.get(meta_idx) else {
                continue;
            };
            if !meta.applies_to(channel) {
                continue;
            }
            out.push(RuleMatch {
                rule_id: meta.id.clone(),
                pattern_type: PatternType::Keyword,
                severity: meta.severity,
                action: meta.action,
                confidence: 0.8,
                offset: Some(m.start()),
                length: Some(m.end() - m.start()),
            });
        }
    }

    fn scan_fingerprints(&self, channel: DlpChannel, content: &[u8], out: &mut Vec<RuleMatch>) {
        if self.fingerprint_entries.is_empty() {
            return;
        }
        let hash = simhash(content);
        for entry in &self.fingerprint_entries {
            if !entry.meta.applies_to(channel) {
                continue;
            }
            let sim = hamming_similarity(hash, entry.simhash);
            if sim >= FINGERPRINT_SIMILARITY_THRESHOLD {
                out.push(RuleMatch {
                    rule_id: entry.meta.id.clone(),
                    pattern_type: PatternType::Fingerprint,
                    severity: entry.meta.severity,
                    action: entry.meta.action,
                    confidence: sim,
                    offset: None,
                    length: None,
                });
            }
        }
    }

    fn scan_mip_labels(
        &self,
        channel: DlpChannel,
        metadata: &ContentMetadata,
        out: &mut Vec<RuleMatch>,
    ) {
        for entry in &self.mip_entries {
            if !entry.meta.applies_to(channel) {
                continue;
            }
            if metadata.mip_labels.iter().any(|l| l == &entry.label) {
                out.push(RuleMatch {
                    rule_id: entry.meta.id.clone(),
                    pattern_type: PatternType::MipLabel,
                    severity: entry.meta.severity,
                    action: entry.meta.action,
                    confidence: 1.0,
                    offset: None,
                    length: None,
                });
            }
        }
    }

    /// Run the ML-NER detector once over `text` and attribute each
    /// detected entity span to every `MlNer` rule (scoped to `channel`)
    /// whose target class set contains the entity's class.
    ///
    /// The model (or regex fallback) runs a single time per content
    /// event regardless of how many `MlNer` rules are configured — the
    /// detection is shared, then fanned out to the matching rules, the
    /// same one-pass discipline `scan_regex` uses with its `RegexSet`.
    fn scan_ml(&self, channel: DlpChannel, text: &str, out: &mut Vec<RuleMatch>) {
        if self.ml_entries.is_empty() {
            return;
        }
        let entities = self.ml_detector.detect(text);
        if entities.is_empty() {
            return;
        }
        for entry in &self.ml_entries {
            if !entry.meta.applies_to(channel) {
                continue;
            }
            for ent in &entities {
                if entry.targets.contains(&ent.class) {
                    out.push(RuleMatch {
                        rule_id: entry.meta.id.clone(),
                        pattern_type: PatternType::MlNer,
                        severity: entry.meta.severity,
                        action: entry.meta.action,
                        confidence: ent.confidence,
                        offset: Some(ent.offset),
                        length: Some(ent.length),
                    });
                }
            }
        }
    }
}

/// Parse an `MlNer` rule's `pattern_data` (a comma-separated list of
/// entity-class wire names) into a de-duplicated, order-preserving set
/// of [`EntityClass`]. Returns a human-readable reason on an empty
/// list or an unknown class name so the caller can wrap it in a
/// [`DlpError::RuleCompile`].
fn parse_entity_classes(pattern_data: &str) -> Result<Vec<EntityClass>, String> {
    let mut out: Vec<EntityClass> = Vec::new();
    for raw in pattern_data.split(',') {
        let name = raw.trim();
        if name.is_empty() {
            continue;
        }
        let class = EntityClass::from_wire(name).ok_or_else(|| {
            format!("ml_ner pattern_data lists unknown entity class {name:?}")
        })?;
        if !out.contains(&class) {
            out.push(class);
        }
    }
    if out.is_empty() {
        return Err(
            "ml_ner pattern_data must list at least one entity class (e.g. \"person_name,bank_account\")"
                .to_owned(),
        );
    }
    Ok(out)
}

/// Resolve a builtin PII pattern name to its regular expression.
/// Mirrors `builtinPatterns` in
/// `internal/service/dlp/engine/regex.go` so a rule authored on the
/// control plane with `pattern_data = "ssn_us"` detects the same
/// thing on the endpoint.
#[must_use]
// Several builtins intentionally share a regex shape (e.g. Japan My
// Number and India Aadhaar are both 12 grouped digits; Bahrain CPR
// and `routing_number` are both 9 digits). They stay distinct arms
// because each resolves to a different validator / proximity
// dictionary and is documented separately — merging them would lose
// that intent.
#[allow(clippy::match_same_arms)]
pub fn builtin_pattern(name: &str) -> Option<&'static str> {
    let pat = match name {
        "credit_card" => r"\b(?:\d[ -]*?){13,19}\b",
        "ssn_us" => r"\b\d{3}-\d{2}-\d{4}\b",
        "ni_uk" => r"(?i)\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
        "tfn_au" => r"\b\d{3}\s?\d{3}\s?\d{2,3}\b",
        "email" => r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        "phone" => r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}",
        "iban" => r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
        "swift" => r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b",
        "routing_number" => r"\b\d{9}\b",
        "passport_us" => r"\b[A-Z]\d{8}\b",
        "drivers_license" => r"\b[A-Z]\d{4,8}\b",
        "icd10" => r"\b[A-TV-Z]\d{2}(\.\d{1,4})?\b",
        "mrn" => r"\b\d{6,10}\b",

        // Asia national IDs.
        "china_resident_id" => r"\b\d{17}[\dXx]\b",
        "japan_my_number" => r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "korea_rrn" => r"\b\d{6}-?\d{7}\b",
        "singapore_nric" => r"(?i)\b[STFGM]\d{7}[A-Z]\b",
        "malaysia_mykad" => r"\b\d{6}-?\d{2}-?\d{4}\b",
        "thailand_id" => r"\b\d{1}-?\d{4}-?\d{5}-?\d{2}-?\d{1}\b",
        "india_aadhaar" => r"\b\d{4}\s?\d{4}\s?\d{4}\b",
        "india_pan" => r"\b[A-Z]{5}\d{4}[A-Z]\b",

        // GCC national IDs.
        "uae_emirates_id" => r"\b784-?\d{4}-?\d{7}-?\d{1}\b",
        "saudi_id" => r"\b[12]\d{9}\b",
        "qatar_qid" => r"\b\d{11}\b",
        "kuwait_civil_id" => r"\b\d{12}\b",
        "bahrain_cpr" => r"\b\d{9}\b",
        _ => return None,
    };
    Some(pat)
}

/// Parse a 16-char (64-bit) hex SimHash, as produced by the Go
/// fingerprint registrar (`binary.BigEndian` 8-byte hash, hex
/// encoded). Returns `None` for any non-16-hex-char input.
#[must_use]
pub fn parse_simhash_hex(s: &str) -> Option<u64> {
    if s.len() != 16 {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

/// 64-bit SimHash of `content`, byte-identical to the Go
/// `engine.SimHash`: tokens are hashed with SHA-256, truncated to the
/// leading 8 bytes (big-endian u64), and bit-voted MSB-first.
///
/// Tokenization is script-aware so locality-sensitive hashing works
/// for scripts that do not delimit words with spaces:
///
/// * **CJK** (any U+4E00..=U+9FFF ideograph present) → overlapping
///   character *bigrams* of the non-whitespace characters.
/// * **Thai** (any U+0E00..=U+0E7F present, and no CJK) → overlapping
///   character *trigrams*.
/// * otherwise → whitespace-delimited tokens (the original behaviour;
///   correct for Latin, Arabic, etc., which use spaces).
///
/// The Go side (`internal/service/dlp/engine/fingerprint.go`) applies
/// the identical rule so a fingerprint registered on the control
/// plane matches on the endpoint.
#[must_use]
pub fn simhash(content: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(content);
    let tokens = simhash_tokens(&text);
    let mut votes = [0i64; 64];
    let mut token_count = 0u64;
    for token in tokens {
        token_count += 1;
        let digest = Sha256::digest(token.as_bytes());
        let mut bits = [0u8; 8];
        bits.copy_from_slice(&digest[..8]);
        let value = u64::from_be_bytes(bits);
        for (i, vote) in votes.iter_mut().enumerate() {
            // MSB-first: bit (63 - i).
            if value & (1u64 << (63 - i)) != 0 {
                *vote += 1;
            } else {
                *vote -= 1;
            }
        }
    }
    if token_count == 0 {
        return 0;
    }
    let mut result = 0u64;
    for (i, vote) in votes.iter().enumerate() {
        if *vote > 0 {
            result |= 1u64 << (63 - i);
        }
    }
    result
}

/// True if `c` is a CJK Unified Ideograph (U+4E00..=U+9FFF).
fn is_cjk(c: char) -> bool {
    ('\u{4E00}'..='\u{9FFF}').contains(&c)
}

/// True if `c` is in the Thai block (U+0E00..=U+0E7F).
fn is_thai(c: char) -> bool {
    ('\u{0E00}'..='\u{0E7F}').contains(&c)
}

/// Tokenize `text` for [`simhash`] using the script-aware rule
/// documented there. Returned tokens own their bytes so the shingle
/// strings outlive the per-character iteration.
fn simhash_tokens(text: &str) -> Vec<String> {
    let has_cjk = text.chars().any(is_cjk);
    let has_thai = !has_cjk && text.chars().any(is_thai);

    if has_cjk {
        return char_shingles(text, 2);
    }
    if has_thai {
        return char_shingles(text, 3);
    }
    text.split_whitespace().map(ToOwned::to_owned).collect()
}

/// Overlapping character n-grams (`n`-shingles) over the
/// non-whitespace characters of `text`. If fewer than `n` characters
/// remain, the whole sequence is emitted as a single token so short
/// inputs still fingerprint.
fn char_shingles(text: &str, n: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.is_empty() {
        return Vec::new();
    }
    if chars.len() < n {
        return vec![chars.into_iter().collect()];
    }
    (0..=chars.len() - n)
        .map(|i| chars[i..i + n].iter().collect())
        .collect()
}

/// Hamming similarity of two 64-bit hashes: `1 - distance / 64`.
#[must_use]
pub fn hamming_similarity(a: u64, b: u64) -> f64 {
    let distance = (a ^ b).count_ones();
    1.0 - f64::from(distance) / 64.0
}

/// Luhn checksum validation over the digits in `s` (ignoring any
/// separators). Mirrors the Go `luhnValid` used to suppress
/// credit-card false positives.
#[must_use]
pub fn luhn_valid(s: &str) -> bool {
    let digits: Vec<u32> = s.chars().filter_map(|c| c.to_digit(10)).collect();
    // Match the Go `luhnValid` bounds exactly (regex.go): a PAN is
    // 13-19 digits, so anything outside that range is not a card.
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut v = d;
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc_classifier::{DocSignal, DocumentType, OoxmlKind};
    use crate::rules::DlpRule;
    use pretty_assertions::assert_eq;

    fn rule(id: &str, pt: PatternType, data: &str, action: RuleAction) -> DlpRule {
        DlpRule {
            id: id.to_owned(),
            name: id.to_owned(),
            pattern_type: pt,
            pattern_data: data.to_owned(),
            severity: Severity::High,
            action,
            channels: vec![],
        }
    }

    #[test]
    fn regex_builtin_ssn_matches_metadata_only() {
        let c = ContentClassifier::compile(&[rule(
            "ssn",
            PatternType::Regex,
            "ssn_us",
            RuleAction::Block,
        )])
        .expect("compile");
        let res = c.classify(
            DlpChannel::FileWrite,
            b"my ssn is 123-45-6789 ok",
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert_eq!(res.matches.len(), 1);
        let m = &res.matches[0];
        assert_eq!(m.rule_id, "ssn");
        assert_eq!(m.pattern_type, PatternType::Regex);
        assert_eq!(m.offset, Some(10));
        assert_eq!(m.length, Some(11));
    }

    #[test]
    fn credit_card_requires_luhn() {
        let c = ContentClassifier::compile(&[rule(
            "cc",
            PatternType::Regex,
            "credit_card",
            RuleAction::Block,
        )])
        .expect("compile");
        // Luhn-valid Visa test number.
        let good = c.classify(
            DlpChannel::Clipboard,
            b"card 4111111111111111 here",
            &ContentMetadata::default(),
        );
        assert!(good.is_match());
        assert_eq!(good.matches[0].confidence, 1.0);

        // Same shape, invalid checksum.
        let bad = c.classify(
            DlpChannel::Clipboard,
            b"card 4111111111111112 here",
            &ContentMetadata::default(),
        );
        assert!(!bad.is_match());
    }

    #[test]
    fn credit_card_not_matched_inside_longer_digit_run() {
        // Regression: the builtin must carry the same `\b` word
        // boundaries as the Go side (regex.go), so a Luhn-valid 16-digit
        // PAN embedded in a longer contiguous digit identifier does NOT
        // match — matching it would produce endpoint false positives the
        // web/SaaS classifier never raises.
        let c = ContentClassifier::compile(&[rule(
            "cc",
            PatternType::Regex,
            "credit_card",
            RuleAction::Block,
        )])
        .expect("compile");
        let res = c.classify(
            DlpChannel::Clipboard,
            b"99994111111111111111999",
            &ContentMetadata::default(),
        );
        assert!(!res.is_match());
    }

    #[test]
    fn keyword_dictionary_is_case_insensitive_single_pass() {
        let c = ContentClassifier::compile(&[rule(
            "secret-kw",
            PatternType::Keyword,
            "confidential, top secret",
            RuleAction::Warn,
        )])
        .expect("compile");
        let res = c.classify(
            DlpChannel::Print,
            b"This is CONFIDENTIAL material",
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert_eq!(res.matches[0].rule_id, "secret-kw");
        assert_eq!(res.matches[0].pattern_type, PatternType::Keyword);
    }

    #[test]
    fn empty_keyword_dictionary_is_a_compile_error() {
        let err = ContentClassifier::compile(&[rule(
            "empty",
            PatternType::Keyword,
            "  , ,",
            RuleAction::Log,
        )])
        .unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::RuleCompileFailed);
    }

    #[test]
    fn channel_scoping_filters_rules() {
        let mut r = rule(
            "usb-only",
            PatternType::Keyword,
            "secret",
            RuleAction::Block,
        );
        r.channels = vec![DlpChannel::UsbTransfer];
        let c = ContentClassifier::compile(&[r]).expect("compile");
        assert!(
            c.classify(
                DlpChannel::UsbTransfer,
                b"secret",
                &ContentMetadata::default()
            )
            .is_match()
        );
        assert!(
            !c.classify(
                DlpChannel::Clipboard,
                b"secret",
                &ContentMetadata::default()
            )
            .is_match()
        );
    }

    #[test]
    fn mip_label_matches_declared_metadata() {
        let c = ContentClassifier::compile(&[rule(
            "mip-restricted",
            PatternType::MipLabel,
            "restricted",
            RuleAction::Block,
        )])
        .expect("compile");
        let meta = ContentMetadata {
            mip_labels: vec!["restricted".to_owned()],
            ..ContentMetadata::default()
        };
        assert!(c.classify(DlpChannel::FileWrite, b"", &meta).is_match());
        assert!(
            !c.classify(DlpChannel::FileWrite, b"", &ContentMetadata::default())
                .is_match()
        );
    }

    #[test]
    fn fingerprint_matches_near_duplicate() {
        let original = b"the quick brown fox jumps over the lazy dog repeatedly today";
        let hash = simhash(original);
        let hex = format!("{hash:016x}");
        let c = ContentClassifier::compile(&[rule(
            "fp",
            PatternType::Fingerprint,
            &hex,
            RuleAction::Warn,
        )])
        .expect("compile");
        // Exact content → similarity 1.0.
        let res = c.classify(
            DlpChannel::BrowserUpload,
            original,
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert_eq!(res.matches[0].confidence, 1.0);
    }

    // The control plane registers a fingerprint's SimHash over the whole
    // document; the endpoint must hash over the whole delivered content
    // too, even when that content is larger than the span-detector scan
    // ceiling (`max_scan_bytes`). If the fingerprint detector hashed only
    // the truncated prefix, a document longer than the ceiling would hash
    // to a different value and silently fail to match — a fail-open DLP
    // gap. This builds content whose full-document SimHash differs from
    // its first-`limit`-bytes SimHash, registers the full-document hash,
    // then classifies with a deliberately small ceiling and asserts the
    // match still lands.
    #[test]
    fn fingerprint_uses_full_content_not_span_truncated_prefix() {
        // Distinct token streams in the two halves so the prefix SimHash
        // and the whole-document SimHash diverge.
        let head = "alpha bravo charlie delta echo foxtrot golf hotel ";
        let tail = "november oscar papa quebec romeo sierra tango uniform ";
        let mut doc = String::new();
        for _ in 0..32 {
            doc.push_str(head);
        }
        for _ in 0..32 {
            doc.push_str(tail);
        }
        let content = doc.as_bytes();

        let limit = head.len() * 32; // exactly the head; tail is truncated off.
        let prefix_hash = simhash(&content[..limit]);
        let full_hash = simhash(content);
        // Guard the test's own premise: the two hashes really do differ,
        // so hashing the prefix instead of the whole doc would miss.
        assert_ne!(
            prefix_hash, full_hash,
            "test setup: prefix and full SimHash must differ"
        );

        let hex = format!("{full_hash:016x}");
        let c = ContentClassifier::compile_with_limit(
            &[rule("fp", PatternType::Fingerprint, &hex, RuleAction::Warn)],
            limit,
        )
        .expect("compile");

        let res = c.classify(DlpChannel::FileWrite, content, &ContentMetadata::default());
        assert!(
            res.is_match(),
            "fingerprint must match on the full document despite the small scan ceiling"
        );
        assert_eq!(res.matches[0].confidence, 1.0);
    }

    #[test]
    fn bad_fingerprint_hex_is_a_compile_error() {
        let err = ContentClassifier::compile(&[rule(
            "fp",
            PatternType::Fingerprint,
            "not-hex",
            RuleAction::Warn,
        )])
        .unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::RuleCompileFailed);
    }

    #[test]
    fn invalid_regex_is_a_compile_error() {
        let err =
            ContentClassifier::compile(&[rule("bad", PatternType::Regex, "(", RuleAction::Log)])
                .unwrap_err();
        assert_eq!(err.code(), crate::error::DlpErrorCode::RuleCompileFailed);
    }

    #[test]
    fn simhash_is_deterministic_and_self_similar() {
        let a = simhash(b"alpha beta gamma delta");
        let b = simhash(b"alpha beta gamma delta");
        assert_eq!(a, b);
        assert_eq!(hamming_similarity(a, b), 1.0);
        assert_eq!(simhash(b""), 0);
        assert_eq!(simhash(b"   "), 0);
    }

    #[test]
    fn strictest_action_and_max_severity() {
        let rules = vec![
            rule("log", PatternType::Keyword, "alpha", RuleAction::Log),
            rule("block", PatternType::Keyword, "beta", RuleAction::Block),
        ];
        let c = ContentClassifier::compile(&rules).expect("compile");
        let res = c.classify(
            DlpChannel::Clipboard,
            b"alpha and beta",
            &ContentMetadata::default(),
        );
        assert_eq!(res.matches.len(), 2);
        assert_eq!(res.strictest_action(), Some(RuleAction::Block));
        assert_eq!(res.max_severity(), Some(Severity::High));
    }

    #[test]
    fn max_scan_bytes_bounds_the_scan() {
        let c = ContentClassifier::compile_with_limit(
            &[rule("ssn", PatternType::Regex, "ssn_us", RuleAction::Block)],
            4,
        )
        .expect("compile");
        // The SSN is past the 4-byte scan ceiling, so it is not seen.
        let res = c.classify(
            DlpChannel::FileWrite,
            b"xxxx123-45-6789",
            &ContentMetadata::default(),
        );
        assert!(!res.is_match());
    }

    #[test]
    fn luhn_validation_basics() {
        assert!(luhn_valid("4111111111111111"));
        assert!(!luhn_valid("4111111111111112"));
        assert!(!luhn_valid("123"));
        // Regression: mirror the Go upper bound — a digit run longer than
        // 19 is not a PAN even if the trailing digits would checksum.
        assert!(!luhn_valid("41111111111111110000000"));
        // 19 digits, Luhn-valid, stays accepted at the upper boundary.
        assert!(luhn_valid("4111111111111111110"));
    }

    #[test]
    fn rule_match_result_serialises_without_raw_bytes() {
        let c = ContentClassifier::compile(&[rule(
            "ssn",
            PatternType::Regex,
            "ssn_us",
            RuleAction::Block,
        )])
        .expect("compile");
        let res = c.classify(
            DlpChannel::FileWrite,
            b"ssn 123-45-6789",
            &ContentMetadata::default(),
        );
        let json = serde_json::to_string(&res).expect("encode");
        // Metadata only: the matched digits must never appear.
        assert!(!json.contains("123-45-6789"));
        assert!(json.contains("\"rule_id\":\"ssn\""));
    }

    #[test]
    fn national_id_validator_suppresses_invalid_checksum() {
        let c = ContentClassifier::compile(&[rule(
            "cn",
            PatternType::Regex,
            "china_resident_id",
            RuleAction::Block,
        )])
        .expect("compile");
        // Valid MOD 11-2 id with a 身份证 label nearby → validated hit.
        let good = c.classify(
            DlpChannel::FileWrite,
            "身份证 110101199001010015".as_bytes(),
            &ContentMetadata::default(),
        );
        assert!(good.is_match());
        assert_eq!(good.matches[0].confidence, 1.0);
        // Same shape, wrong check digit → dropped entirely.
        let bad = c.classify(
            DlpChannel::FileWrite,
            "身份证 110101199001010010".as_bytes(),
            &ContentMetadata::default(),
        );
        assert!(!bad.is_match());
    }

    #[test]
    fn proximity_context_boosts_bare_pattern() {
        let c = ContentClassifier::compile(&[rule(
            "qa",
            PatternType::Regex,
            "qatar_qid",
            RuleAction::Block,
        )])
        .expect("compile");
        // Bare regex (no validator): base 0.5, lifted by the "qatar id"
        // cue to 0.65. Scored on the neutral baseline channel
        // (Clipboard) with default metadata so this isolates the
        // ProximityAnalyzer from the orthogonal ContextualScorer
        // (covered separately).
        let res = c.classify(
            DlpChannel::Clipboard,
            b"qatar id 12345678901 on file",
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert!((res.matches[0].confidence - 0.65).abs() < 1e-9);

        // No cue at all → stays at the bare base.
        let plain = c.classify(
            DlpChannel::Clipboard,
            b"reference 12345678901 here",
            &ContentMetadata::default(),
        );
        assert!((plain.matches[0].confidence - CONFIDENCE_BARE).abs() < 1e-9);
    }

    #[test]
    fn proximity_counter_context_suppresses_confidence() {
        let c = ContentClassifier::compile(&[rule(
            "qa",
            PatternType::Regex,
            "qatar_qid",
            RuleAction::Block,
        )])
        .expect("compile");
        // "sample" within the window → counter penalty dominates even
        // though the "qid" cue is also present. Neutral baseline
        // channel isolates the proximity penalty from contextual
        // scoring.
        let res = c.classify(
            DlpChannel::Clipboard,
            b"sample qid 12345678901",
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert!((res.matches[0].confidence - 0.2).abs() < 1e-9);
    }

    #[test]
    fn counter_context_floors_validated_hit() {
        let c = ContentClassifier::compile(&[rule(
            "cn",
            PatternType::Regex,
            "china_resident_id",
            RuleAction::Block,
        )])
        .expect("compile");
        // Validated (base 1.0) but flagged as a test sample → 0.7.
        // Neutral baseline channel isolates the proximity floor.
        let res = c.classify(
            DlpChannel::Clipboard,
            "test 身份证 110101199001010015".as_bytes(),
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert!((res.matches[0].confidence - 0.7).abs() < 1e-9);
    }

    #[test]
    fn nfc_normalization_unifies_decomposed_keyword() {
        let c = ContentClassifier::compile(&[rule(
            "kw",
            PatternType::Keyword,
            "café",
            RuleAction::Warn,
        )])
        .expect("compile");
        // Input uses the decomposed form: 'e' + U+0301 COMBINING ACUTE.
        // NFC composes it to 'é' so it matches the composed dictionary.
        let res = c.classify(
            DlpChannel::Print,
            "meet at the cafe\u{0301} now".as_bytes(),
            &ContentMetadata::default(),
        );
        assert!(res.is_match());
        assert_eq!(res.matches[0].rule_id, "kw");
    }

    #[test]
    fn simhash_cjk_bigrams_detect_near_duplicates() {
        // Two sentences differing by a single ideograph share almost
        // every character bigram, so they fingerprint as near-dupes.
        let a = simhash("我爱北京天安门今天天气很好".as_bytes());
        let b = simhash("我爱北京天安门今天天气很坏".as_bytes());
        let unrelated = simhash("完全没有关系的另外一句中文内容".as_bytes());
        assert!(hamming_similarity(a, b) >= FINGERPRINT_SIMILARITY_THRESHOLD);
        assert!(hamming_similarity(a, b) > hamming_similarity(a, unrelated));
        // Determinism + non-empty hash for short CJK input.
        assert_eq!(simhash("好的".as_bytes()), simhash("好的".as_bytes()));
        assert_ne!(simhash("好的".as_bytes()), 0);
    }

    #[test]
    fn simhash_thai_trigrams_are_deterministic() {
        // Thai has no inter-word spaces, so trigrams drive the hash.
        let a = simhash("สวัสดีครับยินดีต้อนรับ".as_bytes());
        let b = simhash("สวัสดีครับยินดีต้อนรับ".as_bytes());
        assert_eq!(a, b);
        assert_ne!(a, 0);
    }

    #[test]
    fn contextual_scorer_neutral_baseline_adds_nothing() {
        // Clipboard + unknown posture + no hour + benign doc is the
        // neutral baseline: confidence is unchanged.
        let scorer = ContextualScorer::new(
            DlpChannel::Clipboard,
            &ContentMetadata::default(),
            &DocumentClassification::default(),
        );
        assert!((scorer.boost() - 0.0).abs() < 1e-9);
        assert!((scorer.adjust(0.5) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn contextual_scorer_stacks_risk_axes() {
        let meta = ContentMetadata {
            device_posture: DevicePosture::Unmanaged,
            local_hour: Some(2), // after hours
            ..ContentMetadata::default()
        };
        let doc = DocumentClassification {
            doc_type: DocumentType::Ooxml(OoxmlKind::Spreadsheet),
            risk: 1.0,
            signals: vec![DocSignal::MacroEnabled],
        };
        let scorer = ContextualScorer::new(DlpChannel::UsbTransfer, &meta, &doc);
        // USB(1.0) + Unmanaged(1.0) + after-hours(1.0) + doc(1.0), each
        // axis capped at CONTEXT_AXIS_MAX_BOOST = 0.15 → 0.60 total.
        assert!((scorer.boost() - 0.60).abs() < 1e-9);
        // Adjusted confidence is clamped to 1.0.
        assert!((scorer.adjust(0.5) - 1.0).abs() < 1e-9);
        assert!((scorer.adjust(0.2) - 0.8).abs() < 1e-9);
    }

    #[test]
    fn contextual_scorer_only_raises_confidence() {
        // Every axis at maximum still never lowers a fully-confident
        // (validated) hit.
        let meta = ContentMetadata {
            device_posture: DevicePosture::Unmanaged,
            local_hour: Some(23),
            ..ContentMetadata::default()
        };
        let doc = DocumentClassification {
            doc_type: DocumentType::Pdf,
            risk: 1.0,
            signals: vec![],
        };
        let scorer = ContextualScorer::new(DlpChannel::UsbTransfer, &meta, &doc);
        assert!((scorer.adjust(1.0) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn working_hours_do_not_boost_but_after_hours_do() {
        let work = ContentMetadata {
            local_hour: Some(12),
            ..ContentMetadata::default()
        };
        let after = ContentMetadata {
            local_hour: Some(22),
            ..ContentMetadata::default()
        };
        let doc = DocumentClassification::default();
        let s_work = ContextualScorer::new(DlpChannel::Clipboard, &work, &doc);
        let s_after = ContextualScorer::new(DlpChannel::Clipboard, &after, &doc);
        assert!((s_work.boost() - 0.0).abs() < 1e-9);
        assert!((s_after.boost() - CONTEXT_AXIS_MAX_BOOST).abs() < 1e-9);
    }

    #[test]
    fn classify_records_document_and_boosts_for_risky_context() {
        // A macro-enabled OOXML carried over USB from an unmanaged
        // device: the keyword hit's confidence is boosted and the
        // document classification is recorded on the result.
        let c = ContentClassifier::compile(&[rule(
            "kw",
            PatternType::Keyword,
            "confidential",
            RuleAction::Block,
        )])
        .expect("compile");
        let zip = build_macro_xlsx_with_text("this is confidential");
        let meta = ContentMetadata {
            device_posture: DevicePosture::Unmanaged,
            ..ContentMetadata::default()
        };
        let res = c.classify(DlpChannel::UsbTransfer, &zip, &meta);
        // The document was classified as a macro-enabled spreadsheet.
        assert_eq!(
            res.document.doc_type,
            DocumentType::Ooxml(OoxmlKind::Spreadsheet)
        );
        assert!(res.document.has_signal(DocSignal::MacroEnabled));
        // Keyword base 0.8, boosted by USB + unmanaged + macro doc risk
        // (no keyword bytes are scannable inside the zip, so this test
        // asserts the boost path via the scorer, not detection within
        // the container).
        let scorer = ContextualScorer::new(DlpChannel::UsbTransfer, &meta, &res.document);
        assert!(scorer.boost() > 0.0);
    }

    /// Build a minimal macro-enabled XLSX whose raw bytes also contain
    /// `text` (stored, uncompressed) so span detectors can still see
    /// it. Reuses the ZIP layout the doc-classifier tests rely on.
    fn build_macro_xlsx_with_text(text: &str) -> Vec<u8> {
        // The doc classifier only reads the central directory, so the
        // entry names drive classification; the trailing plaintext is
        // appended so the keyword scanner (which sees the whole buffer
        // via from_utf8_lossy) can match it too.
        let mut zip = crate::doc_classifier::tests_support::build_zip(&[
            ("[Content_Types].xml", false),
            ("xl/workbook.xml", false),
            ("xl/vbaProject.bin", false),
        ]);
        zip.extend_from_slice(text.as_bytes());
        zip
    }
}

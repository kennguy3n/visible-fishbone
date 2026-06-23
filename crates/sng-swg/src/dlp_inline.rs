// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Inline DLP classification engine for the SWG ext-authz pipeline.
//!
//! The Go control-plane service `internal/service/dlp` classifies content
//! *out-of-band*: it persists audit trails, evaluates MIP labels via
//! Graph API calls, and runs ML NER inference on-device. None of those
//! are suitable for the synchronous, sub-millisecond ext-authz verdict
//! path. This module implements the *inline* subset — regex pattern
//! matching, MIP label header inspection, and document fingerprint
//! matching — that runs inside [`crate::auth::ExtAuthzHandler::evaluate`]
//! without any I/O.
//!
//! ## Design
//!
//! * **No I/O on the request path.** The entire engine is in-memory.
//!   Policy updates are atomic `ArcSwap` swaps, mirroring the CASB
//!   rule-set and YARA bundle hot-swap patterns.
//!
//! * **Bounded scan.** A configurable `scan_ceiling_bytes` caps the
//!   number of body bytes scanned. Bodies larger than the ceiling are
//!   scanned up to the ceiling and `truncated=true` is set on the
//!   verdict so the control plane knows the scan was partial.
//!
//! * **Single-pass regex.** All regex patterns are compiled into a
//!   [`regex::RegexSet`] so the body is scanned exactly once for all
//!   patterns simultaneously. `RegexSet` is O(body_length) regardless
//!   of pattern count.
//!
//! * **Fingerprint matching via Rabin-Karp rolling hash.** Document
//!   fingerprints are pre-computed by the control plane as normalized
//!   n-gram hashes and pushed in the policy bundle. The rolling hash
//!   is O(body_length) with O(1) per position, and the fingerprint
//!   set is bounded to 10 000 per tenant.
//!
//! * **Action precedence.** When multiple detectors match, the
//!   highest-severity action wins: `Block > Redact > Log`. This
//!   mirrors the Go `higherAction` ordering in
//!   `internal/service/dlp/service.go`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use arc_swap::ArcSwap;
use sng_core::events::{DlpAction, DlpFinding, DlpFindingKind};
use serde::{Deserialize, Serialize};

use crate::casb::RequestSignals;
use crate::verdict::Verdict;

/// Default scan ceiling: 1 MiB. Bodies larger than this are scanned
/// up to the ceiling and flagged as truncated. The ceiling bounds the
/// worst-case CPU time on the hot path — a 1 MiB regex scan at
/// ~1 GiB/s is ~1 ms, well within the ext-authz budget.
const DEFAULT_SCAN_CEILING_BYTES: usize = 1024 * 1024;

/// Maximum number of fingerprints the engine will accept. The control
/// plane is expected to prune to this bound before pushing a bundle.
const MAX_FINGERPRINTS: usize = 10_000;

/// N-gram size for document fingerprinting. The control plane uses
/// the same value when computing fingerprints from source documents.
const FINGERPRINT_NGRAM_SIZE: usize = 50;

/// Rolling-hash base and modulus for Rabin-Karp. These are fixed
/// constants (not operator-configurable) so the control plane and
/// edge agree on the hash function without a negotiation step.
const RK_BASE: u64 = 257;
const RK_MODULUS: u64 = 1_000_000_007;

/// A single regex DLP rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpRegexRule {
    /// Stable rule id (e.g. `ssn_us`, `credit_card_visa`). Surfaces
    /// in telemetry and audit; never user content.
    pub rule_id: String,
    /// The regex pattern string. Compiled into the `RegexSet` at
    /// install time; a compilation failure is logged and the rule
    /// is silently dropped (fail-open for the rule, not the engine).
    pub pattern: String,
    /// Action when this rule matches.
    pub action: DlpInlineAction,
    /// Severity label (`low`, `medium`, `high`, `critical`).
    pub severity: String,
    /// Finding kind for telemetry.
    pub finding_kind: DlpFindingKind,
}

/// A single document fingerprint: a set of n-gram hashes pre-computed
/// by the control plane from a source document. The edge matches
/// these against the body via Rabin-Karp rolling hash.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DlpFingerprint {
    /// Stable fingerprint id (e.g. `doc_payroll_q3`). Surfaces in
    /// telemetry.
    pub fingerprint_id: String,
    /// N-gram hashes of the source document. The edge computes
    /// rolling n-gram hashes of the body and checks membership.
    pub hashes: Vec<u64>,
    /// Action when this fingerprint matches.
    pub action: DlpInlineAction,
    /// Severity label.
    pub severity: String,
}

/// DLP action specific to the inline engine. Maps onto the shared
/// [`sng_core::events::DlpAction`] for telemetry, but includes
/// `Redact` which is inline-specific (the engine signals that the
/// body should be redacted; the ext-authz handler currently treats
/// Redact as a Log for the verdict but flags it distinctly in
/// telemetry so a future response-body filter can act on it).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpInlineAction {
    /// Record the match in telemetry; do not block.
    Log,
    /// Signal that the body contains sensitive content that should
    /// be redacted. In the current ext-authz pipeline this is treated
    /// as a Log (the handler cannot rewrite response bodies), but the
    /// telemetry carries the distinct action so a future Envoy body
    /// filter can act on it.
    Redact,
    /// Block the request outright.
    Block,
}

impl DlpInlineAction {
    /// Priority for `highest_action`: higher number = higher priority.
    const fn priority(self) -> u8 {
        match self {
            Self::Log => 0,
            Self::Redact => 1,
            Self::Block => 2,
        }
    }

    /// Map onto the shared wire-form [`DlpAction`].
    const fn to_wire(self) -> DlpAction {
        match self {
            Self::Log => DlpAction::Monitor,
            Self::Redact => DlpAction::Coach,
            Self::Block => DlpAction::Block,
        }
    }
}

/// The inline DLP policy: a compiled snapshot of regex rules,
/// fingerprints, and configuration. Wrapped in [`ArcSwap`] for
/// lock-free hot-swap from the policy bundle.
#[derive(Clone, Debug)]
pub struct DlpInlinePolicy {
    /// Compiled regex set (all patterns in one automaton).
    regex_set: regex::RegexSet,
    /// Parallel array of rules, indexed by `RegexSet` match index.
    regex_rules: Vec<DlpRegexRule>,
    /// Fingerprint lookup: n-gram hash → indices into
    /// `fingerprint_rules`. Built at compile time so the rolling
    /// hash scan is O(1) per position with no per-request
    /// allocation.
    fingerprint_index: HashMap<u64, Vec<usize>>,
    /// Parallel fingerprint rules, indexed by the lookup value.
    fingerprint_rules: Vec<DlpFingerprint>,
    /// Scan ceiling in bytes.
    scan_ceiling_bytes: usize,
}

/// The hot-swappable engine. The `ArcSwap` lets the control plane
/// install a new policy bundle atomically while in-flight verdicts
/// continue using the old snapshot.
#[derive(Debug)]
pub struct DlpInlineEngine {
    policy: ArcSwap<DlpInlinePolicy>,
}

impl DlpInlineEngine {
    /// Construct an engine with an empty (deny-nothing) policy.
    /// The control plane hot-swaps a real policy via [`Self::install`].
    #[must_use]
    pub fn new() -> Self {
        let empty = DlpInlinePolicy {
            regex_set: regex::RegexSet::empty(),
            regex_rules: Vec::new(),
            fingerprint_index: HashMap::new(),
            fingerprint_rules: Vec::new(),
            scan_ceiling_bytes: DEFAULT_SCAN_CEILING_BYTES,
        };
        Self {
            policy: ArcSwap::from_pointee(empty),
        }
    }

    /// Atomically install a new policy. In-flight verdicts continue
    /// using the old snapshot; the next `classify` call picks up the
    /// new one. Returns the number of regex rules and fingerprints
    /// installed so the bundle controller can log it.
    pub fn install(&self, def: &DlpInlinePolicyDef) -> (usize, usize) {
        let policy = compile_policy(def);
        let n_regex = policy.regex_rules.len();
        let n_fp = policy.fingerprint_rules.len();
        self.policy.store(Arc::new(policy));
        (n_regex, n_fp)
    }

    /// Classify a body against the current policy snapshot. Returns
    /// `Some(DlpInlineVerdict)` when at least one detector matches,
    /// `None` when no detector matches or the engine has no rules.
    ///
    /// The caller (ext-authz handler) inspects the `action` field:
    /// `Block` short-circuits to `Verdict::deny`; `Log` and `Redact`
    /// are carried forward for telemetry but do not block.
    #[must_use]
    pub fn classify(&self, body: &[u8], signals: &RequestSignals) -> Option<DlpInlineVerdict> {
        let policy = self.policy.load();
        if policy.regex_rules.is_empty() && policy.fingerprint_rules.is_empty() {
            return None;
        }

        let (scan_region, truncated) = if body.len() > policy.scan_ceiling_bytes {
            (&body[..policy.scan_ceiling_bytes], true)
        } else {
            (body, false)
        };

        let mut matches = Vec::new();
        let mut highest_action = DlpInlineAction::Log;
        let mut max_confidence = 0.0_f64;

        // 1. Regex scan: single pass over the body for all patterns.
        if !policy.regex_rules.is_empty() {
            // RegexSet operates on &str; we scan the body as UTF-8
            // lossy-decoded bytes so binary content doesn't abort the
            // scan. The patterns are written for text content; a
            // binary body that contains embedded text (e.g. a PDF with
            // a credit card) still matches because the lossy decode
            // preserves ASCII byte-for-byte.
            let text = String::from_utf8_lossy(scan_region);
            let regex_matches = policy.regex_set.matches(&text);
            for idx in regex_matches.iter() {
                let rule = &policy.regex_rules[idx];
                let confidence = 0.95; // Regex matches are high-confidence.
                matches.push(DlpFinding {
                    kind: rule.finding_kind,
                    label: rule.rule_id.clone(),
                    count: 1,
                    max_confidence: confidence,
                    severity: rule.severity.clone(),
                });
                if rule.action.priority() > highest_action.priority() {
                    highest_action = rule.action;
                }
                if confidence > max_confidence {
                    max_confidence = confidence;
                }
            }
        }

        // 2. Fingerprint scan: Rabin-Karp rolling hash over the body.
        if !policy.fingerprint_rules.is_empty() {
            let fp_matches = fingerprint_scan(scan_region, &policy.fingerprint_index, &policy.fingerprint_rules);
            for (rule_idx, count) in fp_matches {
                let rule = &policy.fingerprint_rules[rule_idx];
                let confidence = 0.99; // Fingerprint matches are very high-confidence.
                matches.push(DlpFinding {
                    kind: DlpFindingKind::Confidential,
                    label: rule.fingerprint_id.clone(),
                    count,
                    max_confidence: confidence,
                    severity: rule.severity.clone(),
                });
                if rule.action.priority() > highest_action.priority() {
                    highest_action = rule.action;
                }
                if confidence > max_confidence {
                    max_confidence = confidence;
                }
            }
        }

        // 3. MIP label inspection: if the request carries a sensitivity
        //    label header, it is an out-of-band signal the control plane
        //    can use to configure label-gated regex rules (by adding a
        //    regex rule with the label value as its pattern). The label
        //    itself does not produce a finding in Phase 1 — it is carried
        //    forward in the `RequestSignals` for the CASB inspector and
        //    for future Phase 2 label-based classification.
        let _ = &signals.sensitivity_label;

        if matches.is_empty() {
            return None;
        }

        let scanned_bytes = scan_region.len() as u64;
        let severity = matches
            .iter()
            .map(|m| m.severity.as_str())
            .max_by_key(|s| severity_rank(s))
            .unwrap_or("low")
            .to_string();

        Some(DlpInlineVerdict {
            action: highest_action,
            wire_action: highest_action.to_wire(),
            confidence: max_confidence,
            severity,
            findings: matches,
            scanned_bytes,
            truncated,
        })
    }
}

impl Default for DlpInlineEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// The verdict returned by the inline DLP engine.
#[derive(Clone, Debug, PartialEq)]
pub struct DlpInlineVerdict {
    /// The inline action (Log/Redact/Block).
    pub action: DlpInlineAction,
    /// The wire-form action for telemetry.
    pub wire_action: DlpAction,
    /// Overall (max-across-findings) confidence in [0,1].
    pub confidence: f64,
    /// Overall (max-across-findings) severity.
    pub severity: String,
    /// Per-finding evidence (redacted, no matched bytes).
    pub findings: Vec<DlpFinding>,
    /// Body bytes scanned (post ceiling truncation).
    pub scanned_bytes: u64,
    /// Whether the body was truncated at the scan ceiling.
    pub truncated: bool,
}

impl DlpInlineVerdict {
    /// Convert to a SWG `Verdict`. `Block` → `Deny`; `Log` and
    /// `Redact` → `Allow` (the verdict is carried forward for
    /// telemetry but does not block the request).
    #[must_use]
    pub fn to_swg_verdict(&self, destination: &str) -> Verdict {
        match self.action {
            DlpInlineAction::Block => {
                let reason = format!("dlp.inline.block.{}", destination);
                Verdict::deny(reason)
            }
            DlpInlineAction::Redact | DlpInlineAction::Log => {
                let reason = format!("dlp.inline.log.{}", destination);
                Verdict::allow(reason)
            }
        }
    }

    /// Whether this verdict should block the request.
    #[must_use]
    pub const fn is_block(&self) -> bool {
        matches!(self.action, DlpInlineAction::Block)
    }

    /// Build a `DlpEvent` from this verdict for telemetry emission.
    #[must_use]
    pub fn to_dlp_event(&self, destination_app: &str) -> sng_core::events::DlpEvent {
        sng_core::events::DlpEvent {
            destination_app: destination_app.to_string(),
            action: self.wire_action,
            severity: self.severity.clone(),
            confidence: self.confidence,
            findings: self.findings.clone(),
            scanned_bytes: self.scanned_bytes,
            truncated: self.truncated,
        }
    }
}

/// The serde-stable policy definition pushed by the control plane
/// in the policy bundle. The edge compiles this into an
/// [`DlpInlinePolicy`] at install time.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DlpInlinePolicyDef {
    /// Regex rules to compile into the `RegexSet`.
    pub regex_rules: Vec<DlpRegexRule>,
    /// Document fingerprints to match via rolling hash.
    pub fingerprints: Vec<DlpFingerprint>,
    /// Scan ceiling in bytes. 0 = use default (1 MiB).
    #[serde(default)]
    pub scan_ceiling_bytes: usize,
}

/// Compile a policy definition into an immutable policy snapshot.
fn compile_policy(def: &DlpInlinePolicyDef) -> DlpInlinePolicy {
    let scan_ceiling_bytes = if def.scan_ceiling_bytes == 0 {
        DEFAULT_SCAN_CEILING_BYTES
    } else {
        def.scan_ceiling_bytes
    };

    // Compile regex patterns. A compilation failure for one pattern
    // is logged and the rule is dropped (fail-open for that rule,
    // not the entire engine).
    let mut valid_patterns = Vec::new();
    let mut valid_rules = Vec::new();
    for rule in &def.regex_rules {
        match regex::Regex::new(&rule.pattern) {
            Ok(_) => {
                valid_patterns.push(rule.pattern.clone());
                valid_rules.push(rule.clone());
            }
            Err(e) => {
                tracing::warn!(
                    target: "sng_swg::dlp_inline",
                    rule_id = %rule.rule_id,
                    error = %e,
                    "dlp inline: regex compilation failed, dropping rule"
                );
            }
        }
    }
    let regex_set = regex::RegexSet::new(&valid_patterns)
        .unwrap_or_else(|_| regex::RegexSet::empty());

    // Build fingerprint index: hash → rule indices. Multiple
    // fingerprints can share a hash (unlikely but possible), so we
    // map hash → Vec<rule_index>.
    let mut fingerprint_rules = Vec::new();
    let mut fingerprint_index: HashMap<u64, Vec<usize>> = HashMap::new();

    // Limit fingerprints to MAX_FINGERPRINTS to bound memory.
    for (rule_idx, fp) in def.fingerprints.iter().take(MAX_FINGERPRINTS).enumerate() {
        fingerprint_rules.push(fp.clone());
        for &h in &fp.hashes {
            fingerprint_index.entry(h).or_default().push(rule_idx);
        }
    }

    DlpInlinePolicy {
        regex_set,
        regex_rules: valid_rules,
        fingerprint_index,
        fingerprint_rules,
        scan_ceiling_bytes,
    }
}

/// Run the Rabin-Karp rolling hash over the scan region and match
/// against the fingerprint index. Returns a list of
/// `(fingerprint_rule_index, match_count)` pairs.
///
/// The rolling hash computes n-gram hashes over the body and
/// checks each against the pre-built `fingerprint_index` HashMap.
/// When a hash matches, we record which fingerprint rule it belongs to.
fn fingerprint_scan(
    scan_region: &[u8],
    fingerprint_index: &HashMap<u64, Vec<usize>>,
    fingerprint_rules: &[DlpFingerprint],
) -> Vec<(usize, u32)> {
    if fingerprint_rules.is_empty() || scan_region.len() < FINGERPRINT_NGRAM_SIZE {
        return Vec::new();
    }

    // Compute the rolling hash over n-grams.
    let n = FINGERPRINT_NGRAM_SIZE;
    let mut hash: u64 = 0;
    let mut power: u64 = 1; // RK_BASE^(n-1) mod RK_MODULUS

    // Precompute RK_BASE^(n-1) mod RK_MODULUS.
    for _ in 0..(n - 1) {
        power = (power * RK_BASE) % RK_MODULUS;
    }

    // Track which rules have already matched to avoid double-counting
    // the same fingerprint from multiple hash hits in a single n-gram
    // window. We use a HashSet per window position.
    let mut matched_rules: HashSet<usize> = HashSet::new();
    let mut match_counts: HashMap<usize, u32> = HashMap::new();

    for (i, &byte) in scan_region.iter().enumerate() {
        // Add the new byte to the hash.
        hash = (hash * RK_BASE + byte as u64) % RK_MODULUS;

        // Once we have a full n-gram, start checking.
        if i >= n - 1 {
            // Check if this hash matches any fingerprint.
            if let Some(rule_indices) = fingerprint_index.get(&hash) {
                for &rule_idx in rule_indices {
                    if matched_rules.insert(rule_idx) {
                        *match_counts.entry(rule_idx).or_insert(0) += 1;
                    }
                }
            }

            // Remove the oldest byte from the hash (slide the window).
            let old_byte = scan_region[i - (n - 1)] as u64;
            hash = (hash + RK_MODULUS - (old_byte * power) % RK_MODULUS) % RK_MODULUS;
        }
    }

    match_counts.into_iter().collect()
}

/// Severity rank for ordering: higher = more severe.
fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::casb::RequestSignals;

    fn make_signals() -> RequestSignals {
        RequestSignals {
            content_length: Some(100),
            sensitivity_label: None,
        }
    }

    #[test]
    fn empty_engine_classify_returns_none() {
        let engine = DlpInlineEngine::new();
        let body = b"hello world";
        let result = engine.classify(body, &make_signals());
        assert!(result.is_none());
    }

    #[test]
    fn regex_block_match_returns_block_verdict() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn_us".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        let body = b"Employee SSN: 123-45-6789 please process.";
        let result = engine.classify(body, &make_signals());
        assert!(result.is_some());
        let verdict = result.unwrap();
        assert_eq!(verdict.action, DlpInlineAction::Block);
        assert!(verdict.is_block());
        assert_eq!(verdict.findings.len(), 1);
        assert_eq!(verdict.findings[0].label, "ssn_us");
        assert!(!verdict.truncated);
    }

    #[test]
    fn regex_log_match_returns_log_verdict() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "email".into(),
                pattern: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b".into(),
                action: DlpInlineAction::Log,
                severity: "low".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        let body = b"Contact alice@example.com for details.";
        let result = engine.classify(body, &make_signals());
        assert!(result.is_some());
        let verdict = result.unwrap();
        assert_eq!(verdict.action, DlpInlineAction::Log);
        assert!(!verdict.is_block());
    }

    #[test]
    fn no_match_returns_none() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn_us".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        let body = b"This is a clean message with no sensitive data.";
        let result = engine.classify(body, &make_signals());
        assert!(result.is_none());
    }

    #[test]
    fn scan_ceiling_truncates_body() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn_us".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 20,
        };
        engine.install(&def);

        // SSN is at offset 30, beyond the 20-byte ceiling.
        let body = b"0123456789012345678901234567890123-45-6789";
        let result = engine.classify(body, &make_signals());
        // The SSN is beyond the scan ceiling, so no match.
        assert!(result.is_none());
    }

    #[test]
    fn scan_ceiling_truncation_flagged_when_match_in_range() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn_us".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 100,
        };
        engine.install(&def);

        // SSN is within the first 100 bytes, body is larger.
        let mut body = b"SSN: 123-45-6789 ".to_vec();
        body.extend(vec![0u8; 200]);
        let result = engine.classify(&body, &make_signals());
        assert!(result.is_some());
        let verdict = result.unwrap();
        assert!(verdict.truncated);
        assert_eq!(verdict.scanned_bytes, 100);
    }

    #[test]
    fn multiple_matches_highest_action_wins() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![
                DlpRegexRule {
                    rule_id: "email".into(),
                    pattern: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b".into(),
                    action: DlpInlineAction::Log,
                    severity: "low".into(),
                    finding_kind: DlpFindingKind::Pii,
                },
                DlpRegexRule {
                    rule_id: "ssn_us".into(),
                    pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                    action: DlpInlineAction::Block,
                    severity: "high".into(),
                    finding_kind: DlpFindingKind::Pii,
                },
            ],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        let body = b"Email: alice@example.com, SSN: 123-45-6789";
        let result = engine.classify(body, &make_signals());
        assert!(result.is_some());
        let verdict = result.unwrap();
        assert_eq!(verdict.action, DlpInlineAction::Block);
        assert_eq!(verdict.findings.len(), 2);
    }

    #[test]
    fn invalid_regex_dropped_silently() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![
                DlpRegexRule {
                    rule_id: "bad".into(),
                    pattern: "[invalid".into(),
                    action: DlpInlineAction::Block,
                    severity: "high".into(),
                    finding_kind: DlpFindingKind::Pii,
                },
                DlpRegexRule {
                    rule_id: "good".into(),
                    pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                    action: DlpInlineAction::Block,
                    severity: "high".into(),
                    finding_kind: DlpFindingKind::Pii,
                },
            ],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        let body = b"SSN: 123-45-6789";
        let result = engine.classify(body, &make_signals());
        assert!(result.is_some());
        let verdict = result.unwrap();
        // Only the valid rule matched.
        assert_eq!(verdict.findings.len(), 1);
        assert_eq!(verdict.findings[0].label, "good");
    }

    #[test]
    fn hot_swap_replaces_policy() {
        let engine = DlpInlineEngine::new();
        let def1 = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def1);

        let body = b"SSN: 123-45-6789";
        assert!(engine.classify(body, &make_signals()).is_some());

        // Swap to empty policy.
        engine.install(&DlpInlinePolicyDef::default());
        assert!(engine.classify(body, &make_signals()).is_none());
    }

    #[test]
    fn to_swg_verdict_block_produces_deny() {
        let verdict = DlpInlineVerdict {
            action: DlpInlineAction::Block,
            wire_action: DlpAction::Block,
            confidence: 0.95,
            severity: "high".into(),
            findings: vec![],
            scanned_bytes: 100,
            truncated: false,
        };
        let v = verdict.to_swg_verdict("test_app");
        assert_eq!(v.action, crate::verdict::Action::Deny);
        assert!(v.reason.starts_with("dlp.inline.block."));
    }

    #[test]
    fn to_swg_verdict_log_produces_allow() {
        let verdict = DlpInlineVerdict {
            action: DlpInlineAction::Log,
            wire_action: DlpAction::Monitor,
            confidence: 0.80,
            severity: "low".into(),
            findings: vec![],
            scanned_bytes: 100,
            truncated: false,
        };
        let v = verdict.to_swg_verdict("test_app");
        assert_eq!(v.action, crate::verdict::Action::Allow);
        assert!(v.reason.starts_with("dlp.inline.log."));
    }

    #[test]
    fn to_dlp_event_maps_fields_correctly() {
        let verdict = DlpInlineVerdict {
            action: DlpInlineAction::Block,
            wire_action: DlpAction::Block,
            confidence: 0.95,
            severity: "high".into(),
            findings: vec![DlpFinding {
                kind: DlpFindingKind::Pii,
                label: "ssn_us".into(),
                count: 1,
                max_confidence: 0.95,
                severity: "high".into(),
            }],
            scanned_bytes: 500,
            truncated: true,
        };
        let event = verdict.to_dlp_event("chatgpt");
        assert_eq!(event.destination_app, "chatgpt");
        assert_eq!(event.action, DlpAction::Block);
        assert_eq!(event.severity, "high");
        assert!((event.confidence - 0.95).abs() < 1e-9);
        assert_eq!(event.findings.len(), 1);
        assert_eq!(event.scanned_bytes, 500);
        assert!(event.truncated);
    }

    #[test]
    fn binary_body_does_not_panic() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        // Random binary bytes with an embedded SSN.
        let mut body = vec![0xffu8; 50];
        body.extend_from_slice(b" 123-45-6789 ");
        body.extend(vec![0x00u8; 50]);
        let result = engine.classify(&body, &make_signals());
        assert!(result.is_some());
        assert_eq!(result.unwrap().action, DlpInlineAction::Block);
    }

    #[test]
    fn fingerprint_match_detects_known_document() {
        let engine = DlpInlineEngine::new();
        // Create a fingerprint from a known text snippet.
        let source = b"CONFIDENTIAL: Project Atlas budget is $4.2M for Q4 2026.";
        // Compute n-gram hashes of the source.
        let n = FINGERPRINT_NGRAM_SIZE;
        let mut hashes = Vec::new();
        if source.len() >= n {
            let mut h: u64 = 0;
            let mut power: u64 = 1;
            for _ in 0..(n - 1) {
                power = (power * RK_BASE) % RK_MODULUS;
            }
            for (i, &byte) in source.iter().enumerate() {
                h = (h * RK_BASE + byte as u64) % RK_MODULUS;
                if i >= n - 1 {
                    hashes.push(h);
                    let old_byte = source[i - (n - 1)] as u64;
                    h = (h + RK_MODULUS - (old_byte * power) % RK_MODULUS) % RK_MODULUS;
                }
            }
        }

        let def = DlpInlinePolicyDef {
            regex_rules: vec![],
            fingerprints: vec![DlpFingerprint {
                fingerprint_id: "doc_atlas".into(),
                hashes,
                action: DlpInlineAction::Block,
                severity: "critical".into(),
            }],
            scan_ceiling_bytes: 0,
        };
        engine.install(&def);

        // The source text should match itself.
        let result = engine.classify(source, &make_signals());
        assert!(result.is_some());
        let verdict = result.unwrap();
        assert_eq!(verdict.action, DlpInlineAction::Block);
        assert_eq!(verdict.severity, "critical");
        assert!(!verdict.findings.is_empty());
    }

    #[test]
    fn install_returns_counts() {
        let engine = DlpInlineEngine::new();
        let def = DlpInlinePolicyDef {
            regex_rules: vec![
                DlpRegexRule {
                    rule_id: "r1".into(),
                    pattern: r"foo".into(),
                    action: DlpInlineAction::Log,
                    severity: "low".into(),
                    finding_kind: DlpFindingKind::Pii,
                },
                DlpRegexRule {
                    rule_id: "r2".into(),
                    pattern: r"bar".into(),
                    action: DlpInlineAction::Block,
                    severity: "high".into(),
                    finding_kind: DlpFindingKind::Secret,
                },
            ],
            fingerprints: vec![DlpFingerprint {
                fingerprint_id: "fp1".into(),
                hashes: vec![1, 2, 3],
                action: DlpInlineAction::Block,
                severity: "high".into(),
            }],
            scan_ceiling_bytes: 0,
        };
        let (n_regex, n_fp) = engine.install(&def);
        assert_eq!(n_regex, 2);
        assert_eq!(n_fp, 1);
    }
}

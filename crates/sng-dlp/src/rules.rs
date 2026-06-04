//! Endpoint DLP rule model.
//!
//! A [`DlpRule`] is the on-the-wire description of a single
//! detector as compiled by the control plane
//! (`internal/service/dlp` → endpoint bundle). The runtime
//! representation it compiles into lives in [`crate::classifier`];
//! this module is purely the data model + the small amount of
//! validation that does not require building a matcher.

use crate::channels::DlpChannel;
use serde::{Deserialize, Serialize};

/// The detection mechanism a rule uses. Wire-compatible with the Go
/// `repository.DLPRuleType` string set
/// (`internal/repository/types.go`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternType {
    /// A regular expression (raw, or a builtin pattern name such as
    /// `ssn_us` / `credit_card`; see
    /// [`crate::classifier::builtin_pattern`]).
    Regex,
    /// A keyword dictionary — `pattern_data` is a comma-separated
    /// list of literal keywords matched case-insensitively.
    Keyword,
    /// A SimHash document fingerprint — `pattern_data` is the
    /// 16-char hex of the registered 64-bit SimHash.
    Fingerprint,
    /// A Microsoft Information Protection sensitivity label —
    /// `pattern_data` is the label id to match against the content
    /// metadata's declared labels.
    MipLabel,
}

impl PatternType {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Regex => "regex",
            Self::Keyword => "keyword",
            Self::Fingerprint => "fingerprint",
            Self::MipLabel => "mip_label",
        }
    }
}

/// Rule severity. Ordered: [`Severity::Critical`] is the strictest.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Informational only.
    Low,
    /// Notable but not by itself disqualifying.
    Medium,
    /// Sensitive data class.
    High,
    /// Most sensitive — regulated PII / secrets.
    Critical,
}

impl Severity {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// The action a rule requests when it matches. Ordered by
/// strictness so the engine can pick the strongest action across
/// several matching rules: [`RuleAction::Block`] >
/// [`RuleAction::Warn`] > [`RuleAction::Log`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Record the event only; do not interrupt the user.
    Log,
    /// Prompt / warn the user but allow them to proceed.
    Warn,
    /// Refuse the transfer outright.
    Block,
}

impl RuleAction {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Log => "log",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

/// One endpoint DLP detection rule, exactly as it arrives in the
/// endpoint policy bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DlpRule {
    /// Stable per-policy identifier.
    pub id: String,
    /// Operator-facing display name.
    pub name: String,
    /// Detection mechanism.
    pub pattern_type: PatternType,
    /// Mechanism-specific payload. Interpretation depends on
    /// [`Self::pattern_type`]:
    ///
    /// * `Regex` — a raw regular expression or a builtin pattern
    ///   name (`ssn_us`, `credit_card`, …).
    /// * `Keyword` — a comma-separated keyword dictionary.
    /// * `Fingerprint` — 16-char hex of the 64-bit SimHash.
    /// * `MipLabel` — the sensitivity label id.
    pub pattern_data: String,
    /// Severity classification.
    pub severity: Severity,
    /// Action requested on match.
    pub action: RuleAction,
    /// The egress channels this rule is scoped to. An empty list
    /// means "all channels".
    #[serde(default)]
    pub channels: Vec<DlpChannel>,
}

impl DlpRule {
    /// Returns `true` when this rule should be evaluated for
    /// `channel`. An empty [`Self::channels`] list is treated as
    /// "every channel".
    #[must_use]
    pub fn applies_to(&self, channel: DlpChannel) -> bool {
        self.channels.is_empty() || self.channels.contains(&channel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn action_and_severity_order_strictest_last() {
        assert!(RuleAction::Block > RuleAction::Warn);
        assert!(RuleAction::Warn > RuleAction::Log);
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
    }

    #[test]
    fn empty_channel_list_applies_everywhere() {
        let r = DlpRule {
            id: "r1".into(),
            name: "any".into(),
            pattern_type: PatternType::Keyword,
            pattern_data: "secret".into(),
            severity: Severity::High,
            action: RuleAction::Block,
            channels: vec![],
        };
        assert!(r.applies_to(DlpChannel::Clipboard));
        assert!(r.applies_to(DlpChannel::UsbTransfer));
    }

    #[test]
    fn scoped_rule_only_applies_to_listed_channels() {
        let r = DlpRule {
            id: "r2".into(),
            name: "usb only".into(),
            pattern_type: PatternType::Regex,
            pattern_data: "ssn_us".into(),
            severity: Severity::Critical,
            action: RuleAction::Block,
            channels: vec![DlpChannel::UsbTransfer, DlpChannel::Print],
        };
        assert!(r.applies_to(DlpChannel::UsbTransfer));
        assert!(r.applies_to(DlpChannel::Print));
        assert!(!r.applies_to(DlpChannel::Clipboard));
    }

    #[test]
    fn rule_roundtrips_through_json() {
        let r = DlpRule {
            id: "ssn".into(),
            name: "US SSN".into(),
            pattern_type: PatternType::Regex,
            pattern_data: "ssn_us".into(),
            severity: Severity::Critical,
            action: RuleAction::Block,
            channels: vec![DlpChannel::FileWrite],
        };
        let json = serde_json::to_string(&r).expect("encode");
        let back: DlpRule = serde_json::from_str(&json).expect("decode");
        assert_eq!(r, back);
        assert!(json.contains("\"pattern_type\":\"regex\""));
        assert!(json.contains("\"action\":\"block\""));
    }
}

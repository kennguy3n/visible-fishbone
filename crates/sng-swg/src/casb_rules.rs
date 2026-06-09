//! Inline CASB rule model and pure rule evaluation.
//!
//! This module is the data-plane counterpart of the control
//! plane's `internal/service/casb/inline.go`. The control plane
//! compiles per-tenant inline-CASB rules into the SWG slice of a
//! signed policy bundle; the edge / cloud SWG decodes that slice
//! into a [`CasbRuleSet`] and evaluates it on the ext-authz hot
//! path (see [`crate::casb`]).
//!
//! The design mirrors [`crate::categorizer`] and
//! [`crate::malware`]:
//!
//!   * The verdict surface is small and serde-stable so the
//!     telemetry dashboards can group on the string forms.
//!   * Evaluation is a **pure** function over request metadata —
//!     it performs no I/O, takes no locks, and allocates nothing
//!     on the match path. The rule vector is owned by an
//!     [`arc_swap::ArcSwap`] in the inspector ([`crate::casb`]),
//!     so a control-plane bundle install hot-swaps the table
//!     without blocking readers.
//!   * The ruleset is pre-sorted by `(priority desc, app_id,
//!     action)` at install time so the first matching rule under a
//!     linear scan is also the highest-priority match — the scan
//!     returns on first hit.
//!
//! Rule semantics:
//!
//!   * A rule matches a request when the app id, the action, and
//!     every populated condition match. An unset condition (`None`)
//!     is a wildcard for that dimension.
//!   * `app_id == "*"` is an explicit any-app wildcard so an
//!     operator can write a tenant-wide "log every upload" rule
//!     without enumerating each SaaS app.
//!   * `size_threshold` matches when the request's content length
//!     is **greater than or equal to** the threshold ("block
//!     uploads ≥ 10 MB"). A request with no known size never
//!     matches a size-gated rule — the SWG fails open on the size
//!     dimension rather than blocking a request whose length Envoy
//!     could not forward.

use serde::{Deserialize, Serialize};

/// The action a SaaS request performs, as classified by the
/// inspector's app/path detection (see [`crate::casb`]).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CasbAction {
    /// A file is being uploaded to the SaaS app (OneDrive
    /// `PUT .../content`, Slack `files.upload`, Salesforce
    /// `ContentVersion` insert, Google Drive resumable upload).
    Upload,
    /// A file is being downloaded from the SaaS app.
    Download,
    /// A sharing action is being created (public link, external
    /// invite). The high-signal action for data-exfiltration via
    /// over-broad sharing.
    Share,
    /// A file / object is being deleted.
    Delete,
    /// An interactive / programmatic sign-in to the SaaS app
    /// (OAuth token grant, SAML assertion consumption, console
    /// login). High-signal for impossible-travel and
    /// new-geo-login detection.
    Login,
    /// A tenant-level administrative configuration change (SSO /
    /// MFA policy edit, security-setting change, role-binding
    /// update). The highest-signal action for detecting account
    /// takeover and insider tampering with security controls.
    AdminConfigChange,
    /// A new API key / personal-access-token / OAuth client
    /// secret is being minted. High-signal for persistence
    /// establishment after a compromise (a long-lived credential
    /// that survives a password reset).
    ApiKeyCreate,
    /// A share specifically to a principal outside the tenant's
    /// own domain (external collaborator invite, public link to an
    /// anonymous audience). Distinguished from [`Self::Share`] so a
    /// rule can permit internal sharing while blocking external
    /// exfiltration.
    ExternalShare,
    /// A bulk extraction of records / objects (Salesforce Bulk API
    /// job, a report export, a mailbox export). High-signal for
    /// mass data exfiltration that a per-object download rule would
    /// miss.
    BulkExport,
}

impl CasbAction {
    /// Stable string form for telemetry / bundle encoding. MUST
    /// stay byte-identical to the control plane's `InlineAction`
    /// (`internal/service/casb/inline.go`) — the compiled bundle's
    /// action column is matched as a string across the
    /// Go↔Rust boundary, so a drift here silently breaks rule
    /// matching at the edge.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Share => "share",
            Self::Delete => "delete",
            Self::Login => "login",
            Self::AdminConfigChange => "admin_config_change",
            Self::ApiKeyCreate => "api_key_create",
            Self::ExternalShare => "external_share",
            Self::BulkExport => "bulk_export",
        }
    }
}

impl std::fmt::Display for CasbAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The verdict an inline-CASB rule applies when it matches.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CasbVerdict {
    /// Explicitly allow the request. Distinct from "no rule
    /// matched" so an operator can short-circuit an allow ahead of
    /// a broader block rule of lower priority.
    Allow,
    /// Block the request — the SWG returns a deny to Envoy.
    Block,
    /// Allow the request but emit a CASB telemetry event
    /// (log-only / monitor mode). Used for "tag downloads for DLP
    /// scanning" and staged rollouts where the operator wants
    /// visibility before enforcing.
    Log,
}

impl CasbVerdict {
    /// Stable string form for telemetry / bundle encoding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Log => "log",
        }
    }
}

impl std::fmt::Display for CasbVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Conditions that further narrow when a rule fires. Every field
/// is optional; `None` means "do not constrain on this
/// dimension". A rule with all-`None` conditions matches every
/// request for its `(app_id, action)`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasbConditions {
    /// File extension the request must carry (without the leading
    /// dot, e.g. `"docx"`). Compared case-insensitively. `None`
    /// matches any file type. A request whose file type could not
    /// be derived never matches a file-type-gated rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_type: Option<String>,
    /// Minimum content length in bytes. The rule matches when the
    /// request's content length is `>=` this value. `None` matches
    /// any size; a request with unknown size never matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_threshold: Option<u64>,
    /// Sensitivity label the request must carry (e.g. a Microsoft
    /// Purview / MIP label id forwarded by Envoy as request
    /// metadata). Compared case-insensitively. `None` matches any
    /// label; a request with no label never matches a
    /// label-gated rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label_match: Option<String>,
}

impl CasbConditions {
    /// True when every populated condition is satisfied by the
    /// request metadata. Pure and allocation-free.
    #[must_use]
    fn matches(&self, meta: &CasbRequestMeta) -> bool {
        if let Some(want) = &self.file_type {
            match &meta.file_type {
                Some(got) if got.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        if let Some(threshold) = self.size_threshold {
            match meta.size_bytes {
                Some(size) if size >= threshold => {}
                _ => return false,
            }
        }
        if let Some(want) = &self.label_match {
            match &meta.label {
                Some(got) if got.eq_ignore_ascii_case(want) => {}
                _ => return false,
            }
        }
        true
    }
}

/// One inline-CASB rule. Decoded from the SWG slice of a policy
/// bundle (same compile path as the URL category feed).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasbRule {
    /// Stable rule id, carried through to the verdict reason so a
    /// blocked / logged request can be traced back to the rule
    /// that fired. Sourced from the control-plane
    /// `inline_casb_rules.id`.
    pub id: String,
    /// SaaS app this rule applies to (`"m365"`,
    /// `"google_workspace"`, `"slack"`, `"salesforce"`), or `"*"`
    /// for any app.
    pub app_id: String,
    /// Action the rule gates.
    pub action: CasbAction,
    /// Verdict applied on match.
    pub verdict: CasbVerdict,
    /// Additional match conditions.
    #[serde(default)]
    pub conditions: CasbConditions,
    /// Higher priority wins when several rules match the same
    /// request. Ties break on `(app_id, action, id)` for a
    /// deterministic order.
    #[serde(default)]
    pub priority: i32,
}

impl CasbRule {
    /// True when this rule applies to the request metadata. Pure.
    #[must_use]
    fn matches(&self, meta: &CasbRequestMeta) -> bool {
        if self.action != meta.action {
            return false;
        }
        if self.app_id != "*" && !self.app_id.eq_ignore_ascii_case(&meta.app_id) {
            return false;
        }
        self.conditions.matches(meta)
    }
}

/// Decoded request metadata the inspector hands to the rule
/// engine. Built by [`crate::casb`] from the ext-authz
/// [`crate::verdict::RequestContext`] plus the out-of-band DLP
/// signals (content length, sensitivity label). Kept separate
/// from `RequestContext` so the evaluation surface stays a pure
/// function over plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasbRequestMeta {
    /// Detected SaaS app id.
    pub app_id: String,
    /// Detected action.
    pub action: CasbAction,
    /// File extension (lowercase, no dot) if one could be derived
    /// from the request path; `None` otherwise.
    pub file_type: Option<String>,
    /// Content length in bytes if Envoy forwarded it; `None`
    /// otherwise.
    pub size_bytes: Option<u64>,
    /// Sensitivity label forwarded as request metadata; `None`
    /// otherwise.
    pub label: Option<String>,
}

/// The decision produced by a rule match: the verdict plus the
/// id of the rule that produced it, so the inspector can build a
/// traceable telemetry reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CasbDecision {
    /// The matched rule's verdict.
    pub verdict: CasbVerdict,
    /// The matched rule's id.
    pub rule_id: String,
    /// The app id the rule matched (resolved from the request, so
    /// a `"*"` rule still reports the concrete app for telemetry).
    pub app_id: String,
    /// The action the rule matched.
    pub action: CasbAction,
}

/// An immutable, pre-sorted set of inline-CASB rules. Held behind
/// an [`arc_swap::ArcSwap`] by [`crate::casb::InlineCasbInspector`]
/// so installs are atomic and reads are lock-free.
#[derive(Clone, Debug, Default)]
pub struct CasbRuleSet {
    rules: Vec<CasbRule>,
}

impl CasbRuleSet {
    /// Build a ruleset from an unordered rule list. The rules are
    /// sorted into match-walk order (priority descending, then
    /// `(app_id, action, id)` ascending for determinism) so
    /// [`CasbRuleSet::evaluate`] can return on first hit.
    #[must_use]
    pub fn new(mut rules: Vec<CasbRule>) -> Self {
        rules.sort_by(|a, b| {
            b.priority
                .cmp(&a.priority)
                .then_with(|| a.app_id.cmp(&b.app_id))
                .then_with(|| a.action.as_str().cmp(b.action.as_str()))
                .then_with(|| a.id.cmp(&b.id))
        });
        Self { rules }
    }

    /// Number of rules in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Read-only view of the sorted rules. Mostly for tests and
    /// telemetry introspection.
    #[must_use]
    pub fn rules(&self) -> &[CasbRule] {
        &self.rules
    }

    /// Evaluate the request metadata against the ruleset and
    /// return the first (highest-priority) matching rule's
    /// decision, or `None` when no rule matches. Pure: no I/O, no
    /// locks, no allocation on the match path (the returned
    /// `CasbDecision` clones the matched rule's id only when a
    /// rule actually fires).
    #[must_use]
    pub fn evaluate(&self, meta: &CasbRequestMeta) -> Option<CasbDecision> {
        self.rules
            .iter()
            .find(|r| r.matches(meta))
            .map(|r| CasbDecision {
                verdict: r.verdict,
                rule_id: r.id.clone(),
                app_id: meta.app_id.clone(),
                action: meta.action,
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn meta(app: &str, action: CasbAction) -> CasbRequestMeta {
        CasbRequestMeta {
            app_id: app.to_string(),
            action,
            file_type: None,
            size_bytes: None,
            label: None,
        }
    }

    fn rule(id: &str, app: &str, action: CasbAction, verdict: CasbVerdict) -> CasbRule {
        CasbRule {
            id: id.to_string(),
            app_id: app.to_string(),
            action,
            verdict,
            conditions: CasbConditions::default(),
            priority: 0,
        }
    }

    #[test]
    fn action_and_verdict_strings_are_stable() {
        // Telemetry + bundle wire contract. These string forms are
        // matched verbatim against the control plane's InlineAction
        // (internal/service/casb/inline.go); a drift silently breaks
        // rule matching at the edge.
        assert_eq!(CasbAction::Upload.as_str(), "upload");
        assert_eq!(CasbAction::Download.as_str(), "download");
        assert_eq!(CasbAction::Share.as_str(), "share");
        assert_eq!(CasbAction::Delete.as_str(), "delete");
        assert_eq!(CasbAction::Login.as_str(), "login");
        assert_eq!(CasbAction::AdminConfigChange.as_str(), "admin_config_change");
        assert_eq!(CasbAction::ApiKeyCreate.as_str(), "api_key_create");
        assert_eq!(CasbAction::ExternalShare.as_str(), "external_share");
        assert_eq!(CasbAction::BulkExport.as_str(), "bulk_export");
        assert_eq!(CasbVerdict::Allow.as_str(), "allow");
        assert_eq!(CasbVerdict::Block.as_str(), "block");
        assert_eq!(CasbVerdict::Log.as_str(), "log");
    }

    #[test]
    fn action_serde_roundtrip_matches_wire_form() {
        // The data plane must decode every action the control plane
        // can author into the bundle (the WS4 expansion adds five).
        // serde's snake_case form must equal as_str(), and a JSON
        // round-trip must be lossless for every variant.
        for action in [
            CasbAction::Upload,
            CasbAction::Download,
            CasbAction::Share,
            CasbAction::Delete,
            CasbAction::Login,
            CasbAction::AdminConfigChange,
            CasbAction::ApiKeyCreate,
            CasbAction::ExternalShare,
            CasbAction::BulkExport,
        ] {
            let json = serde_json::to_string(&action).expect("serialize");
            assert_eq!(json, format!("\"{}\"", action.as_str()));
            let back: CasbAction = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(back, action);
        }
    }

    #[test]
    fn new_actions_decode_and_evaluate() {
        // A bundle carrying a WS4 action must decode into a rule and
        // match a request the inspector classifies with that action.
        let raw = r#"{
            "id": "r-bulk",
            "app_id": "salesforce",
            "action": "bulk_export",
            "verdict": "block"
        }"#;
        let decoded: CasbRule = serde_json::from_str(raw).expect("decode rule");
        assert_eq!(decoded.action, CasbAction::BulkExport);
        let set = CasbRuleSet::new(vec![decoded]);
        let d = set
            .evaluate(&meta("salesforce", CasbAction::BulkExport))
            .expect("match");
        assert_eq!(d.verdict, CasbVerdict::Block);
        assert_eq!(d.action, CasbAction::BulkExport);
        // A different action must not fire the bulk-export rule.
        assert_eq!(set.evaluate(&meta("salesforce", CasbAction::Login)), None);
    }

    #[test]
    fn empty_set_matches_nothing() {
        let set = CasbRuleSet::default();
        assert!(set.is_empty());
        assert_eq!(set.evaluate(&meta("m365", CasbAction::Upload)), None);
    }

    #[test]
    fn exact_app_action_match() {
        let set = CasbRuleSet::new(vec![rule(
            "r1",
            "m365",
            CasbAction::Share,
            CasbVerdict::Block,
        )]);
        let d = set
            .evaluate(&meta("m365", CasbAction::Share))
            .expect("match");
        assert_eq!(d.verdict, CasbVerdict::Block);
        assert_eq!(d.rule_id, "r1");
        assert_eq!(d.app_id, "m365");
        assert_eq!(d.action, CasbAction::Share);
    }

    #[test]
    fn action_mismatch_does_not_fire() {
        let set = CasbRuleSet::new(vec![rule(
            "r1",
            "m365",
            CasbAction::Share,
            CasbVerdict::Block,
        )]);
        assert_eq!(set.evaluate(&meta("m365", CasbAction::Upload)), None);
    }

    #[test]
    fn app_mismatch_does_not_fire() {
        let set = CasbRuleSet::new(vec![rule(
            "r1",
            "m365",
            CasbAction::Share,
            CasbVerdict::Block,
        )]);
        assert_eq!(set.evaluate(&meta("slack", CasbAction::Share)), None);
    }

    #[test]
    fn wildcard_app_matches_any_app() {
        let set = CasbRuleSet::new(vec![rule("r1", "*", CasbAction::Upload, CasbVerdict::Log)]);
        for app in ["m365", "slack", "google_workspace", "salesforce"] {
            let d = set.evaluate(&meta(app, CasbAction::Upload)).expect("match");
            assert_eq!(d.verdict, CasbVerdict::Log);
            // The decision reports the concrete app, not the wildcard.
            assert_eq!(d.app_id, app);
        }
    }

    #[test]
    fn app_id_match_is_case_insensitive() {
        let set = CasbRuleSet::new(vec![rule(
            "r1",
            "M365",
            CasbAction::Upload,
            CasbVerdict::Block,
        )]);
        assert!(set.evaluate(&meta("m365", CasbAction::Upload)).is_some());
    }

    #[test]
    fn higher_priority_rule_wins() {
        let mut allow = rule("allow", "m365", CasbAction::Upload, CasbVerdict::Allow);
        allow.priority = 100;
        let mut block = rule("block", "m365", CasbAction::Upload, CasbVerdict::Block);
        block.priority = 10;
        // Insert in low-then-high order to prove the sort, not the
        // insertion order, decides the winner.
        let set = CasbRuleSet::new(vec![block, allow]);
        let d = set
            .evaluate(&meta("m365", CasbAction::Upload))
            .expect("match");
        assert_eq!(d.verdict, CasbVerdict::Allow);
        assert_eq!(d.rule_id, "allow");
    }

    #[test]
    fn file_type_condition_is_case_insensitive_and_gates() {
        let mut r = rule("r1", "m365", CasbAction::Upload, CasbVerdict::Block);
        r.conditions.file_type = Some("DOCX".to_string());
        let set = CasbRuleSet::new(vec![r]);

        let mut m = meta("m365", CasbAction::Upload);
        m.file_type = Some("docx".to_string());
        assert!(set.evaluate(&m).is_some());

        m.file_type = Some("pdf".to_string());
        assert_eq!(set.evaluate(&m), None);

        // Unknown file type never matches a file-type-gated rule.
        m.file_type = None;
        assert_eq!(set.evaluate(&m), None);
    }

    #[test]
    fn size_threshold_matches_at_or_above_and_fails_open_on_unknown() {
        let mut r = rule("r1", "salesforce", CasbAction::Upload, CasbVerdict::Log);
        r.conditions.size_threshold = Some(10 * 1024 * 1024); // 10 MiB
        let set = CasbRuleSet::new(vec![r]);

        let mut m = meta("salesforce", CasbAction::Upload);
        m.size_bytes = Some(10 * 1024 * 1024);
        assert!(set.evaluate(&m).is_some(), "exactly at threshold matches");

        m.size_bytes = Some(10 * 1024 * 1024 + 1);
        assert!(set.evaluate(&m).is_some(), "above threshold matches");

        m.size_bytes = Some(1024);
        assert_eq!(set.evaluate(&m), None, "below threshold does not match");

        m.size_bytes = None;
        assert_eq!(set.evaluate(&m), None, "unknown size fails open");
    }

    #[test]
    fn label_match_condition_gates() {
        let mut r = rule("r1", "m365", CasbAction::Download, CasbVerdict::Block);
        r.conditions.label_match = Some("confidential".to_string());
        let set = CasbRuleSet::new(vec![r]);

        let mut m = meta("m365", CasbAction::Download);
        m.label = Some("Confidential".to_string());
        assert!(set.evaluate(&m).is_some());

        m.label = Some("public".to_string());
        assert_eq!(set.evaluate(&m), None);

        m.label = None;
        assert_eq!(set.evaluate(&m), None);
    }

    #[test]
    fn all_conditions_must_hold_together() {
        let mut r = rule("r1", "m365", CasbAction::Upload, CasbVerdict::Block);
        r.conditions.file_type = Some("docx".to_string());
        r.conditions.size_threshold = Some(1000);
        let set = CasbRuleSet::new(vec![r]);

        let mut m = meta("m365", CasbAction::Upload);
        m.file_type = Some("docx".to_string());
        m.size_bytes = Some(2000);
        assert!(set.evaluate(&m).is_some(), "both conditions hold");

        // File type holds but size does not -> no match.
        m.size_bytes = Some(10);
        assert_eq!(set.evaluate(&m), None);
    }

    #[test]
    fn rule_roundtrips_through_json() {
        // The bundle slice is JSON on the wire (the SWG slice is
        // serde_json, same as the category feed). Lock the shape.
        let r = CasbRule {
            id: "rule-1".to_string(),
            app_id: "m365".to_string(),
            action: CasbAction::Share,
            verdict: CasbVerdict::Block,
            conditions: CasbConditions {
                file_type: None,
                size_threshold: None,
                label_match: Some("confidential".to_string()),
            },
            priority: 50,
        };
        let json = serde_json::to_string(&r).expect("serialize");
        let back: CasbRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(r, back);
    }

    #[test]
    fn conditions_omit_none_fields_in_json() {
        // skip_serializing_if keeps the bundle bytes compact and
        // deterministic for the all-None common case.
        let c = CasbConditions::default();
        let json = serde_json::to_string(&c).expect("serialize");
        assert_eq!(json, "{}");
    }
}

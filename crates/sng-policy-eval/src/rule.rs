//! Typed rule model — wire-compatible with the Go compiler at
//! `internal/service/policy/graph.go`.
//!
//! The Go side encodes `Rule` / `Subject` / `Predicate` as JSON
//! (the `Graph` source is JSON; the compiler emits the per-target
//! rule slice via `EncodeRules` which is `json.RawMessage` inside
//! the MessagePack bundle envelope under the `r` key). This module
//! is the symmetric Rust decoder.
//!
//! Wire shape (every field name matches the Go `json:"…"` tag
//! exactly so a byte-identical bundle round-trips):
//!
//! * `id` — stable rule id.
//! * `domain` — enforcement domain (`ngfw|swg|dns|ztna|sdwan|dlp`).
//! * `verb` — policy verb (`allow|deny|inspect|steer|decrypt|log|suggest_only`).
//! * `subject_refs` / `predicate_refs` — named references to
//!   vertices declared on the parent graph.
//! * `subjects` / `predicates` — inline matcher vertices for
//!   single-use rules.
//! * `targets` — optional whitelist of bundle targets the rule
//!   should apply to (overrides the domain → target routing).
//! * `description` — operator-facing label.
//!
//! Unknown JSON keys on a rule object are preserved into
//! [`Rule::extra`] so a future Go-side schema bump that adds a new
//! field does NOT cause us to silently strip the field — we
//! either pass it through unchanged in serialisation or surface it
//! to the caller via [`Rule::extra`].

use crate::matcher::{PredicateMatch, SubjectMatch};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Policy verb — the action a rule applies on match. The
/// serde tag is the lowercase wire form from
/// `internal/service/policy/graph.go::Verb` (`suggest_only` is
/// underscored to match the Go constant).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verb {
    /// Permit the flow.
    Allow,
    /// Refuse the flow at the earliest enforcement point.
    Deny,
    /// Permit + emit inspection telemetry (no decryption).
    Inspect,
    /// Permit + route to a specific traffic class. The class
    /// itself comes from the steering table, not the rule body —
    /// the rule's job is only to opt the flow into steering.
    Steer,
    /// Permit + decrypt TLS for L7 inspection.
    Decrypt,
    /// Permit + log (metadata-only).
    Log,
    /// Suggestion-only: surface the verb in the operator UI but
    /// do not enforce. Used during phased rollouts.
    SuggestOnly,
}

impl Verb {
    /// Canonical wire string. Stable across schema versions.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Inspect => "inspect",
            Self::Steer => "steer",
            Self::Decrypt => "decrypt",
            Self::Log => "log",
            Self::SuggestOnly => "suggest_only",
        }
    }
}

/// Enforcement domain a rule applies to. The Go side uses this to
/// route rules into per-target bundles; receivers use it to
/// dispatch a rule to the right subsystem (NGFW / SWG / DNS / …).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementDomain {
    /// L3/L4 firewall.
    Ngfw,
    /// Secure web gateway (HTTP / HTTPS forward proxy).
    Swg,
    /// DNS resolver / sinkhole / RPZ.
    Dns,
    /// Zero-trust network access (per-app reachability).
    Ztna,
    /// Software-defined WAN steering.
    Sdwan,
    /// Data loss prevention.
    Dlp,
}

impl EnforcementDomain {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ngfw => "ngfw",
            Self::Swg => "swg",
            Self::Dns => "dns",
            Self::Ztna => "ztna",
            Self::Sdwan => "sdwan",
            Self::Dlp => "dlp",
        }
    }
}

/// The kind of vertex a [`Subject`] declares. Mirrors
/// `internal/service/policy/graph.go::SubjectKind`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectKind {
    /// Human principal (login).
    User,
    /// Endpoint identity (device-bound key).
    Device,
    /// Application identifier from the app catalog.
    App,
    /// Physical site (branch office) the flow originates at.
    Site,
    /// IP network — for source-network rules in firewall context.
    Network,
}

impl SubjectKind {
    /// Canonical wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Device => "device",
            Self::App => "app",
            Self::Site => "site",
            Self::Network => "network",
        }
    }
}

/// A subject vertex: matches one of the flow's principals against
/// the [`SubjectMatch`] embedded in this vertex.
///
/// Named subjects (declared at graph level) are referenced from
/// rules via `subject_refs`; inline subjects are embedded directly
/// in the rule's `subjects` array. Both shapes resolve to this
/// struct in the loaded bundle.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    /// Identifier — required for named subjects, may be empty for
    /// inline ones. Matches Go `Subject.Name`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The principal type this subject scopes against.
    pub kind: SubjectKind,
    /// Domain-specific matcher payload. Comes off the wire as
    /// `json.RawMessage`; this crate decodes it into the typed
    /// [`SubjectMatch`] sum so the eval hot path can dispatch
    /// without re-parsing JSON per flow.
    #[serde(default, rename = "match")]
    pub matcher: SubjectMatch,
}

/// A predicate vertex — a domain-specific condition on the flow
/// (time-of-day, geo, URL category, etc.). The matcher schema is
/// intentionally open: each enforcement subsystem owns its own
/// predicate matchers. Predicates the local engine doesn't
/// understand are skipped (the rule does not match) rather than
/// rejecting the whole bundle — this lets the control plane ship
/// new predicate types ahead of an edge upgrade.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Predicate {
    /// Identifier for named predicates.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// Domain-specific matcher payload.
    #[serde(default, rename = "match")]
    pub matcher: PredicateMatch,
}

/// One enforcement rule. Order in [`super::bundle::LoadedBundle::rules`]
/// is significant — the first matching rule wins, matching the Go
/// compiler's contract that the per-target slice preserves source
/// order from the graph.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable per-graph identifier. Required.
    pub id: String,
    /// Enforcement domain this rule belongs to.
    pub domain: EnforcementDomain,
    /// Verb to apply on match.
    pub verb: Verb,

    /// Named subject vertex references — resolve against
    /// [`super::bundle::LoadedBundle::subjects`] at evaluation time.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_refs: Vec<String>,
    /// Named predicate vertex references.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicate_refs: Vec<String>,
    /// Inline subject matchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<Subject>,
    /// Inline predicate matchers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicates: Vec<Predicate>,
    /// Optional whitelist of bundle targets. When empty the
    /// compiler routes by `domain`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Operator-facing description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Unknown JSON keys preserved verbatim. Sorted by key so the
    /// serialised form is byte-deterministic. Read-only at the
    /// evaluation layer — used by telemetry / change-simulator
    /// callers that want to round-trip a bundle without lossy
    /// re-encoding.
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl Rule {
    /// Convenience: does this rule apply to the requested
    /// enforcement subsystem? Combines the [`Self::domain`]
    /// classification with the optional `targets` whitelist on
    /// the rule itself.
    ///
    /// The Go compiler already filters by target at compile-time;
    /// receivers re-check here as a defence-in-depth guard
    /// against a bundle that smuggled an off-target rule past the
    /// compiler (older un-typed graphs from PR6 era can do this).
    #[must_use]
    pub fn applies_to_domain(&self, requested: EnforcementDomain) -> bool {
        self.domain == requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn verb_wire_strings_match_go_side() {
        for (v, want) in [
            (Verb::Allow, "allow"),
            (Verb::Deny, "deny"),
            (Verb::Inspect, "inspect"),
            (Verb::Steer, "steer"),
            (Verb::Decrypt, "decrypt"),
            (Verb::Log, "log"),
            (Verb::SuggestOnly, "suggest_only"),
        ] {
            assert_eq!(v.as_str(), want);
            let json = serde_json::to_string(&v).unwrap();
            assert_eq!(json, format!("\"{want}\""));
            let parsed: Verb = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, v);
        }
    }

    #[test]
    fn enforcement_domain_wire_strings_match_go_side() {
        for (d, want) in [
            (EnforcementDomain::Ngfw, "ngfw"),
            (EnforcementDomain::Swg, "swg"),
            (EnforcementDomain::Dns, "dns"),
            (EnforcementDomain::Ztna, "ztna"),
            (EnforcementDomain::Sdwan, "sdwan"),
            (EnforcementDomain::Dlp, "dlp"),
        ] {
            assert_eq!(d.as_str(), want);
        }
    }

    #[test]
    fn subject_kind_wire_strings_match_go_side() {
        for (k, want) in [
            (SubjectKind::User, "user"),
            (SubjectKind::Device, "device"),
            (SubjectKind::App, "app"),
            (SubjectKind::Site, "site"),
            (SubjectKind::Network, "network"),
        ] {
            assert_eq!(k.as_str(), want);
        }
    }

    #[test]
    fn rule_roundtrips_through_serde_json() {
        let rule = Rule {
            id: "r-1".into(),
            domain: EnforcementDomain::Dns,
            verb: Verb::Deny,
            subject_refs: vec!["all-users".into()],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: "block malware".into(),
            extra: BTreeMap::new(),
        };
        let encoded = serde_json::to_string(&rule).unwrap();
        let decoded: Rule = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, rule);
    }

    #[test]
    fn rule_preserves_unknown_fields_in_extra() {
        // A future Go-side schema bump could add a `priority`
        // field. The decoder must not drop it — operators count
        // on round-tripping a bundle through Rust without
        // mutating the signature payload.
        let json = r#"{
            "id": "r-2",
            "domain": "ngfw",
            "verb": "allow",
            "future_field": 42,
            "priority": "high"
        }"#;
        let r: Rule = serde_json::from_str(json).unwrap();
        assert_eq!(r.extra.len(), 2);
        assert_eq!(r.extra.get("future_field").unwrap().as_i64(), Some(42));
        assert_eq!(r.extra.get("priority").unwrap().as_str(), Some("high"));
    }

    #[test]
    fn rule_applies_to_domain_filters_by_domain_field() {
        let r = Rule {
            id: "r-3".into(),
            domain: EnforcementDomain::Swg,
            verb: Verb::Inspect,
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: BTreeMap::new(),
        };
        assert!(r.applies_to_domain(EnforcementDomain::Swg));
        assert!(!r.applies_to_domain(EnforcementDomain::Ngfw));
    }
}

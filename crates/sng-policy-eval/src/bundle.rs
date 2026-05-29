//! [`LoadedBundle`] — the parsed, immutable representation of a
//! verified policy bundle ready for evaluation.
//!
//! Wire shape (matches the Go compiler at
//! `internal/service/policy/service.go::bundlePayload`):
//!
//! ```text
//! { "v":  schema_version (u8),
//!   "t":  target (string),
//!   "g":  graph_id (UUID string),
//!   "gv": graph_version (i64),
//!   "c":  compiler (string),
//!   "d":  default_action (string),
//!   "r":  rules (JSON-encoded `Vec<Rule>` inside an msgpack bin),
//!   "st": steering (JSON-encoded `SteeringRuleSet`, optional),
//!   "ts": compiled_at (RFC 3339 string) }
//! ```
//!
//! The `r` and `st` fields are `json.RawMessage` on the Go side
//! and serialise to MessagePack `bin` (raw bytes). The decoder
//! consumes them as `Vec<u8>` and then runs `serde_json` over the
//! contained bytes — a two-stage decode, but unavoidable given
//! the wire shape.
//!
//! [`LoadedBundle`] is intentionally immutable: every field is
//! frozen at load time, the steering table is precompiled into
//! its lookup indices, and the rules are stored as
//! `Arc<[Rule]>` so [`crate::engine::PolicyEngine`] can hand out
//! borrowed slices on the read path without cloning.

use crate::error::PolicyEvalError;
use crate::rule::{Predicate, Rule, Subject, Verb};
use crate::steering::{SteeringRuleSet, SteeringTable};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sng_core::ids::PolicyBundleId;
use sng_core::policy::BundleTarget;
use std::collections::HashMap;
use std::sync::Arc;

/// The maximum bundle schema version this engine understands.
/// The Go compiler emits `SchemaVersion = 1` at the time of
/// writing (`internal/service/policy/service.go::encodeBundlePayloadFor`);
/// receivers refuse anything strictly greater so a future
/// incompatible bump cannot accidentally load.
pub const MAX_SUPPORTED_SCHEMA_VERSION: u8 = 1;

/// On-wire bundle envelope. Matches Go `bundlePayload` field-for-
/// field (renamed via `#[serde(rename = "…")]` to the
/// one-or-two-letter tags the Go side encodes).
///
/// Only used as an intermediate during [`LoadedBundle::from_body`];
/// callers should use [`LoadedBundle`] directly.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RawBundle {
    #[serde(rename = "v")]
    schema_version: u8,
    #[serde(rename = "t")]
    target: BundleTarget,
    #[serde(rename = "g")]
    graph_id: String,
    #[serde(rename = "gv")]
    graph_version: i64,
    #[serde(rename = "c", default)]
    compiler: String,
    #[serde(rename = "d", default)]
    default_action: String,
    /// JSON-encoded `Vec<Rule>` inside an msgpack `bin`.
    #[serde(rename = "r", with = "serde_bytes", default)]
    rules_json: Vec<u8>,
    /// JSON-encoded `SteeringRuleSet`. Optional — the field is
    /// `omitempty` on the Go side when no steering compiler is
    /// wired (`encodeBundlePayloadFor` passes `nil` in that
    /// case).
    #[serde(
        rename = "st",
        with = "serde_bytes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    steering_json: Vec<u8>,
    #[serde(rename = "ts")]
    compiled_at: DateTime<Utc>,
}

/// Immutable, fully-decoded policy bundle. Held inside
/// [`crate::engine::PolicyEngine`] behind an `ArcSwap` so the
/// hot path can clone the `Arc` cheaply and read every field
/// without locking.
#[derive(Clone, Debug)]
pub struct LoadedBundle {
    /// Bundle wire schema version (1 today).
    pub schema_version: u8,
    /// Bundle target (`edge` / `endpoint` / `cloud` / `mobile`).
    pub target: BundleTarget,
    /// Source policy graph id. Free-form string at this layer
    /// (the Go side emits a canonical UUID).
    pub graph_id: String,
    /// Monotonic graph version. Higher is newer.
    pub graph_version: i64,
    /// Compiler version that produced this bundle. For
    /// telemetry / fleet-spread dashboards only.
    pub compiler: String,
    /// Default verb when no rule matches. Mirrors the Go
    /// `Graph.DefaultAction`; falls back to `Deny` if the
    /// string is missing or unrecognised — the architecture
    /// mandates `deny` as the safe baseline.
    pub default_verb: Verb,
    /// The original `d` field string verbatim. Carried for
    /// round-trip fidelity / telemetry.
    pub default_action_raw: String,
    /// Compiled per-target rule list, in evaluation order. The
    /// first matching rule wins.
    pub rules: Arc<[Rule]>,
    /// Precompiled steering lookup. Empty when no `st` block
    /// was present in the bundle.
    pub steering: Arc<SteeringTable>,
    /// Raw steering rule set — kept for round-tripping the
    /// bundle through telemetry without re-encoding loss.
    pub steering_raw: Option<Arc<SteeringRuleSet>>,
    /// Wall-clock compile time.
    pub compiled_at: DateTime<Utc>,
    /// Pre-built lookup map for named subjects referenced via
    /// [`Rule::subject_refs`]. Built from every inline subject
    /// with a non-empty `name` field so the engine can resolve
    /// refs without scanning the rule slice per evaluation.
    pub(crate) named_subjects: HashMap<String, Subject>,
    /// Same shape as [`Self::named_subjects`] for predicate
    /// vertices.
    pub(crate) named_predicates: HashMap<String, Predicate>,
}

impl LoadedBundle {
    /// Decode a verified bundle body into a usable
    /// [`LoadedBundle`].
    ///
    /// **Invariant**: callers MUST have already passed `body`
    /// through [`sng_core::policy::PolicyVerifier::verify`] —
    /// this function does NOT re-check the signature. The
    /// schema-version / target-match / staleness checks below
    /// run over fields the signature has already authenticated,
    /// so a network attacker who tries to swap any of them has
    /// already been rejected upstream.
    ///
    /// The `target` argument is the bundle target the local
    /// engine is configured for. A bundle whose `t` field
    /// doesn't match is rejected — defends against a misrouted
    /// bundle being applied to the wrong enforcement surface.
    pub fn from_body(body: &[u8], target: BundleTarget) -> Result<Self, PolicyEvalError> {
        let raw: RawBundle = rmp_serde::from_slice(body)
            .map_err(|e| PolicyEvalError::EnvelopeDecode(format!("decode bundle envelope: {e}")))?;
        if raw.schema_version > MAX_SUPPORTED_SCHEMA_VERSION {
            return Err(PolicyEvalError::SchemaVersionTooNew {
                found: raw.schema_version,
                supported: MAX_SUPPORTED_SCHEMA_VERSION,
            });
        }
        if raw.target != target {
            return Err(PolicyEvalError::TargetMismatch {
                actual: raw.target.as_str().to_owned(),
                expected: target.as_str().to_owned(),
            });
        }
        // Decode the rule list. The Go compiler encodes `[]` for
        // an empty rule set, so the absent-field path also lands
        // on the empty Vec.
        let rules: Vec<Rule> = if raw.rules_json.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(&raw.rules_json)
                .map_err(|e| PolicyEvalError::RulesDecode(format!("decode rule table: {e}")))?
        };
        // Decode the steering rule set. Optional — the Go side
        // omits it (`omitempty`) when no steering compiler is
        // wired.
        let (steering_table, steering_raw) = if raw.steering_json.is_empty() {
            (SteeringTable::default(), None)
        } else {
            let rs: SteeringRuleSet = serde_json::from_slice(&raw.steering_json).map_err(|e| {
                PolicyEvalError::SteeringDecode(format!("decode steering table: {e}"))
            })?;
            let table = SteeringTable::from_rule_set(&rs);
            (table, Some(Arc::new(rs)))
        };
        let default_verb = parse_default_verb(&raw.default_action);
        // Every `suggest_only` rule must carry a `suggested_verb`
        // (the would-be enforcement verb the operator UI surfaces).
        // A bundle whose default action is `suggest_only` is also
        // malformed — there is no per-rule context to attach a
        // suggestion to. Reject both at load time rather than
        // letting the engine emit `Verdict::SuggestOnly { suggestion:
        // SuggestOnly }` at evaluation time.
        for rule in &rules {
            if rule.verb == Verb::SuggestOnly
                && !matches!(rule.suggested_verb, Some(v) if v != Verb::SuggestOnly)
            {
                return Err(PolicyEvalError::SuggestOnlyMissingSuggestion {
                    rule_id: Some(rule.id.clone()),
                });
            }
        }
        if default_verb == Verb::SuggestOnly {
            return Err(PolicyEvalError::SuggestOnlyMissingSuggestion { rule_id: None });
        }
        let (named_subjects, named_predicates) = build_vertex_indices(&rules);
        Ok(Self {
            schema_version: raw.schema_version,
            target: raw.target,
            graph_id: raw.graph_id,
            graph_version: raw.graph_version,
            compiler: raw.compiler,
            default_verb,
            default_action_raw: raw.default_action,
            rules: Arc::from(rules.into_boxed_slice()),
            steering: Arc::new(steering_table),
            steering_raw,
            compiled_at: raw.compiled_at,
            named_subjects,
            named_predicates,
        })
    }

    /// Number of rules carried in this bundle.
    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// Stable bundle "id" used in operator telemetry. Combines
    /// the graph id and the graph version so re-compilations
    /// against the same graph produce distinguishable ids.
    /// Returns `None` when the graph id is not a parseable
    /// UUID (older opaque bundles).
    #[must_use]
    pub fn bundle_id(&self) -> Option<PolicyBundleId> {
        self.graph_id.parse().ok()
    }
}

/// Walk the rule slice once to build named-vertex lookup maps.
/// Both subjects and predicates can be referenced from later
/// rules via `subject_refs` / `predicate_refs`; building the
/// maps here keeps the evaluation hot path free of linear
/// scans.
///
/// On a name collision (two rules declare the same name) the
/// first occurrence wins — matches the Go side's `ParseGraph`
/// behaviour which rejects duplicate names at compile time
/// (we just defend against the bundle slipping past that
/// check).
fn build_vertex_indices(rules: &[Rule]) -> (HashMap<String, Subject>, HashMap<String, Predicate>) {
    let mut subjects: HashMap<String, Subject> = HashMap::new();
    let mut predicates: HashMap<String, Predicate> = HashMap::new();
    for rule in rules {
        for s in &rule.subjects {
            if !s.name.is_empty() {
                subjects.entry(s.name.clone()).or_insert_with(|| s.clone());
            }
        }
        for p in &rule.predicates {
            if !p.name.is_empty() {
                predicates
                    .entry(p.name.clone())
                    .or_insert_with(|| p.clone());
            }
        }
    }
    (subjects, predicates)
}

/// Parse the `d` field. The Go side stores this as a free-form
/// string; we attempt to map it onto the typed [`Verb`] enum and
/// fall back to `Deny` (the architectural safe baseline) on any
/// unrecognised value.
fn parse_default_verb(raw: &str) -> Verb {
    match raw {
        "allow" => Verb::Allow,
        "inspect" => Verb::Inspect,
        "steer" => Verb::Steer,
        "decrypt" => Verb::Decrypt,
        "log" => Verb::Log,
        "suggest_only" => Verb::SuggestOnly,
        // "deny", "", and every unrecognised value all fall to
        // the safe baseline.
        _ => Verb::Deny,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::EnforcementDomain;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeMap;

    fn encode_msgpack_named<T: Serialize>(t: &T) -> Vec<u8> {
        rmp_serde::to_vec_named(t).unwrap()
    }

    /// Build a minimal valid bundle body — schema v1, no rules,
    /// no steering. Used as the happy-path baseline.
    fn empty_bundle_body(target: BundleTarget) -> Vec<u8> {
        let raw = RawBundle {
            schema_version: 1,
            target,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 7,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        encode_msgpack_named(&raw)
    }

    #[test]
    fn empty_bundle_decodes() {
        let body = empty_bundle_body(BundleTarget::Edge);
        let loaded = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.target, BundleTarget::Edge);
        assert_eq!(loaded.graph_version, 7);
        assert_eq!(loaded.rule_count(), 0);
        assert_eq!(loaded.default_verb, Verb::Deny);
        assert!(loaded.steering_raw.is_none());
    }

    #[test]
    fn target_mismatch_rejects_bundle() {
        let body = empty_bundle_body(BundleTarget::Edge);
        let err = LoadedBundle::from_body(&body, BundleTarget::Endpoint).unwrap_err();
        match err {
            PolicyEvalError::TargetMismatch { actual, expected } => {
                assert_eq!(actual, "edge");
                assert_eq!(expected, "endpoint");
            }
            other => panic!("expected TargetMismatch, got {other:?}"),
        }
    }

    #[test]
    fn future_schema_version_is_rejected() {
        let raw = RawBundle {
            schema_version: 99,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "future".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(
            err,
            PolicyEvalError::SchemaVersionTooNew { found: 99, .. }
        ));
    }

    #[test]
    fn malformed_envelope_returns_envelope_decode() {
        let err = LoadedBundle::from_body(b"not msgpack", BundleTarget::Edge).unwrap_err();
        assert!(matches!(err, PolicyEvalError::EnvelopeDecode(_)));
    }

    #[test]
    fn malformed_rules_json_returns_rules_decode() {
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"{not valid json".to_vec(),
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(err, PolicyEvalError::RulesDecode(_)));
    }

    #[test]
    fn malformed_steering_json_returns_steering_decode() {
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: b"{not valid json".to_vec(),
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(err, PolicyEvalError::SteeringDecode(_)));
    }

    #[test]
    fn rules_are_decoded_in_source_order() {
        let rule_a = Rule {
            id: "a".into(),
            domain: EnforcementDomain::Dns,
            verb: Verb::Allow,
            suggested_verb: None,
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: BTreeMap::new(),
        };
        let rule_b = Rule {
            id: "b".into(),
            ..rule_a.clone()
        };
        let rules_json = serde_json::to_vec(&[rule_a.clone(), rule_b.clone()]).unwrap();
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json,
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let loaded = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert_eq!(loaded.rule_count(), 2);
        assert_eq!(loaded.rules[0].id, "a");
        assert_eq!(loaded.rules[1].id, "b");
    }

    #[test]
    fn default_action_parses_known_verbs() {
        assert_eq!(parse_default_verb("allow"), Verb::Allow);
        assert_eq!(parse_default_verb("deny"), Verb::Deny);
        assert_eq!(parse_default_verb(""), Verb::Deny);
        assert_eq!(parse_default_verb("inspect"), Verb::Inspect);
        assert_eq!(parse_default_verb("steer"), Verb::Steer);
        assert_eq!(parse_default_verb("decrypt"), Verb::Decrypt);
        assert_eq!(parse_default_verb("log"), Verb::Log);
        assert_eq!(parse_default_verb("suggest_only"), Verb::SuggestOnly);
        // Unknown verbs fall back to Deny, the safe baseline.
        assert_eq!(parse_default_verb("future_verb"), Verb::Deny);
    }

    #[test]
    fn bundle_id_parses_when_graph_id_is_uuid() {
        let body = empty_bundle_body(BundleTarget::Edge);
        let loaded = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert!(loaded.bundle_id().is_some());
    }

    #[test]
    fn suggest_only_rule_without_suggested_verb_is_rejected() {
        let rule = Rule {
            id: "so-1".into(),
            domain: EnforcementDomain::Ngfw,
            verb: Verb::SuggestOnly,
            suggested_verb: None,
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: BTreeMap::new(),
        };
        let rules_json = serde_json::to_vec(&[rule]).unwrap();
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json,
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(
            matches!(err, PolicyEvalError::SuggestOnlyMissingSuggestion { rule_id: Some(ref id) } if id == "so-1")
        );
    }

    #[test]
    fn suggest_only_rule_with_suggest_only_suggested_verb_is_rejected() {
        let rule = Rule {
            id: "so-2".into(),
            domain: EnforcementDomain::Ngfw,
            verb: Verb::SuggestOnly,
            suggested_verb: Some(Verb::SuggestOnly),
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: BTreeMap::new(),
        };
        let rules_json = serde_json::to_vec(&[rule]).unwrap();
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json,
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(
            err,
            PolicyEvalError::SuggestOnlyMissingSuggestion { .. }
        ));
    }

    #[test]
    fn suggest_only_default_action_is_rejected() {
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "suggest_only".into(),
            rules_json: vec![],
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(
            err,
            PolicyEvalError::SuggestOnlyMissingSuggestion { rule_id: None }
        ));
    }

    #[test]
    fn suggest_only_rule_with_valid_suggested_verb_loads() {
        let rule = Rule {
            id: "so-3".into(),
            domain: EnforcementDomain::Ngfw,
            verb: Verb::SuggestOnly,
            suggested_verb: Some(Verb::Deny),
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: BTreeMap::new(),
        };
        let rules_json = serde_json::to_vec(&[rule]).unwrap();
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json,
            steering_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let loaded = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert_eq!(loaded.rules[0].verb, Verb::SuggestOnly);
        assert_eq!(loaded.rules[0].suggested_verb, Some(Verb::Deny));
    }
}

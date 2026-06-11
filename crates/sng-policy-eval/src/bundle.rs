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
    /// JSON-encoded `Vec<MalwareEntry>` — the threat-intel
    /// malicious file-hash set the SWG installs into its
    /// `StaticMalwareList`. Optional: the Go side emits it
    /// (`omitempty`) only for the edge / cloud targets that run
    /// the malware inspector and only when a malware-hash
    /// compiler is wired.
    #[serde(
        rename = "mw",
        with = "serde_bytes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    malware_json: Vec<u8>,
    /// JSON-encoded endpoint DLP policy document (rules, channel
    /// config, and the optional AI-app detector policy) the agent's
    /// `sng-dlp` engine installs on bundle apply. Optional: the Go
    /// side emits it (`omitempty`) only for the endpoint target and
    /// only when a DLP compiler is wired. This crate carries it as
    /// opaque bytes — decoding belongs to `sng-dlp`
    /// (`DlpPolicy::from_bundle_json`), which this crate cannot depend
    /// on without a cycle.
    #[serde(
        rename = "dl",
        with = "serde_bytes",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    dlp_json: Vec<u8>,
    #[serde(rename = "ts")]
    compiled_at: DateTime<Utc>,
}

/// One malicious file-hash verdict carried in a bundle's malware
/// section. Mirrors the Go `policy.MalwareHashEntry` (terse JSON
/// keys `h`/`v`). `hash` is lowercase hex; `verdict` is the SWG
/// verdict string (`malicious` / `suspicious` / `clean`).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MalwareEntry {
    /// Lowercase-hex file hash (MD5 / SHA-1 / SHA-256).
    #[serde(rename = "h")]
    pub hash: String,
    /// SWG verdict string for the hash.
    #[serde(rename = "v")]
    pub verdict: String,
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
    /// Threat-intel malicious file-hash set. Empty when the
    /// bundle carried no `mw` section (non-SWG targets, or no
    /// malware-hash compiler wired). The SWG subsystem installs
    /// these into its `StaticMalwareList` on bundle apply.
    pub malware: Arc<[MalwareEntry]>,
    /// Endpoint DLP policy document, verbatim JSON bytes from the
    /// bundle's `dl` section. `None` when the bundle carried no DLP
    /// section (every non-endpoint target, or an endpoint bundle
    /// compiled before a DLP compiler was wired). The agent decodes
    /// it with `sng_dlp::DlpPolicy::from_bundle_json` and installs it
    /// into the live DLP engine on bundle apply; this crate keeps it
    /// opaque to avoid a dependency cycle with `sng-dlp`.
    pub dlp: Option<Arc<[u8]>>,
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
        // Decode the malware-hash set. Optional — omitted on
        // targets that do not run the SWG malware inspector and
        // when no malware-hash compiler is wired.
        let malware: Vec<MalwareEntry> = if raw.malware_json.is_empty() {
            Vec::new()
        } else {
            serde_json::from_slice(&raw.malware_json)
                .map_err(|e| PolicyEvalError::MalwareDecode(format!("decode malware table: {e}")))?
        };
        // The DLP document stays opaque here (see the field docs): we
        // only carry the bytes through to the agent, which owns the
        // `sng-dlp` decoder. An empty section means "no DLP policy in
        // this bundle" and maps to `None`.
        let dlp: Option<Arc<[u8]>> = if raw.dlp_json.is_empty() {
            None
        } else {
            Some(Arc::from(raw.dlp_json.into_boxed_slice()))
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
            malware: Arc::from(malware.into_boxed_slice()),
            dlp,
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

/// Build a fail-closed skeleton bundle body for the given
/// target. The body contains zero rules and a `deny` default
/// verb — so every flow evaluated against the resulting
/// [`LoadedBundle`] returns [`Verb::Deny`].
///
/// This is the canonical "we haven't pulled a real bundle yet"
/// boot fixture used by the binary crates (`sng-edge`,
/// `sng-agent`) so the policy engine is constructible at boot
/// before the control-plane puller has delivered the first real
/// bundle. The architectural contract is "fail closed if the
/// puller never reaches the control plane" — the skeleton
/// implements that contract directly.
///
/// `graph_id` is the canonical "skeleton" UUID
/// (`00000000-0000-0000-0000-000000000001`) so operator
/// dashboards can render a clear "boot skeleton, not a pulled
/// bundle" label without parsing the default verb.
///
/// The body is a valid input to [`LoadedBundle::from_body`] for
/// the same target. It is NOT signed — the binary's
/// initialisation path must construct the [`crate::PolicyEngine`]
/// directly via [`crate::PolicyEngine::from_body`] without a
/// [`sng_core::policy::PolicyVerifier`]. The first real
/// bundle pulled from the control plane MUST go through the
/// verifier before [`crate::PolicyEngine::swap`] is called.
///
/// # Panics
///
/// Never. The internal [`rmp_serde::to_vec_named`] call is
/// infallible for the fully-populated [`RawBundle`] this helper
/// constructs (no skipped fields, all primitives, no nested
/// types that could fail to encode).
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "RawBundle is fully populated with primitives + Vec<u8>; \
              rmp_serde::to_vec_named cannot fail on this shape. Documented \
              in the # Panics section above."
)]
pub fn deny_all_skeleton_body(target: BundleTarget) -> Vec<u8> {
    let raw = RawBundle {
        schema_version: MAX_SUPPORTED_SCHEMA_VERSION,
        target,
        graph_id: "00000000-0000-0000-0000-000000000001".into(),
        graph_version: 0,
        compiler: "sng-bundle-skeleton".into(),
        default_action: "deny".into(),
        rules_json: b"[]".to_vec(),
        steering_json: Vec::new(),
        malware_json: Vec::new(),
        dlp_json: Vec::new(),
        compiled_at: Utc::now(),
    };
    // Infallible for the fully-populated RawBundle above.
    rmp_serde::to_vec_named(&raw).expect("deny-all skeleton bundle body must encode infallibly")
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
            malware_json: vec![],
            dlp_json: vec![],
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
    fn deny_all_skeleton_decodes_to_deny_default_for_every_target() {
        for target in [
            BundleTarget::Edge,
            BundleTarget::Endpoint,
            BundleTarget::Cloud,
            BundleTarget::Mobile,
        ] {
            let body = deny_all_skeleton_body(target);
            let loaded = LoadedBundle::from_body(&body, target).unwrap();
            assert_eq!(loaded.target, target);
            assert_eq!(loaded.default_verb, Verb::Deny);
            assert_eq!(loaded.rule_count(), 0);
            assert!(loaded.steering_raw.is_none());
            assert_eq!(loaded.compiler, "sng-bundle-skeleton");
            assert_eq!(loaded.graph_version, 0);
        }
    }

    #[test]
    fn deny_all_skeleton_rejects_mismatched_target() {
        let body = deny_all_skeleton_body(BundleTarget::Edge);
        let err = LoadedBundle::from_body(&body, BundleTarget::Endpoint).unwrap_err();
        assert!(matches!(err, PolicyEvalError::TargetMismatch { .. }));
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
            malware_json: vec![],
            dlp_json: vec![],
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
            malware_json: vec![],
            dlp_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(err, PolicyEvalError::RulesDecode(_)));
    }

    #[test]
    fn malware_section_decodes_into_loaded_bundle() {
        // The Go control plane emits the `mw` section as a
        // JSON-encoded array of {h,v} objects for edge/cloud
        // targets. Verify it round-trips into LoadedBundle.malware.
        let malware_json = serde_json::to_vec(&vec![
            MalwareEntry {
                hash: "deadbeef".into(),
                verdict: "malicious".into(),
            },
            MalwareEntry {
                hash: "cafebabe".into(),
                verdict: "suspicious".into(),
            },
        ])
        .unwrap();
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            malware_json,
            dlp_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let bundle = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert_eq!(bundle.malware.len(), 2);
        assert_eq!(bundle.malware[0].hash, "deadbeef");
        assert_eq!(bundle.malware[0].verdict, "malicious");
        assert_eq!(bundle.malware[1].hash, "cafebabe");
        assert_eq!(bundle.malware[1].verdict, "suspicious");
    }

    #[test]
    fn dlp_section_round_trips_as_opaque_bytes() {
        // The endpoint bundle carries the DLP policy document under
        // `dl`. This crate keeps it opaque (no `sng-dlp` dependency),
        // so the contract is simply: whatever bytes the compiler put
        // in `dl` come back verbatim on `LoadedBundle.dlp`.
        let doc = br#"{"v":1,"t":"endpoint","domain":"dlp","rules":[]}"#.to_vec();
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Endpoint,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            malware_json: vec![],
            dlp_json: doc.clone(),
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let bundle = LoadedBundle::from_body(&body, BundleTarget::Endpoint).unwrap();
        assert_eq!(bundle.dlp.as_deref(), Some(doc.as_slice()));
    }

    #[test]
    fn absent_dlp_section_decodes_to_none() {
        // Non-endpoint targets (and endpoint bundles compiled before a
        // DLP compiler was wired) omit `dl`; the decoder must treat
        // that as "no DLP policy", not an error.
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            malware_json: vec![],
            dlp_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let bundle = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert!(bundle.dlp.is_none());
    }

    #[test]
    fn absent_malware_section_decodes_to_empty() {
        // Non-SWG targets (and bundles compiled without a
        // malware-hash compiler) omit `mw`; the decoder must
        // treat that as an empty set, not an error.
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            malware_json: vec![],
            dlp_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let bundle = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert!(bundle.malware.is_empty());
    }

    #[test]
    fn malformed_malware_json_returns_malware_decode() {
        let raw = RawBundle {
            schema_version: 1,
            target: BundleTarget::Edge,
            graph_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            graph_version: 1,
            compiler: "test".into(),
            default_action: "deny".into(),
            rules_json: b"[]".to_vec(),
            steering_json: vec![],
            malware_json: b"{not valid json".to_vec(),
            dlp_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let err = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap_err();
        assert!(matches!(err, PolicyEvalError::MalwareDecode(_)));
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
            malware_json: vec![],
            dlp_json: vec![],
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
            malware_json: vec![],
            dlp_json: vec![],
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
            malware_json: vec![],
            dlp_json: vec![],
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
            malware_json: vec![],
            dlp_json: vec![],
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
            malware_json: vec![],
            dlp_json: vec![],
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
            malware_json: vec![],
            dlp_json: vec![],
            compiled_at: Utc::now(),
        };
        let body = encode_msgpack_named(&raw);
        let loaded = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        assert_eq!(loaded.rules[0].verb, Verb::SuggestOnly);
        assert_eq!(loaded.rules[0].suggested_verb, Some(Verb::Deny));
    }
}

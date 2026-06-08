//! [`PolicyEngine`] — the top-level evaluation engine.
//!
//! Holds the current [`LoadedBundle`] behind an [`ArcSwap`] so:
//!
//! - The hot path ([`Self::evaluate`]) clones a cheap `Arc` and
//!   reads every field through it. No locking, no per-flow
//!   allocation; the only heap work is the `Arc::clone` and any
//!   strings the verdict carries away.
//! - Bundle rotation ([`Self::swap`]) is atomic: the next
//!   `evaluate` either sees the entire old bundle or the entire
//!   new one — never a tear.
//! - Concurrent `swap` calls are serialised by an
//!   [`ArcSwap::rcu`] loop wrapping the staleness check and the
//!   pointer install. The closure re-reads the current bundle on
//!   every CAS retry, so two operators racing a policy push
//!   cannot interleave their writes in a way that lets a staler
//!   bundle overwrite a newer one — the read-modify-write is a
//!   single atomic step from the perspective of every other
//!   thread.
//!
//! Replay / downgrade protection: [`Self::swap`] refuses a
//! bundle whose `graph_version` is strictly older than what is
//! currently loaded. Callers pass `force = true` when the
//! operator has deliberately rolled back (e.g. recovery flow).

use crate::bundle::LoadedBundle;
use crate::error::PolicyEvalError;
use crate::flow::Flow;
use crate::rule::{Rule, Subject, SubjectKind, Verb};
use crate::verdict::{InspectLevel, Verdict};
use arc_swap::ArcSwap;
use sng_core::ids::PolicyBundleId;
use sng_core::policy::BundleTarget;
use sng_core::traffic_class::TrafficClass;
use std::sync::Arc;
use tracing::error;

/// Atomic policy evaluation engine. One per agent / edge VM —
/// holds the live bundle and dispatches every flow through it.
#[derive(Debug)]
pub struct PolicyEngine {
    target: BundleTarget,
    bundle: ArcSwap<LoadedBundle>,
}

impl PolicyEngine {
    /// Construct an engine from a verified bundle body. `target`
    /// is the enforcement target this engine is configured for;
    /// the bundle's `t` field must match or the call fails with
    /// [`PolicyEvalError::TargetMismatch`].
    ///
    /// **Invariant**: `body` MUST have been verified through
    /// [`sng_core::policy::PolicyVerifier::verify`] before being
    /// handed to this constructor — see [`LoadedBundle::from_body`].
    pub fn from_body(body: &[u8], target: BundleTarget) -> Result<Self, PolicyEvalError> {
        let loaded = LoadedBundle::from_body(body, target)?;
        Ok(Self {
            target,
            bundle: ArcSwap::from_pointee(loaded),
        })
    }

    /// Hot-swap the loaded bundle. Atomic against concurrent
    /// `evaluate` and `swap` callers.
    ///
    /// Replay / downgrade protection: by default, a bundle
    /// whose `graph_version` is strictly less than the
    /// currently-loaded version is rejected with
    /// [`PolicyEvalError::Stale`]. Pass `force = true` to accept
    /// an older version (recovery / explicit rollback).
    ///
    /// Concurrency: the staleness check and the pointer install
    /// run inside [`ArcSwap::rcu`] so a slow swap of e.g. v7
    /// cannot overwrite a fast swap of v10 that committed
    /// between our [`from_body`](LoadedBundle::from_body) and our
    /// store. Previously this method did a plain
    /// `load`-check-`store` sequence which had a TOCTOU window
    /// against concurrent installers; the rcu loop closes it by
    /// re-evaluating the staleness predicate on every retry.
    /// The expensive work (signature verification, body decode,
    /// claims parse via [`LoadedBundle::from_body`]) happens
    /// exactly once outside the loop — concurrent swaps only
    /// serialise on the cheap version-compare and the atomic
    /// pointer CAS.
    pub fn swap(&self, body: &[u8], force: bool) -> Result<(), PolicyEvalError> {
        let next = Arc::new(LoadedBundle::from_body(body, self.target)?);
        if force {
            // Operator-acknowledged rollback — skip the rcu
            // loop entirely. There is no version invariant to
            // protect, so a single atomic store is sufficient.
            self.bundle.store(next);
            return Ok(());
        }
        // Atomic version-check-and-install. The closure may run
        // multiple times if a concurrent `swap` commits between
        // our snapshot read and our CAS; `stale` is overwritten
        // on every iteration so its value after the loop reflects
        // the *last* (committed) iteration's verdict, not an
        // intermediate one that was retried away.
        let mut stale: Option<(PolicyBundleId, i64, i64)> = None;
        self.bundle.rcu(|current| {
            if next.graph_version < current.graph_version {
                // Reject — return the current pointer so the CAS
                // is a no-op and other writers can commit ahead
                // of us without interference.
                stale = Some((
                    next.bundle_id().unwrap_or_else(PolicyBundleId::nil),
                    next.graph_version,
                    current.graph_version,
                ));
                Arc::clone(current)
            } else {
                // Accept — try to install `next`. If a concurrent
                // writer races us, the CAS fails and the closure
                // re-runs against the freshly-observed current,
                // at which point we re-evaluate the staleness
                // predicate against the new `current.graph_version`
                // — so we cannot overwrite a newer bundle that
                // committed between our `from_body` and our CAS.
                stale = None;
                Arc::clone(&next)
            }
        });
        if let Some((bundle_id, found, current)) = stale {
            return Err(PolicyEvalError::Stale {
                bundle_id,
                found,
                current,
            });
        }
        Ok(())
    }

    /// Snapshot the currently-loaded bundle as a cheap `Arc`
    /// clone. The returned bundle is immutable; the engine may
    /// swap a newer one in concurrently but the caller's
    /// snapshot remains stable.
    #[must_use]
    pub fn current_bundle(&self) -> Arc<LoadedBundle> {
        self.bundle.load_full()
    }

    /// The bundle target the engine is configured for.
    #[must_use]
    pub fn target(&self) -> BundleTarget {
        self.target
    }

    /// Evaluate a flow against the current bundle.
    ///
    /// Algorithm:
    ///
    /// 1. Iterate rules in source order.
    /// 2. Skip rules whose `domain` doesn't match the flow's
    ///    `enforcement_domain` — keeps the firewall from acting
    ///    on a DLP rule, etc.
    /// 3. For each remaining rule, run subject + predicate
    ///    matchers. Both refs (named, resolved against the
    ///    bundle's vertex tables) and inline matchers are
    ///    evaluated. The rule matches when EVERY subject and
    ///    EVERY predicate match. An empty subject set is
    ///    treated as "any subject"; same for predicates.
    /// 4. The first matching rule wins — its verb is converted
    ///    to a [`Verdict`].
    /// 5. If no rule matches, fall back to the bundle's
    ///    [`LoadedBundle::default_verb`].
    pub fn evaluate(&self, flow: &Flow<'_>) -> Verdict {
        let bundle = self.bundle.load();
        for rule in bundle.rules.iter() {
            if !rule.applies_to_domain(flow.enforcement_domain) {
                continue;
            }
            if !subjects_match(rule, flow, &bundle) {
                continue;
            }
            if !predicates_match(rule, flow, &bundle) {
                continue;
            }
            return verb_to_verdict(rule.verb, rule.suggested_verb, flow, &bundle);
        }
        // Default action — no rule matched. `default_verb` is
        // guaranteed by [`LoadedBundle::from_body`] not to be
        // `SuggestOnly`, so the `None` suggested-verb here cannot
        // trigger the defensive `Verdict::Allow` fallback path.
        verb_to_verdict(bundle.default_verb, None, flow, &bundle)
    }
}

/// Resolve every subject (named refs + inline) on the rule. All
/// subjects must match for the rule to fire. An empty subject
/// set is treated as "any subject" so a rule with only
/// predicates still matches.
fn subjects_match(rule: &Rule, flow: &Flow<'_>, bundle: &LoadedBundle) -> bool {
    for name in &rule.subject_refs {
        let Some(subject) = bundle.named_subjects.get(name.as_str()) else {
            // Unknown named ref — the bundle is internally
            // inconsistent. Treat as non-match (fail-closed).
            return false;
        };
        if !subject_matches_flow(subject, flow) {
            return false;
        }
    }
    for subject in &rule.subjects {
        if !subject_matches_flow(subject, flow) {
            return false;
        }
    }
    true
}

/// Resolve every predicate on the rule. Empty predicate set is
/// "no extra condition".
fn predicates_match(rule: &Rule, flow: &Flow<'_>, bundle: &LoadedBundle) -> bool {
    for name in &rule.predicate_refs {
        let Some(predicate) = bundle.named_predicates.get(name.as_str()) else {
            return false;
        };
        if !predicate.matcher.matches_context(flow.context) {
            return false;
        }
    }
    for p in &rule.predicates {
        if !p.matcher.matches_context(flow.context) {
            return false;
        }
    }
    true
}

/// Dispatch a single subject vertex against the right flow
/// field. The `kind` field selects which principal (user /
/// device / app / site / network) to compare; the matcher then
/// decides whether the value matches.
///
/// If the flow doesn't supply the principal the subject
/// requires (e.g. a `user`-kind subject against a flow with no
/// user), the subject is treated as non-matching — omitted
/// facts do not silently authorise.
fn subject_matches_flow(subject: &Subject, flow: &Flow<'_>) -> bool {
    match subject.kind {
        SubjectKind::User => flow.user.is_some_and(|u| subject.matcher.matches_string(u)),
        SubjectKind::Device => flow
            .device
            .is_some_and(|d| subject.matcher.matches_string(d)),
        SubjectKind::App => flow.app.is_some_and(|a| subject.matcher.matches_string(a)),
        SubjectKind::Site => flow.site.is_some_and(|s| subject.matcher.matches_string(s)),
        SubjectKind::Network => flow
            .source_ip
            .is_some_and(|addr| subject.matcher.matches_ip(addr)),
    }
}

/// Map a fired-rule verb onto a concrete [`Verdict`], threading
/// the steering table for the `Steer` case and the rule's
/// `suggested_verb` for the [`Verb::SuggestOnly`] case.
///
/// `suggested_verb` is the rule's [`crate::rule::Rule::suggested_verb`]
/// (`None` when the caller is the bundle-level default-action path,
/// which [`crate::bundle::LoadedBundle::from_body`] guarantees is
/// not `SuggestOnly`). For any non-`SuggestOnly` `verb` this
/// argument is ignored.
///
/// The `verb = SuggestOnly` + `suggested_verb = None` path is
/// unreachable in practice — [`crate::bundle::LoadedBundle::from_body`]
/// rejects such bundles with
/// [`crate::error::PolicyEvalError::SuggestOnlyMissingSuggestion`].
/// We defensively map it to [`Verdict::Allow`] (the most permissive
/// non-blocking verdict, matching the existing `SuggestOnly`
/// is-not-blocking semantics) rather than panicking, so a malformed
/// bundle that somehow bypassed validation still fails open at the
/// evaluation layer.
///
/// The `Allow` fallback preserves the documented `SuggestOnly`
/// contract (it is never a blocking verdict). The trade-off is
/// that if a future refactor accidentally bypasses the load-time
/// validator the engine silently allows traffic instead of
/// denying it. We mitigate that by emitting a `tracing::error!`
/// at the point of the unreachable branch so the malformed bundle
/// surfaces immediately in operator logs / alerting, and pinning
/// the behaviour with [`tests::malformed_suggestonly_falls_back_to_allow`]
/// so a future contributor cannot silently change the failure
/// mode without updating the test — every call to `evaluate()`
/// against a malformed bundle will produce a log line tagged
/// `suggest_only_missing_suggestion = true` (on the
/// `sng_policy_eval` target) that dashboards / alerts can
/// pick up.
fn verb_to_verdict(
    verb: Verb,
    suggested_verb: Option<Verb>,
    flow: &Flow<'_>,
    bundle: &LoadedBundle,
) -> Verdict {
    match verb {
        Verb::Allow => Verdict::Allow,
        Verb::Deny => Verdict::Deny,
        Verb::Decrypt => Verdict::Decrypt,
        Verb::Log => Verdict::Log,
        Verb::Inspect => Verdict::Inspect {
            level: InspectLevel::Full,
        },
        Verb::Steer => Verdict::Steer {
            class: steering_class_for_flow(flow, bundle),
        },
        Verb::SuggestOnly => match suggested_verb {
            Some(v) if v != Verb::SuggestOnly => Verdict::SuggestOnly { suggestion: v },
            _ => {
                // Unreachable in practice: `LoadedBundle::from_body`
                // rejects bundles whose default verb or whose
                // matched rule's verb is `SuggestOnly` without a
                // valid `suggested_verb`. Emit a structured error
                // so an operator sees the malformed bundle in
                // logs / alerting if validation is ever bypassed,
                // then fall back to `Allow` to preserve the
                // documented `SuggestOnly` (non-blocking) contract.
                error!(
                    target: "sng_policy_eval",
                    suggest_only_missing_suggestion = true,
                    bundle_id = ?bundle.bundle_id(),
                    bundle_graph_version = bundle.graph_version,
                    "SuggestOnly verb reached evaluator without a valid suggested_verb \
                     — load-time validation was bypassed; falling back to Verdict::Allow \
                     to preserve the SuggestOnly contract"
                );
                Verdict::Allow
            }
        },
    }
}

/// Look up the steering class for the flow's destination.
/// Tries the steering table first (hostname → IP); falls back
/// to [`TrafficClass::default_conservative`] (= `InspectFull`)
/// when nothing matches, matching the Go
/// `appdb/service.go::ResolveTrafficClass` semantics.
fn steering_class_for_flow(flow: &Flow<'_>, bundle: &LoadedBundle) -> TrafficClass {
    if let Some(host) = flow.destination_host
        && let Some(class) = bundle.steering.class_for_host(host)
    {
        return class;
    }
    if let Some(ip) = flow.destination_ip
        && let Some(class) = bundle.steering.class_for_ip(ip)
    {
        return class;
    }
    TrafficClass::default_conservative()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::{PredicateMatch, SubjectMatch};
    use crate::rule::{EnforcementDomain, Predicate};
    use crate::steering::{SteeringClassRules, SteeringRuleSet};
    use chrono::Utc;
    use pretty_assertions::assert_eq;
    use serde::Serialize;
    use std::collections::BTreeMap;

    #[derive(Serialize)]
    struct WireBundle<'a> {
        #[serde(rename = "v")]
        v: u8,
        #[serde(rename = "t")]
        t: BundleTarget,
        #[serde(rename = "g")]
        g: &'a str,
        #[serde(rename = "gv")]
        gv: i64,
        #[serde(rename = "c")]
        c: &'a str,
        #[serde(rename = "d")]
        d: &'a str,
        #[serde(rename = "r", with = "serde_bytes")]
        r: &'a [u8],
        #[serde(
            rename = "st",
            with = "serde_bytes",
            skip_serializing_if = "<[u8]>::is_empty"
        )]
        st: &'a [u8],
        #[serde(rename = "ts")]
        ts: chrono::DateTime<Utc>,
    }

    fn encode_bundle(
        target: BundleTarget,
        graph_version: i64,
        default_action: &str,
        rules: &[Rule],
        steering: Option<&SteeringRuleSet>,
    ) -> Vec<u8> {
        let rules_json = serde_json::to_vec(rules).unwrap();
        let steering_json = steering
            .map(|s| serde_json::to_vec(s).unwrap())
            .unwrap_or_default();
        let wire = WireBundle {
            v: 1,
            t: target,
            g: "550e8400-e29b-41d4-a716-446655440000",
            gv: graph_version,
            c: "test",
            d: default_action,
            r: &rules_json,
            st: &steering_json,
            ts: Utc::now(),
        };
        rmp_serde::to_vec_named(&wire).unwrap()
    }

    fn rule(id: &str, domain: EnforcementDomain, verb: Verb) -> Rule {
        Rule {
            id: id.into(),
            domain,
            verb,
            suggested_verb: None,
            subject_refs: vec![],
            predicate_refs: vec![],
            subjects: vec![],
            predicates: vec![],
            targets: vec![],
            description: String::new(),
            extra: BTreeMap::new(),
        }
    }

    #[test]
    fn empty_bundle_evaluates_to_default_verb() {
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow::default();
        assert_eq!(eng.evaluate(&flow), Verdict::Deny);
    }

    #[test]
    fn first_matching_rule_wins() {
        let r1 = Rule {
            description: "first".into(),
            ..rule("a", EnforcementDomain::Ngfw, Verb::Allow)
        };
        let r2 = Rule {
            description: "second".into(),
            ..rule("b", EnforcementDomain::Ngfw, Verb::Deny)
        };
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[r1, r2], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&flow), Verdict::Allow);
    }

    #[test]
    fn rule_in_other_domain_is_skipped() {
        let dns_allow = rule("a", EnforcementDomain::Dns, Verb::Allow);
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[dns_allow], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let ngfw_flow = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&ngfw_flow), Verdict::Deny);
        let dns_flow = Flow {
            enforcement_domain: EnforcementDomain::Dns,
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&dns_flow), Verdict::Allow);
    }

    #[test]
    fn subject_match_filters_by_user() {
        let mut r = rule("a", EnforcementDomain::Ngfw, Verb::Allow);
        r.subjects.push(Subject {
            name: String::new(),
            kind: SubjectKind::User,
            matcher: SubjectMatch::Literal {
                value: "alice".into(),
            },
        });
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[r], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();

        let alice = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            user: Some("alice"),
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&alice), Verdict::Allow);

        let bob = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            user: Some("bob"),
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&bob), Verdict::Deny);

        let no_user = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&no_user), Verdict::Deny);
    }

    #[test]
    fn predicate_filters_by_context() {
        let mut r = rule("a", EnforcementDomain::Swg, Verb::Deny);
        r.predicates.push(Predicate {
            name: String::new(),
            matcher: PredicateMatch::ContextEquals {
                key: "category".into(),
                value: "malware".into(),
            },
        });
        let body = encode_bundle(BundleTarget::Edge, 1, "allow", &[r], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();

        let ctx_malware: &[(&str, &str)] = &[("category", "malware")];
        let malware_flow = Flow {
            enforcement_domain: EnforcementDomain::Swg,
            context: ctx_malware,
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&malware_flow), Verdict::Deny);

        let ctx_social: &[(&str, &str)] = &[("category", "social")];
        let social_flow = Flow {
            enforcement_domain: EnforcementDomain::Swg,
            context: ctx_social,
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&social_flow), Verdict::Allow);
    }

    #[test]
    fn steer_verdict_uses_steering_table() {
        let r = rule("a", EnforcementDomain::Sdwan, Verb::Steer);
        let steering = SteeringRuleSet {
            target: "edge".into(),
            schema_version: 1,
            classes: vec![SteeringClassRules {
                class: TrafficClass::TrustedDirect,
                action: "direct".into(),
                domains: vec!["microsoft.com".into()],
                ip_ranges: vec![],
                cert_pins: vec![],
                apps: vec![],
            }],
        };
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[r], Some(&steering));
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow {
            enforcement_domain: EnforcementDomain::Sdwan,
            destination_host: Some("microsoft.com"),
            ..Flow::default()
        };
        assert_eq!(
            eng.evaluate(&flow),
            Verdict::Steer {
                class: TrafficClass::TrustedDirect
            }
        );
    }

    #[test]
    fn steer_verdict_falls_back_to_conservative_when_no_match() {
        let r = rule("a", EnforcementDomain::Sdwan, Verb::Steer);
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[r], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow {
            enforcement_domain: EnforcementDomain::Sdwan,
            destination_host: Some("unknown.test"),
            ..Flow::default()
        };
        assert_eq!(
            eng.evaluate(&flow),
            Verdict::Steer {
                class: TrafficClass::default_conservative()
            }
        );
    }

    #[test]
    fn swap_to_newer_version_succeeds() {
        let v1 = encode_bundle(BundleTarget::Edge, 1, "deny", &[], None);
        let v2 = encode_bundle(BundleTarget::Edge, 2, "allow", &[], None);
        let eng = PolicyEngine::from_body(&v1, BundleTarget::Edge).unwrap();
        assert_eq!(eng.current_bundle().graph_version, 1);
        eng.swap(&v2, false).unwrap();
        assert_eq!(eng.current_bundle().graph_version, 2);
        assert_eq!(eng.evaluate(&Flow::default()), Verdict::Allow);
    }

    #[test]
    fn swap_to_older_version_rejected_without_force() {
        let v2 = encode_bundle(BundleTarget::Edge, 2, "deny", &[], None);
        let v1 = encode_bundle(BundleTarget::Edge, 1, "allow", &[], None);
        let eng = PolicyEngine::from_body(&v2, BundleTarget::Edge).unwrap();
        let err = eng.swap(&v1, false).unwrap_err();
        assert!(matches!(
            err,
            PolicyEvalError::Stale {
                found: 1,
                current: 2,
                ..
            }
        ));
        assert_eq!(eng.current_bundle().graph_version, 2);
    }

    #[test]
    fn swap_to_older_version_accepted_with_force() {
        let v2 = encode_bundle(BundleTarget::Edge, 2, "deny", &[], None);
        let v1 = encode_bundle(BundleTarget::Edge, 1, "allow", &[], None);
        let eng = PolicyEngine::from_body(&v2, BundleTarget::Edge).unwrap();
        eng.swap(&v1, true).unwrap();
        assert_eq!(eng.current_bundle().graph_version, 1);
    }

    #[test]
    fn swap_target_mismatch_rejected() {
        let v1 = encode_bundle(BundleTarget::Edge, 1, "deny", &[], None);
        let endpoint = encode_bundle(BundleTarget::Endpoint, 2, "deny", &[], None);
        let eng = PolicyEngine::from_body(&v1, BundleTarget::Edge).unwrap();
        let err = eng.swap(&endpoint, false).unwrap_err();
        assert!(matches!(err, PolicyEvalError::TargetMismatch { .. }));
        assert_eq!(eng.current_bundle().target, BundleTarget::Edge);
    }

    #[test]
    fn named_subject_ref_unknown_fails_closed() {
        let mut r = rule("a", EnforcementDomain::Ngfw, Verb::Allow);
        r.subject_refs.push("undeclared".into());
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[r], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            user: Some("alice"),
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&flow), Verdict::Deny);
    }

    #[test]
    fn named_subject_ref_resolves_when_declared_inline_on_another_rule() {
        let named_subject = Subject {
            name: "alice-only".into(),
            kind: SubjectKind::User,
            matcher: SubjectMatch::Literal {
                value: "alice".into(),
            },
        };
        let r1 = Rule {
            subjects: vec![named_subject.clone()],
            ..rule("declare", EnforcementDomain::Dns, Verb::Log)
        };
        let mut r2 = rule("uses-ref", EnforcementDomain::Ngfw, Verb::Allow);
        r2.subject_refs.push("alice-only".into());
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[r1, r2], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let alice = Flow {
            enforcement_domain: EnforcementDomain::Ngfw,
            user: Some("alice"),
            ..Flow::default()
        };
        assert_eq!(eng.evaluate(&alice), Verdict::Allow);
    }

    #[test]
    fn concurrent_swap_and_evaluate_does_not_deadlock_or_panic() {
        let v1 = encode_bundle(BundleTarget::Edge, 1, "deny", &[], None);
        let eng = Arc::new(PolicyEngine::from_body(&v1, BundleTarget::Edge).unwrap());
        let writer = {
            let eng = Arc::clone(&eng);
            std::thread::spawn(move || {
                for i in 2..50 {
                    let body = encode_bundle(BundleTarget::Edge, i, "deny", &[], None);
                    eng.swap(&body, false).unwrap();
                }
            })
        };
        let reader = {
            let eng = Arc::clone(&eng);
            std::thread::spawn(move || {
                let flow = Flow::default();
                for _ in 0..10_000 {
                    let v = eng.evaluate(&flow);
                    assert_eq!(v, Verdict::Deny);
                }
            })
        };
        writer.join().unwrap();
        reader.join().unwrap();
        assert_eq!(eng.current_bundle().graph_version, 49);
    }

    /// Regression: two writer threads racing concurrent swaps
    /// must not let a staler version overwrite a newer one. Under
    /// the pre-rcu implementation this test occasionally observed
    /// a final `graph_version` strictly less than the maximum
    /// committed value because thread A's `load` returned `v_old`,
    /// thread B then `store`d `v_max`, and thread A's
    /// `store(v_intermediate)` clobbered B's write. The rcu loop
    /// closes that window by re-evaluating the staleness check on
    /// every CAS retry.
    #[test]
    fn concurrent_swap_writers_preserve_monotonic_max() {
        // Each writer attempts a strictly-ascending series of
        // versions disjoint with the other writer's series. The
        // final version must be the max across both series — any
        // observed `current_bundle().graph_version` strictly less
        // than that is a TOCTOU regression. We iterate the entire
        // experiment many times because the race window is small
        // (microseconds) and a single iteration may miss it.
        const ITERATIONS: usize = 64;
        const PER_WRITER_STEPS: i64 = 200;
        for iter in 0..ITERATIONS {
            let v0 = encode_bundle(BundleTarget::Edge, 1, "deny", &[], None);
            let eng = Arc::new(PolicyEngine::from_body(&v0, BundleTarget::Edge).unwrap());
            // Writer A installs even versions 2, 4, …, 2*PER_WRITER_STEPS.
            // Writer B installs odd versions  3, 5, …, 2*PER_WRITER_STEPS+1.
            // Final committed version must be at least
            // `2 * PER_WRITER_STEPS` (writer A's max) since every
            // version writer A installs is `>=` the engine's
            // current; the rcu loop guarantees the final state is
            // the highest-numbered swap that ever committed.
            let target_max = 2 * PER_WRITER_STEPS + 1;
            let writer_a = {
                let eng = Arc::clone(&eng);
                std::thread::spawn(move || {
                    for step in 1..=PER_WRITER_STEPS {
                        let v = step * 2;
                        let body = encode_bundle(BundleTarget::Edge, v, "deny", &[], None);
                        // `swap` MAY return Stale if the other
                        // writer has already raced ahead — that's
                        // not a bug, it's the very downgrade-
                        // protection invariant under test.
                        let _ = eng.swap(&body, false);
                    }
                })
            };
            let writer_b = {
                let eng = Arc::clone(&eng);
                std::thread::spawn(move || {
                    for step in 1..=PER_WRITER_STEPS {
                        let v = step * 2 + 1;
                        let body = encode_bundle(BundleTarget::Edge, v, "deny", &[], None);
                        let _ = eng.swap(&body, false);
                    }
                })
            };
            writer_a.join().unwrap();
            writer_b.join().unwrap();
            let final_v = eng.current_bundle().graph_version;
            // Under the OLD code, final_v could end up at a value
            // strictly less than `target_max` even though both
            // writers ran to completion, because a stale
            // unconditional store could clobber a fresher one.
            // Under the rcu fix, final_v always equals target_max
            // (the maximum version anyone tried to install).
            assert_eq!(
                final_v, target_max,
                "iteration {iter}: final version {final_v} != expected max {target_max} \
                 — concurrent swaps lost a write (TOCTOU regression)",
            );
        }
    }

    #[test]
    fn suggest_only_verdict_carries_the_suggested_verb() {
        let mut r = rule("suggest-deny", EnforcementDomain::Ngfw, Verb::SuggestOnly);
        r.suggested_verb = Some(Verb::Deny);
        let body = encode_bundle(BundleTarget::Edge, 1, "allow", &[r], None);
        let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow::default();
        assert_eq!(
            eng.evaluate(&flow),
            Verdict::SuggestOnly {
                suggestion: Verb::Deny,
            }
        );
        assert!(!eng.evaluate(&flow).is_blocking());
    }

    #[test]
    fn malformed_suggest_only_without_suggestion_falls_back_to_allow() {
        // Defence-in-depth pin: a `SuggestOnly` verb with no
        // `suggested_verb` would normally be rejected by
        // `LoadedBundle::from_body`, but if that validator is ever
        // bypassed `verb_to_verdict` must still produce a
        // non-blocking verdict per the SuggestOnly contract. Direct
        // unit test on `verb_to_verdict` so the test pins the
        // fallback even though the bundle path can't construct the
        // malformed shape. A `tracing::error!` is also emitted on
        // this branch so an operator sees the malformed bundle in
        // logs; the test verifies the verdict only (capturing the
        // tracing event would require a heavyweight subscriber).
        let body = encode_bundle(BundleTarget::Edge, 1, "deny", &[], None);
        let bundle = LoadedBundle::from_body(&body, BundleTarget::Edge).unwrap();
        let flow = Flow::default();
        let v = verb_to_verdict(Verb::SuggestOnly, None, &flow, &bundle);
        assert_eq!(v, Verdict::Allow);
        assert!(!v.is_blocking(), "SuggestOnly contract: never blocking");
        // Also pin the `Some(SuggestOnly)` cycle-rejection branch
        // — a nested `SuggestOnly` suggestion must collapse to
        // Allow rather than recursing.
        let v = verb_to_verdict(Verb::SuggestOnly, Some(Verb::SuggestOnly), &flow, &bundle);
        assert_eq!(v, Verdict::Allow);
    }
}

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Criterion benchmarks for [`sng_policy_eval::PolicyEngine`].
//!
//! Targets sub-microsecond per-flow verdicts for the common
//! cases per the PR4 plan. The benches exercise four shapes:
//!
//! 1. **`evaluate/default_action`** — empty rule list, default
//!    fires. Lower bound on the hot path.
//! 2. **`evaluate/literal_subject`** — single rule with a
//!    literal subject match on the user principal. Common in
//!    operator-written policies.
//! 3. **`evaluate/steer_with_steering_lookup`** — rule with
//!    verb `steer`, requiring the steering table lookup. Tests
//!    the literal-domain hash hit.
//! 4. **`evaluate/100_rules`** — 100-rule bundle, matching the
//!    last rule. Tests linear-scan overhead at realistic graph
//!    sizes.
//!
//! Run with `cargo bench -p sng-policy-eval`. Numbers will
//! drift across hardware; the bench is here to make
//! regressions visible in PR diffs.

use criterion::{Criterion, criterion_group, criterion_main};
use sng_policy_eval::{
    BundleTarget, EnforcementDomain, Flow, PolicyEngine, Predicate, Rule, SteeringClassRules,
    SteeringRuleSet, Subject, SubjectKind, SubjectMatch, TrafficClass, Verb,
};
use std::collections::BTreeMap;
use std::hint::black_box;

#[derive(serde::Serialize)]
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
    ts: chrono::DateTime<chrono::Utc>,
}

fn encode_bundle(
    rules: &[Rule],
    steering: Option<&SteeringRuleSet>,
    default_action: &str,
) -> Vec<u8> {
    let rules_json = serde_json::to_vec(rules).unwrap();
    let steering_json = steering
        .map(|s| serde_json::to_vec(s).unwrap())
        .unwrap_or_default();
    let wire = WireBundle {
        v: 1,
        t: BundleTarget::Edge,
        g: "550e8400-e29b-41d4-a716-446655440000",
        gv: 1,
        c: "bench",
        d: default_action,
        r: &rules_json,
        st: &steering_json,
        ts: chrono::Utc::now(),
    };
    rmp_serde::to_vec_named(&wire).unwrap()
}

fn rule(id: &str, domain: EnforcementDomain, verb: Verb) -> Rule {
    Rule {
        id: id.into(),
        domain,
        verb,
        subject_refs: vec![],
        predicate_refs: vec![],
        subjects: vec![],
        predicates: vec![],
        targets: vec![],
        description: String::new(),
        extra: BTreeMap::new(),
    }
}

fn bench_default_action(c: &mut Criterion) {
    let body = encode_bundle(&[], None, "deny");
    let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
    let flow = Flow {
        enforcement_domain: EnforcementDomain::Ngfw,
        ..Flow::default()
    };
    c.bench_function("evaluate/default_action", |b| {
        b.iter(|| {
            let v = eng.evaluate(black_box(&flow));
            black_box(v);
        });
    });
}

fn bench_literal_subject(c: &mut Criterion) {
    let mut r = rule("a", EnforcementDomain::Ngfw, Verb::Allow);
    r.subjects.push(Subject {
        name: String::new(),
        kind: SubjectKind::User,
        matcher: SubjectMatch::Literal {
            value: "alice".into(),
        },
    });
    let body = encode_bundle(&[r], None, "deny");
    let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
    let flow = Flow {
        enforcement_domain: EnforcementDomain::Ngfw,
        user: Some("alice"),
        ..Flow::default()
    };
    c.bench_function("evaluate/literal_subject", |b| {
        b.iter(|| {
            let v = eng.evaluate(black_box(&flow));
            black_box(v);
        });
    });
}

fn bench_steer_with_steering_lookup(c: &mut Criterion) {
    let r = rule("a", EnforcementDomain::Sdwan, Verb::Steer);
    let steering = SteeringRuleSet {
        target: "edge".into(),
        schema_version: 1,
        classes: vec![SteeringClassRules {
            class: TrafficClass::TrustedDirect,
            action: "direct".into(),
            domains: vec!["microsoft.com".into(), "office365.com".into()],
            ip_ranges: vec![],
            cert_pins: vec![],
            apps: vec![],
        }],
    };
    let body = encode_bundle(&[r], Some(&steering), "deny");
    let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
    let flow = Flow {
        enforcement_domain: EnforcementDomain::Sdwan,
        destination_host: Some("microsoft.com"),
        ..Flow::default()
    };
    c.bench_function("evaluate/steer_with_steering_lookup", |b| {
        b.iter(|| {
            let v = eng.evaluate(black_box(&flow));
            black_box(v);
        });
    });
}

fn bench_100_rules_last_matches(c: &mut Criterion) {
    let mut rules: Vec<Rule> = (0..99)
        .map(|i| {
            let mut r = rule(&format!("r-{i}"), EnforcementDomain::Ngfw, Verb::Allow);
            r.subjects.push(Subject {
                name: String::new(),
                kind: SubjectKind::User,
                matcher: SubjectMatch::Literal {
                    value: format!("user-{i}"),
                },
            });
            r
        })
        .collect();
    let mut last = rule("last", EnforcementDomain::Ngfw, Verb::Deny);
    last.subjects.push(Subject {
        name: String::new(),
        kind: SubjectKind::User,
        matcher: SubjectMatch::Literal {
            value: "target".into(),
        },
    });
    rules.push(last);
    let body = encode_bundle(&rules, None, "allow");
    let eng = PolicyEngine::from_body(&body, BundleTarget::Edge).unwrap();
    let flow = Flow {
        enforcement_domain: EnforcementDomain::Ngfw,
        user: Some("target"),
        ..Flow::default()
    };
    c.bench_function("evaluate/100_rules_last_matches", |b| {
        b.iter(|| {
            let v = eng.evaluate(black_box(&flow));
            black_box(v);
        });
    });
}

// Suppress dead-code warning for Predicate import; it's used
// transitively but the bench module wants the symbol available
// for future bench shapes.
#[allow(dead_code)]
fn _ensure_predicate_import_referenced() -> Predicate {
    Predicate {
        name: String::new(),
        matcher: sng_policy_eval::PredicateMatch::Always,
    }
}

criterion_group!(
    benches,
    bench_default_action,
    bench_literal_subject,
    bench_steer_with_steering_lookup,
    bench_100_rules_last_matches
);
criterion_main!(benches);

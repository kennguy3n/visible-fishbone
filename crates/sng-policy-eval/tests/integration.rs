#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_possible_truncation
)]

//! End-to-end integration tests for `sng-policy-eval`.
//!
//! Exercises the full pipeline a real receiver runs:
//!
//! 1. Producer builds a typed rule list + steering table.
//! 2. Producer encodes the bundle envelope (MessagePack with
//!    JSON-encoded `r` and `st` sub-documents — wire-compatible
//!    with the Go compiler).
//! 3. Producer signs the body with Ed25519 (the same curve the
//!    Go control plane uses).
//! 4. Receiver verifies the signature via
//!    [`sng_core::policy::PolicyVerifier`].
//! 5. Receiver constructs a [`sng_policy_eval::PolicyEngine`]
//!    from the verified body.
//! 6. Receiver evaluates flows and asserts verdicts.
//!
//! These tests are the closest thing the workspace has to a
//! cross-language wire-compatibility check until the Go and
//! Rust sides share a fixture corpus.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::Serialize;
use sng_core::ids::PolicySigningKeyId;
use sng_core::policy::{BundleSignature, BundleTarget, PolicyBundle, PolicyVerifier};
use sng_policy_eval::{
    EnforcementDomain, Flow, FlowBuilder, PolicyEngine, Rule, SteeringClassRules, SteeringRuleSet,
    Subject, SubjectKind, SubjectMatch, TrafficClass, Verb, Verdict,
};
use std::collections::BTreeMap;

/// Wire shape mirroring the Go compiler's `bundlePayload`.
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
    ts: chrono::DateTime<chrono::Utc>,
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

fn encode_bundle_body(
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
        c: "integration-test",
        d: default_action,
        r: &rules_json,
        st: &steering_json,
        ts: chrono::Utc::now(),
    };
    rmp_serde::to_vec_named(&wire).unwrap()
}

fn sign_body(signing_key: &SigningKey, key_id: &PolicySigningKeyId, body: Vec<u8>) -> PolicyBundle {
    let sig = signing_key.sign(&body);
    PolicyBundle {
        body,
        signature: BundleSignature {
            bytes: sig.to_bytes(),
        },
        signing_key_id: key_id.clone(),
    }
}

fn build_verifier(verify_key: VerifyingKey, key_id: &PolicySigningKeyId) -> PolicyVerifier {
    let mut v = PolicyVerifier::new();
    v.add_key(key_id.clone(), &verify_key.to_bytes())
        .expect("insert valid Ed25519 verifying key");
    v
}

#[test]
fn signed_bundle_round_trips_through_verifier_and_engine() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let key_id = PolicySigningKeyId::new("test-key-1").unwrap();

    let mut r = rule("allow-alice", EnforcementDomain::Ngfw, Verb::Allow);
    r.subjects.push(Subject {
        name: String::new(),
        kind: SubjectKind::User,
        matcher: SubjectMatch::Literal {
            value: "alice".into(),
        },
    });
    let body = encode_bundle_body(BundleTarget::Edge, 1, "deny", &[r], None);
    let bundle = sign_body(&signing_key, &key_id, body);

    let verifier = build_verifier(verify_key, &key_id);
    verifier.verify(&bundle).expect("bundle should verify");

    let eng = PolicyEngine::from_body(&bundle.body, BundleTarget::Edge)
        .expect("engine should load verified bundle");

    let alice = FlowBuilder::new(EnforcementDomain::Ngfw)
        .user("alice")
        .build();
    assert_eq!(eng.evaluate(&alice), Verdict::Allow);

    let bob = FlowBuilder::new(EnforcementDomain::Ngfw)
        .user("bob")
        .build();
    assert_eq!(eng.evaluate(&bob), Verdict::Deny);
}

#[test]
fn tampered_body_fails_signature_verification_and_never_reaches_engine() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let key_id = PolicySigningKeyId::new("test-key-2").unwrap();

    let body = encode_bundle_body(BundleTarget::Edge, 1, "deny", &[], None);
    let mut bundle = sign_body(&signing_key, &key_id, body);
    bundle.body[0] ^= 0x55;

    let verifier = build_verifier(verify_key, &key_id);
    assert!(
        verifier.verify(&bundle).is_err(),
        "tampered bundle MUST NOT pass verification"
    );
}

#[test]
fn signed_bundle_with_steering_table_routes_flows_to_correct_class() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let key_id = PolicySigningKeyId::new("test-key-3").unwrap();

    let r = rule("steer-everything", EnforcementDomain::Sdwan, Verb::Steer);
    let steering = SteeringRuleSet {
        target: "edge".into(),
        schema_version: 1,
        classes: vec![
            SteeringClassRules {
                class: TrafficClass::TrustedDirect,
                action: "direct".into(),
                domains: vec!["microsoft.com".into(), "*.office365.com".into()],
                ip_ranges: vec![],
                cert_pins: vec![],
                apps: vec![],
            },
            SteeringClassRules {
                class: TrafficClass::Block,
                action: "block".into(),
                domains: vec!["evil.test".into()],
                ip_ranges: vec![],
                cert_pins: vec![],
                apps: vec![],
            },
        ],
    };
    let body = encode_bundle_body(BundleTarget::Edge, 1, "deny", &[r], Some(&steering));
    let bundle = sign_body(&signing_key, &key_id, body);

    let verifier = build_verifier(verify_key, &key_id);
    verifier.verify(&bundle).unwrap();

    let eng = PolicyEngine::from_body(&bundle.body, BundleTarget::Edge).unwrap();

    let trusted = FlowBuilder::new(EnforcementDomain::Sdwan)
        .destination_host("mail.office365.com")
        .build();
    assert_eq!(
        eng.evaluate(&trusted),
        Verdict::Steer {
            class: TrafficClass::TrustedDirect
        }
    );

    let blocked = FlowBuilder::new(EnforcementDomain::Sdwan)
        .destination_host("evil.test")
        .build();
    assert_eq!(
        eng.evaluate(&blocked),
        Verdict::Steer {
            class: TrafficClass::Block
        }
    );

    let unknown = FlowBuilder::new(EnforcementDomain::Sdwan)
        .destination_host("nope.test")
        .build();
    assert_eq!(
        eng.evaluate(&unknown),
        Verdict::Steer {
            class: TrafficClass::default_conservative()
        }
    );
}

#[test]
fn hot_swap_to_newer_signed_bundle_updates_engine_atomically() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let key_id = PolicySigningKeyId::new("test-key-4").unwrap();
    let verifier = build_verifier(verify_key, &key_id);

    let v1_body = encode_bundle_body(BundleTarget::Edge, 1, "deny", &[], None);
    let v1 = sign_body(&signing_key, &key_id, v1_body);
    verifier.verify(&v1).unwrap();
    let eng = PolicyEngine::from_body(&v1.body, BundleTarget::Edge).unwrap();
    assert_eq!(eng.evaluate(&Flow::default()), Verdict::Deny);

    let v2_body = encode_bundle_body(BundleTarget::Edge, 2, "allow", &[], None);
    let v2 = sign_body(&signing_key, &key_id, v2_body);
    verifier.verify(&v2).unwrap();
    eng.swap(&v2.body, false).unwrap();
    assert_eq!(eng.evaluate(&Flow::default()), Verdict::Allow);
    assert_eq!(eng.current_bundle().graph_version, 2);
}

#[test]
fn swap_to_older_bundle_rejected_without_force_even_if_signed() {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verify_key = signing_key.verifying_key();
    let key_id = PolicySigningKeyId::new("test-key-5").unwrap();
    let verifier = build_verifier(verify_key, &key_id);

    let v2_body = encode_bundle_body(BundleTarget::Edge, 2, "deny", &[], None);
    let v2 = sign_body(&signing_key, &key_id, v2_body);
    verifier.verify(&v2).unwrap();
    let eng = PolicyEngine::from_body(&v2.body, BundleTarget::Edge).unwrap();

    let v1_body = encode_bundle_body(BundleTarget::Edge, 1, "allow", &[], None);
    let v1 = sign_body(&signing_key, &key_id, v1_body);
    verifier.verify(&v1).unwrap();

    let err = eng.swap(&v1.body, false).unwrap_err();
    assert!(
        matches!(err, sng_policy_eval::PolicyEvalError::Stale { .. }),
        "expected Stale, got {err:?}"
    );
    assert_eq!(eng.current_bundle().graph_version, 2);
}

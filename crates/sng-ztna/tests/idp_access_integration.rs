// Test-only allows mirror the in-crate test module (see src/lib.rs):
// an external integration test is its own crate, so the library's
// `cfg_attr(test, allow(...))` does not reach here.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! End-to-end WS8 identity-depth integration: an OIDC ID token is
//! resolved into a ZTNA [`UserIdentity`] (the access-path primitive) and
//! fed into the real [`evaluate_policy`] engine, exercising the
//! "IdP push → token → access decision" and "group change →
//! entitlement re-evaluated" flows against the same code the data path
//! runs.

use std::collections::HashMap;

use sng_oidc::validation::IdTokenClaims;
use sng_ztna::policy::EvaluationInputs;
use sng_ztna::{
    App, DevicePosture, DeviceTrust, NetworkType, UserIdentity, ZtnaDecisionReason, ZtnaPolicy,
    evaluate_policy, identity_from_claims,
};

const TENANT: &str = "tenant-a";
const NOW_SECS: i64 = 1_700_000_000;
const NOW_MS: u64 = 1_700_000_000_000;

// Build validated ID-token claims from JSON (only `Deserialize` is
// derived on `IdTokenClaims`, matching what the validator produces).
fn claims(groups: &[&str], tenant: Option<&str>) -> IdTokenClaims {
    let mut obj = serde_json::json!({
        "iss": "https://idp.example.com",
        "sub": "okta-user-1",
        "aud": ["client-abc"],
        "exp": 9_999_999_999i64,
        "iat": NOW_SECS,
        "groups": groups,
        "amr": ["pwd", "otp"], // MFA satisfied
    });
    if let Some(t) = tenant {
        obj["tenant_id"] = serde_json::Value::String(t.to_owned());
    }
    serde_json::from_value(obj).expect("valid claims fixture")
}

fn device() -> DeviceTrust {
    DeviceTrust {
        device_id: "dev-1".into(),
        tenant_id: TENANT.into(),
        posture: DevicePosture::pristine(NOW_MS),
        tags: HashMap::default(),
    }
}

fn app_requiring(group: &str) -> App {
    let mut a = App::new("vpn", "Corp VPN");
    a.required_groups = [group.to_owned()].into_iter().collect();
    a
}

fn policy() -> ZtnaPolicy {
    ZtnaPolicy {
        tenant_id: TENANT.into(),
        ..Default::default()
    }
}

fn decide(app: &App, identity: &UserIdentity) -> sng_ztna::ZtnaDecision {
    let dev = device();
    let pol = policy();
    evaluate_policy(
        &pol,
        EvaluationInputs {
            app,
            device: &dev,
            identity: Some(identity),
            now_ms: NOW_MS,
            source_country: None,
            network_type: NetworkType::Unknown,
        },
    )
}

/// IdP push → token resolves to an identity carrying the IdP group →
/// the ZTNA evaluator grants access to an app gated on that group.
#[test]
fn token_group_grants_access() {
    let identity = identity_from_claims(&claims(&["vpn-users"], Some(TENANT)), TENANT)
        .expect("identity resolves");
    let app = app_requiring("vpn-users");

    let decision = decide(&app, &identity);
    assert!(decision.allow, "expected access granted, got {decision:?}");
}

/// A token lacking the required group is denied as not-entitled — the
/// ZTNA engine never grants access an IdP group does not back.
#[test]
fn token_without_group_denied() {
    let identity = identity_from_claims(&claims(&["interns"], Some(TENANT)), TENANT)
        .expect("identity resolves");
    let app = app_requiring("vpn-users");

    let decision = decide(&app, &identity);
    assert!(!decision.allow);
    assert_eq!(decision.reason, ZtnaDecisionReason::NotEntitled);
}

/// Group change → entitlement re-evaluated: the same subject, after an
/// IdP group change, flips from granted to denied on the next token
/// without any policy change.
#[test]
fn group_change_reevaluates_entitlement() {
    let app = app_requiring("vpn-users");

    // Before: token carries the entitling group → granted.
    let before = identity_from_claims(&claims(&["vpn-users", "staff"], Some(TENANT)), TENANT)
        .expect("identity");
    assert!(decide(&app, &before).allow, "precondition: access granted");

    // After: IdP removes vpn-users from the user's groups → denied.
    let after = identity_from_claims(&claims(&["staff"], Some(TENANT)), TENANT).expect("identity");
    let decision = decide(&app, &after);
    assert!(!decision.allow, "expected re-evaluation to deny");
    assert_eq!(decision.reason, ZtnaDecisionReason::NotEntitled);
}

/// A token minted for another tenant never resolves an identity under
/// this tenant — isolation holds before any policy evaluation.
#[test]
fn cross_tenant_token_rejected_before_policy() {
    let err = identity_from_claims(&claims(&["vpn-users"], Some("tenant-b")), TENANT)
        .expect_err("cross-tenant token must be rejected");
    assert!(matches!(err, sng_ztna::ZtnaError::TokenRejected { .. }));
}

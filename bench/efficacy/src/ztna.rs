//! ZTNA efficacy: drive the *real* `sng_ztna::ZtnaService` decision
//! over a corpus of unauthorized / stale-posture / cross-tenant
//! requests vs. fully-authorized ones, and confirm the broker denies
//! the former and admits the latter.

use std::sync::Arc;

use sng_ztna::{
    AccessRequest, App, DevicePosture, DeviceTrust, PostureRequirement, StaticAppCatalog,
    StaticDeviceTrustProvider, StaticIdentityProvider, UserIdentity, ZtnaPolicy, ZtnaPolicyHolder,
    ZtnaServiceBuilder,
};

use crate::report::{Case, FunctionReport, Kind, Targets};

// Fixed "now" well above the policy max-ages so stale offsets stay
// positive (12h posture / 8h MFA freshness windows).
const NOW: u64 = 1_000_000_000_000;
const H13_MS: u64 = 13 * 60 * 60 * 1_000; // > 12h posture window
const H9_MS: u64 = 9 * 60 * 60 * 1_000; // > 8h MFA window

fn app(id: &str, posture: PostureRequirement, groups: &[&str]) -> App {
    App {
        app_id: id.into(),
        display_name: id.into(),
        host_patterns: Vec::new(),
        required_groups: groups.iter().map(|s| (*s).to_string()).collect(),
        posture_requirement: posture,
    }
}

fn device(id: &str, tenant: &str, posture: DevicePosture) -> DeviceTrust {
    DeviceTrust {
        device_id: id.into(),
        tenant_id: tenant.into(),
        posture,
    }
}

fn user(id: &str, tenant: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
    UserIdentity {
        user_id: id.into(),
        tenant_id: tenant.into(),
        groups: groups.iter().map(|s| (*s).to_string()).collect(),
        mfa_at_ms,
    }
}

struct ZCase {
    desc: &'static str,
    bad: bool,
    app: &'static str,
    device: &'static str,
    user: &'static str,
}

pub async fn run() -> FunctionReport {
    let pristine = DevicePosture::pristine(NOW);
    let stale_posture = DevicePosture {
        attested_at_ms: NOW - H13_MS,
        ..DevicePosture::pristine(NOW)
    };
    // Fresh attestation but fails the Basic floor (no disk encryption).
    let insufficient = DevicePosture {
        disk_encrypted: false,
        ..DevicePosture::pristine(NOW)
    };

    let apps = vec![
        // High-value app: requires Basic posture + engineering group.
        app("crm", PostureRequirement::Basic, &["engineering"]),
        // Low-risk app: no posture floor, open to eng + sales.
        app("wiki", PostureRequirement::None, &["engineering", "sales"]),
    ];

    let devices = vec![
        device("dev-good", "t1", pristine.clone()),
        device("dev-stale", "t1", stale_posture),
        device("dev-weak", "t1", insufficient),
        device("dev-foreign", "t2", DevicePosture::pristine(NOW)),
    ];

    let users = vec![
        user("alice", "t1", &["engineering"], NOW),
        user("carol", "t1", &["engineering"], NOW),
        user("bob", "t1", &["sales"], NOW),
        user("stale-mfa", "t1", &["engineering"], NOW - H9_MS),
        user("foreign", "t2", &["engineering"], NOW),
    ];

    let policy = ZtnaPolicy {
        tenant_id: "t1".into(),
        ..ZtnaPolicy::default()
    };

    let (tx, _rx) = tokio::sync::mpsc::channel(256);
    let svc = ZtnaServiceBuilder::new()
        .with_policy(Arc::new(ZtnaPolicyHolder::new(policy)))
        .with_app_catalog(Arc::new(StaticAppCatalog::new(apps)))
        .with_device_trust(Arc::new(StaticDeviceTrustProvider::new(devices)))
        .with_identity(Arc::new(StaticIdentityProvider::new(users)))
        .build(tx);

    let corpus = vec![
        // --- known-bad: MUST be denied ---
        ZCase {
            desc: "unknown app (not in catalog)",
            bad: true,
            app: "ghost-app",
            device: "dev-good",
            user: "alice",
        },
        ZCase {
            desc: "device not enrolled",
            bad: true,
            app: "crm",
            device: "ghost-device",
            user: "alice",
        },
        ZCase {
            desc: "stale device posture (>12h)",
            bad: true,
            app: "crm",
            device: "dev-stale",
            user: "alice",
        },
        ZCase {
            desc: "insufficient posture (no disk encryption)",
            bad: true,
            app: "crm",
            device: "dev-weak",
            user: "alice",
        },
        ZCase {
            desc: "unknown identity",
            bad: true,
            app: "crm",
            device: "dev-good",
            user: "ghost-user",
        },
        ZCase {
            desc: "stale MFA (>8h)",
            bad: true,
            app: "crm",
            device: "dev-good",
            user: "stale-mfa",
        },
        ZCase {
            desc: "not entitled (sales user -> eng app)",
            bad: true,
            app: "crm",
            device: "dev-good",
            user: "bob",
        },
        ZCase {
            desc: "cross-tenant request (t2 -> t1 policy)",
            bad: true,
            app: "crm",
            device: "dev-foreign",
            user: "foreign",
        },
        // --- known-good: MUST be allowed ---
        ZCase {
            desc: "engineer, pristine device, fresh MFA -> crm",
            bad: false,
            app: "crm",
            device: "dev-good",
            user: "alice",
        },
        ZCase {
            desc: "second engineer -> crm",
            bad: false,
            app: "crm",
            device: "dev-good",
            user: "carol",
        },
        ZCase {
            desc: "sales user -> low-risk wiki (no posture floor)",
            bad: false,
            app: "wiki",
            device: "dev-good",
            user: "bob",
        },
        ZCase {
            desc: "weak-posture device -> no-floor wiki",
            bad: false,
            app: "wiki",
            device: "dev-weak",
            user: "alice",
        },
    ];

    let mut cases = Vec::new();
    for z in corpus {
        let req = AccessRequest::new(z.app, z.device, z.user, NOW);
        let (allowed, actual) = match svc.evaluate(&req) {
            Ok(d) => (
                d.allow,
                format!(
                    "{} ({})",
                    if d.allow { "allow" } else { "deny" },
                    d.reason.as_str()
                ),
            ),
            // Fail-closed: an evaluation error is treated as a deny.
            Err(e) => (false, format!("deny (error: {e})")),
        };
        let correct = if z.bad { !allowed } else { allowed };
        cases.push(Case {
            description: z.desc.into(),
            bad: z.bad,
            expected: if z.bad { "deny" } else { "allow" }.into(),
            actual,
            correct,
        });
    }

    FunctionReport::from_cases(
        "ztna",
        "sng-ztna",
        Kind::Enforcement,
        Targets::default(),
        cases,
        Some(
            "Real ZtnaService.evaluate brokering. Denies unknown app/device/identity, \
             stale posture, insufficient posture, stale MFA, missing entitlement, and \
             cross-tenant requests; admits authorized engineers on compliant devices."
                .into(),
        ),
    )
}

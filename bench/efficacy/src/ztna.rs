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

use crate::report::{measure, Case, Feature, FunctionReport, Kind, Targets};

/// Timed iterations for the decision-throughput microbenchmark.
const THROUGHPUT_ITERS: u64 = 50_000;

// Fixed "now" well above the policy max-ages so stale offsets stay
// positive (12h posture / 8h MFA freshness windows).
const NOW: u64 = 1_000_000_000_000;
const H13_MS: u64 = 13 * 60 * 60 * 1_000; // > 12h posture window
const H9_MS: u64 = 9 * 60 * 60 * 1_000; // > 8h MFA window

fn app(id: &str, posture: PostureRequirement, groups: &[&str]) -> App {
    let mut a = App::new(id, id);
    a.required_groups = groups.iter().map(|s| (*s).to_string()).collect();
    a.posture_requirement = posture;
    a
}

fn device(id: &str, tenant: &str, posture: DevicePosture) -> DeviceTrust {
    DeviceTrust {
        device_id: id.into(),
        tenant_id: tenant.into(),
        posture,
        tags: std::collections::HashMap::new(),
    }
}

fn user(id: &str, tenant: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
    UserIdentity {
        user_id: id.into(),
        tenant_id: tenant.into(),
        groups: groups.iter().map(|s| (*s).to_string()).collect(),
        mfa_at_ms,
        tags: std::collections::HashMap::new(),
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
    // Fresh attestation but fails the Basic floor (score 60): only
    // disk encryption on (25) — well below 60 under the weighted
    // risk_score model. Expanded signals stay healthy so this case
    // isolates the *score* floor.
    let insufficient = DevicePosture {
        disk_encrypted: true,
        os_patched: false,
        antimalware_running: false,
        firewall_enabled: false,
        screen_lock_configured: false,
        attested_at_ms: NOW,
        ..DevicePosture::pristine(NOW)
    };
    // Expanded-signal regressions. Each keeps a full score (every
    // original signal on) and a fresh attestation, so only the new
    // hard gate it targets can flip the verdict to deny.
    let killed_edr = DevicePosture {
        edr_healthy: false,
        ..DevicePosture::pristine(NOW)
    };
    let stale_av = DevicePosture {
        antivirus_definitions_age_hours: 72,
        ..DevicePosture::pristine(NOW)
    };
    let out_of_date_patch = DevicePosture {
        os_patch_days_since: 30,
        ..DevicePosture::pristine(NOW)
    };

    let apps = vec![
        // High-value app: requires Basic posture + engineering group.
        app("crm", PostureRequirement::BASIC, &["engineering"]),
        // Low-risk app: no posture floor, open to eng + sales.
        app("wiki", PostureRequirement::NONE, &["engineering", "sales"]),
        // Expanded-posture apps: a Basic floor plus one hard gate
        // each, all restricted to engineering.
        app(
            "crm-edr",
            PostureRequirement::BASIC.with_require_edr(true),
            &["engineering"],
        ),
        app(
            "crm-av",
            PostureRequirement::BASIC.with_max_av_definition_age_hours(24),
            &["engineering"],
        ),
        app(
            "crm-patch",
            PostureRequirement::BASIC.with_min_patch_days(7),
            &["engineering"],
        ),
    ];

    let devices = vec![
        device("dev-good", "t1", pristine.clone()),
        device("dev-stale", "t1", stale_posture),
        device("dev-weak", "t1", insufficient),
        device("dev-foreign", "t2", DevicePosture::pristine(NOW)),
        device("dev-no-edr", "t1", killed_edr),
        device("dev-stale-av", "t1", stale_av),
        device("dev-old-patch", "t1", out_of_date_patch),
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

    // The broker emits one audit/telemetry event per evaluation on `tx`. We
    // don't assert on them here, but `_rx` is a named binding (not `_`), so
    // the receiver is held for the whole function scope — the channel stays
    // open and the buffered sends (<= corpus size, well under 256) succeed
    // rather than erroring on a closed channel.
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
        ZCase {
            desc: "degraded EDR sensor -> EDR-gated crm",
            bad: true,
            app: "crm-edr",
            device: "dev-no-edr",
            user: "alice",
        },
        ZCase {
            desc: "stale AV definitions (>24h) -> AV-gated crm",
            bad: true,
            app: "crm-av",
            device: "dev-stale-av",
            user: "alice",
        },
        ZCase {
            desc: "out-of-date OS patch (>7d) -> patch-gated crm",
            bad: true,
            app: "crm-patch",
            device: "dev-old-patch",
            user: "alice",
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
        ZCase {
            desc: "healthy EDR sensor -> EDR-gated crm",
            bad: false,
            app: "crm-edr",
            device: "dev-good",
            user: "alice",
        },
        ZCase {
            desc: "fresh AV definitions -> AV-gated crm",
            bad: false,
            app: "crm-av",
            device: "dev-good",
            user: "alice",
        },
        ZCase {
            desc: "recent OS patch -> patch-gated crm",
            bad: false,
            app: "crm-patch",
            device: "dev-good",
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

    // Throughput: time the real evaluate() decision path over a fully
    // authorized request (the worst case — it runs every step instead of
    // short-circuiting on an early deny), so decisions/s reflects a request
    // that traverses revocation → tenant → conditions → entitlement →
    // posture → MFA.
    let hot_req = AccessRequest::new("crm", "dev-good", "alice", NOW);
    let throughput = vec![measure(
        "evaluate",
        "decisions/s",
        THROUGHPUT_ITERS,
        None,
        |_| svc.evaluate(&hot_req).map(|d| d.allow),
    )];

    FunctionReport::from_cases(
        "ztna",
        "sng-ztna",
        Kind::Enforcement,
        Targets::default(),
        cases,
        Some(
            "Real ZtnaService.evaluate brokering. Denies unknown app/device/identity, \
             stale posture, insufficient posture, degraded EDR, stale AV definitions, \
             out-of-date OS patches, stale MFA, missing entitlement, and cross-tenant \
             requests; admits authorized engineers on compliant devices."
                .into(),
        ),
    )
    .with_features(features())
    .with_throughput(throughput)
}

/// Capability catalog for the ZTNA broker, in evaluation order. Each entry
/// maps to a real step in `ZtnaService::evaluate` / `evaluate_policy`.
fn features() -> Vec<Feature> {
    fn f(name: &str, how: &str, coverage: &str) -> Feature {
        Feature {
            name: name.into(),
            how: how.into(),
            coverage: coverage.into(),
        }
    }
    vec![
        f(
            "Session revocation (step 0)",
            "Before any other check, the device-id and user-id are tested against an \
             ArcSwap revocation set the control plane pushes over NATS; a hit denies \
             immediately — enabling instant cut-off on compromise or offboarding without \
             waiting for posture/MFA TTLs to expire.",
            "Per-device and per-user revocation, reason `Revoked`",
        ),
        f(
            "Tenant isolation guard",
            "The request's app/device/identity must all resolve within the policy's \
             tenant; a cross-tenant mismatch is denied before any entitlement logic runs.",
            "Hard tenant boundary on every request",
        ),
        f(
            "Geo / time / network conditions",
            "Optional per-app AccessConditions check the request's GeoIP country against \
             allow/block lists, the source network class (corporate/vpn/public), and a \
             UTC TimeWindow (hours + days-of-week) carried in the signed bundle.",
            "Reasons `GeoBlocked`, `NetworkTypeBlocked`, `OutsideAllowedHours`",
        ),
        f(
            "Tag / label conditions",
            "App, device, and user carry key=value tag maps; per-app TagConditions assert \
             Equals/NotEquals/Exists/NotExists against them (e.g. device managed=true, \
             user risk_tier=elevated) as policy-driven gates with no connector required.",
            "Foundation for attribute-based access on bundle-delivered tags",
        ),
        f(
            "Group entitlement",
            "The resolved identity's group memberships must satisfy the app's required \
             groups before access is granted.",
            "Group-to-app entitlement matrix",
        ),
        f(
            "Risk-adaptive posture",
            "Device posture is scored 0-100 from weighted signals (disk encryption 25, OS \
             patch 25, anti-malware 20, firewall 15, screen-lock 15) and compared to a \
             per-app min-score threshold (None/Basic/Strict map to 0/60/90), replacing the \
             old 3-level bucket with any-granularity thresholds.",
            "Weighted numeric posture, attestation-freshness window",
        ),
        f(
            "Expanded posture hard gates",
            "Beyond the weighted score, an app may declare independent hard gates on the \
             expanded posture signals: require_edr (the EDR sensor must report healthy), \
             min_patch_days (the OS must have been patched within N days), and \
             max_av_definition_age_hours (antivirus must be enabled with definitions no \
             older than N hours). Each is enforced separately from the score, so a device \
             with a perfect score is still denied if its EDR was killed, its patches \
             lapsed, or its AV signatures went stale — and the continuous re-evaluation \
             loop revokes live sessions the moment a pushed posture trips any gate.",
            "Reason `DevicePostureInsufficient` on degraded EDR / stale AV / out-of-date patch",
        ),
        f(
            "Per-app MFA freshness override",
            "MFA recency is enforced against the policy-global max-age unless the app sets \
             an mfa_max_age_override_ms, letting a high-risk app demand MFA every 30 min \
             while low-risk apps stay at the 8 h default.",
            "Per-app step-up MFA windows",
        ),
    ]
}

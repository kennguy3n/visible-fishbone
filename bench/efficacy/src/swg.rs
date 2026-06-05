//! SWG efficacy: drive the *real* `sng_swg::ExtAuthzHandler` decision
//! over a corpus of forbidden-category vs. sanctioned URLs and confirm
//! the proxy blocks the forbidden ones and permits the rest.

use std::sync::Arc;

use sng_swg::auth::ExtAuthzHandlerBuilder;
use sng_swg::{
    Action, BypassList, Category, CategoryEntry, LocalCategoryDb, RateLimiter, RequestContext,
    RequestSignals, StaticMalwareList, TelemetryEmitter, VerdictEvent,
};

use crate::report::{Case, FunctionReport, Kind, Targets};

/// Telemetry sink that drops every event — the efficacy harness only
/// cares about the verdict, not the emitted telemetry.
#[derive(Debug)]
struct NoopEmitter;

impl TelemetryEmitter for NoopEmitter {
    fn emit(&self, _event: VerdictEvent) {}
}

fn entry(host: &str, category: &str) -> CategoryEntry {
    CategoryEntry {
        host: host.into(),
        path_prefix: None,
        category: Category::new(category),
    }
}

fn ctx(host: &str, path: &str) -> RequestContext {
    RequestContext {
        tenant_id: "t1".into(),
        principal_id: "user-1".into(),
        method: "get".into(),
        scheme: "https".into(),
        host: host.into(),
        path: path.into(),
        sni: Some(host.into()),
        file_hash: None,
    }
}

struct UrlCase {
    desc: &'static str,
    bad: bool,
    host: &'static str,
    path: &'static str,
}

pub async fn run() -> FunctionReport {
    // Operator deny list — the forbidden URL categories.
    let deny_categories = vec![
        "malware".to_string(),
        "phishing".to_string(),
        "gambling".to_string(),
        "adult".to_string(),
    ];

    // Local URL feed mapping hosts -> categories.
    let db = LocalCategoryDb::new(vec![
        entry("malware.example", "malware"),
        entry("drive-by.example", "malware"),
        entry("login-update-account.example", "phishing"),
        entry("verify-paypa1.example", "phishing"),
        entry("casino-roulette.example", "gambling"),
        entry("adult-content.example", "adult"),
        // sanctioned business categories (allowed)
        entry("github.com", "technology"),
        entry("salesforce.com", "business"),
        entry("office.com", "business"),
        entry("wikipedia.org", "reference"),
    ]);

    let handler = ExtAuthzHandlerBuilder::new()
        .with_categorizer(Arc::new(db))
        .with_deny_categories(deny_categories)
        // No file-hash cases in this corpus; an empty malware list
        // satisfies the builder without affecting URL-category verdicts.
        .with_malware(Arc::new(StaticMalwareList::new(std::iter::empty())))
        // No SNI bypass entries — every request sees the full pipeline.
        .with_bypass(Arc::new(BypassList::new(Vec::new())))
        // Effectively unlimited so rate-limiting never masks a verdict.
        .with_rate_limiter(RateLimiter::with_system_clock(1_000_000.0, 1_000_000.0))
        .with_telemetry(Arc::new(NoopEmitter))
        .build()
        .expect("build SWG ext-authz handler");

    let corpus = vec![
        // --- known-bad: forbidden categories, MUST be blocked ---
        UrlCase {
            desc: "malware drive-by host",
            bad: true,
            host: "malware.example",
            path: "/payload.exe",
        },
        UrlCase {
            desc: "second malware host",
            bad: true,
            host: "drive-by.example",
            path: "/",
        },
        UrlCase {
            desc: "phishing credential-harvest page",
            bad: true,
            host: "login-update-account.example",
            path: "/signin",
        },
        UrlCase {
            desc: "phishing typosquat (paypa1)",
            bad: true,
            host: "verify-paypa1.example",
            path: "/",
        },
        UrlCase {
            desc: "gambling site",
            bad: true,
            host: "casino-roulette.example",
            path: "/play",
        },
        UrlCase {
            desc: "adult-content site",
            bad: true,
            host: "adult-content.example",
            path: "/",
        },
        // --- known-good: sanctioned categories, MUST be allowed ---
        UrlCase {
            desc: "developer platform (github)",
            bad: false,
            host: "github.com",
            path: "/torvalds/linux",
        },
        UrlCase {
            desc: "business SaaS (salesforce)",
            bad: false,
            host: "salesforce.com",
            path: "/",
        },
        UrlCase {
            desc: "business SaaS (office)",
            bad: false,
            host: "office.com",
            path: "/mail",
        },
        UrlCase {
            desc: "reference (wikipedia)",
            bad: false,
            host: "wikipedia.org",
            path: "/wiki/Firewall",
        },
        UrlCase {
            desc: "uncategorized benign host",
            bad: false,
            host: "example.org",
            path: "/",
        },
    ];

    let mut cases = Vec::new();
    for u in corpus {
        // This corpus exercises only URL-category verdicts; no CASB
        // size/label signals are relevant, so pass the defaults.
        let v = handler
            .evaluate(&ctx(u.host, u.path), &RequestSignals::default())
            .await;
        let denied = v.action == Action::Deny;
        let correct = if u.bad { denied } else { !denied };
        cases.push(Case {
            description: u.desc.into(),
            bad: u.bad,
            expected: if u.bad { "deny" } else { "allow" }.into(),
            actual: if denied { "deny" } else { "allow" }.into(),
            correct,
        });
    }

    FunctionReport::from_cases(
        "swg",
        "sng-swg",
        Kind::Enforcement,
        Targets::default(),
        cases,
        Some(
            "Real ExtAuthzHandler categorize->deny-list path. Forbidden categories \
             (malware/phishing/gambling/adult) blocked; sanctioned + uncategorized \
             traffic permitted."
                .into(),
        ),
    )
}

// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Remote Browser Isolation (RBI) policy engine for the SWG
//! data plane. Mirrors the control-plane `rbi.PolicyConfig` in
//! Go — the operator-configurable trigger rules that decide
//! which URLs are redirected to the RBI proxy for isolated
//! rendering instead of being passed through to the upstream
//! origin.
//!
//! ## Pipeline position
//!
//! RBI evaluation runs in `ExtAuthzHandler::evaluate` as step
//! 3c — after inline DLP (3b) and before URL categorisation (4).
//! A trigger short-circuits to a `Verdict::redirect` so the
//! client receives a 302 to the RBI proxy URL. Non-triggering
//! requests fall through to the normal categorise/deny/malware
//! pipeline unchanged.
//!
//! ## Policy precedence (mirrors the Go engine)
//!
//! 1. **ExplicitIsolate** — host pinned by the operator is
//!    always isolated (highest precedence, deny-wins).
//! 2. **ExplicitBypass** — host on the trusted allow-list is
//!    never isolated, short-circuiting the heuristic rules.
//! 3. **IsolateUncategorised** — isolate any URL the
//!    categoriser could not classify.
//! 4. **RiskScoreThreshold** — isolate when the categoriser's
//!    risk score meets or exceeds the threshold.
//! 5. **Categories** — isolate when the URL's category is on
//!    the trigger list.

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// Why a URL was routed to RBI. Recorded on the verdict reason
/// and on telemetry for audit / dashboards.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RbiTriggerReason {
    CategoryMatch,
    RiskScore,
    Uncategorised,
    ExplicitPolicy,
}

impl RbiTriggerReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CategoryMatch => "category_match",
            Self::RiskScore => "risk_score",
            Self::Uncategorised => "uncategorised",
            Self::ExplicitPolicy => "explicit_policy",
        }
    }
}

/// Operator-configurable RBI trigger policy, hot-swappable at
/// runtime via [`RbiPolicyEngine::install`]. Mirrors the Go
/// `rbi.PolicyConfig` struct field-for-field.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RbiPolicyDef {
    /// URL categories that trigger RBI (e.g. "gambling",
    /// "phishing"). Empty disables category-based triggering.
    #[serde(default)]
    pub categories: Vec<String>,
    /// Risk score threshold [0,100]. 0 disables risk-based
    /// triggering. A URL whose risk score >= threshold is
    /// isolated.
    #[serde(default)]
    pub risk_score_threshold: u32,
    /// Isolate any URL the categoriser could not classify.
    #[serde(default)]
    pub isolate_uncategorised: bool,
    /// Host patterns that ALWAYS route to RBI. A pattern
    /// matches the destination host exactly or as a parent
    /// domain ("example.com" matches "app.example.com").
    #[serde(default)]
    pub explicit_isolate: Vec<String>,
    /// Host patterns that are NEVER isolated even when a
    /// heuristic rule would match. Deny-wins: a host in both
    /// lists is isolated.
    #[serde(default)]
    pub explicit_bypass: Vec<String>,
}

/// The proxy base URL (e.g. "https://rbi.example.com"). The
/// engine builds the redirect target as
/// `{base_url}/rbi/session/{session_id}`. Empty disables RBI.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RbiProxyConfig {
    pub base_url: String,
}

impl RbiProxyConfig {
    pub fn configured(&self) -> bool {
        !self.base_url.is_empty()
    }

    pub fn session_url(&self, session_id: &str) -> String {
        format!("{}/rbi/session/{}", self.base_url, url_escape(session_id))
    }
}

/// Minimal URL path-segment escaper (avoids pulling in a `url`
/// crate dependency for a single format call).
fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Internal compiled policy snapshot. Pre-normalises host
/// patterns and category strings at install time so the
/// per-request hot path is a linear scan with no allocations.
#[derive(Clone, Debug, Default)]
struct CompiledPolicy {
    categories: Vec<String>,
    risk_score_threshold: u32,
    isolate_uncategorised: bool,
    explicit_isolate: Vec<String>,
    explicit_bypass: Vec<String>,
}

impl CompiledPolicy {
    fn compile(def: &RbiPolicyDef) -> Self {
        Self {
            categories: def.categories.iter().map(|c| c.to_ascii_lowercase()).collect(),
            risk_score_threshold: def.risk_score_threshold,
            isolate_uncategorised: def.isolate_uncategorised,
            explicit_isolate: def.explicit_isolate.iter().map(|h| normalize_host(h)).collect(),
            explicit_bypass: def.explicit_bypass.iter().map(|h| normalize_host(h)).collect(),
        }
    }
}

/// The RBI policy engine. Wraps a compiled policy snapshot in
/// [`ArcSwap`] for lock-free hot-swap from the control plane.
/// The engine is cheap to clone (an `Arc` inner) so the handler
/// can hold one alongside the other engines.
#[derive(Debug)]
pub struct RbiPolicyEngine {
    policy: ArcSwap<CompiledPolicy>,
    proxy: RbiProxyConfig,
}

impl RbiPolicyEngine {
    /// Construct with an empty policy. The control plane
    /// hot-swaps a real policy via [`Self::install`].
    #[must_use]
    pub fn new(proxy: RbiProxyConfig) -> Self {
        Self {
            policy: ArcSwap::from_pointee(CompiledPolicy::default()),
            proxy,
        }
    }

    /// Hot-swap the policy definition. Compiles the def into
    /// a snapshot and atomically swaps it in. Returns the
    /// number of categories and explicit-isolate hosts
    /// installed (for control-plane logging).
    pub fn install(&self, def: &RbiPolicyDef) -> (usize, usize) {
        let snap = CompiledPolicy::compile(def);
        let n_cat = snap.categories.len();
        let n_iso = snap.explicit_isolate.len();
        self.policy.store(Arc::new(snap));
        (n_cat, n_iso)
    }

    /// Whether the proxy is configured. When false, `evaluate`
    /// always returns `None` (RBI is disabled).
    #[must_use]
    pub fn configured(&self) -> bool {
        self.proxy.configured()
    }

    /// The proxy base URL, or `None` when not configured. Used by
    /// the AI-governance engine to build a redirect URL when a
    /// governance rule redirects an AI-app destination to RBI.
    #[must_use]
    pub fn proxy_base_url(&self) -> Option<&str> {
        if self.proxy.configured() {
            Some(&self.proxy.base_url)
        } else {
            None
        }
    }

    /// Evaluate whether a request should be redirected to RBI.
    /// Returns `Some((reason, redirect_url))` when isolation is
    /// triggered, `None` otherwise. The `redirect_url` is built
    /// from the proxy config and a synthetic session id (the
    /// control plane creates the real session record on
    /// receipt of the redirect).
    ///
    /// Parameters mirror what the evaluate pipeline already
    /// has: the destination host, the categoriser's category
    /// (if any), and the risk score.
    #[must_use]
    pub fn evaluate(
        &self,
        host: &str,
        category: Option<&str>,
        risk_score: u32,
    ) -> Option<(RbiTriggerReason, String)> {
        if !self.proxy.configured() {
            return None;
        }
        let snap = self.policy.load();
        let h = normalize_host(host);

        // 1. ExplicitIsolate — deny-wins.
        if host_matches(&snap.explicit_isolate, &h) {
            let url = self.proxy.session_url(&format!("pending:{h}"));
            return Some((RbiTriggerReason::ExplicitPolicy, url));
        }
        // 2. ExplicitBypass — short-circuit.
        if host_matches(&snap.explicit_bypass, &h) {
            return None;
        }
        // 3. IsolateUncategorised.
        if snap.isolate_uncategorised {
            if let Some(cat) = category {
                if is_uncategorised(cat) {
                    let url = self.proxy.session_url(&format!("pending:{h}"));
                    return Some((RbiTriggerReason::Uncategorised, url));
                }
            } else {
                let url = self.proxy.session_url(&format!("pending:{h}"));
                return Some((RbiTriggerReason::Uncategorised, url));
            }
        }
        // 4. RiskScoreThreshold.
        if snap.risk_score_threshold > 0 && risk_score >= snap.risk_score_threshold {
            let url = self.proxy.session_url(&format!("pending:{h}"));
            return Some((RbiTriggerReason::RiskScore, url));
        }
        // 5. Categories.
        if let Some(cat) = category {
            let cat_lower = cat.to_ascii_lowercase();
            if snap.categories.iter().any(|c| *c == cat_lower) {
                let url = self.proxy.session_url(&format!("pending:{h}"));
                return Some((RbiTriggerReason::CategoryMatch, url));
            }
        }
        None
    }
}

fn is_uncategorised(cat: &str) -> bool {
    let c = cat.to_ascii_lowercase();
    c.is_empty() || c == "uncategorised" || c == "uncategorized" || c == "unknown"
}

fn normalize_host(h: &str) -> String {
    let mut s = h.to_ascii_lowercase();
    if s.starts_with('.') {
        s.remove(0);
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

fn host_matches(list: &[String], host: &str) -> bool {
    if host.is_empty() {
        return false;
    }
    for pat in list {
        if pat.is_empty() {
            continue;
        }
        if host == pat || host.ends_with(&format!(".{pat}")) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> RbiPolicyEngine {
        RbiPolicyEngine::new(RbiProxyConfig {
            base_url: "https://rbi.test".into(),
        })
    }

    #[test]
    fn unconfigured_proxy_never_triggers() {
        let e = RbiPolicyEngine::new(RbiProxyConfig::default());
        e.install(&RbiPolicyDef {
            isolate_uncategorised: true,
            ..Default::default()
        });
        assert!(e.evaluate("evil.com", None, 0).is_none());
    }

    #[test]
    fn explicit_isolate_triggers() {
        let e = engine();
        e.install(&RbiPolicyDef {
            explicit_isolate: vec!["evil.com".into()],
            ..Default::default()
        });
        let (reason, url) = e.evaluate("evil.com", Some("clean"), 0).unwrap();
        assert_eq!(reason, RbiTriggerReason::ExplicitPolicy);
        assert!(url.starts_with("https://rbi.test/rbi/session/pending%3Aevil.com"));
    }

    #[test]
    fn explicit_isolate_matches_subdomain() {
        let e = engine();
        e.install(&RbiPolicyDef {
            explicit_isolate: vec!["evil.com".into()],
            ..Default::default()
        });
        let (reason, _) = e.evaluate("app.evil.com", Some("clean"), 0).unwrap();
        assert_eq!(reason, RbiTriggerReason::ExplicitPolicy);
    }

    #[test]
    fn explicit_bypass_overrides_category() {
        let e = engine();
        e.install(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            explicit_bypass: vec!["trusted.com".into()],
            ..Default::default()
        });
        assert!(e.evaluate("trusted.com", Some("gambling"), 0).is_none());
    }

    #[test]
    fn deny_wins_when_host_in_both_lists() {
        let e = engine();
        e.install(&RbiPolicyDef {
            explicit_isolate: vec!["evil.com".into()],
            explicit_bypass: vec!["evil.com".into()],
            ..Default::default()
        });
        assert!(e.evaluate("evil.com", None, 0).is_some());
    }

    #[test]
    fn isolate_uncategorised_with_none_category() {
        let e = engine();
        e.install(&RbiPolicyDef {
            isolate_uncategorised: true,
            ..Default::default()
        });
        let (reason, _) = e.evaluate("unknown.com", None, 0).unwrap();
        assert_eq!(reason, RbiTriggerReason::Uncategorised);
    }

    #[test]
    fn isolate_uncategorised_with_empty_string() {
        let e = engine();
        e.install(&RbiPolicyDef {
            isolate_uncategorised: true,
            ..Default::default()
        });
        let (reason, _) = e.evaluate("unknown.com", Some(""), 0).unwrap();
        assert_eq!(reason, RbiTriggerReason::Uncategorised);
    }

    #[test]
    fn risk_score_threshold_triggers() {
        let e = engine();
        e.install(&RbiPolicyDef {
            risk_score_threshold: 70,
            ..Default::default()
        });
        let (reason, _) = e.evaluate("risky.com", Some("clean"), 75).unwrap();
        assert_eq!(reason, RbiTriggerReason::RiskScore);
    }

    #[test]
    fn risk_score_below_threshold_does_not_trigger() {
        let e = engine();
        e.install(&RbiPolicyDef {
            risk_score_threshold: 70,
            ..Default::default()
        });
        assert!(e.evaluate("risky.com", Some("clean"), 50).is_none());
    }

    #[test]
    fn category_match_triggers() {
        let e = engine();
        e.install(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            ..Default::default()
        });
        let (reason, _) = e.evaluate("casino.com", Some("gambling"), 0).unwrap();
        assert_eq!(reason, RbiTriggerReason::CategoryMatch);
    }

    #[test]
    fn category_match_is_case_insensitive() {
        let e = engine();
        e.install(&RbiPolicyDef {
            categories: vec!["Gambling".into()],
            ..Default::default()
        });
        let (reason, _) = e.evaluate("casino.com", Some("GAMBLING"), 0).unwrap();
        assert_eq!(reason, RbiTriggerReason::CategoryMatch);
    }

    #[test]
    fn no_rules_no_trigger() {
        let e = engine();
        e.install(&RbiPolicyDef::default());
        assert!(e.evaluate("anywhere.com", Some("clean"), 0).is_none());
    }

    #[test]
    fn hot_swap_replaces_rules() {
        let e = engine();
        e.install(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            ..Default::default()
        });
        assert!(e.evaluate("casino.com", Some("gambling"), 0).is_some());
        e.install(&RbiPolicyDef::default());
        assert!(e.evaluate("casino.com", Some("gambling"), 0).is_none());
    }

    #[test]
    fn url_escape_works() {
        assert_eq!(url_escape("abc123-_.~"), "abc123-_.~");
        assert_eq!(url_escape("a b/c"), "a%20b%2Fc");
    }
}

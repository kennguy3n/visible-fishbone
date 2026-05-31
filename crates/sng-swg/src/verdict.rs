//! Verdict types — the shape Envoy's ext-authz call sees back.
//!
//! [`Verdict`] is the per-request decision the handler computes
//! from the verdict-providing modules (`bypass`, `categorizer`,
//! `malware`, `rate_limit`). [`RequestContext`] is the
//! decoded ext-authz request body the handler builds before
//! consulting any provider.
//!
//! The shape is small on purpose: the request context carries
//! only the inputs every provider needs (tenant id, principal id,
//! method, scheme, host, path, optional SNI, optional file hash
//! for downloads). The verdict is a single enum plus an optional
//! reason string. Anything richer (rewrite, header injection)
//! lives in the [`crate::auth::ExtAuthzResponse`] wire shape.

use serde::{Deserialize, Serialize};

/// The on-wire decision the ext-authz handler returns to Envoy.
///
/// Envoy's ext-authz filter expects a HTTP-style verdict; this
/// enum is the in-memory model and the [`crate::auth`] response
/// encoder maps it onto the JSON shape Envoy parses.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// The request is allowed to proceed to the upstream origin.
    /// Maps onto Envoy's `OK` response.
    Allow,
    /// The request is blocked. Envoy returns a 403 to the client.
    Deny,
    /// TLS interception is bypassed for this request — Envoy
    /// short-circuits the CONNECT tunnel without acting as a MITM
    /// CA. The request still completes; the SWG simply does not
    /// inspect the body. Distinct from `Allow` so a downstream
    /// telemetry consumer can count "bypassed" separately from
    /// "inspected and allowed".
    Bypass,
    /// The client is rate-limited. Envoy returns a 429 with the
    /// `Retry-After` value supplied in the verdict reason.
    RateLimit,
}

impl Action {
    /// Stable string form for telemetry / logs.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Bypass => "bypass",
            Self::RateLimit => "rate_limit",
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-request verdict returned by the SWG's ext-authz handler.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    /// The on-wire action Envoy must enforce.
    pub action: Action,
    /// Human-readable reason: dotted category for telemetry
    /// drill-down ("bypass.tls.healthcare", "deny.malware.sha256",
    /// "rate_limit.tenant"). Stable contract for the dashboards
    /// that group on it.
    pub reason: String,
    /// Optional category the URL resolved to. None for verdicts
    /// not produced by the categoriser (bypass, rate limit,
    /// malware).
    pub category: Option<String>,
    /// Seconds the client should wait before retrying. `Some` only
    /// when `action == Action::RateLimit`; `None` otherwise.
    ///
    /// The rate limiter computes this in
    /// [`crate::rate_limit::RateLimitDecision::retry_after_secs`];
    /// the handler threads it through here so
    /// [`crate::auth::ExtAuthzResponse::from_verdict`] can copy it
    /// onto the wire response. Envoy reads the wire response and
    /// stamps it onto a `Retry-After` header on the 429 — without
    /// the value, clients have no signal to back off and may keep
    /// hammering the SWG, amplifying the overload that triggered
    /// the rate limit in the first place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
}

impl Verdict {
    /// Construct an allow verdict with an explicit reason. The
    /// allow path almost always wants `Verdict::allow_uncategorized`
    /// unless a categoriser produced an explicit allow-listed
    /// category for the request.
    #[must_use]
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            action: Action::Allow,
            reason: reason.into(),
            category: None,
            retry_after_secs: None,
        }
    }

    /// Allow verdict with no categoriser hit. Reason is the
    /// fixed `"allow.uncategorized"` string so dashboards can
    /// count the no-match path distinctly from the categorised
    /// allow path.
    #[must_use]
    pub fn allow_uncategorized() -> Self {
        Self::allow("allow.uncategorized")
    }

    /// Allow verdict carrying the matched category. Reason
    /// becomes `"allow.<category>"` so the verdict event's
    /// category and reason fields stay consistent.
    #[must_use]
    pub fn allow_categorized(category: impl Into<String>) -> Self {
        let c = category.into();
        Self {
            action: Action::Allow,
            reason: format!("allow.{c}"),
            category: Some(c),
            retry_after_secs: None,
        }
    }

    /// Deny verdict. Reason is the dotted category (e.g.
    /// `"deny.malware.sha256"` or `"deny.category.gambling"`).
    #[must_use]
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            action: Action::Deny,
            reason: reason.into(),
            category: None,
            retry_after_secs: None,
        }
    }

    /// Deny verdict carrying the offending category.
    #[must_use]
    pub fn deny_categorized(category: impl Into<String>) -> Self {
        let c = category.into();
        Self {
            action: Action::Deny,
            reason: format!("deny.{c}"),
            category: Some(c),
            retry_after_secs: None,
        }
    }

    /// Bypass verdict — TLS interception is intentionally skipped.
    #[must_use]
    pub fn bypass(reason: impl Into<String>) -> Self {
        Self {
            action: Action::Bypass,
            reason: reason.into(),
            category: None,
            retry_after_secs: None,
        }
    }

    /// Rate-limited verdict. The reason carries the bucket
    /// identifier for dashboards; `retry_after_secs` is the
    /// number of seconds the client should wait before
    /// retrying — sourced from
    /// [`crate::rate_limit::RateLimitDecision::retry_after_secs`]
    /// and surfaced verbatim on the ext-authz wire response so
    /// Envoy can stamp it onto the `Retry-After` header of the
    /// 429. The argument is mandatory (not `Option<u64>`)
    /// because every rate-limit decision comes from the limiter
    /// and the limiter always computes a value — making it
    /// optional would invite a future caller to forget the
    /// retry signal and silently regress the wire contract.
    #[must_use]
    pub fn rate_limit(reason: impl Into<String>, retry_after_secs: u64) -> Self {
        Self {
            action: Action::RateLimit,
            reason: reason.into(),
            category: None,
            retry_after_secs: Some(retry_after_secs),
        }
    }

    /// True when the verdict completes the request (Allow /
    /// Bypass). False for verdicts that abort the request (Deny /
    /// RateLimit). Used by the telemetry layer to gate
    /// "completed_requests" vs "blocked_requests" counters.
    #[must_use]
    pub const fn is_completing(&self) -> bool {
        matches!(self.action, Action::Allow | Action::Bypass)
    }
}

/// Decoded ext-authz request. Built by the [`crate::auth`] HTTP
/// frame decoder before being passed to the verdict pipeline.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestContext {
    /// Tenant the request was issued under. Carried in the
    /// `x-sng-tenant` header by the Envoy filter chain.
    pub tenant_id: String,
    /// Stable principal id (device / user / service account).
    /// Carried in the `x-sng-principal` header.
    pub principal_id: String,
    /// HTTP method. Lowercased on decode to make subsequent
    /// matching case-insensitive without per-callsite normalisation.
    pub method: String,
    /// `http` or `https`. Lowercased on decode.
    pub scheme: String,
    /// Request host (no port). Lowercased on decode so the
    /// categoriser does not have to case-fold per request.
    pub host: String,
    /// Request path (with leading slash, no query). The query
    /// is stripped before reaching the categoriser — the SWG's
    /// URL feed indexes on host+path, not on per-request query.
    pub path: String,
    /// SNI extracted from the TLS ClientHello by Envoy and
    /// forwarded in the ext-authz body. Optional because plain
    /// HTTP requests have no SNI.
    pub sni: Option<String>,
    /// SHA-256 of the response body for malware verdicts. Set
    /// only when Envoy is asking for a *response*-side decision
    /// (file download); None for request-side decisions.
    pub file_hash: Option<String>,
}

impl RequestContext {
    /// Normalise the context's case-sensitive fields. The decoder
    /// already does this on construction, but the helper is
    /// exposed for callers building a context by hand in tests so
    /// the normalisation contract has one source of truth.
    pub fn normalize(&mut self) {
        self.method = self.method.to_ascii_lowercase();
        self.scheme = self.scheme.to_ascii_lowercase();
        self.host = self.host.to_ascii_lowercase();
        if let Some(s) = self.sni.as_mut() {
            *s = s.to_ascii_lowercase();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn action_strings_are_stable() {
        // Wire contract — telemetry dashboards group on these
        // exact strings; changing one is a breaking change to the
        // observability schema.
        assert_eq!(Action::Allow.as_str(), "allow");
        assert_eq!(Action::Deny.as_str(), "deny");
        assert_eq!(Action::Bypass.as_str(), "bypass");
        assert_eq!(Action::RateLimit.as_str(), "rate_limit");
    }

    #[test]
    fn verdict_allow_uncategorized_uses_fixed_reason() {
        // The no-match allow path produces a fixed reason string
        // so dashboards count it separately from the categorised
        // allow path. Locking the string here so a refactor
        // can't quietly diverge.
        let v = Verdict::allow_uncategorized();
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.reason, "allow.uncategorized");
        assert_eq!(v.category, None);
    }

    #[test]
    fn verdict_allow_categorized_carries_category_in_reason() {
        // The categorised allow path joins the category into the
        // reason field with a "." separator so a downstream
        // telemetry consumer can `split_once('.')` and reuse the
        // category without parsing the verdict struct.
        let v = Verdict::allow_categorized("business.saas");
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.reason, "allow.business.saas");
        assert_eq!(v.category.as_deref(), Some("business.saas"));
    }

    #[test]
    fn verdict_deny_categorized_uses_deny_prefix() {
        let v = Verdict::deny_categorized("gambling");
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.reason, "deny.gambling");
        assert_eq!(v.category.as_deref(), Some("gambling"));
    }

    #[test]
    fn is_completing_distinguishes_allow_bypass_from_deny_rate_limit() {
        // The telemetry layer uses is_completing() to bucket
        // events between "completed" and "blocked" counters; the
        // distinction must match the request's actual fate at
        // Envoy.
        assert!(Verdict::allow_uncategorized().is_completing());
        assert!(Verdict::bypass("bypass.tls.healthcare").is_completing());
        assert!(!Verdict::deny("deny.malware.sha256").is_completing());
        assert!(!Verdict::rate_limit("rate_limit.tenant", 30).is_completing());
    }

    #[test]
    fn request_context_normalize_lowercases_method_scheme_host_sni() {
        // The decoder lowercases on entry, but callers building a
        // context by hand (tests, future control-plane wiring)
        // must produce the same normal form.
        let mut ctx = RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "GET".into(),
            scheme: "HTTPS".into(),
            host: "Bank.Example".into(),
            path: "/Login".into(),
            sni: Some("Bank.Example".into()),
            file_hash: None,
        };
        ctx.normalize();
        assert_eq!(ctx.method, "get");
        assert_eq!(ctx.scheme, "https");
        assert_eq!(ctx.host, "bank.example");
        assert_eq!(ctx.sni.as_deref(), Some("bank.example"));
        // Path is left untouched — Envoy already normalises path
        // segments and the URL feed indexes on the unmodified
        // path form.
        assert_eq!(ctx.path, "/Login");
    }

    #[test]
    fn verdict_round_trips_through_serde_json() {
        // The verdict is serialised to JSON for the ext-authz
        // response body; round-trip stability is the wire
        // contract.
        let v = Verdict::allow_categorized("business.saas");
        let s = serde_json::to_string(&v).expect("serialise");
        let v2: Verdict = serde_json::from_str(&s).expect("deserialise");
        assert_eq!(v, v2);
    }
}

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
    /// Normalise the context's case-sensitive fields and strip
    /// the query component from `path`. The decoder already does
    /// this on construction, but the helper is exposed for
    /// callers building a context by hand in tests so the
    /// normalisation contract has one source of truth.
    ///
    /// Stripping the query is a contract obligation, not a
    /// cosmetic detail: the field's doc comment promises "no
    /// query", the categoriser indexes on `host` + `path` (not
    /// per-request query), and the verdict telemetry serialises
    /// the path verbatim — leaving the query in would surface
    /// session tokens, OAuth state, and other PII-shaped
    /// secrets through the wire-level dashboards.
    pub fn normalize(&mut self) {
        self.method = self.method.to_ascii_lowercase();
        self.scheme = self.scheme.to_ascii_lowercase();
        self.host = self.host.to_ascii_lowercase();
        if let Some(idx) = self.path.find('?') {
            self.path.truncate(idx);
        }
        if let Some(s) = self.sni.as_mut() {
            *s = s.to_ascii_lowercase();
        }
        // `MalwareVerdictProvider::verdict` is documented as
        // taking hex-encoded lowercase SHA-256 — callers must
        // normalise before querying so the provider's internal
        // storage can be case-sensitive (see
        // `MalwareVerdictProvider` doc comment in `malware.rs`).
        // Envoy and upstream feeds aren't consistent on hex case:
        // RFC 3548 §6 says hex is case-insensitive but
        // implementations differ — OpenSSL emits lowercase,
        // browsers emit uppercase, and several threat-intel feeds
        // ship mixed-case. Lowercasing here means the verdict
        // pipeline has one source of truth, and a future
        // `MalwareVerdictProvider` impl that compares hashes
        // byte-for-byte against an internal lowercase map (the
        // `StaticMalwareList` pattern in `malware.rs:117-120`)
        // cannot silently miss a known-bad hash because Envoy
        // forwarded it uppercase. The verdict response also
        // serialises `file_hash` into telemetry, so normalising
        // here also collapses dashboard cardinality from
        // "same-hash-different-case" duplicates.
        if let Some(h) = self.file_hash.as_mut() {
            *h = h.to_ascii_lowercase();
        }
    }
}

/// A deny policy over dotted category strings, supporting both exact-category
/// rules and *group* (dotted-subtree) rules.
///
/// # The dotted-category vocabulary
///
/// Categories are dotted, hierarchical strings — `security.malware`,
/// `adult.content`, `business.saas` — where each dot introduces a more
/// specific child of its parent namespace (see [`crate::categorizer`] for the
/// full vocabulary). This policy exploits that hierarchy:
///
/// * An **exact** rule `"adult.content"` denies *only* the category
///   `adult.content` — not a parent (`adult`) and not a child
///   (`adult.content.explicit`). This is the precise, no-surprises match the
///   handler's pre-existing operator deny-list always had.
/// * A **group** rule `"security"` denies the whole `security.*` subtree —
///   `security.malware`, `security.phishing`, `security.botnet`, … — plus the
///   bare `security` node itself.
///
/// Group matching is *dotted-segment* prefix matching: a rule `g` matches a
/// category `c` when `c == g` or `c` starts with `g + "."`. The segment
/// boundary matters — the group `"mal"` must **not** match `malware`, only a
/// genuine `mal.*` child. This is what lets an SME write one short rule
/// (`security`) and have every present and future safe-browsing threat
/// category denied, without enumerating each leaf or risking an accidental
/// substring match.
///
/// # Why both exact and group rules
///
/// The handler's pre-existing operator deny-list is *exact* match (an operator
/// who denied `gambling` meant `gambling`, not everything containing it).
/// Preserving that as the `exact` set keeps existing bundles
/// behaving identically. Group rules are the additive, opt-in Goal-B surface:
/// smart safe-browsing defaults and industry/topic groups an operator enables
/// without hand-listing leaves.
///
/// # Performance
///
/// Exact rules are a sorted `Vec` probed with `binary_search` (O(log n) — the
/// same structure the handler used before, chosen over a `HashSet` because the
/// typical list is 50–200 entries and the sorted vec is more cache-friendly).
/// Group rules are a small handful (safe-browsing defaults plus a few operator
/// groups), scanned linearly; with the segment-boundary check this is a few
/// `starts_with` comparisons over short strings — well under the cost of the
/// `categorize` lookup that precedes it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CategoryDenyPolicy {
    /// Sorted, deduped, lowercased exact-match categories.
    exact: Vec<String>,
    /// Sorted, deduped, lowercased group (subtree) prefixes.
    groups: Vec<String>,
}

impl CategoryDenyPolicy {
    /// Empty policy — denies nothing. Equivalent to [`Default::default`].
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build a policy from exact categories and group prefixes. Both are
    /// lowercased, sorted, and deduped so lookups are canonical and O(log n)
    /// on the exact set. Empty strings are dropped.
    #[must_use]
    pub fn new(
        exact: impl IntoIterator<Item = String>,
        groups: impl IntoIterator<Item = String>,
    ) -> Self {
        let mut p = Self::default();
        p.add_exact(exact);
        p.add_groups(groups);
        p
    }

    /// The smart safe-browsing default: deny the entire `security.*` subtree
    /// (malware, phishing, botnet, …). This is the SME-friendly baseline —
    /// one group rule that blocks every present and future safe-browsing
    /// threat category with zero per-leaf configuration. Compose with
    /// operator rules via [`Self::with_groups`] / [`Self::with_exact`].
    #[must_use]
    pub fn safe_browsing_defaults() -> Self {
        Self::new(
            std::iter::empty(),
            crate::categorizer::safe_browsing_deny_groups()
                .into_iter()
                .map(String::from),
        )
    }

    /// Add exact-match categories (builder style).
    #[must_use]
    pub fn with_exact(mut self, exact: impl IntoIterator<Item = String>) -> Self {
        self.add_exact(exact);
        self
    }

    /// Add group (subtree) prefixes (builder style).
    #[must_use]
    pub fn with_groups(mut self, groups: impl IntoIterator<Item = String>) -> Self {
        self.add_groups(groups);
        self
    }

    fn add_exact(&mut self, exact: impl IntoIterator<Item = String>) {
        for c in exact {
            let c = c.trim().to_ascii_lowercase();
            if !c.is_empty() {
                self.exact.push(c);
            }
        }
        self.exact.sort();
        self.exact.dedup();
    }

    fn add_groups(&mut self, groups: impl IntoIterator<Item = String>) {
        for g in groups {
            // A group is stored without a trailing dot; matching adds the
            // boundary. Strip any the caller supplied so `"security."` and
            // `"security"` are equivalent.
            let g = g.trim().trim_end_matches('.').to_ascii_lowercase();
            if !g.is_empty() {
                self.groups.push(g);
            }
        }
        self.groups.sort();
        self.groups.dedup();
    }

    /// Whether `category` is denied by this policy. The category is matched
    /// case-insensitively (the handler already canonicalises to lowercase
    /// before calling, so the common path does no extra allocation).
    #[must_use]
    pub fn is_denied(&self, category: &str) -> bool {
        self.matched_rule(category).is_some()
    }

    /// The rule that denies `category`, or `None` if allowed. Exact matches
    /// take precedence (more specific operator intent); otherwise the first
    /// matching group. The returned `&str` borrows the matched rule from the
    /// policy (not the input), so an operator can see *why* a category was
    /// blocked (a specific leaf vs a group default) in telemetry.
    #[must_use]
    pub fn matched_rule(&self, category: &str) -> Option<&str> {
        // Avoid an allocation when the input is already lowercase (the hot
        // path); only fall back to owned-lowercase when it is not. Either way
        // the returned borrow is tied to `&self`, not the temporary.
        if category.bytes().any(|b| b.is_ascii_uppercase()) {
            self.find_rule(&category.to_ascii_lowercase())
        } else {
            self.find_rule(category)
        }
    }

    fn find_rule(&self, lower: &str) -> Option<&str> {
        if let Ok(idx) = self.exact.binary_search_by(|c| c.as_str().cmp(lower)) {
            return Some(self.exact[idx].as_str());
        }
        self.groups
            .iter()
            .find(|g| category_in_group(lower, g))
            .map(String::as_str)
    }

    /// Whether the policy denies nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.groups.is_empty()
    }

    /// Number of exact rules. Exposed for the handler's `Debug` impl / tests.
    #[must_use]
    pub fn exact_len(&self) -> usize {
        self.exact.len()
    }

    /// Number of group rules.
    #[must_use]
    pub fn group_len(&self) -> usize {
        self.groups.len()
    }
}

/// Dotted-segment subtree test: `category` is in `group` when it equals the
/// group or is a dotted child of it. The segment boundary (`group + "."`)
/// prevents `"mal"` from matching `"malware"`.
fn category_in_group(category: &str, group: &str) -> bool {
    if category == group {
        return true;
    }
    category
        .strip_prefix(group)
        .is_some_and(|rest| rest.starts_with('.'))
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
        // Path casing is left untouched — Envoy already
        // normalises path segments and the URL feed indexes on
        // the path form Envoy emits. Only the query component is
        // stripped (see request_context_normalize_strips_query).
        assert_eq!(ctx.path, "/Login");
    }

    #[test]
    fn request_context_normalize_strips_query() {
        // Wire contract: `RequestContext::path` is documented as
        // "Request path (with leading slash, no query)". HTTP/2's
        // `:path` pseudo-header includes the query, so the
        // decoder hands us "/checkout?token=…" and `normalize()`
        // must drop the `?token=…` tail before the categoriser
        // ever sees it. Leaving the query would:
        //   * make per-request cache lookups miss (the URL feed
        //     indexes on host+path, never query),
        //   * leak session tokens / OAuth `state` / OTP material
        //     into the verdict telemetry the dashboards index on,
        //   * silently drift from the field's own docstring.
        // Pin both the empty-query and dense-query cases.
        let mut ctx = RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "GET".into(),
            scheme: "HTTPS".into(),
            host: "bank.example".into(),
            path: "/checkout?session=abc123&csrf=deadbeef".into(),
            sni: None,
            file_hash: None,
        };
        ctx.normalize();
        assert_eq!(ctx.path, "/checkout");

        // A path with a question-mark in the middle of a
        // percent-encoded value is still stripped at the first
        // literal `?` — by the time `:path` reaches the SWG the
        // URI is already in its on-wire form (Envoy does not
        // decode `%3F`), so any literal `?` is unambiguously the
        // query delimiter.
        let mut ctx = RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "GET".into(),
            scheme: "HTTPS".into(),
            host: "bank.example".into(),
            path: "/p%3Fnotquery/page?actual=query".into(),
            sni: None,
            file_hash: None,
        };
        ctx.normalize();
        assert_eq!(ctx.path, "/p%3Fnotquery/page");

        // Path with no query is preserved verbatim — no spurious
        // truncation on the common case.
        let mut ctx = RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "GET".into(),
            scheme: "HTTPS".into(),
            host: "bank.example".into(),
            path: "/api/v1/users".into(),
            sni: None,
            file_hash: None,
        };
        ctx.normalize();
        assert_eq!(ctx.path, "/api/v1/users");
    }

    #[test]
    fn request_context_normalize_lowercases_file_hash() {
        // `MalwareVerdictProvider::verdict` contract (malware.rs:74-78)
        // says "The hash is hex-encoded lowercase; callers must
        // normalise before querying". A mixed-case hash forwarded
        // by Envoy must be lowercased on the way in or the
        // provider would silently miss a known-bad hash.
        //
        // Pin both the mixed-case → lowercase transform AND that
        // `None` stays `None` (response-side decisions only carry
        // `file_hash` when Envoy is asking for a response decision —
        // request-side decisions have no body to hash).
        let mut ctx = RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "GET".into(),
            scheme: "HTTPS".into(),
            host: "bank.example".into(),
            path: "/download".into(),
            sni: None,
            file_hash: Some(
                "ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789".into(),
            ),
        };
        ctx.normalize();
        assert_eq!(
            ctx.file_hash.as_deref(),
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
        );

        let mut ctx = RequestContext {
            tenant_id: "tenant-1".into(),
            principal_id: "device-42".into(),
            method: "GET".into(),
            scheme: "HTTPS".into(),
            host: "bank.example".into(),
            path: "/login".into(),
            sni: None,
            file_hash: None,
        };
        ctx.normalize();
        assert_eq!(ctx.file_hash, None);
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

    // --- CategoryDenyPolicy ---------------------------------------------

    #[test]
    fn empty_policy_denies_nothing() {
        let p = CategoryDenyPolicy::empty();
        assert!(p.is_empty());
        assert!(!p.is_denied("security.malware"));
        assert!(!p.is_denied("anything"));
    }

    #[test]
    fn exact_rule_matches_only_itself() {
        let p = CategoryDenyPolicy::new(["adult.content".to_string()], std::iter::empty());
        assert!(p.is_denied("adult.content"));
        // Exact means exact: neither a deeper child, a sibling, nor a parent
        // is denied by an exact rule. (Subtree denial is what group rules are
        // for.)
        assert!(!p.is_denied("adult.content.explicit"));
        assert!(!p.is_denied("adult.dating"));
        assert!(!p.is_denied("adult"));
    }

    #[test]
    fn group_rule_matches_whole_subtree() {
        let p = CategoryDenyPolicy::new(std::iter::empty(), ["security".to_string()]);
        assert!(p.is_denied("security"), "bare group node is denied");
        assert!(p.is_denied("security.malware"));
        assert!(p.is_denied("security.phishing"));
        assert!(p.is_denied("security.botnet.c2"));
        // Segment boundary: a category that merely starts with the group
        // string but is not a dotted child must NOT match.
        assert!(!p.is_denied("securitywidgets"));
        assert!(!p.is_denied("securitywidgets.shop"));
    }

    #[test]
    fn safe_browsing_defaults_deny_security_subtree_only() {
        let p = CategoryDenyPolicy::safe_browsing_defaults();
        assert!(p.is_denied("security.malware"));
        assert!(p.is_denied("security.phishing"));
        // Smart default is conservative: it does not block productivity /
        // business categories an SME relies on.
        assert!(!p.is_denied("business.saas"));
        assert!(!p.is_denied("social.media"));
    }

    #[test]
    fn matched_rule_reports_why_and_prefers_exact() {
        let p = CategoryDenyPolicy::new(
            ["security.malware".to_string()],
            ["security".to_string()],
        );
        // Exact wins over the overlapping group for the same category.
        assert_eq!(p.matched_rule("security.malware"), Some("security.malware"));
        // The group covers the rest of the subtree.
        assert_eq!(p.matched_rule("security.phishing"), Some("security"));
        assert_eq!(p.matched_rule("business.saas"), None);
    }

    #[test]
    fn policy_is_case_insensitive_and_normalises_input() {
        let p = CategoryDenyPolicy::new(
            ["Adult.Content".to_string()],
            ["Security".to_string()],
        );
        // Rules were lowercased on construction; lookups fold case too.
        assert!(p.is_denied("adult.content"));
        assert!(p.is_denied("ADULT.CONTENT"));
        assert!(p.is_denied("Security.Malware"));
    }

    #[test]
    fn group_trailing_dot_is_normalised() {
        // `"security."` and `"security"` must be equivalent.
        let p = CategoryDenyPolicy::new(std::iter::empty(), ["security.".to_string()]);
        assert_eq!(p.group_len(), 1);
        assert!(p.is_denied("security.malware"));
    }

    #[test]
    fn builder_composes_defaults_with_operator_rules() {
        let p = CategoryDenyPolicy::safe_browsing_defaults()
            .with_groups(["adult".to_string()])
            .with_exact(["gambling".to_string()]);
        assert!(p.is_denied("security.phishing"), "default retained");
        assert!(p.is_denied("adult.content"), "operator group added");
        assert!(p.is_denied("gambling"), "operator exact added");
        assert!(!p.is_denied("news"));
    }

    #[test]
    fn empty_and_whitespace_rules_are_dropped() {
        let p = CategoryDenyPolicy::new(
            [String::new(), "  ".to_string(), "real".to_string()],
            [String::new(), " ".to_string()],
        );
        assert_eq!(p.exact_len(), 1);
        assert_eq!(p.group_len(), 0);
        assert!(p.is_denied("real"));
    }
}

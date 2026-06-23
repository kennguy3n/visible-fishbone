//! Envoy ext-authz HTTP handler.
//!
//! Envoy posts each candidate proxied request to
//! `POST /ext_authz` with a small JSON body describing the
//! request (method, scheme, host, path, SNI, tenant +
//! principal headers). The handler returns a verdict JSON the
//! ext_authz filter translates into an Envoy wire action:
//!
//! * `{"action": "allow"}` → Envoy lets the request flow upstream
//! * `{"action": "deny",  "status": 403, "reason": "…"}` → Envoy
//!   returns the supplied status + reason to the client
//! * `{"action": "rate_limit", "retry_after_secs": 30}` → Envoy
//!   returns 429 with `Retry-After`
//! * `{"action": "bypass"}` → identical wire behaviour to allow;
//!   the distinction lives on the telemetry event so the
//!   operator dashboard can distinguish decrypted-and-allowed
//!   from straight-through-no-MITM.
//!
//! The handler is a *pure* function over the trait surface — it
//! takes the categorizer, malware verdict provider, bypass
//! list, rate limiter, and telemetry emitter — and decides
//! synchronously. No I/O happens inside the verdict logic
//! itself. The HTTP listener that wraps the handler is a thin
//! tokio reader that calls `handle(request) -> response`.

use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::bypass::BypassList;
use crate::casb::{InlineCasbInspector, RequestSignals};
use crate::casb_rules::CasbRuleSet;
use crate::categorizer::UrlCategorizer;
use crate::dlp_inline::{DlpInlineEngine, DlpInlinePolicyDef};
use crate::error::SwgError;
use crate::malware::{ContentScanVerdict, ContentScanner, MalwareVerdict, MalwareVerdictProvider};
use crate::rate_limit::RateLimiter;
use crate::ai_governance::{AiGovernanceEngine, AiGovernancePolicy, governance_to_verdict};
use crate::rbi::{RbiPolicyDef, RbiPolicyEngine};
#[cfg(test)]
use crate::rbi::RbiProxyConfig;
use crate::telemetry::{TelemetryEmitter, VerdictEvent};
use crate::verdict::{Action, CategoryDenyConfig, CategoryDenyPolicy, RequestContext, Verdict};
use crate::yara::{YaraEngine, YaraRuleBundle, YaraRuleVerifier, YaraSeverity};

use base64::Engine as _;

/// Header carrying an upstream-applied sensitivity label (e.g. a
/// Microsoft Purview / MIP label id). Read into
/// [`RequestSignals::sensitivity_label`] for inline-CASB
/// label-gated rules. Distinct from the `:`-prefixed Envoy pseudo
/// headers so an operator's `allowed_headers` allow-list controls
/// whether the label is forwarded.
const DLP_LABEL_HEADER: &str = "x-sng-dlp-label";

/// JSON shape Envoy POSTs at the ext-authz endpoint. Field
/// names match what an operator can configure via Envoy's
/// `ext_authz` HTTP service `headers_to_add` /
/// `allowed_headers` lists. Required headers:
///
/// * `:method`, `:scheme`, `:path` — Envoy pseudo-headers
/// * `host` — the request Host header
/// * `x-sng-tenant` — tenant the principal authenticates under,
///   injected by the upstream agent / IdP
/// * `x-sng-principal` — principal id (device id / user id /
///   service account)
///
/// Optional headers:
/// * `x-sng-sni` — TLS SNI when the request originates from an
///   intercepted CONNECT
///
/// The pre-hashed request body sha256 is **not** carried in a
/// header — it lives on the dedicated [`Self::body_sha256`]
/// field below. The split is intentional: the ext_authz emitter
/// in Envoy attaches the body hash on a wire-format-specific
/// slot (`request.attributes.request.http.body_sha256` on the
/// gRPC ext_authz API; the HTTP ext_authz transport surfaces it
/// as a dedicated request field rather than as a free-form
/// header) so [`Self::into_context`] reads it directly out of
/// `body_sha256` and does not look at any `x-sng-file-sha256`
/// header. An operator who configures Envoy's HTTP ext_authz
/// `allowed_headers` to forward `x-sng-file-sha256` MUST also
/// configure the filter chain that promotes the header value
/// into the request envelope's `body_sha256` field before
/// hitting this endpoint — the handler itself ignores headers
/// for the hash payload.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtAuthzRequest {
    /// Flat header map. Lower-cased keys are required (the
    /// Envoy ext-authz emitter lowercases by default).
    pub headers: Vec<(String, String)>,
    /// Pre-hashed request body sha256, hex-encoded lowercase.
    /// This is the **only** slot the handler reads for the file
    /// hash — see the doc comment on the enclosing struct for
    /// why no `x-sng-file-sha256` header is consulted. When
    /// present the handler queries the malware provider; when
    /// absent the handler skips the malware lookup entirely.
    pub body_sha256: Option<String>,
    /// Optional response body bytes, base64-encoded (standard
    /// alphabet, with padding). Envoy forwards the (size-capped)
    /// response body through the JSON envelope as base64 so the
    /// raw bytes survive the JSON transport without a binary
    /// side-channel; the handler base64-decodes it and runs the
    /// YARA signature scan over the bytes. `None` (the default,
    /// and the only value an older Envoy filter sends) skips the
    /// YARA stage — exactly like a missing `body_sha256` skips the
    /// hash check. The hash check and the YARA scan are
    /// independent: a deployment can run either, both, or neither.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body_b64: Option<String>,
}

impl ExtAuthzRequest {
    /// Build a [`RequestContext`] from the request envelope.
    /// Returns [`SwgError::ExtAuthzDecode`] when a required
    /// header is missing or has an empty value.
    pub fn into_context(self) -> Result<RequestContext, SwgError> {
        let header = |k: &str| {
            self.headers
                .iter()
                .find(|(h, _)| h.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.clone())
        };
        let require = |k: &str| -> Result<String, SwgError> {
            header(k)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| SwgError::ExtAuthzDecode(format!("missing header: {k}")))
        };
        let method = require(":method")?;
        let scheme = require(":scheme")?;
        let path = require(":path")?;
        let host = require("host")?;
        let tenant_id = require("x-sng-tenant")?;
        let principal_id = require("x-sng-principal")?;
        let mut ctx = RequestContext {
            tenant_id,
            principal_id,
            method,
            scheme,
            host,
            path,
            sni: header("x-sng-sni").filter(|v| !v.is_empty()),
            file_hash: self.body_sha256,
        };
        ctx.normalize();
        Ok(ctx)
    }

    /// Extract the out-of-band inline-CASB signals (content length,
    /// sensitivity label) from the request headers. Borrows `self`
    /// so the caller can build the signals before consuming the
    /// request via [`Self::into_context`].
    ///
    /// `content-length` is parsed leniently: a missing, empty, or
    /// non-numeric value yields `None` (unknown size), matching the
    /// inspector's fail-open-on-size contract — a request whose
    /// length the proxy could not forward never matches a
    /// size-gated rule rather than being wrongly blocked.
    #[must_use]
    pub fn signals(&self) -> RequestSignals {
        let header = |k: &str| {
            self.headers
                .iter()
                .find(|(h, _)| h.eq_ignore_ascii_case(k))
                .map(|(_, v)| v.as_str())
        };
        RequestSignals {
            content_length: header("content-length").and_then(|v| v.trim().parse::<u64>().ok()),
            sensitivity_label: header(DLP_LABEL_HEADER)
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(str::to_string),
        }
    }

    /// Decode the optional base64 response body the YARA scan runs
    /// over. Borrows `self` so the caller can decode before
    /// [`Self::into_context`] consumes the request.
    ///
    /// * `Ok(None)` — no body was forwarded (the common case; the
    ///   YARA stage is skipped, mirroring a missing `body_sha256`).
    /// * `Ok(Some(bytes))` — the decoded response body.
    /// * `Err(ExtAuthzDecode)` — the field was present but not
    ///   valid base64. A malformed body field is a request-shaping
    ///   bug in the Envoy filter, not attacker-controlled framing
    ///   we should silently ignore, so it surfaces as a decode
    ///   error (handled as a 400, the same as any other malformed
    ///   envelope field) rather than masking a misconfiguration.
    pub fn scan_body(&self) -> Result<Option<Vec<u8>>, SwgError> {
        match self.body_b64.as_deref() {
            None => Ok(None),
            Some(b64) => base64::engine::general_purpose::STANDARD
                .decode(b64)
                .map(Some)
                .map_err(|e| SwgError::ExtAuthzDecode(format!("body_b64 not valid base64: {e}"))),
        }
    }
}

/// Verdict JSON Envoy reads back. Stable wire contract — adding
/// a field is fine; removing or renaming one is a wire break.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtAuthzResponse {
    /// "allow" | "deny" | "bypass" | "rate_limit" | "redirect"
    pub action: String,
    /// HTTP status Envoy returns to the client on deny /
    /// rate_limit / redirect. `None` on allow / bypass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Categorisation/deny reason — surfaces in operator
    /// telemetry and in any 4xx body Envoy emits.
    pub reason: String,
    /// Bound on the value of `Retry-After` Envoy puts on a
    /// rate_limit response, in seconds. `None` on allow /
    /// bypass / deny / redirect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// Optional category tag — surfaces on telemetry so a
    /// dashboard can drill into "% of requests by category".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Redirect target URL. `Some` only when
    /// `action == "redirect"`; `None` otherwise. Envoy stamps
    /// this onto the `Location` header of the 302 response so
    /// the client is sent to the RBI proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_url: Option<String>,
}

/// Serialize an [`ExtAuthzResponse`] to bytes.
///
/// `ExtAuthzResponse` has a fixed, all-finite shape — every
/// field is a string, an `Option<u16>`, or an `Option<u64>`, none
/// of which can fail `serde_json::to_vec`. We still handle the
/// theoretical error by writing a minimal hard-coded JSON blob
/// rather than `expect`, because (a) the production lint policy
/// denies `expect_used`, and (b) the supervisor must never
/// panic on a malformed verdict — even a theoretical one —
/// because doing so would tear down the SWG and let traffic
/// through unfiltered.
fn serialize_response(resp: &ExtAuthzResponse) -> Vec<u8> {
    serde_json::to_vec(resp).unwrap_or_else(|_| {
        // Hand-rolled JSON literal as a final fallback. Stable
        // shape, no escaping pitfalls (no operator-supplied
        // strings), and the response is a 5xx so Envoy will
        // surface the failure mode to the caller.
        br#"{"action":"deny","status":500,"reason":"verdict serialization failed"}"#.to_vec()
    })
}

impl ExtAuthzResponse {
    fn from_verdict(v: &Verdict) -> Self {
        match v.action {
            Action::Allow => Self {
                action: "allow".into(),
                status: None,
                reason: v.reason.clone(),
                retry_after_secs: None,
                category: v.category.clone(),
                redirect_url: None,
            },
            Action::Bypass => Self {
                action: "bypass".into(),
                status: None,
                reason: v.reason.clone(),
                retry_after_secs: None,
                category: v.category.clone(),
                redirect_url: None,
            },
            Action::Deny => Self {
                action: "deny".into(),
                status: Some(403),
                reason: v.reason.clone(),
                retry_after_secs: None,
                category: v.category.clone(),
                redirect_url: None,
            },
            Action::RateLimit => Self {
                action: "rate_limit".into(),
                status: Some(429),
                reason: v.reason.clone(),
                retry_after_secs: v.retry_after_secs,
                category: v.category.clone(),
                redirect_url: None,
            },
            Action::Redirect => Self {
                action: "redirect".into(),
                status: Some(302),
                reason: v.reason.clone(),
                retry_after_secs: None,
                category: v.category.clone(),
                redirect_url: v.redirect_url.clone(),
            },
        }
    }
}

/// Telemetry emitter for inline DLP events. Mirrors
/// [`TelemetryEmitter`] but for `DlpEvent` — the handler calls
/// `emit_dlp` on every DLP match (Block, Log, or Redact) so the
/// finding metadata reaches the control plane's DLP review queue
/// through the shared telemetry pipeline. Implementations must be
/// non-blocking on the hot path (drop-on-backpressure, same as
/// [`TelemetryEmitter::emit`]).
pub trait DlpTelemetryEmitter: Send + Sync + 'static {
    /// Publish a DLP event. Called on the per-request verdict path;
    /// implementations must not block.
    fn emit_dlp(&self, event: sng_core::events::DlpEvent);
}

/// The handler. Wires the pluggable trait surfaces — categoriser,
/// malware provider, bypass list, rate limiter, telemetry — into
/// a single per-request decision function.
#[derive(Clone)]
pub struct ExtAuthzHandler {
    inner: Arc<HandlerInner>,
}

struct HandlerInner {
    categorizer: Arc<dyn UrlCategorizer>,
    malware: Arc<dyn MalwareVerdictProvider>,
    /// Bypass list is hot-swap via [`RwLock<Arc<BypassList>>`].
    /// The hot path takes a brief read lock to clone the
    /// Arc, then drops the lock before evaluating — so a
    /// concurrent install path doesn't block per-request
    /// verdicts. The ArcSwap pattern would also work; we use
    /// RwLock here because BypassList is small enough that
    /// the read-side overhead is in the noise.
    bypass: Arc<RwLock<Arc<BypassList>>>,
    rate_limiter: RateLimiter,
    telemetry: Arc<dyn TelemetryEmitter>,
    /// Operator + smart-default category deny policy. A resolved
    /// category this policy denies — by an exact rule or a
    /// dotted-subtree group rule — causes the handler to return
    /// Deny instead of Allow. Exact rules preserve the handler's
    /// original operator deny-list semantics (O(log n) binary
    /// search over a sorted, lowercased vec); group rules add the
    /// additive, opt-in safe-browsing / topic-group deny capability
    /// (one rule denies a whole `security.*` subtree). See
    /// [`CategoryDenyPolicy`].
    deny_policy: CategoryDenyPolicy,
    /// When true, [`MalwareVerdict::Suspicious`] (heuristic-only
    /// match — classifier not confident enough to deny outright)
    /// is promoted to Deny on the response-side malware check.
    /// When false (the documented default), `Suspicious` is
    /// treated the same as `Clean` so a heuristic-only match
    /// does not produce a false-positive block. The flag is set
    /// at builder-time by the operator-controlled SWG config —
    /// a deployment that wants the higher-vigilance posture
    /// opts in explicitly.
    elevated_risk_mode: bool,
    /// Optional inline-CASB inspector. When set, the verdict
    /// pipeline runs the inspector on every request after the rate
    /// limiter (so abusive callers are throttled before they reach
    /// the CASB stage) and before URL categorisation. A CASB
    /// `block` short-circuits to Deny; a CASB `log` / `allow` is
    /// carried forward and surfaced on the allow path so the
    /// verdict telemetry reflects the CASB hit — but it does NOT
    /// suppress a later malware or deny-category block. `None`
    /// leaves the pipeline exactly as it was before inline CASB
    /// existed.
    casb: Option<Arc<InlineCasbInspector>>,
    /// Optional YARA signature engine. When set, the verdict
    /// pipeline runs a content scan over the (base64-decoded)
    /// response body *after* the hash-based malware check — so a
    /// hash hit on a known-bad file still short-circuits without
    /// paying for a scan, and the YARA stage adds signature
    /// coverage for novel samples the hash list has not seen. A
    /// [`YaraSeverity::Malicious`] match denies unconditionally; a
    /// [`YaraSeverity::Suspicious`] match denies only under
    /// [`Self::elevated_risk_mode`] — the same two-tier gate the
    /// hash provider's `Suspicious` verdict uses. `None` leaves the
    /// pipeline unchanged. The engine is shared (`Arc`) and
    /// hot-swaps its own rule set internally, so the control plane
    /// can install a new signed bundle without rebuilding the
    /// handler.
    yara: Option<Arc<YaraEngine>>,
    /// Optional streaming content scanner (the canonical impl is
    /// [`crate::clamd::ClamdScanner`], which streams the body to a
    /// `clamd` daemon over INSTREAM). When set, the verdict pipeline
    /// runs it over the (base64-decoded) response body as the *last*
    /// stage of the malware chain — after the in-memory hash check
    /// and the in-process YARA scan — because a daemon round-trip is
    /// the most expensive check, so a cheaper local hit should
    /// short-circuit first. The scanner owns its fail posture
    /// (fail-open `Clean` allows, fail-closed `Malicious` with the
    /// `scanner.unavailable` sentinel denies), so a scanner outage
    /// degrades to the pre-scan coverage rather than wedging the
    /// verdict. `None` leaves the pipeline unchanged.
    content_scanner: Option<Arc<dyn ContentScanner>>,
    /// Optional inline DLP classification engine. When set, the
    /// verdict pipeline runs the engine over the (base64-decoded)
    /// body *after* the inline CASB stage and *before* URL
    /// categorisation — so a DLP `Block` short-circuits to Deny
    /// before any category or malware check. A DLP `Log` or `Redact`
    /// does NOT short-circuit: it is carried forward in
    /// `dlp_verdict` so the allow path can surface it on the verdict
    /// telemetry, and a later malware or deny-category hit can still
    /// override it with a Deny. `None` leaves the pipeline unchanged.
    /// The engine is shared (`Arc`) and hot-swaps its own policy set
    /// internally via `ArcSwap`, so the control plane can install a
    /// new DLP policy bundle without rebuilding the handler.
    dlp_engine: Option<Arc<DlpInlineEngine>>,
    /// Telemetry sink for DLP events. When the DLP engine produces a
    /// non-`None` verdict, a `DlpEvent` is published here in addition
    /// to the normal `VerdictEvent` — so the control plane's DLP
    /// review queue receives the finding metadata (redacted, no
    /// matched bytes) alongside the HTTP verdict. `None` when no DLP
    /// engine is wired; the verdict path never blocks on this sink
    /// (it uses `try_send` / drop-on-backpressure, same as the
    /// verdict emitter).
    dlp_telemetry: Option<Arc<dyn DlpTelemetryEmitter>>,
    /// Optional RBI policy engine. When set, the verdict pipeline
    /// runs the engine after inline DLP and before URL
    /// categorisation — so a DLP block still short-circuits first,
    /// and an RBI trigger redirects before the categoriser's
    /// deny-list is consulted. A trigger short-circuits to a
    /// `Verdict::redirect` so Envoy returns a 302 to the RBI
    /// proxy. `None` leaves the pipeline unchanged. The engine is
    /// shared (`Arc`) and hot-swaps its own policy set internally
    /// via `ArcSwap`, so the control plane can install a new RBI
    /// policy without rebuilding the handler.
    rbi_engine: Option<Arc<RbiPolicyEngine>>,
    /// Optional AI-governance policy engine. When set, the
    /// verdict pipeline runs the engine after RBI and before
    /// the deny-list check — so a DLP block still
    /// short-circuits first, an RBI trigger redirects first,
    /// and then AI governance can block or redirect AI-app
    /// destinations. A `Block` action short-circuits to a
    /// `Verdict::deny`; a `Redirect` action short-circuits to
    /// a `Verdict::redirect`; `Allow` and `Monitor` pass
    /// through. `None` leaves the pipeline unchanged. The
    /// engine is shared (`Arc`) and hot-swaps its own policy
    /// set internally via `ArcSwap`, so the control plane can
    /// install a new AI-governance policy without rebuilding
    /// the handler.
    ai_governance_engine: Option<Arc<AiGovernanceEngine>>,
}

impl std::fmt::Debug for ExtAuthzHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthzHandler")
            .field("deny_exact_len", &self.inner.deny_policy.exact_len())
            .field("deny_group_len", &self.inner.deny_policy.group_len())
            .field("content_scanner_set", &self.inner.content_scanner.is_some())
            .finish_non_exhaustive()
    }
}

/// Builder for [`ExtAuthzHandler`] — the trait dependencies are
/// all required so the builder is just a named constructor; we
/// keep it on the type to mirror the manager's lifecycle (which
/// produces a handler from the configured providers).
pub struct ExtAuthzHandlerBuilder {
    // Trait objects don't derive Debug so the builder hand-rolls
    // an impl below. The fields are `Option<...>` because the
    // builder accumulates set/unset state before `build` checks
    // for completeness.
    #[allow(missing_docs, missing_debug_implementations)]
    _phantom: std::marker::PhantomData<()>,
    categorizer: Option<Arc<dyn UrlCategorizer>>,
    malware: Option<Arc<dyn MalwareVerdictProvider>>,
    bypass: Option<Arc<BypassList>>,
    rate_limiter: Option<RateLimiter>,
    telemetry: Option<Arc<dyn TelemetryEmitter>>,
    deny_policy: CategoryDenyPolicy,
    elevated_risk_mode: bool,
    casb: Option<Arc<InlineCasbInspector>>,
    yara: Option<Arc<YaraEngine>>,
    content_scanner: Option<Arc<dyn ContentScanner>>,
    dlp_engine: Option<Arc<DlpInlineEngine>>,
    dlp_telemetry: Option<Arc<dyn DlpTelemetryEmitter>>,
    rbi_engine: Option<Arc<RbiPolicyEngine>>,
    ai_governance_engine: Option<Arc<AiGovernanceEngine>>,
}

impl std::fmt::Debug for ExtAuthzHandlerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthzHandlerBuilder")
            .field("categorizer_set", &self.categorizer.is_some())
            .field("malware_set", &self.malware.is_some())
            .field("bypass_set", &self.bypass.is_some())
            .field("rate_limiter_set", &self.rate_limiter.is_some())
            .field("telemetry_set", &self.telemetry.is_some())
            .field("deny_exact_len", &self.deny_policy.exact_len())
            .field("deny_group_len", &self.deny_policy.group_len())
            .field("elevated_risk_mode", &self.elevated_risk_mode)
            .field("casb_set", &self.casb.is_some())
            .field("yara_set", &self.yara.is_some())
            .field("content_scanner_set", &self.content_scanner.is_some())
            .field("dlp_engine_set", &self.dlp_engine.is_some())
            .field("dlp_telemetry_set", &self.dlp_telemetry.is_some())
            .field("rbi_engine_set", &self.rbi_engine.is_some())
            .field("ai_governance_engine_set", &self.ai_governance_engine.is_some())
            .finish()
    }
}

impl ExtAuthzHandlerBuilder {
    /// Start a new builder. All trait deps must be set before
    /// [`Self::build`] is called.
    #[must_use]
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
            categorizer: None,
            malware: None,
            bypass: None,
            rate_limiter: None,
            telemetry: None,
            deny_policy: CategoryDenyPolicy::empty(),
            elevated_risk_mode: false,
            casb: None,
            yara: None,
            content_scanner: None,
            dlp_engine: None,
            dlp_telemetry: None,
            rbi_engine: None,
            ai_governance_engine: None,
        }
    }

    #[must_use]
    pub fn with_categorizer(mut self, c: Arc<dyn UrlCategorizer>) -> Self {
        self.categorizer = Some(c);
        self
    }

    #[must_use]
    pub fn with_malware(mut self, m: Arc<dyn MalwareVerdictProvider>) -> Self {
        self.malware = Some(m);
        self
    }

    #[must_use]
    pub fn with_bypass(mut self, b: Arc<BypassList>) -> Self {
        self.bypass = Some(b);
        self
    }

    #[must_use]
    pub fn with_rate_limiter(mut self, r: RateLimiter) -> Self {
        self.rate_limiter = Some(r);
        self
    }

    #[must_use]
    pub fn with_telemetry(mut self, t: Arc<dyn TelemetryEmitter>) -> Self {
        self.telemetry = Some(t);
        self
    }

    /// Add exact-match deny categories (builder style). An exact
    /// rule denies *only* the named category — not a parent and not
    /// a child — preserving the handler's original operator
    /// deny-list semantics. Categories are lowercased, sorted, and
    /// deduped inside the [`CategoryDenyPolicy`]; the hot path tests
    /// membership with an O(log n) binary search. Repeated calls
    /// accumulate.
    #[must_use]
    pub fn with_deny_categories(mut self, cats: Vec<String>) -> Self {
        self.deny_policy = std::mem::take(&mut self.deny_policy).with_exact(cats);
        self
    }

    /// Add group (dotted-subtree) deny rules (builder style). A
    /// group rule `"security"` denies the whole `security.*`
    /// subtree (`security.malware`, `security.phishing`, …) plus
    /// the bare `security` node, with segment-boundary safety (the
    /// group `"mal"` does not match `malware`). This is the
    /// additive, opt-in Goal-B surface that lets an SME deny every
    /// present and future safe-browsing threat category with one
    /// short rule instead of enumerating each leaf. Repeated calls
    /// accumulate.
    #[must_use]
    pub fn with_deny_groups(mut self, groups: Vec<String>) -> Self {
        self.deny_policy = std::mem::take(&mut self.deny_policy).with_groups(groups);
        self
    }

    /// Replace the accumulated deny policy wholesale with a
    /// pre-built [`CategoryDenyPolicy`] — e.g.
    /// [`CategoryDenyPolicy::safe_browsing_defaults`] composed with
    /// operator rules via its builder. Overrides any prior
    /// [`Self::with_deny_categories`] / [`Self::with_deny_groups`]
    /// calls on this builder.
    #[must_use]
    pub fn with_deny_policy(mut self, policy: CategoryDenyPolicy) -> Self {
        self.deny_policy = policy;
        self
    }

    /// Wire an operator's [`CategoryDenyConfig`] (the serde-stable
    /// config-plane shape a policy bundle carries) into the handler by
    /// compiling it into a [`CategoryDenyPolicy`]. This is the
    /// intended entry point for config-driven deployments: the
    /// deployment layer deserialises the bundle's deny config and
    /// passes it straight here, rather than translating into the
    /// individual `with_deny_*` calls by hand. Like
    /// [`Self::with_deny_policy`], this replaces the accumulated
    /// policy wholesale (the config already expresses the full intent,
    /// including the opt-in safe-browsing baseline).
    #[must_use]
    pub fn with_deny_config(self, config: CategoryDenyConfig) -> Self {
        self.with_deny_policy(config.into_policy())
    }

    /// Opt in to elevated-risk posture: promote
    /// [`MalwareVerdict::Suspicious`] (heuristic-only match) to
    /// Deny. The default posture (false) treats `Suspicious` the
    /// same as `Clean`, matching the contract documented on the
    /// [`MalwareVerdict::Suspicious`] variant.
    ///
    /// Use this for tenants where heuristic-only matches should
    /// block out of caution (regulated industries, IR-mode
    /// activations). The default is conservative because
    /// auto-denying on heuristic-only matches causes
    /// false-positive blocks on legitimate downloads.
    #[must_use]
    pub fn with_elevated_risk_mode(mut self, on: bool) -> Self {
        self.elevated_risk_mode = on;
        self
    }

    /// Install an inline-CASB inspector. Optional: a handler built
    /// without one runs the pre-CASB verdict pipeline unchanged.
    /// The inspector's rule set is hot-swappable post-build via
    /// [`ExtAuthzHandler::install_casb_rules`], so a handler can be
    /// built with the inspector wired (built-in app catalog, empty
    /// rule set) and have its rules installed later from the first
    /// policy-bundle the control plane publishes.
    #[must_use]
    pub fn with_casb_inspector(mut self, inspector: Arc<InlineCasbInspector>) -> Self {
        self.casb = Some(inspector);
        self
    }

    /// Install a YARA signature engine. Optional: a handler built
    /// without one runs the verdict pipeline with no content scan
    /// (hash-based malware detection only). The engine's rule set
    /// is hot-swappable post-build via
    /// [`ExtAuthzHandler::install_yara_bundle`], so a handler can be
    /// built with the built-in rule set and have an operator bundle
    /// installed later from the first signed YARA bundle the
    /// control plane publishes — exactly like the CASB rule set.
    #[must_use]
    pub fn with_yara_engine(mut self, engine: Arc<YaraEngine>) -> Self {
        self.yara = Some(engine);
        self
    }

    /// Install a streaming content scanner (the canonical impl is
    /// [`crate::clamd::ClamdScanner`] over the `clamd` INSTREAM
    /// protocol). Optional: a handler built without one runs the
    /// malware chain with the hash check + YARA scan only. When wired,
    /// the scanner runs as the last malware stage in [`Self::build`]'s
    /// handler — after the cheap local checks — so a daemon round-trip
    /// is paid only for content no earlier stage already denied. The
    /// scanner is shared (`Arc`) and owns its own connection pool /
    /// verdict cache, so the same scanner can back several handlers.
    #[must_use]
    pub fn with_content_scanner(mut self, scanner: Arc<dyn ContentScanner>) -> Self {
        self.content_scanner = Some(scanner);
        self
    }

    /// Install an inline DLP classification engine. Optional: a
    /// handler built without one runs the verdict pipeline with no
    /// inline DLP enforcement (out-of-band DLP via the endpoint agent
    /// is unaffected). The engine's policy is hot-swappable
    /// post-build via [`ExtAuthzHandler::install_dlp_policy`], so a
    /// handler can be built with the engine wired (empty policy) and
    /// have its rules installed later from the first policy bundle.
    /// When `dlp_telemetry` is also wired, the handler publishes a
    /// `DlpEvent` for every DLP match alongside the normal verdict
    /// telemetry.
    #[must_use]
    pub fn with_dlp_engine(mut self, engine: Arc<DlpInlineEngine>) -> Self {
        self.dlp_engine = Some(engine);
        self
    }

    /// Wire the DLP telemetry emitter so DLP findings are published
    /// to the shared telemetry pipeline. Optional: when `None`, DLP
    /// matches still produce verdicts (Block → Deny, Log → Allow)
    /// but no `DlpEvent` is emitted — the finding metadata is lost.
    /// In practice this should always be set when a DLP engine is
    /// wired.
    #[must_use]
    pub fn with_dlp_telemetry(mut self, emitter: Arc<dyn DlpTelemetryEmitter>) -> Self {
        self.dlp_telemetry = Some(emitter);
        self
    }

    /// Wire the RBI policy engine. When set, the verdict pipeline
    /// evaluates RBI trigger rules after inline DLP and before URL
    /// categorisation. A trigger short-circuits to a redirect
    /// verdict so Envoy sends the client to the RBI proxy. The
    /// engine hot-swaps its policy internally via `ArcSwap`, so the
    /// control plane can install a new RBI policy without
    /// rebuilding the handler.
    #[must_use]
    pub fn with_rbi_engine(mut self, engine: Arc<RbiPolicyEngine>) -> Self {
        self.rbi_engine = Some(engine);
        self
    }

    /// Wire the AI-governance policy engine. When set, the
    /// verdict pipeline evaluates AI-app governance rules after
    /// RBI and before the deny-list check. A `Block` action
    /// short-circuits to a deny; a `Redirect` action
    /// short-circuits to a redirect to the RBI proxy; `Allow`
    /// and `Monitor` pass through. The engine hot-swaps its
    /// policy internally via `ArcSwap`, so the control plane
    /// can install a new AI-governance policy without
    /// rebuilding the handler.
    #[must_use]
    pub fn with_ai_governance_engine(mut self, engine: Arc<AiGovernanceEngine>) -> Self {
        self.ai_governance_engine = Some(engine);
        self
    }

    /// Build the handler. Returns an error when any required
    /// dep was not set.
    pub fn build(self) -> Result<ExtAuthzHandler, SwgError> {
        // The deny policy canonicalises (lowercase), sorts, and
        // dedups its rules as they are added, so the hot-path lookup
        // is O(log n) on the exact set with no per-request
        // allocation — no normalisation step is needed here.
        Ok(ExtAuthzHandler {
            inner: Arc::new(HandlerInner {
                categorizer: self
                    .categorizer
                    .ok_or_else(|| SwgError::Config("categorizer not set".into()))?,
                malware: self
                    .malware
                    .ok_or_else(|| SwgError::Config("malware provider not set".into()))?,
                bypass: Arc::new(RwLock::new(
                    self.bypass
                        .ok_or_else(|| SwgError::Config("bypass list not set".into()))?,
                )),
                rate_limiter: self
                    .rate_limiter
                    .ok_or_else(|| SwgError::Config("rate limiter not set".into()))?,
                telemetry: self
                    .telemetry
                    .ok_or_else(|| SwgError::Config("telemetry emitter not set".into()))?,
                deny_policy: self.deny_policy,
                elevated_risk_mode: self.elevated_risk_mode,
                casb: self.casb,
                yara: self.yara,
                content_scanner: self.content_scanner,
                dlp_engine: self.dlp_engine,
                dlp_telemetry: self.dlp_telemetry,
                rbi_engine: self.rbi_engine,
                ai_governance_engine: self.ai_governance_engine,
            }),
        })
    }
}

impl Default for ExtAuthzHandlerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtAuthzHandler {
    /// Atomically swap in a new bypass list. The hot path picks
    /// up the new list on its next read; any in-flight verdicts
    /// continue using the old list.
    pub fn install_bypass(&self, list: Arc<BypassList>) {
        *self.inner.bypass.write() = list;
    }

    /// Hot-swap the inline-CASB rule set, preserving the inspector's
    /// app catalog. No-op (returns 0) when the handler was built
    /// without an inspector. Returns the number of rules installed
    /// so the policy-bundle controller can log it. The control
    /// plane calls this on every bundle install with the CASB slice
    /// decoded from the freshly-signed bundle.
    pub fn install_casb_rules(&self, rules: &CasbRuleSet) -> usize {
        match &self.inner.casb {
            Some(insp) => insp.install_rules(rules),
            None => 0,
        }
    }

    /// Verify and hot-swap a signed YARA rule bundle into the
    /// engine. Mirrors [`Self::install_casb_rules`]: the control
    /// plane calls this on every signed YARA bundle it publishes.
    ///
    /// Returns:
    /// * `Ok(Some(rev))` — the installed bundle revision.
    /// * `Ok(None)` — the handler was built without a YARA engine,
    ///   so there is nothing to install (no-op, not an error, so a
    ///   YARA-less deployment can run the same bundle-install code
    ///   path without special-casing).
    /// * `Err(_)` — signature / staleness / compile failure from
    ///   [`YaraEngine::install_bundle`]; the live rule set is left
    ///   untouched.
    pub fn install_yara_bundle(
        &self,
        verifier: &YaraRuleVerifier,
        bundle: &YaraRuleBundle,
    ) -> Result<Option<u64>, SwgError> {
        match &self.inner.yara {
            Some(engine) => engine.install_bundle(verifier, bundle).map(Some),
            None => Ok(None),
        }
    }

    /// The installed YARA bundle revision, or `None` when no engine
    /// is wired or only the built-in rule set is live. Exposed for
    /// boot diagnostics / operator status endpoints.
    #[must_use]
    pub fn yara_version(&self) -> Option<u64> {
        self.inner.yara.as_ref().and_then(|e| e.version())
    }

    /// Hot-swap the inline DLP policy. No-op (returns `(0, 0)`) when
    /// the handler was built without a DLP engine. Returns the number
    /// of regex rules and fingerprints installed so the policy-bundle
    /// controller can log it. The control plane calls this on every
    /// bundle install with the DLP slice decoded from the bundle.
    pub fn install_dlp_policy(&self, def: &DlpInlinePolicyDef) -> (usize, usize) {
        match &self.inner.dlp_engine {
            Some(engine) => engine.install(def),
            None => (0, 0),
        }
    }

    /// Hot-swap the RBI policy. No-op (returns `(0, 0)`) when
    /// the handler was built without an RBI engine. Returns the
    /// number of categories and explicit-isolate hosts installed
    /// so the policy-bundle controller can log it. The control
    /// plane calls this on every bundle install with the RBI slice
    /// decoded from the bundle.
    pub fn install_rbi_policy(&self, def: &RbiPolicyDef) -> (usize, usize) {
        match &self.inner.rbi_engine {
            Some(engine) => engine.install(def),
            None => (0, 0),
        }
    }

    /// Hot-swap the AI-governance policy. No-op (returns
    /// `(0, 0)`) when the handler was built without an
    /// AI-governance engine. Returns the number of rules
    /// installed so the policy-bundle controller can log it.
    /// The control plane calls this on every bundle install
    /// with the AI-governance slice decoded from the bundle.
    pub fn install_ai_governance_policy(&self, def: &AiGovernancePolicy) -> (usize, usize) {
        match &self.inner.ai_governance_engine {
            Some(engine) => engine.install(def),
            None => (0, 0),
        }
    }

    /// Convenience: process a decoded JSON request envelope.
    /// Returns the response envelope ready for serialisation.
    pub async fn handle_request(&self, req: ExtAuthzRequest) -> Result<ExtAuthzResponse, SwgError> {
        // Build the out-of-band CASB signals and decode the YARA
        // scan body before `into_context` consumes the request
        // envelope. A malformed `body_b64` surfaces as an
        // `ExtAuthzDecode` (400) rather than being silently dropped.
        let signals = req.signals();
        let scan_body = req.scan_body()?;
        let ctx = req.into_context()?;
        let verdict = self.evaluate(&ctx, &signals, scan_body.as_deref()).await;
        let resp = ExtAuthzResponse::from_verdict(&verdict);
        self.inner
            .telemetry
            .emit(VerdictEvent::from_context(&ctx, verdict));
        Ok(resp)
    }

    /// Convenience: process a raw JSON byte buffer (Envoy's
    /// over-the-wire shape) and return the JSON byte buffer
    /// Envoy expects. This is the entry point a thin tokio HTTP
    /// listener wraps; the verdict logic remains testable via
    /// [`Self::evaluate`] without needing to spin one up.
    pub async fn handle_json_bytes(&self, body: &[u8]) -> Vec<u8> {
        let req: ExtAuthzRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                let r = ExtAuthzResponse {
                    action: "deny".into(),
                    status: Some(400),
                    reason: format!("malformed ext_authz request: {e}"),
                    retry_after_secs: None,
                    category: None,
                    redirect_url: None,
                };
                return serialize_response(&r);
            }
        };
        let resp = match self.handle_request(req).await {
            Ok(r) => r,
            Err(SwgError::ExtAuthzDecode(msg)) => ExtAuthzResponse {
                action: "deny".into(),
                status: Some(400),
                reason: format!("ext_authz decode: {msg}"),
                retry_after_secs: None,
                category: None,
                redirect_url: None,
            },
            Err(other) => ExtAuthzResponse {
                action: "deny".into(),
                status: Some(500),
                reason: format!("handler error: {other}"),
                retry_after_secs: None,
                category: None,
                redirect_url: None,
            },
        };
        serialize_response(&resp)
    }

    /// The verdict engine. Pure over the trait surface — given
    /// the same `(categorizer, bypass, malware, rate limiter)`
    /// snapshot the same context always produces the same
    /// verdict. That's what makes the handler unit-testable
    /// without an HTTP layer.
    ///
    /// Decision order:
    /// 1. TLS bypass — exempt the request entirely if SNI matches
    /// 2. Rate limit — protect the verdict pipeline from runaways
    /// 3. Inline CASB — block short-circuits; log/allow is carried
    ///    forward so a later deny still wins
    /// 3b. Inline DLP — block short-circuits; log/redact is carried
    ///    forward so a later deny still wins
    /// 3c. RBI policy — redirect short-circuits to the RBI proxy
    ///    when a trigger rule matches (runs after categorisation
    ///    so the category is available)
    /// 3d. AI governance — block short-circuits to deny, redirect
    ///    short-circuits to the RBI proxy; allow/monitor passes
    ///    through (runs after RBI so an RBI trigger wins over a
    ///    governance redirect, and before the deny-list so a
    ///    governance block wins over a category allow)
    /// 4. URL categorisation — operator deny-list wins; default allow
    /// 5. Malware verdict on the response body hash (when supplied)
    /// 6. YARA content scan on the response body (when supplied and
    ///    an engine is wired) — runs after the hash check so a known
    ///    hash hit short-circuits without a scan
    /// 7. Streaming content scan / ClamAV INSTREAM on the response
    ///    body (when supplied and a scanner is wired) — runs last in
    ///    the malware chain because a daemon round-trip is the most
    ///    expensive check, so a cheaper local hit denies first
    ///
    /// `signals` carries the out-of-band inline-CASB inputs (content
    /// length, sensitivity label) extracted from the request by
    /// [`ExtAuthzRequest::signals`]. They are ignored when no CASB
    /// inspector is wired. `scan_body` is the (already base64-decoded)
    /// response body the YARA stage and the streaming content scanner
    /// scan; `None` skips both content stages (mirroring a missing
    /// file hash). The verdict stays a pure function of
    /// `(ctx, signals, scan_body)` over the configured trait +
    /// inspector + engine + scanner snapshot (the streaming scanner is
    /// the one stage that performs I/O — a `clamd` socket round-trip —
    /// which is why `evaluate` is `async`).
    pub async fn evaluate(
        &self,
        ctx: &RequestContext,
        signals: &RequestSignals,
        scan_body: Option<&[u8]>,
    ) -> Verdict {
        // 1. TLS bypass — we *only* short-circuit when SNI
        //    matches a bypass entry. Other paths see the full
        //    pipeline. Pulling a clone of the Arc out of the
        //    RwLock lets us drop the lock before the
        //    (synchronous) match call so the read side is as
        //    narrow as possible.
        let bypass = { Arc::clone(&self.inner.bypass.read()) };
        if let Some(sni) = ctx.sni.as_deref() {
            let dec = bypass.evaluate(Some(sni));
            if dec.bypass {
                return Verdict::bypass(dec.reason.to_telemetry_string());
            }
        }

        // 2. Rate limit. Bucket key is (tenant_id, principal_id);
        //    the rate limiter is the source-of-truth for retry
        //    timing.
        let rate = self
            .inner
            .rate_limiter
            .acquire(&ctx.tenant_id, &ctx.principal_id);
        if !rate.permitted {
            // Thread the limiter's retry_after_secs through the
            // verdict so [`ExtAuthzResponse::from_verdict`] can
            // surface it on the wire and Envoy can stamp a
            // `Retry-After` header on the 429. Without this,
            // clients have no back-off signal and tend to
            // retry aggressively, amplifying the overload that
            // triggered the rate limit in the first place.
            let mut v = Verdict::rate_limit(
                format!("rate_limit.{}", rate.bucket_key),
                rate.retry_after_secs,
            );
            v.category = Some("rate_limit.bucket".into());
            return v;
        }

        // 3. Inline CASB. Runs after the rate limiter (so an
        //    abusive caller is throttled before reaching the
        //    inspector) and before URL categorisation. A `block`
        //    rule short-circuits straight to Deny. A `log` / `allow`
        //    rule does NOT short-circuit: it is carried forward in
        //    `casb_verdict` so a later malware or deny-category hit
        //    can still override it with a Deny, and only surfaces on
        //    the allow path below — where it takes precedence over a
        //    plain categoriser allow so the verdict telemetry
        //    reflects the specific SaaS action (e.g. tagging an
        //    OneDrive download for DLP). `None` (not CASB-relevant,
        //    or no rule matched) leaves the pipeline unchanged.
        let casb_verdict = self
            .inner
            .casb
            .as_ref()
            .and_then(|insp| insp.inspect(ctx, signals));
        if let Some(v) = &casb_verdict
            && v.action == Action::Deny
        {
            return v.clone();
        }

        // 3b. Inline DLP classification. Runs after CASB (so a
        //     CASB block short-circuits first) and before URL
        //     categorisation — so a DLP block denies before any
        //     category or malware check. A DLP `Log` or `Redact` is
        //     carried forward in `dlp_verdict` so the allow path can
        //     surface it on the verdict telemetry, and a later
        //     malware or deny-category hit can still override it.
        //     The scan runs over the same `scan_body` the YARA and
        //     streaming content scanner stages use (the base64-
        //     decoded response body Envoy forwarded). `None` (no
        //     engine wired, no body forwarded, or no rules matched)
        //     leaves the pipeline unchanged.
        let dlp_verdict = if let Some(engine) = self.inner.dlp_engine.as_ref() {
            scan_body.and_then(|body| {
                let destination = ctx.host.as_str();
                engine.classify(body, signals).map(|v| {
                    // Emit DLP telemetry for every match (Block, Log, or Redact).
                    if let Some(sink) = self.inner.dlp_telemetry.as_ref() {
                        sink.emit_dlp(v.to_dlp_event(destination));
                    }
                    v
                })
            })
        } else {
            None
        };
        if let Some(v) = &dlp_verdict
            && v.is_block()
        {
            return v.to_swg_verdict(&ctx.host);
        }

        // 4. Categorise + apply deny list.
        //
        // The verdict's `category` field is canonicalised to
        // ASCII lowercase here rather than carried through with
        // whatever casing the categoriser returned. For the
        // in-process [`LocalCategoryDb`] this is a no-op — the
        // local install path already lowercases entries on swap
        // — but `UrlCategorizer` is a `pub` trait designed for
        // remote providers (Cisco Talos, custom HTTPS feed,
        // managed verdict service) that we cannot guarantee
        // return canonical-cased category strings. Without this
        // canonicalisation a remote provider that emits `"Adult"`
        // for one tenant and `"adult"` for another would feed
        // two distinct `category = '…'` rows into the operator
        // dashboards for what is logically one category,
        // splitting per-category counts and breaking the
        // deny-list audit trail that groups by category. Doing
        // the lowercase once here is symmetric with the
        // `LocalCategoryDb::install` canonicalisation and with
        // the case-folded lookup against the already-lowercased
        // [`CategoryDenyPolicy`] that follows.
        let category_canonical = self
            .inner
            .categorizer
            .categorize(&ctx.host, &ctx.path)
            .await
            .map(|c| c.0.to_ascii_lowercase());

        // 3c. RBI policy evaluation. Runs after categorisation
        //     (so the category and risk score are available for
        //     the trigger rules) and before the deny-list check —
        //     so an RBI trigger redirects the client to the
        //     isolation proxy instead of hitting the deny-list or
        //     proceeding to the upstream. A non-trigger leaves the
        //     pipeline unchanged. When no RBI engine is wired, or
        //     the proxy is not configured, this stage is a no-op.
        if let Some(rbi) = self.inner.rbi_engine.as_ref() {
            let risk = 0_u32; // TODO: wire risk score from categoriser when available
            if let Some((reason, url)) =
                rbi.evaluate(&ctx.host, category_canonical.as_deref(), risk)
            {
                return Verdict::redirect(
                    format!("rbi.{}", reason.as_str()),
                    url,
                );
            }
        }

        // 3d. AI-governance policy evaluation. Runs after RBI
        //     (so an RBI trigger on the same host wins over a
        //     governance redirect) and before the deny-list
        //     check — so a governance block on an AI-app
        //     destination denies even when the category is
        //     allowed. A Block action short-circuits to deny;
        //     a Redirect action short-circuits to redirect to
        //     the RBI proxy (using the RBI proxy base URL from
        //     the engine's config); Allow and Monitor pass
        //     through. When no AI-governance engine is wired,
        //     this stage is a no-op.
        if let Some(aig) = self.inner.ai_governance_engine.as_ref() {
            if let Some(gv) = aig.evaluate(&ctx.host, &ctx.path) {
                match gv.action {
                    crate::ai_governance::AiGovernanceAction::Block
                    | crate::ai_governance::AiGovernanceAction::Redirect => {
                        let rbi_url = self
                            .inner
                            .rbi_engine
                            .as_ref()
                            .and_then(|rbi| rbi.proxy_base_url());
                        return governance_to_verdict(&gv, rbi_url);
                    }
                    // Allow and Monitor: pass through. The
                    // governance verdict is recorded in
                    // telemetry via the reason on the final
                    // verdict — the pipeline continues.
                    crate::ai_governance::AiGovernanceAction::Allow
                    | crate::ai_governance::AiGovernanceAction::Monitor => {}
                }
            }
        }

        // The policy denies a category by an exact operator rule
        // *or* a dotted-subtree group rule (e.g. a `security` group
        // denies `security.malware`). The verdict still reports the
        // resolved category (not the rule), keeping the
        // `deny.<category>` telemetry contract stable whether the
        // block came from an exact or a group rule.
        if let Some(cat) = &category_canonical
            && self.inner.deny_policy.is_denied(cat)
        {
            return Verdict::deny_categorized(cat.clone());
        }

        // 5. Malware verdict on response body hash. Only kicks
        //    in when an upstream scanner has supplied a hash —
        //    a missing hash is *not* a deny signal.
        //
        //    `Suspicious` is the heuristic-only verdict: the
        //    provider matched a heuristic but is not confident
        //    enough to call the file Malicious. The variant doc
        //    contract is "treat as Clean by default; promote to
        //    Deny only under elevated-risk mode". Auto-denying
        //    on heuristic-only matches without operator opt-in
        //    causes false-positive blocks on legitimate
        //    downloads, which is why the default is
        //    conservative.
        if let Some(hash) = ctx.file_hash.as_deref() {
            match self.inner.malware.verdict(hash).await {
                MalwareVerdict::Malicious => {
                    return Verdict::deny_categorized("malware.detected");
                }
                MalwareVerdict::Suspicious if self.inner.elevated_risk_mode => {
                    return Verdict::deny_categorized("malware.suspicious");
                }
                MalwareVerdict::Suspicious | MalwareVerdict::Clean | MalwareVerdict::Unknown => {}
            }
        }

        // 6. YARA content scan on the response body. Runs only when
        //    an engine is wired AND Envoy forwarded a body, and
        //    only after the hash check above — so a known-bad hash
        //    short-circuits to Deny without paying for a scan, and
        //    the scan adds signature coverage for files the hash
        //    list has not seen. The scan itself is pure
        //    (immutable rule snapshot, no I/O) and fails open on a
        //    scanner error, so a YARA fault degrades to the same
        //    coverage the pipeline had before this stage rather
        //    than wedging the verdict.
        //
        //    Severity mirrors the hash provider's two-tier gate:
        //    a `Malicious` rule denies unconditionally; a
        //    `Suspicious` rule denies only under elevated-risk
        //    mode (heuristic-only matches must not false-positive
        //    block legitimate downloads by default). The category
        //    carries the matching family so the malware dashboard
        //    can group YARA hits the same way it groups hash hits.
        if let (Some(engine), Some(body)) = (self.inner.yara.as_ref(), scan_body)
            && let Some(m) = engine.worst_match(body)
        {
            let family = m.family.as_deref().unwrap_or(&m.rule);
            match m.severity {
                YaraSeverity::Malicious => {
                    return Verdict::deny_categorized(format!("malware.yara.{family}"));
                }
                YaraSeverity::Suspicious if self.inner.elevated_risk_mode => {
                    return Verdict::deny_categorized(format!("malware.yara.suspicious.{family}"));
                }
                YaraSeverity::Suspicious => {}
            }
        }

        // 7. Streaming content scan (ClamAV INSTREAM) on the response
        //    body. Runs only when a scanner is wired AND Envoy
        //    forwarded a body, and last in the malware chain — after
        //    the in-memory hash check and the in-process YARA scan —
        //    because it is the most expensive stage (a round-trip to
        //    the `clamd` daemon). Ordering the cheap, local checks
        //    first means a known-bad hash or a YARA signature hit
        //    denies without ever paying for the daemon call.
        //
        //    The scanner owns its fail posture: a scan error / timeout
        //    is resolved inside the scanner to either a fail-open
        //    `Clean` (allow) or a fail-closed `Malicious` carrying the
        //    `scanner.unavailable` sentinel (deny), so this stage never
        //    sees a raw error and the open/closed decision lives in
        //    exactly one place. `Clean` and `Skipped` (empty / oversize
        //    body) are passthroughs.
        //
        //    We pass `None` for the precomputed hash rather than
        //    `ctx.file_hash`: `body_sha256` is the *request*-body hash
        //    the malware stage consumes and is not guaranteed to be the
        //    SHA-256 of the (response) bytes scanned here, so handing it
        //    in as the cache key could mis-key the scanner's
        //    content-verdict cache. Letting the scanner hash the bytes
        //    it actually inspects keeps the cache correct; the second
        //    hash is cheap next to the socket round-trip it guards.
        if let (Some(scanner), Some(body)) = (self.inner.content_scanner.as_ref(), scan_body)
            && let ContentScanVerdict::Malicious { signature } = scanner.scan(body, None).await
        {
            return Verdict::deny_categorized(format!("malware.content.{signature}"));
        }

        // Allow path. A carried-forward CASB `log` / `allow`
        // verdict wins over the categoriser's allow: it is the
        // higher-signal decision (a specific SaaS action the
        // operator asked to log or explicitly allow) and it carries
        // the `casb.<app>.<action>` category the DLP / CASB
        // dashboards group on. Falling through to the categoriser
        // allow would drop that signal. When no CASB verdict was
        // produced, behaviour is identical to the pre-CASB pipeline.
        // A carried-forward DLP `Log` or `Redact` verdict wins
        // over a plain categoriser allow: it is the higher-signal
        // decision (specific DLP finding the operator asked to log)
        // and carries the `dlp.inline.log.<destination>` reason the
        // DLP dashboards group on. When no DLP verdict was produced,
        // behaviour is identical to the pre-DLP pipeline.
        if let Some(v) = &dlp_verdict {
            return v.to_swg_verdict(&ctx.host);
        }
        if let Some(v) = casb_verdict {
            return v;
        }
        match category_canonical {
            // Use the canonicalised category for the allow path
            // too — same rationale as the deny path above: the
            // verdict's `category` field is operator-facing
            // telemetry and must carry one canonical form per
            // logical category regardless of which provider
            // returned it.
            Some(cat) => Verdict::allow_categorized(cat),
            None => Verdict::allow_uncategorized(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bypass::{BypassEntry, BypassList};
    use crate::categorizer::{Category, CategoryEntry, LocalCategoryDb};
    use crate::dlp_inline::{DlpRegexRule, DlpInlineAction, DlpInlinePolicyDef};
    use crate::malware::{NullMalwareProvider, StaticMalwareList};
    use crate::rate_limit::{RateLimiter, TestClock};
    use crate::ai_governance::{
        AiGovernanceAction, AiGovernanceEngine, AiGovernancePolicy, AiGovernanceRule,
    };
    use crate::telemetry::{SwgEventSource, TelemetryEmitter, VerdictEvent};
    use parking_lot::Mutex;
    use pretty_assertions::assert_eq;
    use sng_core::events::DlpFindingKind;
    use sng_telemetry::EventSource;
    use std::time::Duration;

    #[derive(Debug, Default)]
    struct CapturingEmitter {
        events: Mutex<Vec<VerdictEvent>>,
    }
    impl TelemetryEmitter for CapturingEmitter {
        fn emit(&self, event: VerdictEvent) {
            self.events.lock().push(event);
        }
    }

    fn make_handler(deny: Vec<&str>) -> (ExtAuthzHandler, Arc<CapturingEmitter>) {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![BypassEntry {
            suffix: "bank.com".into(),
            category: "tls.finance".into(),
        }]));
        let cats = LocalCategoryDb::new(vec![
            CategoryEntry {
                host: "porn.example".into(),
                path_prefix: None,
                category: Category("adult".into()),
            },
            CategoryEntry {
                host: "biz.example".into(),
                path_prefix: None,
                category: Category("business.saas".into()),
            },
        ]);
        let mal = Arc::new(StaticMalwareList::new(vec![(
            "a".repeat(64),
            MalwareVerdict::Malicious,
        )]));
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(2.0, 1.0, clock);
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap.clone() as Arc<dyn TelemetryEmitter>)
            .with_deny_categories(deny.into_iter().map(Into::into).collect())
            .build()
            .unwrap();
        (h, cap)
    }

    /// Handler with a YARA engine wired (built-in rule set) and a
    /// generous rate-limit budget so multi-request tests don't trip
    /// the limiter. `elevated` toggles the elevated-risk posture
    /// that promotes a `suspicious` YARA match to Deny.
    fn make_yara_handler(elevated: bool) -> ExtAuthzHandler {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![]));
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "biz.example".into(),
            path_prefix: None,
            category: Category("business.saas".into()),
        }]);
        // Hash list flags this specific hash so we can assert the
        // hash check short-circuits before the YARA stage.
        let mal = Arc::new(StaticMalwareList::new(vec![(
            "a".repeat(64),
            MalwareVerdict::Malicious,
        )]));
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 1.0, clock);
        let yara = Arc::new(YaraEngine::with_builtin_rules().unwrap());
        ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap as Arc<dyn TelemetryEmitter>)
            .with_elevated_risk_mode(elevated)
            .with_yara_engine(yara)
            .build()
            .unwrap()
    }

    /// EICAR test string, assembled at runtime so this source file
    /// is not itself flagged by a host scanner.
    fn eicar_bytes() -> Vec<u8> {
        format!(
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}}${}!$H+H*",
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
        )
        .into_bytes()
    }

    /// Build a request carrying a base64-encoded response body for
    /// the YARA scan stage.
    fn req_with_body(host: &str, body: &[u8]) -> ExtAuthzRequest {
        let mut r = req(host, "/download", None, None);
        r.body_b64 = Some(base64::engine::general_purpose::STANDARD.encode(body));
        r
    }

    #[tokio::test]
    async fn yara_malicious_body_triggers_deny() {
        let h = make_yara_handler(false);
        let resp = h
            .handle_request(req_with_body("biz.example", &eicar_bytes()))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        assert_eq!(resp.category.as_deref(), Some("malware.yara.eicar"));
    }

    #[tokio::test]
    async fn yara_suspicious_body_allows_by_default() {
        // A bare ELF executable is `suspicious`, not `malicious`,
        // so the default posture allows it.
        let h = make_yara_handler(false);
        let elf = b"\x7fELF\x02\x01\x01\x00not-really-a-binary";
        let resp = h
            .handle_request(req_with_body("biz.example", elf))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn yara_suspicious_body_denies_under_elevated_risk() {
        let h = make_yara_handler(true);
        let elf = b"\x7fELF\x02\x01\x01\x00not-really-a-binary";
        let resp = h
            .handle_request(req_with_body("biz.example", elf))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(
            resp.category.as_deref(),
            Some("malware.yara.suspicious.elf")
        );
    }

    #[tokio::test]
    async fn yara_benign_body_allows() {
        let h = make_yara_handler(true);
        let resp = h
            .handle_request(req_with_body("biz.example", b"just a normal text file"))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn hash_deny_short_circuits_before_yara() {
        // The request carries BOTH a known-bad hash and a benign
        // body. The hash check (step 5) must win, proving YARA runs
        // strictly after — and the deny reason is the hash
        // category, not a YARA one.
        let h = make_yara_handler(false);
        let mut r = req_with_body("biz.example", b"benign content");
        r.body_sha256 = Some("a".repeat(64));
        let resp = h.handle_request(r).await.unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.category.as_deref(), Some("malware.detected"));
    }

    #[tokio::test]
    async fn malformed_body_b64_returns_400() {
        let h = make_yara_handler(false);
        let mut r = req("biz.example", "/download", None, None);
        r.body_b64 = Some("not valid base64 !!!".into());
        let body = serde_json::to_vec(&r).unwrap();
        let out = h.handle_json_bytes(&body).await;
        let resp: ExtAuthzResponse = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(400));
    }

    #[tokio::test]
    async fn yara_stage_skipped_when_no_engine_wired() {
        // The default make_handler has no YARA engine; a request
        // with an EICAR body is allowed (no content scan runs).
        let (h, _cap) = make_handler(vec![]);
        let resp = h
            .handle_request(req_with_body("biz.example", &eicar_bytes()))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    /// Test content scanner: records how many times it was asked to
    /// scan and returns a fixed verdict, so a test can assert both the
    /// verdict mapping and the decision-tree ordering (that the
    /// expensive scan stage is reached only when no cheaper stage
    /// already denied).
    #[derive(Debug)]
    struct RecordingScanner {
        verdict: ContentScanVerdict,
        calls: Mutex<usize>,
    }
    impl RecordingScanner {
        fn new(verdict: ContentScanVerdict) -> Self {
            Self {
                verdict,
                calls: Mutex::new(0),
            }
        }
        fn call_count(&self) -> usize {
            *self.calls.lock()
        }
    }
    #[async_trait::async_trait]
    impl ContentScanner for RecordingScanner {
        async fn scan(&self, _bytes: &[u8], _sha256_hex: Option<&str>) -> ContentScanVerdict {
            *self.calls.lock() += 1;
            self.verdict.clone()
        }
    }

    /// Handler wired with a [`RecordingScanner`] returning `verdict`,
    /// a generous rate-limit budget, and a hash list that flags
    /// `"a".repeat(64)` so ordering-vs-hash tests can be expressed.
    fn make_scanner_handler(
        verdict: ContentScanVerdict,
    ) -> (ExtAuthzHandler, Arc<RecordingScanner>) {
        let cap = Arc::new(CapturingEmitter::default());
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "biz.example".into(),
            path_prefix: None,
            category: Category("business.saas".into()),
        }]);
        let mal = Arc::new(StaticMalwareList::new(vec![(
            "a".repeat(64),
            MalwareVerdict::Malicious,
        )]));
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 1.0, clock);
        let scanner = Arc::new(RecordingScanner::new(verdict));
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(Arc::new(BypassList::new(vec![])))
            .with_rate_limiter(rl)
            .with_telemetry(cap as Arc<dyn TelemetryEmitter>)
            .with_content_scanner(Arc::clone(&scanner) as Arc<dyn ContentScanner>)
            .build()
            .unwrap();
        (h, scanner)
    }

    #[tokio::test]
    async fn content_scanner_malicious_body_triggers_deny() {
        let (h, scanner) = make_scanner_handler(ContentScanVerdict::Malicious {
            signature: "Eicar-Test-Signature".into(),
        });
        let resp = h
            .handle_request(req_with_body("biz.example", b"some download"))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        assert_eq!(
            resp.category.as_deref(),
            Some("malware.content.Eicar-Test-Signature")
        );
        assert_eq!(scanner.call_count(), 1);
    }

    #[tokio::test]
    async fn content_scanner_clean_body_allows() {
        let (h, scanner) = make_scanner_handler(ContentScanVerdict::Clean);
        let resp = h
            .handle_request(req_with_body("biz.example", b"clean bytes"))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(scanner.call_count(), 1);
    }

    #[tokio::test]
    async fn content_scanner_skipped_body_allows() {
        let (h, scanner) = make_scanner_handler(ContentScanVerdict::Skipped {
            reason: crate::malware::ScanSkip::Oversize,
        });
        let resp = h
            .handle_request(req_with_body("biz.example", b"oversize-ish"))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(scanner.call_count(), 1);
    }

    #[tokio::test]
    async fn content_scanner_fail_closed_denies_with_sentinel() {
        // The scanner resolves a backend failure to its fail-closed
        // sentinel; the handler denies and the category carries the
        // sentinel so the dashboard can tell it apart from a real hit.
        let (h, _s) = make_scanner_handler(ContentScanVerdict::scanner_unavailable());
        let resp = h
            .handle_request(req_with_body("biz.example", b"x"))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(
            resp.category.as_deref(),
            Some("malware.content.scanner.unavailable")
        );
    }

    #[tokio::test]
    async fn content_scanner_not_invoked_without_body() {
        // No body forwarded → the scan stage is skipped entirely, the
        // same passthrough a missing file hash gets at the hash stage.
        let (h, scanner) = make_scanner_handler(ContentScanVerdict::Malicious {
            signature: "should-not-run".into(),
        });
        let resp = h
            .handle_request(req("biz.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(scanner.call_count(), 0);
    }

    #[tokio::test]
    async fn hash_deny_short_circuits_before_content_scanner() {
        // Known-bad hash + benign body + a scanner that WOULD deny.
        // The hash check (step 5) must win and the scanner must never
        // run — proving the daemon round-trip is paid only for content
        // the cheaper hash check did not already flag.
        let (h, scanner) = make_scanner_handler(ContentScanVerdict::Malicious {
            signature: "should-not-run".into(),
        });
        let mut r = req_with_body("biz.example", b"benign content");
        r.body_sha256 = Some("a".repeat(64));
        let resp = h.handle_request(r).await.unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.category.as_deref(), Some("malware.detected"));
        assert_eq!(scanner.call_count(), 0);
    }

    #[tokio::test]
    async fn yara_deny_short_circuits_before_content_scanner() {
        // Both a YARA engine and a content scanner are wired. An EICAR
        // body trips YARA (step 6); the content scanner (step 7) must
        // not run, proving the cheaper in-process scan denies before
        // the daemon round-trip.
        let scanner = Arc::new(RecordingScanner::new(ContentScanVerdict::Clean));
        let cap = Arc::new(CapturingEmitter::default());
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "biz.example".into(),
            path_prefix: None,
            category: Category("business.saas".into()),
        }]);
        let clock = Arc::new(TestClock::new());
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(Arc::new(NullMalwareProvider))
            .with_bypass(Arc::new(BypassList::new(vec![])))
            .with_rate_limiter(RateLimiter::new(100.0, 1.0, clock))
            .with_telemetry(cap as Arc<dyn TelemetryEmitter>)
            .with_yara_engine(Arc::new(YaraEngine::with_builtin_rules().unwrap()))
            .with_content_scanner(Arc::clone(&scanner) as Arc<dyn ContentScanner>)
            .build()
            .unwrap();
        let resp = h
            .handle_request(req_with_body("biz.example", &eicar_bytes()))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.category.as_deref(), Some("malware.yara.eicar"));
        assert_eq!(scanner.call_count(), 0);
    }

    fn req(host: &str, path: &str, sni: Option<&str>, file_hash: Option<&str>) -> ExtAuthzRequest {
        let mut headers = vec![
            (":method".into(), "GET".into()),
            (":scheme".into(), "https".into()),
            (":path".into(), path.into()),
            ("host".into(), host.into()),
            ("x-sng-tenant".into(), "tenant-1".into()),
            ("x-sng-principal".into(), "principal-1".into()),
        ];
        if let Some(s) = sni {
            headers.push(("x-sng-sni".into(), s.into()));
        }
        ExtAuthzRequest {
            headers,
            body_sha256: file_hash.map(Into::into),
            body_b64: None,
        }
    }

    #[tokio::test]
    async fn allow_default_when_uncategorized() {
        let (h, cap) = make_handler(vec![]);
        let resp = h
            .handle_request(req("unknown.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert!(resp.status.is_none());
        assert!(resp.reason.starts_with("allow"));
        assert_eq!(cap.events.lock().len(), 1);
    }

    #[tokio::test]
    async fn allow_categorised_when_category_not_in_deny_list() {
        let (h, _cap) = make_handler(vec![]);
        let resp = h
            .handle_request(req("biz.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(resp.category.as_deref(), Some("business.saas"));
    }

    #[tokio::test]
    async fn deny_when_category_matches_operator_deny_list() {
        let (h, _cap) = make_handler(vec!["adult"]);
        let resp = h
            .handle_request(req("porn.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        assert_eq!(resp.category.as_deref(), Some("adult"));
    }

    #[tokio::test]
    async fn bypass_short_circuits_before_categorization() {
        let (h, _cap) = make_handler(vec!["adult"]);
        // SNI matches bank.com → bypass; even though host
        // matches a deny-list category, the bypass wins.
        let resp = h
            .handle_request(req("porn.example", "/", Some("online.bank.com"), None))
            .await
            .unwrap();
        assert_eq!(resp.action, "bypass");
        assert!(resp.reason.contains("bypass"));
    }

    #[tokio::test]
    async fn malware_verdict_triggers_deny() {
        let (h, _cap) = make_handler(vec![]);
        let hash = "a".repeat(64);
        let resp = h
            .handle_request(req("biz.example", "/", None, Some(&hash)))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.category.as_deref(), Some("malware.detected"));
    }

    #[tokio::test]
    async fn unknown_malware_verdict_does_not_change_decision() {
        let (h, _cap) = make_handler(vec![]);
        let resp = h
            .handle_request(req("biz.example", "/", None, Some("9".repeat(64).as_str())))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn rate_limit_kicks_in_after_capacity_exhausted() {
        let (h, _cap) = make_handler(vec![]);
        for _ in 0..2 {
            let r = h
                .handle_request(req("biz.example", "/", None, None))
                .await
                .unwrap();
            assert_eq!(r.action, "allow");
        }
        let r = h
            .handle_request(req("biz.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(r.action, "rate_limit");
        assert_eq!(r.status, Some(429));
    }

    #[tokio::test]
    async fn rate_limit_response_carries_retry_after_secs_from_limiter() {
        // Regression test for the ext-authz contract: the rate
        // limiter computes a `retry_after_secs` value the
        // moment a bucket is exhausted, and that value MUST
        // reach Envoy on the wire so it can stamp a
        // `Retry-After` header on the 429. Previously
        // `Verdict::rate_limit` dropped the value on the floor
        // and `ExtAuthzResponse::from_verdict` unconditionally
        // emitted `retry_after_secs: None`, defeating the
        // computed timing. This test pins the propagation:
        //   limiter -> Verdict::retry_after_secs
        //          -> ExtAuthzResponse::retry_after_secs
        //          -> serialised JSON Envoy reads
        let (h, _cap) = make_handler(vec![]);
        // Exhaust the bucket.
        for _ in 0..2 {
            let _ = h
                .handle_request(req("biz.example", "/", None, None))
                .await
                .unwrap();
        }
        // First rejection: surfaced on the typed response.
        let r = h
            .handle_request(req("biz.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(r.action, "rate_limit");
        assert_eq!(r.status, Some(429));
        let retry = r.retry_after_secs.expect(
            "rate_limit responses MUST carry retry_after_secs \
             so Envoy can stamp it onto the Retry-After header",
        );
        assert!(
            retry >= 1,
            "limiter promises retry_after >= 1 on rejection; got {retry}"
        );

        // Round-trip via the JSON byte path Envoy actually
        // calls, to pin the wire shape. `handle_json_bytes` is
        // what an HTTP listener wraps in production.
        // Use the same `(tenant, principal)` bucket key as the
        // exhaustion loop above (the helper `req()` defaults
        // both to `tenant-1` / `principal-1`); otherwise the
        // limiter sees a fresh bucket and would permit the
        // request, leaving the wire-shape assertion untested.
        let body = serde_json::to_vec(&ExtAuthzRequest {
            headers: vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/".into()),
                ("host".into(), "biz.example".into()),
                ("x-sng-tenant".into(), "tenant-1".into()),
                ("x-sng-principal".into(), "principal-1".into()),
            ],
            body_sha256: None,
            body_b64: None,
        })
        .unwrap();
        let raw = h.handle_json_bytes(&body).await;
        let on_wire: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(on_wire["action"], "rate_limit");
        assert_eq!(on_wire["status"], 429);
        assert!(
            on_wire["retry_after_secs"].is_u64(),
            "wire shape MUST include retry_after_secs as an unsigned integer; \
             got {raw:?}",
            raw = String::from_utf8_lossy(&raw)
        );
        assert!(on_wire["retry_after_secs"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn from_verdict_drops_retry_after_secs_on_non_rate_limit_actions() {
        // Defence-in-depth: even if a future caller sets
        // `Verdict::retry_after_secs = Some(...)` on a non-
        // rate-limit verdict by mistake, the wire encoder must
        // not leak it onto allow / deny / bypass responses.
        // The serde field is `skip_serializing_if = "is_none"`
        // so emitting `None` here is the contract.
        let allow = ExtAuthzResponse::from_verdict(&Verdict::allow_uncategorized());
        assert_eq!(allow.retry_after_secs, None);
        let bypass = ExtAuthzResponse::from_verdict(&Verdict::bypass("bypass.tls.healthcare"));
        assert_eq!(bypass.retry_after_secs, None);
        let deny = ExtAuthzResponse::from_verdict(&Verdict::deny("deny.malware.sha256"));
        assert_eq!(deny.retry_after_secs, None);
        let rate = ExtAuthzResponse::from_verdict(&Verdict::rate_limit("rate_limit.tenant", 45));
        assert_eq!(rate.retry_after_secs, Some(45));
    }

    #[tokio::test]
    async fn missing_required_header_returns_400_via_handle_json_bytes() {
        let (h, _cap) = make_handler(vec![]);
        // Build an envelope missing x-sng-tenant.
        let bad = serde_json::to_vec(&ExtAuthzRequest {
            headers: vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/".into()),
                ("host".into(), "biz.example".into()),
                ("x-sng-principal".into(), "p".into()),
            ],
            body_sha256: None,
            body_b64: None,
        })
        .unwrap();
        let out = h.handle_json_bytes(&bad).await;
        let resp: ExtAuthzResponse = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(400));
        assert!(resp.reason.contains("x-sng-tenant"));
    }

    #[tokio::test]
    async fn malformed_json_returns_400_with_decode_message() {
        let (h, _cap) = make_handler(vec![]);
        let out = h.handle_json_bytes(b"{not json").await;
        let resp: ExtAuthzResponse = serde_json::from_slice(&out).unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(400));
        assert!(resp.reason.contains("malformed"));
    }

    #[tokio::test]
    async fn install_bypass_atomically_swaps_table() {
        let (h, _cap) = make_handler(vec![]);
        let r = h
            .handle_request(req("biz.example", "/", Some("foo.com"), None))
            .await
            .unwrap();
        assert_eq!(r.action, "allow");
        h.install_bypass(Arc::new(BypassList::new(vec![BypassEntry {
            suffix: "foo.com".into(),
            category: "tls.dev".into(),
        }])));
        let r = h
            .handle_request(req("biz.example", "/", Some("foo.com"), None))
            .await
            .unwrap();
        assert_eq!(r.action, "bypass");
    }

    #[test]
    fn ext_authz_request_into_context_normalizes_lowercase_fields() {
        let r = ExtAuthzRequest {
            headers: vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "HTTPS".into()),
                (":path".into(), "/abc".into()),
                ("HOST".into(), "Example.COM".into()),
                ("x-sng-tenant".into(), "t".into()),
                ("x-sng-principal".into(), "p".into()),
                ("x-sng-sni".into(), "EXAMPLE.com".into()),
            ],
            body_sha256: None,
            body_b64: None,
        };
        let ctx = r.into_context().unwrap();
        assert_eq!(ctx.method, "get");
        assert_eq!(ctx.scheme, "https");
        assert_eq!(ctx.host, "example.com");
        assert_eq!(ctx.path, "/abc");
        assert_eq!(ctx.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn ext_authz_request_into_context_strips_query_from_path() {
        // HTTP/2's `:path` pseudo-header includes the query, but
        // the `RequestContext::path` field is documented as
        // query-free. The decoder must therefore strip the query
        // before downstream code (categoriser, telemetry, verdict
        // dashboards) sees it — otherwise session tokens, OAuth
        // state, OTP material, and other PII-shaped query
        // parameters surface in the wire-level verdict events.
        let r = ExtAuthzRequest {
            headers: vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (
                    ":path".into(),
                    "/oauth/callback?code=secret123&state=xyz".into(),
                ),
                ("host".into(), "bank.example".into()),
                ("x-sng-tenant".into(), "t".into()),
                ("x-sng-principal".into(), "p".into()),
            ],
            body_sha256: None,
            body_b64: None,
        };
        let ctx = r.into_context().unwrap();
        assert_eq!(ctx.path, "/oauth/callback");
    }

    #[test]
    fn ext_authz_request_into_context_treats_empty_header_as_missing() {
        // An empty header value satisfies the "required header"
        // check syntactically but carries no information — the
        // operator's intent is unambiguous: this is a missing
        // header. The decoder must reject it instead of
        // silently using an empty tenant id.
        let r = ExtAuthzRequest {
            headers: vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/".into()),
                ("host".into(), "h".into()),
                ("x-sng-tenant".into(), String::new()),
                ("x-sng-principal".into(), "p".into()),
            ],
            body_sha256: None,
            body_b64: None,
        };
        let err = r.into_context().expect_err("must reject empty tenant");
        match err {
            SwgError::ExtAuthzDecode(msg) => assert!(msg.contains("x-sng-tenant"), "{msg}"),
            other => panic!("expected ExtAuthzDecode, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn handler_emits_one_verdict_event_per_request() {
        let (h, cap) = make_handler(vec![]);
        for _ in 0..3 {
            h.handle_request(req("biz.example", "/", None, None))
                .await
                .unwrap();
        }
        assert_eq!(cap.events.lock().len(), 3);
    }

    #[tokio::test]
    async fn telemetry_sink_receives_swg_event_source_events() {
        // Smoke-test that a real SwgEventSource sink wires up
        // and the handler emits decodable events through it.
        let (sink, mut source) = SwgEventSource::channel(8);
        let cap = Arc::new(sink) as Arc<dyn TelemetryEmitter>;
        let bypass = Arc::new(BypassList::new(vec![]));
        let cats = LocalCategoryDb::new(vec![]);
        let mal = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(RateLimiter::new(100.0, 100.0, clock))
            .with_telemetry(cap)
            .build()
            .unwrap();
        h.handle_request(req("any.example", "/x", None, None))
            .await
            .unwrap();
        // The channel sink fed the source — receive one event.
        // tokio::time::timeout guards against a hang.
        let got = tokio::time::timeout(Duration::from_millis(100), source.recv()).await;
        assert!(got.unwrap().is_some());
    }

    #[test]
    fn ext_authz_response_serializes_with_stable_field_order() {
        let v = Verdict::deny_categorized("adult");
        let resp = ExtAuthzResponse::from_verdict(&v);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"action\":\"deny\""));
        assert!(json.contains("\"status\":403"));
        assert!(json.contains("\"category\":\"adult\""));
    }

    #[test]
    fn ext_authz_response_omits_none_fields_on_allow() {
        let v = Verdict::allow_uncategorized();
        let resp = ExtAuthzResponse::from_verdict(&v);
        let json = serde_json::to_string(&resp).unwrap();
        assert!(!json.contains("status"), "{json}");
        assert!(!json.contains("retry_after"), "{json}");
        assert!(!json.contains("category"), "{json}");
    }

    /// Mock categoriser that returns whatever category casing was
    /// preconfigured, mimicking a remote provider that surfaces
    /// non-canonical (e.g. `"Adult"`) category strings. The
    /// in-process `LocalCategoryDb` already lowercases on install,
    /// so a regression test for the handler-side canonicalisation
    /// needs a categoriser whose return value is *not* run through
    /// the local install path.
    #[derive(Debug)]
    struct MixedCaseRemoteCategorizer {
        category: Option<Category>,
    }
    #[async_trait::async_trait]
    impl UrlCategorizer for MixedCaseRemoteCategorizer {
        async fn categorize(&self, _host: &str, _path: &str) -> Option<Category> {
            self.category.clone()
        }
    }

    fn make_handler_with_categorizer(
        cats: Arc<dyn UrlCategorizer>,
        deny: Vec<&str>,
    ) -> (ExtAuthzHandler, Arc<CapturingEmitter>) {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(Vec::new()));
        let mal: Arc<dyn MalwareVerdictProvider> = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 50.0, clock);
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(cats)
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap.clone() as Arc<dyn TelemetryEmitter>)
            .with_deny_categories(deny.into_iter().map(Into::into).collect())
            .build()
            .unwrap();
        (h, cap)
    }

    #[tokio::test]
    async fn deny_verdict_carries_canonical_lowercase_category_from_mixed_case_provider() {
        // Regression: a future remote provider could return a
        // category in non-canonical casing (`"Adult"` rather than
        // `"adult"`). The verdict's `category` field is
        // operator-facing telemetry and must collapse to one
        // canonical row per logical category regardless of which
        // provider returned it, or the per-category counts on
        // operator dashboards split into two rows for what is
        // semantically one category. Pin: the deny verdict's
        // category field is lowercased exactly once, at the
        // handler boundary, so the local-DB and remote-provider
        // paths produce identical verdict telemetry.
        let mixed = Arc::new(MixedCaseRemoteCategorizer {
            category: Some(Category("Adult".into())),
        });
        let (h, cap) = make_handler_with_categorizer(mixed, vec!["adult"]);
        let resp = h
            .handle_request(req("evil.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(
            resp.category.as_deref(),
            Some("adult"),
            "verdict category must be canonical lowercase, got: {resp:?}",
        );
        let events = cap.events.lock();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].swg_verdict.category.as_deref(),
            Some("adult"),
            "telemetry event category must be canonical lowercase, got: {:?}",
            events[0],
        );
    }

    #[tokio::test]
    async fn allow_verdict_carries_canonical_lowercase_category_from_mixed_case_provider() {
        // Same canonicalisation invariant on the *allow* path —
        // a non-denied category emitted by a remote provider in
        // mixed case must still surface as canonical lowercase on
        // the verdict so dashboards group it with the matching
        // local-DB entries.
        let mixed = Arc::new(MixedCaseRemoteCategorizer {
            category: Some(Category("Business.SaaS".into())),
        });
        let (h, cap) = make_handler_with_categorizer(mixed, vec![]);
        let resp = h
            .handle_request(req("ok.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(
            resp.category.as_deref(),
            Some("business.saas"),
            "verdict category must be canonical lowercase, got: {resp:?}",
        );
        let events = cap.events.lock();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].swg_verdict.category.as_deref(),
            Some("business.saas"),
            "telemetry event category must be canonical lowercase, got: {:?}",
            events[0],
        );
    }

    // --- CategoryDenyPolicy wiring (exact + group) --------------

    /// Build a handler whose categoriser always returns `category`
    /// and whose deny decision is governed by a full
    /// [`CategoryDenyPolicy`]. Lets a test prove a *group* rule
    /// denies a resolved subtree category end-to-end through the
    /// handler — the capability `with_deny_categories` (exact only)
    /// could not exercise.
    fn make_handler_with_policy(
        category: &str,
        policy: CategoryDenyPolicy,
    ) -> (ExtAuthzHandler, Arc<CapturingEmitter>) {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(Vec::new()));
        let mal: Arc<dyn MalwareVerdictProvider> = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 50.0, clock);
        let cats = Arc::new(MixedCaseRemoteCategorizer {
            category: Some(Category(category.into())),
        });
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(cats)
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap.clone() as Arc<dyn TelemetryEmitter>)
            .with_deny_policy(policy)
            .build()
            .unwrap();
        (h, cap)
    }

    #[tokio::test]
    async fn group_deny_rule_blocks_whole_subtree_through_handler() {
        // The Goal-B capability: an operator enables the `security`
        // group and every resolved `security.*` leaf is denied,
        // with no per-leaf enumeration. Proves the handler consults
        // the group rules, not just the exact set the old
        // `Vec<String>` + binary_search supported.
        let policy = CategoryDenyPolicy::empty().with_groups(vec!["security".into()]);
        let (h, _cap) = make_handler_with_policy("security.malware", policy);
        let resp = h
            .handle_request(req("threat.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        // The verdict reports the *resolved* category (the leaf),
        // not the group rule, so the `deny.<category>` telemetry
        // contract is unchanged whether an exact or group rule fired.
        assert_eq!(resp.category.as_deref(), Some("security.malware"));
        assert_eq!(resp.reason, "deny.security.malware");
    }

    #[tokio::test]
    async fn safe_browsing_defaults_deny_security_leaf_through_handler() {
        // Wiring the SME-friendly baseline (deny the whole
        // safe-browsing `security.*` subtree) blocks a phishing
        // category end-to-end.
        let (h, _cap) = make_handler_with_policy(
            "security.phishing",
            CategoryDenyPolicy::safe_browsing_defaults(),
        );
        let resp = h
            .handle_request(req("phish.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.category.as_deref(), Some("security.phishing"));
    }

    #[tokio::test]
    async fn group_deny_respects_segment_boundary_through_handler() {
        // Segment-boundary safety end-to-end: a `security` group
        // must NOT deny a sibling category that merely shares a
        // prefix (`securityawareness`), only genuine `security.*`
        // children. A false match here would over-block legitimate
        // traffic for 5000 tenants.
        let policy = CategoryDenyPolicy::empty().with_groups(vec!["security".into()]);
        let (h, _cap) = make_handler_with_policy("securityawareness", policy);
        let resp = h
            .handle_request(req("training.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(resp.category.as_deref(), Some("securityawareness"));
    }

    #[tokio::test]
    async fn exact_and_group_rules_compose_through_handler() {
        // Exact and group rules coexist on one handler: the exact
        // `gambling` rule and the `security` group both deny, while
        // an unrelated category is allowed. Confirms
        // `with_deny_categories` (exact) and `with_deny_groups`
        // accumulate rather than overwrite.
        let policy = CategoryDenyPolicy::empty()
            .with_exact(vec!["gambling".into()])
            .with_groups(vec!["security".into()]);
        let (deny_exact, _c1) = make_handler_with_policy("gambling", policy.clone());
        assert_eq!(
            deny_exact
                .handle_request(req("bet.example", "/", None, None))
                .await
                .unwrap()
                .action,
            "deny",
        );
        let (deny_group, _c2) = make_handler_with_policy("security.botnet", policy.clone());
        assert_eq!(
            deny_group
                .handle_request(req("bot.example", "/", None, None))
                .await
                .unwrap()
                .action,
            "deny",
        );
        let (allow_other, _c3) = make_handler_with_policy("business.saas", policy);
        assert_eq!(
            allow_other
                .handle_request(req("ok.example", "/", None, None))
                .await
                .unwrap()
                .action,
            "allow",
        );
    }

    /// Build a handler whose deny policy comes from an operator
    /// [`CategoryDenyConfig`] via [`ExtAuthzHandlerBuilder::with_deny_config`],
    /// exercising the config-plane path end-to-end.
    fn make_handler_with_config(
        category: &str,
        config: CategoryDenyConfig,
    ) -> (ExtAuthzHandler, Arc<CapturingEmitter>) {
        let cap = Arc::new(CapturingEmitter::default());
        let mal: Arc<dyn MalwareVerdictProvider> = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let cats = Arc::new(MixedCaseRemoteCategorizer {
            category: Some(Category(category.into())),
        });
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(cats)
            .with_malware(mal)
            .with_bypass(Arc::new(BypassList::new(Vec::new())))
            .with_rate_limiter(RateLimiter::new(100.0, 50.0, clock))
            .with_telemetry(cap.clone() as Arc<dyn TelemetryEmitter>)
            .with_deny_config(config)
            .build()
            .unwrap();
        (h, cap)
    }

    #[tokio::test]
    async fn deny_config_drives_handler_deny_end_to_end() {
        // The config-plane entry point: an operator bundle enables the
        // safe-browsing baseline and adds a `gambling` exact rule. Both
        // the baseline subtree and the operator rule must deny through
        // the live handler, while an unrelated category is allowed —
        // proving with_deny_config compiles the config into the policy
        // the evaluate path consults.
        let config = CategoryDenyConfig {
            exact: vec!["gambling".into()],
            groups: Vec::new(),
            safe_browsing_defaults: true,
        };

        let (deny_baseline, _c1) = make_handler_with_config("security.phishing", config.clone());
        assert_eq!(
            deny_baseline
                .handle_request(req("phish.example", "/", None, None))
                .await
                .unwrap()
                .action,
            "deny",
        );

        let (deny_exact, _c2) = make_handler_with_config("gambling", config.clone());
        assert_eq!(
            deny_exact
                .handle_request(req("bet.example", "/", None, None))
                .await
                .unwrap()
                .action,
            "deny",
        );

        let (allow_other, _c3) = make_handler_with_config("business.saas", config);
        assert_eq!(
            allow_other
                .handle_request(req("ok.example", "/", None, None))
                .await
                .unwrap()
                .action,
            "allow",
        );
    }

    #[tokio::test]
    async fn missing_required_dependency_in_builder_returns_config_error() {
        // Forgetting to wire a trait is a wiring bug; the
        // builder must fail loudly instead of silently
        // building a handler that panics on the first
        // request.
        let err = ExtAuthzHandlerBuilder::new()
            .build()
            .expect_err("must fail");
        match err {
            SwgError::Config(msg) => assert!(msg.contains("categorizer"), "{msg}"),
            other => panic!("expected Config, got {other:?}"),
        }
    }

    // --- Inline CASB wiring -------------------------------------

    use crate::casb::InlineCasbInspector;
    use crate::casb_rules::{CasbAction, CasbConditions, CasbRule, CasbRuleSet, CasbVerdict};

    fn casb_rule(app: &str, action: CasbAction, verdict: CasbVerdict) -> CasbRule {
        CasbRule {
            id: format!("{app}-{}", action.as_str()),
            app_id: app.to_string(),
            action,
            verdict,
            conditions: CasbConditions::default(),
            priority: 0,
        }
    }

    /// Build a handler with an inline-CASB inspector wired and the
    /// given rule set installed. Generous rate-limit budget so the
    /// CASB behaviour under test is not masked by throttling.
    fn make_casb_handler(rules: Vec<CasbRule>) -> (ExtAuthzHandler, Arc<CapturingEmitter>) {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![]));
        // Categorise graph.microsoft.com so we can prove a CASB
        // log/allow verdict wins over the plain categoriser allow.
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "graph.microsoft.com".into(),
            path_prefix: None,
            category: Category("business.saas".into()),
        }]);
        let mal = Arc::new(StaticMalwareList::new(vec![(
            "a".repeat(64),
            MalwareVerdict::Malicious,
        )]));
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(1000.0, 1000.0, clock);
        let inspector = Arc::new(InlineCasbInspector::with_rules(CasbRuleSet::new(rules)));
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap.clone() as Arc<dyn TelemetryEmitter>)
            .with_casb_inspector(inspector)
            .build()
            .unwrap();
        (h, cap)
    }

    /// An M365 OneDrive upload via Graph: `PUT /v1.0/me/drive/items/{id}/content`.
    fn m365_upload_req(size: Option<u64>, label: Option<&str>) -> ExtAuthzRequest {
        let mut headers = vec![
            (":method".into(), "PUT".into()),
            (":scheme".into(), "https".into()),
            (":path".into(), "/v1.0/me/drive/items/01ABC/content".into()),
            ("host".into(), "graph.microsoft.com".into()),
            ("x-sng-tenant".into(), "tenant-1".into()),
            ("x-sng-principal".into(), "principal-1".into()),
        ];
        if let Some(s) = size {
            headers.push(("content-length".into(), s.to_string()));
        }
        if let Some(l) = label {
            headers.push((DLP_LABEL_HEADER.into(), l.into()));
        }
        ExtAuthzRequest {
            headers,
            body_sha256: None,
            body_b64: None,
        }
    }

    #[test]
    fn signals_parses_content_length_and_label() {
        let s = m365_upload_req(Some(4096), Some("confidential")).signals();
        assert_eq!(s.content_length, Some(4096));
        assert_eq!(s.sensitivity_label.as_deref(), Some("confidential"));
        // Missing / unset → None (fail-open on size).
        let s2 = m365_upload_req(None, None).signals();
        assert_eq!(s2.content_length, None);
        assert_eq!(s2.sensitivity_label, None);
    }

    #[test]
    fn signals_ignores_non_numeric_content_length() {
        let mut r = m365_upload_req(None, None);
        r.headers
            .push(("content-length".into(), "not-a-number".into()));
        assert_eq!(r.signals().content_length, None);
    }

    #[tokio::test]
    async fn casb_block_rule_denies_upload() {
        let (h, cap) = make_casb_handler(vec![casb_rule(
            "m365",
            CasbAction::Upload,
            CasbVerdict::Block,
        )]);
        let resp = h.handle_request(m365_upload_req(None, None)).await.unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        assert_eq!(resp.category.as_deref(), Some("casb.m365.upload"));
        assert_eq!(cap.events.lock().len(), 1);
    }

    #[tokio::test]
    async fn casb_log_rule_allows_but_tags_and_wins_over_categoriser() {
        let (h, _cap) = make_casb_handler(vec![casb_rule(
            "m365",
            CasbAction::Upload,
            CasbVerdict::Log,
        )]);
        let resp = h.handle_request(m365_upload_req(None, None)).await.unwrap();
        assert_eq!(resp.action, "allow");
        assert!(resp.status.is_none());
        // The CASB log verdict's category wins over the
        // categoriser's "business.saas" so DLP dashboards see the
        // tagged SaaS action.
        assert_eq!(resp.category.as_deref(), Some("casb.m365.upload"));
        assert!(
            resp.reason.starts_with("log.casb.m365.upload"),
            "got: {resp:?}"
        );
    }

    #[tokio::test]
    async fn casb_block_short_circuits_before_categoriser_allow() {
        // A block rule on a host the categoriser would otherwise
        // allow must still deny — proves CASB runs ahead of the
        // categorise/allow stage.
        let (h, _cap) = make_casb_handler(vec![casb_rule(
            "m365",
            CasbAction::Upload,
            CasbVerdict::Block,
        )]);
        let resp = h.handle_request(m365_upload_req(None, None)).await.unwrap();
        assert_eq!(resp.action, "deny");
    }

    #[tokio::test]
    async fn casb_size_threshold_gates_block() {
        // Block uploads >= 10 MiB only.
        let mut rule = casb_rule("m365", CasbAction::Upload, CasbVerdict::Block);
        rule.conditions.size_threshold = Some(10 * 1024 * 1024);
        let (h, _cap) = make_casb_handler(vec![rule]);

        // Small upload: under threshold → allowed (no rule match).
        let small = h
            .handle_request(m365_upload_req(Some(1024), None))
            .await
            .unwrap();
        assert_eq!(small.action, "allow");

        // Large upload: over threshold → blocked.
        let large = h
            .handle_request(m365_upload_req(Some(20 * 1024 * 1024), None))
            .await
            .unwrap();
        assert_eq!(large.action, "deny");
    }

    #[tokio::test]
    async fn malware_deny_wins_over_casb_log() {
        // A CASB log verdict must not suppress a malware block: the
        // download is tagged for DLP *and* still denied when the
        // body hash is known-malicious.
        let (h, _cap) = make_casb_handler(vec![casb_rule(
            "m365",
            CasbAction::Download,
            CasbVerdict::Log,
        )]);
        let r = ExtAuthzRequest {
            headers: vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/v1.0/me/drive/items/01ABC/content".into()),
                ("host".into(), "graph.microsoft.com".into()),
                ("x-sng-tenant".into(), "tenant-1".into()),
                ("x-sng-principal".into(), "principal-1".into()),
            ],
            body_sha256: Some("a".repeat(64)),
            body_b64: None,
        };
        let resp = h.handle_request(r).await.unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.category.as_deref(), Some("malware.detected"));
    }

    #[tokio::test]
    async fn no_casb_rule_match_leaves_pipeline_unchanged() {
        // Inspector wired but no rule matches the action → behaves
        // exactly like the pre-CASB allow path (categoriser allow).
        let (h, _cap) = make_casb_handler(vec![casb_rule(
            "slack",
            CasbAction::Upload,
            CasbVerdict::Block,
        )]);
        let resp = h.handle_request(m365_upload_req(None, None)).await.unwrap();
        assert_eq!(resp.action, "allow");
        assert_eq!(resp.category.as_deref(), Some("business.saas"));
    }

    #[tokio::test]
    async fn install_casb_rules_hot_swaps_ruleset() {
        let (h, _cap) = make_casb_handler(vec![]);
        // No rules installed → upload allowed.
        let before = h.handle_request(m365_upload_req(None, None)).await.unwrap();
        assert_eq!(before.action, "allow");
        // Install a block rule, then the same request is denied.
        let n = h.install_casb_rules(&CasbRuleSet::new(vec![casb_rule(
            "m365",
            CasbAction::Upload,
            CasbVerdict::Block,
        )]));
        assert_eq!(n, 1);
        let after = h.handle_request(m365_upload_req(None, None)).await.unwrap();
        assert_eq!(after.action, "deny");
    }

    #[tokio::test]
    async fn install_casb_rules_is_noop_without_inspector() {
        // A handler built without an inspector must accept the
        // install call (returns 0) rather than panicking.
        let (h, _cap) = make_handler(vec![]);
        assert_eq!(
            h.install_casb_rules(&CasbRuleSet::new(vec![casb_rule(
                "m365",
                CasbAction::Upload,
                CasbVerdict::Block,
            )])),
            0
        );
    }

    // ─── Inline DLP integration tests ───

    /// A capturing DLP telemetry emitter for tests.
    #[derive(Debug, Default)]
    struct CapturingDlpEmitter {
        events: Mutex<Vec<sng_core::events::DlpEvent>>,
    }
    impl DlpTelemetryEmitter for CapturingDlpEmitter {
        fn emit_dlp(&self, event: sng_core::events::DlpEvent) {
            self.events.lock().push(event);
        }
    }

    /// Build a handler with a DLP engine wired (empty policy) and a
    /// capturing DLP telemetry emitter. The rate limiter is generous
    /// so multi-request tests don't trip it.
    fn make_dlp_handler() -> (
        ExtAuthzHandler,
        Arc<CapturingEmitter>,
        Arc<CapturingDlpEmitter>,
    ) {
        let cap = Arc::new(CapturingEmitter::default());
        let dlp_cap = Arc::new(CapturingDlpEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![]));
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "upload.example".into(),
            path_prefix: None,
            category: Category("business.saas".into()),
        }]);
        let mal = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 1.0, clock);
        let dlp_engine = Arc::new(DlpInlineEngine::new());
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap.clone() as Arc<dyn TelemetryEmitter>)
            .with_dlp_engine(dlp_engine)
            .with_dlp_telemetry(dlp_cap.clone() as Arc<dyn DlpTelemetryEmitter>)
            .with_deny_categories(Vec::new())
            .build()
            .unwrap();
        (h, cap, dlp_cap)
    }

    #[tokio::test]
    async fn dlp_block_denies_request() {
        let (h, _cap, dlp_cap) = make_dlp_handler();
        // Install a DLP policy that blocks SSNs.
        h.install_dlp_policy(&DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn_us".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        });
        let body = b"SSN: 123-45-6789";
        let req = req_with_body("upload.example", body);
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.action, "deny");
        // DLP telemetry was emitted.
        let dlp_events = dlp_cap.events.lock();
        assert_eq!(dlp_events.len(), 1);
        assert_eq!(dlp_events[0].action, sng_core::events::DlpAction::Block);
    }

    #[tokio::test]
    async fn dlp_log_allows_request_but_emits_telemetry() {
        let (h, _cap, dlp_cap) = make_dlp_handler();
        h.install_dlp_policy(&DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "email".into(),
                pattern: r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b".into(),
                action: DlpInlineAction::Log,
                severity: "low".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        });
        let body = b"Contact: alice@example.com";
        let req = req_with_body("upload.example", body);
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.action, "allow");
        // DLP telemetry was still emitted.
        let dlp_events = dlp_cap.events.lock();
        assert_eq!(dlp_events.len(), 1);
        assert_eq!(dlp_events[0].action, sng_core::events::DlpAction::Monitor);
    }

    #[tokio::test]
    async fn dlp_no_match_allows_and_no_telemetry() {
        let (h, _cap, dlp_cap) = make_dlp_handler();
        h.install_dlp_policy(&DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn_us".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        });
        let body = b"Clean content, no sensitive data.";
        let req = req_with_body("upload.example", body);
        let resp = h.handle_request(req).await.unwrap();
        assert_eq!(resp.action, "allow");
        // No DLP telemetry emitted.
        assert!(dlp_cap.events.lock().is_empty());
    }

    #[tokio::test]
    async fn dlp_no_engine_behaves_unchanged() {
        // A handler built without a DLP engine must behave identically
        // to the pre-DLP pipeline.
        let (h, _cap) = make_handler(vec![]);
        let body = b"SSN: 123-45-6789";
        let req = req_with_body("upload.example", body);
        let resp = h.handle_request(req).await.unwrap();
        // No DLP engine → no DLP verdict → normal allow.
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn dlp_install_policy_is_noop_without_engine() {
        let (h, _cap) = make_handler(vec![]);
        let (n_regex, n_fp) = h.install_dlp_policy(&DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn".into(),
                pattern: r"\d{3}-\d{2}-\d{4}".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        });
        assert_eq!(n_regex, 0);
        assert_eq!(n_fp, 0);
    }

    #[tokio::test]
    async fn dlp_hot_swap_replaces_rules() {
        let (h, _cap, _dlp_cap) = make_dlp_handler();
        // Install a blocking rule.
        h.install_dlp_policy(&DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        });
        let body = b"SSN: 123-45-6789";
        let req = req_with_body("upload.example", body);
        assert_eq!(h.handle_request(req).await.unwrap().action, "deny");

        // Hot-swap to empty policy → same request now allowed.
        h.install_dlp_policy(&DlpInlinePolicyDef::default());
        let req2 = req_with_body("upload.example", body);
        assert_eq!(h.handle_request(req2).await.unwrap().action, "allow");
    }

    // ---- RBI integration tests ----

    /// Build a handler with an RBI engine wired and a category DB
    /// that maps `casino.example` → `gambling` and `safe.example`
    /// → `business.saas`. Rate limiter is generous so multi-request
    /// tests don't trip.
    fn make_rbi_handler() -> ExtAuthzHandler {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![]));
        let cats = LocalCategoryDb::new(vec![
            CategoryEntry {
                host: "casino.example".into(),
                path_prefix: None,
                category: Category("gambling".into()),
            },
            CategoryEntry {
                host: "safe.example".into(),
                path_prefix: None,
                category: Category("business.saas".into()),
            },
        ]);
        let mal = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 1.0, clock);
        let rbi = Arc::new(RbiPolicyEngine::new(RbiProxyConfig {
            base_url: "https://rbi.test".into(),
        }));
        ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap as Arc<dyn TelemetryEmitter>)
            .with_rbi_engine(rbi)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn rbi_category_match_produces_redirect() {
        let h = make_rbi_handler();
        h.install_rbi_policy(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("casino.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "redirect");
        assert_eq!(resp.status, Some(302));
        assert!(resp.reason.starts_with("rbi."));
        assert!(resp.redirect_url.is_some());
        assert!(
            resp.redirect_url
                .as_ref()
                .unwrap()
                .starts_with("https://rbi.test/rbi/session/")
        );
    }

    #[tokio::test]
    async fn rbi_no_trigger_falls_through_to_allow() {
        let h = make_rbi_handler();
        h.install_rbi_policy(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("safe.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert!(resp.redirect_url.is_none());
    }

    #[tokio::test]
    async fn rbi_explicit_isolate_triggers_redirect() {
        let h = make_rbi_handler();
        h.install_rbi_policy(&RbiPolicyDef {
            explicit_isolate: vec!["evil.example".into()],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("evil.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "redirect");
        assert_eq!(resp.status, Some(302));
    }

    #[tokio::test]
    async fn rbi_explicit_bypass_overrides_category_match() {
        let h = make_rbi_handler();
        h.install_rbi_policy(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            explicit_bypass: vec!["casino.example".into()],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("casino.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
        assert!(resp.redirect_url.is_none());
    }

    #[tokio::test]
    async fn rbi_dlp_block_takes_precedence_over_redirect() {
        // DLP block (step 3b) runs before RBI (step 3c), so a DLP
        // block on the same host that RBI would match should deny,
        // not redirect.
        let cap = Arc::new(CapturingEmitter::default());
        let dlp_cap = Arc::new(CapturingDlpEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![]));
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "casino.example".into(),
            path_prefix: None,
            category: Category("gambling".into()),
        }]);
        let mal = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 1.0, clock);
        let dlp_engine = Arc::new(DlpInlineEngine::new());
        let rbi = Arc::new(RbiPolicyEngine::new(RbiProxyConfig {
            base_url: "https://rbi.test".into(),
        }));
        let h = ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap as Arc<dyn TelemetryEmitter>)
            .with_dlp_engine(dlp_engine)
            .with_dlp_telemetry(dlp_cap as Arc<dyn DlpTelemetryEmitter>)
            .with_rbi_engine(rbi)
            .build()
            .unwrap();
        // Install both a DLP block rule and an RBI category rule.
        h.install_dlp_policy(&DlpInlinePolicyDef {
            regex_rules: vec![DlpRegexRule {
                rule_id: "ssn".into(),
                pattern: r"\b\d{3}-\d{2}-\d{4}\b".into(),
                action: DlpInlineAction::Block,
                severity: "high".into(),
                finding_kind: DlpFindingKind::Pii,
            }],
            fingerprints: vec![],
            scan_ceiling_bytes: 0,
        });
        h.install_rbi_policy(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            ..Default::default()
        });
        // Request with a body that triggers DLP block on a gambling host.
        let body = b"SSN: 123-45-6789";
        let resp = h
            .handle_request(req_with_body("casino.example", body))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        assert!(resp.redirect_url.is_none());
    }

    #[tokio::test]
    async fn rbi_hot_swap_replaces_rules() {
        let h = make_rbi_handler();
        h.install_rbi_policy(&RbiPolicyDef {
            categories: vec!["gambling".into()],
            ..Default::default()
        });
        // Gambling host triggers redirect.
        let resp = h
            .handle_request(req("casino.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "redirect");

        // Hot-swap to empty policy → same host now allowed.
        h.install_rbi_policy(&RbiPolicyDef::default());
        let resp2 = h
            .handle_request(req("casino.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp2.action, "allow");
    }

    #[tokio::test]
    async fn rbi_uncategorised_isolate_triggers_on_unknown_host() {
        let h = make_rbi_handler();
        h.install_rbi_policy(&RbiPolicyDef {
            isolate_uncategorised: true,
            ..Default::default()
        });
        let resp = h
            .handle_request(req("totally-unknown.example", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "redirect");
        assert_eq!(resp.status, Some(302));
    }

    #[tokio::test]
    async fn rbi_no_engine_falls_through() {
        // Handler without RBI engine — no redirect ever.
        let (h, _cap) = make_handler(vec![]);
        let resp = h
            .handle_request(req("casino.example", "/", None, None))
            .await
            .unwrap();
        assert_ne!(resp.action, "redirect");
    }

    // ---- AI governance integration tests ----

    /// Build a handler with an AI-governance engine wired (and an
    /// RBI engine for redirect tests). Category DB maps
    /// `chatgpt.com` → `business.saas` so the deny-list doesn't
    /// interfere.
    fn make_ai_governance_handler() -> ExtAuthzHandler {
        let cap = Arc::new(CapturingEmitter::default());
        let bypass = Arc::new(BypassList::new(vec![]));
        let cats = LocalCategoryDb::new(vec![CategoryEntry {
            host: "chatgpt.com".into(),
            path_prefix: None,
            category: Category("business.saas".into()),
        }]);
        let mal = Arc::new(NullMalwareProvider);
        let clock = Arc::new(TestClock::new());
        let rl = RateLimiter::new(100.0, 1.0, clock);
        let rbi = Arc::new(RbiPolicyEngine::new(RbiProxyConfig {
            base_url: "https://rbi.test".into(),
        }));
        let aig = Arc::new(AiGovernanceEngine::new());
        ExtAuthzHandlerBuilder::new()
            .with_categorizer(Arc::new(cats))
            .with_malware(mal)
            .with_bypass(bypass)
            .with_rate_limiter(rl)
            .with_telemetry(cap as Arc<dyn TelemetryEmitter>)
            .with_rbi_engine(rbi)
            .with_ai_governance_engine(aig)
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn ai_governance_block_produces_deny() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: Some("chatgpt".into()),
                category: None,
                action: AiGovernanceAction::Block,
            }],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
        assert_eq!(resp.status, Some(403));
        assert!(resp.reason.contains("ai_governance"));
    }

    #[tokio::test]
    async fn ai_governance_allow_passes_through() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: Some("chatgpt".into()),
                category: None,
                action: AiGovernanceAction::Allow,
            }],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn ai_governance_monitor_passes_through() {
        let h = make_ai_governance_handler();
        // Default policy is monitor — no rules installed.
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn ai_governance_redirect_produces_redirect() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: Some("chatgpt".into()),
                category: None,
                action: AiGovernanceAction::Redirect,
            }],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "redirect");
        assert_eq!(resp.status, Some(302));
        assert!(resp.redirect_url.is_some());
        assert!(
            resp.redirect_url
                .as_ref()
                .unwrap()
                .starts_with("https://rbi.test/rbi/session/")
        );
    }

    #[tokio::test]
    async fn ai_governance_category_rule_blocks_all_chatbots() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: None,
                category: Some("chatbot".into()),
                action: AiGovernanceAction::Block,
            }],
            ..Default::default()
        });
        // chatgpt.com is a known chatbot.
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");
    }

    #[tokio::test]
    async fn ai_governance_per_app_overrides_category() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![
                AiGovernanceRule {
                    app: Some("chatgpt".into()),
                    category: None,
                    action: AiGovernanceAction::Allow,
                },
                AiGovernanceRule {
                    app: None,
                    category: Some("chatbot".into()),
                    action: AiGovernanceAction::Block,
                },
            ],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn ai_governance_no_engine_falls_through() {
        // Handler without AI governance engine — no block.
        let (h, _cap) = make_handler(vec![]);
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_ne!(resp.action, "deny");
    }

    #[tokio::test]
    async fn ai_governance_hot_swap_replaces_rules() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: Some("chatgpt".into()),
                category: None,
                action: AiGovernanceAction::Block,
            }],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "deny");

        // Hot-swap to empty policy → default monitor → allow.
        h.install_ai_governance_policy(&AiGovernancePolicy::default());
        let resp2 = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp2.action, "allow");
    }

    #[tokio::test]
    async fn ai_governance_non_ai_app_passes_through() {
        let h = make_ai_governance_handler();
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: None,
                category: Some("chatbot".into()),
                action: AiGovernanceAction::Block,
            }],
            ..Default::default()
        });
        // Non-AI host — governance doesn't match.
        let resp = h
            .handle_request(req("example.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "allow");
    }

    #[tokio::test]
    async fn ai_governance_rbi_wins_over_governance_redirect() {
        // When both RBI and AI governance would redirect, RBI
        // runs first (step 3c before 3d) and wins.
        let h = make_ai_governance_handler();
        // RBI policy: isolate chatgpt.com explicitly.
        h.install_rbi_policy(&RbiPolicyDef {
            explicit_isolate: vec!["chatgpt.com".into()],
            ..Default::default()
        });
        // Governance policy: redirect chatgpt.
        h.install_ai_governance_policy(&AiGovernancePolicy {
            rules: vec![AiGovernanceRule {
                app: Some("chatgpt".into()),
                category: None,
                action: AiGovernanceAction::Redirect,
            }],
            ..Default::default()
        });
        let resp = h
            .handle_request(req("chatgpt.com", "/", None, None))
            .await
            .unwrap();
        assert_eq!(resp.action, "redirect");
        // RBI reason starts with "rbi.", governance with "ai_governance."
        assert!(resp.reason.starts_with("rbi."));
    }
}

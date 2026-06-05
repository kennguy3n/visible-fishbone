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
use crate::error::SwgError;
use crate::malware::{MalwareVerdict, MalwareVerdictProvider};
use crate::rate_limit::RateLimiter;
use crate::telemetry::{TelemetryEmitter, VerdictEvent};
use crate::verdict::{Action, RequestContext, Verdict};

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
}

/// Verdict JSON Envoy reads back. Stable wire contract — adding
/// a field is fine; removing or renaming one is a wire break.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtAuthzResponse {
    /// "allow" | "deny" | "bypass" | "rate_limit"
    pub action: String,
    /// HTTP status Envoy returns to the client on deny /
    /// rate_limit. `None` on allow / bypass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Categorisation/deny reason — surfaces in operator
    /// telemetry and in any 4xx body Envoy emits.
    pub reason: String,
    /// Bound on the value of `Retry-After` Envoy puts on a
    /// rate_limit response, in seconds. `None` on allow /
    /// bypass / deny.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_secs: Option<u64>,
    /// Optional category tag — surfaces on telemetry so a
    /// dashboard can drill into "% of requests by category".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
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
            },
            Action::Bypass => Self {
                action: "bypass".into(),
                status: None,
                reason: v.reason.clone(),
                retry_after_secs: None,
                category: v.category.clone(),
            },
            Action::Deny => Self {
                action: "deny".into(),
                status: Some(403),
                reason: v.reason.clone(),
                retry_after_secs: None,
                category: v.category.clone(),
            },
            Action::RateLimit => Self {
                action: "rate_limit".into(),
                status: Some(429),
                reason: v.reason.clone(),
                // Copy the verdict's retry timing verbatim onto
                // the wire response so Envoy can stamp it onto
                // the 429's `Retry-After` header. The verdict
                // constructor guarantees `Some` on the RateLimit
                // arm — falling back to `None` here would be a
                // silent regression of the ext-authz contract.
                retry_after_secs: v.retry_after_secs,
                category: v.category.clone(),
            },
        }
    }
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
    /// Operator-controlled deny-categories. A category that
    /// appears here causes the handler to return Deny instead of
    /// Allow. Stored as a sorted Vec so contains() is O(log n)
    /// after a binary_search, which beats HashSet on the typical
    /// 50-200 entry list.
    deny_categories: Vec<String>,
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
}

impl std::fmt::Debug for ExtAuthzHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthzHandler")
            .field("deny_categories_len", &self.inner.deny_categories.len())
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
    deny_categories: Vec<String>,
    elevated_risk_mode: bool,
    casb: Option<Arc<InlineCasbInspector>>,
}

impl std::fmt::Debug for ExtAuthzHandlerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthzHandlerBuilder")
            .field("categorizer_set", &self.categorizer.is_some())
            .field("malware_set", &self.malware.is_some())
            .field("bypass_set", &self.bypass.is_some())
            .field("rate_limiter_set", &self.rate_limiter.is_some())
            .field("telemetry_set", &self.telemetry.is_some())
            .field("deny_categories", &self.deny_categories)
            .field("elevated_risk_mode", &self.elevated_risk_mode)
            .field("casb_set", &self.casb.is_some())
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
            deny_categories: Vec::new(),
            elevated_risk_mode: false,
            casb: None,
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

    /// Categories that map onto Deny instead of Allow. Stored
    /// in a Vec the builder sorts + dedups at build time; the
    /// hot path uses binary_search to test membership.
    #[must_use]
    pub fn with_deny_categories(mut self, cats: Vec<String>) -> Self {
        self.deny_categories = cats;
        self
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

    /// Build the handler. Returns an error when any required
    /// dep was not set.
    pub fn build(mut self) -> Result<ExtAuthzHandler, SwgError> {
        // Sort + dedup so binary_search works on the hot path.
        // Lowercasing here keeps the case-insensitive compare
        // out of every request.
        for c in &mut self.deny_categories {
            *c = c.to_ascii_lowercase();
        }
        self.deny_categories.sort();
        self.deny_categories.dedup();
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
                deny_categories: self.deny_categories,
                elevated_risk_mode: self.elevated_risk_mode,
                casb: self.casb,
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

    /// Convenience: process a decoded JSON request envelope.
    /// Returns the response envelope ready for serialisation.
    pub async fn handle_request(&self, req: ExtAuthzRequest) -> Result<ExtAuthzResponse, SwgError> {
        // Build the out-of-band CASB signals before `into_context`
        // consumes the request envelope.
        let signals = req.signals();
        let ctx = req.into_context()?;
        let verdict = self.evaluate(&ctx, &signals).await;
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
            },
            Err(other) => ExtAuthzResponse {
                action: "deny".into(),
                status: Some(500),
                reason: format!("handler error: {other}"),
                retry_after_secs: None,
                category: None,
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
    /// 4. URL categorisation — operator deny-list wins; default allow
    /// 5. Malware verdict on the response body hash (when supplied)
    ///
    /// `signals` carries the out-of-band inline-CASB inputs (content
    /// length, sensitivity label) extracted from the request by
    /// [`ExtAuthzRequest::signals`]. They are ignored when no CASB
    /// inspector is wired, so the verdict stays a pure function of
    /// `(ctx, signals)` over the configured trait + inspector
    /// snapshot.
    pub async fn evaluate(&self, ctx: &RequestContext, signals: &RequestSignals) -> Verdict {
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
        if let Some(v) = &casb_verdict {
            if v.action == Action::Deny {
                return v.clone();
            }
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
        // the binary-search lookup against the already-lowercased
        // `deny_categories` table that follows.
        let category_canonical = self
            .inner
            .categorizer
            .categorize(&ctx.host, &ctx.path)
            .await
            .map(|c| c.0.to_ascii_lowercase());
        if let Some(cat) = &category_canonical {
            if self.inner.deny_categories.binary_search(cat).is_ok() {
                return Verdict::deny_categorized(cat.clone());
            }
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
        // Allow path. A carried-forward CASB `log` / `allow`
        // verdict wins over the categoriser's allow: it is the
        // higher-signal decision (a specific SaaS action the
        // operator asked to log or explicitly allow) and it carries
        // the `casb.<app>.<action>` category the DLP / CASB
        // dashboards group on. Falling through to the categoriser
        // allow would drop that signal. When no CASB verdict was
        // produced, behaviour is identical to the pre-CASB pipeline.
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
    use crate::malware::{NullMalwareProvider, StaticMalwareList};
    use crate::rate_limit::{RateLimiter, TestClock};
    use crate::telemetry::{SwgEventSource, TelemetryEmitter, VerdictEvent};
    use parking_lot::Mutex;
    use pretty_assertions::assert_eq;
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
}

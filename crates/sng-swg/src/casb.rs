//! Inline CASB inspection on the SWG ext-authz decision path.
//!
//! API-mode CASB (`internal/service/casb` on the control plane)
//! polls SaaS provider APIs out-of-band to discover apps and
//! assess posture. This module is the *inline* counterpart: it
//! sits in the per-request Envoy ext-authz path and inspects live
//! traffic to configured SaaS apps (Microsoft 365, Google
//! Workspace, Slack, Salesforce) for:
//!
//!   * **Uploads** — block sensitive file uploads per the inline
//!     DLP rule set (file type / size / sensitivity label).
//!   * **Sharing actions** — detect public-sharing links / external
//!     invites being created and block or log them.
//!   * **Downloads** — tag for DLP scanning (log-only verdict).
//!   * **Deletes** — gated like the other actions.
//!
//! The inspector is a two-stage pipeline:
//!
//!   1. **App + action detection** ([`AppCatalog`]) — match the
//!      request by SNI / host suffix and URL path pattern (e.g.
//!      `graph.microsoft.com` + `PUT /v1.0/me/drive/items/*/content`
//!      ⇒ M365 upload). Detection reuses
//!      [`sng_fw::sni_suffix_match`] for the host match so the
//!      SaaS-app suffix list has identical semantics to the TLS
//!      bypass list and the firewall L7 classifier.
//!   2. **Rule evaluation** ([`crate::casb_rules`]) — a pure
//!      function over the detected `(app, action)` plus request
//!      metadata (file type, size, label). The rule set is owned
//!      by an [`arc_swap::ArcSwap`] so a control-plane bundle
//!      install hot-swaps both the rules and the app catalog
//!      atomically without taking a lock on the hot path.
//!
//! A request that does not resolve to a configured app, or that
//! resolves to an app/action with no matching rule, yields `None`
//! — the ext-authz handler then continues the rest of the verdict
//! pipeline (categoriser, malware, rate limit) unchanged. Only a
//! rule that actually fires produces a [`Verdict`].

use crate::casb_rules::{CasbAction, CasbDecision, CasbRequestMeta, CasbRuleSet, CasbVerdict};
use crate::verdict::{Action, RequestContext, Verdict};
use arc_swap::ArcSwap;
use sng_fw::sni_suffix_match;
use std::sync::Arc;

/// Out-of-band signals the ext-authz handler forwards alongside
/// the [`RequestContext`] so the inspector can evaluate
/// size / label conditions. These come from Envoy request
/// metadata (the `Content-Length` header, an upstream DLP label
/// header) rather than the URL, so they live in a dedicated
/// struct rather than bloating `RequestContext`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestSignals {
    /// Content length in bytes, from Envoy's `Content-Length`
    /// forwarding. `None` when the request is chunked / the header
    /// was absent.
    pub content_length: Option<u64>,
    /// Sensitivity label (e.g. a Microsoft Purview / MIP label id)
    /// forwarded as request metadata. `None` when no label is
    /// present.
    pub sensitivity_label: Option<String>,
}

/// One method + path-glob → action mapping within an
/// [`AppSignature`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathRule {
    /// HTTP method the request must use (lowercase). `None`
    /// matches any method.
    pub method: Option<String>,
    /// Path glob. `*` matches exactly one non-empty path segment;
    /// every other segment matches literally (case-sensitive, per
    /// RFC 3986 §3.3). The glob and the request path must have the
    /// same segment count.
    pub path_glob: String,
    /// Action a matching request is classified as.
    pub action: CasbAction,
    /// Whether the path's matched final segment is a real filename
    /// (and thus carries a meaningful extension). Drives whether
    /// [`inspect`](InlineCasbInspector::inspect) derives `file_type`
    /// from the request path.
    ///
    /// This is an explicit property of the rule, NOT inferred from
    /// the glob shape: a trailing `*` is just as likely to match an
    /// opaque resource id (Graph drive-item id, Salesforce
    /// `ContentVersion` id) as a filename, and a literal tail (Slack
    /// `files.upload`) is an API method name whose embedded dot must
    /// never be read as an extension. Inferring "tail is `*`" ⇒
    /// "filename" would wrongly enable extension derivation for every
    /// id-tailed delete/download endpoint. None of the four builtin
    /// SaaS APIs put a filename in the path, so all builtin rules set
    /// this `false`; a future catalog whose path genuinely ends in a
    /// filename uses [`PathRule::new_filename`].
    pub filename_in_path: bool,
}

impl PathRule {
    /// A rule whose matched tail segment is NOT a filename — the
    /// common case (literal API method names, opaque resource ids).
    /// `file_type` is not derived from the path.
    fn new(method: Option<&str>, path_glob: &str, action: CasbAction) -> Self {
        Self {
            method: method.map(str::to_ascii_lowercase),
            path_glob: path_glob.to_string(),
            action,
            filename_in_path: false,
        }
    }

    /// A rule whose final `*` segment is a real filename, so a file
    /// extension is derived from it for file-type-gated rules. Use
    /// only when the matched segment genuinely carries a filename.
    #[cfg(test)]
    fn new_filename(method: Option<&str>, path_glob: &str, action: CasbAction) -> Self {
        Self {
            filename_in_path: true,
            ..Self::new(method, path_glob, action)
        }
    }
}

/// Detection signature for one SaaS app: the host suffixes that
/// identify it plus the ordered path rules that classify the
/// action. Path rules are matched in declaration order; the first
/// match wins, so more specific globs are declared ahead of more
/// general ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppSignature {
    /// Canonical app id (`"m365"`, `"google_workspace"`,
    /// `"slack"`, `"salesforce"`).
    pub app_id: String,
    /// Host suffixes that identify the app. Matched with
    /// [`sng_fw::sni_suffix_match`] against the SNI first (the
    /// authoritative signal on a CONNECT tunnel) and the request
    /// host as a fallback. A bare suffix (`graph.microsoft.com`)
    /// matches the apex and any subdomain.
    pub host_suffixes: Vec<String>,
    /// Ordered action classification rules.
    pub path_rules: Vec<PathRule>,
}

impl AppSignature {
    /// True when the request's authoritative target host resolves to
    /// this app. The SNI is authoritative when present (on a CONNECT
    /// tunnel it is the real TLS destination and cannot be forged by
    /// a mismatched inner `Host` header); the request host is only a
    /// fallback when there is no SNI. Using SNI-or-host (rather than
    /// SNI-then-host) would let a spoofed `Host` header steer
    /// detection to a different app than the connection actually
    /// terminates at.
    #[must_use]
    fn host_matches(&self, ctx: &RequestContext) -> bool {
        let target = ctx.sni.as_deref().unwrap_or(ctx.host.as_str());
        self.host_suffixes
            .iter()
            .any(|suffix| sni_suffix_match(suffix, target))
    }

    /// Classify the request against this app's path rules, returning
    /// the first matching [`PathRule`] in declaration order.
    #[must_use]
    fn classify(&self, ctx: &RequestContext) -> Option<&PathRule> {
        let path = match_path(&ctx.path);
        self.path_rules.iter().find(|pr| {
            if let Some(m) = &pr.method {
                if !ctx.method.eq_ignore_ascii_case(m) {
                    return false;
                }
            }
            path_glob_match(&pr.path_glob, path)
        })
    }
}

/// The result of app + action detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedApp {
    /// Detected SaaS app id.
    pub app_id: String,
    /// Detected action.
    pub action: CasbAction,
    /// Mirrors the matched [`PathRule::filename_in_path`]: true when
    /// the request path's last segment is a real filename. Drives
    /// whether `file_type` is derived from the request path.
    pub filename_in_path: bool,
}

/// Catalog of SaaS-app detection signatures. The default catalog
/// covers the four launch apps; an operator can install a wider
/// or narrower catalog from the policy bundle.
#[derive(Clone, Debug, Default)]
pub struct AppCatalog {
    signatures: Vec<AppSignature>,
}

impl AppCatalog {
    /// Build a catalog from an explicit signature list.
    #[must_use]
    pub fn new(signatures: Vec<AppSignature>) -> Self {
        Self { signatures }
    }

    /// Number of app signatures in the catalog.
    #[must_use]
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Detect the SaaS app and action for a request. Returns
    /// `None` when the host matches no configured app, or matches
    /// an app but no action path rule.
    #[must_use]
    pub fn detect(&self, ctx: &RequestContext) -> Option<DetectedApp> {
        self.signatures.iter().find_map(|sig| {
            if !sig.host_matches(ctx) {
                return None;
            }
            sig.classify(ctx).map(|pr| DetectedApp {
                app_id: sig.app_id.clone(),
                action: pr.action,
                filename_in_path: pr.filename_in_path,
            })
        })
    }

    /// The built-in catalog for the four launch SaaS apps. The
    /// path globs encode the documented API shapes for file
    /// upload, download, sharing, and delete on each provider.
    #[must_use]
    pub fn builtin() -> Self {
        Self::new(vec![
            // Microsoft 365 (OneDrive / SharePoint via Graph).
            AppSignature {
                app_id: "m365".to_string(),
                host_suffixes: vec!["graph.microsoft.com".to_string()],
                path_rules: vec![
                    PathRule::new(
                        Some("put"),
                        "/v1.0/me/drive/items/*/content",
                        CasbAction::Upload,
                    ),
                    PathRule::new(
                        Some("put"),
                        "/v1.0/drives/*/items/*/content",
                        CasbAction::Upload,
                    ),
                    PathRule::new(
                        Some("get"),
                        "/v1.0/me/drive/items/*/content",
                        CasbAction::Download,
                    ),
                    PathRule::new(
                        Some("get"),
                        "/v1.0/drives/*/items/*/content",
                        CasbAction::Download,
                    ),
                    PathRule::new(
                        Some("post"),
                        "/v1.0/me/drive/items/*/createLink",
                        CasbAction::Share,
                    ),
                    PathRule::new(
                        Some("post"),
                        "/v1.0/drives/*/items/*/createLink",
                        CasbAction::Share,
                    ),
                    PathRule::new(
                        Some("post"),
                        "/v1.0/me/drive/items/*/invite",
                        CasbAction::Share,
                    ),
                    PathRule::new(Some("delete"), "/v1.0/me/drive/items/*", CasbAction::Delete),
                ],
            },
            // Google Workspace (Drive v3). Note: the binary
            // download is `GET /drive/v3/files/{id}?alt=media`; the
            // query is stripped before the categoriser/inspector
            // sees the path, so this rule also matches a metadata
            // GET — a download-tag (log) verdict is the safe
            // default for that ambiguity.
            AppSignature {
                app_id: "google_workspace".to_string(),
                host_suffixes: vec!["googleapis.com".to_string()],
                path_rules: vec![
                    PathRule::new(Some("post"), "/upload/drive/v3/files", CasbAction::Upload),
                    PathRule::new(
                        Some("post"),
                        "/drive/v3/files/*/permissions",
                        CasbAction::Share,
                    ),
                    PathRule::new(Some("delete"), "/drive/v3/files/*", CasbAction::Delete),
                    PathRule::new(Some("get"), "/drive/v3/files/*", CasbAction::Download),
                ],
            },
            // Slack (Web API).
            AppSignature {
                app_id: "slack".to_string(),
                host_suffixes: vec!["slack.com".to_string()],
                path_rules: vec![
                    PathRule::new(Some("post"), "/api/files.upload", CasbAction::Upload),
                    PathRule::new(
                        Some("post"),
                        "/api/files.completeUploadExternal",
                        CasbAction::Upload,
                    ),
                    PathRule::new(
                        Some("post"),
                        "/api/files.sharedPublicURL",
                        CasbAction::Share,
                    ),
                    PathRule::new(Some("post"), "/api/files.delete", CasbAction::Delete),
                ],
            },
            // Salesforce (REST data API).
            AppSignature {
                app_id: "salesforce".to_string(),
                host_suffixes: vec!["salesforce.com".to_string(), "force.com".to_string()],
                path_rules: vec![
                    PathRule::new(
                        Some("get"),
                        "/services/data/*/sobjects/ContentVersion/*/VersionData",
                        CasbAction::Download,
                    ),
                    PathRule::new(
                        Some("post"),
                        "/services/data/*/sobjects/ContentVersion",
                        CasbAction::Upload,
                    ),
                    PathRule::new(
                        Some("post"),
                        "/services/data/*/sobjects/ContentDistribution",
                        CasbAction::Share,
                    ),
                    PathRule::new(
                        Some("delete"),
                        "/services/data/*/sobjects/ContentVersion/*",
                        CasbAction::Delete,
                    ),
                ],
            },
        ])
    }
}

/// Immutable snapshot the inspector reads on the hot path:
/// the SaaS-app catalog plus the compiled rule set.
#[derive(Clone, Debug, Default)]
struct InspectorState {
    catalog: AppCatalog,
    rules: CasbRuleSet,
}

/// Inline CASB inspector. Holds the app catalog and rule set
/// behind an [`ArcSwap`] so a control-plane bundle install swaps
/// both atomically. Lookups are lock-free.
#[derive(Debug)]
pub struct InlineCasbInspector {
    inner: ArcSwap<InspectorState>,
}

impl Default for InlineCasbInspector {
    /// An inspector with the built-in app catalog and an empty
    /// rule set — detection works but nothing is enforced until
    /// rules are installed.
    fn default() -> Self {
        Self {
            inner: ArcSwap::from_pointee(InspectorState {
                catalog: AppCatalog::builtin(),
                rules: CasbRuleSet::default(),
            }),
        }
    }
}

impl InlineCasbInspector {
    /// Build an inspector with an explicit catalog and rule set.
    #[must_use]
    pub fn new(catalog: AppCatalog, rules: CasbRuleSet) -> Self {
        Self {
            inner: ArcSwap::from_pointee(InspectorState { catalog, rules }),
        }
    }

    /// Build an inspector with the built-in catalog and the given
    /// rule set.
    #[must_use]
    pub fn with_rules(rules: CasbRuleSet) -> Self {
        Self::new(AppCatalog::builtin(), rules)
    }

    /// Atomically swap in a new catalog + rule set. Returns the
    /// number of rules installed so the manager can log it.
    pub fn install(&self, catalog: AppCatalog, rules: CasbRuleSet) -> usize {
        let n = rules.len();
        self.inner
            .store(Arc::new(InspectorState { catalog, rules }));
        n
    }

    /// Atomically swap in a new rule set, preserving the current
    /// app catalog.
    ///
    /// Uses [`ArcSwap::rcu`] so the read-copy-update is atomic with
    /// respect to a concurrent [`install`](Self::install) /
    /// `install_rules`: the closure re-reads the current catalog and
    /// retries if another writer raced in between, rather than
    /// load-then-store (which could clobber a concurrent catalog
    /// swap with a stale clone). The closure may run more than once
    /// under contention, so it only clones — no side effects. The
    /// rule set is borrowed (not moved) because the closure may need
    /// to re-clone it on a retry.
    pub fn install_rules(&self, rules: &CasbRuleSet) -> usize {
        let n = rules.len();
        self.inner.rcu(|cur| {
            Arc::new(InspectorState {
                catalog: cur.catalog.clone(),
                rules: rules.clone(),
            })
        });
        n
    }

    /// Detect the SaaS app + action for a request without
    /// evaluating any rule. Exposed for telemetry / debugging.
    #[must_use]
    pub fn detect(&self, ctx: &RequestContext) -> Option<DetectedApp> {
        self.inner.load().catalog.detect(ctx)
    }

    /// Inspect a request on the ext-authz path. Returns:
    ///
    ///   * `None` — the request is not CASB-relevant (host matches
    ///     no configured app, or no action rule matched, or a
    ///     matched rule's verdict is `Allow`-with-no-rule). The
    ///     caller continues the rest of the verdict pipeline.
    ///   * `Some(Verdict::Deny)` — a `block` rule fired.
    ///   * `Some(Verdict::Allow)` — a `log` rule fired (the
    ///     request is allowed but tagged for CASB / DLP telemetry)
    ///     or an explicit `allow` rule short-circuited a broader
    ///     block.
    ///
    /// Pure with respect to I/O: it loads the immutable
    /// [`ArcSwap`] snapshot and runs the pure rule engine.
    #[must_use]
    pub fn inspect(&self, ctx: &RequestContext, signals: &RequestSignals) -> Option<Verdict> {
        let state = self.inner.load();
        let detected = state.catalog.detect(ctx)?;
        // Only derive a file extension when the matched rule's last
        // path segment is a wildcard (a real filename variable).
        // SaaS APIs like Slack put a dotted *method* name in the path
        // (`/api/files.upload`); deriving `file_type` from that would
        // yield a bogus `"upload"` and silently break file-type-gated
        // rules, so literal-tailed globs contribute no file type.
        let file_type = if detected.filename_in_path {
            file_type_from_path(match_path(&ctx.path))
        } else {
            None
        };
        let meta = CasbRequestMeta {
            app_id: detected.app_id,
            action: detected.action,
            file_type,
            size_bytes: signals.content_length,
            label: signals.sensitivity_label.clone(),
        };
        let decision = state.rules.evaluate(&meta)?;
        Some(verdict_from_decision(&decision))
    }
}

/// Map a fired rule's decision onto the SWG [`Verdict`] the
/// ext-authz handler returns. The dotted reason
/// (`<action>.casb.<app>.<casb_action>`) keeps the telemetry
/// schema consistent with the categoriser / malware reasons so a
/// single dashboard can group CASB verdicts alongside the rest.
fn verdict_from_decision(d: &CasbDecision) -> Verdict {
    let category = format!("casb.{}.{}", d.app_id, d.action.as_str());
    match d.verdict {
        CasbVerdict::Block => Verdict::deny_categorized(category),
        CasbVerdict::Allow => Verdict::allow_categorized(category),
        CasbVerdict::Log => Verdict {
            action: Action::Allow,
            reason: format!("log.{category}"),
            category: Some(category),
            retry_after_secs: None,
        },
    }
}

/// Derive a lowercase file extension (no dot) from a request
/// path's last segment. Returns `None` when the last segment has
/// no dot or the extension is empty.
fn file_type_from_path(path: &str) -> Option<String> {
    let last = path.rsplit('/').next()?;
    let (_, ext) = last.rsplit_once('.')?;
    if ext.is_empty() {
        None
    } else {
        Some(ext.to_ascii_lowercase())
    }
}

/// Normalise a request path for CASB matching by trimming trailing
/// slashes. [`RequestContext::normalize`] strips the query but leaves
/// a trailing slash intact, so `/api/files.upload/` would otherwise
/// gain an empty trailing segment and fail the segment-count parity
/// [`path_glob_match`] requires, silently bypassing detection (a
/// fail-open miss). Envoy normalises this away in production, but a
/// hand-built context or a non-conforming client must not slip past
/// the inspector. The root path stays `/` so it never collapses to
/// the empty string.
fn match_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

/// Segment-wise path glob match. `*` matches exactly one non-empty
/// segment; every other segment matches literally. The glob and
/// the path must have the same number of `/`-delimited segments.
/// Case-sensitive on literal segments (RFC 3986 §3.3 treats the
/// path component as case-sensitive).
fn path_glob_match(glob: &str, path: &str) -> bool {
    let mut gs = glob.split('/');
    let mut ps = path.split('/');
    loop {
        match (gs.next(), ps.next()) {
            (Some(g), Some(p)) => {
                if g == "*" {
                    if p.is_empty() {
                        return false;
                    }
                } else if g != p {
                    return false;
                }
            }
            (None, None) => return true,
            // Differing segment counts never match.
            _ => return false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn ctx(method: &str, host: &str, path: &str) -> RequestContext {
        let mut c = RequestContext {
            tenant_id: "t1".to_string(),
            principal_id: "p1".to_string(),
            method: method.to_string(),
            scheme: "https".to_string(),
            host: host.to_string(),
            path: path.to_string(),
            sni: Some(host.to_string()),
            file_hash: None,
        };
        c.normalize();
        c
    }

    #[test]
    fn path_glob_matches_single_segment_wildcard() {
        assert!(path_glob_match(
            "/v1.0/me/drive/items/*/content",
            "/v1.0/me/drive/items/01ABCDEF/content"
        ));
        // Wildcard does not span multiple segments.
        assert!(!path_glob_match(
            "/v1.0/me/drive/items/*/content",
            "/v1.0/me/drive/items/a/b/content"
        ));
        // Segment count must match.
        assert!(!path_glob_match("/a/*/c", "/a/b"));
        // Empty segment never matches a wildcard.
        assert!(!path_glob_match("/a/*/c", "/a//c"));
        // Literal segments are case-sensitive.
        assert!(!path_glob_match("/Content", "/content"));
    }

    #[test]
    fn detects_m365_upload_share_download_delete() {
        let cat = AppCatalog::builtin();
        let up = cat
            .detect(&ctx(
                "PUT",
                "graph.microsoft.com",
                "/v1.0/me/drive/items/01X/content",
            ))
            .expect("upload");
        assert_eq!(up.app_id, "m365");
        assert_eq!(up.action, CasbAction::Upload);

        let share = cat
            .detect(&ctx(
                "POST",
                "graph.microsoft.com",
                "/v1.0/me/drive/items/01X/createLink",
            ))
            .expect("share");
        assert_eq!(share.action, CasbAction::Share);

        let down = cat
            .detect(&ctx(
                "GET",
                "graph.microsoft.com",
                "/v1.0/me/drive/items/01X/content",
            ))
            .expect("download");
        assert_eq!(down.action, CasbAction::Download);

        let del = cat
            .detect(&ctx(
                "DELETE",
                "graph.microsoft.com",
                "/v1.0/me/drive/items/01X",
            ))
            .expect("delete");
        assert_eq!(del.action, CasbAction::Delete);
    }

    #[test]
    fn detects_other_saas_apps() {
        let cat = AppCatalog::builtin();
        assert_eq!(
            cat.detect(&ctx("POST", "slack.com", "/api/files.upload"))
                .map(|d| (d.app_id, d.action)),
            Some(("slack".to_string(), CasbAction::Upload))
        );
        assert_eq!(
            cat.detect(&ctx("POST", "www.googleapis.com", "/upload/drive/v3/files"))
                .map(|d| (d.app_id, d.action)),
            Some(("google_workspace".to_string(), CasbAction::Upload))
        );
        assert_eq!(
            cat.detect(&ctx(
                "POST",
                "acme.my.salesforce.com",
                "/services/data/v59.0/sobjects/ContentVersion"
            ))
            .map(|d| (d.app_id, d.action)),
            Some(("salesforce".to_string(), CasbAction::Upload))
        );
    }

    #[test]
    fn detection_uses_sni_over_unrelated_host() {
        // On a CONNECT tunnel the SNI is the authoritative app
        // signal; a mismatched Host header must not defeat it.
        let cat = AppCatalog::builtin();
        let mut c = ctx("POST", "internal-proxy.local", "/api/files.upload");
        c.sni = Some("slack.com".to_string());
        c.normalize();
        let d = cat.detect(&c).expect("detect via sni");
        assert_eq!(d.app_id, "slack");
    }

    #[test]
    fn non_saas_host_is_not_detected() {
        let cat = AppCatalog::builtin();
        assert_eq!(cat.detect(&ctx("GET", "example.com", "/index.html")), None);
    }

    #[test]
    fn wrong_method_is_not_classified() {
        let cat = AppCatalog::builtin();
        // GET on the upload path is not an upload.
        assert_eq!(
            cat.detect(&ctx("GET", "slack.com", "/api/files.upload")),
            None
        );
    }

    #[test]
    fn trailing_slash_still_detects() {
        // A request path with a trailing slash must not silently
        // bypass detection: `match_path` trims it so segment-count
        // parity with the glob holds. Otherwise `/api/files.upload/`
        // would gain an empty trailing segment and fail to match
        // `/api/files.upload`, fail-open past the inspector.
        let cat = AppCatalog::builtin();
        assert_eq!(
            cat.detect(&ctx("POST", "slack.com", "/api/files.upload/"))
                .map(|d| (d.app_id, d.action)),
            Some(("slack".to_string(), CasbAction::Upload)),
            "trailing slash must not defeat detection"
        );
        // Multiple trailing slashes are trimmed too.
        assert_eq!(
            cat.detect(&ctx("POST", "slack.com", "/api/files.upload///"))
                .map(|d| d.action),
            Some(CasbAction::Upload)
        );
    }

    #[test]
    fn host_used_only_when_sni_absent() {
        // SNI is authoritative: a Host header pointing at a different
        // app must not steer detection when the SNI says otherwise.
        let cat = AppCatalog::builtin();
        let mut c = ctx("POST", "graph.microsoft.com", "/api/files.upload");
        c.sni = Some("slack.com".to_string());
        c.normalize();
        // SNI (slack) wins over the M365 Host header; the M365 share
        // path does not match the Slack upload path, so this resolves
        // to the Slack upload rule, not M365.
        assert_eq!(
            cat.detect(&c).map(|d| d.app_id),
            Some("slack".to_string()),
            "SNI must override a mismatched Host header"
        );
        // With no SNI, the Host header is the fallback signal.
        let mut c2 = ctx("POST", "slack.com", "/api/files.upload");
        c2.sni = None;
        c2.normalize();
        assert_eq!(cat.detect(&c2).map(|d| d.app_id), Some("slack".to_string()));
    }

    #[test]
    fn inspect_blocks_public_sharing_on_m365() {
        let rules = CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
            id: "block-share".to_string(),
            app_id: "m365".to_string(),
            action: CasbAction::Share,
            verdict: CasbVerdict::Block,
            conditions: crate::casb_rules::CasbConditions::default(),
            priority: 10,
        }]);
        let inspector = InlineCasbInspector::with_rules(rules);
        let v = inspector
            .inspect(
                &ctx(
                    "POST",
                    "graph.microsoft.com",
                    "/v1.0/me/drive/items/01X/createLink",
                ),
                &RequestSignals::default(),
            )
            .expect("verdict");
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.reason, "deny.casb.m365.share");
        assert_eq!(v.category.as_deref(), Some("casb.m365.share"));
    }

    #[test]
    fn inspect_logs_large_uploads_to_salesforce() {
        let rules = CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
            id: "log-large".to_string(),
            app_id: "salesforce".to_string(),
            action: CasbAction::Upload,
            verdict: CasbVerdict::Log,
            conditions: crate::casb_rules::CasbConditions {
                file_type: None,
                size_threshold: Some(10 * 1024 * 1024),
                label_match: None,
            },
            priority: 5,
        }]);
        let inspector = InlineCasbInspector::with_rules(rules);
        let big = RequestSignals {
            content_length: Some(20 * 1024 * 1024),
            sensitivity_label: None,
        };
        let v = inspector
            .inspect(
                &ctx(
                    "POST",
                    "acme.my.salesforce.com",
                    "/services/data/v59.0/sobjects/ContentVersion",
                ),
                &big,
            )
            .expect("verdict");
        assert_eq!(v.action, Action::Allow);
        assert_eq!(v.reason, "log.casb.salesforce.upload");
        assert!(v.is_completing());

        // A small upload does not meet the threshold -> no verdict.
        let small = RequestSignals {
            content_length: Some(1024),
            sensitivity_label: None,
        };
        assert_eq!(
            inspector.inspect(
                &ctx(
                    "POST",
                    "acme.my.salesforce.com",
                    "/services/data/v59.0/sobjects/ContentVersion",
                ),
                &small,
            ),
            None
        );
    }

    #[test]
    fn inspect_passes_through_when_no_rule_matches() {
        // Detection succeeds but the (empty) rule set has nothing
        // to say -> None, so the handler continues the pipeline.
        let inspector = InlineCasbInspector::default();
        assert_eq!(
            inspector.inspect(
                &ctx(
                    "PUT",
                    "graph.microsoft.com",
                    "/v1.0/me/drive/items/01X/content"
                ),
                &RequestSignals::default(),
            ),
            None
        );
    }

    #[test]
    fn inspect_passes_through_for_non_saas_request() {
        let inspector =
            InlineCasbInspector::with_rules(CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
                id: "r".to_string(),
                app_id: "*".to_string(),
                action: CasbAction::Upload,
                verdict: CasbVerdict::Block,
                conditions: crate::casb_rules::CasbConditions::default(),
                priority: 0,
            }]));
        assert_eq!(
            inspector.inspect(&ctx("GET", "example.com", "/"), &RequestSignals::default()),
            None
        );
    }

    #[test]
    fn install_swaps_rules_atomically() {
        let inspector = InlineCasbInspector::default();
        let c = ctx(
            "PUT",
            "graph.microsoft.com",
            "/v1.0/me/drive/items/01X/content",
        );
        assert_eq!(inspector.inspect(&c, &RequestSignals::default()), None);

        let n = inspector.install_rules(&CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
            id: "block-upload".to_string(),
            app_id: "m365".to_string(),
            action: CasbAction::Upload,
            verdict: CasbVerdict::Block,
            conditions: crate::casb_rules::CasbConditions::default(),
            priority: 1,
        }]));
        assert_eq!(n, 1);
        let v = inspector
            .inspect(&c, &RequestSignals::default())
            .expect("verdict");
        assert_eq!(v.action, Action::Deny);
    }

    #[test]
    fn install_rules_preserves_installed_catalog() {
        // install_rules must keep whatever catalog install() last
        // set — the rcu read-copy-update reads the current catalog
        // rather than reverting to the builtin one.
        let custom = AppCatalog::new(vec![AppSignature {
            app_id: "acme".to_string(),
            host_suffixes: vec!["acme.example".to_string()],
            path_rules: vec![PathRule::new(
                Some("post"),
                "/files/*/upload",
                CasbAction::Upload,
            )],
        }]);
        let inspector = InlineCasbInspector::new(custom, CasbRuleSet::default());

        inspector.install_rules(&CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
            id: "block-acme-upload".to_string(),
            app_id: "acme".to_string(),
            action: CasbAction::Upload,
            verdict: CasbVerdict::Block,
            conditions: crate::casb_rules::CasbConditions::default(),
            priority: 1,
        }]));

        // The custom catalog is still in effect after install_rules.
        let c = ctx("POST", "acme.example", "/files/42/upload");
        let v = inspector
            .inspect(&c, &RequestSignals::default())
            .expect("verdict");
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.reason, "deny.casb.acme.upload");

        // A builtin host is NOT detected — the builtin catalog was
        // never restored.
        let builtin_host = ctx(
            "PUT",
            "graph.microsoft.com",
            "/v1.0/me/drive/items/01X/content",
        );
        assert_eq!(inspector.detect(&builtin_host), None);
    }

    #[test]
    fn file_type_is_derived_from_path_tail() {
        assert_eq!(
            file_type_from_path("/a/b/report.DOCX").as_deref(),
            Some("docx")
        );
        assert_eq!(file_type_from_path("/a/b/content"), None);
        assert_eq!(
            file_type_from_path("/a/b/.hidden").as_deref(),
            Some("hidden")
        );
        assert_eq!(file_type_from_path("/a/b/trailingdot."), None);
    }

    #[test]
    fn slack_dotted_method_path_yields_no_file_type() {
        // Regression: Slack's API paths use dotted *method* names
        // (`/api/files.upload`). The trailing segment is a literal,
        // not a `*` wildcard, so `file_type` must NOT be derived from
        // it — otherwise it would spuriously be `Some("upload")` and
        // silently break (or wrongly trigger) file-type-gated rules.
        let cat = AppCatalog::builtin();
        let detected = cat
            .detect(&ctx("POST", "slack.com", "/api/files.upload"))
            .expect("slack upload detected");
        assert_eq!(detected.action, CasbAction::Upload);
        assert!(
            !detected.filename_in_path,
            "literal dotted method segment must not be treated as a filename"
        );

        // A rule keyed on the bogus pre-fix file type `"upload"` must
        // NOT fire, because `file_type` is now `None` for this path.
        let inspector =
            InlineCasbInspector::with_rules(CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
                id: "block-upload-ext".to_string(),
                app_id: "slack".to_string(),
                action: CasbAction::Upload,
                verdict: CasbVerdict::Block,
                conditions: crate::casb_rules::CasbConditions {
                    file_type: Some("upload".to_string()),
                    size_threshold: None,
                    label_match: None,
                },
                priority: 1,
            }]));
        assert_eq!(
            inspector.inspect(
                &ctx("POST", "slack.com", "/api/files.upload"),
                &RequestSignals::default(),
            ),
            None,
            "dotted method name must not be mistaken for a file extension"
        );
    }

    #[test]
    fn wildcard_tail_path_derives_file_type() {
        // When the matched rule's last glob segment IS a wildcard, the
        // request path's last segment is a real filename, so the
        // extension is derived and file-type-gated rules work.
        let cat = AppCatalog::new(vec![AppSignature {
            app_id: "acme".to_string(),
            host_suffixes: vec!["acme.example".to_string()],
            path_rules: vec![PathRule::new_filename(
                Some("post"),
                "/files/*",
                CasbAction::Upload,
            )],
        }]);
        let detected = cat
            .detect(&ctx("POST", "acme.example", "/files/report.docx"))
            .expect("acme upload detected");
        assert!(
            detected.filename_in_path,
            "wildcard tail carries a filename"
        );

        let inspector = InlineCasbInspector::new(
            cat,
            CasbRuleSet::new(vec![crate::casb_rules::CasbRule {
                id: "block-docx".to_string(),
                app_id: "acme".to_string(),
                action: CasbAction::Upload,
                verdict: CasbVerdict::Block,
                conditions: crate::casb_rules::CasbConditions {
                    file_type: Some("docx".to_string()),
                    size_threshold: None,
                    label_match: None,
                },
                priority: 1,
            }]),
        );

        // A .docx upload matches the file-type-gated rule.
        let v = inspector
            .inspect(
                &ctx("POST", "acme.example", "/files/report.docx"),
                &RequestSignals::default(),
            )
            .expect("verdict");
        assert_eq!(v.action, Action::Deny);
        assert_eq!(v.reason, "deny.casb.acme.upload");

        // A .pdf upload to the same path does not match (wrong type).
        assert_eq!(
            inspector.inspect(
                &ctx("POST", "acme.example", "/files/report.pdf"),
                &RequestSignals::default(),
            ),
            None
        );
    }
}

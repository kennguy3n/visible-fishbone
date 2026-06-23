//! Clientless ZTNA — browser-based access to internal web
//! apps without an endpoint agent.
//!
//! The user's browser connects directly to the edge proxy
//! over HTTPS. The proxy authenticates via an OIDC redirect
//! flow (or accepts a validated bearer cookie), evaluates
//! the same ZTNA policy, and reverse-proxies to the
//! internal backend.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::app::App;
use crate::identity::UserIdentity;
use crate::policy::ZtnaDecision;
use crate::request::{AccessRequest, NetworkType};

/// Errors specific to the clientless ZTNA access path.
#[derive(Debug, thiserror::Error)]
pub enum ClientlessError {
    #[error("no app matches host: {host}")]
    HostNotMatched { host: String },
    #[error("no session cookie")]
    NoSession,
    #[error("session expired")]
    SessionExpired,
    #[error("session tenant {session_tenant} does not match app tenant {app_tenant}")]
    TenantMismatch { session_tenant: String, app_tenant: String },
    #[error("ztna deny: {0}")]
    Denied(String),
    #[error("ztna error: {0}")]
    ZtnaError(#[from] crate::error::ZtnaError),
}

// --- Host matching ---

/// Case-insensitive exact-match index from external FQDN
/// to `app_id`.
#[derive(Debug, Default)]
pub struct HostMatcher {
    by_host: ArcSwap<HashMap<String, String>>,
}

impl HostMatcher {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn rebuild_from_apps(&self, apps: &[App]) {
        let mut table = HashMap::new();
        for app in apps {
            for pattern in &app.host_patterns {
                table.insert(pattern.to_ascii_lowercase(), app.app_id.clone());
            }
        }
        self.by_host.store(Arc::new(table));
    }

    #[must_use]
    pub fn match_host(&self, host: &str) -> Option<String> {
        let host = host.split(':').next().unwrap_or(host);
        self.by_host.load().get(&host.to_ascii_lowercase()).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize { self.by_host.load().len() }
    #[must_use]
    pub fn is_empty(&self) -> bool { self.by_host.load().is_empty() }
}

// --- Session store ---

pub const DEFAULT_SESSION_TTL_MS: u64 = 8 * 60 * 60 * 1000;
pub const DEFAULT_SESSION_SHARDS: usize = 16;

/// One authenticated browser session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientlessSession {
    pub session_id: String,
    pub tenant_id: String,
    pub app_id: String,
    pub identity: UserIdentity,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    #[serde(default)]
    pub source_ip: Option<String>,
    #[serde(default)]
    pub network_type: Option<NetworkType>,
}

impl ClientlessSession {
    #[must_use]
    pub fn is_expired(&self, now_ms: u64) -> bool { now_ms >= self.expires_at_ms }

    #[must_use]
    pub fn to_access_request(&self, now_ms: u64) -> AccessRequest {
        AccessRequest::new(
            self.app_id.clone(),
            format!("clientless:{}", self.session_id),
            self.identity.user_id.clone(),
            now_ms,
        ).with_network(self.source_ip.clone(), None, self.network_type)
    }
}

/// Sharded, thread-safe store of browser sessions.
pub struct ClientlessSessionStore {
    shards: Vec<Mutex<HashMap<String, ClientlessSession>>>,
    ttl_ms: u64,
}

impl std::fmt::Debug for ClientlessSessionStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total: usize = self.shards.iter().map(|s| s.lock().len()).sum();
        f.debug_struct("ClientlessSessionStore")
            .field("sessions", &total)
            .field("ttl_ms", &self.ttl_ms)
            .finish_non_exhaustive()
    }
}

impl ClientlessSessionStore {
    #[must_use]
    pub fn with_ttl_and_shards(ttl_ms: u64, shards: usize) -> Self {
        let shards = shards.max(1);
        let mut vec = Vec::with_capacity(shards);
        for _ in 0..shards { vec.push(Mutex::new(HashMap::new())); }
        Self { shards: vec, ttl_ms }
    }

    #[must_use]
    pub fn new() -> Self { Self::with_ttl_and_shards(DEFAULT_SESSION_TTL_MS, DEFAULT_SESSION_SHARDS) }

    fn shard_index(&self, key: &str) -> usize {
        let mut hash: u64 = 0xcbf29ce484222325;
        for &b in key.as_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        (hash as usize) & (self.shards.len() - 1)
    }

    pub fn insert(&self, session: ClientlessSession) -> Option<ClientlessSession> {
        let idx = self.shard_index(&session.session_id);
        self.shards[idx].lock().insert(session.session_id.clone(), session)
    }

    #[must_use]
    pub fn lookup(&self, session_id: &str, now_ms: u64) -> Option<ClientlessSession> {
        let idx = self.shard_index(session_id);
        let mut shard = self.shards[idx].lock();
        let expired = shard.get(session_id).map(|s| s.is_expired(now_ms)).unwrap_or(false);
        if expired { shard.remove(session_id); return None; }
        shard.get(session_id).cloned()
    }

    pub fn remove(&self, session_id: &str) -> Option<ClientlessSession> {
        let idx = self.shard_index(session_id);
        self.shards[idx].lock().remove(session_id)
    }

    #[must_use]
    pub fn len(&self) -> usize { self.shards.iter().map(|s| s.lock().len()).sum() }
    #[must_use]
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    pub fn purge_expired(&self, now_ms: u64) -> usize {
        let mut purged = 0;
        for shard in &self.shards {
            let mut guard = shard.lock();
            let expired_ids: Vec<String> = guard.iter()
                .filter(|(_, s)| s.is_expired(now_ms))
                .map(|(k, _)| k.clone()).collect();
            for id in expired_ids { guard.remove(&id); purged += 1; }
        }
        purged
    }

    #[must_use]
    pub fn ttl_ms(&self) -> u64 { self.ttl_ms }
}

impl Default for ClientlessSessionStore {
    fn default() -> Self { Self::new() }
}

// --- Cookie generation ---

/// Generate a random 64-char hex session id (32 bytes of
/// entropy) using the operating system CSPRNG.
#[must_use]
pub fn generate_session_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let mut buf = String::with_capacity(64);
    for b in &bytes {
        buf.push_str(&format!("{:02x}", b));
    }
    buf
}

// --- Reverse proxy target ---

/// Describes how to proxy an allowed request to the
/// internal backend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyTarget {
    pub app_id: String,
    pub backend_url: String,
    #[serde(default)]
    pub strip_path_prefix: String,
    #[serde(default = "default_pass_identity_headers")]
    pub pass_identity_headers: bool,
}

fn default_pass_identity_headers() -> bool { true }

/// Hot-swappable `app_id → ProxyTarget` table.
#[derive(Debug, Default)]
pub struct ProxyTargetTable {
    by_app: ArcSwap<HashMap<String, ProxyTarget>>,
}

impl ProxyTargetTable {
    #[must_use]
    pub fn new() -> Self { Self::default() }

    pub fn install(&self, targets: Vec<ProxyTarget>) {
        let table = targets.into_iter()
            .map(|t| (t.app_id.clone(), t))
            .collect::<HashMap<_, _>>();
        self.by_app.store(Arc::new(table));
    }

    #[must_use]
    pub fn get(&self, app_id: &str) -> Option<ProxyTarget> {
        self.by_app.load().get(app_id).cloned()
    }

    #[must_use]
    pub fn len(&self) -> usize { self.by_app.load().len() }
    #[must_use]
    pub fn is_empty(&self) -> bool { self.by_app.load().is_empty() }
}

// --- Access evaluation outcome ---

/// The outcome of a clientless access evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientlessOutcome {
    /// Access granted — reverse-proxy to the backend.
    Allow {
        target: ProxyTarget,
        decision: ZtnaDecision,
        session: ClientlessSession,
    },
    /// Access denied by ZTNA policy — return 403.
    Deny { decision: ZtnaDecision },
    /// No session — redirect to IdP `/authorize`.
    RedirectToIdp { redirect_url: String },
    /// Host not matched — return 404.
    HostNotFound,
}

// --- Clientless access evaluator ---

/// The clientless ZTNA access evaluator. Wires together
/// host matching, session lookup, ZTNA policy evaluation,
/// and reverse-proxy routing.
pub struct ClientlessEvaluator {
    host_matcher: HostMatcher,
    sessions: ClientlessSessionStore,
    targets: ProxyTargetTable,
    service: Arc<crate::service::ZtnaService>,
    idp_authorize_url: String,
}

impl std::fmt::Debug for ClientlessEvaluator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientlessEvaluator")
            .field("host_patterns", &self.host_matcher.len())
            .field("sessions", &self.sessions.len())
            .field("targets", &self.targets.len())
            .finish_non_exhaustive()
    }
}

impl ClientlessEvaluator {
    #[must_use]
    pub fn new(
        service: Arc<crate::service::ZtnaService>,
        idp_authorize_url: String,
    ) -> Self {
        Self {
            host_matcher: HostMatcher::new(),
            sessions: ClientlessSessionStore::new(),
            targets: ProxyTargetTable::new(),
            service,
            idp_authorize_url,
        }
    }

    pub fn rebuild_hosts(&self, apps: &[App]) {
        self.host_matcher.rebuild_from_apps(apps);
    }

    pub fn install_targets(&self, targets: Vec<ProxyTarget>) {
        self.targets.install(targets);
    }

    #[must_use]
    pub fn sessions(&self) -> &ClientlessSessionStore { &self.sessions }
    #[must_use]
    pub fn host_matcher(&self) -> &HostMatcher { &self.host_matcher }
    #[must_use]
    pub fn targets(&self) -> &ProxyTargetTable { &self.targets }

    /// Evaluate a clientless access request. **Sync** — no I/O.
    #[must_use]
    pub fn evaluate(
        &self,
        host: &str,
        _path: &str,
        cookie: Option<&str>,
        now_ms: u64,
        redirect_uri: &str,
    ) -> ClientlessOutcome {
        // 1. Resolve host → app_id.
        let app_id = match self.host_matcher.match_host(host) {
            Some(id) => id,
            None => return ClientlessOutcome::HostNotFound,
        };

        // 2. Look up session.
        let session = cookie
            .and_then(|sid| self.sessions.lookup(sid, now_ms))
            .filter(|s| s.app_id == app_id);

        let session = match session {
            Some(s) => s,
            None => {
                let url = self.idp_authorize_url
                    .replace("{redirect_uri}", &url_encode(redirect_uri));
                return ClientlessOutcome::RedirectToIdp { redirect_url: url };
            }
        };

        // 3. Build AccessRequest and evaluate ZTNA policy.
        let req = session.to_access_request(now_ms);
        let decision = match self.service.evaluate(&req) {
            Ok(d) => d,
            Err(e) => {
                return ClientlessOutcome::Deny {
                    decision: ZtnaDecision {
                        allow: false,
                        reason: e.as_decision_reason(),
                        posture_result: crate::policy::PostureResult::NotEvaluated,
                    },
                };
            }
        };

        if !decision.allow {
            self.sessions.remove(&session.session_id);
            return ClientlessOutcome::Deny { decision };
        }

        // 4. Look up proxy target.
        let target = match self.targets.get(&app_id) {
            Some(t) => t,
            None => return ClientlessOutcome::HostNotFound,
        };

        ClientlessOutcome::Allow { target, decision, session }
    }

    /// Create a new session after a successful OIDC callback.
    #[must_use]
    pub fn create_session(
        &self,
        tenant_id: impl Into<String>,
        app_id: impl Into<String>,
        identity: UserIdentity,
        now_ms: u64,
        source_ip: Option<String>,
        network_type: Option<NetworkType>,
    ) -> ClientlessSession {
        let session = ClientlessSession {
            session_id: generate_session_id(),
            tenant_id: tenant_id.into(),
            app_id: app_id.into(),
            identity,
            created_at_ms: now_ms,
            expires_at_ms: now_ms + self.sessions.ttl_ms,
            source_ip,
            network_type,
        };
        self.sessions.insert(session.clone());
        session
    }

    /// Logout: remove a session by cookie value.
    pub fn logout(&self, session_id: &str) -> Option<ClientlessSession> {
        self.sessions.remove(session_id)
    }

    /// Purge expired sessions. Returns the count purged.
    pub fn purge_expired(&self, now_ms: u64) -> usize {
        self.sessions.purge_expired(now_ms)
    }
}

// --- URL encoding ---

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for &b in input.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

// --- Cookie header rendering ---

/// Render a `Set-Cookie` header for a clientless session.
#[must_use]
pub fn render_set_cookie(session: &ClientlessSession, cookie_name: &str) -> String {
    let expires = ms_to_http_date(session.expires_at_ms);
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires={}",
        cookie_name, session.session_id, expires,
    )
}

/// Render a `Set-Cookie` header that deletes the cookie.
#[must_use]
pub fn render_clear_cookie(cookie_name: &str) -> String {
    format!(
        "{}=; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        cookie_name,
    )
}

fn ms_to_http_date(ms: u64) -> String {
    use chrono::{DateTime, Utc};
    let dt = DateTime::<Utc>::from_timestamp((ms / 1000) as i64, 0)
        .unwrap_or(DateTime::<Utc>::from_timestamp(0, 0).unwrap());
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{App, StaticAppCatalog};
    use crate::identity::UserIdentity;
    use crate::policy::{PostureRequirement, ZtnaPolicy};
    use crate::service::{ZtnaServiceBuilder, ZtnaServiceConfig};
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn make_service() -> std::sync::Arc<crate::service::ZtnaService> {
        let cfg = ZtnaServiceConfig {
            max_sessions: 100,
            ..Default::default()
        };
        let builder = ZtnaServiceBuilder::new().with_config(cfg);
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        std::sync::Arc::new(builder.build(tx))
    }

    fn make_identity() -> UserIdentity {
        UserIdentity {
            user_id: "alice".into(),
            tenant_id: "acme".into(),
            groups: HashSet::from(["engineering".into()]),
            mfa_at_ms: 1000,
            tags: Default::default(),
        }
    }

    fn make_app(app_id: &str, host: &str) -> App {
        let mut app = App::new(app_id, app_id);
        app.host_patterns = vec![host.into()];
        app.required_groups = HashSet::from(["engineering".into()]);
        app.posture_requirement = PostureRequirement::NONE;
        app
    }

    #[test]
    fn host_matcher_resolves_exact() {
        let m = HostMatcher::new();
        m.rebuild_from_apps(&[make_app("wiki", "wiki.acme.internal")]);
        assert_eq!(m.match_host("wiki.acme.internal"), Some("wiki".into()));
        assert_eq!(m.match_host("WIKI.ACME.INTERNAL"), Some("wiki".into()));
        assert_eq!(m.match_host("wiki.acme.internal:8443"), Some("wiki".into()));
        assert_eq!(m.match_host("other.com"), None);
    }

    #[test]
    fn host_matcher_empty_returns_none() {
        let m = HostMatcher::new();
        assert_eq!(m.match_host("anything"), None);
        assert!(m.is_empty());
    }

    #[test]
    fn session_store_insert_and_lookup() {
        let store = ClientlessSessionStore::new();
        let session = ClientlessSession {
            session_id: "test-sid".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 1000,
            expires_at_ms: 1000 + DEFAULT_SESSION_TTL_MS,
            source_ip: None,
            network_type: None,
        };
        store.insert(session.clone());
        let found = store.lookup("test-sid", 2000).unwrap();
        assert_eq!(found.session_id, "test-sid");
        assert_eq!(found.identity.user_id, "alice");
    }

    #[test]
    fn session_store_expired_returns_none() {
        let store = ClientlessSessionStore::with_ttl_and_shards(100, 4);
        let session = ClientlessSession {
            session_id: "short-lived".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 1000,
            expires_at_ms: 1100,
            source_ip: None,
            network_type: None,
        };
        store.insert(session);
        assert!(store.lookup("short-lived", 1200).is_none());
        // Entry should be lazily removed.
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn session_store_remove() {
        let store = ClientlessSessionStore::new();
        let session = ClientlessSession {
            session_id: "removable".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 1000,
            expires_at_ms: 9999_999_999,
            source_ip: None,
            network_type: None,
        };
        store.insert(session);
        assert!(store.remove("removable").is_some());
        assert!(store.lookup("removable", 1000).is_none());
    }

    #[test]
    fn session_store_purge_expired() {
        let store = ClientlessSessionStore::with_ttl_and_shards(100, 4);
        for i in 0..10 {
            let sid = format!("sid-{}", i);
            store.insert(ClientlessSession {
                session_id: sid,
                tenant_id: "acme".into(),
                app_id: "wiki".into(),
                identity: make_identity(),
                created_at_ms: 1000,
                expires_at_ms: if i < 5 { 1050 } else { 9999_999_999 },
                source_ip: None,
                network_type: None,
            });
        }
        assert_eq!(store.len(), 10);
        let purged = store.purge_expired(1100);
        assert_eq!(purged, 5);
        assert_eq!(store.len(), 5);
    }

    #[test]
    fn session_to_access_request_stamps_now() {
        let session = ClientlessSession {
            session_id: "sid".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 1000,
            expires_at_ms: 2000,
            source_ip: Some("10.0.0.1".into()),
            network_type: Some(NetworkType::Corporate),
        };
        let req = session.to_access_request(5000);
        assert_eq!(req.app_id, "wiki");
        assert_eq!(req.user_id, "alice");
        assert_eq!(req.now_ms, 5000);
        assert_eq!(req.source_ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(req.network_type, Some(NetworkType::Corporate));
        assert!(req.device_id.starts_with("clientless:"));
    }

    #[test]
    fn proxy_target_table_install_and_get() {
        let t = ProxyTargetTable::new();
        t.install(vec![ProxyTarget {
            app_id: "wiki".into(),
            backend_url: "http://wiki.internal:8080".into(),
            strip_path_prefix: "/wiki".into(),
            pass_identity_headers: true,
        }]);
        let target = t.get("wiki").unwrap();
        assert_eq!(target.backend_url, "http://wiki.internal:8080");
        assert_eq!(target.strip_path_prefix, "/wiki");
        assert!(t.get("missing").is_none());
    }

    #[test]
    fn url_encode_encodes_special() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a/b?c=d"), "a%2Fb%3Fc%3Dd");
        assert_eq!(url_encode("safe-_.~"), "safe-_.~");
    }

    #[test]
    fn render_set_cookie_format() {
        let session = ClientlessSession {
            session_id: "abc123".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 0,
            expires_at_ms: 0,
            source_ip: None,
            network_type: None,
        };
        let cookie = render_set_cookie(&session, "sng_session");
        assert!(cookie.starts_with("sng_session=abc123;"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Strict"));
    }

    #[test]
    fn render_clear_cookie_format() {
        let cookie = render_clear_cookie("sng_session");
        assert!(cookie.contains("sng_session=;"));
        assert!(cookie.contains("1970"));
    }

    #[test]
    fn generate_session_id_is_64_hex() {
        let id = generate_session_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ms_to_http_date_epoch() {
        // 0 ms → Thursday, 1 Jan 1970 00:00:00 GMT
        let date = ms_to_http_date(0);
        assert_eq!(date, "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn ms_to_http_date_known() {
        // 2024-01-01 00:00:00 UTC = 1704067200 seconds
        let ms = 1704067200 * 1000;
        let date = ms_to_http_date(ms);
        assert_eq!(date, "Mon, 01 Jan 2024 00:00:00 GMT");
    }

    // --- Integration tests with ZtnaService ---

    fn make_evaluator() -> ClientlessEvaluator {
        let service = make_service();
        let eval = ClientlessEvaluator::new(
            service,
            "https://idp.example.com/authorize?redirect_uri={redirect_uri}".into(),
        );
        eval.rebuild_hosts(&[make_app("wiki", "wiki.acme.internal")]);
        eval.install_targets(vec![ProxyTarget {
            app_id: "wiki".into(),
            backend_url: "http://wiki.internal:8080".into(),
            strip_path_prefix: String::new(),
            pass_identity_headers: true,
        }]);
        eval
    }

    #[test]
    fn evaluate_host_not_found() {
        let eval = make_evaluator();
        let outcome = eval.evaluate("unknown.com", "/", None, 1000, "https://unknown.com/");
        assert_eq!(outcome, ClientlessOutcome::HostNotFound);
    }

    #[test]
    fn evaluate_no_cookie_redirects_to_idp() {
        let eval = make_evaluator();
        let outcome = eval.evaluate("wiki.acme.internal", "/", None, 1000, "https://wiki.acme.internal/");
        match outcome {
            ClientlessOutcome::RedirectToIdp { redirect_url } => {
                assert!(redirect_url.starts_with("https://idp.example.com/authorize"));
                assert!(redirect_url.contains("redirect_uri="));
                assert!(redirect_url.contains("https%3A%2F%2Fwiki.acme.internal%2F"));
            }
            _ => panic!("expected RedirectToIdp, got {:?}", outcome),
        }
    }

    #[test]
    fn evaluate_with_session_but_unknown_app_denies() {
        let eval = make_evaluator();
        // Insert a session for an app that has no target.
        let session = eval.create_session(
            "acme", "nonexistent", make_identity(), 1000, None, None,
        );
        // Host doesn't match → HostNotFound (session is irrelevant).
        let outcome = eval.evaluate("wiki.acme.internal", "/", Some(&session.session_id), 2000, "");
        // The session is for "nonexistent" but host resolves to "wiki".
        // Session.app_id != app_id → treated as no session → redirect.
        match outcome {
            ClientlessOutcome::RedirectToIdp { .. } => {}
            _ => panic!("expected RedirectToIdp, got {:?}", outcome),
        }
    }

    #[test]
    fn evaluate_expired_session_redirects() {
        let eval = make_evaluator();
        let session = eval.create_session(
            "acme", "wiki", make_identity(), 1000, None, None,
        );
        // Advance past expiry.
        let outcome = eval.evaluate(
            "wiki.acme.internal", "/", Some(&session.session_id),
            1000 + DEFAULT_SESSION_TTL_MS + 1, "",
        );
        match outcome {
            ClientlessOutcome::RedirectToIdp { .. } => {}
            _ => panic!("expected RedirectToIdp, got {:?}", outcome),
        }
    }

    #[test]
    fn evaluate_logout_removes_session() {
        let eval = make_evaluator();
        let session = eval.create_session(
            "acme", "wiki", make_identity(), 1000, None, None,
        );
        assert!(eval.logout(&session.session_id).is_some());
        assert!(eval.sessions().lookup(&session.session_id, 2000).is_none());
    }

    #[test]
    fn evaluate_purge_expired() {
        let eval = ClientlessEvaluator::new(
            make_service(),
            "https://idp/authorize?redirect_uri={redirect_uri}".into(),
        );
        // Create a store with short TTL.
        let short_store = ClientlessSessionStore::with_ttl_and_shards(100, 4);
        // Insert directly.
        short_store.insert(ClientlessSession {
            session_id: "old".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 1000,
            expires_at_ms: 1050,
            source_ip: None,
            network_type: None,
        });
        short_store.insert(ClientlessSession {
            session_id: "new".into(),
            tenant_id: "acme".into(),
            app_id: "wiki".into(),
            identity: make_identity(),
            created_at_ms: 1000,
            expires_at_ms: 9999_999_999,
            source_ip: None,
            network_type: None,
        });
        assert_eq!(short_store.purge_expired(1100), 1);
        assert!(short_store.lookup("old", 1100).is_none());
        assert!(short_store.lookup("new", 1100).is_some());
    }
}

//! SWG orchestrator.
//!
//! [`SwgService`] is the brain Envoy / sng-edge talks to
//! per HTTP transaction. The flow:
//!
//! 1. Producer calls [`SwgService::observe`] with an
//!    [`crate::request::HttpObservation`].
//! 2. Service resolves the effective host (URL > Host >
//!    SNI), looks up the category and reputation through
//!    the configured providers.
//! 3. On a `Response` phase observation with a known
//!    sha256, the service consults the malware provider.
//! 4. Service runs the inputs through the
//!    [`crate::policy::SwgPolicyHolder`] to produce a
//!    [`crate::policy::Posture`].
//! 5. Service maps the posture to an
//!    [`sng_core::envelope::Verdict`] and emits one
//!    [`sng_core::events::HttpEvent`] through the
//!    telemetry channel — `try_send`, never blocking.
//! 6. Service returns [`SwgDecision`] to the producer
//!    (verdict + posture + category + reputation).
//!
//! The whole call is **sync** — no I/O. The category /
//! reputation / malware providers are expected to do
//! their I/O off the request path (downloader tasks
//! refresh in-process tables; producer-side caches sit
//! in front of remote APIs).

use crate::category::{Category, CategoryProvider, StaticCategoryProvider};
use crate::error::SwgError;
use crate::malware::{MalwareProvider, MalwareVerdict, ScanRequest, StaticMalwareProvider};
use crate::policy::{DecisionInputs, Posture, SwgPolicy, SwgPolicyHolder, evaluate_policy};
use crate::reputation::{ReputationProvider, ReputationScore, StaticReputationProvider};
use crate::request::{HttpObservation, ObservationPhase};
use crate::stats::SwgStats;
use sng_core::envelope::Verdict;
use sng_core::events::HttpEvent;
use sng_telemetry::TelemetryEvent;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Decision returned to the producer.
#[derive(Clone, Debug, PartialEq)]
pub struct SwgDecision {
    /// Wire verdict for the data path. Derived from
    /// [`Self::posture`].
    pub verdict: Verdict,
    /// SWG-specific posture. Carries the TLS-bypass /
    /// inspect-full distinction that the wire `Verdict`
    /// collapses.
    pub posture: Posture,
    /// Category the request was matched against.
    pub category: Category,
    /// Reputation score, when the provider had one.
    pub reputation: Option<ReputationScore>,
    /// Malware verdict, when one was produced.
    pub malware: Option<MalwareVerdict>,
}

impl SwgDecision {
    /// True when the data path should block the
    /// transaction. The producer pairs this with the
    /// posture to decide what HTML / error to surface.
    #[must_use]
    pub const fn should_block(&self) -> bool {
        self.posture.is_blocking()
    }
}

/// Map a posture to a wire verdict.
#[must_use]
pub const fn posture_to_verdict(posture: Posture) -> Verdict {
    match posture {
        Posture::Allow | Posture::TlsBypass => Verdict::Allow,
        Posture::AlertOnly => Verdict::Alert,
        Posture::InspectFull => Verdict::Inspect,
        Posture::Quarantine | Posture::Block => Verdict::Deny,
    }
}

/// Configuration for [`SwgService`].
#[derive(Clone, Debug)]
pub struct SwgServiceConfig {
    /// Maximum number of concurrent SWG sessions. The
    /// brain itself doesn't hold session state, but the
    /// counter is plumbed through so the producer can
    /// shed load when it sees the bucket fill.
    pub max_sessions: usize,
}

impl Default for SwgServiceConfig {
    fn default() -> Self {
        Self {
            max_sessions: 131_072,
        }
    }
}

/// Builder for [`SwgService`].
#[allow(missing_debug_implementations)]
pub struct SwgServiceBuilder {
    cfg: SwgServiceConfig,
    policy: Arc<SwgPolicyHolder>,
    category: Arc<dyn CategoryProvider>,
    reputation: Arc<dyn ReputationProvider>,
    malware: Arc<dyn MalwareProvider>,
    stats: Arc<SwgStats>,
}

impl SwgServiceBuilder {
    /// Initialise a builder with default providers
    /// (empty in-memory tables) and default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfg: SwgServiceConfig::default(),
            policy: Arc::new(SwgPolicyHolder::default()),
            category: Arc::new(StaticCategoryProvider::new()),
            reputation: Arc::new(StaticReputationProvider::new()),
            malware: Arc::new(StaticMalwareProvider::new()),
            stats: Arc::new(SwgStats::default()),
        }
    }

    /// Override the config.
    #[must_use]
    pub fn with_config(mut self, cfg: SwgServiceConfig) -> Self {
        self.cfg = cfg;
        self
    }

    /// Override the policy holder.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<SwgPolicyHolder>) -> Self {
        self.policy = policy;
        self
    }

    /// Override the category provider.
    #[must_use]
    pub fn with_category_provider(mut self, p: Arc<dyn CategoryProvider>) -> Self {
        self.category = p;
        self
    }

    /// Override the reputation provider.
    #[must_use]
    pub fn with_reputation_provider(mut self, p: Arc<dyn ReputationProvider>) -> Self {
        self.reputation = p;
        self
    }

    /// Override the malware provider.
    #[must_use]
    pub fn with_malware_provider(mut self, p: Arc<dyn MalwareProvider>) -> Self {
        self.malware = p;
        self
    }

    /// Override the stats handle (shared with peers).
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<SwgStats>) -> Self {
        self.stats = stats;
        self
    }

    /// Build the service. `telemetry` is the egress
    /// channel — alerts and per-request events are
    /// `try_send` here.
    #[must_use]
    pub fn build(self, telemetry: mpsc::Sender<TelemetryEvent>) -> SwgService {
        SwgService {
            cfg: self.cfg,
            policy: self.policy,
            category: self.category,
            reputation: self.reputation,
            malware: self.malware,
            stats: self.stats,
            telemetry,
        }
    }
}

impl Default for SwgServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The SWG service. Cheap to share via [`Arc`] — every
/// internal handle is itself clone-cheap.
#[derive(Clone)]
pub struct SwgService {
    cfg: SwgServiceConfig,
    policy: Arc<SwgPolicyHolder>,
    category: Arc<dyn CategoryProvider>,
    reputation: Arc<dyn ReputationProvider>,
    malware: Arc<dyn MalwareProvider>,
    stats: Arc<SwgStats>,
    telemetry: mpsc::Sender<TelemetryEvent>,
}

impl std::fmt::Debug for SwgService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SwgService")
            .field("cfg", &self.cfg)
            .field("policy", &"<policy>")
            .field("category", &"<provider>")
            .field("reputation", &"<provider>")
            .field("malware", &"<provider>")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl SwgService {
    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<SwgStats> {
        &self.stats
    }

    /// Policy holder.
    #[must_use]
    pub fn policy(&self) -> &Arc<SwgPolicyHolder> {
        &self.policy
    }

    /// Reload the active SWG policy. The compile step is
    /// trivial for the SWG (the policy is data, not
    /// patterns), so this is an unconditional success.
    pub fn reload_policy(&self, policy: SwgPolicy) {
        self.policy.replace(policy);
        self.stats.record_bundle_load();
    }

    /// Configured max session count — surfaced for the
    /// producer's shed-load logic.
    #[must_use]
    pub fn max_sessions(&self) -> usize {
        self.cfg.max_sessions
    }

    /// Inspect one HTTP observation.
    ///
    /// # Errors
    ///
    /// - [`SwgError::InvalidUrl`] when neither the URL,
    ///   the Host header, nor SNI yields a usable host.
    pub fn observe(&self, obs: &HttpObservation) -> Result<SwgDecision, SwgError> {
        self.stats.record_request_observed(obs.response_bytes);

        let host = obs.effective_host()?;
        let category = if let Some(c) = self.category.category_for(&host) {
            self.stats.record_category_lookup(true);
            c
        } else {
            self.stats.record_category_lookup(false);
            Category::Uncategorised
        };
        let reputation = if let Some(s) = self.reputation.score_for(&host) {
            self.stats.record_reputation_lookup(true);
            Some(s)
        } else {
            self.stats.record_reputation_lookup(false);
            None
        };
        let malware = if matches!(obs.phase, ObservationPhase::Response) {
            obs.response_sha256.as_deref().and_then(|sha| {
                let scan = ScanRequest {
                    sha256: sha,
                    content_type: obs.content_type.as_deref(),
                };
                let v = self.malware.scan(&scan);
                if let Some(verdict) = v {
                    self.stats.record_malware(verdict);
                }
                v
            })
        } else {
            None
        };

        let inputs = DecisionInputs {
            category,
            reputation,
            malware,
        };
        let policy = self.policy.snapshot();
        let posture = evaluate_policy(&policy, inputs);
        self.stats.record_posture(posture);

        let verdict = posture_to_verdict(posture);
        let event = build_http_event(obs, &host, verdict);
        if self
            .telemetry
            .try_send(TelemetryEvent::Http(event))
            .is_err()
        {
            self.stats.record_telemetry_drop();
        }

        Ok(SwgDecision {
            verdict,
            posture,
            category,
            reputation,
            malware,
        })
    }
}

fn build_http_event(obs: &HttpObservation, host: &str, verdict: Verdict) -> HttpEvent {
    HttpEvent {
        method: obs.method.clone(),
        url: obs.url.clone(),
        host: host.to_string(),
        status_code: obs.status_code.unwrap_or(0),
        verdict,
        tls_version: obs.tls_version.clone(),
        sni: obs.sni.clone(),
        content_type: obs.content_type.clone(),
        bytes: if obs.response_bytes > 0 {
            Some(obs.response_bytes)
        } else {
            None
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::malware::{MalwareVerdict, StaticMalwareProvider};
    use crate::reputation::ReputationScore;
    use pretty_assertions::assert_eq;
    use std::collections::HashMap;
    use std::net::IpAddr;

    fn obs(url: &str) -> HttpObservation {
        HttpObservation {
            session_id: 1,
            client_ip: IpAddr::from([10, 0, 0, 1]),
            server_ip: IpAddr::from([10, 0, 0, 2]),
            method: "GET".into(),
            url: url.into(),
            host: String::new(),
            sni: None,
            tls_version: None,
            phase: ObservationPhase::Request,
            status_code: None,
            content_type: None,
            response_sha256: None,
            response_bytes: 0,
            now_ms: 1_000,
        }
    }

    fn mk_service_with(
        cat_entries: &[(&str, Category)],
        rep_entries: &[(&str, f32)],
    ) -> (SwgService, mpsc::Receiver<TelemetryEvent>) {
        let mut cat = HashMap::new();
        for (k, v) in cat_entries {
            cat.insert((*k).to_string(), *v);
        }
        let mut rep = HashMap::new();
        for (k, v) in rep_entries {
            rep.insert((*k).to_string(), ReputationScore::new(*v));
        }
        let (tx, rx) = mpsc::channel(64);
        let svc = SwgServiceBuilder::new()
            .with_category_provider(Arc::new(StaticCategoryProvider::from_table(cat)))
            .with_reputation_provider(Arc::new(StaticReputationProvider::from_table(rep)))
            .build(tx);
        (svc, rx)
    }

    #[test]
    fn unknown_host_uses_uncategorised_inspect_full() {
        let (svc, mut rx) = mk_service_with(&[], &[]);
        let d = svc.observe(&obs("https://unknown.example/")).unwrap();
        assert_eq!(d.category, Category::Uncategorised);
        assert_eq!(d.posture, Posture::InspectFull);
        assert_eq!(d.verdict, Verdict::Inspect);
        let ev = rx.try_recv().unwrap();
        match ev {
            TelemetryEvent::Http(e) => {
                assert_eq!(e.host, "unknown.example");
                assert_eq!(e.verdict, Verdict::Inspect);
            }
            _ => panic!("expected Http event"),
        }
    }

    #[test]
    fn business_category_allows_request() {
        let (svc, mut rx) = mk_service_with(&[("trustedsaas.example", Category::Business)], &[]);
        let d = svc.observe(&obs("https://trustedsaas.example/")).unwrap();
        assert_eq!(d.category, Category::Business);
        assert_eq!(d.posture, Posture::Allow);
        assert_eq!(d.verdict, Verdict::Allow);
        let _ev = rx.try_recv().unwrap();
    }

    #[test]
    fn malware_category_blocks_request() {
        let (svc, mut rx) = mk_service_with(&[("evil.example", Category::Malware)], &[]);
        let d = svc.observe(&obs("https://evil.example/payload")).unwrap();
        assert_eq!(d.posture, Posture::Block);
        assert_eq!(d.verdict, Verdict::Deny);
        assert!(d.should_block());
        let _ev = rx.try_recv().unwrap();
    }

    #[test]
    fn sensitive_category_emits_tls_bypass_as_allow_verdict() {
        let (svc, _rx) = mk_service_with(&[("bank.example", Category::Sensitive)], &[]);
        let d = svc.observe(&obs("https://bank.example/login")).unwrap();
        assert_eq!(d.posture, Posture::TlsBypass);
        // Wire verdict collapses TlsBypass to Allow —
        // the posture carries the bypass detail.
        assert_eq!(d.verdict, Verdict::Allow);
    }

    #[test]
    fn high_reputation_upgrades_business_to_block() {
        let (svc, _rx) = mk_service_with(
            &[("hot.example", Category::Business)],
            &[("hot.example", 0.99)],
        );
        let d = svc.observe(&obs("https://hot.example/")).unwrap();
        assert_eq!(d.posture, Posture::Block);
        assert_eq!(d.reputation.map(ReputationScore::value), Some(0.99));
    }

    #[test]
    fn medium_reputation_upgrades_allow_to_inspect_full() {
        let (svc, _rx) = mk_service_with(
            &[("warm.example", Category::Business)],
            &[("warm.example", 0.6)],
        );
        let d = svc.observe(&obs("https://warm.example/")).unwrap();
        assert_eq!(d.posture, Posture::InspectFull);
    }

    #[test]
    fn malware_verdict_on_response_blocks_request() {
        let mut o = obs("https://saas.example/download");
        o.phase = ObservationPhase::Response;
        o.response_sha256 = Some("deadbeef".into());
        o.status_code = Some(200);
        let cat = vec![("saas.example", Category::Business)];
        let (svc, _rx) = {
            let (tx, rx) = mpsc::channel(64);
            let mw = StaticMalwareProvider::new();
            mw.record("deadbeef", MalwareVerdict::Malicious);
            let mut cat_map = HashMap::new();
            for (k, v) in cat.iter() {
                cat_map.insert((*k).to_string(), *v);
            }
            let svc = SwgServiceBuilder::new()
                .with_category_provider(Arc::new(StaticCategoryProvider::from_table(cat_map)))
                .with_malware_provider(Arc::new(mw))
                .build(tx);
            (svc, rx)
        };
        let d = svc.observe(&o).unwrap();
        assert_eq!(d.posture, Posture::Block);
        assert_eq!(d.malware, Some(MalwareVerdict::Malicious));
    }

    #[test]
    fn suspicious_malware_on_response_quarantines_allow() {
        let mut o = obs("https://saas.example/download");
        o.phase = ObservationPhase::Response;
        o.response_sha256 = Some("ABCDEF".into());
        o.status_code = Some(200);
        let mw = StaticMalwareProvider::new();
        mw.record("abcdef", MalwareVerdict::Suspicious);
        let mut cat = HashMap::new();
        cat.insert("saas.example".into(), Category::Business);
        let (tx, _rx) = mpsc::channel(64);
        let svc = SwgServiceBuilder::new()
            .with_category_provider(Arc::new(StaticCategoryProvider::from_table(cat)))
            .with_malware_provider(Arc::new(mw))
            .build(tx);
        let d = svc.observe(&o).unwrap();
        assert_eq!(d.posture, Posture::Quarantine);
    }

    #[test]
    fn request_phase_does_not_consult_malware_provider() {
        let mw = StaticMalwareProvider::new();
        mw.record("zzz", MalwareVerdict::Malicious);
        let mut cat = HashMap::new();
        cat.insert("saas.example".into(), Category::Business);
        let (tx, _rx) = mpsc::channel(64);
        let svc = SwgServiceBuilder::new()
            .with_category_provider(Arc::new(StaticCategoryProvider::from_table(cat)))
            .with_malware_provider(Arc::new(mw))
            .build(tx);
        let mut o = obs("https://saas.example/");
        o.phase = ObservationPhase::Request;
        o.response_sha256 = Some("zzz".into());
        let d = svc.observe(&o).unwrap();
        // Malware is `None` because phase is Request.
        assert_eq!(d.malware, None);
        assert_eq!(d.posture, Posture::Allow);
    }

    #[test]
    fn invalid_url_returns_error() {
        let (svc, _rx) = mk_service_with(&[], &[]);
        let e = svc.observe(&obs("not a url")).unwrap_err();
        assert!(matches!(e, SwgError::InvalidUrl(_)));
    }

    #[test]
    fn host_header_fallback_yields_decision_when_url_lacks_host() {
        let (svc, _rx) = mk_service_with(&[("header.example", Category::Business)], &[]);
        let mut o = obs("data:,hello");
        o.host = "header.example".into();
        let d = svc.observe(&o).unwrap();
        assert_eq!(d.category, Category::Business);
        assert_eq!(d.posture, Posture::Allow);
    }

    #[test]
    fn telemetry_full_records_drop_counter() {
        let mut cat = HashMap::new();
        cat.insert("saas.example".into(), Category::Business);
        let (tx, rx) = mpsc::channel(1);
        // Pre-fill the channel.
        tx.try_send(TelemetryEvent::Http(HttpEvent {
            method: "GET".into(),
            url: "https://pad.example".into(),
            host: "pad.example".into(),
            status_code: 0,
            verdict: Verdict::Allow,
            tls_version: None,
            sni: None,
            content_type: None,
            bytes: None,
        }))
        .unwrap();
        let svc = SwgServiceBuilder::new()
            .with_category_provider(Arc::new(StaticCategoryProvider::from_table(cat)))
            .build(tx);
        let _ = svc.observe(&obs("https://saas.example/")).unwrap();
        assert_eq!(svc.stats.snapshot().telemetry_drops, 1);
        drop(rx);
    }

    #[test]
    fn reload_policy_swaps_active_set_and_records_counter() {
        let (svc, _rx) = mk_service_with(&[("saas.example", Category::Business)], &[]);
        // Default policy allows Business.
        let d = svc.observe(&obs("https://saas.example/")).unwrap();
        assert_eq!(d.posture, Posture::Allow);
        // Replace with a stricter policy that blocks
        // Business.
        let mut strict = SwgPolicy::default();
        strict
            .by_category
            .insert(Category::Business, Posture::Block);
        svc.reload_policy(strict);
        let d = svc.observe(&obs("https://saas.example/")).unwrap();
        assert_eq!(d.posture, Posture::Block);
        assert_eq!(svc.stats.snapshot().bundle_loads, 1);
    }

    #[test]
    fn posture_to_verdict_mapping_is_total() {
        assert_eq!(posture_to_verdict(Posture::Allow), Verdict::Allow);
        assert_eq!(posture_to_verdict(Posture::AlertOnly), Verdict::Alert);
        assert_eq!(posture_to_verdict(Posture::InspectFull), Verdict::Inspect);
        assert_eq!(posture_to_verdict(Posture::TlsBypass), Verdict::Allow);
        assert_eq!(posture_to_verdict(Posture::Quarantine), Verdict::Deny);
        assert_eq!(posture_to_verdict(Posture::Block), Verdict::Deny);
    }

    #[test]
    fn max_sessions_returns_configured_value() {
        let (tx, _rx) = mpsc::channel(64);
        let svc = SwgServiceBuilder::new()
            .with_config(SwgServiceConfig { max_sessions: 1234 })
            .build(tx);
        assert_eq!(svc.max_sessions(), 1234);
    }
}

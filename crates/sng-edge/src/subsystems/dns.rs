// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! DNS service subsystem adapter.
//!
//! Wraps a [`sng_dns::DnsService`] built around a fixed
//! reputation → category → sinkhole filter chain. The
//! subsystem's background task is an mtime-watcher on the
//! operator-supplied reputation file: when the file's mtime
//! advances, the task reloads the [`sng_dns::Reputation`]
//! filter atomically via [`sng_dns::Reputation::replace_entries`].
//!
//! The actual UDP DNS listener is intentionally out-of-scope
//! for this PR — the wire-side response encoder is not yet in
//! the `sng-dns` library (only the upstream-query encoder is).
//! Other subsystems and the future listener invoke the held
//! [`sng_dns::DnsService`] via [`DnsSubsystem::service`].

use crate::config::DnsConfig;
use async_trait::async_trait;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_dns::{
    AppliedFeed, Category, CategoryAction, DnsService, FeedBundleError, FeedVerifier, FilterChain,
    ManagedFeedApplier, Reputation, Resolver, SignedFeedBundle, Sinkhole, StaticResolver,
};
use sng_telemetry::TelemetryEvent;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;
use tokio::sync::mpsc;
use tokio::task;

/// Edge-tier DNS subsystem.
pub struct DnsSubsystem<R: Resolver = StaticResolver> {
    service: Arc<DnsService<R>>,
    reputation: Arc<Reputation>,
    category: Arc<Category>,
    reputation_file: Option<PathBuf>,
    refresh_interval: std::time::Duration,
    reloads_total: Arc<AtomicU64>,
    reload_failures: Arc<AtomicU64>,
    entries_loaded: Arc<AtomicU64>,
    // Managed signed-bundle consumer seam. `applier` is None unless the
    // operator pinned at least one verifying key (DEFAULT-OFF), in which
    // case apply_feed_bundle is a no-op error. `category_actions` is the
    // operator's per-category disposition applied at swap time.
    applier: Option<Arc<ManagedFeedApplier>>,
    category_actions: HashMap<String, CategoryAction>,
    feeds_applied: Arc<AtomicU64>,
    feed_apply_failures: Arc<AtomicU64>,
}

impl<R: Resolver> std::fmt::Debug for DnsSubsystem<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `service` and `reputation` are not surfaced — both
        // hold large internal caches that aren't safe to dump
        // into a debug log. `finish_non_exhaustive` signals the
        // omission to readers and silences the
        // `clippy::missing_fields_in_debug` lint.
        f.debug_struct("DnsSubsystem")
            .field("reputation_file", &self.reputation_file)
            .field("refresh_interval", &self.refresh_interval)
            .field("reloads_total", &self.reloads_total.load(Ordering::Relaxed))
            .field(
                "reload_failures",
                &self.reload_failures.load(Ordering::Relaxed),
            )
            .field(
                "entries_loaded",
                &self.entries_loaded.load(Ordering::Relaxed),
            )
            .field("managed_feed", &self.applier.is_some())
            .field("feeds_applied", &self.feeds_applied.load(Ordering::Relaxed))
            .field(
                "feed_apply_failures",
                &self.feed_apply_failures.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl DnsSubsystem<StaticResolver> {
    /// Build a subsystem with the canonical edge filter chain:
    /// reputation → category → sinkhole. The reputation set
    /// starts empty (refreshed from disk on the first tick of
    /// the background task); the category DB starts empty
    /// (populated by a future control-plane puller); the
    /// sinkhole is constructed with no entries but the
    /// operator-supplied IPv4/IPv6 sink addresses are honoured
    /// for future entries supplied by the policy puller.
    ///
    /// `telemetry` is the producer half of the pipeline channel
    /// — every handled query emits one
    /// [`sng_core::events::DnsEvent`] to this sender via the
    /// underlying [`DnsService`].
    ///
    /// The resolver is fixed to an empty [`StaticResolver`]
    /// labelled `edge-stub`. The real upstream resolver
    /// (recursive cache / forwarder) is a follow-up PR — the
    /// architectural cut here is the same one we make for the
    /// disk-backed updater / native PAL: real working bridge,
    /// in-memory backend by default, swap to the real backend
    /// in a later PR.
    #[must_use]
    pub fn new(cfg: &DnsConfig, telemetry: mpsc::Sender<TelemetryEvent>) -> Self {
        let reputation = Arc::new(Reputation::new(std::iter::empty::<String>()));
        let category = Arc::new(Category::empty());
        let sinkhole = Arc::new(Sinkhole::new(
            std::iter::empty::<String>(),
            cfg.sinkhole_ipv4,
            cfg.sinkhole_ipv6,
        ));
        let chain = FilterChain::new(vec![
            Arc::clone(&reputation) as Arc<dyn sng_dns::Filter>,
            Arc::clone(&category) as Arc<dyn sng_dns::Filter>,
            Arc::clone(&sinkhole) as Arc<dyn sng_dns::Filter>,
        ]);
        let resolver = Arc::new(StaticResolver::new("edge-stub"));
        let service = Arc::new(DnsService::new(Arc::new(chain), resolver, telemetry));

        // Managed-feed consumer is DEFAULT-OFF: it only comes alive when
        // the operator pins at least one verifying key. A key that fails
        // to decode is skipped with a warning rather than failing boot,
        // matching the fail-soft posture of the rest of the edge config.
        let applier = build_feed_applier(cfg);
        let category_actions = parse_category_actions(cfg);

        Self {
            service,
            reputation,
            category,
            reputation_file: cfg.reputation_file.clone(),
            refresh_interval: cfg.reputation_refresh_interval,
            reloads_total: Arc::new(AtomicU64::new(0)),
            reload_failures: Arc::new(AtomicU64::new(0)),
            entries_loaded: Arc::new(AtomicU64::new(0)),
            applier,
            category_actions,
            feeds_applied: Arc::new(AtomicU64::new(0)),
            feed_apply_failures: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Build the [`ManagedFeedApplier`] from the operator's pinned keys, or
/// `None` (DEFAULT-OFF) when no keys are configured. Keys that fail to
/// decode are skipped with a warning; if every configured key is
/// invalid the applier is still constructed (empty trust store) so the
/// operator's intent to enable the consumer is honoured and every
/// bundle fails closed with `UnknownKey` rather than silently passing.
fn build_feed_applier(cfg: &DnsConfig) -> Option<Arc<ManagedFeedApplier>> {
    if cfg.managed_feed.keys.is_empty() {
        return None;
    }
    let mut verifier = FeedVerifier::new();
    for key in &cfg.managed_feed.keys {
        match hex::decode(key.public_key_hex.trim()) {
            Ok(bytes) => {
                if let Err(e) = verifier.add_key(key.key_id.clone(), &bytes) {
                    tracing::warn!(
                        target: "sng_edge::dns",
                        key_id = %key.key_id,
                        error = %e,
                        "managed feed: skipping invalid verifying key"
                    );
                }
            }
            Err(e) => tracing::warn!(
                target: "sng_edge::dns",
                key_id = %key.key_id,
                error = %e,
                "managed feed: skipping non-hex verifying key"
            ),
        }
    }
    Some(Arc::new(ManagedFeedApplier::new(verifier)))
}

/// Parse the operator's per-category disposition strings into
/// [`CategoryAction`]s. Unknown / malformed values are skipped with a
/// warning so a category falls back to the staged-Allow default rather
/// than failing boot.
fn parse_category_actions(cfg: &DnsConfig) -> HashMap<String, CategoryAction> {
    let mut out = HashMap::new();
    for (cat, action) in &cfg.managed_feed.category_actions {
        if let Some(parsed) = parse_category_action(action) {
            out.insert(cat.clone(), parsed);
        } else {
            tracing::warn!(
                target: "sng_edge::dns",
                category = %cat,
                action = %action,
                "managed feed: unknown category action, defaulting to allow"
            );
        }
    }
    out
}

fn parse_category_action(s: &str) -> Option<CategoryAction> {
    match s.trim().to_ascii_lowercase().as_str() {
        "allow" => Some(CategoryAction::Allow),
        "log" => Some(CategoryAction::Log),
        "block" => Some(CategoryAction::Block),
        _ => None,
    }
}

impl<R: Resolver> DnsSubsystem<R> {
    /// Borrow the underlying [`DnsService`].
    #[must_use]
    pub fn service(&self) -> &Arc<DnsService<R>> {
        &self.service
    }

    /// Borrow the reputation filter handle.
    #[must_use]
    pub fn reputation(&self) -> &Arc<Reputation> {
        &self.reputation
    }

    /// Borrow the category filter handle.
    #[must_use]
    pub fn category(&self) -> &Arc<Category> {
        &self.category
    }

    /// Whether the managed signed-bundle consumer is enabled (i.e. the
    /// operator pinned at least one verifying key).
    #[must_use]
    pub fn managed_feed_enabled(&self) -> bool {
        self.applier.is_some()
    }

    /// Verify a signed control-plane DNS feed bundle and hot-swap it
    /// into the live category + reputation filters. This is the edge
    /// consumer seam for `internal/service/threatintel`'s signed bundle:
    /// the cross-process transport that delivers the bytes here (a NATS
    /// subscription / control-plane pull) is a separate follow-up; this
    /// method is what that transport calls once it has the envelope.
    ///
    /// The applier verifies the signature against the pinned trust store
    /// and enforces serial monotonicity BEFORE touching the filters, so
    /// a tampered, untrusted, or stale bundle leaves the live feed
    /// unchanged (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns [`FeedBundleError::UnknownKey`] when the managed-feed
    /// consumer is disabled (no pinned keys), and otherwise propagates
    /// any verification / staleness error from the applier.
    pub fn apply_feed_bundle(
        &self,
        signed: &SignedFeedBundle,
    ) -> Result<AppliedFeed, FeedBundleError> {
        let Some(applier) = self.applier.as_ref() else {
            // DEFAULT-OFF: no pinned key means the operator never opted
            // in. Report it as an untrusted bundle rather than silently
            // succeeding.
            return Err(FeedBundleError::UnknownKey(signed.key_id.clone()));
        };
        let res = applier.apply(
            signed,
            &self.category,
            &self.reputation,
            &self.category_actions,
        );
        match &res {
            Ok(summary) => {
                self.feeds_applied.fetch_add(1, Ordering::Relaxed);
                tracing::info!(
                    target: "sng_edge::dns",
                    serial = summary.serial,
                    categories = summary.categories,
                    reputation = summary.reputation,
                    "managed feed bundle applied"
                );
            }
            Err(e) => {
                self.feed_apply_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    target: "sng_edge::dns",
                    error = %e,
                    "managed feed bundle rejected"
                );
            }
        }
        res
    }

    /// Read the reputation file (newline-separated names, `#`
    /// comments). Atomically swaps the reputation set on
    /// success. Returns the number of entries loaded.
    ///
    /// # Errors
    ///
    /// Surfaces any [`std::io::Error`] from reading the file.
    /// The caller (the refresh loop) bumps the failure counter
    /// and logs the error; the previous reputation set remains
    /// in effect.
    pub fn reload_reputation_from(&self, path: &std::path::Path) -> std::io::Result<usize> {
        let body = std::fs::read_to_string(path)?;
        let entries: Vec<String> = body
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(str::to_owned)
            .collect();
        let n = entries.len();
        self.reputation.replace_entries(entries);
        Ok(n)
    }
}

#[async_trait]
impl<R: Resolver> Subsystem for DnsSubsystem<R> {
    fn name(&self) -> &'static str {
        "dns"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let path = self.reputation_file.clone();
        let interval = self.refresh_interval;
        let reputation = Arc::clone(&self.reputation);
        let reloads_total = Arc::clone(&self.reloads_total);
        let reload_failures = Arc::clone(&self.reload_failures);
        let entries_loaded = Arc::clone(&self.entries_loaded);
        Ok(task::spawn(async move {
            // No reputation file configured — just idle until
            // shutdown. The subsystem's role is still real:
            // it holds the constructed DnsService for other
            // subsystems to invoke.
            let Some(path) = path else {
                shutdown.wait().await;
                return Ok(());
            };
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut last_mtime: Option<SystemTime> = None;
            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    _ = ticker.tick() => {
                        match std::fs::metadata(&path).and_then(|m| m.modified()) {
                            Ok(m) => {
                                if Some(m) == last_mtime {
                                    continue;
                                }
                                last_mtime = Some(m);
                                match reload_reputation_inner(&reputation, &path) {
                                    Ok(n) => {
                                        reloads_total.fetch_add(1, Ordering::Relaxed);
                                        entries_loaded.store(n as u64, Ordering::Relaxed);
                                        tracing::info!(
                                            target: "sng_edge::dns",
                                            entries = n,
                                            path = %path.display(),
                                            "reputation reloaded"
                                        );
                                    }
                                    Err(e) => {
                                        reload_failures.fetch_add(1, Ordering::Relaxed);
                                        tracing::warn!(
                                            target: "sng_edge::dns",
                                            error = %e,
                                            path = %path.display(),
                                            "reputation reload failed"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                reload_failures.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(
                                    target: "sng_edge::dns",
                                    error = %e,
                                    path = %path.display(),
                                    "reputation mtime check failed"
                                );
                            }
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

fn reload_reputation_inner(
    reputation: &Reputation,
    path: &std::path::Path,
) -> std::io::Result<usize> {
    let body = std::fs::read_to_string(path)?;
    let entries: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect();
    let n = entries.len();
    reputation.replace_entries(entries);
    Ok(n)
}

#[async_trait]
impl<R: Resolver> HealthCheck for DnsSubsystem<R> {
    fn name(&self) -> &'static str {
        "dns"
    }

    async fn check(&self) -> SubsystemHealth {
        // Degrade when the operator configured a reputation
        // file but the most recent reload failed. We treat
        // "configured + at least one failure ever" as Degraded;
        // a hard Down requires `reload_failures > reloads_total`
        // (i.e. the loop has never succeeded).
        let reloads = self.reloads_total.load(Ordering::Relaxed);
        let failures = self.reload_failures.load(Ordering::Relaxed);
        let entries = self.entries_loaded.load(Ordering::Relaxed);
        let configured = self.reputation_file.is_some();
        let status = if configured && reloads == 0 && failures > 0 {
            HealthStatus::Down
        } else if configured && failures > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };
        let detail = format!(
            "configured={configured}, reloads={reloads}, failures={failures}, entries={entries}"
        );
        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(detail),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ManagedFeedConfig, ManagedFeedKey};
    use base64::Engine as _;
    use ed25519_dalek::{Signer as _, SigningKey};
    use sng_core::ShutdownTrigger;
    use sng_dns::managed::SCHEMA_VERSION;
    use sng_dns::{DnsQuery, FeedBundle, QType};
    use std::io::Write;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    fn config_with(path: Option<PathBuf>, interval: Duration) -> DnsConfig {
        DnsConfig {
            sinkhole_ipv4: std::net::Ipv4Addr::UNSPECIFIED,
            sinkhole_ipv6: std::net::Ipv6Addr::UNSPECIFIED,
            reputation_file: path,
            reputation_refresh_interval: interval,
            managed_feed: ManagedFeedConfig::default(),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    /// Sign a bundle exactly as the Go producer does: Ed25519 over the
    /// canonical payload bytes that get base64-encoded into `payload`.
    fn sign_bundle(key: &SigningKey, key_id: &str, bundle: &FeedBundle) -> SignedFeedBundle {
        let payload = serde_json::to_vec(bundle).expect("serialize");
        let sig = key.sign(&payload);
        let engine = base64::engine::general_purpose::STANDARD;
        SignedFeedBundle {
            algorithm: "ed25519".to_string(),
            key_id: key_id.to_string(),
            public_key: engine.encode(key.verifying_key().to_bytes()),
            payload: engine.encode(&payload),
            signature: engine.encode(sig.to_bytes()),
        }
    }

    /// Bundle with a reputation entry (evil.example) and a category
    /// bucket "threat-intel-ioc" holding a suffix-matchable domain.
    fn ioc_bundle(serial: i64) -> FeedBundle {
        let mut categories = HashMap::new();
        categories.insert(
            "threat-intel-ioc".to_string(),
            vec!["bad.example".to_string()],
        );
        FeedBundle {
            schema_version: SCHEMA_VERSION,
            serial,
            generated_at: "2026-01-01T00:00:00Z".to_string(),
            categories,
            reputation: vec!["evil.example".to_string()],
        }
    }

    /// Config that pins the test signing key and maps the IOC bucket to
    /// Block, i.e. the operator has fully opted in to enforcement.
    fn config_with_managed_feed(key: &SigningKey, key_id: &str) -> DnsConfig {
        let mut category_actions = std::collections::HashMap::new();
        category_actions.insert("threat-intel-ioc".to_string(), "block".to_string());
        DnsConfig {
            sinkhole_ipv4: std::net::Ipv4Addr::UNSPECIFIED,
            sinkhole_ipv6: std::net::Ipv6Addr::UNSPECIFIED,
            reputation_file: None,
            reputation_refresh_interval: Duration::from_millis(10),
            managed_feed: ManagedFeedConfig {
                keys: vec![ManagedFeedKey {
                    key_id: key_id.to_string(),
                    public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                }],
                category_actions,
            },
        }
    }

    #[tokio::test]
    async fn apply_feed_bundle_enforces_on_live_filters() {
        let key = signing_key();
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(&config_with_managed_feed(&key, "k1"), tx);
        assert!(sub.managed_feed_enabled());

        let applied = sub
            .apply_feed_bundle(&sign_bundle(&key, "k1", &ioc_bundle(1)))
            .expect("apply");
        assert_eq!(applied.serial, 1);
        assert_eq!(applied.reputation, 1);

        // Reputation hit (exact) — apex of the reputation entry.
        let evil = sub
            .service()
            .handle_query(&DnsQuery::new("evil.example", QType::A))
            .await;
        assert!(evil.short_circuited, "evil.example must be sinkholed");

        // Category hit via suffix-match: a subdomain of the IOC entry.
        let sub_bad = sub
            .service()
            .handle_query(&DnsQuery::new("host.bad.example", QType::A))
            .await;
        assert!(
            sub_bad.short_circuited,
            "host.bad.example must match the IOC category suffix"
        );

        // A domain in neither list resolves (no short-circuit).
        let ok = sub
            .service()
            .handle_query(&DnsQuery::new("allowed.example", QType::A))
            .await;
        assert!(!ok.short_circuited, "allowed.example must pass the chain");
    }

    #[tokio::test]
    async fn apply_feed_bundle_rejects_stale_serial() {
        let key = signing_key();
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(&config_with_managed_feed(&key, "k1"), tx);

        sub.apply_feed_bundle(&sign_bundle(&key, "k1", &ioc_bundle(5)))
            .expect("first apply");
        let err = sub
            .apply_feed_bundle(&sign_bundle(&key, "k1", &ioc_bundle(4)))
            .expect_err("stale serial must be rejected");
        assert!(matches!(err, FeedBundleError::StaleSerial { .. }));
    }

    #[tokio::test]
    async fn apply_feed_bundle_rejects_untrusted_key() {
        let pinned = signing_key();
        let attacker = SigningKey::from_bytes(&[9u8; 32]);
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(&config_with_managed_feed(&pinned, "k1"), tx);

        // Signed by a key NOT in the trust store (same key_id).
        let err = sub
            .apply_feed_bundle(&sign_bundle(&attacker, "k1", &ioc_bundle(1)))
            .expect_err("untrusted signature must be rejected");
        assert!(matches!(err, FeedBundleError::SignatureInvalid));

        // The live filters must be untouched (fail-closed).
        let evil = sub
            .service()
            .handle_query(&DnsQuery::new("evil.example", QType::A))
            .await;
        assert!(!evil.short_circuited, "rejected bundle must not enforce");
    }

    #[tokio::test]
    async fn managed_feed_disabled_by_default() {
        let key = signing_key();
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        // No pinned keys -> consumer OFF.
        let sub = DnsSubsystem::new(&config_with(None, Duration::from_millis(10)), tx);
        assert!(!sub.managed_feed_enabled());

        let err = sub
            .apply_feed_bundle(&sign_bundle(&key, "k1", &ioc_bundle(1)))
            .expect_err("disabled consumer must reject");
        assert!(matches!(err, FeedBundleError::UnknownKey(_)));

        let evil = sub
            .service()
            .handle_query(&DnsQuery::new("evil.example", QType::A))
            .await;
        assert!(
            !evil.short_circuited,
            "disabled consumer must not enforce anything"
        );
    }

    #[tokio::test]
    async fn subsystem_idles_until_shutdown_without_file() {
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(&config_with(None, Duration::from_millis(10)), tx);
        let (trigger, signal) = ShutdownTrigger::new();
        let handle = sub.start(signal).await.expect("start");
        trigger.fire();
        let res = tokio::time::timeout(Duration::from_secs(1), handle)
            .await
            .expect("drain");
        assert!(res.expect("join").is_ok());
    }

    #[tokio::test]
    async fn reload_reputation_from_file_loads_and_skips_comments() {
        let mut tf = NamedTempFile::new().expect("tempfile");
        writeln!(tf, "# header comment").expect("write");
        writeln!(tf, "evil.example").expect("write");
        writeln!(tf, "  spaced.example  ").expect("write");
        writeln!(tf).expect("write"); // blank
        writeln!(tf, "malicious.test").expect("write");
        tf.flush().expect("flush");
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(
            &config_with(Some(tf.path().to_path_buf()), Duration::from_millis(10)),
            tx,
        );
        let n = sub.reload_reputation_from(tf.path()).expect("reload");
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn refresh_loop_loads_file_on_first_tick() {
        let mut tf = NamedTempFile::new().expect("tempfile");
        writeln!(tf, "bad.example").expect("write");
        writeln!(tf, "worse.example").expect("write");
        tf.flush().expect("flush");
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(
            &config_with(Some(tf.path().to_path_buf()), Duration::from_millis(5)),
            tx,
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let reloads = Arc::clone(&sub.reloads_total);
        let entries = Arc::clone(&sub.entries_loaded);
        let handle = sub.start(signal).await.expect("start");
        // Wait for at least one tick + reload to land.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if reloads.load(Ordering::Relaxed) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        trigger.fire();
        let _ = tokio::time::timeout(Duration::from_secs(1), handle).await;
        assert!(reloads.load(Ordering::Relaxed) >= 1);
        assert_eq!(entries.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn health_degrades_when_reload_fails_after_success() {
        let mut tf = NamedTempFile::new().expect("tempfile");
        writeln!(tf, "bad.example").expect("write");
        tf.flush().expect("flush");
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(
            &config_with(Some(tf.path().to_path_buf()), Duration::from_millis(5)),
            tx,
        );
        sub.reloads_total.store(2, Ordering::Relaxed);
        sub.reload_failures.store(1, Ordering::Relaxed);
        sub.entries_loaded.store(7, Ordering::Relaxed);
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Degraded);
    }

    #[tokio::test]
    async fn health_down_when_configured_and_never_succeeded() {
        let (tx, _rx) = mpsc::channel::<TelemetryEvent>(4);
        let sub = DnsSubsystem::new(
            &config_with(
                Some(PathBuf::from("/nonexistent")),
                Duration::from_millis(5),
            ),
            tx,
        );
        sub.reload_failures.store(1, Ordering::Relaxed);
        let h = sub.check().await;
        assert_eq!(h.status, HealthStatus::Down);
    }
}

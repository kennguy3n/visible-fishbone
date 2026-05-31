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
use sng_dns::{Category, DnsService, FilterChain, Reputation, Resolver, Sinkhole, StaticResolver};
use sng_telemetry::TelemetryEvent;
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
    reputation_file: Option<PathBuf>,
    refresh_interval: std::time::Duration,
    reloads_total: Arc<AtomicU64>,
    reload_failures: Arc<AtomicU64>,
    entries_loaded: Arc<AtomicU64>,
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
        Self {
            service,
            reputation,
            reputation_file: cfg.reputation_file.clone(),
            refresh_interval: cfg.reputation_refresh_interval,
            reloads_total: Arc::new(AtomicU64::new(0)),
            reload_failures: Arc::new(AtomicU64::new(0)),
            entries_loaded: Arc::new(AtomicU64::new(0)),
        }
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
    use sng_core::ShutdownTrigger;
    use std::io::Write;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    fn config_with(path: Option<PathBuf>, interval: Duration) -> DnsConfig {
        DnsConfig {
            sinkhole_ipv4: std::net::Ipv4Addr::UNSPECIFIED,
            sinkhole_ipv6: std::net::Ipv6Addr::UNSPECIFIED,
            reputation_file: path,
            reputation_refresh_interval: interval,
        }
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

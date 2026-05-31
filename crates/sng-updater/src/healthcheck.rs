//! Health check abstraction.
//!
//! After the bootloader has been swapped to the staged image
//! and the system is now running on the new bank, the
//! orchestrator runs one or more health checks to decide
//! whether to commit the swap or roll back. Real-world
//! checks: "service responsive", "control plane reachable
//! over mTLS", "policy bundle loads". The trait is async so
//! production implementations can do network I/O.
//!
//! The trait, the report shape, and an in-process double live
//! here. The actual orchestration logic (timeout + commit
//! vs. rollback) lives in [`crate::service`].

use crate::error::UpdaterError;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;

/// Result of a single health-check probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthReport {
    /// Probe passed — the orchestrator may commit the swap.
    Healthy {
        /// Free-form description of what passed (e.g. "control
        /// plane reachable, policy bundle loaded"). Surfaced
        /// on operator dashboards.
        details: String,
    },
    /// Probe failed — the orchestrator MUST roll back the
    /// swap.
    Unhealthy {
        /// Free-form description of what failed.
        details: String,
    },
}

impl HealthReport {
    /// Returns true iff the report indicates a healthy state.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy { .. })
    }

    /// Returns the details string, regardless of outcome.
    #[must_use]
    pub fn details(&self) -> &str {
        match self {
            Self::Healthy { details } | Self::Unhealthy { details } => details,
        }
    }

    /// Construct a healthy report with the given details.
    #[must_use]
    pub fn healthy<S: Into<String>>(details: S) -> Self {
        Self::Healthy {
            details: details.into(),
        }
    }

    /// Construct an unhealthy report with the given details.
    #[must_use]
    pub fn unhealthy<S: Into<String>>(details: S) -> Self {
        Self::Unhealthy {
            details: details.into(),
        }
    }
}

/// Health-check trait. The orchestrator wraps the call in a
/// `tokio::time::timeout` driven by the
/// [`crate::policy::UpdaterPolicy::health_check_timeout`]; a
/// timeout surfaces as
/// [`UpdaterError::HealthCheckTimeout`].
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Run a single probe. The orchestrator may invoke this
    /// repeatedly within the health-check window; each call
    /// is independent.
    async fn probe(&self) -> Result<HealthReport, UpdaterError>;
}

/// In-process health check for tests. Holds a queue of
/// [`HealthReport`]s and pops one on each `probe` call;
/// empty queue → returns the last-configured "default"
/// report (defaults to `Unhealthy("no probes configured")`).
#[derive(Debug)]
pub struct StaticHealthCheck {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    queue: Mutex<VecDeque<HealthReport>>,
    default: Mutex<HealthReport>,
    /// Optional override that makes every subsequent probe
    /// fail with `UpdaterError::HealthCheckFailed(msg)`.
    fail_with: Mutex<Option<String>>,
    /// Optional delay applied to each probe — exposes the
    /// orchestrator's timeout path to tests.
    delay: Mutex<std::time::Duration>,
    /// Call counter.
    calls: Mutex<u64>,
}

impl Default for StaticHealthCheck {
    fn default() -> Self {
        Self {
            inner: Arc::new(Inner {
                queue: Mutex::new(VecDeque::new()),
                default: Mutex::new(HealthReport::unhealthy("no probes configured")),
                fail_with: Mutex::new(None),
                delay: Mutex::new(std::time::Duration::ZERO),
                calls: Mutex::new(0),
            }),
        }
    }
}

impl StaticHealthCheck {
    /// Construct an empty health check (every probe returns
    /// the default unhealthy report).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a health check that always returns
    /// `Healthy`.
    #[must_use]
    pub fn always_healthy<S: Into<String>>(details: S) -> Self {
        let s = Self::new();
        *s.inner.default.lock() = HealthReport::healthy(details);
        s
    }

    /// Construct a health check that always returns
    /// `Unhealthy`.
    #[must_use]
    pub fn always_unhealthy<S: Into<String>>(details: S) -> Self {
        let s = Self::new();
        *s.inner.default.lock() = HealthReport::unhealthy(details);
        s
    }

    /// Replace the default report.
    pub fn set_default(&self, report: HealthReport) {
        *self.inner.default.lock() = report;
    }

    /// Push a report onto the back of the queue.
    pub fn push(&self, report: HealthReport) {
        self.inner.queue.lock().push_back(report);
    }

    /// Push many reports onto the back of the queue.
    pub fn push_many<I: IntoIterator<Item = HealthReport>>(&self, iter: I) {
        let mut g = self.inner.queue.lock();
        for r in iter {
            g.push_back(r);
        }
    }

    /// Force every subsequent probe to fail.
    pub fn force_failure(&self, msg: Option<String>) {
        *self.inner.fail_with.lock() = msg;
    }

    /// Apply a delay to every probe. Used by tests that want
    /// to exercise the orchestrator's health-check timeout.
    pub fn set_delay(&self, delay: std::time::Duration) {
        *self.inner.delay.lock() = delay;
    }

    /// Number of `probe` calls served.
    pub fn call_count(&self) -> u64 {
        *self.inner.calls.lock()
    }

    /// Cheap shareable handle.
    #[must_use]
    pub fn handle(&self) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(&self.inner),
        })
    }
}

#[async_trait]
impl HealthCheck for StaticHealthCheck {
    async fn probe(&self) -> Result<HealthReport, UpdaterError> {
        *self.inner.calls.lock() += 1;
        if let Some(msg) = self.inner.fail_with.lock().clone() {
            return Err(UpdaterError::HealthCheckFailed(msg));
        }
        let delay = *self.inner.delay.lock();
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if let Some(r) = self.inner.queue.lock().pop_front() {
            return Ok(r);
        }
        Ok(self.inner.default.lock().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn health_report_helpers_round_trip() {
        let h = HealthReport::healthy("ok");
        assert!(h.is_healthy());
        assert_eq!(h.details(), "ok");
        let u = HealthReport::unhealthy("nope");
        assert!(!u.is_healthy());
        assert_eq!(u.details(), "nope");
    }

    #[tokio::test]
    async fn empty_queue_returns_default_report() {
        let hc = StaticHealthCheck::new();
        let r = hc.probe().await.expect("probe");
        assert!(!r.is_healthy());
        assert_eq!(hc.call_count(), 1);
    }

    #[tokio::test]
    async fn always_healthy_constructor() {
        let hc = StaticHealthCheck::always_healthy("svc ok");
        for _ in 0..3 {
            let r = hc.probe().await.expect("probe");
            assert!(r.is_healthy());
        }
        assert_eq!(hc.call_count(), 3);
    }

    #[tokio::test]
    async fn queued_reports_consumed_in_fifo_order() {
        let hc = StaticHealthCheck::new();
        hc.set_default(HealthReport::healthy("eventual ok"));
        hc.push_many([
            HealthReport::unhealthy("first probe failed"),
            HealthReport::unhealthy("second probe failed"),
        ]);
        let r1 = hc.probe().await.expect("p1");
        assert_eq!(r1.details(), "first probe failed");
        let r2 = hc.probe().await.expect("p2");
        assert_eq!(r2.details(), "second probe failed");
        // Queue drained — default takes over.
        let r3 = hc.probe().await.expect("p3");
        assert!(r3.is_healthy());
    }

    #[tokio::test]
    async fn force_failure_surfaces_updater_error() {
        let hc = StaticHealthCheck::new();
        hc.force_failure(Some("probe panicked".into()));
        let err = hc.probe().await.expect_err("forced");
        assert!(matches!(err, UpdaterError::HealthCheckFailed(_)));
    }

    #[tokio::test]
    async fn handle_shares_state_with_owner() {
        let owner = StaticHealthCheck::new();
        let handle = owner.handle();
        owner.push(HealthReport::healthy("ok"));
        let r = handle.probe().await.expect("p");
        assert!(r.is_healthy());
        assert_eq!(owner.call_count(), 1);
    }
}

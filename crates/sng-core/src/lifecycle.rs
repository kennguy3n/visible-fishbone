//! Lifecycle primitives: shutdown signal, health checks.
//!
//! Every long-running module in the workspace participates in
//! the same drain protocol:
//!
//! 1. The supervising binary (`sng-edge` / `sng-agent`)
//!    constructs a [`ShutdownTrigger`] / [`ShutdownSignal`] pair
//!    at startup and clones the signal into each subsystem.
//! 2. When the binary receives `SIGINT`, `SIGTERM`, or the
//!    Windows equivalent, it fires the trigger.
//! 3. Each subsystem's main loop selects on
//!    `shutdown.wait()` and exits cleanly when it resolves.
//! 4. The supervisor joins every subsystem with a bounded
//!    timeout. Any subsystem that does not exit within the
//!    timeout is logged but not killed — the OS supervisor
//!    (systemd, service control manager) is responsible for the
//!    hard kill if needed.
//!
//! Health checks follow the same shape: every subsystem
//! implements [`HealthCheck`] and the supervisor aggregates the
//! results into a [`Health`] response. The control plane polls
//! the agent's `/health` endpoint and uses the response to drive
//! its operator dashboard.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::sync::Notify;
use tokio::time::timeout;

/// Producer half of the shutdown signal pair. The supervising
/// binary holds this; firing it broadcasts the signal to every
/// [`ShutdownSignal`] clone.
#[derive(Debug)]
pub struct ShutdownTrigger {
    notify: Arc<Notify>,
    fired: Arc<parking_lot::Mutex<bool>>,
}

impl ShutdownTrigger {
    /// Build a new trigger / signal pair.
    #[must_use]
    pub fn new() -> (Self, ShutdownSignal) {
        let notify = Arc::new(Notify::new());
        let fired = Arc::new(parking_lot::Mutex::new(false));
        let trigger = Self {
            notify: notify.clone(),
            fired: fired.clone(),
        };
        let signal = ShutdownSignal { notify, fired };
        (trigger, signal)
    }

    /// Fire the trigger. Every subsystem waiting on the
    /// matching [`ShutdownSignal`] is woken. Safe to call from
    /// any thread; calling twice is a no-op.
    pub fn fire(&self) {
        let mut fired = self.fired.lock();
        if !*fired {
            *fired = true;
            // notify_waiters wakes every current waiter; future
            // `wait()` calls return immediately because `fired`
            // is now true.
            self.notify.notify_waiters();
        }
    }

    /// Returns true if [`Self::fire`] has been called.
    #[must_use]
    pub fn is_fired(&self) -> bool {
        *self.fired.lock()
    }
}

impl Default for ShutdownTrigger {
    fn default() -> Self {
        Self::new().0
    }
}

/// Consumer half of the shutdown signal pair. Cheap to clone —
/// every cloned signal sees the same firing.
#[derive(Clone, Debug)]
pub struct ShutdownSignal {
    notify: Arc<Notify>,
    fired: Arc<parking_lot::Mutex<bool>>,
}

impl ShutdownSignal {
    /// Awaits shutdown. Resolves immediately if the trigger has
    /// already been fired; otherwise blocks until it is.
    pub async fn wait(&self) {
        if *self.fired.lock() {
            return;
        }
        self.notify.notified().await;
    }

    /// Polls shutdown status without awaiting.
    #[must_use]
    pub fn is_fired(&self) -> bool {
        *self.fired.lock()
    }
}

/// Per-subsystem health status. Stable wire form so the control
/// plane's health-check schema does not have to change when a
/// new subsystem is added.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// Subsystem is operating normally.
    Up,
    /// Subsystem is impaired but still serving (e.g. local
    /// spool is degraded; bundle pull failing but evaluation
    /// continues against the last good bundle).
    Degraded,
    /// Subsystem is not operating.
    Down,
}

/// Aggregated health report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// Overall status — `Up` only when every subsystem is `Up`,
    /// `Down` if any is `Down`, else `Degraded`.
    pub status: HealthStatus,
    /// Per-subsystem detail.
    pub subsystems: Vec<SubsystemHealth>,
}

/// Per-subsystem entry in a [`Health`] report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SubsystemHealth {
    /// Subsystem name (stable, lowercase, e.g. `policy`, `telemetry`).
    pub name: String,
    /// Status.
    pub status: HealthStatus,
    /// Optional human-readable detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl Health {
    /// Aggregate a slice of subsystem reports into a single
    /// overall status.
    #[must_use]
    pub fn aggregate(subsystems: Vec<SubsystemHealth>) -> Self {
        let mut status = HealthStatus::Up;
        for s in &subsystems {
            match s.status {
                HealthStatus::Down => {
                    status = HealthStatus::Down;
                    break;
                }
                HealthStatus::Degraded if status != HealthStatus::Down => {
                    status = HealthStatus::Degraded;
                }
                _ => {}
            }
        }
        Self { status, subsystems }
    }
}

/// Trait every long-running subsystem implements. The
/// supervisor polls each subsystem's `check` method on a fixed
/// cadence and aggregates the results into a [`Health`] report.
#[async_trait]
pub trait HealthCheck: Send + Sync {
    /// Stable subsystem name. Used as the key in the
    /// [`Health::subsystems`] vector and as the metrics label.
    fn name(&self) -> &str;

    /// Probe the subsystem. The default timeout for a single
    /// check is set by the supervisor via [`Self::check_with_timeout`];
    /// the implementer's job is to do the actual probe.
    async fn check(&self) -> SubsystemHealth;

    /// Wrap [`Self::check`] in a bounded timeout. If the check
    /// does not return within `budget`, the subsystem is
    /// reported as `Down` with a `timeout` detail string. The
    /// default implementation is what the supervisor calls so
    /// no subsystem can starve the health endpoint by hanging.
    async fn check_with_timeout(&self, budget: Duration) -> SubsystemHealth {
        match timeout(budget, self.check()).await {
            Ok(s) => s,
            Err(_) => SubsystemHealth {
                name: self.name().to_owned(),
                status: HealthStatus::Down,
                detail: Some(format!("timeout after {budget:?}")),
            },
        }
    }
}

/// Error returned by the supervisor's drain helper when a
/// subsystem fails to exit within the supplied budget.
#[derive(Debug, Error)]
#[error("drain timeout: {0} did not exit in {1:?}")]
pub struct DrainTimeout(pub String, pub Duration);

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn shutdown_signal_resolves_after_fire() {
        let (trigger, signal) = ShutdownTrigger::new();
        assert!(!signal.is_fired());
        // Spawn the waiter, then fire on the main task. The
        // tokio scheduler interleaves the two and the waiter
        // should resolve immediately after fire.
        let handle = tokio::spawn({
            let signal = signal.clone();
            async move { signal.wait().await }
        });
        // Yield once so the spawned task reaches the await.
        tokio::task::yield_now().await;
        trigger.fire();
        // Bounded wait so a buggy implementation fails the test
        // rather than hanging CI.
        timeout(Duration::from_millis(100), handle)
            .await
            .expect("waiter resolved")
            .expect("join ok");
        assert!(signal.is_fired());
        assert!(trigger.is_fired());
    }

    #[tokio::test]
    async fn shutdown_signal_clones_all_observe_fire() {
        let (trigger, signal) = ShutdownTrigger::new();
        let a = signal.clone();
        let b = signal.clone();
        let c = signal.clone();
        let waiters = tokio::spawn(async move {
            // All three must resolve after the fire.
            a.wait().await;
            b.wait().await;
            c.wait().await;
        });
        tokio::task::yield_now().await;
        trigger.fire();
        timeout(Duration::from_millis(100), waiters)
            .await
            .expect("waiters resolved")
            .expect("join ok");
    }

    #[tokio::test]
    async fn fire_after_fire_is_a_no_op() {
        let (trigger, signal) = ShutdownTrigger::new();
        trigger.fire();
        trigger.fire();
        trigger.fire();
        // Still resolves.
        signal.wait().await;
    }

    #[test]
    fn health_aggregate_picks_worst_status() {
        let cases: Vec<(Vec<HealthStatus>, HealthStatus)> = vec![
            (vec![HealthStatus::Up], HealthStatus::Up),
            (vec![HealthStatus::Up, HealthStatus::Up], HealthStatus::Up),
            (
                vec![HealthStatus::Up, HealthStatus::Degraded],
                HealthStatus::Degraded,
            ),
            (
                vec![HealthStatus::Degraded, HealthStatus::Degraded],
                HealthStatus::Degraded,
            ),
            (
                vec![HealthStatus::Up, HealthStatus::Down],
                HealthStatus::Down,
            ),
            (
                vec![HealthStatus::Up, HealthStatus::Degraded, HealthStatus::Down],
                HealthStatus::Down,
            ),
        ];
        for (statuses, expected) in cases {
            let subs: Vec<SubsystemHealth> = statuses
                .into_iter()
                .enumerate()
                .map(|(i, status)| SubsystemHealth {
                    name: format!("sys{i}"),
                    status,
                    detail: None,
                })
                .collect();
            let agg = Health::aggregate(subs);
            assert_eq!(agg.status, expected);
        }
    }

    struct SlowCheck;

    #[async_trait]
    impl HealthCheck for SlowCheck {
        fn name(&self) -> &'static str {
            "slow"
        }
        async fn check(&self) -> SubsystemHealth {
            tokio::time::sleep(Duration::from_secs(60)).await;
            SubsystemHealth {
                name: "slow".into(),
                status: HealthStatus::Up,
                detail: None,
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn check_with_timeout_reports_down_on_overrun() {
        let check = SlowCheck;
        let result = check.check_with_timeout(Duration::from_millis(10)).await;
        assert_eq!(result.name, "slow");
        assert_eq!(result.status, HealthStatus::Down);
        assert!(result.detail.is_some_and(|d| d.contains("timeout")));
    }

    struct FastCheck;

    #[async_trait]
    impl HealthCheck for FastCheck {
        fn name(&self) -> &'static str {
            "fast"
        }
        async fn check(&self) -> SubsystemHealth {
            SubsystemHealth {
                name: "fast".into(),
                status: HealthStatus::Up,
                detail: None,
            }
        }
    }

    #[tokio::test]
    async fn check_with_timeout_returns_result_when_in_budget() {
        let check = FastCheck;
        let result = check.check_with_timeout(Duration::from_secs(5)).await;
        assert_eq!(result.status, HealthStatus::Up);
    }
}

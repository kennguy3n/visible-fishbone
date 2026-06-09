// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//! Integration tests for the top-level edge [`Watchdog`] escalation
//! ladder, driven through the public crate API with in-process mocks
//! for the three injected seams (health source, subsystem restarter,
//! edge controller).
//!
//! These cover the WS2 escalation contract:
//!
//! * a sustained-`Down` subsystem is restarted in place and, on
//!   recovery, the escalation is cleared with a `Recovered` event;
//! * a single `Down` blip below the threshold does not escalate;
//! * when in-place restarts exhaust their budget, the watchdog bounces
//!   the edge (fires the process shutdown) and stops;
//! * when even the edge bounce cannot be initiated, the watchdog
//!   alerts the control plane with a terminal `Exhausted` event and
//!   does not spam further alerts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;

use sng_core::events::{SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason};
use sng_core::lifecycle::{Health, HealthStatus, SubsystemHealth};
use sng_core::restart::SubsystemRestartSink;
use sng_core::{ShutdownTrigger, ShutdownSignal};
use sng_edge::{
    EdgeController, HealthSource, SubsystemRestarter, Watchdog, WatchdogConfig, WatchdogError,
};

const SUBSYS: &str = "ips";

/// Health source whose per-subsystem status the test mutates at will.
#[derive(Debug)]
struct ScriptedHealth {
    status: Mutex<HealthStatus>,
}

impl ScriptedHealth {
    fn new(status: HealthStatus) -> Arc<Self> {
        Arc::new(Self {
            status: Mutex::new(status),
        })
    }

    fn set(&self, status: HealthStatus) {
        *self.status.lock() = status;
    }
}

#[async_trait]
impl HealthSource for ScriptedHealth {
    async fn health(&self) -> Health {
        let status = *self.status.lock();
        Health {
            status,
            subsystems: vec![SubsystemHealth {
                name: SUBSYS.to_owned(),
                status,
                detail: None,
            }],
        }
    }
}

/// Restarter scripted with a queue of results. When it succeeds it can
/// optionally flip a shared health source back to `Up` to model a real
/// recovery.
#[derive(Debug)]
struct ScriptedRestarter {
    results: Mutex<VecDeque<Result<(), WatchdogError>>>,
    calls: AtomicUsize,
    on_success_up: Option<Arc<ScriptedHealth>>,
}

impl ScriptedRestarter {
    fn new(
        results: impl IntoIterator<Item = Result<(), WatchdogError>>,
        on_success_up: Option<Arc<ScriptedHealth>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            results: Mutex::new(results.into_iter().collect()),
            calls: AtomicUsize::new(0),
            on_success_up,
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SubsystemRestarter for ScriptedRestarter {
    async fn restart_subsystem(&self, _name: &str) -> Result<(), WatchdogError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let res = self.results.lock().pop_front().unwrap_or(Ok(()));
        if res.is_ok()
            && let Some(health) = &self.on_success_up
        {
            health.set(HealthStatus::Up);
        }
        res
    }
}

/// Edge controller that records bounces and is scripted to succeed or
/// fail.
#[derive(Debug)]
struct ScriptedEdge {
    succeed: bool,
    bounces: AtomicUsize,
}

impl ScriptedEdge {
    fn new(succeed: bool) -> Arc<Self> {
        Arc::new(Self {
            succeed,
            bounces: AtomicUsize::new(0),
        })
    }

    fn bounces(&self) -> usize {
        self.bounces.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl EdgeController for ScriptedEdge {
    async fn restart_edge(&self, _reason: &str) -> Result<(), WatchdogError> {
        self.bounces.fetch_add(1, Ordering::SeqCst);
        if self.succeed {
            Ok(())
        } else {
            Err(WatchdogError::EdgeRestart("no init supervisor".to_owned()))
        }
    }
}

#[derive(Debug, Default)]
struct RecordingSink {
    events: Mutex<Vec<SubsystemRestart>>,
}

impl RecordingSink {
    fn snapshot(&self) -> Vec<SubsystemRestart> {
        self.events.lock().clone()
    }

    fn len(&self) -> usize {
        self.events.lock().len()
    }
}

#[async_trait]
impl SubsystemRestartSink for RecordingSink {
    async fn record(&self, event: SubsystemRestart) {
        self.events.lock().push(event);
    }
}

fn fast_config() -> WatchdogConfig {
    WatchdogConfig {
        poll_interval: Duration::from_millis(5),
        down_threshold: 3,
        subsystem_restart_attempts: 2,
        restart_initial_backoff: Duration::from_millis(5),
        restart_max_backoff: Duration::from_millis(20),
        subsystem_fail_open: HashMap::new(),
    }
}

async fn wait_for_events(sink: &RecordingSink, n: usize, within: Duration) -> Vec<SubsystemRestart> {
    let deadline = Instant::now() + within;
    loop {
        if sink.len() >= n {
            return sink.snapshot();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} event(s); saw {}",
            sink.len()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

fn spawn(watchdog: Arc<Watchdog>, signal: ShutdownSignal) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { watchdog.run(signal).await })
}

#[tokio::test]
async fn single_down_blip_below_threshold_does_not_escalate() {
    let health = ScriptedHealth::new(HealthStatus::Down);
    let restarter = ScriptedRestarter::new([], None);
    let edge = ScriptedEdge::new(true);
    let sink = Arc::new(RecordingSink::default());
    let wd = Arc::new(
        Watchdog::new(
            health.clone(),
            restarter.clone(),
            edge.clone(),
            WatchdogConfig {
                down_threshold: 5,
                ..fast_config()
            },
        )
        .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let handle = spawn(wd, signal);

    // Let a couple of poll cycles pass, then recover before the
    // threshold is reached.
    tokio::time::sleep(Duration::from_millis(15)).await;
    health.set(HealthStatus::Up);
    tokio::time::sleep(Duration::from_millis(15)).await;

    assert_eq!(restarter.calls(), 0, "must not restart below threshold");
    assert_eq!(edge.bounces(), 0, "must not bounce the edge");
    assert_eq!(sink.len(), 0, "no escalation telemetry below threshold");

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn sustained_down_is_restarted_in_place_then_recovers() {
    let health = ScriptedHealth::new(HealthStatus::Down);
    // First restart succeeds and flips the subsystem back to Up.
    let restarter = ScriptedRestarter::new([Ok(())], Some(health.clone()));
    let edge = ScriptedEdge::new(true);
    let sink = Arc::new(RecordingSink::default());
    let wd = Arc::new(
        Watchdog::new(health.clone(), restarter.clone(), edge.clone(), fast_config())
            .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let handle = spawn(wd, signal);

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    let recovered = &events[0];
    assert_eq!(recovered.subsystem, SUBSYS);
    assert_eq!(recovered.reason, SubsystemRestartReason::Escalated);
    assert_eq!(recovered.outcome, SubsystemRestartOutcome::Recovered);
    assert_eq!(recovered.attempt, 1);
    assert_eq!(restarter.calls(), 1, "exactly one in-place restart");
    assert_eq!(edge.bounces(), 0, "recovery means no edge bounce");

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn escalation_event_reports_configured_fail_closed_posture() {
    let health = ScriptedHealth::new(HealthStatus::Down);
    let restarter = ScriptedRestarter::new([Ok(())], Some(health.clone()));
    let edge = ScriptedEdge::new(true);
    let sink = Arc::new(RecordingSink::default());
    // Declare the subsystem fail-closed: while it is down, traffic is
    // dropped, so the escalation telemetry must report fail_open=false
    // rather than the optimistic default.
    let mut fail_open = HashMap::new();
    fail_open.insert(SUBSYS.to_owned(), false);
    let wd = Arc::new(
        Watchdog::new(
            health.clone(),
            restarter.clone(),
            edge.clone(),
            WatchdogConfig {
                subsystem_fail_open: fail_open,
                ..fast_config()
            },
        )
        .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let handle = spawn(wd, signal);

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    assert!(
        !events[0].fail_open,
        "fail-closed subsystem must report fail_open=false in escalation telemetry"
    );

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn exhausted_in_place_restarts_bounce_the_edge_and_stop() {
    let health = ScriptedHealth::new(HealthStatus::Down);
    // Every in-place restart fails; never recovers.
    let restarter = ScriptedRestarter::new(
        std::iter::repeat_with(|| Err(WatchdogError::SubsystemRestart {
            subsystem: SUBSYS.to_owned(),
            detail: "still dead".to_owned(),
        }))
        .take(8),
        None,
    );
    let edge = ScriptedEdge::new(true);
    let sink = Arc::new(RecordingSink::default());
    let wd = Arc::new(
        Watchdog::new(health.clone(), restarter.clone(), edge.clone(), fast_config())
            .with_sink(sink.clone()),
    );

    let (_trigger, signal) = ShutdownTrigger::new();
    let handle = spawn(wd, signal);

    // The run loop returns on its own once it fires the edge bounce.
    tokio::time::timeout(Duration::from_secs(3), handle)
        .await
        .expect("watchdog stops after bouncing the edge")
        .unwrap();

    assert_eq!(edge.bounces(), 1, "exactly one edge bounce");
    let events = sink.snapshot();
    // 2 failed in-place attempts (budget) + 1 edge-bounce Exhausted.
    let outcomes: Vec<SubsystemRestartOutcome> = events.iter().map(|e| e.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            SubsystemRestartOutcome::Failed,
            SubsystemRestartOutcome::Failed,
            SubsystemRestartOutcome::Exhausted,
        ]
    );
    assert!(events.iter().all(|e| e.reason == SubsystemRestartReason::Escalated));
    assert_eq!(restarter.calls(), 2, "tier-1 budget = 2 attempts");
}

#[tokio::test]
async fn failed_edge_bounce_alerts_control_plane_once() {
    let health = ScriptedHealth::new(HealthStatus::Down);
    let restarter = ScriptedRestarter::new(
        std::iter::repeat_with(|| Err(WatchdogError::SubsystemRestart {
            subsystem: SUBSYS.to_owned(),
            detail: "still dead".to_owned(),
        }))
        .take(8),
        None,
    );
    // Edge bounce cannot be initiated.
    let edge = ScriptedEdge::new(false);
    let sink = Arc::new(RecordingSink::default());
    let wd = Arc::new(
        Watchdog::new(health.clone(), restarter.clone(), edge.clone(), fast_config())
            .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let handle = spawn(wd, signal);

    // Expect: 2 Failed (tier-1) + 1 terminal Exhausted (control-plane
    // alert after the edge bounce fails).
    let events = wait_for_events(&sink, 3, Duration::from_secs(3)).await;
    let terminal = events.last().unwrap();
    assert_eq!(terminal.outcome, SubsystemRestartOutcome::Exhausted);
    assert_eq!(terminal.reason, SubsystemRestartReason::Escalated);
    assert!(
        terminal.detail.contains("edge restart failed"),
        "terminal alert names the failed edge restart: {:?}",
        terminal.detail
    );

    // After the terminal alert, the watchdog must not spam more events
    // (Tier::Alerted is a no-op until recovery).
    let after_terminal = sink.len();
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(
        sink.len(),
        after_terminal,
        "no alert spam once the control plane has been notified"
    );

    // At least one edge bounce was attempted.
    assert!(edge.bounces() >= 1);

    trigger.fire();
    handle.await.unwrap();
}

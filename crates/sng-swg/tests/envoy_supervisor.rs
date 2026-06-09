// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//! Integration tests for the SWG [`EnvoySupervisor`] self-healing
//! loop, driven through the public crate API against the in-process
//! [`MockEnvoy`] harness plus an injectable readiness probe.
//!
//! These exercise the WS2 self-healing contract for Envoy end to end:
//!
//! * a crashed process is detected and hot-restarted, emitting a
//!   `Recovered` [`SubsystemRestart`] with a monotonic restart epoch;
//! * an "alive but not `/ready`" process is restarted with reason
//!   `Unresponsive` once the readiness blip persists past the
//!   flap-suppression threshold;
//! * a restart rolls back to the last-known-good config when a newer
//!   config was applied but never observed healthy;
//! * repeated restart failures back off exponentially and, once the
//!   attempt budget is spent, emit `Exhausted` and hand off;
//! * the configured fail-open / fail-closed posture is reflected on
//!   the emitted telemetry.
//!
//! Timing uses short real durations rather than a paused clock, for
//! the same reason as the IPS supervisor tests: the control loop
//! interleaves an interruptible shutdown wait with its poll/backoff
//! sleeps, so assertions wait for an exact event count rather than a
//! fixed sleep.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;

use sng_core::ShutdownTrigger;
use sng_core::events::{SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason};
use sng_core::restart::SubsystemRestartSink;
use sng_swg::{
    EnvoyProcess, EnvoyReadiness, EnvoySupervisor, EnvoySupervisorConfig, FailMode, HealthState,
    MockEnvoy, SWG_SUBSYSTEM_NAME, SwgError,
};

/// In-memory sink recording every restart event for assertions.
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

/// Readiness probe whose answer the test flips at will.
#[derive(Debug)]
struct SwitchableReadiness {
    ready: AtomicBool,
}

impl SwitchableReadiness {
    fn new(ready: bool) -> Arc<Self> {
        Arc::new(Self {
            ready: AtomicBool::new(ready),
        })
    }

    fn set(&self, ready: bool) {
        self.ready.store(ready, Ordering::SeqCst);
    }
}

#[async_trait]
impl EnvoyReadiness for SwitchableReadiness {
    async fn ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }
}

async fn wait_for_events(
    sink: &RecordingSink,
    n: usize,
    within: Duration,
) -> Vec<SubsystemRestart> {
    let deadline = Instant::now() + within;
    loop {
        if sink.len() >= n {
            return sink.snapshot();
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {n} restart event(s); saw {}",
            sink.len()
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

async fn wait_until(mut predicate: impl FnMut() -> bool, within: Duration) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for condition");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

fn fast_config() -> EnvoySupervisorConfig {
    EnvoySupervisorConfig {
        poll_interval: Duration::from_millis(5),
        failed_consecutive_required: 1,
        fail_mode: FailMode::Open,
        restart_initial_backoff: Duration::from_millis(10),
        restart_max_backoff: Duration::from_millis(40),
        restart_max_attempts: None,
    }
}

/// A running, ready Envoy mock.
async fn running_mock() -> Arc<MockEnvoy> {
    let mock = Arc::new(MockEnvoy::new());
    mock.start(std::path::Path::new("/etc/sng/envoy.yaml"))
        .await
        .unwrap();
    mock
}

#[tokio::test]
async fn crash_is_detected_and_hot_restarted_with_recovered_event() {
    let mock = running_mock().await;
    let readiness = SwitchableReadiness::new(true);
    let sink = Arc::new(RecordingSink::default());
    let sup = Arc::new(
        EnvoySupervisor::new(
            mock.clone(),
            readiness.clone(),
            "/etc/sng/envoy.yaml",
            fast_config(),
        )
        .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    // Observe at least one healthy probe so the active config is
    // promoted to last-known-good.
    wait_until(
        || sup.state() == HealthState::Healthy,
        Duration::from_secs(2),
    )
    .await;

    let starts_before = mock.start_count();
    mock.mark_crashed();

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    let ev = &events[0];
    assert_eq!(ev.subsystem, SWG_SUBSYSTEM_NAME);
    assert_eq!(ev.reason, SubsystemRestartReason::LivenessLost);
    assert_eq!(ev.outcome, SubsystemRestartOutcome::Recovered);
    assert_eq!(ev.attempt, 1);
    assert!(ev.fail_open, "default posture is fail-open");
    assert!(!ev.rolled_back_config, "config unchanged across the crash");
    assert!(
        mock.start_count() > starts_before,
        "supervisor issued a fresh start()"
    );
    // First supervisor restart uses epoch 1 (manager owns epoch 0).
    assert_eq!(mock.hot_restart_epochs(), vec![1]);
    assert!(
        ev.detail.contains("restart-epoch=1"),
        "epoch surfaces on telemetry detail: {:?}",
        ev.detail
    );

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn alive_but_not_ready_triggers_unresponsive_restart() {
    let mock = running_mock().await;
    let readiness = SwitchableReadiness::new(true);
    let sink = Arc::new(RecordingSink::default());
    let sup = Arc::new(
        EnvoySupervisor::new(
            mock.clone(),
            readiness.clone(),
            "/etc/sng/envoy.yaml",
            fast_config(),
        )
        .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    wait_until(
        || sup.state() == HealthState::Healthy,
        Duration::from_secs(2),
    )
    .await;

    // PID stays alive, but /ready stops returning LIVE — the wedged
    // listener case. Once the restart relaunches the process, mark it
    // ready again so the attempt recovers.
    readiness.set(false);

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    assert_eq!(events[0].reason, SubsystemRestartReason::Unresponsive);
    // The process never lost its PID, so the restart's is_alive check
    // sees it live and reports recovery.
    assert_eq!(events[0].outcome, SubsystemRestartOutcome::Recovered);

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn restart_rolls_back_to_last_known_good_config() {
    let mock = running_mock().await;
    let readiness = SwitchableReadiness::new(true);
    let sink = Arc::new(RecordingSink::default());
    let good = "/etc/sng/envoy.good.yaml";
    let bad = "/etc/sng/envoy.bad.yaml";
    let sup = Arc::new(
        EnvoySupervisor::new(mock.clone(), readiness.clone(), good, fast_config())
            .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    wait_until(
        || sup.last_known_good().as_deref() == Some(std::path::Path::new(good)),
        Duration::from_secs(2),
    )
    .await;

    // A new candidate config is applied, then the process dies before
    // that candidate is ever observed healthy.
    sup.set_active_config(bad);
    mock.mark_crashed();

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    assert!(
        events[0].rolled_back_config,
        "a never-healthy candidate config must be rolled back"
    );
    assert_eq!(events[0].outcome, SubsystemRestartOutcome::Recovered);
    assert_eq!(
        mock.recorded().started_with.last().map(PathBuf::as_path),
        Some(std::path::Path::new(good)),
        "restart relaunched with the last-known-good config"
    );

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn repeated_failures_back_off_then_exhaust_and_hand_off() {
    let mock = running_mock().await;
    let readiness = SwitchableReadiness::new(true);
    let sink = Arc::new(RecordingSink::default());
    let config = EnvoySupervisorConfig {
        restart_max_attempts: Some(3),
        ..fast_config()
    };
    let sup = Arc::new(
        EnvoySupervisor::new(
            mock.clone(),
            readiness.clone(),
            "/etc/sng/envoy.yaml",
            config,
        )
        .with_sink(sink.clone()),
    );

    // Every restart attempt fails to relaunch.
    for _ in 0..6 {
        mock.fail_next_start(SwgError::Process("simulated launch failure".into()));
    }

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    mock.mark_crashed();

    let events = wait_for_events(&sink, 3, Duration::from_secs(3)).await;
    assert_eq!(events.len(), 3, "exactly the attempt budget, then hand-off");

    let attempts: Vec<u32> = events.iter().map(|e| e.attempt).collect();
    assert_eq!(attempts, vec![1, 2, 3]);
    let backoffs: Vec<u64> = events.iter().map(|e| e.backoff_ms).collect();
    assert_eq!(
        backoffs,
        vec![10, 20, 40],
        "exponential backoff, capped at 40ms"
    );
    let outcomes: Vec<SubsystemRestartOutcome> = events.iter().map(|e| e.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            SubsystemRestartOutcome::Failed,
            SubsystemRestartOutcome::Failed,
            SubsystemRestartOutcome::Exhausted,
        ]
    );
    // Epochs increment strictly across attempts even when each fails.
    assert_eq!(mock.hot_restart_epochs(), vec![1, 2, 3]);
    assert!(
        events
            .iter()
            .all(|e| e.reason == SubsystemRestartReason::LivenessLost)
    );

    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor exited after exhausting its restart budget")
        .unwrap();
    drop(trigger);
}

#[tokio::test]
async fn fail_closed_posture_is_reflected_on_telemetry() {
    let mock = running_mock().await;
    let readiness = SwitchableReadiness::new(true);
    let sink = Arc::new(RecordingSink::default());
    let config = EnvoySupervisorConfig {
        fail_mode: FailMode::Closed,
        ..fast_config()
    };
    let sup = Arc::new(
        EnvoySupervisor::new(
            mock.clone(),
            readiness.clone(),
            "/etc/sng/envoy.yaml",
            config,
        )
        .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    mock.mark_crashed();
    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    assert!(
        !events[0].fail_open,
        "fail-closed posture must surface as fail_open=false"
    );

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn single_readiness_blip_below_threshold_does_not_restart() {
    let mock = running_mock().await;
    let readiness = SwitchableReadiness::new(true);
    let sink = Arc::new(RecordingSink::default());
    // Require 3 consecutive unhealthy probes before a restart.
    let config = EnvoySupervisorConfig {
        failed_consecutive_required: 3,
        ..fast_config()
    };
    let sup = Arc::new(
        EnvoySupervisor::new(
            mock.clone(),
            readiness.clone(),
            "/etc/sng/envoy.yaml",
            config,
        )
        .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    wait_until(
        || sup.state() == HealthState::Healthy,
        Duration::from_secs(2),
    )
    .await;

    // A single not-ready blip, then immediately ready again.
    readiness.set(false);
    wait_until(
        || sup.state() == HealthState::Degraded,
        Duration::from_secs(2),
    )
    .await;
    readiness.set(true);
    wait_until(
        || sup.state() == HealthState::Healthy,
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(sink.len(), 0, "a single blip must not trigger a restart");

    trigger.fire();
    handle.await.unwrap();
}

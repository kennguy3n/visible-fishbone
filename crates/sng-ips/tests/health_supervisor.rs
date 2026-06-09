// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//! Integration tests for the IPS [`HealthSupervisor`] self-healing
//! loop, driven through the public crate API against the in-process
//! [`MockSuricata`] harness.
//!
//! These exercise the WS2 self-healing contract end to end:
//!
//! * a crashed process is detected and restarted, emitting a
//!   `Recovered` [`SubsystemRestart`];
//! * a restart rolls back to the last-known-good config when a newer
//!   config was applied but never observed healthy;
//! * repeated restart failures back off exponentially and, once the
//!   attempt budget is spent, emit `Exhausted` and hand off;
//! * the configured fail-open / fail-closed posture is reflected on
//!   the emitted telemetry;
//! * an "alive but wedged" process (stats socket silent) is restarted
//!   with reason `Unresponsive`, and a sustained drop-ratio breach
//!   with reason `HealthFailed`.
//!
//! Timing uses short real durations rather than a paused clock: the
//! supervisor's control loop interleaves an interruptible shutdown
//! wait with its poll/backoff sleeps, so a paused clock would need
//! manual advancement at every select point. Short real intervals plus
//! a polled deadline keep the tests deterministic without that
//! fragility — assertions wait for an exact event count, never a fixed
//! sleep.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use parking_lot::Mutex;

use sng_core::ShutdownTrigger;
use sng_core::events::{SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason};
use sng_core::restart::SubsystemRestartSink;
use sng_ips::{
    FailMode, HealthState, HealthSupervisor, HealthSupervisorConfig, HealthThresholds, IpsError,
    MockSuricata, SUBSYSTEM_NAME, SuricataProcess, SuricataStats,
};

/// In-memory sink that records every restart event for assertions.
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

/// Poll until the sink has recorded at least `n` events or the
/// deadline elapses. Returns the recorded events; panics on timeout so
/// the failure points at the missing transition rather than a later
/// assertion.
async fn wait_for_events(sink: &RecordingSink, n: usize, within: Duration) -> Vec<SubsystemRestart> {
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

/// Poll until `predicate` holds or the deadline elapses.
async fn wait_until(mut predicate: impl FnMut() -> bool, within: Duration) {
    let deadline = Instant::now() + within;
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for condition");
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}

/// Stats snapshot with the given processed/dropped counters and zero
/// for the rest.
fn stats(processed: u64, dropped: u64) -> SuricataStats {
    SuricataStats {
        packets_processed: processed,
        packets_dropped: dropped,
        ..SuricataStats::zero()
    }
}

/// A fast-cadence config: single dead probe latches `Failed`, short
/// backoff, generous nothing else. Keeps the tests sub-second.
fn fast_config() -> HealthSupervisorConfig {
    HealthSupervisorConfig {
        poll_interval: Duration::from_millis(5),
        thresholds: HealthThresholds::default(),
        failed_consecutive_required: 1,
        fail_mode: FailMode::Open,
        restart_initial_backoff: Duration::from_millis(10),
        restart_max_backoff: Duration::from_millis(40),
        restart_max_attempts: None,
    }
}

/// Bring a fresh mock to a running, healthy steady state.
async fn running_mock() -> Arc<MockSuricata> {
    let mock = Arc::new(MockSuricata::new());
    mock.start(std::path::Path::new("/etc/sng/suricata.yaml"))
        .await
        .unwrap();
    mock
}

#[tokio::test]
async fn crash_is_detected_and_restarted_with_recovered_event() {
    let mock = running_mock().await;
    let sink = Arc::new(RecordingSink::default());
    let sup = Arc::new(
        HealthSupervisor::new(mock.clone(), "/etc/sng/suricata.yaml", fast_config())
            .with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    // Let the supervisor observe at least one healthy probe so the
    // active config is promoted to last-known-good.
    wait_until(|| sup.state() == HealthState::Healthy, Duration::from_secs(2)).await;

    let starts_before = mock.start_count();
    mock.mark_crashed();

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    let ev = &events[0];
    assert_eq!(ev.subsystem, SUBSYSTEM_NAME);
    assert_eq!(ev.reason, SubsystemRestartReason::LivenessLost);
    assert_eq!(ev.outcome, SubsystemRestartOutcome::Recovered);
    assert_eq!(ev.attempt, 1);
    assert!(ev.fail_open, "default posture is fail-open");
    assert!(!ev.rolled_back_config, "config was unchanged across the crash");
    assert!(
        mock.start_count() > starts_before,
        "supervisor issued a fresh start()"
    );

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn restart_rolls_back_to_last_known_good_config() {
    let mock = running_mock().await;
    let sink = Arc::new(RecordingSink::default());
    let good = "/etc/sng/suricata.good.yaml";
    let bad = "/etc/sng/suricata.bad.yaml";
    let sup = Arc::new(
        HealthSupervisor::new(mock.clone(), good, fast_config()).with_sink(sink.clone()),
    );

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    // Establish `good` as last-known-good via a healthy observation.
    wait_until(
        || sup.last_known_good().as_deref() == Some(std::path::Path::new(good)),
        Duration::from_secs(2),
    )
    .await;

    // Operator applies a new candidate config, then the process dies
    // before that candidate is ever observed healthy.
    sup.set_active_config(bad);
    mock.mark_crashed();

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    let ev = &events[0];
    assert!(
        ev.rolled_back_config,
        "a never-healthy candidate config must be rolled back"
    );
    assert_eq!(ev.outcome, SubsystemRestartOutcome::Recovered);
    assert_eq!(
        mock.last_config().as_deref(),
        Some(std::path::Path::new(good)),
        "restart relaunched with the last-known-good config, not the bad candidate"
    );

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn repeated_failures_back_off_then_exhaust_and_hand_off() {
    let mock = running_mock().await;
    let sink = Arc::new(RecordingSink::default());
    let config = HealthSupervisorConfig {
        restart_max_attempts: Some(3),
        ..fast_config()
    };
    let sup = Arc::new(
        HealthSupervisor::new(mock.clone(), "/etc/sng/suricata.yaml", config)
            .with_sink(sink.clone()),
    );

    // Every restart attempt fails to launch.
    for _ in 0..6 {
        mock.fail_next_start(IpsError::Process("simulated launch failure".into()));
    }

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    mock.mark_crashed();

    let events = wait_for_events(&sink, 3, Duration::from_secs(3)).await;
    assert_eq!(events.len(), 3, "exactly the attempt budget, then hand-off");

    // Attempts climb 1..=3 with doubling backoff and the terminal
    // attempt reports Exhausted.
    let attempts: Vec<u32> = events.iter().map(|e| e.attempt).collect();
    assert_eq!(attempts, vec![1, 2, 3]);
    let backoffs: Vec<u64> = events.iter().map(|e| e.backoff_ms).collect();
    assert_eq!(backoffs, vec![10, 20, 40], "exponential backoff, capped at 40ms");
    let outcomes: Vec<SubsystemRestartOutcome> = events.iter().map(|e| e.outcome).collect();
    assert_eq!(
        outcomes,
        vec![
            SubsystemRestartOutcome::Failed,
            SubsystemRestartOutcome::Failed,
            SubsystemRestartOutcome::Exhausted,
        ]
    );
    assert!(events.iter().all(|e| e.reason == SubsystemRestartReason::LivenessLost));
    assert!(events.iter().all(|e| !e.detail.is_empty()), "failures carry detail");

    // After exhaustion the supervisor returns on its own — the
    // hand-off to the top-level watchdog. No shutdown fire needed.
    tokio::time::timeout(Duration::from_secs(2), handle)
        .await
        .expect("supervisor exited after exhausting its restart budget")
        .unwrap();
    drop(trigger);
}

#[tokio::test]
async fn fail_closed_posture_is_reflected_on_telemetry() {
    let mock = running_mock().await;
    let sink = Arc::new(RecordingSink::default());
    let config = HealthSupervisorConfig {
        fail_mode: FailMode::Closed,
        ..fast_config()
    };
    let sup = Arc::new(
        HealthSupervisor::new(mock.clone(), "/etc/sng/suricata.yaml", config)
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
async fn alive_but_unresponsive_stats_socket_triggers_unresponsive_restart() {
    let mock = running_mock().await;
    // PID stays alive across the whole test; only the stats socket
    // goes silent.
    mock.force_alive(true);
    let sink = Arc::new(RecordingSink::default());
    let sup = Arc::new(
        HealthSupervisor::new(mock.clone(), "/etc/sng/suricata.yaml", fast_config())
            .with_sink(sink.clone()),
    );

    // One stats() failure is enough: failed_consecutive_required == 1.
    mock.fail_next_stats(IpsError::Process("stats socket timeout".into()));

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    assert_eq!(events[0].reason, SubsystemRestartReason::Unresponsive);
    assert_eq!(events[0].outcome, SubsystemRestartOutcome::Recovered);

    trigger.fire();
    handle.await.unwrap();
}

#[tokio::test]
async fn sustained_drop_ratio_breach_triggers_health_failed_restart() {
    let mock = running_mock().await;
    mock.force_alive(true);
    let sink = Arc::new(RecordingSink::default());
    let sup = Arc::new(
        HealthSupervisor::new(mock.clone(), "/etc/sng/suricata.yaml", fast_config())
            .with_sink(sink.clone()),
    );

    // First read establishes a baseline (healthy); the second read
    // jumps the drop counter so the per-interval delta breaches the
    // 25% failed_drop_ratio threshold while the process is alive.
    mock.queue_stats(stats(0, 0));
    mock.queue_stats(stats(100, 100));

    let (trigger, signal) = ShutdownTrigger::new();
    let driver = sup.clone();
    let handle = tokio::spawn(async move { driver.run(signal).await });

    let events = wait_for_events(&sink, 1, Duration::from_secs(2)).await;
    assert_eq!(events[0].reason, SubsystemRestartReason::HealthFailed);

    trigger.fire();
    handle.await.unwrap();
}

// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! PAL posture-collection subsystem.
//!
//! Periodically invokes a [`sng_pal::PostureCollector`] and
//! fans the resulting [`sng_pal::PostureSnapshot`] out onto:
//!
//! 1. The telemetry pipeline as an [`AgentEvent`] (so the
//!    control-plane dashboards see fresh posture for the
//!    device).
//! 2. A `tokio::sync::watch` channel so the ZTNA subsystem
//!    can read the latest snapshot synchronously when
//!    evaluating an access request.
//!
//! The cadence is operator-configurable; the default is 30s
//! which matches the typical control-plane staleness budget
//! for a roaming endpoint.

use crate::config::PostureConfig;
use async_trait::async_trait;
use sng_core::envelope::Platform;
use sng_core::events::AgentEvent;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_pal::posture::{PostureCollector, PostureSnapshot};
use sng_telemetry::{PipelineHandle, TelemetryEvent, TrySubmitError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::watch;
use tokio::task;
use tokio::time::{MissedTickBehavior, interval};

/// PAL posture-collection subsystem.
pub struct PalPostureSubsystem {
    collector: Arc<dyn PostureCollector>,
    platform: Platform,
    device_id: String,
    telemetry: PipelineHandle,
    snapshot_tx: watch::Sender<Option<PostureSnapshot>>,
    snapshot_rx: watch::Receiver<Option<PostureSnapshot>>,
    stats: Arc<PostureStats>,
    collect_interval: Duration,
}

impl std::fmt::Debug for PalPostureSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PalPostureSubsystem")
            .field("collect_interval", &self.collect_interval)
            .field("platform", &self.platform)
            .finish_non_exhaustive()
    }
}

/// Atomic counters surfaced through the health endpoint.
#[derive(Debug, Default)]
pub struct PostureStats {
    /// Total collector invocations.
    pub collections: AtomicU64,
    /// Collector invocations that returned an error.
    pub collection_errors: AtomicU64,
    /// Telemetry submissions dropped because the pipeline
    /// channel was full.
    pub telemetry_drops_full: AtomicU64,
    /// Telemetry submissions dropped because the pipeline
    /// channel was closed (pipeline already shutting down).
    pub telemetry_drops_closed: AtomicU64,
}

impl PalPostureSubsystem {
    /// Build from the selected collector backend + telemetry
    /// pipeline handle + the agent identity's device id /
    /// platform. The watch channel is created internally; use
    /// [`Self::snapshot_rx`] to subscribe.
    #[must_use]
    pub fn new(
        cfg: &PostureConfig,
        collector: Arc<dyn PostureCollector>,
        platform: Platform,
        device_id: impl Into<String>,
        telemetry: PipelineHandle,
    ) -> Self {
        let (snapshot_tx, snapshot_rx) = watch::channel(None);
        Self {
            collector,
            platform,
            device_id: device_id.into(),
            telemetry,
            snapshot_tx,
            snapshot_rx,
            stats: Arc::new(PostureStats::default()),
            collect_interval: cfg.collect_interval,
        }
    }

    /// Subscribe to posture-snapshot updates. The receiver's
    /// initial value is `None` until the first collection
    /// succeeds.
    #[must_use]
    pub fn snapshot_rx(&self) -> watch::Receiver<Option<PostureSnapshot>> {
        self.snapshot_rx.clone()
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<PostureStats> {
        &self.stats
    }
}

#[async_trait]
impl Subsystem for PalPostureSubsystem {
    fn name(&self) -> &'static str {
        "pal_posture"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let collector = Arc::clone(&self.collector);
        let telemetry = self.telemetry.clone();
        let stats = Arc::clone(&self.stats);
        let snapshot_tx = self.snapshot_tx.clone();
        let platform = self.platform;
        let device_id = self.device_id.clone();
        let collect_interval = self.collect_interval;

        Ok(task::spawn(async move {
            let mut ticker = interval(collect_interval);
            ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // Eat the immediate tick — first probe fires at
            // collect_interval, not at t=0, so the binary
            // doesn't hammer the OS APIs the instant the
            // supervisor boots.
            ticker.tick().await;

            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    _ = ticker.tick() => {
                        stats.collections.fetch_add(1, Ordering::Relaxed);
                        match collector.collect().await {
                            Ok(snapshot) => {
                                // Publish to subscribers
                                // first so a slow telemetry
                                // pipeline never delays
                                // the ZTNA gate's view of
                                // posture freshness.
                                let _ = snapshot_tx.send(Some(snapshot.clone()));

                                let event = AgentEvent {
                                    device_id: device_id.clone(),
                                    event_type: "posture".to_owned(),
                                    posture_snapshot: serde_json::to_value(&snapshot).ok(),
                                    reason: String::new(),
                                    platform,
                                };
                                if let Err(err) =
                                    telemetry.try_submit(TelemetryEvent::Agent(event))
                                {
                                    match err {
                                        TrySubmitError::Full(_) => {
                                            stats
                                                .telemetry_drops_full
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                        TrySubmitError::Closed(_) => {
                                            stats
                                                .telemetry_drops_closed
                                                .fetch_add(1, Ordering::Relaxed);
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                stats.collection_errors.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(
                                    target: "sng_agent::pal_posture",
                                    error = %err,
                                    "posture collection failed; will retry next tick"
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

#[async_trait]
impl HealthCheck for PalPostureSubsystem {
    fn name(&self) -> &'static str {
        "pal_posture"
    }

    async fn check(&self) -> SubsystemHealth {
        let collections = self.stats.collections.load(Ordering::Relaxed);
        let collection_errors = self.stats.collection_errors.load(Ordering::Relaxed);
        let drops_full = self.stats.telemetry_drops_full.load(Ordering::Relaxed);
        let drops_closed = self.stats.telemetry_drops_closed.load(Ordering::Relaxed);

        let status = if collection_errors > 0 && collections == collection_errors {
            HealthStatus::Down
        } else if collection_errors > 0 || drops_full > 0 || drops_closed > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "collections={collections}, errors={collection_errors}, \
                 drops_full={drops_full}, drops_closed={drops_closed}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::ShutdownTrigger;
    use sng_core::ids::{DeviceId, TenantId};
    use sng_pal::posture::UnknownPostureCollector;
    use std::sync::Arc;
    use uuid::Uuid;

    fn fresh_pipeline_handle() -> (
        PipelineHandle,
        sng_telemetry::Pipeline<sng_telemetry::SystemTime>,
    ) {
        use sng_comms::TelemetryClient;
        use sng_core::envelope::Platform;
        use sng_telemetry::{
            AgentIdentity, Enricher, PcapRing, PcapRingConfig, Pipeline, PipelineConfig,
            RedactionPolicy, SystemTime,
        };
        let identity = AgentIdentity::new(
            TenantId::from_uuid(Uuid::from_u128(1)),
            DeviceId::from_uuid(Uuid::from_u128(2)),
            None,
            Platform::Linux,
        );
        let enricher = Enricher::new(identity.clone(), SystemTime);
        let egress = Arc::new(TelemetryClient::new(
            sng_comms::TelemetryClientConfig::with_defaults(identity.to_comms_enrichment_context()),
        ));
        let pcap = Arc::new(PcapRing::new(PcapRingConfig {
            max_packets: 1,
            max_total_bytes: 1024,
            max_packet_bytes: 1024,
        }));
        let (pipeline, handle) = Pipeline::new(
            PipelineConfig::default(),
            enricher,
            RedactionPolicy::strict(),
            egress,
            pcap,
        )
        .expect("pipeline");
        (handle, pipeline)
    }

    #[tokio::test]
    async fn subsystem_collects_once_at_first_tick_and_publishes_snapshot() {
        let (handle, pipeline) = fresh_pipeline_handle();
        let pipeline_task = tokio::spawn(async move { pipeline.run().await });
        let subsys = PalPostureSubsystem::new(
            &PostureConfig {
                collect_interval: Duration::from_millis(10),
            },
            Arc::new(UnknownPostureCollector),
            Platform::Linux,
            "device-1",
            handle.clone(),
        );
        let mut rx = subsys.snapshot_rx();
        let (trigger, signal) = ShutdownTrigger::new();
        let task_handle = subsys.start(signal).await.expect("start");

        // Wait until the first snapshot is published or until
        // we hit a generous safety budget (50ms is well above
        // the 10ms tick).
        for _ in 0..10 {
            if rx.borrow_and_update().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            rx.borrow().is_some(),
            "posture subsystem should publish at least one snapshot"
        );

        trigger.fire();
        let join = task_handle.await.expect("join");
        assert!(join.is_ok());
        // Drop both producer handles so the pipeline's
        // input channel closes and `run()` returns.
        drop(subsys);
        drop(handle);
        pipeline_task.await.expect("pipeline join");
    }

    #[tokio::test]
    async fn subsystem_shuts_down_on_signal_without_first_collection() {
        let (handle, pipeline) = fresh_pipeline_handle();
        let pipeline_task = tokio::spawn(async move { pipeline.run().await });
        let subsys = PalPostureSubsystem::new(
            &PostureConfig {
                // Very long interval — guaranteed to NOT
                // fire before the test cancels.
                collect_interval: Duration::from_secs(3600),
            },
            Arc::new(UnknownPostureCollector),
            Platform::Linux,
            "device-1",
            handle.clone(),
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let task_handle = subsys.start(signal).await.expect("start");
        trigger.fire();
        let join = task_handle.await.expect("join");
        assert!(join.is_ok());
        let stats = subsys.stats();
        assert_eq!(stats.collections.load(Ordering::Relaxed), 0);
        // Drop both producer handles so the pipeline's
        // input channel closes and `run()` returns.
        drop(subsys);
        drop(handle);
        pipeline_task.await.expect("pipeline join");
    }
}

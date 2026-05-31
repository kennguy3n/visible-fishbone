// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! PAL traffic-capture subsystem.
//!
//! Drives a [`sng_pal::TrafficCapture`] backend in a tight
//! polling loop. For each [`sng_pal::PacketRecord`] the
//! subsystem:
//!
//! 1. Maps the L3/L4 5-tuple into a
//!    [`sng_policy_eval::Flow`] addressed at
//!    [`sng_policy_eval::EnforcementDomain::Ngfw`] (endpoint
//!    side; the kernel hook fires on every flow that lands on
//!    the host's PAL backend regardless of which subsystem
//!    will ultimately enforce it).
//! 2. Evaluates the flow against the live
//!    [`sng_policy_eval::PolicyEngine`].
//! 3. Submits a [`FlowEvent`] to the telemetry pipeline via
//!    `try_submit` so a saturated pipeline drops at the
//!    producer rather than backpressure-ing the kernel
//!    capture loop.
//!
//! The actual *enforcement* (drop / reset / mark) is the job
//! of a per-OS PAL hook in a follow-on PR (WFP on Windows,
//! Network Extension on macOS, nftables TPROXY on Linux) —
//! this subsystem's responsibility ends at observation +
//! verdict computation + telemetry. The agent's binary
//! refuses to boot without a verdict producer; the PR that
//! lands the enforcement hook can attach to the same
//! producer through a sibling subscriber.

use crate::config::CaptureConfig;
use async_trait::async_trait;
use sng_core::envelope::Verdict as WireVerdict;
use sng_core::events::FlowEvent;
use sng_core::{
    HealthCheck, HealthStatus, ShutdownSignal, Subsystem, SubsystemError, SubsystemHandle,
    SubsystemHealth,
};
use sng_pal::traffic::{PacketDirection, PacketRecord, TrafficCapture, TrafficCaptureError};
use sng_policy_eval::{
    EnforcementDomain, FlowBuilder, InspectLevel, PolicyEngine, Verdict as PolicyVerdict,
};
use sng_telemetry::{PipelineHandle, TelemetryEvent, TrySubmitError};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::task;

/// PAL traffic-capture subsystem.
pub struct PalCaptureSubsystem {
    capture: Arc<dyn TrafficCapture>,
    engine: Arc<PolicyEngine>,
    telemetry: PipelineHandle,
    stats: Arc<CaptureStats>,
    idle_sleep: Duration,
}

impl std::fmt::Debug for PalCaptureSubsystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PalCaptureSubsystem")
            .field("idle_sleep", &self.idle_sleep)
            .finish_non_exhaustive()
    }
}

/// Atomic counters surfaced through the health endpoint.
#[derive(Debug, Default)]
pub struct CaptureStats {
    /// Packets observed by the underlying backend.
    pub packets_observed: AtomicU64,
    /// Flow evaluations whose verdict was `Allow`.
    pub verdict_allow: AtomicU64,
    /// Flow evaluations whose verdict was `Deny`.
    pub verdict_deny: AtomicU64,
    /// Flow evaluations whose verdict was `Inspect` (any
    /// level) or `Steer` (any class).
    pub verdict_other: AtomicU64,
    /// Telemetry submissions dropped because the pipeline
    /// channel was full.
    pub telemetry_drops_full: AtomicU64,
    /// Telemetry submissions dropped because the pipeline
    /// channel was closed (pipeline already shutting down).
    pub telemetry_drops_closed: AtomicU64,
    /// `TrafficCapture::next` returned an error.
    pub capture_errors: AtomicU64,
    /// `TrafficCapture::next` returned `Ok(None)` (clean
    /// closure of the kernel channel).
    pub capture_closed: AtomicU64,
}

impl PalCaptureSubsystem {
    /// Build from the selected capture backend + policy engine
    /// + telemetry pipeline handle.
    #[must_use]
    pub fn new(
        cfg: &CaptureConfig,
        capture: Arc<dyn TrafficCapture>,
        engine: Arc<PolicyEngine>,
        telemetry: PipelineHandle,
    ) -> Self {
        Self {
            capture,
            engine,
            telemetry,
            stats: Arc::new(CaptureStats::default()),
            idle_sleep: cfg.idle_sleep,
        }
    }

    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<CaptureStats> {
        &self.stats
    }
}

#[async_trait]
impl Subsystem for PalCaptureSubsystem {
    fn name(&self) -> &'static str {
        "pal_capture"
    }

    async fn start(&self, shutdown: ShutdownSignal) -> Result<SubsystemHandle, SubsystemError> {
        let capture = Arc::clone(&self.capture);
        let engine = Arc::clone(&self.engine);
        let telemetry = self.telemetry.clone();
        let stats = Arc::clone(&self.stats);
        let idle_sleep = self.idle_sleep;

        Ok(task::spawn(async move {
            loop {
                tokio::select! {
                    () = shutdown.wait() => break,
                    next = capture.next() => match next {
                        Ok(Some(record)) => {
                            stats.packets_observed.fetch_add(1, Ordering::Relaxed);
                            let event = evaluate_and_render(&engine, &record);
                            match event.verdict {
                                WireVerdict::Allow => {
                                    stats.verdict_allow.fetch_add(1, Ordering::Relaxed);
                                }
                                WireVerdict::Deny => {
                                    stats.verdict_deny.fetch_add(1, Ordering::Relaxed);
                                }
                                _ => {
                                    stats.verdict_other.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            if let Err(err) = telemetry.try_submit(TelemetryEvent::Flow(event)) {
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
                        Ok(None) => {
                            // Kernel closed the channel; we are
                            // not getting any more packets until
                            // (re-)init. Sleep before retrying
                            // so we don't burn CPU spinning on
                            // a dead capture.
                            stats.capture_closed.fetch_add(1, Ordering::Relaxed);
                            tokio::time::sleep(idle_sleep).await;
                        }
                        Err(err) => {
                            stats.capture_errors.fetch_add(1, Ordering::Relaxed);
                            tracing::warn!(
                                target: "sng_agent::pal_capture",
                                error = %err,
                                "traffic capture failed; will retry after idle_sleep"
                            );
                            // Backend-specific permanent
                            // errors (e.g. Unavailable) are
                            // worth surfacing in health but
                            // don't kill the subsystem — the
                            // operator may flip the PAL
                            // backend at runtime.
                            if matches!(err, TrafficCaptureError::Closed) {
                                break;
                            }
                            tokio::time::sleep(idle_sleep).await;
                        }
                    }
                }
            }
            Ok(())
        }))
    }
}

#[async_trait]
impl HealthCheck for PalCaptureSubsystem {
    fn name(&self) -> &'static str {
        "pal_capture"
    }

    async fn check(&self) -> SubsystemHealth {
        let observed = self.stats.packets_observed.load(Ordering::Relaxed);
        let allow = self.stats.verdict_allow.load(Ordering::Relaxed);
        let deny = self.stats.verdict_deny.load(Ordering::Relaxed);
        let other = self.stats.verdict_other.load(Ordering::Relaxed);
        let drops_full = self.stats.telemetry_drops_full.load(Ordering::Relaxed);
        let drops_closed = self.stats.telemetry_drops_closed.load(Ordering::Relaxed);
        let capture_errors = self.stats.capture_errors.load(Ordering::Relaxed);

        // Sustained capture errors with zero observed packets
        // is the "backend is dead" signal — Down rather than
        // Degraded so the dashboard renders a red marker.
        let status = if capture_errors > 0 && observed == 0 {
            HealthStatus::Down
        } else if drops_full > 0 || capture_errors > 0 || drops_closed > 0 {
            HealthStatus::Degraded
        } else {
            HealthStatus::Up
        };

        SubsystemHealth {
            name: <Self as HealthCheck>::name(self).into(),
            status,
            detail: Some(format!(
                "observed={observed}, allow={allow}, deny={deny}, other={other}, \
                 drops_full={drops_full}, drops_closed={drops_closed}, errors={capture_errors}"
            )),
        }
    }
}

/// Build a [`Flow`] from a [`PacketRecord`], evaluate it
/// against the engine, and render a [`FlowEvent`] suitable
/// for the telemetry pipeline.
fn evaluate_and_render(engine: &PolicyEngine, record: &PacketRecord) -> FlowEvent {
    let src_ip = record.source.addr();
    let dst_ip = record.destination.addr();
    // L4 port isn't carried on the PacketRecord (the trait
    // intentionally exposes only what every backend can
    // produce — see traffic.rs:21-43). We pass the destination
    // port as 0 to the engine; rules that don't reference a
    // port-shaped predicate match unchanged, and the
    // FlowEvent records the same.
    let flow = FlowBuilder::new(EnforcementDomain::Ngfw)
        .source_ip(src_ip)
        .destination_ip(dst_ip)
        .destination_port(0)
        .build();
    let verdict = engine.evaluate(&flow);
    FlowEvent {
        src_ip: src_ip.to_string(),
        dst_ip: dst_ip.to_string(),
        src_port: 0,
        dst_port: 0,
        protocol: protocol_str(record.protocol).to_owned(),
        app_id: None,
        verdict: policy_verdict_to_wire(&verdict),
        score: None,
        bytes_in: if record.direction == PacketDirection::Ingress {
            u64::from(record.length)
        } else {
            0
        },
        bytes_out: if record.direction == PacketDirection::Egress {
            u64::from(record.length)
        } else {
            0
        },
        duration_ms: 0,
    }
}

/// Map a [`PolicyVerdict`] (the engine's rich enum) onto the
/// wire-format [`WireVerdict`] the [`FlowEvent`] carries. The
/// FlowEvent's Verdict is a flat enum so the Go consumer can
/// filter uniformly — Inspect and Steer collapse onto
/// `Inspect`, which is the on-wire indicator that an
/// engine-elective action was taken.
fn policy_verdict_to_wire(v: &PolicyVerdict) -> WireVerdict {
    match v {
        PolicyVerdict::Allow => WireVerdict::Allow,
        PolicyVerdict::Deny => WireVerdict::Deny,
        PolicyVerdict::Inspect { level } => match level {
            InspectLevel::Lite | InspectLevel::Full => WireVerdict::Inspect,
        },
        // Steer + Decrypt both correspond to engine-elective
        // actions taken on a permitted flow — collapse onto
        // the wire's `Inspect` so dashboards filter uniformly.
        PolicyVerdict::Steer { .. } | PolicyVerdict::Decrypt => WireVerdict::Inspect,
        // Log and SuggestOnly both surface on the wire as
        // `Log`:
        // * `Log` is a pass-through verb (metadata-only, no
        //   payload, no decrypt) — emit `Log` so the consumer
        //   can distinguish a permitted-but-logged flow from
        //   a plain Allow.
        // * `SuggestOnly` is advisory — never enforced. The
        //   wrapped verb is the would-be outcome; on the wire
        //   we surface as `Log` (advisory metadata) regardless
        //   of suggestion content so a misconfigured advisory
        //   rule cannot accidentally signal Deny / Allow.
        PolicyVerdict::Log | PolicyVerdict::SuggestOnly { .. } => WireVerdict::Log,
    }
}

/// Convert the IANA IP protocol number on a [`PacketRecord`]
/// into the canonical short string the FlowEvent carries. We
/// stick to the four short tags `internal/nats/schema/events.go`
/// understands — anything else collapses onto `other`.
fn protocol_str(proto: u8) -> &'static str {
    match proto {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use ipnet::IpNet;
    use sng_core::ShutdownTrigger;
    use sng_core::ids::{DeviceId, TenantId};
    use sng_pal::traffic::InMemoryCapture;
    use sng_policy_eval::{BundleTarget, deny_all_skeleton_body};
    use sng_telemetry::{Enricher, Pipeline, PipelineConfig, RedactionPolicy, SystemTime};
    use std::str::FromStr;
    use std::sync::Arc;
    use uuid::Uuid;

    fn engine() -> Arc<PolicyEngine> {
        let body = deny_all_skeleton_body(BundleTarget::Endpoint);
        Arc::new(PolicyEngine::from_body(&body, BundleTarget::Endpoint).expect("engine"))
    }

    fn fresh_pipeline_handle() -> (PipelineHandle, Pipeline<SystemTime>) {
        use sng_comms::TelemetryClient;
        use sng_core::envelope::Platform;
        use sng_telemetry::{AgentIdentity, PcapRing, PcapRingConfig};
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

    fn sample_record() -> PacketRecord {
        PacketRecord {
            captured_at: Utc::now(),
            interface_index: 2,
            direction: PacketDirection::Egress,
            source: IpNet::from_str("10.0.0.1/32").expect("net"),
            destination: IpNet::from_str("1.1.1.1/32").expect("net"),
            protocol: 6,
            length: 1500,
        }
    }

    #[test]
    fn evaluate_and_render_maps_protocol_and_direction() {
        let e = engine();
        let record = sample_record();
        let event = evaluate_and_render(&e, &record);
        assert_eq!(event.src_ip, "10.0.0.1");
        assert_eq!(event.dst_ip, "1.1.1.1");
        assert_eq!(event.protocol, "tcp");
        assert_eq!(event.bytes_out, 1500);
        assert_eq!(event.bytes_in, 0);
        // The deny_all bootstrap bundle yields Deny.
        assert_eq!(event.verdict, WireVerdict::Deny);
    }

    #[test]
    fn protocol_str_collapses_unknown_to_other() {
        assert_eq!(protocol_str(1), "icmp");
        assert_eq!(protocol_str(6), "tcp");
        assert_eq!(protocol_str(17), "udp");
        assert_eq!(protocol_str(255), "other");
    }

    #[test]
    fn policy_verdict_inspect_and_steer_collapse_to_wire_inspect() {
        use sng_core::traffic_class::TrafficClass;
        assert_eq!(
            policy_verdict_to_wire(&PolicyVerdict::Inspect {
                level: InspectLevel::Lite
            }),
            WireVerdict::Inspect
        );
        assert_eq!(
            policy_verdict_to_wire(&PolicyVerdict::Steer {
                class: TrafficClass::TrustedDirect
            }),
            WireVerdict::Inspect
        );
    }

    #[tokio::test]
    async fn subsystem_drains_capture_and_emits_flow_events() {
        let cap = Arc::new(InMemoryCapture::new());
        cap.push(sample_record()).await;
        cap.push(sample_record()).await;
        let e = engine();
        let (handle, pipeline) = fresh_pipeline_handle();
        let pipeline_task = tokio::spawn(async move { pipeline.run().await });
        let subsys = PalCaptureSubsystem::new(
            &CaptureConfig {
                idle_sleep: Duration::from_millis(5),
                channel_capacity: 1024,
            },
            cap,
            e,
            handle.clone(),
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let task_handle = subsys.start(signal).await.expect("start");

        // Give the loop time to drain both records.
        tokio::time::sleep(Duration::from_millis(50)).await;
        trigger.fire();
        let join = task_handle.await.expect("join");
        assert!(join.is_ok());

        let observed = subsys.stats.packets_observed.load(Ordering::Relaxed);
        assert_eq!(observed, 2, "subsystem should drain both records");
        // Drop both producer handles so the pipeline's
        // input channel closes and `run()` returns.
        drop(subsys);
        drop(handle);
        pipeline_task.await.expect("pipeline join");
    }

    #[tokio::test]
    async fn subsystem_shuts_down_on_signal_with_empty_capture() {
        let cap = Arc::new(InMemoryCapture::new());
        let e = engine();
        let (handle, pipeline) = fresh_pipeline_handle();
        let pipeline_task = tokio::spawn(async move { pipeline.run().await });
        let subsys = PalCaptureSubsystem::new(
            &CaptureConfig {
                idle_sleep: Duration::from_millis(5),
                channel_capacity: 1024,
            },
            cap,
            e,
            handle.clone(),
        );
        let (trigger, signal) = ShutdownTrigger::new();
        let task_handle = subsys.start(signal).await.expect("start");
        trigger.fire();
        let join = task_handle.await.expect("join");
        assert!(join.is_ok());
        // Drop both producer handles so the pipeline's
        // input channel closes and `run()` returns.
        drop(subsys);
        drop(handle);
        pipeline_task.await.expect("pipeline join");
    }
}

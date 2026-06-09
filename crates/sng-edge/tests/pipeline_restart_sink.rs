// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
//! End-to-end test for [`sng_edge::PipelineRestartSink`], the
//! production [`SubsystemRestartSink`] that bridges the WS2 self-healing
//! supervisors to the telemetry pipeline ("alert control plane" leg).
//!
//! This wires a real [`Pipeline`] to a real `sng_comms::TelemetryClient`
//! (in-memory spool mode, no network) and asserts that a
//! [`SubsystemRestart`] handed to the sink flows through the same
//! dedup → redact → enrich → spool path as traffic telemetry and lands
//! on the egress spool as exactly one envelope. It also asserts the
//! non-blocking contract: recording against a closed pipeline neither
//! panics nor blocks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use sng_comms::{TelemetryClient, TelemetryClientConfig};
use sng_core::envelope::Platform;
use sng_core::events::{
    SubsystemRestart, SubsystemRestartOutcome, SubsystemRestartReason,
};
use sng_core::ids::{DeviceId, SiteId, TenantId};
use sng_core::restart::SubsystemRestartSink;
use sng_core::traffic_class::TrafficClass;
use sng_edge::PipelineRestartSink;
use sng_telemetry::{
    AgentIdentity, Enricher, PcapRing, PcapRingConfig, Pipeline, PipelineConfig, RedactionPolicy,
    SystemTime,
};
use uuid::Uuid;

fn identity() -> AgentIdentity {
    AgentIdentity {
        tenant_id: TenantId::from(Uuid::from_u128(0x1111)),
        device_id: DeviceId::from(Uuid::from_u128(0x2222)),
        site_id: Some(SiteId::from(Uuid::from_u128(0x3333))),
        platform: Platform::Linux,
        default_traffic_class: TrafficClass::InspectFull,
    }
}

fn mk_egress(spool_cap: usize) -> Arc<TelemetryClient> {
    let cfg = TelemetryClientConfig {
        spool_capacity: spool_cap,
        ..TelemetryClientConfig::with_defaults(identity().to_comms_enrichment_context())
    };
    Arc::new(TelemetryClient::new(cfg))
}

fn mk_pipeline(egress: Arc<TelemetryClient>) -> (Pipeline<SystemTime>, sng_telemetry::PipelineHandle) {
    let pcap = Arc::new(PcapRing::new(PcapRingConfig::default()));
    Pipeline::new(
        PipelineConfig::default(),
        Enricher::new(identity(), SystemTime),
        RedactionPolicy::strict(),
        egress,
        pcap,
    )
    .expect("identity contract holds in test wiring")
}

fn restart_event() -> SubsystemRestart {
    SubsystemRestart {
        subsystem: "ips".to_owned(),
        reason: SubsystemRestartReason::HealthFailed,
        outcome: SubsystemRestartOutcome::Recovered,
        attempt: 1,
        fail_open: false,
        rolled_back_config: true,
        backoff_ms: 1_000,
        detail: "liveness probe failed; restarted with last-known-good config".to_owned(),
    }
}

#[tokio::test]
async fn restart_event_flows_through_pipeline_to_spool() {
    let egress = mk_egress(1024);
    let (pipeline, handle) = mk_pipeline(Arc::clone(&egress));
    let sink = PipelineRestartSink::new(handle);

    let before = egress.spool_stats().pushed;

    // The sink only enqueues; the pipeline task owns the drain loop.
    // Spawn it, hand it one event through the sink, then drop the sink
    // so every producer handle is gone — `run` then drains the channel,
    // force-seals the egress builder, and exits.
    let pump = tokio::spawn(pipeline.run());
    sink.record(restart_event()).await;
    drop(sink);
    tokio::time::timeout(std::time::Duration::from_secs(2), pump)
        .await
        .expect("pipeline drains and exits once producers drop")
        .expect("pipeline task does not panic");

    let after = egress.spool_stats().pushed;
    assert_eq!(
        after - before,
        1,
        "the restart event reached the egress spool as exactly one envelope"
    );
}

#[tokio::test]
async fn recording_against_closed_pipeline_does_not_panic() {
    let egress = mk_egress(16);
    let (pipeline, handle) = mk_pipeline(egress);
    let sink = PipelineRestartSink::new(handle);

    // Drop the pipeline (and thus its receiver): the channel is now
    // closed. The non-blocking sink must swallow this rather than
    // panic or block the supervisor's self-healing loop.
    drop(pipeline);

    sink.record(restart_event()).await;
    sink.record(restart_event()).await;
}

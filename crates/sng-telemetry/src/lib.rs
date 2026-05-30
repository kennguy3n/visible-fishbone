// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary
// `.expect("fixture")` / `.unwrap()` are idiomatic in test
// scaffolding; CI runs `cargo clippy --tests -D warnings` across
// the workspace. Allow them in `#[cfg(test)]` only — production
// code paths still get the workspace-level warning.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_possible_wrap,
        clippy::cast_lossless,
        clippy::float_cmp,
    )
)]

//! # sng-telemetry
//!
//! Telemetry collector for the ShieldNet Gateway agent.
//!
//! The crate implements the five-stage pipeline described in
//! `ARCHITECTURE.md` §4.8:
//!
//! 1. **Collect** — typed [`TelemetryEvent`]s arrive from each
//!    agent subsystem (DNS filter, firewall, IPS, SWG, ZTNA,
//!    SD-WAN, agent lifecycle). Subsystems implement
//!    [`EventSource`] or push directly into a
//!    [`PipelineHandle`].
//! 2. **Dedup** — a rolling window
//!    ([`Dedup`]) drops fingerprint-equal events observed
//!    within the configured TTL. The fingerprint is computed
//!    over producer-relevant fields only — byte counters and
//!    other observation-dependent fields are excluded — so a
//!    retry path emitting the same flow twice collapses into
//!    one record.
//! 3. **Redact** — [`RedactionPolicy::redact`] strips per-class
//!    payload fields the active policy disallows (DNS upstream,
//!    HTTP URL, HTTP SNI, agent posture snapshot). Strict mode
//!    is the default.
//! 4. **Enrich** — [`Enricher::enrich`] wraps the typed event
//!    into a fully populated [`sng_core::envelope::Envelope`]
//!    with tenant/device/site/timestamp/traffic_class/byte
//!    counters all set. Tests can pin the clock via
//!    [`FixedTime`].
//! 5. **Egress** — the envelope is submitted to a
//!    [`sng_comms::TelemetryClient`] which owns the batch
//!    builder + bounded spool. Spool overflow is oldest-drop;
//!    the pipeline tracks evictions as a backpressure
//!    indicator.
//!
//! Side-pipe: a [`PcapRing`] captures recent packet frames
//! out-of-band so an operator can pull the raw bytes that back
//! a flagged telemetry event without enabling a full-stack
//! capture out of band.
//!
//! ## Wiring
//!
//! ```no_run
//! use std::sync::Arc;
//! use sng_telemetry::{
//!     AgentIdentity, Enricher, Pipeline, PipelineConfig,
//!     PcapRing, PcapRingConfig, RedactionPolicy, SystemTime,
//! };
//! use sng_comms::{EnrichmentContext, TelemetryClient, TelemetryClientConfig};
//! use sng_core::envelope::Platform;
//! use sng_core::ids::{DeviceId, TenantId};
//!
//! // 1. Identity bound at agent enrolment.
//! let identity = AgentIdentity::new(
//!     TenantId::nil(),
//!     DeviceId::nil(),
//!     None,
//!     Platform::Linux,
//! );
//!
//! // 2. Egress sink. sng-comms owns the wire.
//! let egress_cfg = TelemetryClientConfig::with_defaults(EnrichmentContext {
//!     tenant_id: identity.tenant_id,
//!     device_id: identity.device_id,
//!     site_id: identity.site_id,
//! });
//! let egress = Arc::new(TelemetryClient::new(egress_cfg));
//!
//! // 3. PCAP ring. Shared so producers can also push into it.
//! let pcap = Arc::new(PcapRing::new(PcapRingConfig::default()));
//!
//! // 4. Pipeline.
//! let enricher = Enricher::new(identity, SystemTime);
//! let (pipeline, handle) = Pipeline::new(
//!     PipelineConfig::default(),
//!     enricher,
//!     RedactionPolicy::strict(),
//!     Arc::clone(&egress),
//!     pcap,
//! );
//!
//! // 5. Spawn the run loop. Producers clone `handle` and call
//! //    `handle.submit(event).await`.
//! tokio::spawn(pipeline.run());
//! ```

#![doc(html_root_url = "https://docs.rs/sng-telemetry/0.1.0")]

pub mod dedup;
pub mod enrichment;
pub mod error;
pub mod pcap;
pub mod pipeline;
pub mod redaction;
pub mod source;

pub use dedup::{DEFAULT_MAX_ENTRIES, DEFAULT_WINDOW, Dedup, Fingerprint};
pub use enrichment::{
    AgentIdentity, Enricher, EnrichmentContext, FixedTime, SystemTime, TimeSource,
};
pub use error::TelemetryError;
pub use pcap::{CapturedFrame, PcapRing, PcapRingConfig, PcapStats};
pub use pipeline::{
    Pipeline, PipelineConfig, PipelineHandle, PipelineStats, ProcessOutcome, TrySubmitError,
};
pub use redaction::RedactionPolicy;
pub use source::{ChannelSource, EventSource, TelemetryEvent};

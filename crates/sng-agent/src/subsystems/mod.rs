// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! Subsystem adapters for the `sng-agent` binary.
//!
//! The agent composes a strict subset of the Phase-2 library
//! crates — every adapter implements the
//! [`sng_core::Subsystem`] trait so the
//! [`sng_core::Supervisor`] can drive its lifecycle. The
//! subsystems supplied by the agent binary are:
//!
//! - [`comms::CommsSubsystem`] — control-plane mTLS / HTTP/2
//!   client + policy-bundle puller. Pulls bundles targetted at
//!   [`sng_policy_eval::BundleTarget::Endpoint`] (not `Edge`).
//! - [`policy_eval::PolicyEvalSubsystem`] — endpoint-tier
//!   policy engine.
//! - [`telemetry::TelemetrySubsystem`] — telemetry pipeline +
//!   egress flush. Single sink, no PCAP ring on the agent
//!   (endpoints don't run a packet capture buffer; the edge
//!   does).
//! - [`ztna::ZtnaSubsystem`] — per-flow ZTNA evaluation.
//! - [`pal_capture::PalCaptureSubsystem`] — drives the PAL
//!   [`sng_pal::TrafficCapture`] backend in a tight loop and
//!   forwards records into the policy engine + telemetry.
//! - [`dlp::DlpSubsystem`] — drives the `sng-pal` DLP channel
//!   interceptors through the `sng-dlp` engine and reports
//!   verdicts via a [`dlp::DlpVerdictSink`].
//! - [`pal_posture::PalPostureSubsystem`] — invokes the PAL
//!   [`sng_pal::PostureCollector`] at the configured cadence
//!   and fans the resulting [`sng_pal::PostureSnapshot`] out
//!   onto the telemetry pipeline.
//! - [`pal_tunnel::PalTunnelSubsystem`] — owns the lifecycle
//!   of the PAL [`sng_pal::TunnelProvider`] (start / stop /
//!   list reconciliation against the policy verdicts).

pub mod comms;
pub mod dlp;
pub mod pal_capture;
pub mod pal_posture;
pub mod pal_tunnel;
pub mod policy_eval;
pub mod telemetry;
pub mod ztna;

pub use comms::CommsSubsystem;
pub use dlp::{DlpSubsystem, DlpVerdictSink, TracingDlpSink};
pub use pal_capture::PalCaptureSubsystem;
pub use pal_posture::PalPostureSubsystem;
pub use pal_tunnel::PalTunnelSubsystem;
pub use policy_eval::PolicyEvalSubsystem;
pub use telemetry::TelemetrySubsystem;
pub use ztna::ZtnaSubsystem;

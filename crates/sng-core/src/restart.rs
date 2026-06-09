//! Self-healing restart telemetry sink.
//!
//! The WS2 self-healing supervisors — `sng-ips`'s health supervisor,
//! `sng-swg`'s Envoy supervisor, and `sng-edge`'s top-level watchdog —
//! emit one [`crate::events::SubsystemRestart`] per restart attempt.
//! [`SubsystemRestartSink`] is the seam between those supervisors and
//! the telemetry pipeline:
//!
//! * In the edge binary the sink forwards each event onto the existing
//!   telemetry pipeline as a `TelemetryEvent::System`, so it reaches
//!   the control-plane dashboard via the same dedup / redaction /
//!   batch path as traffic telemetry (the "alert control plane" leg of
//!   the watchdog escalation chain).
//! * In tests the sink records events so an assertion can verify the
//!   supervisor emitted the expected restart sequence.
//!
//! The trait lives in `sng-core` rather than `sng-telemetry` because
//! `sng-core` is the base crate every supervisor already depends on,
//! and it must not take a dependency on `sng-telemetry` (which depends
//! on `sng-core`). The sink therefore traffics in the wire type
//! ([`crate::events::SubsystemRestart`]); the edge layer adapts it to
//! the telemetry enum.

use async_trait::async_trait;

use crate::events::SubsystemRestart;

/// Sink for self-healing supervisor restart telemetry.
///
/// # Non-blocking contract
///
/// [`Self::record`] is invoked from a supervisor's control loop, which
/// is on the critical self-healing path. Implementations MUST NOT block
/// or await unboundedly: a pipeline-backed implementation should hand
/// the event to a bounded channel with a non-blocking `try_send` and
/// drop (and ideally count) on backpressure rather than stall the
/// supervisor. Losing a restart-telemetry record is strictly preferable
/// to delaying the restart it describes.
#[async_trait]
pub trait SubsystemRestartSink: Send + Sync + std::fmt::Debug {
    /// Record a single restart attempt.
    async fn record(&self, event: SubsystemRestart);
}

/// A no-op sink: discards every event.
///
/// Used as the default when no telemetry pipeline is wired — e.g. unit
/// tests of the restart state machine that assert on process lifecycle
/// rather than on emitted telemetry.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopRestartSink;

#[async_trait]
impl SubsystemRestartSink for NoopRestartSink {
    async fn record(&self, _event: SubsystemRestart) {}
}

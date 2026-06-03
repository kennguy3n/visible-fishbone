//! Lightweight, metadata-only mobile telemetry.
//!
//! Mobile telemetry is deliberately frugal: it carries decision
//! metadata (which app a ZTNA check targeted, the allow/deny
//! outcome, a DNS query's verdict, tunnel up/down transitions) and
//! never payload bytes or user content, so it fits the sub-5 MB /
//! sub-0.5%-CPU mobile budget and respects the metadata-only
//! privacy posture.
//!
//! [`MobileTelemetryEvent`] is the mobile-facing event shape;
//! [`MobileTelemetryEvent::to_envelope`] lifts it into the
//! workspace-standard [`sng_core::envelope::Envelope`] so it is
//! wire-identical to what the desktop agent emits. [`MobileTelemetry`]
//! wraps the shared [`sng_comms::TelemetryClient`], whose internal
//! [`sng_comms::BoundedSpool`] provides the bounded local buffering
//! and batched, sequence-tracked upload — i.e. the spool + batch
//! upload are reused from `sng-comms` rather than reimplemented.

use std::sync::Arc;

use chrono::{DateTime, Utc};

use sng_comms::{FlushOutcome, TelemetryClient};
use sng_core::envelope::{Envelope, EventClass, Platform, SCHEMA_VERSION, Verdict};
use sng_core::events::{AgentEvent, DnsEvent, ZtnaEvent};
use sng_core::{DeviceId, EventId, TenantId, pack_payload};

use crate::error::MobileError;

/// The identity an event is stamped with on the wire.
#[derive(Clone, Copy, Debug)]
pub struct EnvelopeContext {
    /// Tenant the device is enrolled under.
    pub tenant_id: TenantId,
    /// Reporting device.
    pub device_id: DeviceId,
    /// Platform the agent runs on.
    pub platform: Platform,
}

/// A metadata-only mobile telemetry event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MobileTelemetryEvent {
    /// A per-app ZTNA access decision.
    ZtnaAccess {
        /// The application the access targeted.
        app_id: String,
        /// Allow (`true`) / deny (`false`).
        allow: bool,
        /// Structured decision reason
        /// ([`sng_ztna::ZtnaDecisionReason::as_str`]).
        reason: String,
        /// Posture-check tri-state
        /// ([`sng_ztna::PostureResult::as_str`]).
        posture_result: String,
        /// Whether the user identity was verified.
        identity_verified: bool,
    },
    /// A DNS resolution observed by the agent.
    Dns {
        /// Query name.
        query: String,
        /// Query type (`A` / `AAAA` / …).
        qtype: String,
        /// Response code (`NOERROR` / `NXDOMAIN` / …).
        response_code: String,
        /// Verdict the local filter applied.
        verdict: Verdict,
        /// Resolution latency in milliseconds.
        latency_ms: u32,
    },
    /// The data-plane tunnel came up.
    TunnelUp,
    /// The data-plane tunnel went down.
    TunnelDown {
        /// Operator-readable reason.
        reason: String,
    },
}

impl MobileTelemetryEvent {
    /// The envelope event class this event maps to.
    #[must_use]
    pub fn event_class(&self) -> EventClass {
        match self {
            Self::ZtnaAccess { .. } => EventClass::Ztna,
            Self::Dns { .. } => EventClass::Dns,
            Self::TunnelUp | Self::TunnelDown { .. } => EventClass::Agent,
        }
    }

    /// Pack the class-specific payload bytes.
    fn payload(&self, ctx: &EnvelopeContext) -> Result<Vec<u8>, MobileError> {
        let did = ctx.device_id.to_string();
        let bytes = match self {
            Self::ZtnaAccess {
                app_id,
                allow,
                reason,
                posture_result,
                identity_verified,
            } => pack_payload(&ZtnaEvent {
                device_id: did,
                app_id: app_id.clone(),
                posture_result: posture_result.clone(),
                decision: if *allow { "allow" } else { "deny" }.to_owned(),
                reason: reason.clone(),
                identity_verified: *identity_verified,
            })?,
            Self::Dns {
                query,
                qtype,
                response_code,
                verdict,
                latency_ms,
            } => pack_payload(&DnsEvent {
                query: query.clone(),
                qtype: qtype.clone(),
                response_code: response_code.clone(),
                verdict: *verdict,
                latency_ms: *latency_ms,
                upstream: None,
            })?,
            Self::TunnelUp | Self::TunnelDown { .. } => {
                let event_type = match self {
                    Self::TunnelUp => "tunnel_up",
                    _ => "tunnel_down",
                };
                pack_payload(&AgentEvent {
                    device_id: did,
                    event_type: event_type.to_owned(),
                    posture_snapshot: None,
                    platform: ctx.platform,
                })?
            }
        };
        Ok(bytes)
    }

    /// Lift this event into a wire [`Envelope`] stamped with `ctx`
    /// and `timestamp`. The envelope is validated before return so
    /// a malformed event is rejected here rather than at the
    /// `sng-comms` submit boundary.
    pub fn to_envelope(
        &self,
        ctx: &EnvelopeContext,
        timestamp: DateTime<Utc>,
    ) -> Result<Envelope, MobileError> {
        let payload = self.payload(ctx)?;
        let envelope = Envelope {
            schema_version: SCHEMA_VERSION,
            event_id: EventId::new_v4(),
            tenant_id: ctx.tenant_id,
            device_id: ctx.device_id,
            site_id: None,
            timestamp,
            event_class: self.event_class(),
            platform: ctx.platform,
            traffic_class: None,
            bytes_in: 0,
            bytes_out: 0,
            payload,
        };
        envelope.validate()?;
        Ok(envelope)
    }
}

/// Mobile telemetry egress, layered on the shared
/// [`sng_comms::TelemetryClient`].
///
/// The client's internal bounded spool buffers events while the
/// link is unhealthy and its batch builder coalesces them into
/// sequence-tracked uploads — both reused rather than
/// reimplemented. `MobileTelemetry` only adds the mobile event
/// shape + the envelope stamping.
#[derive(Clone)]
pub struct MobileTelemetry {
    client: Arc<TelemetryClient>,
    ctx: EnvelopeContext,
}

impl std::fmt::Debug for MobileTelemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MobileTelemetry").field("ctx", &self.ctx).finish_non_exhaustive()
    }
}

impl MobileTelemetry {
    /// Wrap a telemetry client with the envelope context every
    /// event is stamped with.
    #[must_use]
    pub fn new(client: Arc<TelemetryClient>, ctx: EnvelopeContext) -> Self {
        Self { client, ctx }
    }

    /// Record an event at `timestamp`, enqueuing it into the
    /// bounded spool for the next batch upload. Non-blocking with
    /// respect to the network.
    pub async fn record(
        &self,
        event: &MobileTelemetryEvent,
        timestamp: DateTime<Utc>,
    ) -> Result<(), MobileError> {
        let envelope = event.to_envelope(&self.ctx, timestamp)?;
        self.client.submit(envelope).await?;
        Ok(())
    }

    /// Advance the batch builder's time-based seal so a partial
    /// batch does not sit unflushed past its age threshold.
    pub async fn tick(&self, now: DateTime<Utc>) {
        self.client.tick(now).await;
    }

    /// Flush one spooled batch over `conn`.
    pub async fn flush_one(
        &self,
        conn: &sng_comms::ControlPlaneConnection,
    ) -> Result<FlushOutcome, MobileError> {
        Ok(self.client.flush_one(conn).await?)
    }

    /// Snapshot of the bounded spool's occupancy, for health
    /// reporting.
    #[must_use]
    pub fn spool_stats(&self) -> sng_comms::SpoolStats {
        self.client.spool_stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use sng_comms::{EnrichmentContext, TelemetryClientConfig};
    use sng_core::unpack_payload;

    fn ctx() -> EnvelopeContext {
        EnvelopeContext {
            tenant_id: TenantId::new_v4(),
            device_id: DeviceId::new_v4(),
            platform: Platform::Android,
        }
    }

    #[test]
    fn ztna_event_maps_to_ztna_envelope() {
        let ctx = ctx();
        let ev = MobileTelemetryEvent::ZtnaAccess {
            app_id: "wiki".into(),
            allow: false,
            reason: "not_entitled".into(),
            posture_result: "not_evaluated".into(),
            identity_verified: true,
        };
        let env = ev.to_envelope(&ctx, Utc::now()).unwrap();
        assert_eq!(env.event_class, EventClass::Ztna);
        assert_eq!(env.device_id, ctx.device_id);
        let payload: ZtnaEvent = unpack_payload(&env.payload).unwrap();
        assert_eq!(payload.decision, "deny");
        assert_eq!(payload.reason, "not_entitled");
        assert!(payload.identity_verified);
    }

    #[test]
    fn dns_event_maps_to_dns_envelope() {
        let ev = MobileTelemetryEvent::Dns {
            query: "example.com".into(),
            qtype: "A".into(),
            response_code: "NOERROR".into(),
            verdict: Verdict::Allow,
            latency_ms: 12,
        };
        let env = ev.to_envelope(&ctx(), Utc::now()).unwrap();
        assert_eq!(env.event_class, EventClass::Dns);
        let payload: DnsEvent = unpack_payload(&env.payload).unwrap();
        assert_eq!(payload.query, "example.com");
        assert_eq!(payload.latency_ms, 12);
    }

    #[test]
    fn tunnel_events_map_to_agent_envelope() {
        let up = MobileTelemetryEvent::TunnelUp
            .to_envelope(&ctx(), Utc::now())
            .unwrap();
        assert_eq!(up.event_class, EventClass::Agent);
        let payload: AgentEvent = unpack_payload(&up.payload).unwrap();
        assert_eq!(payload.event_type, "tunnel_up");

        let down = MobileTelemetryEvent::TunnelDown {
            reason: "idle".into(),
        }
        .to_envelope(&ctx(), Utc::now())
        .unwrap();
        let payload: AgentEvent = unpack_payload(&down.payload).unwrap();
        assert_eq!(payload.event_type, "tunnel_down");
    }

    #[tokio::test]
    async fn record_enqueues_into_spool() {
        let c = ctx();
        let enrichment = EnrichmentContext {
            tenant_id: c.tenant_id,
            device_id: c.device_id,
            site_id: None,
        };
        let client = Arc::new(TelemetryClient::new(TelemetryClientConfig::with_defaults(
            enrichment,
        )));
        let telemetry = MobileTelemetry::new(client, c);

        telemetry
            .record(&MobileTelemetryEvent::TunnelUp, Utc::now())
            .await
            .unwrap();
        // Force the partial batch to seal so it lands in the spool.
        telemetry.client.force_seal().await;
        assert!(telemetry.spool_stats().len >= 1);
    }
}

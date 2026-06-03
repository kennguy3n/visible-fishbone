//! Enrichment: bind every outgoing event to the agent's
//! identity, site, and the producer-side timestamp.
//!
//! The collector wraps a typed [`TelemetryEvent`] into an
//! [`Envelope`] populated with:
//!
//! * `tenant_id` — bound at agent boot from the enrolment
//!   bundle.
//! * `device_id` — bound at agent boot.
//! * `site_id` — optional; bound when the device joined a site.
//! * `platform` — bound at agent boot.
//! * `timestamp` — the producer-side wall-clock time of the
//!   observation. Pulled from a [`TimeSource`] so tests can drive
//!   the clock deterministically.
//! * `traffic_class` — hoisted onto the envelope so the
//!   ClickHouse writer can promote it to a dedicated column. For
//!   non-flow events the enricher uses a class default; for flow
//!   events the caller may override per-flow.
//! * `bytes_in` / `bytes_out` — hoisted from FlowEvent onto the
//!   envelope for the same column-promotion reason.
//!
//! The [`Enricher`] is intentionally cheap to clone — its fields
//! are small `Copy` types or strings — so per-call enrichment
//! does not allocate.

use chrono::{DateTime, Utc};
use sng_core::envelope::{Envelope, Platform};
use sng_core::events::FlowEvent;
use sng_core::ids::{DeviceId, EventId, SiteId, TenantId};
use sng_core::traffic_class::TrafficClass;

use crate::source::TelemetryEvent;

/// Pluggable time source. Production uses [`SystemTime`]; tests
/// inject a fake [`FixedTime`] so they can pin the envelope
/// timestamp.
pub trait TimeSource: Send + Sync + 'static {
    /// Current UTC wall-clock time.
    fn now(&self) -> DateTime<Utc>;
}

/// Production [`TimeSource`] reading the system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTime;

impl TimeSource for SystemTime {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// Test [`TimeSource`] returning a fixed instant.
#[derive(Clone, Copy, Debug)]
pub struct FixedTime(pub DateTime<Utc>);

impl TimeSource for FixedTime {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

/// Per-agent identity binding. Constructed at agent boot and
/// passed by reference into every [`Enricher`].
#[derive(Clone, Debug)]
pub struct AgentIdentity {
    /// Tenant the agent enrolled into.
    pub tenant_id: TenantId,
    /// This agent's stable device id.
    pub device_id: DeviceId,
    /// Site the device belongs to (optional — endpoints not
    /// bound to a site omit this).
    pub site_id: Option<SiteId>,
    /// Platform the agent is running on.
    pub platform: Platform,
    /// Default traffic class assigned to events whose producer
    /// did not record one (typically non-flow events). The
    /// pipeline-wide default is [`TrafficClass::InspectFull`].
    pub default_traffic_class: TrafficClass,
}

impl AgentIdentity {
    /// Convenience constructor for production wiring. The
    /// `default_traffic_class` is set to
    /// [`TrafficClass::default_conservative`] which matches the
    /// ClickHouse column default and what the Go writer uses
    /// for legacy producers that did not record a class.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        device_id: DeviceId,
        site_id: Option<SiteId>,
        platform: Platform,
    ) -> Self {
        Self {
            tenant_id,
            device_id,
            site_id,
            platform,
            default_traffic_class: TrafficClass::default_conservative(),
        }
    }

    /// Project this identity into the
    /// [`sng_comms::EnrichmentContext`] the egress
    /// [`sng_comms::TelemetryClient`] uses to stamp the canonical
    /// `tenant_id` / `device_id` / `site_id` on every outgoing
    /// envelope.
    ///
    /// Use this helper when constructing the
    /// [`sng_comms::TelemetryClientConfig`] so both enrichment
    /// stages — the producer-side [`Enricher::enrich`] and the
    /// egress-side [`sng_comms::EnrichmentContext::enrich`] —
    /// share a single source of truth. The
    /// [`crate::Pipeline::new`] constructor verifies this
    /// invariant at boot and refuses to start a pipeline whose
    /// two enrichment stages disagree on identity, so wiring
    /// divergent identities surfaces as a hard error rather than
    /// the previous silent overwrite at the wire.
    #[must_use]
    pub fn to_comms_enrichment_context(&self) -> sng_comms::EnrichmentContext {
        sng_comms::EnrichmentContext {
            tenant_id: self.tenant_id,
            device_id: self.device_id,
            site_id: self.site_id,
        }
    }
}

/// Per-event enrichment context — a fast-path bag of caller-
/// supplied overrides the producer can attach to an event when
/// it has more information than the [`Enricher`]'s defaults.
#[derive(Clone, Copy, Debug, Default)]
pub struct EnrichmentContext {
    /// Override the producer-side timestamp. When `None`, the
    /// [`Enricher`]'s configured [`TimeSource::now`] is used.
    pub timestamp: Option<DateTime<Utc>>,
    /// Override the traffic class for this event. When `None`,
    /// the agent identity's `default_traffic_class` is used.
    pub traffic_class: Option<TrafficClass>,
}

impl EnrichmentContext {
    /// Producer wants to override only the traffic class.
    #[must_use]
    pub const fn with_traffic_class(tc: TrafficClass) -> Self {
        Self {
            timestamp: None,
            traffic_class: Some(tc),
        }
    }

    /// Producer wants to override only the timestamp.
    #[must_use]
    pub const fn with_timestamp(ts: DateTime<Utc>) -> Self {
        Self {
            timestamp: Some(ts),
            traffic_class: None,
        }
    }
}

/// The enricher itself. Generic over the time source so a test
/// can swap in a [`FixedTime`].
#[derive(Debug)]
pub struct Enricher<T: TimeSource> {
    identity: AgentIdentity,
    clock: T,
}

impl<T: TimeSource> Enricher<T> {
    /// New enricher with the given identity and clock.
    pub const fn new(identity: AgentIdentity, clock: T) -> Self {
        Self { identity, clock }
    }

    /// Agent identity the enricher is bound to.
    #[must_use]
    pub const fn identity(&self) -> &AgentIdentity {
        &self.identity
    }

    /// Wrap a [`TelemetryEvent`] into a fully-populated
    /// [`Envelope`]. Returns an error only if the payload encode
    /// step fails — every other field is statically constructible.
    ///
    /// The returned envelope passes [`Envelope::validate`] by
    /// construction: schema_version is set, every id is non-nil
    /// (the caller wires non-nil ids at agent boot), the
    /// timestamp is never Go-zero (the time source returns
    /// real-clock time, the producer's override is also real
    /// time), and the payload is encoded from the typed event.
    pub fn enrich(
        &self,
        event: &TelemetryEvent,
        ctx: EnrichmentContext,
    ) -> Result<Envelope, rmp_serde::encode::Error> {
        let payload = event.encode_payload()?;
        let timestamp = ctx.timestamp.unwrap_or_else(|| self.clock.now());
        let traffic_class = ctx
            .traffic_class
            .unwrap_or(self.identity.default_traffic_class);

        let (bytes_in, bytes_out) = bytes_hoisted_from(event);

        Ok(Envelope {
            schema_version: sng_core::envelope::SCHEMA_VERSION,
            event_id: EventId::new_v4(),
            tenant_id: self.identity.tenant_id,
            device_id: self.identity.device_id,
            site_id: self.identity.site_id,
            timestamp,
            event_class: event.event_class(),
            platform: self.identity.platform,
            traffic_class: Some(traffic_class),
            bytes_in,
            bytes_out,
            payload,
        })
    }
}

/// Hoist `bytes_in` / `bytes_out` from a Flow event onto the
/// envelope so the ClickHouse writer can promote them to
/// dedicated columns. For non-flow events both counters are
/// zero (matching the Go-side encoder, which `omitempty`s the
/// fields).
fn bytes_hoisted_from(event: &TelemetryEvent) -> (u64, u64) {
    match event {
        TelemetryEvent::Flow(FlowEvent {
            bytes_in,
            bytes_out,
            ..
        }) => (*bytes_in, *bytes_out),
        _ => (0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::envelope::{EventClass, Verdict};
    use sng_core::events::{AgentEvent, FlowEvent};
    use uuid::Uuid;

    fn identity() -> AgentIdentity {
        AgentIdentity {
            tenant_id: TenantId::from(Uuid::from_u128(1)),
            device_id: DeviceId::from(Uuid::from_u128(2)),
            site_id: Some(SiteId::from(Uuid::from_u128(3))),
            platform: Platform::Linux,
            default_traffic_class: TrafficClass::InspectFull,
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-05-01T12:34:56Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn flow() -> TelemetryEvent {
        TelemetryEvent::Flow(FlowEvent {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 51_234,
            dst_port: 443,
            protocol: "tcp".into(),
            app_id: None,
            verdict: Verdict::Allow,
            score: None,
            bytes_in: 1_024,
            bytes_out: 2_048,
            duration_ms: 100,
        })
    }

    #[test]
    fn enrich_populates_envelope_fields() {
        let ts = fixed_now();
        let e = Enricher::new(identity(), FixedTime(ts));
        let env = e.enrich(&flow(), EnrichmentContext::default()).unwrap();
        assert_eq!(env.event_class, EventClass::Flow);
        assert_eq!(env.tenant_id, identity().tenant_id);
        assert_eq!(env.device_id, identity().device_id);
        assert_eq!(env.site_id, identity().site_id);
        assert_eq!(env.platform, Platform::Linux);
        assert_eq!(env.timestamp, ts);
        assert_eq!(env.traffic_class, Some(TrafficClass::InspectFull));
        assert_eq!(env.bytes_in, 1_024);
        assert_eq!(env.bytes_out, 2_048);
        assert!(!env.event_id.is_nil());
        // The envelope must be valid by construction: the
        // pipeline's submit boundary re-runs validate() but the
        // enricher should never produce an invalid envelope to
        // start with.
        env.validate().expect("enriched envelope must validate");
    }

    #[test]
    fn enrich_honours_context_overrides() {
        let ts = fixed_now();
        let e = Enricher::new(identity(), FixedTime(ts));
        let override_ts = ts + chrono::Duration::seconds(5);
        let env = e
            .enrich(
                &flow(),
                EnrichmentContext {
                    timestamp: Some(override_ts),
                    traffic_class: Some(TrafficClass::TrustedDirect),
                },
            )
            .unwrap();
        assert_eq!(env.timestamp, override_ts);
        assert_eq!(env.traffic_class, Some(TrafficClass::TrustedDirect));
    }

    #[test]
    fn enrich_non_flow_zeroes_byte_counters() {
        let ts = fixed_now();
        let e = Enricher::new(identity(), FixedTime(ts));
        let agent_event = TelemetryEvent::Agent(AgentEvent {
            device_id: "d1".into(),
            event_type: "started".into(),
            posture_snapshot: None,
            reason: String::new(),
            platform: Platform::Linux,
        });
        let env = e
            .enrich(&agent_event, EnrichmentContext::default())
            .unwrap();
        assert_eq!(env.bytes_in, 0);
        assert_eq!(env.bytes_out, 0);
        assert_eq!(env.event_class, EventClass::Agent);
    }
}

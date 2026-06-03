//! Telemetry event source abstraction.
//!
//! Every subsystem in the agent (DNS filter, firewall, IPS,
//! SWG, ZTNA, SD-WAN, the agent lifecycle itself) produces
//! typed events. The [`EventSource`] trait is the contract each
//! subsystem implements; the pipeline pulls from sources via
//! the async [`EventSource::recv`] method.

use async_trait::async_trait;
use sng_core::events::{
    AgentEvent, DnsEvent, FlowEvent, HttpEvent, IpsEvent, SdwanEvent, ZtnaEvent,
};

/// A typed telemetry event produced by one of the agent's
/// subsystems. The pipeline dispatches on the variant to set
/// [`sng_core::envelope::EventClass`] on the envelope and to
/// encode the correct payload bytes.
#[derive(Clone, Debug, PartialEq)]
pub enum TelemetryEvent {
    Flow(FlowEvent),
    Dns(DnsEvent),
    Http(HttpEvent),
    Ips(IpsEvent),
    Ztna(ZtnaEvent),
    Sdwan(SdwanEvent),
    Agent(AgentEvent),
}

impl TelemetryEvent {
    /// The [`sng_core::envelope::EventClass`] this event
    /// corresponds to.
    #[must_use]
    pub fn event_class(&self) -> sng_core::envelope::EventClass {
        use sng_core::envelope::EventClass;
        match self {
            Self::Flow(_) => EventClass::Flow,
            Self::Dns(_) => EventClass::Dns,
            Self::Http(_) => EventClass::Http,
            Self::Ips(_) => EventClass::Ips,
            Self::Ztna(_) => EventClass::Ztna,
            Self::Sdwan(_) => EventClass::Sdwan,
            Self::Agent(_) => EventClass::Agent,
        }
    }

    /// Encode the event payload as MessagePack bytes suitable
    /// for [`sng_core::Envelope::payload`].
    pub fn encode_payload(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        match self {
            Self::Flow(e) => rmp_serde::to_vec_named(e),
            Self::Dns(e) => rmp_serde::to_vec_named(e),
            Self::Http(e) => rmp_serde::to_vec_named(e),
            Self::Ips(e) => rmp_serde::to_vec_named(e),
            Self::Ztna(e) => rmp_serde::to_vec_named(e),
            Self::Sdwan(e) => rmp_serde::to_vec_named(e),
            Self::Agent(e) => rmp_serde::to_vec_named(e),
        }
    }
}

/// Async event source trait. Subsystems implement this to feed
/// the telemetry pipeline.
///
/// The pipeline calls [`Self::recv`] in a loop; the source
/// blocks until an event is available or the channel is closed.
/// A `None` return signals end-of-stream (subsystem shutdown).
#[async_trait]
pub trait EventSource: Send + Sync + 'static {
    /// Receive the next event. Returns `None` when the source
    /// is permanently closed (subsystem shut down).
    async fn recv(&mut self) -> Option<TelemetryEvent>;
}

/// Convenience [`EventSource`] backed by a
/// [`tokio::sync::mpsc::Receiver`].
#[derive(Debug)]
pub struct ChannelSource {
    rx: tokio::sync::mpsc::Receiver<TelemetryEvent>,
}

impl ChannelSource {
    /// Create a source/sender pair with the given channel
    /// capacity. The sender half is returned so the producing
    /// subsystem can push events.
    #[must_use]
    pub fn new(capacity: usize) -> (tokio::sync::mpsc::Sender<TelemetryEvent>, Self) {
        let (tx, rx) = tokio::sync::mpsc::channel(capacity);
        (tx, Self { rx })
    }
}

#[async_trait]
impl EventSource for ChannelSource {
    async fn recv(&mut self) -> Option<TelemetryEvent> {
        self.rx.recv().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::envelope::{EventClass, Platform, Verdict};
    use sng_core::events::FlowEvent;

    fn sample_flow() -> FlowEvent {
        FlowEvent {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 51_234,
            dst_port: 443,
            protocol: "tcp".into(),
            app_id: Some("microsoft.teams".into()),
            verdict: Verdict::Allow,
            score: Some(0.42),
            bytes_in: 1_024,
            bytes_out: 2_048,
            duration_ms: 1_500,
        }
    }

    #[test]
    fn event_class_matches_variant() {
        let ev = TelemetryEvent::Flow(sample_flow());
        assert_eq!(ev.event_class(), EventClass::Flow);

        let ev = TelemetryEvent::Agent(sng_core::events::AgentEvent {
            device_id: "d1".into(),
            event_type: "started".into(),
            posture_snapshot: None,
            reason: String::new(),
            platform: Platform::Linux,
        });
        assert_eq!(ev.event_class(), EventClass::Agent);
    }

    #[test]
    fn encode_payload_produces_valid_msgpack() {
        let ev = TelemetryEvent::Flow(sample_flow());
        let bytes = ev.encode_payload().expect("encode");
        assert!(!bytes.is_empty());
        let decoded: FlowEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, sample_flow());
    }

    #[tokio::test]
    async fn channel_source_delivers_events() {
        let (tx, mut src) = ChannelSource::new(4);
        let flow = TelemetryEvent::Flow(sample_flow());
        tx.send(flow.clone()).await.unwrap();
        drop(tx);
        let got = src.recv().await;
        assert_eq!(got, Some(flow));
        assert_eq!(src.recv().await, None);
    }
}

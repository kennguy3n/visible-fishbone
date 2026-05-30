//! IPS → telemetry pipeline glue.
//!
//! [`IpsEventSource`] implements the
//! [`sng_telemetry::EventSource`] trait, draining a channel of
//! normalised [`sng_core::events::IpsEvent`] records into the
//! workspace telemetry pipeline. The IPS manager produces events
//! by parsing Suricata's EVE JSON output ([`crate::eve`]); the
//! source is the bridge that hands those events off in the
//! shape the rest of the workspace already consumes.

use async_trait::async_trait;
use sng_core::events::IpsEvent;
use sng_telemetry::source::{EventSource, TelemetryEvent};
use tokio::sync::mpsc;

/// Producer half of the IPS event channel. Held by the
/// [`crate::manager::IpsManager`]; pushes normalised alerts.
#[derive(Clone, Debug)]
pub struct IpsEventSink {
    tx: mpsc::Sender<IpsEvent>,
}

impl IpsEventSink {
    /// Push an event into the channel. Returns `Ok(())` on
    /// success; `Err(())` if the consumer has been dropped (i.e.
    /// the telemetry pipeline has shut down). Callers should
    /// treat that as terminal for the IPS subsystem.
    pub fn try_send(&self, ev: IpsEvent) -> Result<(), IpsEvent> {
        match self.tx.try_send(ev) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(ev) | mpsc::error::TrySendError::Closed(ev)) => {
                Err(ev)
            }
        }
    }

    /// Async send. Returns `Err(())` only when the channel is
    /// permanently closed (consumer dropped); back-pressure
    /// blocks rather than failing.
    pub async fn send(&self, ev: IpsEvent) -> Result<(), IpsEvent> {
        self.tx.send(ev).await.map_err(|e| e.0)
    }

    /// Approximate channel capacity remaining. Used by health
    /// reporting to alert when the manager is back-pressured.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.tx.capacity()
    }
}

/// Consumer half. Wired into the telemetry pipeline as one of
/// many [`EventSource`]s.
#[derive(Debug)]
pub struct IpsEventSource {
    rx: mpsc::Receiver<IpsEvent>,
}

impl IpsEventSource {
    /// Build a `(sink, source)` pair with the given channel
    /// capacity. The default capacity callers should use is the
    /// burst size their Suricata config emits in one EVE flush
    /// — `1024` is a sensible production default.
    #[must_use]
    pub fn channel(capacity: usize) -> (IpsEventSink, Self) {
        let (tx, rx) = mpsc::channel(capacity);
        (IpsEventSink { tx }, Self { rx })
    }
}

#[async_trait]
impl EventSource for IpsEventSource {
    async fn recv(&mut self) -> Option<TelemetryEvent> {
        self.rx.recv().await.map(TelemetryEvent::Ips)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::envelope::EventClass;

    fn alert(rule_id: &str) -> IpsEvent {
        IpsEvent {
            rule_id: rule_id.into(),
            signature: "ET TROJAN test".into(),
            severity: "high".into(),
            action: "alert".into(),
            src_ip: "10.0.0.5".into(),
            dst_ip: "1.2.3.4".into(),
            protocol: "tcp".into(),
        }
    }

    #[tokio::test]
    async fn channel_delivers_ips_events_through_event_source_trait() {
        let (sink, mut source) = IpsEventSource::channel(4);
        sink.send(alert("2000001")).await.unwrap();
        sink.send(alert("2000002")).await.unwrap();
        drop(sink);
        let mut classes = Vec::new();
        while let Some(ev) = source.recv().await {
            classes.push(ev.event_class());
        }
        assert_eq!(classes, vec![EventClass::Ips, EventClass::Ips]);
    }

    #[tokio::test]
    async fn channel_returns_none_after_sink_dropped() {
        let (sink, mut source) = IpsEventSource::channel(1);
        drop(sink);
        assert!(source.recv().await.is_none());
    }

    #[tokio::test]
    async fn try_send_returns_event_back_when_channel_full() {
        let (sink, _source) = IpsEventSource::channel(1);
        sink.try_send(alert("a")).unwrap();
        let back = sink.try_send(alert("b")).unwrap_err();
        assert_eq!(back.rule_id, "b");
    }

    #[tokio::test]
    async fn try_send_returns_event_back_when_channel_closed() {
        let (sink, source) = IpsEventSource::channel(1);
        drop(source);
        let back = sink.try_send(alert("a")).unwrap_err();
        assert_eq!(back.rule_id, "a");
    }

    #[tokio::test]
    async fn payload_round_trips_through_messagepack() {
        // Defensive check that the IpsEvent we produce serialises
        // through the telemetry pipeline without losing any
        // field — the field renames are short single-letter
        // codes so a typo would silently corrupt the wire shape.
        let (sink, mut source) = IpsEventSource::channel(1);
        sink.send(alert("2000001")).await.unwrap();
        drop(sink);
        let ev = source.recv().await.unwrap();
        let bytes = ev.encode_payload().unwrap();
        let decoded: IpsEvent = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded.rule_id, "2000001");
        assert_eq!(decoded.severity, "high");
        assert_eq!(decoded.src_ip, "10.0.0.5");
    }

    #[tokio::test]
    async fn capacity_decreases_after_send() {
        let (sink, _source) = IpsEventSource::channel(4);
        let before = sink.capacity();
        sink.send(alert("a")).await.unwrap();
        let after = sink.capacity();
        assert_eq!(after, before - 1);
    }
}

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

/// Reason a `try_send` could not deliver the event. The caller
/// uses this to decide whether the failure is recoverable
/// (`Full` — back-pressure, drop the alert and keep tailing) or
/// terminal (`Closed` — the telemetry pipeline has shut down,
/// so the IPS supervisor should wind down too).
#[derive(Debug)]
pub enum SinkSendError {
    /// The channel buffer is full. The unsent event is returned
    /// so the caller can choose to drop, retry, or telemetry-log
    /// it.
    Full(IpsEvent),
    /// The receiver has been dropped. Subsequent sends will all
    /// fail; the caller should treat this as terminal.
    Closed(IpsEvent),
}

impl SinkSendError {
    /// True when the failure is `Closed` — the consumer is gone
    /// permanently and the caller cannot recover by retrying.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Closed(_))
    }

    /// Borrow the event that was not delivered.
    #[must_use]
    pub const fn event(&self) -> &IpsEvent {
        match self {
            Self::Full(ev) | Self::Closed(ev) => ev,
        }
    }
}

/// Producer half of the IPS event channel. Held by the
/// [`crate::manager::IpsManager`]; pushes normalised alerts.
#[derive(Clone, Debug)]
pub struct IpsEventSink {
    tx: mpsc::Sender<IpsEvent>,
}

impl IpsEventSink {
    /// Push an event into the channel without blocking.
    ///
    /// Returns:
    /// * `Ok(())` if the event was queued,
    /// * `Err(SinkSendError::Full(ev))` if the channel buffer
    ///   is full — the caller may drop the event and continue,
    /// * `Err(SinkSendError::Closed(ev))` if the consumer has
    ///   been dropped — the IPS supervisor should treat this
    ///   as terminal and stop tailing.
    ///
    /// The two error paths used to be conflated under a single
    /// `Err(IpsEvent)` return; callers (and operators reading
    /// the dashboard) couldn't tell a transient back-pressure
    /// drop from a permanent shutdown of the telemetry pipeline.
    pub fn try_send(&self, ev: IpsEvent) -> Result<(), SinkSendError> {
        match self.tx.try_send(ev) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(ev)) => Err(SinkSendError::Full(ev)),
            Err(mpsc::error::TrySendError::Closed(ev)) => Err(SinkSendError::Closed(ev)),
        }
    }

    /// Async send. Returns `Err(SinkSendError::Closed(ev))`
    /// only when the channel is permanently closed (consumer
    /// dropped); back-pressure blocks rather than failing, so
    /// there is no `Full` variant on this path.
    pub async fn send(&self, ev: IpsEvent) -> Result<(), SinkSendError> {
        self.tx
            .send(ev)
            .await
            .map_err(|e| SinkSendError::Closed(e.0))
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
        // `Full` is recoverable — the caller may drop the alert
        // and keep tailing; `is_terminal()` must say so.
        assert!(matches!(back, SinkSendError::Full(_)));
        assert!(!back.is_terminal());
        assert_eq!(back.event().rule_id, "b");
    }

    #[tokio::test]
    async fn try_send_returns_event_back_when_channel_closed() {
        let (sink, source) = IpsEventSource::channel(1);
        drop(source);
        let back = sink.try_send(alert("a")).unwrap_err();
        // `Closed` is terminal — the consumer is gone and no
        // retry will succeed.
        assert!(matches!(back, SinkSendError::Closed(_)));
        assert!(back.is_terminal());
        assert_eq!(back.event().rule_id, "a");
    }

    #[tokio::test]
    async fn async_send_returns_closed_when_consumer_dropped() {
        // The async send path used to return `Err(IpsEvent)`
        // — same opaque return as the sync path — so callers
        // couldn't classify the failure. Pin the new contract:
        // it returns `Closed`, never `Full` (back-pressure on
        // this path blocks rather than failing).
        let (sink, source) = IpsEventSource::channel(1);
        drop(source);
        let back = sink.send(alert("x")).await.unwrap_err();
        assert!(matches!(back, SinkSendError::Closed(_)));
        assert!(back.is_terminal());
        assert_eq!(back.event().rule_id, "x");
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

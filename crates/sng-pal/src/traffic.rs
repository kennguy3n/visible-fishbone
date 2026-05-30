//! Traffic capture trait.
//!
//! The trait is intentionally narrow: yield raw packet records
//! one at a time, with the OS-blessed timestamp and interface
//! handle, until the consumer drops the stream. Real backends
//! (WFP, NE, nftables) plug in behind it via per-OS modules.
//!
//! For PR 2 we ship the trait definition + a deterministic
//! in-memory backend used by every higher-layer crate's unit
//! tests. Per-OS production backends land in PR 7 (`sng-fw`),
//! where they finally have a consumer.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

/// A single observed packet.
///
/// The record is intentionally small — bulk per-packet fields
/// (IP options, TCP flags, payload bytes) live in a follow-on
/// struct in `sng-fw`. This is the part everyone, including the
/// posture / telemetry pipeline, needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketRecord {
    /// Observation time.
    pub captured_at: DateTime<Utc>,
    /// Interface index the kernel attributed the packet to.
    pub interface_index: u32,
    /// Direction (`ingress` / `egress`).
    pub direction: PacketDirection,
    /// Source IP/prefix.
    pub source: IpNet,
    /// Destination IP/prefix.
    pub destination: IpNet,
    /// IP protocol number.
    pub protocol: u8,
    /// Length of the captured packet in bytes.
    pub length: u32,
}

/// Packet direction.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PacketDirection {
    Ingress,
    Egress,
}

/// Traffic-capture error.
#[derive(Debug, Error)]
pub enum TrafficCaptureError {
    /// Backend not available on this OS / build.
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    /// The capture engine could not be initialised (privilege
    /// missing, driver not loaded, etc.).
    #[error("init: {0}")]
    Init(String),
    /// Permanent shutdown signalled.
    #[error("closed")]
    Closed,
}

/// Capture trait. Implementations are stream-shaped — call
/// `next` repeatedly until you get `Ok(None)` (the kernel
/// closed the channel) or an error.
#[async_trait]
pub trait TrafficCapture: Send + Sync {
    /// Yield the next packet, or `None` when the underlying
    /// kernel channel has been closed cleanly.
    async fn next(&self) -> Result<Option<PacketRecord>, TrafficCaptureError>;
}

/// Deterministic in-memory backend. Used by tests in every
/// dependent crate. Records are popped from the head of an
/// `Arc<Mutex<VecDeque>>`, so the consumer sees them in FIFO
/// order even when polled concurrently.
#[derive(Clone, Debug, Default)]
pub struct InMemoryCapture {
    inner: Arc<Mutex<std::collections::VecDeque<PacketRecord>>>,
}

impl InMemoryCapture {
    /// Construct an empty capture.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a record. Records appear in `next` in push order.
    pub async fn push(&self, r: PacketRecord) {
        self.inner.lock().await.push_back(r);
    }

    /// Length of the queue. Mostly for assertion in tests.
    pub async fn len(&self) -> usize {
        self.inner.lock().await.len()
    }

    /// Returns true when the queue is empty. Paired with
    /// [`Self::len`] to satisfy the clippy `len_without_is_empty`
    /// lint and as a convenience in test scaffolding.
    pub async fn is_empty(&self) -> bool {
        self.inner.lock().await.is_empty()
    }
}

#[async_trait]
impl TrafficCapture for InMemoryCapture {
    async fn next(&self) -> Result<Option<PacketRecord>, TrafficCaptureError> {
        Ok(self.inner.lock().await.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ipnet::IpNet;
    use pretty_assertions::assert_eq;
    use std::str::FromStr;

    fn sample(direction: PacketDirection) -> PacketRecord {
        PacketRecord {
            captured_at: Utc::now(),
            interface_index: 2,
            direction,
            source: IpNet::from_str("10.0.0.1/32").expect("net"),
            destination: IpNet::from_str("1.1.1.1/32").expect("net"),
            protocol: 6,
            length: 1234,
        }
    }

    #[tokio::test]
    async fn in_memory_yields_records_in_fifo_order() {
        let cap = InMemoryCapture::new();
        cap.push(sample(PacketDirection::Egress)).await;
        cap.push(sample(PacketDirection::Ingress)).await;
        assert_eq!(cap.len().await, 2);
        let first = cap.next().await.expect("ok").expect("some");
        assert_eq!(first.direction, PacketDirection::Egress);
        let second = cap.next().await.expect("ok").expect("some");
        assert_eq!(second.direction, PacketDirection::Ingress);
        let third = cap.next().await.expect("ok");
        assert!(third.is_none());
    }

    #[test]
    fn packet_record_serialises_round_trip() {
        let p = sample(PacketDirection::Egress);
        let json = serde_json::to_string(&p).expect("ok");
        let back: PacketRecord = serde_json::from_str(&json).expect("ok");
        assert_eq!(p, back);
    }

    #[test]
    fn direction_uses_lowercase_wire_strings() {
        assert_eq!(
            serde_json::to_string(&PacketDirection::Ingress).expect("ok"),
            "\"ingress\""
        );
        assert_eq!(
            serde_json::to_string(&PacketDirection::Egress).expect("ok"),
            "\"egress\""
        );
    }
}

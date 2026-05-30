//! Steering request input shape.
//!
//! A [`SteeringRequest`] is what the data path produces
//! per steerable flow before consulting
//! [`crate::service::SdwanService`]. The brain reads four
//! signals:
//!
//! - `flow_key` — the producer's stable key for the flow
//!   (5-tuple hash, app-id, etc.). The brain uses this to
//!   keep sticky-flow state.
//! - `traffic_class` — drives candidate filtering through
//!   the [`crate::path::Path::eligible_classes`] gate.
//! - `tenant_id` — surfaced into the
//!   [`sng_core::envelope::Envelope`] context. The brain
//!   doesn't currently use it for path selection (every
//!   path is per-tenant in the catalog), but the field
//!   is plumbed so future per-tenant overrides on the
//!   policy don't need a request-shape change.
//! - `now_ms` — wall-clock millisecond timestamp the
//!   selector compares against
//!   [`crate::probe::PathProbe::observed_at_ms`] for
//!   freshness. Carried on the request (not read from a
//!   global clock) so unit tests can pin time.

use serde::{Deserialize, Serialize};

use crate::path::TrafficClass;

/// Per-flow steering request.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SteeringRequest {
    /// Producer-assigned stable key for the flow. The
    /// selector uses this to recognise sticky-flow
    /// pinning across calls. Typical values: a Blake3
    /// hash of the 5-tuple, an app-flow id, or the SNI
    /// host for HTTPS traffic.
    pub flow_key: String,
    /// Tenant id the request is scoped to. The brain
    /// surfaces this on the emitted
    /// [`sng_core::envelope::Envelope::tenant_id`] and
    /// the value participates in the dedup hash on the
    /// emitted [`sng_core::events::SdwanEvent`].
    pub tenant_id: String,
    /// Class the producer is steering. Drives the
    /// candidate filter in [`crate::PathProvider::candidates`].
    pub traffic_class: TrafficClass,
    /// Unix epoch milliseconds the producer observed the
    /// flow. The selector compares against
    /// [`crate::probe::PathProbe::observed_at_ms`].
    pub now_ms: u64,
}

impl SteeringRequest {
    /// Convenience constructor with a real-time class
    /// and now_ms = 0. Tests should set fields
    /// explicitly with struct syntax.
    #[must_use]
    pub fn new(flow_key: impl Into<String>, tenant_id: impl Into<String>) -> Self {
        Self {
            flow_key: flow_key.into(),
            tenant_id: tenant_id.into(),
            traffic_class: TrafficClass::Interactive,
            now_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn new_defaults_to_interactive_class_at_t0() {
        let r = SteeringRequest::new("flow-1", "tenant-a");
        assert_eq!(r.traffic_class, TrafficClass::Interactive);
        assert_eq!(r.now_ms, 0);
        assert_eq!(r.flow_key, "flow-1");
        assert_eq!(r.tenant_id, "tenant-a");
    }

    #[test]
    fn struct_constructor_carries_overrides() {
        let r = SteeringRequest {
            flow_key: "voip-42".into(),
            tenant_id: "tenant-a".into(),
            traffic_class: TrafficClass::RealTime,
            now_ms: 12_345,
        };
        assert_eq!(r.traffic_class, TrafficClass::RealTime);
        assert_eq!(r.now_ms, 12_345);
    }
}

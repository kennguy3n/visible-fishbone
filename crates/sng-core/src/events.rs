//! Typed per-class event payloads.
//!
//! Mirrors `internal/nats/schema/events.go` field-for-field with
//! identical msgpack tags. The wire compatibility property — that
//! a Rust producer's marshalled bytes round-trip through the Go
//! schema validator and a Go producer's bytes round-trip through
//! the Rust unmarshaller — is what makes the SNG telemetry
//! pipeline polyglot.
//!
//! Field-name choice rules:
//!
//! 1. The Rust struct field names are full descriptive snake_case
//!    (`src_ip`, `bytes_in`) for readability in the Rust API.
//! 2. The `#[serde(rename = "...")]` annotation pins the on-wire
//!    name to the short tag the Go side uses (`sip`, `bi`). The
//!    wire bytes are what defines compatibility, not the Rust
//!    field name.
//! 3. Optional fields use `Option<T>` + `#[serde(skip_serializing_if = "Option::is_none")]`
//!    so the absence of a value produces a missing key (matching
//!    Go's `omitempty`) rather than a present null.

use serde::{Deserialize, Serialize};

use crate::envelope::{Platform, Verdict};

/// Per-flow telemetry record (5-tuple + verdict + counters).
///
/// One of the highest-volume event classes — the field set is
/// chosen to fit a typical observation in under ~200 bytes wire
/// size after MessagePack encoding.
///
/// Note: the per-flow traffic-classification decision lives on
/// the parent [`crate::Envelope`], not here, so the single source
/// of truth for `traffic_class` is the envelope. The Go side
/// enforces the same separation
/// (`internal/nats/schema/events.go::FlowEvent`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowEvent {
    /// Source IP (canonical text form, dotted-quad for v4,
    /// colon-hex for v6).
    #[serde(rename = "sip")]
    pub src_ip: String,
    /// Destination IP.
    #[serde(rename = "dip")]
    pub dst_ip: String,
    /// Source port.
    #[serde(rename = "spt")]
    pub src_port: u16,
    /// Destination port.
    #[serde(rename = "dpt")]
    pub dst_port: u16,
    /// IP protocol (`tcp` / `udp` / `icmp` / `other`).
    #[serde(rename = "prt")]
    pub protocol: String,
    /// Layer-7 application id (`microsoft.teams.media`, etc.).
    /// Absent for unclassified flows.
    #[serde(rename = "app", default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Verdict the local enforcement engine applied.
    #[serde(rename = "vd")]
    pub verdict: Verdict,
    /// Per-flow confidence / risk score (0.0 .. 1.0). Absent
    /// when the engine does not score.
    #[serde(rename = "sc", default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f32>,
    /// Inbound bytes (server → client).
    #[serde(rename = "bi")]
    pub bytes_in: u64,
    /// Outbound bytes (client → server).
    #[serde(rename = "bo")]
    pub bytes_out: u64,
    /// Flow duration in milliseconds.
    #[serde(rename = "dur")]
    pub duration_ms: u32,
}

/// Per-query DNS telemetry record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DnsEvent {
    /// Query name.
    #[serde(rename = "q")]
    pub query: String,
    /// Query type (`A` / `AAAA` / `CNAME` / …).
    #[serde(rename = "qt")]
    pub qtype: String,
    /// Response code (`NOERROR` / `NXDOMAIN` / `SERVFAIL` / `REFUSED` / …).
    #[serde(rename = "rc")]
    pub response_code: String,
    /// Verdict the local filter chain applied.
    #[serde(rename = "vd")]
    pub verdict: Verdict,
    /// Resolution latency in milliseconds.
    #[serde(rename = "lat")]
    pub latency_ms: u32,
    /// Upstream resolver used. Absent for cache hits.
    #[serde(rename = "up", default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
}

/// Per-request HTTP / HTTPS telemetry record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpEvent {
    /// HTTP method.
    #[serde(rename = "m")]
    pub method: String,
    /// Request URL.
    #[serde(rename = "u")]
    pub url: String,
    /// Host header.
    #[serde(rename = "h")]
    pub host: String,
    /// Response status code.
    #[serde(rename = "sc")]
    pub status_code: u16,
    /// Verdict the SWG applied.
    #[serde(rename = "vd")]
    pub verdict: Verdict,
    /// Negotiated TLS version, when applicable.
    #[serde(rename = "tlv", default, skip_serializing_if = "Option::is_none")]
    pub tls_version: Option<String>,
    /// TLS SNI value, when present.
    #[serde(rename = "sni", default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// Response content type.
    #[serde(rename = "ct", default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Bytes transferred.
    #[serde(rename = "b", default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// IDS / IPS rule hit (Suricata-style alert in normalised form).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IpsEvent {
    /// Rule id (Suricata SID or normalised equivalent).
    #[serde(rename = "rid")]
    pub rule_id: String,
    /// Human-readable rule signature.
    #[serde(rename = "sig")]
    pub signature: String,
    /// Severity (`info` / `low` / `medium` / `high` / `critical`).
    #[serde(rename = "sev")]
    pub severity: String,
    /// Action taken (`alert` / `block` / `drop` / `reset`).
    #[serde(rename = "act")]
    pub action: String,
    /// Source IP.
    #[serde(rename = "sip")]
    pub src_ip: String,
    /// Destination IP.
    #[serde(rename = "dip")]
    pub dst_ip: String,
    /// Protocol.
    #[serde(rename = "prt")]
    pub protocol: String,
}

/// Zero-Trust Network Access decision record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZtnaEvent {
    /// Device id (as wire string; the typed [`crate::DeviceId`]
    /// is in the envelope so this duplicates it for downstream
    /// consumers that filter on device without parsing the
    /// envelope).
    #[serde(rename = "did")]
    pub device_id: String,
    /// Application id.
    #[serde(rename = "app")]
    pub app_id: String,
    /// Posture result (`pass` / `fail`).
    #[serde(rename = "pst")]
    pub posture_result: String,
    /// Decision (`allow` / `deny`).
    #[serde(rename = "dec")]
    pub decision: String,
    /// Was the user identity verified (mTLS + IdP).
    #[serde(rename = "iv")]
    pub identity_verified: bool,
}

/// SD-WAN steering decision + path-quality snapshot.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SdwanEvent {
    /// Selected path id.
    #[serde(rename = "pid")]
    pub path_id: String,
    /// Probe latency, milliseconds.
    #[serde(rename = "lat")]
    pub latency_ms: f32,
    /// Probe loss, percent.
    #[serde(rename = "loss")]
    pub loss_pct: f32,
    /// Probe jitter, milliseconds.
    #[serde(rename = "jit")]
    pub jitter_ms: f32,
    /// Path score (weighted composite).
    #[serde(rename = "sc")]
    pub score: f32,
    /// Steering decision (which traffic class / app uses this path).
    #[serde(rename = "sd")]
    pub steering_decision: String,
}

/// Endpoint agent lifecycle / posture record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AgentEvent {
    /// Device id (duplicated from the envelope, see
    /// [`ZtnaEvent::device_id`]).
    #[serde(rename = "did")]
    pub device_id: String,
    /// Event type (`started` / `stopped` / `posture` / `error`).
    #[serde(rename = "et")]
    pub event_type: String,
    /// Opaque posture snapshot (JSON-encoded bytes).
    #[serde(rename = "pst", default, skip_serializing_if = "Option::is_none")]
    pub posture_snapshot: Option<serde_json::Value>,
    /// Platform.
    #[serde(rename = "plt")]
    pub platform: Platform,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{Platform, Verdict};
    use pretty_assertions::assert_eq;

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
    fn flow_msgpack_uses_short_field_tags() {
        // Round-trip the bytes through msgpack and decode as a
        // map<string,value>: the keys we see must be the short
        // tags (matching the Go-side `internal/nats/schema/events.go`)
        // rather than the Rust field names.
        let flow = sample_flow();
        let bytes = rmp_serde::to_vec_named(&flow).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        let keys: std::collections::BTreeSet<&str> = decoded.keys().map(String::as_str).collect();
        for required in [
            "sip", "dip", "spt", "dpt", "prt", "app", "vd", "sc", "bi", "bo", "dur",
        ] {
            assert!(
                keys.contains(required),
                "msgpack key {required} missing; got {keys:?}"
            );
        }
        // And we should never see the Rust-side names on the wire.
        for forbidden in ["src_ip", "dst_ip", "bytes_in"] {
            assert!(
                !keys.contains(forbidden),
                "Rust field {forbidden} leaked onto the wire; got {keys:?}"
            );
        }
    }

    #[test]
    fn flow_round_trip_preserves_all_fields() {
        let flow = sample_flow();
        let bytes = rmp_serde::to_vec_named(&flow).expect("encode");
        let back: FlowEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(flow, back);
    }

    #[test]
    fn flow_omits_optionals_when_none() {
        let mut flow = sample_flow();
        flow.app_id = None;
        flow.score = None;
        let bytes = rmp_serde::to_vec_named(&flow).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        assert!(!decoded.contains_key("app"));
        assert!(!decoded.contains_key("sc"));
    }

    #[test]
    fn dns_event_round_trip() {
        let ev = DnsEvent {
            query: "example.com".into(),
            qtype: "A".into(),
            response_code: "NOERROR".into(),
            verdict: Verdict::Allow,
            latency_ms: 17,
            upstream: Some("1.1.1.1:53".into()),
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let back: DnsEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }

    #[test]
    fn agent_event_round_trip_carries_platform() {
        let ev = AgentEvent {
            device_id: "d1".into(),
            event_type: "started".into(),
            posture_snapshot: Some(serde_json::json!({"disk_encrypted": true})),
            platform: Platform::Linux,
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let back: AgentEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }
}

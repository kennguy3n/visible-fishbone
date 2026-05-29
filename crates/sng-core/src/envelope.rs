//! Wire-format event envelope and per-class enums.
//!
//! Mirrors `internal/nats/schema/envelope.go` byte-for-byte:
//!
//! * MessagePack encoding (Go `vmihailenco/msgpack/v5` ↔ Rust
//!   `rmp-serde`);
//! * short-tag field names (`v`, `id`, `tid`, `did`, `sid`,
//!   `ts`, `cls`, `plt`, `tc`, `bi`, `bo`, `pl`);
//! * closed-set enums (event class, platform, verdict) that
//!   carry the same string values on both sides.
//!
//! The envelope is what the NATS JetStream pipeline carries on
//! the `sng.telemetry.>` and `sng.policy.>` subjects. Validating
//! it on both sides (rather than just one) is the single most
//! valuable wire-safety check in the workspace — it catches the
//! kind of "the producer's schema bumped silently" bug that would
//! otherwise poison the ClickHouse aggregates for hours before
//! anyone noticed.

use crate::error::ErrorCode;
use crate::ids::{DeviceId, EventId, SiteId, TenantId};
use crate::traffic_class::TrafficClass;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Current wire-format version. Bumped only on a backwards-
/// incompatible change; additive field changes do not bump it.
/// Must match `internal/nats/schema/envelope.go::SchemaVersion`.
pub const SCHEMA_VERSION: u8 = 1;

/// Event class — the closed set of telemetry / decision variants.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventClass {
    Flow,
    Dns,
    Http,
    Ips,
    Ztna,
    Sdwan,
    Agent,
    Posture,
}

impl EventClass {
    /// The lowercased wire string. Matches Go side
    /// `internal/nats/schema/envelope.go::EventClass`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Flow => "flow",
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Ips => "ips",
            Self::Ztna => "ztna",
            Self::Sdwan => "sdwan",
            Self::Agent => "agent",
            Self::Posture => "posture",
        }
    }
}

impl fmt::Display for EventClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Supported endpoint platform. Matches
/// `internal/nats/schema/envelope.go::Platform` and
/// `internal/repository.DevicePlatform`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    Windows,
    Macos,
    Linux,
    Ios,
    Android,
}

impl Platform {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Macos => "macos",
            Self::Linux => "linux",
            Self::Ios => "ios",
            Self::Android => "android",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Per-event disposition. Common across event classes so
/// downstream consumers can filter uniformly. Matches
/// `internal/nats/schema/envelope.go::Verdict`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Allow,
    Deny,
    Inspect,
    Alert,
    Log,
}

impl Verdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Inspect => "inspect",
            Self::Alert => "alert",
            Self::Log => "log",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Wire-format event envelope.
///
/// Field tags are intentionally short — telemetry channels carry
/// millions of events/sec at scale, and three-character keys
/// against eight-character field names is the difference between
/// the envelope fitting in a 200-byte typical observation or not.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    /// Schema version. Wire tag `v`.
    #[serde(rename = "v")]
    pub schema_version: u8,
    /// Per-event identifier (random v4 or v7).
    #[serde(rename = "id")]
    pub event_id: EventId,
    /// Tenant the event belongs to.
    #[serde(rename = "tid")]
    pub tenant_id: TenantId,
    /// Reporting device.
    #[serde(rename = "did")]
    pub device_id: DeviceId,
    /// Site (optional — endpoints not bound to a site omit it).
    #[serde(rename = "sid", default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<SiteId>,
    /// Producer-side timestamp.
    #[serde(rename = "ts", with = "chrono::serde::ts_milliseconds")]
    pub timestamp: DateTime<Utc>,
    /// Class of event the payload encodes.
    #[serde(rename = "cls")]
    pub event_class: EventClass,
    /// Platform the producing process is running on.
    #[serde(rename = "plt")]
    pub platform: Platform,
    /// Per-flow traffic class. Optional — legacy producers
    /// pre-dating classification omit it and the writer applies
    /// the [`TrafficClass::default_conservative`] default. Empty
    /// string on the wire is normalised to [`None`] by the
    /// custom serde adapter.
    #[serde(
        rename = "tc",
        default,
        skip_serializing_if = "Option::is_none",
        with = "traffic_class_serde"
    )]
    pub traffic_class: Option<TrafficClass>,
    /// Inbound bytes (server → client) hoisted from the FlowEvent
    /// payload onto the envelope so the telemetry writer can
    /// promote it to a dedicated ClickHouse column. Zero on
    /// non-flow events.
    #[serde(rename = "bi", default, skip_serializing_if = "is_zero_u64")]
    pub bytes_in: u64,
    /// Outbound bytes (client → server). See [`Self::bytes_in`].
    #[serde(rename = "bo", default, skip_serializing_if = "is_zero_u64")]
    pub bytes_out: u64,
    /// MessagePack-encoded class-specific payload, opaque to
    /// the envelope. Decoders dispatch on [`Self::event_class`]
    /// and call [`unpack_payload`] with the matching type.
    #[serde(rename = "pl", with = "serde_bytes")]
    pub payload: Vec<u8>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

/// `TrafficClass` adapter that lets the optional wire value be
/// either absent or an empty string (Go's `omitempty` semantics
/// emit absence, but older producers wrote `""` instead). Both
/// shapes deserialise to `None`; serialising `None` always emits
/// absence.
mod traffic_class_serde {
    use crate::traffic_class::TrafficClass;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(super) fn serialize<S: Serializer>(
        v: &Option<TrafficClass>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<TrafficClass>, D::Error> {
        // Accept either the absent case (handled by the
        // top-level `default`), an explicit null, or an empty
        // string. Anything non-empty has to be a known class —
        // unknown strings are rejected so a malformed producer
        // cannot pollute the ClickHouse `traffic_class` column.
        let raw = <Option<String>>::deserialize(d)?;
        match raw {
            None => Ok(None),
            Some(s) if s.is_empty() => Ok(None),
            Some(s) => s
                .parse::<TrafficClass>()
                .map(Some)
                .map_err(serde::de::Error::custom),
        }
    }
}

/// Wire-format error returned by envelope encode / decode / validate.
#[derive(Debug, Error)]
pub enum WireError {
    /// MessagePack encode failure.
    #[error("encode: {0}")]
    Encode(#[source] rmp_serde::encode::Error),
    /// MessagePack decode failure.
    #[error("decode: {0}")]
    Decode(#[source] rmp_serde::decode::Error),
    /// Decoded successfully but failed schema validation.
    #[error("schema: {0}")]
    Schema(String),
}

impl WireError {
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Encode(_) | Self::Decode(_) => ErrorCode::WireEncoding,
            Self::Schema(_) => ErrorCode::WireSchema,
        }
    }
}

impl Envelope {
    /// Schema-validate the envelope. Mirrors the Go-side
    /// `internal/nats/schema/envelope.go::Envelope::Validate`
    /// check set so a Rust producer cannot emit bytes that the
    /// Go consumer rejects (and vice-versa).
    pub fn validate(&self) -> Result<(), WireError> {
        if self.schema_version == 0 {
            return Err(WireError::Schema("schema_version is required".into()));
        }
        if self.event_id.is_nil() {
            return Err(WireError::Schema("event_id is required".into()));
        }
        if self.tenant_id.is_nil() {
            return Err(WireError::Schema("tenant_id is required".into()));
        }
        if self.device_id.is_nil() {
            return Err(WireError::Schema("device_id is required".into()));
        }
        // Producer-side timestamps must be non-zero; the Go side
        // uses `time.Time.IsZero()` which corresponds to the
        // Unix epoch on the chrono side.
        if self.timestamp.timestamp() == 0 && self.timestamp.timestamp_subsec_nanos() == 0 {
            return Err(WireError::Schema("timestamp is required".into()));
        }
        if self.payload.is_empty() {
            return Err(WireError::Schema("payload is required".into()));
        }
        Ok(())
    }
}

/// Trait implemented by [`Envelope`] to give callers a convenient
/// associated namespace for the encode/decode entry points. The
/// concrete methods live as free functions because they are also
/// useful in `#[cfg(test)]` fixtures without needing an
/// `Envelope` instance.
pub trait Marshal: Sized {
    /// Encode `self` to MessagePack bytes, running [`Envelope::validate`]
    /// first.
    fn marshal(&self) -> Result<Vec<u8>, WireError>;

    /// Decode MessagePack bytes, running [`Envelope::validate`]
    /// on the resulting struct.
    fn unmarshal(bytes: &[u8]) -> Result<Self, WireError>;
}

impl Marshal for Envelope {
    fn marshal(&self) -> Result<Vec<u8>, WireError> {
        self.validate()?;
        // Use `to_vec_named` so the encoder writes the
        // {key:value} map form msgpack — that's what the Go
        // `vmihailenco/msgpack/v5` library produces by default
        // (struct tags → map keys), and it is what the Go-side
        // tests assert against.
        rmp_serde::to_vec_named(self).map_err(WireError::Encode)
    }

    fn unmarshal(bytes: &[u8]) -> Result<Self, WireError> {
        let env: Self = rmp_serde::from_slice(bytes).map_err(WireError::Decode)?;
        env.validate()?;
        Ok(env)
    }
}

/// Encode an arbitrary serde-serialisable payload to the opaque
/// `payload` bytes the envelope carries.
pub fn pack_payload<T: Serialize>(payload: &T) -> Result<Vec<u8>, WireError> {
    rmp_serde::to_vec_named(payload).map_err(WireError::Encode)
}

/// Decode the opaque `payload` bytes back to a typed payload.
pub fn unpack_payload<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, WireError> {
    rmp_serde::from_slice(bytes).map_err(WireError::Decode)
}

/// Builds an envelope around a [`crate::events::FlowEvent`],
/// hoisting the byte counters and traffic-class decision onto
/// the envelope so they cannot drift from the payload. The
/// helper is the only sanctioned way to produce a flow envelope
/// — bypassing it risks the envelope `bi`/`bo` and the payload
/// `bi`/`bo` disagreeing, which silently breaks per-class byte
/// aggregates on the cost-attribution chart.
///
/// `tenant_id` / `device_id` / `site_id` / `timestamp` /
/// `platform` come from the caller; everything else is filled
/// from the supplied flow.
#[allow(clippy::too_many_arguments)]
pub fn wrap_flow_event(
    event_id: EventId,
    tenant_id: TenantId,
    device_id: DeviceId,
    site_id: Option<SiteId>,
    timestamp: DateTime<Utc>,
    platform: Platform,
    traffic_class: Option<TrafficClass>,
    flow: &crate::events::FlowEvent,
) -> Result<Envelope, WireError> {
    let payload = pack_payload(flow)?;
    let env = Envelope {
        schema_version: SCHEMA_VERSION,
        event_id,
        tenant_id,
        device_id,
        site_id,
        timestamp,
        event_class: EventClass::Flow,
        platform,
        traffic_class,
        bytes_in: flow.bytes_in,
        bytes_out: flow.bytes_out,
        payload,
    };
    env.validate()?;
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::FlowEvent;
    use chrono::TimeZone;
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

    fn sample_envelope() -> Envelope {
        let flow = sample_flow();
        wrap_flow_event(
            EventId::new_v4(),
            TenantId::new_v4(),
            DeviceId::new_v4(),
            Some(SiteId::new_v4()),
            Utc.timestamp_opt(1_716_000_000, 0).unwrap(),
            Platform::Linux,
            Some(TrafficClass::InspectFull),
            &flow,
        )
        .expect("envelope")
    }

    #[test]
    fn envelope_wire_uses_short_tags_from_go_schema() {
        let env = sample_envelope();
        let bytes = env.marshal().expect("marshal");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode dynamic");
        let keys: std::collections::BTreeSet<&str> = map.keys().map(String::as_str).collect();
        // Required short tags must all appear.
        for required in [
            "v", "id", "tid", "did", "sid", "ts", "cls", "plt", "tc", "bi", "bo", "pl",
        ] {
            assert!(
                keys.contains(required),
                "short tag {required} missing; got {keys:?}"
            );
        }
        // Rust field names must NOT leak.
        for forbidden in ["schema_version", "event_id", "tenant_id"] {
            assert!(
                !keys.contains(forbidden),
                "Rust field {forbidden} leaked; got {keys:?}"
            );
        }
    }

    #[test]
    fn envelope_round_trip_is_byte_stable_through_msgpack() {
        let env = sample_envelope();
        let bytes = env.marshal().expect("marshal");
        let back = Envelope::unmarshal(&bytes).expect("unmarshal");
        assert_eq!(env, back);
    }

    #[test]
    fn validate_rejects_nil_tenant_id() {
        let mut env = sample_envelope();
        env.tenant_id = TenantId::nil();
        let err = env.validate().expect_err("nil tenant rejected");
        assert!(err.to_string().contains("tenant_id"));
    }

    #[test]
    fn validate_rejects_empty_payload() {
        let mut env = sample_envelope();
        env.payload.clear();
        let err = env.validate().expect_err("empty payload rejected");
        assert!(err.to_string().contains("payload"));
    }

    #[test]
    fn validate_rejects_zero_schema_version() {
        let mut env = sample_envelope();
        env.schema_version = 0;
        let err = env.validate().expect_err("zero schema rejected");
        assert!(err.to_string().contains("schema_version"));
    }

    #[test]
    fn wrap_flow_event_hoists_byte_counters_onto_envelope() {
        let mut flow = sample_flow();
        flow.bytes_in = 7_777;
        flow.bytes_out = 8_888;
        let env = wrap_flow_event(
            EventId::new_v4(),
            TenantId::new_v4(),
            DeviceId::new_v4(),
            None,
            Utc.timestamp_opt(1_716_000_000, 0).unwrap(),
            Platform::Macos,
            None,
            &flow,
        )
        .expect("wrap");
        assert_eq!(env.bytes_in, 7_777);
        assert_eq!(env.bytes_out, 8_888);
        let decoded_payload: FlowEvent = unpack_payload(&env.payload).expect("payload");
        // Envelope counters and payload counters must agree —
        // that's the wrap_flow_event invariant the Go side also
        // depends on.
        assert_eq!(decoded_payload.bytes_in, env.bytes_in);
        assert_eq!(decoded_payload.bytes_out, env.bytes_out);
    }

    #[test]
    fn traffic_class_none_omits_field_on_wire() {
        let mut env = sample_envelope();
        env.traffic_class = None;
        let bytes = env.marshal().expect("marshal");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        assert!(!map.contains_key("tc"), "tc should be omitted; got {map:?}");
    }

    #[test]
    fn traffic_class_empty_string_decodes_as_none() {
        // Produce a manually-encoded envelope with `tc: ""` to
        // simulate a legacy Go producer pre-dating
        // omitempty / classification. The decoder must accept
        // that shape and normalise it to None rather than
        // erroring on the empty string.
        let mut env = sample_envelope();
        env.traffic_class = Some(TrafficClass::InspectFull);
        let bytes = env.marshal().expect("marshal");
        // Rewrite tc from "inspect_full" to "" by decoding to a
        // dynamic map, mutating, and re-encoding.
        let mut map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        map.insert("tc".into(), rmpv::Value::String("".into()));
        let mut rewritten = Vec::new();
        rmpv::encode::write_value(
            &mut rewritten,
            &rmpv::Value::Map(
                map.into_iter()
                    .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                    .collect(),
            ),
        )
        .expect("write");
        let back = Envelope::unmarshal(&rewritten).expect("decode legacy tc");
        assert_eq!(back.traffic_class, None);
    }

    #[test]
    fn traffic_class_unknown_string_is_rejected() {
        // Same shape as the legacy test above but with a
        // garbage tc value — must be rejected so polluted
        // dimensions never reach ClickHouse.
        let env = sample_envelope();
        let bytes = env.marshal().expect("marshal");
        let mut map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        map.insert("tc".into(), rmpv::Value::String("nope".into()));
        let mut rewritten = Vec::new();
        rmpv::encode::write_value(
            &mut rewritten,
            &rmpv::Value::Map(
                map.into_iter()
                    .map(|(k, v)| (rmpv::Value::String(k.into()), v))
                    .collect(),
            ),
        )
        .expect("write");
        let err = Envelope::unmarshal(&rewritten).expect_err("unknown tc rejected");
        // The error surfaces as a decode error rather than a
        // schema error because the rejection happens during
        // serde deserialisation, not later validation.
        assert!(matches!(err, WireError::Decode(_)));
    }
}

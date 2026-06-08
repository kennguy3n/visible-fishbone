//! Wire-format event envelope and per-class enums.
//!
//! Mirrors `internal/nats/schema/envelope.go` byte-for-byte:
//!
//! * MessagePack encoding (Go `vmihailenco/msgpack/v5` ↔ Rust
//!   `rmp-serde`);
//! * short-tag field names (`v`, `id`, `tid`, `did`, `sid`,
//!   `ts`, `cls`, `plt`, `tc`, `bi`, `bo`, `pl`);
//! * closed-set enums (event class, platform, verdict) that
//!   carry the same string values on both sides;
//! * **timestamp wire format**: the `ts` field is encoded as
//!   MessagePack [Timestamp extension type -1](https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type)
//!   — that is what `vmihailenco/msgpack/v5` emits by default for
//!   a Go `time.Time` struct field. Plain integer milliseconds
//!   (what `chrono::serde::ts_milliseconds` would produce) is
//!   **wire-incompatible**: Go decoders looking for an ext type
//!   would reject the integer and vice-versa. See
//!   [`msgpack_timestamp`] for the adapter that bridges chrono's
//!   `DateTime<Utc>` onto ext type -1.
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

/// The exact `DateTime<Utc>` that corresponds to Go's `time.Time{}`
/// zero value (year 1 AD UTC). `vmihailenco/msgpack/v5` encodes a
/// zero `time.Time` as the `timestamp 96` extension variant whose
/// signed-i64 seconds field is `-62_135_596_800` (= seconds from
/// Unix epoch back to `0001-01-01T00:00:00Z`). `validate()` rejects
/// exactly this value to mirror Go's `e.Timestamp.IsZero()` check
/// at `internal/nats/schema/envelope.go::Envelope.Validate`.
///
/// Exposed (pub) so downstream crates (e.g. `sng-comms`,
/// `sng-telemetry`) can write regression tests that assemble an
/// "is-zero" timestamp without re-deriving the constant.
pub const GO_ZERO_TIME_SECS: i64 = -62_135_596_800;

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
    ///
    /// Wire shape: MessagePack Timestamp extension (type -1).
    /// See module docs and [`msgpack_timestamp`].
    #[serde(rename = "ts", with = "msgpack_timestamp")]
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
        // Mirror Go's `e.Timestamp.IsZero()` check at
        // `internal/nats/schema/envelope.go::Envelope.Validate`.
        // Go's `time.Time{}` zero value is `0001-01-01T00:00:00Z`
        // UTC; on the wire it round-trips back to exactly
        // `GO_ZERO_TIME_SECS` seconds since the Unix epoch.
        //
        // The previous `timestamp_millis() <= 0` rule was strictly
        // stricter than Go (it also rejected the Unix epoch and
        // any pre-1970 timestamp). That divergence caused valid
        // Go-produced envelopes — e.g. fixtures explicitly set to
        // the Unix epoch — to fail Rust-side validation while
        // passing Go-side validation, exactly the kind of
        // asymmetric wire-safety bug the round-trip tests in this
        // module exist to catch.
        if self.timestamp.timestamp() == GO_ZERO_TIME_SECS
            && self.timestamp.timestamp_subsec_nanos() == 0
        {
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

/// MessagePack [Timestamp extension type -1][spec] serde adapter
/// for chrono `DateTime<Utc>`.
///
/// `vmihailenco/msgpack/v5` (the Go side's encoder) emits a Go
/// `time.Time` struct field as an extension type with tag `-1` and
/// one of three payload variants:
///
/// * `timestamp 32` (4 bytes): `seconds` as big-endian `u32`, used
///   when `nanos == 0` and `seconds` fits in `u32`;
/// * `timestamp 64` (8 bytes): `(nanos << 34) | seconds`, used when
///   `0 <= seconds < 2^34` and `nanos < 1_000_000_000`;
/// * `timestamp 96` (12 bytes): 4-byte BE `u32` nanos followed by
///   8-byte BE `i64` seconds, used for everything else (including
///   pre-epoch values like Go's `time.Time{}` zero).
///
/// This module reproduces all three variants for serialisation
/// (picking the smallest valid one, exactly like the Go encoder)
/// and accepts all three on deserialisation. `rmp-serde` exposes
/// the extension wire form through the magic
/// [`MSGPACK_EXT_STRUCT_NAME`](rmp_serde::MSGPACK_EXT_STRUCT_NAME)
/// newtype convention; the `Ext` newtype below is that hook.
///
/// [spec]: https://github.com/msgpack/msgpack/blob/master/spec.md#timestamp-extension-type
pub(crate) mod msgpack_timestamp {
    use chrono::{DateTime, TimeZone, Utc};
    use serde::de::Error as DeError;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::ByteBuf;

    /// rmp-serde's hook for emitting / decoding MessagePack ext
    /// types. The crate recognises a `_ExtStruct((i8, ByteBuf))`
    /// newtype on the wire and routes it through its ext-encoder
    /// rather than the generic newtype path.
    #[derive(Serialize, Deserialize)]
    #[serde(rename = "_ExtStruct")]
    struct Ext((i8, ByteBuf));

    /// MessagePack timestamp extension tag, defined by the spec
    /// linked at the module docs. Reserved for `time.Time` /
    /// `Instant` and never reused by application-level extensions.
    const TIMESTAMP_EXT_TYPE: i8 = -1;

    /// Encode `dt` to the smallest valid MessagePack timestamp
    /// extension payload, matching `vmihailenco/msgpack/v5`'s
    /// emission rules so the bytes are byte-identical to what the
    /// Go side produces.
    pub(super) fn serialize<S: Serializer>(dt: &DateTime<Utc>, ser: S) -> Result<S::Ok, S::Error> {
        let secs = dt.timestamp();
        let nanos = dt.timestamp_subsec_nanos();
        let buf = encode_payload(secs, nanos);
        Ext((TIMESTAMP_EXT_TYPE, ByteBuf::from(buf))).serialize(ser)
    }

    /// Decode a MessagePack timestamp extension. Rejects any
    /// extension whose tag is not `-1` (defends against an attacker
    /// substituting an application-level extension for a timestamp
    /// field) and any payload length not in `{4, 8, 12}`.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<DateTime<Utc>, D::Error> {
        let Ext((tag, bytes)) = Ext::deserialize(de)?;
        if tag != TIMESTAMP_EXT_TYPE {
            return Err(D::Error::custom(format!(
                "expected msgpack timestamp ext type {TIMESTAMP_EXT_TYPE}, got {tag}"
            )));
        }
        let (secs, nanos) = decode_payload(&bytes).map_err(D::Error::custom)?;
        Utc.timestamp_opt(secs, nanos)
            .single()
            .ok_or_else(|| D::Error::custom("timestamp out of range"))
    }

    /// timestamp 64 packs seconds into the bottom 34 bits, so any
    /// value `0 <= secs < 2^34` is encodable. Above the boundary
    /// (~year 2514) the encoder falls back to timestamp 96.
    const SECS_TIMESTAMP_64_MAX: i64 = 1i64 << 34;

    /// Pick the smallest of the three MessagePack timestamp
    /// variants for the given seconds/nanos pair. Mirrors the
    /// branching in `vmihailenco/msgpack/v5`'s
    /// `encodeNativeTime`.
    fn encode_payload(secs: i64, nanos: u32) -> Vec<u8> {
        // timestamp 32 fits when nanos is zero and seconds is a
        // non-negative `u32`. Use `try_from` rather than `as` to
        // keep clippy's cast-truncation lint quiet and to make
        // the bounds explicit at the call site.
        if nanos == 0
            && let Ok(secs_u32) = u32::try_from(secs)
        {
            return secs_u32.to_be_bytes().to_vec();
        }
        // timestamp 64 fits when seconds is a non-negative value
        // that fits in 34 bits and nanos < 1e9. The shift up by 34
        // packs nanos into the high 30 bits of a 64-bit unsigned
        // word; the spec guarantees the result is < 2^64.
        // `u64::try_from` only fails on negative inputs, which the
        // `(0..)` range already excludes downstream.
        if (0..SECS_TIMESTAMP_64_MAX).contains(&secs)
            && nanos < 1_000_000_000
            && let Ok(secs_u64) = u64::try_from(secs)
        {
            let data = (u64::from(nanos) << 34) | secs_u64;
            return data.to_be_bytes().to_vec();
        }
        // timestamp 96: 4-byte BE nanos, 8-byte BE i64 seconds.
        let mut buf = vec![0u8; 12];
        buf[..4].copy_from_slice(&nanos.to_be_bytes());
        buf[4..].copy_from_slice(&secs.to_be_bytes());
        buf
    }

    /// Decode any of the three MessagePack timestamp variants.
    /// Returns `(seconds, nanos)` where `nanos < 1_000_000_000`.
    fn decode_payload(data: &[u8]) -> Result<(i64, u32), String> {
        // `<[u8; N]>::try_from` on a slice of the right length
        // never fails, but using it (instead of `expect` on a
        // `try_into`) keeps clippy's `expect_used` lint quiet and
        // makes the panic path unreachable rather than
        // length-guarded.
        if let Ok(payload) = <[u8; 4]>::try_from(data) {
            let s = u32::from_be_bytes(payload);
            return Ok((i64::from(s), 0));
        }
        if let Ok(payload) = <[u8; 8]>::try_from(data) {
            let v = u64::from_be_bytes(payload);
            let n = u32::try_from(v >> 34)
                .map_err(|_| "timestamp 64: nanos high bits set".to_owned())?;
            // 34-bit mask; the upper 30 bits are nanoseconds, the
            // lower 34 are seconds. `as i64` is bounded by the
            // mask so no sign loss occurs.
            let s_unsigned = v & ((1u64 << 34) - 1);
            let s = i64::try_from(s_unsigned)
                .map_err(|_| "timestamp 64: seconds overflow i64".to_owned())?;
            if n >= 1_000_000_000 {
                return Err(format!("nanoseconds out of range: {n}"));
            }
            return Ok((s, n));
        }
        if let Ok(payload) = <[u8; 12]>::try_from(data) {
            let mut n_bytes = [0u8; 4];
            n_bytes.copy_from_slice(&payload[..4]);
            let mut s_bytes = [0u8; 8];
            s_bytes.copy_from_slice(&payload[4..]);
            let n = u32::from_be_bytes(n_bytes);
            let s = i64::from_be_bytes(s_bytes);
            if n >= 1_000_000_000 {
                return Err(format!("nanoseconds out of range: {n}"));
            }
            return Ok((s, n));
        }
        Err(format!(
            "invalid msgpack timestamp ext length: {}",
            data.len()
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use pretty_assertions::assert_eq;

        #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
        struct W {
            #[serde(with = "super")]
            ts: DateTime<Utc>,
        }

        fn encode(w: &W) -> Vec<u8> {
            rmp_serde::to_vec_named(w).expect("encode")
        }

        fn decode(b: &[u8]) -> W {
            rmp_serde::from_slice(b).expect("decode")
        }

        // Wire layout: byte 0 = fixmap(1) marker (0x81), bytes 1-3
        // = fixstr(2) "ts" key (`0xa2 0x74 0x73`), then the ext
        // marker starts at byte 4.
        const EXT_MARKER: usize = 4;
        const EXT_TYPE: usize = 5;

        #[test]
        fn timestamp32_round_trip() {
            // Seconds-only past-epoch value with nanos == 0 —
            // encoder should pick the 4-byte timestamp 32 variant.
            let w = W {
                ts: Utc.timestamp_opt(1_716_000_000, 0).unwrap(),
            };
            let b = encode(&w);
            assert_eq!(b[EXT_MARKER], 0xd6, "expected fixext 4 prefix, got {b:?}");
            assert_eq!(b[EXT_TYPE], 0xff, "expected ext type -1");
            assert_eq!(decode(&b), w);
        }

        #[test]
        fn timestamp64_round_trip() {
            // Sub-second precision — forces timestamp 64.
            let w = W {
                ts: Utc.timestamp_opt(1_716_000_000, 123_000_000).unwrap(),
            };
            let b = encode(&w);
            assert_eq!(b[EXT_MARKER], 0xd7, "expected fixext 8 prefix, got {b:?}");
            assert_eq!(b[EXT_TYPE], 0xff, "expected ext type -1");
            assert_eq!(decode(&b), w);
        }

        #[test]
        fn timestamp96_round_trip_pre_epoch() {
            // Year-1900 forces the timestamp 96 variant (negative
            // seconds don't fit in the u34 of timestamp 64).
            let w = W {
                ts: Utc.with_ymd_and_hms(1900, 1, 1, 0, 0, 0).unwrap(),
            };
            let b = encode(&w);
            // Wire shape: `c7 0c ff ...` = ext 8 (1-byte length
            // prefix), length=12, tag -1, 12-byte payload. The
            // length byte sits between the marker and the tag
            // for this variant only.
            assert_eq!(b[EXT_MARKER], 0xc7, "expected ext 8 prefix, got {b:?}");
            assert_eq!(b[EXT_MARKER + 1], 12, "expected length 12");
            assert_eq!(b[EXT_MARKER + 2], 0xff, "expected ext type -1");
            assert_eq!(decode(&b), w);
        }

        #[test]
        fn decodes_go_emitted_bytes_byte_for_byte() {
            // These bytes were captured from the `vmihailenco/msgpack/v5`
            // Go encoder for `time.Date(2024, 1, 15, 10, 30, 45, 123_000_000, time.UTC)`
            // and represent the canonical timestamp 64 wire shape.
            // If this decode ever drifts, Rust consumers will silently
            // ignore live Go-produced envelopes — hence the byte-literal
            // fixture rather than a generated-at-runtime value.
            let go_bytes: [u8; 14] = [
                0x81, 0xa2, 0x74, 0x73, 0xd7, 0xff, 0x1d, 0x53, 0x53, 0x00, 0x65, 0xa5, 0x09, 0x55,
            ];
            let decoded = decode(&go_bytes);
            assert_eq!(
                decoded.ts,
                Utc.timestamp_opt(1_705_314_645, 123_000_000).unwrap()
            );
        }

        #[test]
        fn rejects_non_timestamp_ext_tag() {
            // `d6 02 00000000` = fixext 4 with tag = 2 (application
            // ext, not timestamp). The decoder must reject it rather
            // than silently treating it as a 1970 timestamp.
            let bytes: [u8; 10] = [0x81, 0xa2, 0x74, 0x73, 0xd6, 0x02, 0, 0, 0, 0];
            let err: Result<W, _> = rmp_serde::from_slice(&bytes);
            assert!(err.is_err(), "non-timestamp ext tag must be rejected");
        }

        #[test]
        fn rejects_invalid_payload_length() {
            // `c7 05 ff 0000000000` = ext 8 length=5, tag -1, garbage
            // 5-byte payload. The decoder must reject the unknown
            // length rather than guessing.
            let bytes: [u8; 12] = [0x81, 0xa2, 0x74, 0x73, 0xc7, 0x05, 0xff, 0, 0, 0, 0, 0];
            let err: Result<W, _> = rmp_serde::from_slice(&bytes);
            assert!(err.is_err(), "invalid ext length must be rejected");
        }

        #[test]
        fn nano_precision_round_trip() {
            let w = W {
                ts: Utc.timestamp_opt(1_716_000_000, 999_999_999).unwrap(),
            };
            assert_eq!(decode(&encode(&w)), w);
        }
    }
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

    /// The "always-on" envelope fields must use the short tag
    /// form on the wire and the Rust field names must never
    /// leak. This test only asserts on tags that have no
    /// `skip_serializing_if` / `default` adapter — fields that
    /// may be omitted are covered separately so the assertion
    /// failure mode is self-explanatory.
    #[test]
    fn envelope_wire_uses_short_tags_from_go_schema() {
        let env = sample_envelope();
        let bytes = env.marshal().expect("marshal");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode dynamic");
        let keys: std::collections::BTreeSet<&str> = map.keys().map(String::as_str).collect();
        // Required short tags must all appear — these have no
        // `skip_serializing_if` adapter and are emitted for
        // every envelope.
        for required in ["v", "id", "tid", "did", "ts", "cls", "plt", "pl"] {
            assert!(
                keys.contains(required),
                "required short tag {required} missing; got {keys:?}"
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

    /// Optional / `skip_serializing_if` fields must appear
    /// **only** when their value warrants emission, and must
    /// use the short tag form when they do. Splitting this from
    /// the always-on assertion above is what gives a future
    /// failure mode a clear name: "the `tc` tag is missing from
    /// a non-default-traffic-class envelope" vs "a default
    /// envelope is unexpectedly emitting `tc`".
    #[test]
    fn envelope_wire_emits_optional_tags_when_populated() {
        // Build a flow envelope whose optional fields all
        // carry non-default values. Every optional tag MUST be
        // present.
        let env = sample_envelope();
        assert!(
            env.site_id.is_some()
                && env.traffic_class.is_some()
                && env.bytes_in > 0
                && env.bytes_out > 0,
            "fixture must exercise all optional tags",
        );
        let bytes = env.marshal().expect("marshal");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode dynamic");
        let keys: std::collections::BTreeSet<&str> = map.keys().map(String::as_str).collect();
        for populated in ["sid", "tc", "bi", "bo"] {
            assert!(
                keys.contains(populated),
                "optional short tag {populated} should be present when populated; got {keys:?}",
            );
        }
    }

    /// The inverse of the above: when every optional field is
    /// at its default ("absent") value, the encoder MUST omit
    /// the tag entirely rather than emit zero / null. This is
    /// what `skip_serializing_if` exists for — losing the
    /// guard silently doubles the wire size of an idle agent's
    /// heartbeat traffic.
    #[test]
    fn envelope_wire_omits_optional_tags_at_default() {
        let mut env = sample_envelope();
        // Synthesise a minimal-envelope flow: no site, no
        // traffic class decision yet, zero bytes counted.
        env.site_id = None;
        env.traffic_class = None;
        env.bytes_in = 0;
        env.bytes_out = 0;
        let bytes = env.marshal().expect("marshal");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode dynamic");
        let keys: std::collections::BTreeSet<&str> = map.keys().map(String::as_str).collect();
        for absent in ["sid", "tc", "bi", "bo"] {
            assert!(
                !keys.contains(absent),
                "optional short tag {absent} must be omitted at default; got {keys:?}",
            );
        }
        // The required tags must still all be present.
        for required in ["v", "id", "tid", "did", "ts", "cls", "plt", "pl"] {
            assert!(
                keys.contains(required),
                "required short tag {required} missing in minimal envelope; got {keys:?}",
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
    fn validate_accepts_unix_epoch_timestamp() {
        // Aligning Rust validation to Go's `e.Timestamp.IsZero()`:
        // the Unix epoch is a valid (if unusual) producer timestamp
        // that Go accepts, so the Rust side must accept it too.
        // Anything else risks valid Go-produced envelopes failing
        // Rust-side validation purely because the two sides disagree
        // on what "zero" means.
        let mut env = sample_envelope();
        env.timestamp = Utc.timestamp_opt(0, 0).unwrap();
        env.validate()
            .expect("unix epoch is valid per Go semantics");
    }

    #[test]
    fn validate_rejects_go_zero_time() {
        // Go's `time.Time{}` zero value is `0001-01-01T00:00:00Z`,
        // which `vmihailenco/msgpack/v5` encodes as the
        // `timestamp 96` ext variant with signed-i64 seconds =
        // -62_135_596_800. This is the exact value Go's
        // `e.Timestamp.IsZero()` rejects; the Rust side must reject
        // the same value.
        let mut env = sample_envelope();
        env.timestamp = Utc.timestamp_opt(GO_ZERO_TIME_SECS, 0).unwrap();
        let err = env.validate().expect_err("Go zero time rejected");
        assert!(err.to_string().contains("timestamp"));
    }

    #[test]
    fn validate_accepts_pre_epoch_timestamp() {
        // A pre-1970 timestamp is unusual but Go accepts it (only
        // `time.Time{}` is rejected). The Rust side must match —
        // otherwise a Go producer that emits a historical timestamp
        // (rare but legal) trips a Rust-only validation error.
        let mut env = sample_envelope();
        env.timestamp = Utc.with_ymd_and_hms(1969, 6, 1, 0, 0, 0).unwrap();
        env.validate().expect("pre-epoch is valid per Go semantics");
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

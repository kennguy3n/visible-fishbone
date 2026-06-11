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
    /// Posture-check result (`pass` / `fail` / `not_evaluated`).
    /// Stamped by the `sng-ztna` brain from the
    /// `sng_ztna::policy::PostureResult` tri-state enum;
    /// see that type's wire-form doc for the full
    /// alphabet rationale. The `not_evaluated` value is
    /// emitted on denies that short-circuit before the
    /// posture check runs (e.g. `unknown_app`,
    /// `tenant_mismatch`, `not_entitled`, `mfa_stale`) so
    /// dashboards can distinguish a posture failure from
    /// a deny that never reached the posture check.
    #[serde(rename = "pst")]
    pub posture_result: String,
    /// Decision (`allow` / `deny`). Carries only the
    /// allow/deny outcome — the detailed reason (e.g.
    /// `unknown_app`, `mfa_stale`, `tenant_mismatch`)
    /// lives on the sibling [`Self::reason`] field so
    /// dashboards that bucket by outcome and dashboards
    /// that bucket by cause both have a single source of
    /// truth.
    #[serde(rename = "dec")]
    pub decision: String,
    /// Detailed structured reason — the dashboards' deny
    /// bucket label (e.g. `unknown_app`, `mfa_stale`,
    /// `not_entitled`, `device_posture_insufficient`,
    /// `tenant_mismatch`) or `allow` on the allow path.
    /// Always non-empty when produced by `sng-ztna`; the
    /// field maps to the `ZtnaDecisionReason::as_str()` wire
    /// string.
    ///
    /// `#[serde(default)]` is load-bearing: producers older
    /// than this field (any pre-`sng-ztna` brain that emits
    /// a `ZtnaEvent` envelope without `rsn`) and the
    /// inverse — newer producer ↔ older consumer mismatch
    /// during a rolling deploy — must still decode. The
    /// empty string is the "unspecified" sentinel: dashboards
    /// already gate on the binary [`Self::decision`] and
    /// treat a missing reason as legacy-pre-PR-30 data, not
    /// a deny-bucket label collision (no real reason string
    /// is ever empty).
    #[serde(rename = "rsn", default)]
    pub reason: String,
    /// Finer-grained posture-deny cause, populated only on a
    /// `device_posture_insufficient` deny so dashboards can break
    /// out *why* posture failed without disturbing the stable
    /// [`Self::reason`] bucket. The mobile fail-closed pre-gate
    /// emits `posture_unprovable`, `posture_compromised`, or
    /// `posture_screen_lock_off`; it is empty on every other
    /// decision (and from producers predating this field).
    ///
    /// `#[serde(default, skip_serializing_if)]` is load-bearing:
    /// the field is additive and wire-stable — omitted from the
    /// `to_vec_named` map when empty, and decoding to the empty
    /// "unspecified" sentinel for any producer/consumer mismatch
    /// during a rolling deploy. Dashboards treat empty as "no
    /// finer cause reported" and fall back to [`Self::reason`].
    #[serde(rename = "psd", default, skip_serializing_if = "String::is_empty")]
    pub posture_detail: String,
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
    /// Optional operator-readable diagnostic reason for the event —
    /// e.g. the cause carried by a `tunnel_down`. Empty for events
    /// that have no free-form reason (`started` / `stopped` /
    /// `posture` / `tunnel_up`), so most agent records omit it on
    /// the wire.
    ///
    /// Mirrors [`ZtnaEvent::reason`]'s wire contract: `#[serde(default)]`
    /// plus `skip_serializing_if` keep the field backward- and
    /// forward-compatible across rolling deploys — a producer that
    /// predates the field omits `rsn` and decodes as the empty
    /// "unspecified" sentinel, and a newer producer's `rsn` is
    /// ignored by an older consumer. Carrying the reason in its own
    /// field rather than overloading the opaque [`Self::posture_snapshot`]
    /// slot keeps `pst` unambiguously posture-shaped.
    #[serde(rename = "rsn", default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Platform.
    #[serde(rename = "plt")]
    pub platform: Platform,
}

/// What triggered a subsystem restart.
///
/// Mirrors `internal/nats/schema/events.go::SubsystemRestartReason`.
/// The set is closed so the control plane's operator dashboard can
/// bucket self-healing activity by cause without parsing a free-form
/// string.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemRestartReason {
    /// The supervised process was observed dead / unreachable
    /// (PID gone, or the OS reported it exited).
    LivenessLost,
    /// The process is alive at the OS level but its control
    /// surface (Suricata stats socket, Envoy `/ready`) stopped
    /// answering — the classic "alive but wedged" failure.
    Unresponsive,
    /// The subsystem's composite health state machine reached
    /// its terminal `Failed` state (e.g. a sustained drop-ratio
    /// breach) without a clean single cause.
    HealthFailed,
    /// A lower tier's self-heal exhausted its restart budget and
    /// the top-level watchdog escalated (subsystem restart →
    /// edge restart → control-plane alert).
    Escalated,
}

/// Outcome of a single restart attempt.
///
/// Mirrors `internal/nats/schema/events.go::SubsystemRestartOutcome`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemRestartOutcome {
    /// The restart attempt was issued and the subsystem returned
    /// to a serving state.
    Recovered,
    /// The restart attempt was issued but the subsystem did not
    /// recover; the supervisor will retry under backoff.
    Failed,
    /// The supervisor exhausted its restart budget and is handing
    /// off to the next escalation tier.
    Exhausted,
}

/// Self-healing supervisor telemetry: a subsystem (`ips`, `swg`,
/// or the edge appliance itself) was restarted, or a restart was
/// attempted, by the WS2 self-healing supervisors.
///
/// This is the wire form of the "alert control plane" leg of the
/// watchdog escalation chain — the operator dashboard renders one
/// of these per restart attempt so a flapping subsystem is visible
/// fleet-wide across the 5000-tenant estate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemRestart {
    /// Stable subsystem name (`ips`, `swg`, `edge`). Matches the
    /// `sng_core::Subsystem::name` of the affected subsystem so a
    /// consumer can join this against the `/health` report.
    #[serde(rename = "sub")]
    pub subsystem: String,
    /// Why the restart was triggered.
    #[serde(rename = "rsn")]
    pub reason: SubsystemRestartReason,
    /// Outcome of this attempt.
    #[serde(rename = "out")]
    pub outcome: SubsystemRestartOutcome,
    /// 1-based attempt counter within the current failure episode.
    /// Resets to zero once the subsystem recovers, so a climbing
    /// value is the dashboard's crash-loop signal.
    #[serde(rename = "att")]
    pub attempt: u32,
    /// Fail posture in effect at the time of the restart: `true`
    /// when the operator policy is fail-open (traffic keeps
    /// flowing without coverage), `false` for fail-closed (traffic
    /// dropped until coverage returns).
    #[serde(rename = "fo")]
    pub fail_open: bool,
    /// Whether the restart rolled the subsystem back to its
    /// last-known-good config (rather than re-applying the config
    /// that was live when it failed). `true` means a candidate
    /// config was implicated in the failure and discarded.
    #[serde(rename = "rbc", default, skip_serializing_if = "is_false")]
    pub rolled_back_config: bool,
    /// Backoff applied before this attempt, in milliseconds.
    #[serde(rename = "boff")]
    pub backoff_ms: u64,
    /// Optional operator-readable detail (e.g. the underlying
    /// start error). Empty for the common success path, so most
    /// records omit it on the wire.
    #[serde(rename = "det", default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

/// `skip_serializing_if` predicate matching Go's `omitempty` for a
/// `bool`: a `false` value is omitted from the wire map entirely.
fn is_false(b: &bool) -> bool {
    !*b
}

/// `skip_serializing_if` predicate matching Go's `omitempty` for a
/// `u64`: a zero value is omitted from the wire map entirely.
fn is_zero_u64(n: &u64) -> bool {
    *n == 0
}

/// Coach-first action the endpoint DLP engine recommended for a
/// flagged AI-app upload.
///
/// Mirrors `internal/nats/schema/events.go::DLPAction` and the
/// existing [`crate::events`] wire convention. Ordered by user impact:
/// `monitor` < `coach` < `block`. This is the wire-form mirror of
/// `sng_dlp::ai_app::AiAppAction`; the two are kept distinct so the
/// shared `sng-core` crate does not depend on `sng-dlp`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    /// Recorded for audit; the user was not interrupted.
    Monitor,
    /// A non-blocking coaching nudge was surfaced — the canonical
    /// human-review candidate.
    Coach,
    /// The upload was refused at the edge (operator opt-in +
    /// high-confidence). Already enforced.
    Block,
}

/// Redacted finding family. Mirrors
/// `internal/nats/schema/events.go::DLPFindingKind` and the
/// `sng_dlp::ai_app::FindingKind` snake_case wire forms.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpFindingKind {
    /// Personally-identifiable information.
    Pii,
    /// Credential material.
    Secret,
    /// A company-confidential banner.
    Confidential,
}

/// One redacted, aggregate finding inside a flagged upload. Carries
/// NO matched bytes, offsets, or surrounding text — only a stable
/// detector label and per-class counts — preserving the redaction
/// invariant the AI-app signal enforces.
///
/// Mirrors `internal/nats/schema/events.go::DLPFinding` field-for-field.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DlpFinding {
    /// Finding family.
    #[serde(rename = "k")]
    pub kind: DlpFindingKind,
    /// Detector/rule id that fired (e.g. `ssn_us`, `github_token`,
    /// `confidential`). Stable identifier, never user data.
    #[serde(rename = "l")]
    pub label: String,
    /// How many distinct matches of this label were observed.
    #[serde(rename = "c")]
    pub count: u32,
    /// Strongest per-match confidence in `[0,1]`.
    #[serde(rename = "mc")]
    pub max_confidence: f64,
    /// Severity assigned to this finding class (`low` … `critical`).
    #[serde(rename = "sev")]
    pub severity: String,
}

/// Redacted endpoint DLP signal for an AI-app upload the edge flagged
/// but (by default) did not block — the producer half of the control
/// plane's human-in-the-loop review queue. Metadata-only by
/// construction: the destination app id, a severity and confidence,
/// and per-class finding summaries, never the matched content or the
/// upload's path/query.
///
/// Mirrors `internal/nats/schema/events.go::DLPEvent` field-for-field
/// with identical msgpack tags.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DlpEvent {
    /// Classified AI-app id (e.g. `chatgpt`) or the heuristic
    /// `suspected_ai_app` sentinel.
    #[serde(rename = "dst")]
    pub destination_app: String,
    /// Coach-first action the edge recommended.
    #[serde(rename = "act")]
    pub action: DlpAction,
    /// Overall (max-across-findings) severity (`low` … `critical`).
    #[serde(rename = "sev")]
    pub severity: String,
    /// Overall detector confidence in `[0,1]`.
    #[serde(rename = "cf")]
    pub confidence: f64,
    /// Redacted per-class evidence. May be empty for a
    /// destination-only signal.
    #[serde(rename = "fnd", default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<DlpFinding>,
    /// Body bytes scanned (post scan-ceiling truncation). Diagnostic.
    #[serde(rename = "sb", default, skip_serializing_if = "is_zero_u64")]
    pub scanned_bytes: u64,
    /// True when the body was truncated at the scan ceiling.
    #[serde(rename = "tr", default, skip_serializing_if = "is_false")]
    pub truncated: bool,
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
            reason: String::new(),
            platform: Platform::Linux,
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let back: AgentEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }

    #[test]
    fn agent_event_reason_round_trips_on_rsn_tag() {
        let ev = AgentEvent {
            device_id: "d1".into(),
            event_type: "tunnel_down".into(),
            posture_snapshot: None,
            reason: "idle".into(),
            platform: Platform::Android,
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        // The reason rides the short `rsn` wire tag (matching the Go
        // `internal/nats/schema/events.go::AgentEvent.Reason`), not the
        // Rust field name, and survives the round trip.
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode map");
        assert!(decoded.contains_key("rsn"), "rsn tag missing: {decoded:?}");
        assert!(
            !decoded.contains_key("reason"),
            "Rust field name leaked: {decoded:?}"
        );
        let back: AgentEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }

    #[test]
    fn agent_event_omits_empty_reason_on_wire() {
        let ev = AgentEvent {
            device_id: "d1".into(),
            event_type: "tunnel_up".into(),
            posture_snapshot: None,
            reason: String::new(),
            platform: Platform::Ios,
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode map");
        // An empty reason is omitted (skip_serializing_if), so legacy
        // consumers never see a spurious `rsn` key, and it decodes back
        // to the empty "unspecified" sentinel via `#[serde(default)]`.
        assert!(
            !decoded.contains_key("rsn"),
            "empty reason should be omitted: {decoded:?}"
        );
        let back: AgentEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }

    #[test]
    fn agent_event_decodes_legacy_payload_without_rsn() {
        // A pre-`rsn` producer emits only the original four fields;
        // `#[serde(default)]` must decode the missing reason as empty.
        let legacy = AgentEvent {
            device_id: "d1".into(),
            event_type: "started".into(),
            posture_snapshot: None,
            reason: String::new(),
            platform: Platform::Linux,
        };
        let bytes = rmp_serde::to_vec_named(&legacy).expect("encode");
        let back: AgentEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert!(back.reason.is_empty());
    }

    fn sample_ztna() -> ZtnaEvent {
        ZtnaEvent {
            device_id: "device-1".into(),
            app_id: "salesforce".into(),
            posture_result: "pass".into(),
            decision: "allow".into(),
            reason: "allow".into(),
            posture_detail: String::new(),
            identity_verified: true,
        }
    }

    #[test]
    fn ztna_event_round_trip_preserves_reason() {
        let ev = sample_ztna();
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let back: ZtnaEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
        assert_eq!(back.reason, "allow");
    }

    /// Legacy producer encoded a `ZtnaEvent` envelope without
    /// the `rsn` key — newer consumer must still decode it
    /// during a rolling deploy. The `#[serde(default)]` on
    /// [`ZtnaEvent::reason`] makes this safe; without it the
    /// decode would fail with `missing field 'rsn'` and the
    /// envelope would be dropped on the floor.
    #[test]
    fn ztna_event_decodes_legacy_wire_without_rsn_key() {
        // Build a msgpack map that's intentionally missing
        // the `rsn` key (i.e. the on-the-wire shape of a
        // legacy producer before this PR landed). Use the
        // short wire tags exactly as `#[serde(rename = ...)]`
        // sets them.
        let mut legacy = std::collections::BTreeMap::new();
        legacy.insert("did".to_string(), rmpv::Value::from("device-1"));
        legacy.insert("app".to_string(), rmpv::Value::from("salesforce"));
        legacy.insert("pst".to_string(), rmpv::Value::from("pass"));
        legacy.insert("dec".to_string(), rmpv::Value::from("allow"));
        legacy.insert("iv".to_string(), rmpv::Value::Boolean(true));
        // Intentionally no "rsn" entry.

        let bytes = rmp_serde::to_vec_named(&legacy).expect("encode legacy");
        let decoded: ZtnaEvent =
            rmp_serde::from_slice(&bytes).expect("legacy wire without `rsn` key must still decode");

        assert_eq!(decoded.device_id, "device-1");
        assert_eq!(decoded.app_id, "salesforce");
        assert_eq!(decoded.posture_result, "pass");
        assert_eq!(decoded.decision, "allow");
        assert!(decoded.identity_verified);
        // Sentinel for "legacy producer didn't ship a reason"
        // — dashboards distinguish this from a real reason
        // string by emptiness, and gate on `decision` for the
        // allow/deny rollup.
        assert_eq!(decoded.reason, "");
    }

    #[test]
    fn ztna_event_posture_detail_is_additive_and_wire_stable() {
        // Empty `posture_detail` (the common case) is omitted from
        // the wire map so existing consumers see no new key.
        let plain = sample_ztna();
        let bytes = rmp_serde::to_vec_named(&plain).expect("encode");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode map");
        assert!(
            !map.contains_key("psd"),
            "empty posture_detail must be omitted: {map:?}"
        );

        // When populated (a mobile posture-deny), the finer cause
        // rides the dedicated `psd` key and round-trips.
        let detailed = ZtnaEvent {
            decision: "deny".into(),
            reason: "device_posture_insufficient".into(),
            posture_detail: "posture_compromised".into(),
            ..sample_ztna()
        };
        let bytes = rmp_serde::to_vec_named(&detailed).expect("encode");
        let map: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode map");
        assert_eq!(
            map.get("psd").and_then(rmpv::Value::as_str),
            Some("posture_compromised")
        );
        let back: ZtnaEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(detailed, back);

        // A legacy producer without the `psd` key still decodes
        // (the empty sentinel), so a rolling deploy is safe.
        let mut legacy = std::collections::BTreeMap::new();
        legacy.insert("did".to_string(), rmpv::Value::from("device-1"));
        legacy.insert("app".to_string(), rmpv::Value::from("salesforce"));
        legacy.insert("pst".to_string(), rmpv::Value::from("fail"));
        legacy.insert("dec".to_string(), rmpv::Value::from("deny"));
        legacy.insert(
            "rsn".to_string(),
            rmpv::Value::from("device_posture_insufficient"),
        );
        legacy.insert("iv".to_string(), rmpv::Value::Boolean(false));
        let bytes = rmp_serde::to_vec_named(&legacy).expect("encode legacy");
        let decoded: ZtnaEvent =
            rmp_serde::from_slice(&bytes).expect("legacy wire without `psd` must decode");
        assert_eq!(decoded.posture_detail, "");
    }

    #[test]
    fn ztna_event_msgpack_uses_short_field_tags() {
        // Populate `posture_detail` so its rename (`psd`) is exercised
        // here too — with the empty default it is skipped, so the
        // required/forbidden lists below could not otherwise verify it.
        let ev = ZtnaEvent {
            posture_detail: "posture_compromised".into(),
            ..sample_ztna()
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        let keys: std::collections::BTreeSet<&str> = decoded.keys().map(String::as_str).collect();
        for required in ["did", "app", "pst", "dec", "rsn", "psd", "iv"] {
            assert!(
                keys.contains(required),
                "msgpack key {required} missing; got {keys:?}"
            );
        }
        for forbidden in [
            "device_id",
            "app_id",
            "posture_result",
            "decision",
            "reason",
            "posture_detail",
            "identity_verified",
        ] {
            assert!(
                !keys.contains(forbidden),
                "Rust field {forbidden} leaked onto the wire; got {keys:?}"
            );
        }
    }

    fn sample_restart() -> SubsystemRestart {
        SubsystemRestart {
            subsystem: "ips".into(),
            reason: SubsystemRestartReason::Unresponsive,
            outcome: SubsystemRestartOutcome::Recovered,
            attempt: 2,
            fail_open: true,
            rolled_back_config: true,
            backoff_ms: 4_000,
            detail: "stats socket silent for 9s".into(),
        }
    }

    #[test]
    fn subsystem_restart_round_trip_preserves_all_fields() {
        let ev = sample_restart();
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let back: SubsystemRestart = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }

    #[test]
    fn subsystem_restart_uses_short_field_tags() {
        let ev = sample_restart();
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        let keys: std::collections::BTreeSet<&str> = decoded.keys().map(String::as_str).collect();
        for required in ["sub", "rsn", "out", "att", "fo", "rbc", "boff", "det"] {
            assert!(
                keys.contains(required),
                "msgpack key {required} missing; got {keys:?}"
            );
        }
        for forbidden in [
            "subsystem",
            "reason",
            "outcome",
            "attempt",
            "fail_open",
            "backoff_ms",
        ] {
            assert!(
                !keys.contains(forbidden),
                "Rust field {forbidden} leaked onto the wire; got {keys:?}"
            );
        }
    }

    #[test]
    fn subsystem_restart_omits_empty_optionals() {
        // The common success path carries no detail and did not
        // roll back config — both must be omitted (Go `omitempty`).
        let ev = SubsystemRestart {
            rolled_back_config: false,
            detail: String::new(),
            ..sample_restart()
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        assert!(!decoded.contains_key("rbc"), "false rbc must be omitted");
        assert!(!decoded.contains_key("det"), "empty det must be omitted");
        // fail_open is NOT omitempty even when false — it is
        // meaningful posture state, mirroring the Go tag.
        let ev = SubsystemRestart {
            fail_open: false,
            ..ev
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        assert!(decoded.contains_key("fo"), "fo must always be present");
    }

    #[test]
    fn subsystem_restart_reason_and_outcome_wire_strings() {
        // The enum wire forms are part of the dashboard contract.
        let bytes = rmp_serde::to_vec_named(&SubsystemRestartReason::LivenessLost).expect("encode");
        let s: String = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(s, "liveness_lost");
        let bytes = rmp_serde::to_vec_named(&SubsystemRestartOutcome::Exhausted).expect("encode");
        let s: String = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(s, "exhausted");
    }

    fn sample_dlp() -> DlpEvent {
        DlpEvent {
            destination_app: "chatgpt".into(),
            action: DlpAction::Coach,
            severity: "high".into(),
            confidence: 0.92,
            findings: vec![
                DlpFinding {
                    kind: DlpFindingKind::Secret,
                    label: "github_token".into(),
                    count: 2,
                    max_confidence: 0.99,
                    severity: "high".into(),
                },
                DlpFinding {
                    kind: DlpFindingKind::Pii,
                    label: "ssn_us".into(),
                    count: 1,
                    max_confidence: 0.95,
                    severity: "medium".into(),
                },
            ],
            scanned_bytes: 4_096,
            truncated: true,
        }
    }

    #[test]
    fn dlp_event_round_trip_preserves_all_fields() {
        let ev = sample_dlp();
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let back: DlpEvent = rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(ev, back);
    }

    #[test]
    fn dlp_event_uses_short_field_tags() {
        let ev = sample_dlp();
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        let keys: std::collections::BTreeSet<&str> = decoded.keys().map(String::as_str).collect();
        for required in ["dst", "act", "sev", "cf", "fnd", "sb", "tr"] {
            assert!(
                keys.contains(required),
                "msgpack key {required} missing; got {keys:?}"
            );
        }
        for forbidden in [
            "destination_app",
            "action",
            "confidence",
            "findings",
            "scanned_bytes",
        ] {
            assert!(
                !keys.contains(forbidden),
                "Rust field {forbidden} leaked onto the wire; got {keys:?}"
            );
        }
    }

    #[test]
    fn dlp_event_omits_empty_optionals() {
        // A destination-only monitor signal carries no findings and no
        // diagnostics — all three optional tags must be omitted to
        // match the Go `omitempty` side.
        let ev = DlpEvent {
            destination_app: "claude".into(),
            action: DlpAction::Monitor,
            severity: "low".into(),
            confidence: 0.2,
            findings: vec![],
            scanned_bytes: 0,
            truncated: false,
        };
        let bytes = rmp_serde::to_vec_named(&ev).expect("encode");
        let decoded: std::collections::BTreeMap<String, rmpv::Value> =
            rmp_serde::from_slice(&bytes).expect("decode");
        for omitted in ["fnd", "sb", "tr"] {
            assert!(
                !decoded.contains_key(omitted),
                "empty optional {omitted} must be omitted; got {decoded:?}"
            );
        }
    }

    #[test]
    fn dlp_action_and_kind_wire_strings() {
        // The snake_case wire forms are the cross-language contract.
        let b = rmp_serde::to_vec_named(&DlpAction::Coach).expect("encode");
        let s: String = rmp_serde::from_slice(&b).expect("decode");
        assert_eq!(s, "coach");
        let b = rmp_serde::to_vec_named(&DlpFindingKind::Confidential).expect("encode");
        let s: String = rmp_serde::from_slice(&b).expect("decode");
        assert_eq!(s, "confidential");
    }
}

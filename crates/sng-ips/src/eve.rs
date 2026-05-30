//! Suricata EVE JSON parser and normaliser.
//!
//! Suricata writes a JSON-lines log (`eve.json`) with one event
//! per line. Every line shares a common envelope — timestamp,
//! src/dst tuple, `event_type` discriminator — and then carries
//! a per-event-type payload object. The set of event types the
//! manager tails is:
//!
//! * `alert` — IDS / IPS rule hit ([`EveAlert`])
//! * `anomaly` — protocol anomaly detector hit
//!   ([`EveAnomaly`])
//! * `dns` — DNS request / response observation
//!   ([`EveDns`])
//! * `http` — HTTP request observation ([`EveHttp`])
//! * `tls` — TLS handshake observation ([`EveTls`])
//! * `fileinfo` — file-extraction event ([`EveFileinfo`])
//! * `flow` — flow record (5-tuple + counters) ([`EveFlow`])
//!
//! `event_type`s outside this set are surfaced as
//! [`EveRecord::Unknown`] rather than dropped: a Suricata
//! upgrade that introduces a new event class (e.g. `mqtt`,
//! `krb5`, `rfb`) should not silently lose telemetry. The
//! manager normalises only the known ones into the shared
//! [`sng_core::events`] schema and forwards `Unknown` as a
//! one-line tracing log so an operator can decide whether to
//! upgrade `sng-ips`.
//!
//! ## Why not `derive(Deserialize)` and call it a day
//!
//! Each EVE event-type payload is its own nested struct with
//! its own optional fields and Suricata version differences. We
//! could decode every line into a single struct with every
//! payload as `Option<T>`, but that surface would be misleading
//! — a `flow` record genuinely cannot have an `alert` payload,
//! and a downstream consumer that branches on the variant gets
//! exhaustiveness checking from the Rust compiler. The
//! discriminator-then-payload shape costs one extra
//! `serde_json::Value` decode per line; this is a micro-optimisation
//! we deliberately do not make.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sng_core::envelope::Verdict;
use sng_core::events::{DnsEvent, FlowEvent, HttpEvent, IpsEvent};

use crate::error::IpsError;

/// A decoded EVE JSON line. Every variant carries the common
/// envelope fields (timestamp, 5-tuple) plus its own payload.
#[derive(Clone, Debug, PartialEq)]
pub enum EveRecord {
    Alert(EveAlert),
    Anomaly(EveAnomaly),
    Dns(EveDns),
    Http(EveHttp),
    Tls(EveTls),
    Fileinfo(EveFileinfo),
    Flow(EveFlow),
    /// Event type the parser does not recognise. Carries the
    /// raw `event_type` string + the parsed JSON object so the
    /// supervisor can log it without re-parsing. The manager
    /// surfaces this as a `tracing::warn` rather than dropping —
    /// a new Suricata event type appearing should be visible.
    Unknown {
        event_type: String,
        raw: Value,
    },
}

impl EveRecord {
    /// Parse a single EVE JSON line. Returns
    /// [`IpsError::EveDecode`] for malformed JSON or for an EVE
    /// envelope missing the discriminator field.
    ///
    /// `line` is expected to be a single JSON object on a single
    /// line (Suricata never emits multi-line JSON in EVE mode).
    pub fn parse_line(line: &str) -> Result<Self, IpsError> {
        let v: Value = serde_json::from_str(line)
            .map_err(|e| IpsError::EveDecode(format!("invalid json: {e}")))?;
        let event_type = v
            .get("event_type")
            .and_then(Value::as_str)
            .ok_or_else(|| IpsError::EveDecode("missing event_type".into()))?
            .to_string();
        match event_type.as_str() {
            "alert" => Ok(Self::Alert(decode_payload(&v, "alert")?)),
            "anomaly" => Ok(Self::Anomaly(decode_payload(&v, "anomaly")?)),
            "dns" => Ok(Self::Dns(decode_payload(&v, "dns")?)),
            "http" => Ok(Self::Http(decode_payload(&v, "http")?)),
            "tls" => Ok(Self::Tls(decode_payload(&v, "tls")?)),
            "fileinfo" => Ok(Self::Fileinfo(decode_payload(&v, "fileinfo")?)),
            "flow" => Ok(Self::Flow(decode_payload(&v, "flow")?)),
            _ => Ok(Self::Unknown { event_type, raw: v }),
        }
    }

    /// The 5-tuple discriminator the envelope carries. Returned
    /// flat (not nested) so the manager's per-record fan-out
    /// does not need to walk the variant.
    #[must_use]
    pub fn flow_tuple(&self) -> Option<&FlowTuple> {
        match self {
            Self::Alert(a) => Some(&a.tuple),
            Self::Anomaly(a) => Some(&a.tuple),
            Self::Dns(d) => Some(&d.tuple),
            Self::Http(h) => Some(&h.tuple),
            Self::Tls(t) => Some(&t.tuple),
            Self::Fileinfo(f) => Some(&f.tuple),
            Self::Flow(f) => Some(&f.tuple),
            Self::Unknown { .. } => None,
        }
    }

    /// The discriminator string this record was decoded from.
    /// Used by the tracing layer.
    #[must_use]
    pub fn event_type(&self) -> &str {
        match self {
            Self::Alert(_) => "alert",
            Self::Anomaly(_) => "anomaly",
            Self::Dns(_) => "dns",
            Self::Http(_) => "http",
            Self::Tls(_) => "tls",
            Self::Fileinfo(_) => "fileinfo",
            Self::Flow(_) => "flow",
            Self::Unknown { event_type, .. } => event_type.as_str(),
        }
    }
}

/// Decode the named payload object out of the raw EVE line.
/// Used by every concrete variant — kept private because the
/// envelope-shape contract (the payload lives under a key equal
/// to the `event_type` discriminator) is internal to Suricata.
fn decode_payload<T: for<'de> Deserialize<'de>>(line: &Value, key: &str) -> Result<T, IpsError> {
    // The envelope fields (timestamp, src_ip, …) sit alongside
    // the payload object on the same JSON line, so we serde-
    // decode the whole line into the typed struct rather than
    // pulling just the payload sub-object. The struct definitions
    // below use `#[serde(flatten)]` to collect the envelope into
    // a [`FlowTuple`] field and `#[serde(rename = "...")]` to
    // pull the payload sub-object into the typed `payload` field.
    //
    // We pass the key in so the same decoder helper works for
    // every variant; the typed struct's rename annotation does
    // the actual extraction.
    let _ = key;
    serde_json::from_value(line.clone())
        .map_err(|e| IpsError::EveDecode(format!("decode payload: {e}")))
}

/// 5-tuple + timestamp envelope every EVE record carries.
///
/// Suricata fills `dest_*` rather than `dst_*` (only the field
/// names — the meaning is the same as the SNG event schema's
/// `dst_*`). We keep the Suricata naming on the deserialised
/// struct and translate at the normalisation boundary so the
/// JSON test fixtures stay byte-identical to the raw EVE output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowTuple {
    /// RFC 3339 timestamp emitted by Suricata.
    #[serde(default)]
    pub timestamp: Option<String>,
    /// Suricata flow id (per-connection, monotonically assigned).
    #[serde(default)]
    pub flow_id: Option<u64>,
    /// Source IP (canonical text form).
    #[serde(default)]
    pub src_ip: Option<String>,
    /// Source port.
    #[serde(default)]
    pub src_port: Option<u16>,
    /// Destination IP — Suricata key is `dest_ip`.
    #[serde(default, rename = "dest_ip")]
    pub dst_ip: Option<String>,
    /// Destination port — Suricata key is `dest_port`.
    #[serde(default, rename = "dest_port")]
    pub dst_port: Option<u16>,
    /// IP protocol (`TCP` / `UDP` / `ICMP` / …). Suricata
    /// emits uppercase; we normalise to lowercase when mapping
    /// to [`IpsEvent::protocol`].
    #[serde(default)]
    pub proto: Option<String>,
    /// Layer-7 application protocol Suricata identified.
    #[serde(default)]
    pub app_proto: Option<String>,
}

impl FlowTuple {
    /// Lowercase protocol string suitable for the SNG event
    /// schema (which uses `tcp` / `udp` / `icmp` / `other`).
    /// Defaults to `"other"` when Suricata omits the field.
    #[must_use]
    pub fn normalised_protocol(&self) -> String {
        self.proto
            .as_deref()
            .map_or_else(|| "other".into(), str::to_ascii_lowercase)
    }
}

/// `event_type: alert` payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveAlert {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub alert: AlertPayload,
}

/// Inner `alert` object on an EVE alert line.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlertPayload {
    /// Suricata signature id.
    pub signature_id: u32,
    /// Signature revision.
    #[serde(default)]
    pub rev: u32,
    /// Human-readable signature.
    pub signature: String,
    /// Category Suricata assigned (e.g. "A Network Trojan was
    /// detected").
    #[serde(default)]
    pub category: Option<String>,
    /// Suricata severity 1 (highest) through 4 (lowest).
    pub severity: u8,
    /// `allowed` / `blocked` / `drop` / `pass`.
    ///
    /// Suricata 6 introduced this field as `action`; older
    /// installs may omit it, in which case it defaults to
    /// `alert` (detected, not blocked).
    #[serde(default = "default_alert_action")]
    pub action: String,
    /// Group of signatures the rule belongs to.
    #[serde(default)]
    pub gid: Option<u32>,
}

fn default_alert_action() -> String {
    "alert".into()
}

/// `event_type: anomaly` payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveAnomaly {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub anomaly: AnomalyPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AnomalyPayload {
    /// Anomaly event short type code (e.g.
    /// `applayer_wrong_direction_first_data`).
    #[serde(rename = "event")]
    pub event_name: String,
    /// Anomaly type — `applayer` / `decode` / `stream`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Layer Suricata observed the anomaly at.
    #[serde(default)]
    pub layer: Option<String>,
}

/// `event_type: dns` payload.
///
/// Suricata emits a single object that contains either a query
/// or a response depending on the direction. The struct mirrors
/// the EVE shape rather than splitting query / response so the
/// fixture round-trips byte-perfectly.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveDns {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub dns: DnsPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DnsPayload {
    /// `query` or `answer`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Queried name.
    pub rrname: String,
    /// Query type (`A` / `AAAA` / `CNAME` / …).
    pub rrtype: String,
    /// Response code (only present on `answer` records). Suricata
    /// uses the IANA name (`NOERROR`, `NXDOMAIN`, …).
    #[serde(default)]
    pub rcode: Option<String>,
    /// Transaction id.
    #[serde(default)]
    pub id: Option<u32>,
    /// Authoritative-answer bit.
    #[serde(default)]
    pub aa: Option<bool>,
}

/// `event_type: http` payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveHttp {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub http: HttpPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HttpPayload {
    /// Request hostname.
    pub hostname: String,
    /// Request URL path.
    pub url: String,
    /// Method (`GET`, `POST`, …).
    #[serde(default)]
    pub http_method: Option<String>,
    /// Response status code, when the response was observed.
    #[serde(default)]
    pub status: Option<u16>,
    /// Response content-type, when present.
    #[serde(default)]
    pub http_content_type: Option<String>,
    /// User-agent.
    #[serde(default)]
    pub http_user_agent: Option<String>,
    /// Response length.
    #[serde(default)]
    pub length: Option<u64>,
}

/// `event_type: tls` payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveTls {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub tls: TlsPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TlsPayload {
    /// SNI extension value.
    #[serde(default)]
    pub sni: Option<String>,
    /// Negotiated TLS version (`TLS 1.3`, `TLS 1.2`, …).
    pub version: String,
    /// Subject DN of the server certificate.
    #[serde(default)]
    pub subject: Option<String>,
    /// Issuer DN of the server certificate.
    #[serde(default)]
    pub issuerdn: Option<String>,
    /// JA3 fingerprint of the client hello.
    #[serde(default)]
    pub ja3: Option<TlsJa3>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TlsJa3 {
    /// MD5 hash of the JA3 string.
    pub hash: String,
    /// The full JA3 string (TLS version, ciphers, extensions,
    /// curves, point formats).
    #[serde(rename = "string")]
    pub raw: String,
}

/// `event_type: fileinfo` payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveFileinfo {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub fileinfo: FileinfoPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileinfoPayload {
    /// Filename as observed on the wire (HTTP filename, SMB
    /// path, …).
    pub filename: String,
    /// File size in bytes.
    pub size: u64,
    /// SHA-256 hex digest of the file contents, when Suricata
    /// computed it (the `file-store` feature must be enabled).
    #[serde(default)]
    pub sha256: Option<String>,
    /// `true` if Suricata's file extraction stored the full
    /// file body.
    #[serde(default)]
    pub stored: bool,
    /// `true` if the size on the wire matches the size from the
    /// transport protocol's content-length / equivalent header.
    #[serde(default)]
    pub size_matches: Option<bool>,
}

/// `event_type: flow` payload.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EveFlow {
    #[serde(flatten)]
    pub tuple: FlowTuple,
    pub flow: FlowPayload,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlowPayload {
    /// Packets observed in the to-server direction.
    pub pkts_toserver: u64,
    /// Packets observed in the to-client direction.
    pub pkts_toclient: u64,
    /// Bytes in the to-server direction.
    pub bytes_toserver: u64,
    /// Bytes in the to-client direction.
    pub bytes_toclient: u64,
    /// Flow state (`new` / `established` / `closed`).
    #[serde(default)]
    pub state: Option<String>,
    /// Reason the flow was logged (`timeout` / `forced` /
    /// `shutdown`).
    #[serde(default)]
    pub reason: Option<String>,
    /// Flow start timestamp.
    #[serde(default)]
    pub start: Option<String>,
    /// Flow end timestamp.
    #[serde(default)]
    pub end: Option<String>,
}

// ----- Normalisation into the workspace event schema -----

impl EveAlert {
    /// Map an EVE alert into the workspace [`IpsEvent`] schema.
    ///
    /// The translation is total: every required field on
    /// [`IpsEvent`] has a sensible default if Suricata omitted
    /// the corresponding EVE field (an alert with no `src_ip` is
    /// rare but valid for decode-layer rules, and we surface it
    /// as `"unknown"` rather than dropping the alert).
    #[must_use]
    pub fn to_ips_event(&self) -> IpsEvent {
        IpsEvent {
            rule_id: self.alert.signature_id.to_string(),
            signature: self.alert.signature.clone(),
            severity: severity_label(self.alert.severity).into(),
            action: self.alert.action.clone(),
            src_ip: self
                .tuple
                .src_ip
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            dst_ip: self
                .tuple
                .dst_ip
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            protocol: self.tuple.normalised_protocol(),
        }
    }
}

/// Map Suricata's numeric severity (1 highest, 4 lowest) to the
/// SNG event schema's string severity. Suricata occasionally
/// emits 0 ("never seen in the field, but the field is u8" — we
/// treat it as `info`).
#[must_use]
pub fn severity_label(severity: u8) -> &'static str {
    match severity {
        1 => "critical",
        2 => "high",
        3 => "medium",
        4 => "low",
        _ => "info",
    }
}

impl EveDns {
    /// Map an EVE DNS observation into [`DnsEvent`]. Returns
    /// `None` for `query` records (the SNG schema is response-
    /// oriented: a query without an answer is not yet a useful
    /// telemetry event — Suricata will emit a paired `answer`
    /// when the response is observed). The verdict is always
    /// [`Verdict::Allow`] because Suricata does not block at the
    /// DNS layer — that is sng-dns's job; an EVE record is
    /// observational only.
    #[must_use]
    pub fn to_dns_event(&self) -> Option<DnsEvent> {
        if self.dns.kind != "answer" {
            return None;
        }
        Some(DnsEvent {
            query: self.dns.rrname.clone(),
            qtype: self.dns.rrtype.clone(),
            response_code: self.dns.rcode.clone().unwrap_or_else(|| "NOERROR".into()),
            verdict: Verdict::Allow,
            latency_ms: 0,
            upstream: None,
        })
    }
}

impl EveHttp {
    /// Map an EVE HTTP record into [`HttpEvent`]. Always
    /// produces an event (HTTP records are emitted at request
    /// time on Suricata even before the response). When the
    /// status is unknown the schema requires a u16 — we use 0,
    /// matching what the SWG does for in-flight requests.
    #[must_use]
    pub fn to_http_event(&self) -> HttpEvent {
        HttpEvent {
            method: self
                .http
                .http_method
                .clone()
                .unwrap_or_else(|| "UNKNOWN".into()),
            url: self.http.url.clone(),
            host: self.http.hostname.clone(),
            status_code: self.http.status.unwrap_or(0),
            verdict: Verdict::Allow,
            tls_version: None,
            sni: None,
            content_type: self.http.http_content_type.clone(),
            bytes: self.http.length,
        }
    }
}

impl EveFlow {
    /// Map an EVE flow record into the workspace [`FlowEvent`].
    /// The SNG schema's `bytes_in` / `bytes_out` are oriented
    /// from the server's perspective; Suricata's
    /// `bytes_toserver` / `bytes_toclient` are oriented from
    /// the connection's perspective. So `toserver` maps to
    /// `bytes_out` (client → server) and `toclient` to
    /// `bytes_in` (server → client).
    #[must_use]
    pub fn to_flow_event(&self) -> FlowEvent {
        FlowEvent {
            src_ip: self
                .tuple
                .src_ip
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            dst_ip: self
                .tuple
                .dst_ip
                .clone()
                .unwrap_or_else(|| "unknown".into()),
            src_port: self.tuple.src_port.unwrap_or(0),
            dst_port: self.tuple.dst_port.unwrap_or(0),
            protocol: self.tuple.normalised_protocol(),
            app_id: self.tuple.app_proto.clone(),
            verdict: Verdict::Allow,
            score: None,
            bytes_in: self.flow.bytes_toclient,
            bytes_out: self.flow.bytes_toserver,
            duration_ms: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Real Suricata 7.x alert line (from `eve.json`, with the
    /// timestamp date adjusted for stability). Preserved as a
    /// fixture so any future renamed field would surface
    /// here.
    const REAL_ALERT_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:00.000000+0000","flow_id":1234567890123456,"in_iface":"eth0","event_type":"alert","src_ip":"10.0.0.5","src_port":51234,"dest_ip":"203.0.113.10","dest_port":80,"proto":"TCP","alert":{"action":"blocked","gid":1,"signature_id":2001234,"rev":3,"signature":"ET MALWARE Suspicious User-Agent","category":"A Network Trojan was detected","severity":1},"app_proto":"http","flow":{"pkts_toserver":4,"pkts_toclient":3,"bytes_toserver":540,"bytes_toclient":380,"start":"2024-01-15T10:30:00.000000+0000"}}"#;

    const REAL_ANOMALY_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:01.000000+0000","flow_id":1234567890123457,"event_type":"anomaly","src_ip":"10.0.0.5","src_port":51235,"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP","anomaly":{"type":"stream","event":"stream.pkt_invalid_ack","layer":"tcp"}}"#;

    const REAL_DNS_ANSWER_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:02.000000+0000","flow_id":1234567890123458,"event_type":"dns","src_ip":"10.0.0.5","src_port":53000,"dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP","dns":{"type":"answer","id":42,"rrname":"example.com","rrtype":"A","rcode":"NOERROR","aa":false}}"#;

    const REAL_DNS_QUERY_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:02.000000+0000","flow_id":1234567890123458,"event_type":"dns","src_ip":"10.0.0.5","src_port":53000,"dest_ip":"1.1.1.1","dest_port":53,"proto":"UDP","dns":{"type":"query","id":42,"rrname":"example.com","rrtype":"A"}}"#;

    const REAL_HTTP_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:03.000000+0000","flow_id":1234567890123459,"event_type":"http","src_ip":"10.0.0.5","src_port":51236,"dest_ip":"203.0.113.10","dest_port":80,"proto":"TCP","http":{"hostname":"example.com","url":"/path?q=1","http_method":"GET","http_user_agent":"curl/8.0","status":200,"http_content_type":"text/html","length":1234}}"#;

    const REAL_TLS_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:04.000000+0000","flow_id":1234567890123460,"event_type":"tls","src_ip":"10.0.0.5","src_port":51237,"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP","tls":{"sni":"example.com","version":"TLS 1.3","subject":"CN=example.com","issuerdn":"CN=Let's Encrypt R3","ja3":{"hash":"66918128f1b9b03303d77c6f2eefd128","string":"771,4865-4866-4867,0-23-65281-10-11-35,29-23-24,0"}}}"#;

    const REAL_FILEINFO_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:05.000000+0000","flow_id":1234567890123461,"event_type":"fileinfo","src_ip":"203.0.113.10","src_port":80,"dest_ip":"10.0.0.5","dest_port":51238,"proto":"TCP","fileinfo":{"filename":"/payload.bin","size":4096,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","stored":true,"size_matches":true}}"#;

    const REAL_FLOW_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:06.000000+0000","flow_id":1234567890123462,"event_type":"flow","src_ip":"10.0.0.5","src_port":51239,"dest_ip":"203.0.113.10","dest_port":443,"proto":"TCP","app_proto":"tls","flow":{"pkts_toserver":50,"pkts_toclient":40,"bytes_toserver":5000,"bytes_toclient":80000,"state":"closed","reason":"timeout","start":"2024-01-15T10:30:00.000000+0000","end":"2024-01-15T10:30:06.000000+0000"}}"#;

    const UNKNOWN_LINE: &str = r#"{"timestamp":"2024-01-15T10:30:07.000000+0000","event_type":"mqtt","src_ip":"10.0.0.5","mqtt":{"client_id":"x"}}"#;

    #[test]
    fn parse_real_alert_line_decodes_full_payload() {
        let rec = EveRecord::parse_line(REAL_ALERT_LINE).expect("parse");
        match rec {
            EveRecord::Alert(a) => {
                assert_eq!(a.tuple.src_ip.as_deref(), Some("10.0.0.5"));
                assert_eq!(a.tuple.dst_ip.as_deref(), Some("203.0.113.10"));
                assert_eq!(a.tuple.dst_port, Some(80));
                assert_eq!(a.tuple.proto.as_deref(), Some("TCP"));
                assert_eq!(a.alert.signature_id, 2_001_234);
                assert_eq!(a.alert.signature, "ET MALWARE Suspicious User-Agent");
                assert_eq!(a.alert.severity, 1);
                assert_eq!(a.alert.action, "blocked");
                assert_eq!(a.alert.gid, Some(1));
                assert_eq!(a.alert.rev, 3);
            }
            other => panic!("expected Alert, got {other:?}"),
        }
    }

    #[test]
    fn alert_normalises_to_ips_event() {
        let rec = EveRecord::parse_line(REAL_ALERT_LINE).expect("parse");
        let EveRecord::Alert(a) = rec else {
            panic!("expected alert");
        };
        let ev = a.to_ips_event();
        assert_eq!(ev.rule_id, "2001234");
        assert_eq!(ev.signature, "ET MALWARE Suspicious User-Agent");
        assert_eq!(ev.severity, "critical");
        assert_eq!(ev.action, "blocked");
        assert_eq!(ev.src_ip, "10.0.0.5");
        assert_eq!(ev.dst_ip, "203.0.113.10");
        assert_eq!(ev.protocol, "tcp");
    }

    #[test]
    fn alert_severity_labels_cover_every_suricata_level() {
        // Suricata's severity scale is 1 (highest) through 4
        // (lowest); we add a defensive bucket for 0 / >4.
        assert_eq!(severity_label(1), "critical");
        assert_eq!(severity_label(2), "high");
        assert_eq!(severity_label(3), "medium");
        assert_eq!(severity_label(4), "low");
        assert_eq!(severity_label(0), "info");
        assert_eq!(severity_label(99), "info");
    }

    #[test]
    fn alert_action_defaults_when_omitted_by_suricata_5() {
        // Suricata 5.x omits the `action` field. Default to
        // `alert` so the IpsEvent normaliser doesn't crash on
        // legacy input.
        let line = REAL_ALERT_LINE.replace(r#""action":"blocked","#, "");
        let rec = EveRecord::parse_line(&line).expect("parse without action");
        let EveRecord::Alert(a) = rec else {
            panic!("expected alert");
        };
        assert_eq!(a.alert.action, "alert");
    }

    #[test]
    fn parse_real_anomaly_line() {
        let rec = EveRecord::parse_line(REAL_ANOMALY_LINE).expect("parse");
        match rec {
            EveRecord::Anomaly(a) => {
                assert_eq!(a.anomaly.event_name, "stream.pkt_invalid_ack");
                assert_eq!(a.anomaly.kind, "stream");
                assert_eq!(a.anomaly.layer.as_deref(), Some("tcp"));
            }
            other => panic!("expected Anomaly, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_dns_answer_line_then_normalise() {
        let rec = EveRecord::parse_line(REAL_DNS_ANSWER_LINE).expect("parse");
        let EveRecord::Dns(d) = rec else {
            panic!("expected dns");
        };
        assert_eq!(d.dns.kind, "answer");
        assert_eq!(d.dns.rrname, "example.com");
        let ev = d.to_dns_event().expect("answer should map");
        assert_eq!(ev.query, "example.com");
        assert_eq!(ev.qtype, "A");
        assert_eq!(ev.response_code, "NOERROR");
        assert_eq!(ev.verdict, Verdict::Allow);
    }

    #[test]
    fn dns_query_lines_do_not_emit_events() {
        let rec = EveRecord::parse_line(REAL_DNS_QUERY_LINE).expect("parse");
        let EveRecord::Dns(d) = rec else {
            panic!("expected dns");
        };
        // Suricata's `query` record alone is not an SNG event;
        // the paired `answer` is. The normaliser must signal
        // this with None rather than emitting a phantom event.
        assert!(d.to_dns_event().is_none());
    }

    #[test]
    fn dns_answer_without_rcode_defaults_to_noerror() {
        // Older Suricata versions occasionally omit `rcode` on a
        // synthesised answer record; the SNG schema requires the
        // field, so the normaliser defaults to NOERROR.
        let line = REAL_DNS_ANSWER_LINE.replace(r#""rcode":"NOERROR","#, "");
        let rec = EveRecord::parse_line(&line).expect("parse without rcode");
        let EveRecord::Dns(d) = rec else {
            panic!("expected dns");
        };
        assert_eq!(
            d.to_dns_event().expect("answer maps").response_code,
            "NOERROR"
        );
    }

    #[test]
    fn parse_real_http_line_then_normalise() {
        let rec = EveRecord::parse_line(REAL_HTTP_LINE).expect("parse");
        let EveRecord::Http(h) = rec else {
            panic!("expected http");
        };
        let ev = h.to_http_event();
        assert_eq!(ev.method, "GET");
        assert_eq!(ev.url, "/path?q=1");
        assert_eq!(ev.host, "example.com");
        assert_eq!(ev.status_code, 200);
        assert_eq!(ev.content_type.as_deref(), Some("text/html"));
        assert_eq!(ev.bytes, Some(1234));
    }

    #[test]
    fn parse_real_tls_line_extracts_sni_and_ja3() {
        let rec = EveRecord::parse_line(REAL_TLS_LINE).expect("parse");
        let EveRecord::Tls(t) = rec else {
            panic!("expected tls");
        };
        assert_eq!(t.tls.sni.as_deref(), Some("example.com"));
        assert_eq!(t.tls.version, "TLS 1.3");
        let ja3 = t.tls.ja3.expect("ja3 present");
        assert_eq!(ja3.hash, "66918128f1b9b03303d77c6f2eefd128");
        assert!(ja3.raw.starts_with("771,"));
    }

    #[test]
    fn parse_real_fileinfo_line() {
        let rec = EveRecord::parse_line(REAL_FILEINFO_LINE).expect("parse");
        let EveRecord::Fileinfo(f) = rec else {
            panic!("expected fileinfo");
        };
        assert_eq!(f.fileinfo.filename, "/payload.bin");
        assert_eq!(f.fileinfo.size, 4096);
        assert_eq!(
            f.fileinfo.sha256.as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        );
        assert!(f.fileinfo.stored);
        assert_eq!(f.fileinfo.size_matches, Some(true));
    }

    #[test]
    fn parse_real_flow_line_then_normalise() {
        let rec = EveRecord::parse_line(REAL_FLOW_LINE).expect("parse");
        let EveRecord::Flow(f) = rec else {
            panic!("expected flow");
        };
        let ev = f.to_flow_event();
        assert_eq!(ev.src_ip, "10.0.0.5");
        assert_eq!(ev.dst_ip, "203.0.113.10");
        assert_eq!(ev.dst_port, 443);
        assert_eq!(ev.protocol, "tcp");
        assert_eq!(ev.app_id.as_deref(), Some("tls"));
        // Suricata's toserver=client→server (= SNG's bytes_out);
        // toclient=server→client (= SNG's bytes_in).
        assert_eq!(ev.bytes_out, 5000);
        assert_eq!(ev.bytes_in, 80_000);
    }

    #[test]
    fn unknown_event_type_is_surfaced_not_dropped() {
        // A Suricata upgrade that adds a new event_type must
        // surface as Unknown so the supervisor can log and
        // decide whether to upgrade sng-ips. Dropping the line
        // silently would be a telemetry regression.
        let rec = EveRecord::parse_line(UNKNOWN_LINE).expect("parse");
        match rec {
            EveRecord::Unknown { event_type, raw } => {
                assert_eq!(event_type, "mqtt");
                assert!(raw.get("mqtt").is_some(), "raw payload preserved");
            }
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    #[test]
    fn flow_tuple_accessible_from_every_record_variant() {
        // Every typed variant must expose its 5-tuple so the
        // manager's fan-out path can branch on src/dst without
        // walking the variant. Unknown deliberately returns None.
        for (line, expected_dst) in [
            (REAL_ALERT_LINE, Some("203.0.113.10")),
            (REAL_ANOMALY_LINE, Some("203.0.113.10")),
            (REAL_DNS_ANSWER_LINE, Some("1.1.1.1")),
            (REAL_HTTP_LINE, Some("203.0.113.10")),
            (REAL_TLS_LINE, Some("203.0.113.10")),
            (REAL_FILEINFO_LINE, Some("10.0.0.5")),
            (REAL_FLOW_LINE, Some("203.0.113.10")),
        ] {
            let rec = EveRecord::parse_line(line).expect("parse");
            let tuple = rec.flow_tuple().expect("tuple present");
            assert_eq!(tuple.dst_ip.as_deref(), expected_dst);
        }
        let rec = EveRecord::parse_line(UNKNOWN_LINE).expect("parse");
        assert!(rec.flow_tuple().is_none(), "unknown has no tuple");
    }

    #[test]
    fn parse_rejects_invalid_json() {
        let err = EveRecord::parse_line("{not json").expect_err("must reject");
        assert!(matches!(err, IpsError::EveDecode(_)));
    }

    #[test]
    fn parse_rejects_missing_event_type() {
        let err = EveRecord::parse_line(r#"{"timestamp":"x"}"#).expect_err("must reject");
        assert!(matches!(err, IpsError::EveDecode(_)));
    }

    #[test]
    fn flow_tuple_normalises_protocol_to_lowercase_with_other_default() {
        let mut t = FlowTuple {
            timestamp: None,
            flow_id: None,
            src_ip: None,
            src_port: None,
            dst_ip: None,
            dst_port: None,
            proto: Some("TCP".into()),
            app_proto: None,
        };
        assert_eq!(t.normalised_protocol(), "tcp");
        t.proto = Some("UDP".into());
        assert_eq!(t.normalised_protocol(), "udp");
        t.proto = None;
        assert_eq!(t.normalised_protocol(), "other");
    }
}

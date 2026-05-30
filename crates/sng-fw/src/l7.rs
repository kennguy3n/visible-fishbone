//! Layer-7 application identification.
//!
//! Once the L3 / L4 firewall has decided a packet is interesting
//! enough to inspect (`RuleAction::Inspect`), the L7 module runs
//! cheap byte-pattern probes on the first packet's payload to
//! classify the application protocol. Identification is wire-
//! based, not port-based — we recognise HTTP on port 8081 and
//! flag plaintext on port 443 as anomalies.
//!
//! Supported protocols (the closed set):
//!
//! * `Http` — request lines starting with one of the
//!   RFC 7231 §4 verbs (`GET`, `POST`, `PUT`, `DELETE`, `HEAD`,
//!   `OPTIONS`, `PATCH`, `CONNECT`, `TRACE`).
//! * `Tls` — first 5 bytes are a TLS record header (content type
//!   `0x16` handshake, version `0x0301..=0x0304`).
//! * `Dns` — UDP payload conforming to RFC 1035 §4.1.1 header
//!   (12-byte header with sensible field values).
//! * `Quic` — first byte has the long-header bit set and the
//!   QUIC version field matches IETF QUIC v1 (`0x00000001`).
//! * `Ssh` — banner starts with `SSH-2.0` or `SSH-1.99`.
//! * `Rdp` — TPKT header (`0x03 0x00 ...`) wrapping an X.224
//!   connection request.
//! * `Smb` — first 4 bytes are the SMB1 magic `\xffSMB` or the
//!   SMB2/3 magic `\xfeSMB`.
//!
//! The identifier is **stateless** — it works on the first
//! packet of a flow and returns "unknown" if the payload is
//! ambiguous. The integration test exercises real-world packet
//! captures.
//!
//! TLS SNI extraction parses the ClientHello extensions and
//! returns the first `server_name` of type `host_name`
//! (RFC 6066 §3). Failed parses surface the underlying error
//! shape so the operator can tell "no SNI" from "malformed
//! payload".

use serde::{Deserialize, Serialize};

use sng_core::traffic_class::TrafficClass;

use crate::error::FirewallError;

/// The closed set of protocols this identifier recognises. New
/// protocols are added here and to [`AppIdentifier::identify`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L7Protocol {
    /// Plain HTTP request.
    Http,
    /// TLS (any record type — usually handshake).
    Tls,
    /// DNS query / response (UDP payload).
    Dns,
    /// IETF QUIC v1.
    Quic,
    /// SSH-2 / SSH-1.99 banner.
    Ssh,
    /// RDP (TPKT-wrapped X.224).
    Rdp,
    /// SMB1 / SMB2 / SMB3.
    Smb,
    /// First packet is too short or doesn't match any known
    /// signature.
    Unknown,
}

impl L7Protocol {
    /// Canonical lowercase wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Dns => "dns",
            Self::Quic => "quic",
            Self::Ssh => "ssh",
            Self::Rdp => "rdp",
            Self::Smb => "smb",
            Self::Unknown => "unknown",
        }
    }
}

/// Stateless first-packet identifier. Constructed once and
/// reused across flows.
#[derive(Clone, Debug, Default)]
pub struct AppIdentifier;

impl AppIdentifier {
    /// New default identifier.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Identify the protocol of the supplied first-packet
    /// payload. Returns [`L7Protocol::Unknown`] when no
    /// signature matches.
    #[must_use]
    pub fn identify(&self, payload: &[u8]) -> L7Protocol {
        if payload.is_empty() {
            return L7Protocol::Unknown;
        }
        if SignatureScanner::is_tls(payload) {
            return L7Protocol::Tls;
        }
        if SignatureScanner::is_http(payload) {
            return L7Protocol::Http;
        }
        if SignatureScanner::is_ssh(payload) {
            return L7Protocol::Ssh;
        }
        if SignatureScanner::is_smb(payload) {
            return L7Protocol::Smb;
        }
        if SignatureScanner::is_rdp(payload) {
            return L7Protocol::Rdp;
        }
        if SignatureScanner::is_quic(payload) {
            return L7Protocol::Quic;
        }
        if SignatureScanner::is_dns(payload) {
            return L7Protocol::Dns;
        }
        L7Protocol::Unknown
    }
}

/// Standalone byte-pattern checks. Exposed as static functions
/// so callers that already know the protocol (e.g. a fully-
/// decrypted HTTPS flow) can skip the wider dispatch.
#[derive(Debug)]
pub struct SignatureScanner;

impl SignatureScanner {
    /// TLS record header: first byte is a content type
    /// (`0x14` ChangeCipherSpec .. `0x17` ApplicationData), next
    /// two bytes are a TLS version (`0x0301` TLS1.0 ..
    /// `0x0304` TLS1.3), next two bytes are the record length.
    #[must_use]
    pub fn is_tls(payload: &[u8]) -> bool {
        if payload.len() < 5 {
            return false;
        }
        let content_type = payload[0];
        let version_major = payload[1];
        let version_minor = payload[2];
        let record_len = u16::from_be_bytes([payload[3], payload[4]]);
        // ContentType range from RFC 8446 §B.1.
        if !(0x14..=0x18).contains(&content_type) {
            return false;
        }
        if version_major != 0x03 {
            return false;
        }
        if !(0x00..=0x04).contains(&version_minor) {
            return false;
        }
        // TLS records are at most 2^14 + 2^11 = 18 432 bytes
        // (RFC 8446 §5.1) — but a 0-length record is also
        // valid (CCS subprotocol). Reject obviously-corrupt
        // lengths.
        record_len <= 18_432
    }

    /// HTTP request line: optional whitespace, then one of the
    /// RFC 7231 verbs followed by a space.
    #[must_use]
    pub fn is_http(payload: &[u8]) -> bool {
        // Method tokens we care about — must match the start of
        // the payload. CONNECT is the longest at 7 bytes.
        const METHODS: &[&[u8]] = &[
            b"GET ",
            b"POST ",
            b"PUT ",
            b"HEAD ",
            b"DELETE ",
            b"OPTIONS ",
            b"PATCH ",
            b"CONNECT ",
            b"TRACE ",
        ];
        METHODS.iter().any(|m| payload.starts_with(m))
    }

    /// SSH-2 banner.
    #[must_use]
    pub fn is_ssh(payload: &[u8]) -> bool {
        payload.starts_with(b"SSH-2.0") || payload.starts_with(b"SSH-1.99")
    }

    /// SMB1 or SMB2/3 magic.
    #[must_use]
    pub fn is_smb(payload: &[u8]) -> bool {
        if payload.len() < 4 {
            return false;
        }
        // SMB1: 0xff 'S' 'M' 'B'
        if payload[0..4] == [0xFF, b'S', b'M', b'B'] {
            return true;
        }
        // SMB2/3: 0xfe 'S' 'M' 'B'
        if payload[0..4] == [0xFE, b'S', b'M', b'B'] {
            return true;
        }
        false
    }

    /// RDP TPKT header wrapping an X.224 connection request.
    #[must_use]
    pub fn is_rdp(payload: &[u8]) -> bool {
        if payload.len() < 7 {
            return false;
        }
        // TPKT: version=0x03, reserved=0x00, length (big-endian).
        if payload[0] != 0x03 || payload[1] != 0x00 {
            return false;
        }
        // X.224 length indicator at byte 4, then the COTP PDU
        // type at byte 5 (CR is 0xE0).
        payload[5] == 0xE0
    }

    /// IETF QUIC v1 long-header packet. Long-header bit is the
    /// most significant bit of the first byte; the version field
    /// is bytes 1..=4.
    #[must_use]
    pub fn is_quic(payload: &[u8]) -> bool {
        if payload.len() < 5 {
            return false;
        }
        let has_long_header = payload[0] & 0x80 != 0;
        if !has_long_header {
            return false;
        }
        // Fixed-bit (second-MSB) is 1 on every QUIC long-header
        // packet (RFC 9000 §17.2).
        if payload[0] & 0x40 == 0 {
            return false;
        }
        let version = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        // QUIC v1 = 0x00000001. Version-negotiation packets
        // carry 0x00000000; accept both as QUIC.
        version == 0x0000_0001 || version == 0x0000_0000
    }

    /// DNS query / response header check (RFC 1035 §4.1.1).
    #[must_use]
    pub fn is_dns(payload: &[u8]) -> bool {
        if payload.len() < 12 {
            return false;
        }
        // Header is 12 bytes: id, flags (2), qd/an/ns/ar counts.
        // Validate the (still-reserved) Z bit is zero and the
        // opcode is one of the assigned values.
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let opcode = (flags >> 11) & 0x0F;
        // RFC 1035 §4.1.1 originally defined Z as a 3-bit
        // reserved field (bits 6–4 of the low byte). RFC 2535 /
        // RFC 4035 reallocated two of those bits as AD
        // (Authenticated Data) and CD (Checking Disabled) for
        // DNSSEC, leaving a single reserved bit at position 6.
        // Rejecting traffic where AD or CD is set would block
        // legitimate DNSSEC resolvers, so we only enforce that
        // the lone remaining reserved bit is zero.
        let z_reserved = (flags >> 6) & 0x01;
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if z_reserved != 0 {
            return false;
        }
        // Opcodes 0 (QUERY), 1 (IQUERY), 2 (STATUS), 4 (NOTIFY),
        // 5 (UPDATE) are RFC-assigned; anything else is suspect.
        if ![0, 1, 2, 4, 5].contains(&opcode) {
            return false;
        }
        // Almost every DNS query carries at least one question.
        qdcount > 0
    }
}

/// SNI extractor for TLS ClientHello. Returns the first
/// `host_name` extension value, or `None` if no SNI is present.
/// Returns [`FirewallError::L7Parse`] on a malformed
/// ClientHello (truncated, wrong handshake type, length
/// inconsistency).
#[derive(Debug, Default)]
pub struct SniExtractor;

impl SniExtractor {
    /// Construct an extractor. Stateless — reuse across flows.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Parse the supplied first record and return the SNI host.
    pub fn extract(&self, payload: &[u8]) -> Result<Option<String>, FirewallError> {
        // 5-byte TLS record header.
        if payload.len() < 5 {
            return Err(FirewallError::L7Parse("tls record header truncated".into()));
        }
        if payload[0] != 0x16 {
            return Err(FirewallError::L7Parse(
                "expected handshake record (content type 0x16)".into(),
            ));
        }
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;
        if 5 + record_len > payload.len() {
            return Err(FirewallError::L7Parse(format!(
                "tls record length {record_len} exceeds payload"
            )));
        }
        let body = &payload[5..5 + record_len];
        // Handshake header: type (1), length (3).
        if body.len() < 4 {
            return Err(FirewallError::L7Parse("handshake header truncated".into()));
        }
        if body[0] != 0x01 {
            return Err(FirewallError::L7Parse(
                "expected ClientHello (handshake type 0x01)".into(),
            ));
        }
        let hs_len = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | (body[3] as usize);
        if 4 + hs_len > body.len() {
            return Err(FirewallError::L7Parse(format!(
                "handshake length {hs_len} exceeds record body"
            )));
        }
        let hello = &body[4..4 + hs_len];
        // ClientHello fixed prefix: client_version (2), random
        // (32), session_id_length (1).
        if hello.len() < 35 {
            return Err(FirewallError::L7Parse("client hello truncated".into()));
        }
        let session_id_len = hello[34] as usize;
        let mut cursor = 35 + session_id_len;
        if hello.len() < cursor + 2 {
            return Err(FirewallError::L7Parse(
                "client hello session id length exceeds payload".into(),
            ));
        }
        let cipher_suites_len = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
        cursor += 2 + cipher_suites_len;
        if hello.len() < cursor + 1 {
            return Err(FirewallError::L7Parse(
                "client hello cipher suites length exceeds payload".into(),
            ));
        }
        let compression_len = hello[cursor] as usize;
        cursor += 1 + compression_len;
        if hello.len() < cursor + 2 {
            // No extensions block — legal but no SNI possible.
            return Ok(None);
        }
        let ext_total = u16::from_be_bytes([hello[cursor], hello[cursor + 1]]) as usize;
        cursor += 2;
        if hello.len() < cursor + ext_total {
            return Err(FirewallError::L7Parse(format!(
                "client hello extensions length {ext_total} exceeds payload"
            )));
        }
        let mut ext_cursor = cursor;
        let ext_end = cursor + ext_total;
        while ext_cursor + 4 <= ext_end {
            let ext_type = u16::from_be_bytes([hello[ext_cursor], hello[ext_cursor + 1]]);
            let ext_len =
                u16::from_be_bytes([hello[ext_cursor + 2], hello[ext_cursor + 3]]) as usize;
            ext_cursor += 4;
            if ext_cursor + ext_len > ext_end {
                return Err(FirewallError::L7Parse(format!(
                    "extension {ext_type} length {ext_len} exceeds extensions block"
                )));
            }
            // SNI = ext type 0x0000.
            if ext_type == 0 {
                return parse_sni_extension(&hello[ext_cursor..ext_cursor + ext_len]);
            }
            ext_cursor += ext_len;
        }
        Ok(None)
    }
}

fn parse_sni_extension(data: &[u8]) -> Result<Option<String>, FirewallError> {
    // ServerNameList: total length (2), then a sequence of
    // ServerName entries (name_type (1), name_length (2), name).
    if data.len() < 2 {
        return Err(FirewallError::L7Parse("sni extension truncated".into()));
    }
    let total = u16::from_be_bytes([data[0], data[1]]) as usize;
    if 2 + total > data.len() {
        return Err(FirewallError::L7Parse(format!(
            "sni extension length {total} exceeds payload"
        )));
    }
    let mut cursor = 2;
    while cursor + 3 <= 2 + total {
        let name_type = data[cursor];
        let name_len = u16::from_be_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
        cursor += 3;
        if cursor + name_len > 2 + total {
            return Err(FirewallError::L7Parse(format!(
                "sni name length {name_len} exceeds extension"
            )));
        }
        // host_name = type 0 (RFC 6066 §3). We accept the first
        // host_name and ignore other name types per the RFC's
        // "the server SHOULD select the first server_name".
        if name_type == 0 {
            let name = std::str::from_utf8(&data[cursor..cursor + name_len])
                .map_err(|_| FirewallError::L7Parse("sni host_name not valid utf-8".into()))?;
            return Ok(Some(name.to_ascii_lowercase()));
        }
        cursor += name_len;
    }
    Ok(None)
}

/// HTTP host / URI predicate.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpMatch {
    /// Required `Host` header value (exact match, case-
    /// insensitive). Empty means "any host".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub host: String,
    /// URI path prefix (case-sensitive). Empty means "any path".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub path_prefix: String,
    /// HTTP method (uppercase). Empty means "any method".
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
}

impl HttpMatch {
    /// Test whether the supplied first-packet payload represents
    /// an HTTP request matching this predicate.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        let Some(request_line_end) = payload.iter().position(|b| *b == b'\n') else {
            return false;
        };
        let request_line = match std::str::from_utf8(&payload[..request_line_end]) {
            Ok(s) => s.trim_end_matches('\r'),
            Err(_) => return false,
        };
        let mut parts = request_line.splitn(3, ' ');
        let (Some(method), Some(path)) = (parts.next(), parts.next()) else {
            return false;
        };
        if !self.method.is_empty() && !self.method.eq_ignore_ascii_case(method) {
            return false;
        }
        if !self.path_prefix.is_empty() && !path.starts_with(&self.path_prefix) {
            return false;
        }
        if !self.host.is_empty() {
            // Walk the header block for a Host header.
            let header_block = &payload[request_line_end + 1..];
            let Ok(header_text) = std::str::from_utf8(header_block) else {
                return false;
            };
            let host_value = header_text
                .lines()
                .map_while(|l| if l.is_empty() { None } else { Some(l) })
                .find_map(|l| {
                    let mut split = l.splitn(2, ':');
                    let name = split.next()?.trim();
                    let val = split.next()?.trim();
                    if name.eq_ignore_ascii_case("host") {
                        Some(val.to_ascii_lowercase())
                    } else {
                        None
                    }
                });
            let Some(hv) = host_value else { return false };
            if !hv.eq_ignore_ascii_case(&self.host) {
                return false;
            }
        }
        true
    }
}

/// L7 match — either a `host`-style predicate on an HTTP flow,
/// a `sni`-style match on a TLS flow, or the protocol identity
/// itself.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum L7Match {
    /// Match by raw protocol identity.
    Protocol {
        /// The expected protocol.
        protocol: L7Protocol,
    },
    /// Match against the TLS SNI host (case-insensitive, dot-
    /// suffix semantics — `*.example.com` matches
    /// `mail.example.com`).
    SniSuffix {
        /// The suffix value, with or without a leading `*.`.
        suffix: String,
    },
    /// Match against the HTTP request line + Host header.
    Http(HttpMatch),
}

impl L7Match {
    /// Evaluate the predicate against the supplied first-packet
    /// payload.
    #[must_use]
    pub fn matches(&self, payload: &[u8]) -> bool {
        match self {
            Self::Protocol { protocol } => AppIdentifier::new().identify(payload) == *protocol,
            Self::SniSuffix { suffix } => {
                let extractor = SniExtractor::new();
                match extractor.extract(payload) {
                    Ok(Some(sni)) => sni_suffix_match(suffix, &sni),
                    _ => false,
                }
            }
            Self::Http(h) => h.matches(payload),
        }
    }
}

/// SNI suffix matcher used by the SWG bypass list.
///
/// **Intentionally diverges from RFC 6125 §6.4 / from
/// `sng_policy_eval::matcher::domain_suffix_match`**: the
/// PKI matcher is for subject-name verification, where only
/// a single-label subdomain may match the wildcard and the
/// apex is *excluded*. This matcher is for an operator-written
/// SNI bypass list — `*.bank.com` is meant to express "bypass
/// TLS interception for anything under bank.com, including the
/// apex itself and any depth of subdomain". Using strict RFC
/// 6125 semantics here would silently let `bank.com` (the
/// apex) hit the inspection path, defeating the purpose of
/// listing it.
///
/// Keep this divergence greppable from either side: search
/// `domain_suffix_match` (the PKI flavor) vs `sni_suffix_match`
/// (the bypass-list flavor).
///
/// Re-exported as a `pub` symbol because `sng-swg`'s TLS bypass
/// evaluator must use the *same* matcher as the firewall's L7
/// classifier — having two implementations of "permissive SNI
/// match" in the same workspace would let an operator-curated
/// bypass list match in one subsystem but miss in the other.
pub fn sni_suffix_match(suffix: &str, value: &str) -> bool {
    let suffix = suffix.strip_prefix("*.").unwrap_or(suffix);
    if suffix.is_empty() || value.is_empty() {
        return false;
    }
    let v = value.to_ascii_lowercase();
    let s = suffix.to_ascii_lowercase();
    if v == s {
        // Exact match — accept the apex.
        return true;
    }
    if let Some(prefix) = v.strip_suffix(&s) {
        prefix.ends_with('.')
    } else {
        false
    }
}

/// App identifier — a stable string used by the policy compiler
/// to label flows for the SWG / IPS / steering subsystems.
/// Constructed as `protocol/service` (e.g. `tls/microsoft.teams`,
/// `dns/google.dns`).
pub type AppId = String;

/// Map an [`L7Protocol`] + optional host hint to a default
/// [`TrafficClass`]. Used by the engine when the policy bundle
/// hasn't shipped a specific app-class mapping. The defaults
/// match ARCHITECTURE.md §4.4a:
///
/// * media-class L4 (RTP / SRTP on UDP, QUIC) → `INSPECT_LITE`
/// * TLS / HTTP without a sensitive-host hit → `INSPECT_FULL`
/// * DNS → `INSPECT_LITE` (DNS-only flows are metadata-only)
/// * SSH / RDP / SMB → `INSPECT_FULL` (admin protocols)
#[must_use]
pub fn default_traffic_class(proto: L7Protocol) -> TrafficClass {
    match proto {
        L7Protocol::Quic | L7Protocol::Dns => TrafficClass::InspectLite,
        // TLS / HTTP carry user content the SWG needs to scan;
        // SSH / RDP / SMB are admin protocols the IDS hooks
        // into. All five collapse to `INSPECT_FULL` today —
        // separated logically for readability so a future
        // policy split (e.g. SSH gets its own class) only
        // touches one arm.
        L7Protocol::Tls
        | L7Protocol::Http
        | L7Protocol::Ssh
        | L7Protocol::Rdp
        | L7Protocol::Smb => TrafficClass::InspectFull,
        L7Protocol::Unknown => TrafficClass::Block,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn tls_client_hello_with_sni(host: &str) -> Vec<u8> {
        // Hand-crafted minimal TLS 1.2 ClientHello with one SNI
        // extension. Layout:
        //   record: 0x16 0x03 0x01 LEN(2)
        //   handshake: 0x01 LEN(3)
        //   client_hello body
        let mut hello = Vec::<u8>::new();
        // client_version
        hello.extend_from_slice(&[0x03, 0x03]);
        // random (32 bytes, zeros for the test)
        hello.extend_from_slice(&[0u8; 32]);
        // session_id_length = 0
        hello.push(0);
        // cipher_suites_length = 2, one cipher
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]);
        // compression_methods_length = 1, null
        hello.extend_from_slice(&[0x01, 0x00]);
        // extensions length placeholder
        let ext_offset = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        let ext_start = hello.len();
        // SNI extension
        hello.extend_from_slice(&[0x00, 0x00]); // ext type 0 (SNI)
        let sni_len_offset = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]); // ext length placeholder
        let sni_data_start = hello.len();
        // ServerNameList length placeholder
        hello.extend_from_slice(&[0x00, 0x00]);
        // ServerName: type=0 host_name, length=N, name bytes.
        hello.push(0x00);
        let name_bytes = host.as_bytes();
        hello.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        hello.extend_from_slice(name_bytes);
        let sni_data_end = hello.len();
        // Patch ServerNameList length (excludes the 2-byte length itself).
        let server_name_list_len = (sni_data_end - sni_data_start - 2) as u16;
        let bytes = server_name_list_len.to_be_bytes();
        hello[sni_data_start] = bytes[0];
        hello[sni_data_start + 1] = bytes[1];
        // Patch SNI extension length.
        let sni_total_len = (sni_data_end - sni_data_start) as u16;
        let bytes = sni_total_len.to_be_bytes();
        hello[sni_len_offset] = bytes[0];
        hello[sni_len_offset + 1] = bytes[1];
        // Patch extensions block length.
        let ext_total = (hello.len() - ext_start) as u16;
        let bytes = ext_total.to_be_bytes();
        hello[ext_offset] = bytes[0];
        hello[ext_offset + 1] = bytes[1];
        // Wrap in handshake + record headers.
        let hs_len = hello.len() as u32;
        let mut handshake = Vec::<u8>::with_capacity(4 + hello.len());
        handshake.push(0x01);
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&hello);
        let mut record = Vec::<u8>::with_capacity(5 + handshake.len());
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn identify_recognises_http_request_line() {
        let id = AppIdentifier::new();
        assert_eq!(id.identify(b"GET / HTTP/1.1\r\n\r\n"), L7Protocol::Http);
        assert_eq!(id.identify(b"POST /api HTTP/1.1\r\n\r\n"), L7Protocol::Http);
        assert_eq!(
            id.identify(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
            L7Protocol::Http
        );
    }

    #[test]
    fn identify_recognises_tls_handshake() {
        let id = AppIdentifier::new();
        // Minimal handshake record header: 0x16 0x03 0x01 length(2).
        let mut p = vec![0x16, 0x03, 0x01, 0x00, 0x10];
        p.extend_from_slice(&[0u8; 16]);
        assert_eq!(id.identify(&p), L7Protocol::Tls);
    }

    #[test]
    fn identify_recognises_ssh_banner() {
        let id = AppIdentifier::new();
        assert_eq!(id.identify(b"SSH-2.0-OpenSSH_9\r\n"), L7Protocol::Ssh);
        assert_eq!(id.identify(b"SSH-1.99-OpenSSH_3\r\n"), L7Protocol::Ssh);
    }

    #[test]
    fn identify_recognises_smb_magic() {
        let id = AppIdentifier::new();
        let mut p = vec![0xFF, b'S', b'M', b'B'];
        p.extend_from_slice(&[0u8; 28]);
        assert_eq!(id.identify(&p), L7Protocol::Smb);
        let mut p = vec![0xFE, b'S', b'M', b'B'];
        p.extend_from_slice(&[0u8; 28]);
        assert_eq!(id.identify(&p), L7Protocol::Smb);
    }

    #[test]
    fn identify_recognises_rdp_tpkt() {
        let id = AppIdentifier::new();
        // TPKT header + COTP CR.
        let p = [0x03, 0x00, 0x00, 0x2C, 0x22, 0xE0, 0x00];
        assert_eq!(id.identify(&p), L7Protocol::Rdp);
    }

    #[test]
    fn identify_recognises_quic_v1_long_header() {
        let id = AppIdentifier::new();
        // First byte: long header (0x80) + fixed bit (0x40) +
        // initial type. Then 0x00000001 version.
        let p = [0xC0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
        assert_eq!(id.identify(&p), L7Protocol::Quic);
    }

    #[test]
    fn identify_recognises_dns_query() {
        let id = AppIdentifier::new();
        // id=0x1234, flags=0x0100 (standard query), qd=1.
        let p = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(id.identify(&p), L7Protocol::Dns);
    }

    #[test]
    fn identify_recognises_dnssec_query_with_ad_and_cd_flags() {
        // Resolvers that speak DNSSEC set AD (bit 5 of the low
        // byte) on responses they authenticated, and CD (bit 4)
        // on outbound queries to disable downstream validation.
        // Both must be accepted as DNS.
        let id = AppIdentifier::new();
        // flags = 0x0130: RD=1 (bit 8) | AD=1 (bit 5) | CD=1 (bit 4)
        let ad_and_cd = [
            0x12, 0x34, 0x01, 0x30, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(id.identify(&ad_and_cd), L7Protocol::Dns);
        // Just AD, simulating a validated response.
        // flags = 0x8120: QR=1 | RD=1 | AD=1
        let just_ad = [
            0x12, 0x34, 0x81, 0x20, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(id.identify(&just_ad), L7Protocol::Dns);
    }

    #[test]
    fn identify_rejects_dns_with_reserved_z_bit_set() {
        // The single reserved Z bit at position 6 of the low byte
        // must still be zero per RFC 4035; anything else looks
        // malformed.
        let id = AppIdentifier::new();
        // flags = 0x0140: RD=1 | Z=1 (bit 6 of low byte)
        let z_set = [
            0x12, 0x34, 0x01, 0x40, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(id.identify(&z_set), L7Protocol::Unknown);
    }

    #[test]
    fn identify_returns_unknown_for_empty_and_garbage() {
        let id = AppIdentifier::new();
        assert_eq!(id.identify(&[]), L7Protocol::Unknown);
        assert_eq!(id.identify(b"abc"), L7Protocol::Unknown);
        assert_eq!(
            id.identify(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            L7Protocol::Unknown
        );
    }

    #[test]
    fn sni_extractor_returns_host_name() {
        let payload = tls_client_hello_with_sni("mail.example.com");
        let sni = SniExtractor::new().extract(&payload).unwrap();
        assert_eq!(sni, Some("mail.example.com".into()));
    }

    #[test]
    fn sni_extractor_returns_none_for_no_extensions() {
        // Build a minimal ClientHello with no extensions block.
        let mut hello = Vec::<u8>::new();
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]);
        hello.extend_from_slice(&[0x01, 0x00]);
        let hs_len = hello.len() as u32;
        let mut handshake = Vec::<u8>::with_capacity(4 + hello.len());
        handshake.push(0x01);
        handshake.push(((hs_len >> 16) & 0xFF) as u8);
        handshake.push(((hs_len >> 8) & 0xFF) as u8);
        handshake.push((hs_len & 0xFF) as u8);
        handshake.extend_from_slice(&hello);
        let mut record = Vec::<u8>::with_capacity(5 + handshake.len());
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        assert_eq!(SniExtractor::new().extract(&record).unwrap(), None);
    }

    #[test]
    fn sni_extractor_rejects_non_tls_record() {
        let p = vec![0x17, 0x03, 0x01, 0x00, 0x00];
        assert!(matches!(
            SniExtractor::new().extract(&p),
            Err(FirewallError::L7Parse(_))
        ));
    }

    #[test]
    fn sni_extractor_rejects_truncated_payload() {
        let p = vec![0x16, 0x03];
        assert!(matches!(
            SniExtractor::new().extract(&p),
            Err(FirewallError::L7Parse(_))
        ));
    }

    #[test]
    fn http_match_filters_method_and_path_and_host() {
        let h = HttpMatch {
            host: "example.com".into(),
            path_prefix: "/api".into(),
            method: "GET".into(),
        };
        let req = b"GET /api/v1/foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(h.matches(req));
        // Different method.
        let req = b"POST /api/v1/foo HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!h.matches(req));
        // Different host.
        let req = b"GET /api/v1/foo HTTP/1.1\r\nHost: other.com\r\n\r\n";
        assert!(!h.matches(req));
        // Different path prefix.
        let req = b"GET /other HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(!h.matches(req));
    }

    #[test]
    fn l7_match_protocol_dispatches_through_identifier() {
        let m = L7Match::Protocol {
            protocol: L7Protocol::Http,
        };
        assert!(m.matches(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!m.matches(b"SSH-2.0-OpenSSH\r\n"));
    }

    #[test]
    fn l7_match_sni_suffix_matches_subdomain_and_apex() {
        let payload = tls_client_hello_with_sni("mail.example.com");
        let m = L7Match::SniSuffix {
            suffix: "*.example.com".into(),
        };
        assert!(m.matches(&payload));
        // SNI bypass lists use permissive matching — the apex
        // (`example.com`) also matches `*.example.com` because
        // operators expect "bypass example.com" to also bypass
        // `www.example.com` and the apex.
        let apex_payload = tls_client_hello_with_sni("example.com");
        assert!(m.matches(&apex_payload));
    }

    #[test]
    fn default_traffic_class_for_each_protocol() {
        assert_eq!(
            default_traffic_class(L7Protocol::Quic),
            TrafficClass::InspectLite
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Dns),
            TrafficClass::InspectLite
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Tls),
            TrafficClass::InspectFull
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Http),
            TrafficClass::InspectFull
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Ssh),
            TrafficClass::InspectFull
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Rdp),
            TrafficClass::InspectFull
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Smb),
            TrafficClass::InspectFull
        );
        assert_eq!(
            default_traffic_class(L7Protocol::Unknown),
            TrafficClass::Block
        );
    }

    #[test]
    fn l7_protocol_strings_are_canonical() {
        assert_eq!(L7Protocol::Http.as_str(), "http");
        assert_eq!(L7Protocol::Tls.as_str(), "tls");
        assert_eq!(L7Protocol::Dns.as_str(), "dns");
        assert_eq!(L7Protocol::Quic.as_str(), "quic");
        assert_eq!(L7Protocol::Ssh.as_str(), "ssh");
        assert_eq!(L7Protocol::Rdp.as_str(), "rdp");
        assert_eq!(L7Protocol::Smb.as_str(), "smb");
        assert_eq!(L7Protocol::Unknown.as_str(), "unknown");
    }
}

//! Application identification.
//!
//! The firewall identifies the upper-layer application
//! sitting on top of a flow's L4 in two stages, in order:
//!
//! 1. **Port heuristic** ([`PortHeuristicResolver`]): a cheap
//!    L4-port lookup that pins a flow to a canonical app id
//!    for the well-known IANA ports (53 = DNS, 80 = HTTP,
//!    443 = HTTPS, 22 = SSH, …). The result is provisional —
//!    a flow on port 443 is *probably* HTTPS but could be
//!    QUIC-over-443 or some bespoke protocol.
//! 2. **L7 sniff** ([`SniExtractor`] + [`AppIdResolver::refine`]):
//!    once the firewall has the first packet payload, an
//!    L7 sniff confirms or refines the app id. For TLS, we
//!    extract the SNI from the ClientHello and stamp it
//!    onto the flow's [`AppId::Tls`] variant.
//!
//! The two stages are wired together in
//! [`AppIdResolver::resolve`]: the caller hands it
//! `(FlowKey, payload_bytes)` and gets a single [`AppId`]
//! back. If `payload_bytes` is empty (the firewall has only
//! seen the IP/L4 header — typical for the very first packet
//! of a TCP flow before any data arrives), the resolver
//! falls back to the port heuristic.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::error::FwError;
use crate::flow::{FlowKey, IpProtocol};

/// Canonical application identification.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppId {
    /// DNS — typically UDP/53 or TCP/53, sometimes 853 (DoT).
    Dns,
    /// HTTP (cleartext) — typically TCP/80 or TCP/8080.
    Http,
    /// HTTPS — typically TCP/443. Carries the SNI when an L7
    /// sniff has been done; `None` means we know it's HTTPS
    /// but the ClientHello didn't include an SNI extension
    /// (or sniff hasn't happened yet).
    Tls {
        /// SNI as advertised in the TLS ClientHello, lower-cased
        /// at extraction time. Stored owned to avoid borrowing
        /// from a transient packet buffer.
        sni: Option<String>,
    },
    /// QUIC — UDP/443 with the first byte's long-header bit set.
    Quic,
    /// SSH — typically TCP/22 with "SSH-" magic in the first bytes.
    Ssh,
    /// SMTP / SMTPS / submission — 25/465/587. Distinguished
    /// from HTTP by port; not currently sniff-refined.
    Smtp,
    /// NTP — typically UDP/123.
    Ntp,
    /// SMB — TCP/445 (Windows file sharing). Surfaced because
    /// SMB-over-internet is one of the bigger policy red
    /// flags an SNG can catch.
    Smb,
    /// The protocol couldn't be identified by port or by sniff.
    /// Caller should treat the flow as "default deny" or "default
    /// log" per its policy posture.
    Unknown,
}

impl AppId {
    /// Short text-form used in [`FlowEvent::app_id`] and policy
    /// rules. Stable wire form — downstream consumers
    /// (ClickHouse columns, NATS subjects) index on this.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Dns => "dns",
            Self::Http => "http",
            Self::Tls { .. } => "tls",
            Self::Quic => "quic",
            Self::Ssh => "ssh",
            Self::Smtp => "smtp",
            Self::Ntp => "ntp",
            Self::Smb => "smb",
            Self::Unknown => "unknown",
        }
    }

    /// SNI surface when the variant is [`AppId::Tls`].
    /// Returns `None` for any other variant or when the
    /// SNI was absent from the ClientHello.
    #[must_use]
    pub fn sni(&self) -> Option<&str> {
        match self {
            Self::Tls { sni } => sni.as_deref(),
            _ => None,
        }
    }
}

impl fmt::Display for AppId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Cheap port-based app classifier. The map is wired at
/// construction time so callers can extend the table for
/// site-specific apps without forking the crate.
#[derive(Clone, Debug)]
pub struct PortHeuristicResolver {
    /// (protocol, port) → app id. Stored as a flat `Vec` so the
    /// lookup is a small linear scan; the table is short
    /// (the well-known ports we care about fit in a few dozen
    /// entries) and the cost is dominated by cache footprint,
    /// where Vec wins over HashMap.
    table: Vec<(IpProtocol, u16, AppId)>,
}

impl Default for PortHeuristicResolver {
    fn default() -> Self {
        Self::with_well_known()
    }
}

impl PortHeuristicResolver {
    /// Construct a resolver pre-populated with the IANA
    /// well-known port assignments the agent / edge cares
    /// about. Operators can build a custom table via
    /// [`Self::empty`] + [`Self::insert`] if a deployment
    /// uses non-standard ports.
    #[must_use]
    pub fn with_well_known() -> Self {
        let table = vec![
            (IpProtocol::Tcp, 22, AppId::Ssh),
            (IpProtocol::Tcp, 25, AppId::Smtp),
            (IpProtocol::Tcp, 53, AppId::Dns),
            (IpProtocol::Udp, 53, AppId::Dns),
            (IpProtocol::Tcp, 80, AppId::Http),
            (IpProtocol::Tcp, 8080, AppId::Http),
            (IpProtocol::Udp, 123, AppId::Ntp),
            (IpProtocol::Tcp, 443, AppId::Tls { sni: None }),
            (IpProtocol::Udp, 443, AppId::Quic),
            (IpProtocol::Tcp, 445, AppId::Smb),
            (IpProtocol::Tcp, 465, AppId::Smtp),
            (IpProtocol::Tcp, 587, AppId::Smtp),
            (IpProtocol::Tcp, 853, AppId::Dns),
            (IpProtocol::Udp, 853, AppId::Dns),
        ];
        Self { table }
    }

    /// Construct an empty resolver. Useful for tests that
    /// want to exercise the lookup miss path.
    #[must_use]
    pub fn empty() -> Self {
        Self { table: Vec::new() }
    }

    /// Insert a (protocol, port → app id) binding. Replaces
    /// any prior entry for the same (protocol, port).
    pub fn insert(&mut self, protocol: IpProtocol, port: u16, app: AppId) {
        if let Some(slot) = self
            .table
            .iter_mut()
            .find(|(p, port_in, _)| *p == protocol && *port_in == port)
        {
            slot.2 = app;
        } else {
            self.table.push((protocol, port, app));
        }
    }

    /// Look up the app id for a flow based on its destination
    /// port. We always key on the *destination* port because
    /// the originator's source port is almost always
    /// ephemeral — keying on the source side would
    /// systematically miss everything.
    #[must_use]
    pub fn classify(&self, key: &FlowKey) -> AppId {
        for (proto, port, app) in &self.table {
            if *proto == key.protocol && *port == key.destination_port {
                return app.clone();
            }
        }
        AppId::Unknown
    }
}

/// SNI extractor: parses the TLS ClientHello on the first
/// segment of a TLS-over-TCP flow and returns the
/// server_name extension's hostname if present.
///
/// This is a hand-rolled, intentionally narrow parser — we
/// don't pull in a TLS stack just for this. The format is
/// fixed by RFC 8446 §4.1.2 / RFC 6066 §3, and the depth of
/// parsing we need is shallow:
///
///   record layer (5 bytes):  type=22, version=*, length=N
///   handshake (4 bytes):    type=1 (ClientHello), length=K
///   ClientHello (variable):
///     version (2)
///     random (32)
///     session_id_length (1) + session_id (var)
///     cipher_suites_length (2) + cipher_suites (var)
///     compression_methods_length (1) + compression_methods (var)
///     extensions_length (2) + extensions (var)
///   extensions:
///     ext_type (2) + ext_length (2) + ext_data (var)
///     server_name (ext_type=0):
///       list_length (2)
///         name_type (1) + name_length (2) + name (var)
///
/// The extractor returns `None` if the buffer is short or
/// the ClientHello is malformed.
#[derive(Debug, Default, Clone, Copy)]
pub struct SniExtractor;

impl SniExtractor {
    /// Attempt to parse a TLS ClientHello out of `buf` and
    /// return the SNI hostname. Returns `None` on any short
    /// read or malformed framing — the extractor is
    /// best-effort and never panics.
    ///
    /// # Errors
    ///
    /// Returns [`FwError::AppId`] when the buffer is
    /// non-empty but the framing is clearly invalid (record
    /// type other than handshake, handshake type other than
    /// ClientHello). An empty / short buffer returns `Ok(None)`
    /// to let the caller fall back to the port heuristic.
    pub fn extract(&self, buf: &[u8]) -> Result<Option<String>, FwError> {
        if buf.len() < 5 {
            return Ok(None);
        }
        // Record layer.
        if buf[0] != 0x16 {
            // Not a handshake record — not TLS, or middle of
            // an existing flow. Bail without erroring.
            return Ok(None);
        }
        // record version (buf[1..3]) and record length
        // (buf[3..5]) we accept any version since TLS 1.3
        // negotiates inside an extension on a record advertising
        // 1.2 / 1.0 framing.
        if buf.len() < 5 + 4 {
            return Ok(None);
        }
        // Handshake layer.
        if buf[5] != 0x01 {
            // Not a ClientHello.
            return Err(FwError::AppId(format!(
                "handshake type 0x{:02x} is not ClientHello",
                buf[5]
            )));
        }
        // Handshake length (3 bytes, big-endian).
        let hs_len = ((buf[6] as usize) << 16) | ((buf[7] as usize) << 8) | (buf[8] as usize);
        let hs_body_start = 9usize;
        let hs_body_end = hs_body_start.checked_add(hs_len).ok_or_else(|| {
            FwError::AppId("handshake length overflowed addressable buffer".into())
        })?;
        if buf.len() < hs_body_end {
            // The handshake claims to be longer than the
            // buffer carries — treat as truncated and fall
            // back to the port heuristic. Not an error: the
            // firewall may simply have observed only the
            // first segment.
            return Ok(None);
        }
        let body = &buf[hs_body_start..hs_body_end];
        // ClientHello fields.
        // version (2) + random (32) = 34
        if body.len() < 34 {
            return Ok(None);
        }
        let mut p = 34usize;
        // session_id_length (1) + session_id (var)
        if p >= body.len() {
            return Ok(None);
        }
        let sid_len = body[p] as usize;
        p = p
            .checked_add(1 + sid_len)
            .ok_or_else(|| FwError::AppId("session_id length overflowed".into()))?;
        if p + 2 > body.len() {
            return Ok(None);
        }
        let cs_len = ((body[p] as usize) << 8) | (body[p + 1] as usize);
        p = p
            .checked_add(2 + cs_len)
            .ok_or_else(|| FwError::AppId("cipher_suites length overflowed".into()))?;
        if p >= body.len() {
            return Ok(None);
        }
        let cmeth_len = body[p] as usize;
        p = p
            .checked_add(1 + cmeth_len)
            .ok_or_else(|| FwError::AppId("compression_methods length overflowed".into()))?;
        if p + 2 > body.len() {
            return Ok(None);
        }
        let ext_len = ((body[p] as usize) << 8) | (body[p + 1] as usize);
        p += 2;
        if p + ext_len > body.len() {
            return Ok(None);
        }
        let mut ep = p;
        let ext_end = p + ext_len;
        while ep + 4 <= ext_end {
            let ext_type = (u16::from(body[ep]) << 8) | u16::from(body[ep + 1]);
            let ext_data_len = ((body[ep + 2] as usize) << 8) | (body[ep + 3] as usize);
            ep += 4;
            if ep + ext_data_len > ext_end {
                return Ok(None);
            }
            if ext_type == 0x0000 {
                // server_name extension.
                let ext_data = &body[ep..ep + ext_data_len];
                return Ok(parse_server_name_extension(ext_data));
            }
            ep += ext_data_len;
        }
        Ok(None)
    }
}

/// Parse the body of an RFC 6066 server_name extension and
/// return the first host_name entry. Returns `None` if the
/// extension is empty or malformed.
fn parse_server_name_extension(ext: &[u8]) -> Option<String> {
    if ext.len() < 2 {
        return None;
    }
    let list_len = ((ext[0] as usize) << 8) | (ext[1] as usize);
    if ext.len() < 2 + list_len {
        return None;
    }
    let list = &ext[2..2 + list_len];
    if list.len() < 3 {
        return None;
    }
    let name_type = list[0];
    if name_type != 0 {
        // Only host_name (type 0) is defined; everything else
        // is reserved.
        return None;
    }
    let name_len = ((list[1] as usize) << 8) | (list[2] as usize);
    if list.len() < 3 + name_len {
        return None;
    }
    let name_bytes = &list[3..3 + name_len];
    // SNI is ASCII per RFC 6066. We accept any UTF-8 because
    // some clients ship punycode; reject empty.
    let s = std::str::from_utf8(name_bytes).ok()?;
    if s.is_empty() {
        return None;
    }
    Some(s.to_ascii_lowercase())
}

/// Composite resolver that runs the port heuristic and
/// optional SNI sniff. The flow service calls this once per
/// new flow.
#[derive(Debug, Clone)]
pub struct AppIdResolver {
    /// Inner port table.
    pub port: PortHeuristicResolver,
    /// SNI extractor. Stateless — could be a free function;
    /// kept as a struct so future hook-style refinements
    /// (ALPN, HTTP/2 frame inspection) can land in the same
    /// composite without breaking callers.
    pub sni: SniExtractor,
}

impl Default for AppIdResolver {
    fn default() -> Self {
        Self {
            port: PortHeuristicResolver::default(),
            sni: SniExtractor,
        }
    }
}

impl AppIdResolver {
    /// Resolve the app id for a flow given the first payload
    /// segment. `payload` may be empty (the firewall has only
    /// seen IP/L4 headers); in that case the resolver
    /// returns the port-heuristic answer.
    ///
    /// # Errors
    ///
    /// [`FwError::AppId`] if the payload framing is clearly
    /// malformed (e.g. a handshake record whose type byte is
    /// not ClientHello). Empty / truncated buffers are NOT
    /// errors — the resolver returns the port-heuristic
    /// fallback instead.
    pub fn resolve(&self, key: &FlowKey, payload: &[u8]) -> Result<AppId, FwError> {
        let mut base = self.port.classify(key);
        if let AppId::Tls { sni: _ } = &base {
            // Promote to TLS-with-SNI if we can.
            if let Some(name) = self.sni.extract(payload)? {
                base = AppId::Tls { sni: Some(name) };
            }
        }
        Ok(base)
    }

    /// Refine an existing app id with a later payload
    /// segment. Used when the firewall sees a second packet
    /// that carries the ClientHello where the first carried
    /// only the TCP handshake.
    ///
    /// # Errors
    ///
    /// Same as [`Self::resolve`].
    pub fn refine(&self, current: AppId, payload: &[u8]) -> Result<AppId, FwError> {
        if let AppId::Tls { sni: None } = &current {
            if let Some(name) = self.sni.extract(payload)? {
                return Ok(AppId::Tls { sni: Some(name) });
            }
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_key(port: u16, proto: IpProtocol) -> FlowKey {
        FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            54321,
            port,
            proto,
        )
        .unwrap()
    }

    #[test]
    fn port_heuristic_classifies_well_known_ports() {
        let r = PortHeuristicResolver::with_well_known();
        assert_eq!(r.classify(&make_key(22, IpProtocol::Tcp)), AppId::Ssh);
        assert_eq!(r.classify(&make_key(53, IpProtocol::Udp)), AppId::Dns);
        assert_eq!(r.classify(&make_key(53, IpProtocol::Tcp)), AppId::Dns);
        assert_eq!(r.classify(&make_key(80, IpProtocol::Tcp)), AppId::Http);
        assert_eq!(r.classify(&make_key(123, IpProtocol::Udp)), AppId::Ntp);
        assert_eq!(
            r.classify(&make_key(443, IpProtocol::Tcp)),
            AppId::Tls { sni: None }
        );
        assert_eq!(r.classify(&make_key(443, IpProtocol::Udp)), AppId::Quic);
        assert_eq!(r.classify(&make_key(445, IpProtocol::Tcp)), AppId::Smb);
    }

    #[test]
    fn port_heuristic_unknown_for_unmapped() {
        let r = PortHeuristicResolver::with_well_known();
        assert_eq!(r.classify(&make_key(8443, IpProtocol::Tcp)), AppId::Unknown);
    }

    #[test]
    fn port_heuristic_empty_returns_unknown() {
        let r = PortHeuristicResolver::empty();
        assert_eq!(r.classify(&make_key(443, IpProtocol::Tcp)), AppId::Unknown);
    }

    #[test]
    fn port_heuristic_insert_overrides() {
        let mut r = PortHeuristicResolver::empty();
        r.insert(IpProtocol::Tcp, 8443, AppId::Http);
        assert_eq!(r.classify(&make_key(8443, IpProtocol::Tcp)), AppId::Http);
        // Overwrite.
        r.insert(IpProtocol::Tcp, 8443, AppId::Tls { sni: None });
        assert_eq!(
            r.classify(&make_key(8443, IpProtocol::Tcp)),
            AppId::Tls { sni: None }
        );
    }

    /// Build a minimal valid TLS 1.2 ClientHello carrying a
    /// single server_name extension with the given host.
    /// Returns the raw record-layer bytes.
    fn synthesize_client_hello(host: &str) -> Vec<u8> {
        let mut hello = Vec::new();
        // client_version
        hello.extend_from_slice(&[0x03, 0x03]);
        // random (32 bytes, all zeros for determinism)
        hello.extend_from_slice(&[0u8; 32]);
        // session_id_length = 0
        hello.push(0x00);
        // cipher_suites_length = 2; one suite (0x00, 0x35 =
        // TLS_RSA_WITH_AES_256_CBC_SHA)
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x35]);
        // compression_methods_length = 1; null compression
        hello.extend_from_slice(&[0x01, 0x00]);
        // Build the server_name extension body.
        let host_bytes = host.as_bytes();
        let host_len = host_bytes.len();
        // host_name: name_type (1) + name_length (2) + name (var)
        // server_name_list_length: 1 + 2 + host_len = host_len + 3
        // total extension body: 2 (list_len) + (host_len + 3)
        let mut sn_ext = Vec::new();
        let list_len = u16::try_from(host_len + 3).expect("sni host bound to fit u16");
        sn_ext.extend_from_slice(&list_len.to_be_bytes());
        sn_ext.push(0x00); // host_name type
        let host_len_u16 = u16::try_from(host_len).expect("sni host bound to fit u16");
        sn_ext.extend_from_slice(&host_len_u16.to_be_bytes());
        sn_ext.extend_from_slice(host_bytes);
        // extensions_length = 2 (ext_type) + 2 (ext_len) + sn_ext.len()
        let ext_len_total = u16::try_from(4 + sn_ext.len()).expect("sni extensions block fits u16");
        hello.extend_from_slice(&ext_len_total.to_be_bytes());
        // Single extension: server_name (type 0)
        hello.extend_from_slice(&[0x00, 0x00]); // ext_type = server_name
        let sn_ext_len_u16 = u16::try_from(sn_ext.len()).expect("sni extensions block fits u16");
        hello.extend_from_slice(&sn_ext_len_u16.to_be_bytes());
        hello.extend_from_slice(&sn_ext);
        // Wrap in handshake layer.
        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        let hs_len_bytes = u32::try_from(hello.len())
            .expect("synth ClientHello length must fit in u32")
            .to_be_bytes();
        // 3-byte length, big-endian.
        hs.extend_from_slice(&hs_len_bytes[1..4]);
        hs.extend_from_slice(&hello);
        // Wrap in record layer.
        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend_from_slice(&[0x03, 0x01]); // legacy_record_version
        let hs_len_u16 = u16::try_from(hs.len()).expect("handshake block fits u16");
        rec.extend_from_slice(&hs_len_u16.to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn sni_extractor_pulls_hostname_from_synth_client_hello() {
        let pkt = synthesize_client_hello("example.com");
        let extractor = SniExtractor;
        let sni = extractor.extract(&pkt).unwrap();
        assert_eq!(sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn sni_extractor_lowercases_mixed_case() {
        let pkt = synthesize_client_hello("Example.COM");
        let extractor = SniExtractor;
        let sni = extractor.extract(&pkt).unwrap();
        assert_eq!(sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn sni_extractor_returns_none_for_empty_buffer() {
        let extractor = SniExtractor;
        let sni = extractor.extract(&[]).unwrap();
        assert!(sni.is_none());
    }

    #[test]
    fn sni_extractor_returns_none_for_non_handshake_record() {
        // Record type 0x17 = application_data.
        let pkt = vec![0x17, 0x03, 0x03, 0x00, 0x05, 1, 2, 3, 4, 5];
        let extractor = SniExtractor;
        let sni = extractor.extract(&pkt).unwrap();
        assert!(sni.is_none());
    }

    #[test]
    fn sni_extractor_errors_on_non_client_hello_handshake() {
        // Record type 0x16 (handshake) but handshake type 0x02
        // (ServerHello). The firewall should never see a
        // ServerHello from an originator-side sniff, so flag
        // it.
        let pkt = vec![
            0x16, 0x03, 0x01, 0x00, 0x05, // record header
            0x02, 0x00, 0x00, 0x00, 0x00, // ServerHello header
        ];
        let extractor = SniExtractor;
        let err = extractor
            .extract(&pkt)
            .expect_err("ServerHello must be rejected");
        match err {
            FwError::AppId(msg) => assert!(msg.contains("ClientHello")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn sni_extractor_handles_truncated_handshake() {
        // Build a valid ClientHello, then truncate it
        // halfway through the random nonce.
        let pkt = synthesize_client_hello("example.com");
        let truncated = &pkt[..pkt.len() - 50];
        let extractor = SniExtractor;
        let sni = extractor
            .extract(truncated)
            .expect("truncated buffer must not error");
        // Either None (insufficient bytes) or some salvaged
        // hostname — depending on where the truncation
        // landed. The contract is "no panic, no error", and
        // for this specific truncation it's None.
        assert!(sni.is_none());
    }

    #[test]
    fn resolver_promotes_tls_to_tls_with_sni_when_payload_carries_hello() {
        let r = AppIdResolver::default();
        let key = make_key(443, IpProtocol::Tcp);
        let pkt = synthesize_client_hello("api.example.com");
        let app = r.resolve(&key, &pkt).unwrap();
        assert_eq!(
            app,
            AppId::Tls {
                sni: Some("api.example.com".into())
            }
        );
    }

    #[test]
    fn resolver_falls_back_to_port_heuristic_when_payload_empty() {
        let r = AppIdResolver::default();
        let key = make_key(443, IpProtocol::Tcp);
        let app = r.resolve(&key, &[]).unwrap();
        assert_eq!(app, AppId::Tls { sni: None });
    }

    #[test]
    fn refine_promotes_tls_without_sni_to_with_sni() {
        let r = AppIdResolver::default();
        let pkt = synthesize_client_hello("api.example.com");
        let app = r.refine(AppId::Tls { sni: None }, &pkt).expect("refine ok");
        assert_eq!(app.sni(), Some("api.example.com"));
    }

    #[test]
    fn refine_leaves_non_tls_unchanged() {
        let r = AppIdResolver::default();
        let pkt = synthesize_client_hello("api.example.com");
        let app = r.refine(AppId::Ssh, &pkt).expect("refine ok");
        assert_eq!(app, AppId::Ssh);
    }

    #[test]
    fn appid_as_str_matches_wire_form() {
        assert_eq!(AppId::Dns.as_str(), "dns");
        assert_eq!(AppId::Http.as_str(), "http");
        assert_eq!(AppId::Tls { sni: None }.as_str(), "tls");
        assert_eq!(
            AppId::Tls {
                sni: Some("x".into())
            }
            .as_str(),
            "tls"
        );
        assert_eq!(AppId::Quic.as_str(), "quic");
        assert_eq!(AppId::Ssh.as_str(), "ssh");
        assert_eq!(AppId::Smtp.as_str(), "smtp");
        assert_eq!(AppId::Ntp.as_str(), "ntp");
        assert_eq!(AppId::Smb.as_str(), "smb");
        assert_eq!(AppId::Unknown.as_str(), "unknown");
    }
}

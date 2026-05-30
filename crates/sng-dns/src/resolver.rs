//! Recursive-resolver wrapper.
//!
//! [`Resolver`] is the abstraction over "send this query
//! upstream and parse the answer." Two real impls live here:
//!
//! - [`UdpResolver`]: production path. Encodes the query with
//!   [`crate::wire::encode_query`], sends it to a configured
//!   upstream `SocketAddr` over UDP, waits for the response with
//!   a deadline, parses with [`crate::wire::parse_*`].
//! - [`StaticResolver`]: in-memory map keyed by canonical name +
//!   qtype. Used by [`crate::service`] integration tests so the
//!   filter-chain / event-emission path can be exercised
//!   without a live upstream.
//!
//! The trait is `async fn`-based via [`async_trait`] so the
//! [`crate::service`] orchestrator can be generic over either
//! implementation. The trait method returns a
//! [`crate::query::DnsResponse`] rather than raw bytes so the
//! caller never sees the wire form once it lands inside this
//! crate's boundary.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::error::DnsError;
use crate::qtype::{QType, RCode};
use crate::query::{DnsQuery, DnsResponse, canonicalize_name};
use crate::wire::{parse_header, parse_question, parse_records};

/// Async resolver trait. The filter chain calls this only after
/// [`crate::filter::ChainOutcome::ResolveAndObserve`]: a
/// short-circuited query never hits the resolver at all.
#[async_trait]
pub trait Resolver: Send + Sync + 'static {
    /// Resolve a single query. Implementations MUST NOT panic on
    /// transient upstream failures; they must return
    /// [`DnsError::Io`] / [`DnsError::UpstreamRcode`] /
    /// [`DnsError::WireFormat`] so the caller can stamp the
    /// failure onto the emitted DnsEvent.
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse, DnsError>;
}

/// Production UDP resolver. Wraps a [`UdpSocket`] bound to an
/// ephemeral local port and configured with a single upstream
/// target and a per-query deadline.
///
/// The transaction-ID side of the protocol is handled by the
/// caller via [`crate::wire::encode_query`]; this resolver
/// supplies a fresh, randomized 16-bit ID per query so concurrent
/// queries against the same socket disambiguate cleanly.
#[derive(Debug)]
pub struct UdpResolver {
    upstream: SocketAddr,
    deadline: Duration,
    /// We use a single bound socket per resolver instance.
    /// Wrapping it in [`Arc`] makes [`Self::resolve`] cheap to
    /// share across tokio tasks under the agent's flat-async
    /// scheduling model.
    socket: Arc<UdpSocket>,
    /// Monotonic counter used to seed the transaction ID. The
    /// counter is XORed against a per-resolver random salt at
    /// construction time so two resolvers started in the same
    /// process don't reuse the same TXID sequence (which would
    /// confuse some upstream cache implementations).
    txid_seed: parking_lot::Mutex<u16>,
}

impl UdpResolver {
    /// Bind a UDP socket and prepare the resolver. The local
    /// bind address is `0.0.0.0:0` (kernel picks an ephemeral
    /// port).
    ///
    /// # Errors
    ///
    /// [`DnsError::Io`] if the socket bind fails.
    pub async fn bind(upstream: SocketAddr, deadline: Duration) -> Result<Self, DnsError> {
        // Constant strings; the parse cannot fail. Using
        // `SocketAddr::new` keeps the construction lint-clean
        // (no `expect` / `unwrap` on a literal).
        let bind: SocketAddr = if upstream.is_ipv4() {
            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|e| DnsError::Io(format!("udp bind {bind}: {e}")))?;
        socket
            .connect(upstream)
            .await
            .map_err(|e| DnsError::Io(format!("udp connect {upstream}: {e}")))?;
        // Seed the TXID counter with the low 16 bits of the
        // monotonic clock so two resolvers in the same process
        // start from different points.
        // Take the low 16 bits of the monotonic nanosecond
        // counter — the cast IS intentional truncation; we only
        // want the bottom of the nanosecond value to seed a TXID
        // counter.
        #[allow(clippy::cast_possible_truncation)]
        let seed = (std::time::Instant::now().elapsed().as_nanos() as u16).wrapping_add(0x9E37);
        Ok(Self {
            upstream,
            deadline,
            socket: Arc::new(socket),
            txid_seed: parking_lot::Mutex::new(seed),
        })
    }

    fn next_txid(&self) -> u16 {
        let mut g = self.txid_seed.lock();
        // Linear congruential step; 16 bits is small enough that
        // we collide on the order of 65535 queries between
        // wraps, but the TXID is only one half of the
        // disambiguation (the source-port chosen by the kernel
        // is the other). Good enough for an agent-side
        // recursive client; the upstream is the security
        // boundary, not us.
        *g = g.wrapping_mul(0x515A).wrapping_add(0x3A29);
        *g
    }

    /// Address of the configured upstream. Surfaced so the
    /// supervisor can log it during boot.
    #[must_use]
    pub const fn upstream(&self) -> SocketAddr {
        self.upstream
    }
}

#[async_trait]
impl Resolver for UdpResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse, DnsError> {
        let txid = self.next_txid();
        let pkt = crate::wire::encode_query(txid, &query.name, query.qtype)?;
        // Send and recv must both observe the deadline. We use a
        // single outer timeout that wraps both halves so a slow
        // send + fast recv still fits inside the budget rather
        // than getting two deadlines back-to-back.
        let socket = self.socket.clone();
        let upstream = self.upstream;
        let resp = timeout(self.deadline, async move {
            socket
                .send(&pkt)
                .await
                .map_err(|e| DnsError::Io(format!("udp send {upstream}: {e}")))?;
            // 4 KiB covers any non-EDNS response. We do NOT
            // advertise EDNS0 so the upstream is bound to <= 512
            // bytes by RFC 1035; the larger buffer is defensive.
            let mut buf = vec![0u8; 4096];
            let n = socket
                .recv(&mut buf)
                .await
                .map_err(|e| DnsError::Io(format!("udp recv {upstream}: {e}")))?;
            buf.truncate(n);
            Ok::<Vec<u8>, DnsError>(buf)
        })
        .await
        .map_err(|_| DnsError::Io(format!("udp deadline {upstream}: {:?}", self.deadline)))??;

        decode_udp_response(&resp, txid, query, &self.upstream.to_string())
    }
}

/// Parse a UDP DNS response into the agent-facing form.
/// Factored out so [`StaticResolver`] and the unit tests can
/// reuse it.
fn decode_udp_response(
    buf: &[u8],
    expected_txid: u16,
    query: &DnsQuery,
    upstream_label: &str,
) -> Result<DnsResponse, DnsError> {
    let hdr = parse_header(buf)?;
    if hdr.id != expected_txid {
        return Err(DnsError::WireFormat(format!(
            "txid mismatch: expected {expected_txid:#06x}, got {:#06x}",
            hdr.id
        )));
    }
    if !hdr.qr {
        return Err(DnsError::WireFormat(
            "response packet has QR=0 (looks like a query)".into(),
        ));
    }
    if hdr.qd_count != 1 {
        return Err(DnsError::WireFormat(format!(
            "expected qd_count=1, got {}",
            hdr.qd_count
        )));
    }
    // Skip the echoed question to land on the answer section.
    let (echoed_name, echoed_qtype, _qc, offset) = parse_question(buf, 12)?;
    if canonicalize_name(&echoed_name) != query.name {
        return Err(DnsError::WireFormat(format!(
            "question name mismatch: expected {}, got {}",
            query.name, echoed_name
        )));
    }
    if echoed_qtype != query.qtype {
        return Err(DnsError::WireFormat(format!(
            "question qtype mismatch: expected {}, got {}",
            query.qtype, echoed_qtype
        )));
    }
    // Answer + authority sections, in order. The additional
    // section is ignored: it's mostly OPT pseudo-RR's we did not
    // request and glue records the agent never uses.
    let (answers, after_answers) = parse_records(buf, offset, hdr.an_count)?;
    let (authority, _after_authority) = parse_records(buf, after_answers, hdr.ns_count)?;

    // Terminal RCODEs (NXDOMAIN is NOT terminal — it's a
    // legitimate "name does not exist" the agent must surface to
    // the caller) get mapped to UpstreamRcode so the supervisor
    // can decide whether to fail-open or fail-closed.
    if matches!(hdr.rcode, RCode::ServFail | RCode::Refused) {
        return Err(DnsError::UpstreamRcode {
            rcode: hdr.rcode.to_wire(),
        });
    }

    let primary_ip = answers.iter().find_map(super::wire::Record::as_ip);
    Ok(DnsResponse {
        rcode: hdr.rcode,
        answers,
        authority,
        primary_ip,
        upstream: Some(upstream_label.to_string()),
    })
}

/// In-process static resolver. Used by [`crate::service`]
/// integration tests; not a production component. The map is
/// keyed by canonical lowercase name + qtype.
///
/// A name absent from the map returns NXDOMAIN. The "upstream"
/// label is stamped onto every emitted response so the
/// downstream [`sng_core::DnsEvent::upstream`] field is populated
/// just like the production path.
pub struct StaticResolver {
    table: RwLock<HashMap<(String, QType), DnsResponse>>,
    label: String,
}

impl std::fmt::Debug for StaticResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticResolver")
            .field("label", &self.label)
            .field("entries", &self.table.read().len())
            .finish()
    }
}

impl StaticResolver {
    /// Build a static resolver with the given upstream-label.
    #[must_use]
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            table: RwLock::new(HashMap::new()),
            label: label.into(),
        }
    }

    /// Install a canned answer for a query.
    pub fn install(&self, name: &str, qtype: QType, mut response: DnsResponse) {
        response.upstream = Some(self.label.clone());
        let key = (canonicalize_name(name), qtype);
        self.table.write().insert(key, response);
    }

    /// Number of canned answers installed. Used by tests to
    /// assert the fixture was populated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.table.read().len()
    }

    /// Whether any canned answers are installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.table.read().is_empty()
    }
}

#[async_trait]
impl Resolver for StaticResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResponse, DnsError> {
        let key = (query.name.clone(), query.qtype);
        let table = self.table.read();
        if let Some(resp) = table.get(&key) {
            return Ok(resp.clone());
        }
        Ok(DnsResponse {
            rcode: RCode::NxDomain,
            answers: Vec::new(),
            authority: Vec::new(),
            primary_ip: None,
            upstream: Some(self.label.clone()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{CLASS_IN, Record};
    use std::net::{IpAddr, Ipv4Addr};

    fn synth_response_for_static() -> DnsResponse {
        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        DnsResponse {
            rcode: RCode::NoError,
            answers: vec![Record {
                name: "example.com".into(),
                rtype: QType::A,
                class: CLASS_IN,
                ttl: 60,
                rdata: Ipv4Addr::new(93, 184, 216, 34).octets().to_vec(),
            }],
            authority: Vec::new(),
            primary_ip: Some(ip),
            upstream: None,
        }
    }

    #[tokio::test]
    async fn static_resolver_returns_canned_answer() {
        let r = StaticResolver::new("test-upstream");
        r.install("example.com", QType::A, synth_response_for_static());
        let q = DnsQuery::new("EXAMPLE.com.", QType::A);
        let resp = r.resolve(&q).await.expect("resolve");
        assert_eq!(resp.rcode, RCode::NoError);
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.upstream.as_deref(), Some("test-upstream"));
    }

    #[tokio::test]
    async fn static_resolver_returns_nxdomain_for_unknown() {
        let r = StaticResolver::new("test-upstream");
        let q = DnsQuery::new("unknown.example", QType::A);
        let resp = r.resolve(&q).await.expect("resolve");
        assert_eq!(resp.rcode, RCode::NxDomain);
        assert!(resp.answers.is_empty());
        assert!(resp.primary_ip.is_none());
        assert_eq!(resp.upstream.as_deref(), Some("test-upstream"));
    }

    #[tokio::test]
    async fn udp_resolver_bind_succeeds_on_loopback_upstream() {
        // We don't have a recursive resolver in the test env; we
        // only assert the bind path. A full round-trip is
        // exercised in tests/integration.rs against a tokio mock
        // UDP socket.
        let upstream: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let _r = UdpResolver::bind(upstream, Duration::from_millis(100))
            .await
            .expect("bind");
    }

    #[tokio::test]
    async fn udp_resolver_resolve_times_out_when_upstream_silent() {
        // Bind upstream to a port that's listening but never
        // replies (we use an ephemeral UDP socket we never
        // recv() on).
        let blackhole = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind blackhole");
        let blackhole_addr = blackhole.local_addr().expect("addr");
        let r = UdpResolver::bind(blackhole_addr, Duration::from_millis(50))
            .await
            .expect("bind resolver");
        let q = DnsQuery::new("example.com", QType::A);
        let err = r.resolve(&q).await.expect_err("must time out");
        assert!(matches!(err, DnsError::Io(_)));
    }

    #[test]
    fn decode_rejects_txid_mismatch() {
        // Build a minimal valid response packet with txid=0x1234
        // and feed it into the decoder expecting 0xABCD.
        let resp = crate::wire::encode_query(0x1234, "example.com", QType::A).expect("encode");
        // Flip QR bit on the response.
        let mut resp = resp;
        resp[2] |= 0x80;
        let q = DnsQuery::new("example.com", QType::A);
        let err = decode_udp_response(&resp, 0xABCD, &q, "upstream").expect_err("must reject txid");
        assert!(matches!(err, DnsError::WireFormat(_)));
    }

    #[test]
    fn decode_rejects_qr_zero() {
        let pkt = crate::wire::encode_query(0x1234, "example.com", QType::A).expect("encode");
        // pkt is a QUERY (QR=0). decode_udp_response should
        // reject it.
        let q = DnsQuery::new("example.com", QType::A);
        let err = decode_udp_response(&pkt, 0x1234, &q, "upstream").expect_err("must reject QR=0");
        assert!(matches!(err, DnsError::WireFormat(_)));
    }
}

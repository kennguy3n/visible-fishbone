//! Per-flow types — `FlowKey` (5-tuple), `FlowDirection`,
//! `IpProtocol`, and `FlowState` (accounting + conntrack
//! micro-state machine).
//!
//! These are the primitives the rest of the firewall crate
//! works in. They are deliberately wire-format-free: the
//! decoder that builds a `FlowKey` from a raw packet header
//! lives outside this crate (in `sng-pal`). Keeping the
//! firewall logic in terms of typed structs means the
//! verdict cache, conntrack table, and policy adapter can
//! be unit-tested without spinning up a kernel netfilter
//! hook.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;

use crate::error::FwError;

/// IP-layer protocol the flow speaks. This is the third
/// component of the canonical 5-tuple — the upper layers
/// (HTTP, DNS, etc.) are identified separately by
/// [`crate::appid::AppId`] after the firewall has the first
/// few payload bytes on hand.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpProtocol {
    /// TCP — the only protocol the firewall does full
    /// conntrack state-machine tracking for. The TCP flag
    /// transitions (SYN → SYN+ACK → ACK → … → FIN/RST) drive
    /// [`FlowState::ConnState`].
    Tcp,
    /// UDP — connectionless. Conntrack uses pure idle-timeout
    /// eviction; no state machine.
    Udp,
    /// ICMP / ICMPv6. Tracked for telemetry but the verdict
    /// path treats it as an L3 question (`Allow` or `Deny`)
    /// based on (src, dst) plus the policy's ICMP rule, with
    /// no L7 sniff.
    Icmp,
    /// Catch-all for anything that isn't one of the above
    /// (SCTP, ESP, GRE, …). The firewall doesn't track
    /// L4 state for these; the policy verdict is based on
    /// (src, dst, protocol-id) alone.
    Other(u8),
}

impl IpProtocol {
    /// The IANA assigned protocol number on the wire.
    #[must_use]
    pub const fn as_wire(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            // ICMP=1 / ICMPv6=58. We collapse the two onto a
            // single variant because policy rules express
            // "icmp" uniformly; the v4/v6 distinction is
            // already carried by [`FlowKey::source_ip`]'s
            // address family. The wire value returned here is
            // the v4 ICMP number — callers that need the
            // address-family-specific number on the egress
            // path should branch on the IP family explicitly.
            Self::Icmp => 1,
            Self::Other(n) => n,
        }
    }

    /// Construct from the IANA wire protocol number.
    #[must_use]
    pub const fn from_wire(proto: u8) -> Self {
        match proto {
            6 => Self::Tcp,
            17 => Self::Udp,
            1 | 58 => Self::Icmp,
            other => Self::Other(other),
        }
    }

    /// The short textual form used in [`FlowEvent::protocol`].
    /// Matches the lowercase wire shape downstream consumers
    /// (ClickHouse, NATS subjects) expect.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Other(_) => "other",
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which side of the firewall the flow's first observed
/// packet came from. The agent and edge appliance both
/// distinguish ingress (something from the WAN / public side
/// hitting the trusted network) from egress (something inside
/// the trusted network reaching out). Policy verdicts can be
/// direction-sensitive.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowDirection {
    /// Inside → Outside. The originator is on the agent /
    /// edge's protected side.
    Egress,
    /// Outside → Inside. The originator is from the WAN /
    /// internet / untrusted side. Common for inbound mTLS to
    /// the edge VM, NAT-traversal pinholes, etc.
    Ingress,
    /// Same security zone on both sides (LAN-to-LAN traffic
    /// inside a segmented site network). The policy can still
    /// have segmentation rules for these.
    Lateral,
}

/// Five-tuple that uniquely identifies a flow at the
/// firewall layer. Two packets share a `FlowKey` iff they
/// are part of the same conversation in the same direction.
///
/// Note: this struct's [`Hash`] / [`Eq`] derivation makes it
/// the natural key for the conntrack table.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// Source IP — the originator's address. For an egress
    /// flow this is on the trusted side; for an ingress flow
    /// it's the remote initiator.
    pub source_ip: IpAddr,
    /// Destination IP. For an egress flow this is the
    /// remote service; for an ingress flow it's the
    /// service inside the trusted zone.
    pub destination_ip: IpAddr,
    /// Source port. Zero is reserved for protocols that
    /// lack ports (raw ICMP, IPSEC ESP). The validator
    /// in [`FlowKey::new`] rejects zero source ports on
    /// TCP / UDP.
    pub source_port: u16,
    /// Destination port. Same zero handling as
    /// [`Self::source_port`].
    pub destination_port: u16,
    /// IP protocol the 5-tuple is in.
    pub protocol: IpProtocol,
}

impl FlowKey {
    /// Construct a flow key with the basic sanity checks the
    /// rest of the firewall relies on:
    ///
    /// - Both IPs must be in the same address family
    ///   (no mixed v4 / v6 keys).
    /// - For TCP / UDP, both ports must be non-zero.
    ///
    /// Anything else is a permanent rejection: the caller has
    /// handed us malformed input and re-trying the same packet
    /// won't help.
    ///
    /// # Errors
    ///
    /// [`FwError::FlowInvalid`] on any of the above.
    pub fn new(
        source_ip: IpAddr,
        destination_ip: IpAddr,
        source_port: u16,
        destination_port: u16,
        protocol: IpProtocol,
    ) -> Result<Self, FwError> {
        if source_ip.is_ipv4() != destination_ip.is_ipv4() {
            return Err(FwError::FlowInvalid(format!(
                "mixed-family flow key src={source_ip} dst={destination_ip}"
            )));
        }
        if matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
            if source_port == 0 {
                return Err(FwError::FlowInvalid(format!(
                    "zero source port on {protocol} flow"
                )));
            }
            if destination_port == 0 {
                return Err(FwError::FlowInvalid(format!(
                    "zero destination port on {protocol} flow"
                )));
            }
        }
        Ok(Self {
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol,
        })
    }

    /// The reverse 5-tuple — what a reply packet would key on.
    /// Used by the conntrack table's "established"
    /// short-circuit to recognise the server-to-client half of
    /// an existing flow.
    #[must_use]
    pub fn reverse(&self) -> Self {
        Self {
            source_ip: self.destination_ip,
            destination_ip: self.source_ip,
            source_port: self.destination_port,
            destination_port: self.source_port,
            protocol: self.protocol,
        }
    }

    /// Construct a [`FlowEvent`]-shaped tuple of the canonical
    /// text-form fields (src_ip / dst_ip / src_port / dst_port /
    /// protocol). The telemetry emitter calls this when it
    /// finalises a flow.
    #[must_use]
    pub fn to_event_fields(&self) -> EventFieldSnapshot {
        EventFieldSnapshot {
            src_ip: self.source_ip.to_string(),
            dst_ip: self.destination_ip.to_string(),
            src_port: self.source_port,
            dst_port: self.destination_port,
            protocol: self.protocol.as_str(),
        }
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}-{}->{}:{}",
            self.source_ip,
            self.source_port,
            self.protocol.as_str(),
            self.destination_ip,
            self.destination_port,
        )
    }
}

/// Borrowed-projection of a `FlowKey` in the field shape
/// `FlowEvent` wants. Returned by [`FlowKey::to_event_fields`]
/// so the telemetry emitter doesn't need to know how the key
/// is laid out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventFieldSnapshot {
    /// `FlowEvent::src_ip` text-form.
    pub src_ip: String,
    /// `FlowEvent::dst_ip` text-form.
    pub dst_ip: String,
    /// `FlowEvent::src_port`.
    pub src_port: u16,
    /// `FlowEvent::dst_port`.
    pub dst_port: u16,
    /// `FlowEvent::protocol` lowercase short-form.
    pub protocol: &'static str,
}

/// TCP connection state — RFC 793 simplified.
///
/// We don't replicate every named state in the TCP RFC
/// (there are 11). The firewall only cares about the
/// distinctions that drive verdict / timeout decisions:
/// "are we still establishing?", "is the conversation
/// open?", "is one side trying to close?", "has either
/// side reset?".
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    /// SYN seen, no SYN+ACK yet. Conntrack uses a short
    /// idle timeout in this state so half-open scans don't
    /// pin entries.
    SynSent,
    /// SYN+ACK seen but no client ACK yet.
    SynReceived,
    /// Three-way handshake complete; data may be flowing.
    Established,
    /// One side sent FIN; the other has not finalised.
    Closing,
    /// Both sides finalised the FIN exchange, or one side
    /// sent RST. Eligible for immediate removal from the
    /// conntrack table on the next sweep.
    Closed,
}

impl ConnState {
    /// Whether the firewall should consider a flow in this
    /// state "live" for the purpose of established-flow
    /// verdict caching.
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Established | Self::Closing)
    }

    /// Initial state for a brand-new TCP flow's first SYN.
    #[must_use]
    pub const fn initial_tcp() -> Self {
        Self::SynSent
    }

    /// Initial state for a brand-new UDP / ICMP / other flow.
    /// These protocols have no handshake, so the first packet
    /// puts the flow straight into `Established`.
    #[must_use]
    pub const fn initial_stateless() -> Self {
        Self::Established
    }
}

/// Per-flow accounting + conntrack state. Stored as the value
/// of a `(FlowKey -> FlowState)` map; the key carries the
/// 5-tuple, the state carries everything that mutates packet
/// to packet.
#[derive(Clone, Debug)]
pub struct FlowState {
    /// Conntrack connection state (`ConnState`).
    pub conn_state: ConnState,
    /// Timestamp (`std::time::Instant`-as-milliseconds since the
    /// service's epoch) of the first packet observed on the
    /// flow. Used to compute `FlowEvent::duration_ms` at flow
    /// finalisation.
    pub start_ms: u64,
    /// Timestamp of the most recent packet observed on the
    /// flow. The conntrack sweeper compares this against the
    /// idle-timeout cutoff and evicts when the difference
    /// exceeds the timeout.
    pub last_seen_ms: u64,
    /// Total bytes the originator has sent on this flow.
    /// Maps onto `FlowEvent::bytes_out` for egress flows
    /// (originator = inside) and `FlowEvent::bytes_in` for
    /// ingress flows.
    pub bytes_originator: u64,
    /// Total bytes the responder has sent on this flow.
    /// Mirror of [`Self::bytes_originator`] for the other
    /// direction.
    pub bytes_responder: u64,
    /// Direction of the originating packet. Cached at flow
    /// creation time so a reverse-direction packet doesn't
    /// confuse the bookkeeping.
    pub direction: FlowDirection,
    /// Application id resolved by [`crate::appid`] when (and
    /// only when) the first L7-carrying packet provided
    /// enough bytes to make the call.
    pub app_id: Option<crate::appid::AppId>,
    /// Packet count — used for telemetry sampling decisions and
    /// to bound the cost of repeated per-packet processing on
    /// long-lived flows.
    pub packet_count: u64,
}

impl FlowState {
    /// Construct the per-flow state for a brand-new flow.
    /// Sets the initial conntrack state from the protocol,
    /// stamps the start / last-seen timestamps, and zeroes
    /// the byte counters.
    #[must_use]
    pub fn new(protocol: IpProtocol, direction: FlowDirection, now_ms: u64) -> Self {
        let conn_state = match protocol {
            IpProtocol::Tcp => ConnState::initial_tcp(),
            IpProtocol::Udp | IpProtocol::Icmp | IpProtocol::Other(_) => {
                ConnState::initial_stateless()
            }
        };
        Self {
            conn_state,
            start_ms: now_ms,
            last_seen_ms: now_ms,
            bytes_originator: 0,
            bytes_responder: 0,
            direction,
            app_id: None,
            packet_count: 0,
        }
    }

    /// Observe a packet on the originator side. Updates
    /// `last_seen`, increments the originator byte counter,
    /// and ticks the packet count.
    pub fn observe_originator(&mut self, bytes: u64, now_ms: u64) {
        self.last_seen_ms = now_ms;
        self.bytes_originator = self.bytes_originator.saturating_add(bytes);
        self.packet_count = self.packet_count.saturating_add(1);
    }

    /// Observe a packet on the responder side. Same as
    /// [`Self::observe_originator`] but credits the
    /// responder counter.
    pub fn observe_responder(&mut self, bytes: u64, now_ms: u64) {
        self.last_seen_ms = now_ms;
        self.bytes_responder = self.bytes_responder.saturating_add(bytes);
        self.packet_count = self.packet_count.saturating_add(1);
    }

    /// Advance the TCP state machine in response to a flag
    /// observation. The flag bits passed in are the standard
    /// RFC 793 flags as the kernel surfaces them: SYN=0x02,
    /// ACK=0x10, FIN=0x01, RST=0x04. Returns `true` if the
    /// state changed.
    pub fn advance_tcp(&mut self, tcp_flags: u8) -> bool {
        const SYN: u8 = 0x02;
        const ACK: u8 = 0x10;
        const FIN: u8 = 0x01;
        const RST: u8 = 0x04;
        let prior = self.conn_state;
        // RST short-circuits everything: the flow is dead.
        if tcp_flags & RST != 0 {
            self.conn_state = ConnState::Closed;
            return self.conn_state != prior;
        }
        self.conn_state = match (self.conn_state, tcp_flags) {
            (ConnState::SynSent, f) if f & SYN != 0 && f & ACK != 0 => ConnState::SynReceived,
            (ConnState::SynReceived, f) if f & ACK != 0 && f & SYN == 0 => ConnState::Established,
            // A plain ACK on a SynSent flow is unexpected
            // (the server should send SYN+ACK, not ACK
            // alone) but if it happens, treat the flow as
            // established defensively so we don't gate
            // legitimate traffic on a kernel ordering quirk.
            (ConnState::SynSent, f) if f & ACK != 0 => ConnState::Established,
            (ConnState::Established, f) if f & FIN != 0 => ConnState::Closing,
            // Closing -> Closed only on the peer's FIN, NOT
            // on a plain ACK. After one side sends FIN the
            // peer typically ACKs immediately and then keeps
            // sending data + ACKs in the half-closed window;
            // collapsing to Closed on the first ACK would
            // evict the conntrack entry mid-conversation
            // and split the flow's byte / verdict accounting
            // across a second flow entry on the next packet.
            // The accompanying FIN-from-the-peer (or a RST
            // handled above) is the legitimate Closed
            // trigger. Pinned by
            // `closing_state_holds_on_plain_ack` /
            // `closing_state_closes_on_peer_fin` tests.
            (ConnState::Closing, f) if f & FIN != 0 => ConnState::Closed,
            (other, _) => other,
        };
        self.conn_state != prior
    }

    /// Total bytes the responder has sent on the flow, used
    /// for `FlowEvent::bytes_in` semantics from the
    /// originator's perspective.
    #[must_use]
    pub const fn bytes_in(&self) -> u64 {
        self.bytes_responder
    }

    /// Total bytes the originator has sent on the flow, used
    /// for `FlowEvent::bytes_out` semantics.
    #[must_use]
    pub const fn bytes_out(&self) -> u64 {
        self.bytes_originator
    }

    /// Duration in milliseconds, suitable for
    /// `FlowEvent::duration_ms`. Saturates on `u32::MAX`
    /// because the event field is `u32` — a flow that's lived
    /// longer than ~49 days is implausible and capping is
    /// safer than wrapping.
    #[must_use]
    pub const fn duration_ms(&self) -> u32 {
        let raw = self.last_seen_ms.saturating_sub(self.start_ms);
        // `u32::try_from` would be cleaner but is non-const;
        // the cast below is the explicit equivalent — the
        // `if` branch guarantees `raw` already fits in u32
        // before the truncating `as` runs, so this is a
        // deliberate narrowing rather than the unchecked
        // silent-wrap clippy normally flags.
        if raw > u32::MAX as u64 {
            u32::MAX
        } else {
            #[allow(clippy::cast_possible_truncation)]
            {
                raw as u32
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn ip_protocol_wire_roundtrip() {
        for p in [
            IpProtocol::Tcp,
            IpProtocol::Udp,
            IpProtocol::Icmp,
            IpProtocol::Other(132),
        ] {
            // Icmp's wire form rounds to 1 (v4 ICMP) on output;
            // `from_wire(1)` and `from_wire(58)` both produce
            // `Icmp`, so 58 won't round-trip. That's fine; the
            // round-trip contract is "either v4 or v6 ICMP
            // produces the same `Icmp` variant" — pin both
            // halves explicitly below.
            assert_eq!(IpProtocol::from_wire(p.as_wire()), p);
        }
        // Explicit round-trip for the v6 ICMP wire value: the
        // single `Icmp` variant absorbs both 1 (ICMPv4) and 58
        // (ICMPv6) on the wire, so `from_wire(58)` lands on
        // the same variant as `from_wire(1)`.
        assert_eq!(IpProtocol::from_wire(58), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_wire(132), IpProtocol::Other(132));
    }

    #[test]
    fn flow_key_rejects_mixed_family() {
        let v6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let err = FlowKey::new(v4(1, 1, 1, 1), v6, 1234, 80, IpProtocol::Tcp)
            .expect_err("mixed family must be rejected");
        match err {
            FwError::FlowInvalid(msg) => assert!(msg.contains("mixed-family")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn flow_key_rejects_zero_ports_on_tcp() {
        let err = FlowKey::new(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 80, IpProtocol::Tcp)
            .expect_err("zero src port must be rejected");
        match err {
            FwError::FlowInvalid(msg) => assert!(msg.contains("zero source port")),
            other => panic!("unexpected error: {other:?}"),
        }
        let err = FlowKey::new(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 0, IpProtocol::Udp)
            .expect_err("zero dst port must be rejected");
        match err {
            FwError::FlowInvalid(msg) => assert!(msg.contains("zero destination port")),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn flow_key_allows_zero_ports_on_icmp() {
        // ICMP is portless; the validator must not reject a
        // (src=0, dst=0) ICMP flow.
        FlowKey::new(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 0, 0, IpProtocol::Icmp)
            .expect("ICMP flow without ports must be accepted");
    }

    #[test]
    fn flow_key_reverse_swaps_endpoints() {
        let k = FlowKey::new(v4(1, 1, 1, 1), v4(2, 2, 2, 2), 1234, 80, IpProtocol::Tcp).unwrap();
        let r = k.reverse();
        assert_eq!(r.source_ip, k.destination_ip);
        assert_eq!(r.destination_ip, k.source_ip);
        assert_eq!(r.source_port, k.destination_port);
        assert_eq!(r.destination_port, k.source_port);
        assert_eq!(r.protocol, k.protocol);
    }

    #[test]
    fn flow_key_to_event_fields_uses_canonical_text() {
        let k = FlowKey::new(v4(10, 0, 0, 1), v4(8, 8, 8, 8), 53000, 53, IpProtocol::Udp).unwrap();
        let s = k.to_event_fields();
        assert_eq!(s.src_ip, "10.0.0.1");
        assert_eq!(s.dst_ip, "8.8.8.8");
        assert_eq!(s.src_port, 53000);
        assert_eq!(s.dst_port, 53);
        assert_eq!(s.protocol, "udp");
    }

    #[test]
    fn conn_state_tcp_handshake_progression() {
        let mut s = FlowState::new(IpProtocol::Tcp, FlowDirection::Egress, 1_000);
        assert_eq!(s.conn_state, ConnState::SynSent);
        // Server returns SYN+ACK.
        assert!(s.advance_tcp(0x12));
        assert_eq!(s.conn_state, ConnState::SynReceived);
        // Client ACKs.
        assert!(s.advance_tcp(0x10));
        assert_eq!(s.conn_state, ConnState::Established);
        assert!(s.conn_state.is_live());
        // Half-close.
        assert!(s.advance_tcp(0x01)); // FIN
        assert_eq!(s.conn_state, ConnState::Closing);
        // Final FIN/ACK pair.
        assert!(s.advance_tcp(0x11)); // FIN+ACK
        assert_eq!(s.conn_state, ConnState::Closed);
        assert!(!s.conn_state.is_live());
    }

    #[test]
    fn closing_state_holds_on_plain_ack() {
        // Half-closed flow: client sent FIN, server ACKs the
        // FIN and keeps sending data (typical TCP half-close
        // window). The peer's bare ACK must NOT collapse the
        // flow to Closed — otherwise the conntrack sweeper
        // would evict the entry mid-conversation.
        let mut s = FlowState::new(IpProtocol::Tcp, FlowDirection::Egress, 1_000);
        // Walk into Established.
        s.advance_tcp(0x12); // SYN+ACK
        s.advance_tcp(0x10); // ACK
        assert_eq!(s.conn_state, ConnState::Established);
        // Client FIN -> Closing.
        s.advance_tcp(0x01);
        assert_eq!(s.conn_state, ConnState::Closing);
        // Server ACKs the FIN (plain ACK, no FIN of its own).
        // State must stay Closing.
        let changed = s.advance_tcp(0x10);
        assert!(!changed);
        assert_eq!(s.conn_state, ConnState::Closing);
        // Server keeps sending data + ACK; still Closing.
        let changed = s.advance_tcp(0x10);
        assert!(!changed);
        assert_eq!(s.conn_state, ConnState::Closing);
    }

    #[test]
    fn closing_state_closes_on_peer_fin() {
        // Half-closed flow finally completes with the peer's
        // FIN — this is the legitimate Closed trigger.
        let mut s = FlowState::new(IpProtocol::Tcp, FlowDirection::Egress, 1_000);
        s.advance_tcp(0x12);
        s.advance_tcp(0x10);
        s.advance_tcp(0x01); // client FIN -> Closing
        assert_eq!(s.conn_state, ConnState::Closing);
        // Peer FIN+ACK -> Closed.
        let changed = s.advance_tcp(0x11);
        assert!(changed);
        assert_eq!(s.conn_state, ConnState::Closed);
    }

    #[test]
    fn rst_short_circuits_to_closed() {
        let mut s = FlowState::new(IpProtocol::Tcp, FlowDirection::Egress, 1_000);
        // Established → RST.
        s.advance_tcp(0x12);
        s.advance_tcp(0x10);
        assert_eq!(s.conn_state, ConnState::Established);
        assert!(s.advance_tcp(0x04)); // RST
        assert_eq!(s.conn_state, ConnState::Closed);
    }

    #[test]
    fn stateless_protocols_start_established() {
        let s = FlowState::new(IpProtocol::Udp, FlowDirection::Egress, 1_000);
        assert_eq!(s.conn_state, ConnState::Established);
        let s = FlowState::new(IpProtocol::Icmp, FlowDirection::Lateral, 1_000);
        assert_eq!(s.conn_state, ConnState::Established);
    }

    #[test]
    fn duration_ms_saturates_on_overflow() {
        let mut s = FlowState::new(IpProtocol::Udp, FlowDirection::Egress, 0);
        // Force a > u32::MAX delta to verify the saturation.
        s.last_seen_ms = u64::from(u32::MAX) + 5_000;
        assert_eq!(s.duration_ms(), u32::MAX);
    }

    #[test]
    fn observe_increments_counters() {
        let mut s = FlowState::new(IpProtocol::Tcp, FlowDirection::Egress, 100);
        s.observe_originator(1500, 200);
        s.observe_responder(2400, 300);
        s.observe_originator(800, 400);
        assert_eq!(s.bytes_originator, 2_300);
        assert_eq!(s.bytes_responder, 2_400);
        assert_eq!(s.packet_count, 3);
        assert_eq!(s.last_seen_ms, 400);
        assert_eq!(s.bytes_out(), 2_300);
        assert_eq!(s.bytes_in(), 2_400);
        assert_eq!(s.duration_ms(), 300);
    }

    #[test]
    fn observe_saturates_on_overflow() {
        let mut s = FlowState::new(IpProtocol::Tcp, FlowDirection::Egress, 0);
        s.bytes_originator = u64::MAX - 1;
        s.observe_originator(10, 1);
        assert_eq!(s.bytes_originator, u64::MAX);
        s.packet_count = u64::MAX - 1;
        s.observe_originator(0, 2);
        assert_eq!(s.packet_count, u64::MAX);
    }
}

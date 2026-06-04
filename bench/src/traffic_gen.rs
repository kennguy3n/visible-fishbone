//! Synthetic traffic generation for the edge data-path benchmark.
//!
//! The crafting side ([`PacketBuilder`], the checksum helpers, the
//! 5-tuple sampler) is pure and allocation-free once constructed: it
//! writes a complete Ethernet + IP + L4 frame into a caller-owned,
//! bounded buffer and never heap-allocates per packet. That keeps the
//! generator off the measurement's critical path.
//!
//! The transmit side ([`RawSocketGenerator`]) wraps an `AF_PACKET`
//! `SOCK_RAW` socket bound to a NIC. Link-layer transmission requires a
//! `sockaddr_ll`, which has no safe constructor in `libc`/`socket2`;
//! that single conversion is the only `unsafe` in the crate and is
//! scoped to the [`raw`] submodule with a documented rationale. Every
//! other line is safe Rust.
//!
//! Both IPv4 and IPv6 are supported; UDP and a TCP-SYN flood are the two
//! L4 shapes (SYN is what stresses the edge's flow-table insertion path,
//! which the `concurrent-flows` mode exercises).

use std::net::{Ipv4Addr, Ipv6Addr};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use thiserror::Error;

/// Ethernet header length (dst + src MAC + ethertype), no 802.1Q tag.
pub const ETH_HLEN: usize = 14;
/// Minimum IPv4 header length (no options).
pub const IPV4_HLEN: usize = 20;
/// Fixed IPv6 header length.
pub const IPV6_HLEN: usize = 40;
/// UDP header length.
pub const UDP_HLEN: usize = 8;
/// Minimum TCP header length (no options).
pub const TCP_HLEN: usize = 20;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_TCP: u8 = 6;

/// Largest frame the crafter will build. The IPv4 total-length and IPv6
/// payload-length fields are 16-bit, so the IP portion of a frame cannot
/// exceed 65535 bytes without truncating that field; capping the whole
/// frame at `ETH_HLEN + 65535` keeps both within range.
pub const MAX_FRAME_SIZE: usize = ETH_HLEN + u16::MAX as usize;

/// Errors raised while generating or transmitting synthetic traffic.
#[derive(Debug, Error)]
pub enum TrafficError {
    /// The destination buffer was smaller than the frame to be built.
    #[error("buffer too small: need {needed} bytes, have {got}")]
    BufferTooSmall {
        /// Bytes required to hold the frame.
        needed: usize,
        /// Bytes available in the destination buffer.
        got: usize,
    },

    /// The requested wire packet size cannot hold the protocol headers.
    #[error("packet size {0} is smaller than the required headers")]
    PacketTooSmall(u32),

    /// The requested wire packet size exceeds the largest frame whose IP
    /// length field is representable in 16 bits ([`MAX_FRAME_SIZE`]).
    #[error("packet size {0} exceeds the maximum representable frame ({MAX_FRAME_SIZE})")]
    PacketTooLarge(u32),

    /// The operator-supplied generator config is invalid (empty subnet,
    /// inverted port range, zero-length MAC, ...).
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// A named network interface could not be resolved to an index.
    #[error("interface {0:?} not found")]
    InterfaceNotFound(String),

    /// A socket operation (create / bind / send) failed.
    #[error("socket: {0}")]
    Socket(#[from] std::io::Error),
}

/// IP version selector for the generated traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    /// IPv4 (ethertype 0x0800).
    V4,
    /// IPv6 (ethertype 0x86DD).
    V6,
}

/// L4 protocol shape for the generated traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    /// UDP datagrams (stateless throughput stress).
    Udp,
    /// TCP SYN segments (flow-table insertion stress).
    TcpSyn,
}

/// An IPv4 or IPv6 subnet the sampler draws source/destination addresses
/// from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subnet {
    /// IPv4 `base/prefix`.
    V4 {
        /// Network base address.
        base: Ipv4Addr,
        /// Prefix length, `0..=32`.
        prefix: u8,
    },
    /// IPv6 `base/prefix`.
    V6 {
        /// Network base address.
        base: Ipv6Addr,
        /// Prefix length, `0..=128`.
        prefix: u8,
    },
}

impl Subnet {
    fn ip_version(self) -> IpVersion {
        match self {
            Subnet::V4 { .. } => IpVersion::V4,
            Subnet::V6 { .. } => IpVersion::V6,
        }
    }
}

/// Samples randomized 5-tuples within configured subnets / port ranges.
#[derive(Debug)]
pub struct FiveTupleSampler {
    src: Subnet,
    dst: Subnet,
    src_ports: (u16, u16),
    dst_ports: (u16, u16),
    rng: StdRng,
}

/// A sampled 5-tuple (the L3/L4 selectors the edge keys flows on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FiveTuple {
    /// Source IP (v4 mapped into the low 32 bits for v4 subnets).
    pub src_ip: std::net::IpAddr,
    /// Destination IP.
    pub dst_ip: std::net::IpAddr,
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
}

impl FiveTupleSampler {
    /// Build a sampler. `src` and `dst` must be the same IP version and
    /// each port range must be non-empty (`lo <= hi`).
    ///
    /// # Errors
    /// Returns [`TrafficError::InvalidConfig`] on a mixed-family subnet
    /// pair or an inverted port range.
    pub fn new(
        src: Subnet,
        dst: Subnet,
        src_ports: (u16, u16),
        dst_ports: (u16, u16),
        seed: u64,
    ) -> Result<Self, TrafficError> {
        if src.ip_version() != dst.ip_version() {
            return Err(TrafficError::InvalidConfig(
                "source and destination subnets must be the same IP version".to_string(),
            ));
        }
        if src_ports.0 > src_ports.1 || dst_ports.0 > dst_ports.1 {
            return Err(TrafficError::InvalidConfig(
                "port range low bound exceeds high bound".to_string(),
            ));
        }
        Ok(Self {
            src,
            dst,
            src_ports,
            dst_ports,
            rng: StdRng::seed_from_u64(seed),
        })
    }

    /// The IP version this sampler emits.
    #[must_use]
    pub fn ip_version(&self) -> IpVersion {
        self.src.ip_version()
    }

    /// Draw the next randomized 5-tuple.
    pub fn next_tuple(&mut self) -> FiveTuple {
        let src_ip = sample_addr(self.src, &mut self.rng);
        let dst_ip = sample_addr(self.dst, &mut self.rng);
        let src_port = sample_port(self.src_ports, &mut self.rng);
        let dst_port = sample_port(self.dst_ports, &mut self.rng);
        FiveTuple {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }
}

fn sample_port(range: (u16, u16), rng: &mut StdRng) -> u16 {
    if range.0 == range.1 {
        range.0
    } else {
        rng.gen_range(range.0..=range.1)
    }
}

fn sample_addr(subnet: Subnet, rng: &mut StdRng) -> std::net::IpAddr {
    match subnet {
        Subnet::V4 { base, prefix } => {
            let base = u32::from(base);
            let host_bits = 32 - u32::from(prefix.min(32));
            let net_mask = if host_bits == 32 {
                0
            } else {
                u32::MAX << host_bits
            };
            let host_mask = !net_mask;
            let r: u32 = rng.r#gen();
            std::net::IpAddr::V4(Ipv4Addr::from((base & net_mask) | (r & host_mask)))
        }
        Subnet::V6 { base, prefix } => {
            let base = u128::from(base);
            let host_bits = 128 - u32::from(prefix.min(128));
            let net_mask = if host_bits == 128 {
                0
            } else {
                u128::MAX << host_bits
            };
            let host_mask = !net_mask;
            let r: u128 = rng.r#gen();
            std::net::IpAddr::V6(Ipv6Addr::from((base & net_mask) | (r & host_mask)))
        }
    }
}

/// Configuration for the packet crafter.
#[derive(Debug, Clone)]
pub struct PacketConfig {
    /// Total wire frame size (Ethernet header through payload, excluding
    /// the 4-byte FCS the NIC appends). 64, 512, 1500, 9000, ...
    pub frame_size: u32,
    /// L4 protocol shape.
    pub l4: L4Proto,
    /// Source MAC.
    pub src_mac: [u8; 6],
    /// Destination MAC (next-hop / edge ingress NIC).
    pub dst_mac: [u8; 6],
    /// IP TTL / hop limit.
    pub ttl: u8,
}

impl PacketConfig {
    /// Minimum frame size able to hold the headers for `version` + this
    /// config's L4 protocol.
    #[must_use]
    pub fn min_frame_size(&self, version: IpVersion) -> usize {
        let ip = match version {
            IpVersion::V4 => IPV4_HLEN,
            IpVersion::V6 => IPV6_HLEN,
        };
        let l4 = match self.l4 {
            L4Proto::Udp => UDP_HLEN,
            L4Proto::TcpSyn => TCP_HLEN,
        };
        ETH_HLEN + ip + l4
    }
}

/// Crafts complete Ethernet frames carrying randomized 5-tuples.
#[derive(Debug)]
pub struct PacketBuilder {
    config: PacketConfig,
    sampler: FiveTupleSampler,
    ip_id: u16,
}

impl PacketBuilder {
    /// Build a packet crafter.
    ///
    /// # Errors
    /// Returns [`TrafficError::PacketTooSmall`] if `config.frame_size`
    /// cannot hold the headers for the sampler's IP version, or
    /// [`TrafficError::PacketTooLarge`] if it exceeds [`MAX_FRAME_SIZE`].
    pub fn new(config: PacketConfig, sampler: FiveTupleSampler) -> Result<Self, TrafficError> {
        let min = config.min_frame_size(sampler.ip_version());
        if (config.frame_size as usize) < min {
            return Err(TrafficError::PacketTooSmall(config.frame_size));
        }
        if config.frame_size as usize > MAX_FRAME_SIZE {
            return Err(TrafficError::PacketTooLarge(config.frame_size));
        }
        Ok(Self {
            config,
            sampler,
            ip_id: 0,
        })
    }

    /// Number of bytes [`Self::next`] will write (the configured frame
    /// size).
    #[must_use]
    pub fn frame_len(&self) -> usize {
        self.config.frame_size as usize
    }

    /// Write the next frame into `buf`, returning the number of bytes
    /// written. The 5-tuple is freshly sampled per call.
    ///
    /// # Errors
    /// Returns [`TrafficError::BufferTooSmall`] if `buf` is shorter than
    /// the configured frame size.
    pub fn next(&mut self, buf: &mut [u8]) -> Result<usize, TrafficError> {
        let len = self.config.frame_size as usize;
        if buf.len() < len {
            return Err(TrafficError::BufferTooSmall {
                needed: len,
                got: buf.len(),
            });
        }
        let tuple = self.sampler.next_tuple();
        self.ip_id = self.ip_id.wrapping_add(1);
        let frame = &mut buf[..len];
        // Zero the whole frame first so the payload tail is deterministic
        // padding regardless of any previous contents.
        frame.fill(0);
        match tuple.src_ip {
            std::net::IpAddr::V4(_) => self.write_ipv4(frame, tuple),
            std::net::IpAddr::V6(_) => self.write_ipv6(frame, tuple),
        }
        Ok(len)
    }

    fn write_eth(&self, frame: &mut [u8], ethertype: u16) {
        frame[0..6].copy_from_slice(&self.config.dst_mac);
        frame[6..12].copy_from_slice(&self.config.src_mac);
        frame[12..14].copy_from_slice(&ethertype.to_be_bytes());
    }

    fn write_ipv4(&self, frame: &mut [u8], tuple: FiveTuple) {
        self.write_eth(frame, ETHERTYPE_IPV4);
        // Builder dispatch guarantees both addresses are v4.
        let (std::net::IpAddr::V4(src), std::net::IpAddr::V4(dst)) = (tuple.src_ip, tuple.dst_ip)
        else {
            unreachable!("ipv4 path with non-v4 tuple");
        };
        let proto = self.l4_proto_num();
        let ip = &mut frame[ETH_HLEN..];
        let total_len = (ip.len()) as u16; // IP total length = everything after the eth header
        ip[0] = (4 << 4) | 5; // version 4, IHL 5 (20 bytes)
        ip[1] = 0; // DSCP/ECN
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[4..6].copy_from_slice(&self.ip_id.to_be_bytes());
        ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF set, no fragment
        ip[8] = self.config.ttl;
        ip[9] = proto;
        // ip[10..12] checksum left 0 for computation
        ip[12..16].copy_from_slice(&src.octets());
        ip[16..20].copy_from_slice(&dst.octets());
        let csum = internet_checksum(&ip[..IPV4_HLEN]);
        ip[10..12].copy_from_slice(&csum.to_be_bytes());

        let l4_off = ETH_HLEN + IPV4_HLEN;
        let l4_len = frame.len() - l4_off;
        self.write_l4(frame, l4_off, l4_len, tuple, IpProto::V4 { src, dst });
    }

    fn write_ipv6(&self, frame: &mut [u8], tuple: FiveTuple) {
        self.write_eth(frame, ETHERTYPE_IPV6);
        // Builder dispatch guarantees both addresses are v6.
        let (std::net::IpAddr::V6(src), std::net::IpAddr::V6(dst)) = (tuple.src_ip, tuple.dst_ip)
        else {
            unreachable!("ipv6 path with non-v6 tuple");
        };
        let proto = self.l4_proto_num();
        let payload_len = (frame.len() - ETH_HLEN - IPV6_HLEN) as u16;
        let ip = &mut frame[ETH_HLEN..];
        ip[0] = 6 << 4; // version 6, traffic class / flow label zero
        ip[4..6].copy_from_slice(&payload_len.to_be_bytes());
        ip[6] = proto; // next header
        ip[7] = self.config.ttl; // hop limit
        ip[8..24].copy_from_slice(&src.octets());
        ip[24..40].copy_from_slice(&dst.octets());

        let l4_off = ETH_HLEN + IPV6_HLEN;
        let l4_len = frame.len() - l4_off;
        self.write_l4(frame, l4_off, l4_len, tuple, IpProto::V6 { src, dst });
    }

    fn l4_proto_num(&self) -> u8 {
        match self.config.l4 {
            L4Proto::Udp => IPPROTO_UDP,
            L4Proto::TcpSyn => IPPROTO_TCP,
        }
    }

    fn write_l4(&self, frame: &mut [u8], off: usize, l4_len: usize, tuple: FiveTuple, ip: IpProto) {
        match self.config.l4 {
            L4Proto::Udp => {
                let seg = &mut frame[off..off + l4_len];
                seg[0..2].copy_from_slice(&tuple.src_port.to_be_bytes());
                seg[2..4].copy_from_slice(&tuple.dst_port.to_be_bytes());
                seg[4..6].copy_from_slice(&(l4_len as u16).to_be_bytes());
                // checksum (seg[6..8]) left zero for computation
                let csum = l4_checksum(ip, IPPROTO_UDP, seg);
                // RFC 768: a computed UDP checksum of 0 is transmitted as
                // all-ones so the receiver does not read it as "no checksum".
                let csum = if csum == 0 { 0xFFFF } else { csum };
                seg[6..8].copy_from_slice(&csum.to_be_bytes());
            }
            L4Proto::TcpSyn => {
                let seg = &mut frame[off..off + l4_len];
                seg[0..2].copy_from_slice(&tuple.src_port.to_be_bytes());
                seg[2..4].copy_from_slice(&tuple.dst_port.to_be_bytes());
                // sequence number: reuse ip_id-derived entropy so each SYN
                // looks like a fresh connection attempt.
                seg[4..8].copy_from_slice(&u32::from(self.ip_id).to_be_bytes());
                // ack number zero (seg[8..12])
                seg[12] = 5 << 4; // data offset 5 (20 bytes), reserved 0
                seg[13] = 0x02; // SYN flag
                seg[14..16].copy_from_slice(&64240u16.to_be_bytes()); // window
                // checksum (seg[16..18]) left zero for computation
                // urgent pointer (seg[18..20]) zero
                let csum = l4_checksum(ip, IPPROTO_TCP, seg);
                seg[16..18].copy_from_slice(&csum.to_be_bytes());
            }
        }
    }
}

/// IP-layer source/destination used to build the L4 pseudo-header.
#[derive(Debug, Clone, Copy)]
enum IpProto {
    V4 { src: Ipv4Addr, dst: Ipv4Addr },
    V6 { src: Ipv6Addr, dst: Ipv6Addr },
}

/// Standard 16-bit one's-complement Internet checksum (RFC 1071) over an
/// even-or-odd-length byte slice.
#[must_use]
pub fn internet_checksum(data: &[u8]) -> u16 {
    fold_checksum(accumulate(0, data))
}

fn accumulate(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
    }
    if let [last] = chunks.remainder() {
        // Odd trailing byte is treated as the high byte of a 16-bit word.
        sum += u32::from(*last) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Compute a transport-layer checksum (UDP/TCP) over the pseudo-header
/// plus the L4 segment. The segment's own checksum field must be zero on
/// entry.
fn l4_checksum(ip: IpProto, proto: u8, segment: &[u8]) -> u16 {
    // The one's-complement sum is associative over 16-bit words, so a
    // 32-bit addend folds to the same result as summing its two BE
    // halves; `proto` sits in the low byte of an otherwise-zero word.
    // That lets us add `len`/`proto` directly instead of serializing the
    // pseudo-header fields. `fold_checksum` carries the high half back in.
    let mut sum = 0u32;
    match ip {
        IpProto::V4 { src, dst } => {
            sum = accumulate(sum, &src.octets());
            sum = accumulate(sum, &dst.octets());
            sum += u32::from(proto);
            sum += segment.len() as u32;
        }
        IpProto::V6 { src, dst } => {
            sum = accumulate(sum, &src.octets());
            sum = accumulate(sum, &dst.octets());
            // 32-bit upper-layer length, then 3 zero bytes + next header.
            sum += segment.len() as u32;
            sum += u32::from(proto);
        }
    }
    sum = accumulate(sum, segment);
    fold_checksum(sum)
}

/// Abstraction over a source of synthetic frames.
///
/// The trait is object-safe so the harness can hold a
/// `Box<dyn TrafficGenerator>` chosen at runtime (a live raw-socket
/// transmitter, or an in-process dry-run crafter).
pub trait TrafficGenerator: std::fmt::Debug {
    /// Produce the next frame and return the number of wire bytes it
    /// represents. A live generator transmits the frame; a dry-run
    /// generator crafts it into an internal buffer and discards it.
    ///
    /// # Errors
    /// Returns [`TrafficError`] if crafting fails or the underlying
    /// transmit path errors.
    fn emit(&mut self) -> Result<usize, TrafficError>;

    /// The exact size in bytes of every frame this generator produces.
    fn frame_len(&self) -> usize;

    /// Emit a burst of `count` frames, returning the total wire bytes.
    /// Stops and returns the first error encountered.
    ///
    /// # Errors
    /// Propagates the first [`TrafficError`] from [`Self::emit`].
    fn emit_burst(&mut self, count: u64) -> Result<u64, TrafficError> {
        let mut bytes = 0u64;
        for _ in 0..count {
            bytes += self.emit()? as u64;
        }
        Ok(bytes)
    }
}

/// An in-process generator that crafts frames into a reusable buffer but
/// never transmits them — used by `--dry-run` to exercise the full
/// craft + measure + report pipeline on an unprivileged runner.
#[derive(Debug)]
pub struct DryRunGenerator {
    builder: PacketBuilder,
    scratch: Vec<u8>,
}

impl DryRunGenerator {
    /// Wrap a [`PacketBuilder`], pre-allocating its scratch buffer.
    #[must_use]
    pub fn new(builder: PacketBuilder) -> Self {
        let scratch = vec![0u8; builder.frame_len()];
        Self { builder, scratch }
    }
}

impl TrafficGenerator for DryRunGenerator {
    fn emit(&mut self) -> Result<usize, TrafficError> {
        self.builder.next(&mut self.scratch)
    }

    fn frame_len(&self) -> usize {
        self.builder.frame_len()
    }
}

/// An `AF_PACKET` raw-socket transmitter bound to a NIC.
///
/// Owns the crafting [`PacketBuilder`] plus a single reusable scratch
/// buffer, so steady-state transmission performs no heap allocation.
#[derive(Debug)]
pub struct RawSocketGenerator {
    socket: socket2::Socket,
    dest: socket2::SockAddr,
    builder: PacketBuilder,
    scratch: Vec<u8>,
}

impl RawSocketGenerator {
    /// Open an `AF_PACKET`/`SOCK_RAW` socket bound to interface `ifname`
    /// and prepare it to transmit frames from `builder`.
    ///
    /// # Errors
    /// Returns [`TrafficError::InterfaceNotFound`] if `ifname` does not
    /// resolve, or [`TrafficError::Socket`] on a socket/bind failure
    /// (notably `EPERM` when the harness lacks `CAP_NET_RAW`).
    pub fn open(ifname: &str, builder: PacketBuilder) -> Result<Self, TrafficError> {
        let ifindex = raw::if_index(ifname)?;
        let socket = raw::open_packet_socket(ifindex)?;
        let dest = raw::link_layer_sockaddr(ifindex, builder.config.dst_mac);
        let scratch = vec![0u8; builder.frame_len()];
        Ok(Self {
            socket,
            dest,
            builder,
            scratch,
        })
    }
}

impl TrafficGenerator for RawSocketGenerator {
    fn emit(&mut self) -> Result<usize, TrafficError> {
        let len = self.builder.next(&mut self.scratch)?;
        let sent = self.socket.send_to(&self.scratch[..len], &self.dest)?;
        Ok(sent)
    }

    fn frame_len(&self) -> usize {
        self.builder.frame_len()
    }
}

/// Raw `AF_PACKET` plumbing.
///
/// This is the crate's only `unsafe`. Linux link-layer transmission
/// requires a `sockaddr_ll`, for which neither `libc` nor `socket2`
/// exposes a safe constructor, and `if_nametoindex(3)` takes a C string
/// pointer. Both operations are confined here, each `unsafe` block is
/// individually justified, and nothing raw escapes the module: callers
/// only ever see a `socket2::Socket` and a `socket2::SockAddr`.
mod raw {
    use super::TrafficError;

    /// Resolve an interface name to its kernel index via
    /// `if_nametoindex(3)`.
    pub(super) fn if_index(name: &str) -> Result<u32, TrafficError> {
        let cname = std::ffi::CString::new(name)
            .map_err(|_| TrafficError::InvalidConfig("interface name has a NUL byte".into()))?;
        // SAFETY: `cname` is a valid NUL-terminated C string that outlives
        // the call; `if_nametoindex` only reads from the pointer and
        // returns 0 on failure (no errno contract we rely on beyond that).
        #[allow(unsafe_code)]
        let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
        if idx == 0 {
            return Err(TrafficError::InterfaceNotFound(name.to_string()));
        }
        Ok(idx)
    }

    /// Create an `AF_PACKET`/`SOCK_RAW` socket bound to `ifindex`.
    pub(super) fn open_packet_socket(ifindex: u32) -> Result<socket2::Socket, TrafficError> {
        let socket = socket2::Socket::new(
            socket2::Domain::from(libc::AF_PACKET),
            socket2::Type::from(libc::SOCK_RAW),
            Some(socket2::Protocol::from(i32::from(
                (libc::ETH_P_ALL as u16).to_be(),
            ))),
        )?;
        socket.bind(&link_layer_sockaddr(ifindex, [0u8; 6]))?;
        Ok(socket)
    }

    /// Build a `sockaddr_ll` for `ifindex` targeting `dst_mac`, wrapped in
    /// a `socket2::SockAddr`.
    pub(super) fn link_layer_sockaddr(ifindex: u32, dst_mac: [u8; 6]) -> socket2::SockAddr {
        // SAFETY: `try_init` zeroes a `sockaddr_storage` and hands us a
        // pointer to it. `sockaddr_ll` is smaller than `sockaddr_storage`
        // (`view_as` asserts this), we initialise exactly the link-layer
        // fields, and we report the correct length, satisfying the
        // family/length contract `SockAddr::new` requires.
        #[allow(unsafe_code)]
        let ((), addr) = unsafe {
            socket2::SockAddr::try_init(|storage, len| {
                let sll = storage.cast::<libc::sockaddr_ll>().as_mut().unwrap();
                sll.sll_family = libc::AF_PACKET as u16;
                sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
                sll.sll_ifindex = ifindex as i32;
                sll.sll_halen = 6;
                sll.sll_addr[..6].copy_from_slice(&dst_mac);
                *len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
                Ok(())
            })
        }
        // try_init only fails if the closure returns Err, which it never
        // does here.
        .expect("sockaddr_ll initialisation is infallible");
        addr
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4_sampler(prefix: u8) -> FiveTupleSampler {
        FiveTupleSampler::new(
            Subnet::V4 {
                base: Ipv4Addr::new(10, 0, 0, 0),
                prefix,
            },
            Subnet::V4 {
                base: Ipv4Addr::new(192, 168, 1, 0),
                prefix,
            },
            (1024, 1024),
            (80, 80),
            42,
        )
        .unwrap()
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        // RFC 1071 worked example bytes; the folded one's-complement of
        // this sequence is 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(internet_checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_handles_odd_length() {
        // Must not panic and must fold the trailing byte as a high byte.
        let even = internet_checksum(&[0x12, 0x34, 0x56, 0x00]);
        let odd = internet_checksum(&[0x12, 0x34, 0x56]);
        assert_eq!(even, odd);
    }

    #[test]
    fn sampler_stays_within_v4_prefix() {
        let mut s = v4_sampler(24);
        for _ in 0..500 {
            let t = s.next_tuple();
            match t.src_ip {
                std::net::IpAddr::V4(ip) => {
                    let o = ip.octets();
                    assert_eq!([o[0], o[1], o[2]], [10, 0, 0]);
                }
                std::net::IpAddr::V6(_) => panic!("expected v4"),
            }
            assert_eq!(t.src_port, 1024);
            assert_eq!(t.dst_port, 80);
        }
    }

    #[test]
    fn sampler_rejects_mixed_family() {
        let r = FiveTupleSampler::new(
            Subnet::V4 {
                base: Ipv4Addr::UNSPECIFIED,
                prefix: 24,
            },
            Subnet::V6 {
                base: Ipv6Addr::UNSPECIFIED,
                prefix: 64,
            },
            (1, 2),
            (1, 2),
            0,
        );
        assert!(r.is_err());
    }

    #[test]
    fn sampler_rejects_inverted_port_range() {
        let r = FiveTupleSampler::new(
            Subnet::V4 {
                base: Ipv4Addr::UNSPECIFIED,
                prefix: 24,
            },
            Subnet::V4 {
                base: Ipv4Addr::UNSPECIFIED,
                prefix: 24,
            },
            (200, 100),
            (1, 2),
            0,
        );
        assert!(r.is_err());
    }

    fn cfg(frame_size: u32, l4: L4Proto) -> PacketConfig {
        PacketConfig {
            frame_size,
            l4,
            src_mac: [0x02, 0, 0, 0, 0, 1],
            dst_mac: [0x02, 0, 0, 0, 0, 2],
            ttl: 64,
        }
    }

    #[test]
    fn builder_rejects_undersized_frame() {
        // 40 bytes cannot hold eth(14)+ipv4(20)+udp(8) = 42.
        let r = PacketBuilder::new(cfg(40, L4Proto::Udp), v4_sampler(24));
        assert!(matches!(r, Err(TrafficError::PacketTooSmall(40))));
    }

    #[test]
    fn builder_rejects_oversized_frame() {
        // One byte past the largest representable IP length field.
        let size = (MAX_FRAME_SIZE + 1) as u32;
        let r = PacketBuilder::new(cfg(size, L4Proto::Udp), v4_sampler(24));
        assert!(matches!(r, Err(TrafficError::PacketTooLarge(s)) if s == size));
        // The boundary itself is accepted.
        assert!(
            PacketBuilder::new(cfg(MAX_FRAME_SIZE as u32, L4Proto::Udp), v4_sampler(24)).is_ok()
        );
    }

    #[test]
    fn builder_rejects_small_output_buffer() {
        let mut b = PacketBuilder::new(cfg(64, L4Proto::Udp), v4_sampler(24)).unwrap();
        let mut buf = [0u8; 32];
        assert!(matches!(
            b.next(&mut buf),
            Err(TrafficError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn ipv4_udp_frame_is_well_formed() {
        let mut b = PacketBuilder::new(cfg(64, L4Proto::Udp), v4_sampler(24)).unwrap();
        let mut buf = [0u8; 64];
        let len = b.next(&mut buf).unwrap();
        assert_eq!(len, 64);

        // Ethertype IPv4.
        assert_eq!(u16::from_be_bytes([buf[12], buf[13]]), ETHERTYPE_IPV4);
        let ip = &buf[ETH_HLEN..];
        assert_eq!(ip[0] >> 4, 4); // version
        assert_eq!(ip[0] & 0x0f, 5); // IHL
        assert_eq!(ip[9], IPPROTO_UDP);
        // IP total length = 64 - 14 = 50.
        assert_eq!(u16::from_be_bytes([ip[2], ip[3]]), 50);
        // Header checksum verifies to zero over the 20-byte header.
        assert_eq!(internet_checksum(&ip[..IPV4_HLEN]), 0);
        // UDP length = 50 - 20 = 30.
        let udp = &ip[IPV4_HLEN..];
        assert_eq!(u16::from_be_bytes([udp[4], udp[5]]), 30);
        // UDP checksum is non-zero (computed, then 0 mapped to 0xffff).
        assert_ne!(u16::from_be_bytes([udp[6], udp[7]]), 0);
    }

    #[test]
    fn ipv4_udp_checksum_verifies_over_pseudo_header() {
        let mut b = PacketBuilder::new(cfg(128, L4Proto::Udp), v4_sampler(24)).unwrap();
        let mut buf = [0u8; 128];
        b.next(&mut buf).unwrap();
        let ip = &buf[ETH_HLEN..];
        let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
        let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
        let seg = &ip[IPV4_HLEN..];
        // Recomputing the checksum over the segment that already carries
        // its checksum must verify to zero (the all-ones special case
        // cannot occur here because the field is already populated).
        let verify = l4_checksum(IpProto::V4 { src, dst }, IPPROTO_UDP, seg);
        assert_eq!(verify, 0);
    }

    #[test]
    fn ipv6_tcp_syn_frame_is_well_formed() {
        let sampler = FiveTupleSampler::new(
            Subnet::V6 {
                base: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                prefix: 64,
            },
            Subnet::V6 {
                base: Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0),
                prefix: 64,
            },
            (1024, 2048),
            (443, 443),
            7,
        )
        .unwrap();
        let mut b = PacketBuilder::new(cfg(128, L4Proto::TcpSyn), sampler).unwrap();
        let mut buf = [0u8; 128];
        b.next(&mut buf).unwrap();

        assert_eq!(u16::from_be_bytes([buf[12], buf[13]]), ETHERTYPE_IPV6);
        let ip = &buf[ETH_HLEN..];
        assert_eq!(ip[0] >> 4, 6); // version
        assert_eq!(ip[6], IPPROTO_TCP); // next header
        // Payload length = 128 - 14 - 40 = 74.
        assert_eq!(u16::from_be_bytes([ip[4], ip[5]]), 74);

        let src = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[8..24]).unwrap());
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&ip[24..40]).unwrap());
        let seg = &ip[IPV6_HLEN..];
        // SYN flag set.
        assert_eq!(seg[13] & 0x02, 0x02);
        // TCP checksum verifies to zero over the v6 pseudo-header.
        assert_eq!(l4_checksum(IpProto::V6 { src, dst }, IPPROTO_TCP, seg), 0);
    }

    #[test]
    fn frames_are_deterministic_for_a_fixed_seed() {
        let mut a = PacketBuilder::new(cfg(64, L4Proto::Udp), v4_sampler(16)).unwrap();
        let mut b = PacketBuilder::new(cfg(64, L4Proto::Udp), v4_sampler(16)).unwrap();
        let mut ba = [0u8; 64];
        let mut bb = [0u8; 64];
        for _ in 0..10 {
            a.next(&mut ba).unwrap();
            b.next(&mut bb).unwrap();
            assert_eq!(ba, bb, "same seed must yield identical frames");
        }
    }
}

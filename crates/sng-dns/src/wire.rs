//! RFC 1035 DNS wire-format encoder / decoder.
//!
//! The subset implemented here is what the agent needs to drive
//! a recursive resolver and inspect its answer:
//!
//! - 12-byte fixed header
//! - QNAME / QTYPE / QCLASS for a single question
//! - Answer section parse for A / AAAA / CNAME / TXT / HTTPS /
//!   PTR / etc. (we surface RDATA bytes verbatim and let the
//!   filter chain interpret type-specific RDATA)
//! - Message compression pointers (read-side; the writer never
//!   compresses because the agent only emits single-question
//!   queries with one short QNAME)
//!
//! We deliberately do not implement DNSSEC RRSIG / NSEC / DNSKEY
//! parsing here — the recursive resolver does DNSSEC validation
//! upstream of us, and the filter chain operates on names, not on
//! signed RRSIG chains.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::DnsError;
use crate::qtype::{QType, RCode};

/// RFC 1035 §3.2.4 — the `IN` (Internet) class. Every query the
/// agent originates is `IN`; we surface the constant so other
/// modules in the crate do not litter magic numbers around.
pub const CLASS_IN: u16 = 1;

/// Parsed DNS message header (RFC 1035 §4.1.1).
///
/// The four bool fields (`qr`, `tc`, `rd`, `ra`) are the
/// single-bit flags of the protocol's second header word. They
/// are inherently boolean by the wire spec, not a refactorable
/// state machine, so the `struct_excessive_bools` clippy lint is
/// silenced here with a justification: this struct mirrors the
/// RFC, not domain state.
#[allow(clippy::struct_excessive_bools)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Transaction ID. Random per query; copied verbatim onto
    /// the response.
    pub id: u16,
    /// Bit 15 of the second header word. False = query, true =
    /// response.
    pub qr: bool,
    /// Truncation flag.
    pub tc: bool,
    /// Recursion desired (set by client).
    pub rd: bool,
    /// Recursion available (set by server).
    pub ra: bool,
    /// 4-bit RCODE.
    pub rcode: RCode,
    /// Question count.
    pub qd_count: u16,
    /// Answer count.
    pub an_count: u16,
    /// Authority count.
    pub ns_count: u16,
    /// Additional count.
    pub ar_count: u16,
}

/// A single resource record from the answer section.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Owner name in dotted form (decompressed at parse time).
    pub name: String,
    /// Type code.
    pub rtype: QType,
    /// Class. Almost always [`CLASS_IN`].
    pub class: u16,
    /// TTL in seconds.
    pub ttl: u32,
    /// Raw RDATA bytes. Type-specific interpretation is the
    /// caller's responsibility.
    pub rdata: Vec<u8>,
}

impl Record {
    /// Interpret RDATA as IPv4 if `rtype == A`. Returns `None`
    /// for any other type or malformed RDATA length.
    #[must_use]
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.rtype != QType::A || self.rdata.len() != 4 {
            return None;
        }
        Some(Ipv4Addr::new(
            self.rdata[0],
            self.rdata[1],
            self.rdata[2],
            self.rdata[3],
        ))
    }

    /// Interpret RDATA as IPv6 if `rtype == AAAA`. Returns
    /// `None` for any other type or malformed RDATA length.
    #[must_use]
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rtype != QType::Aaaa || self.rdata.len() != 16 {
            return None;
        }
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&self.rdata);
        Some(Ipv6Addr::from(octets))
    }

    /// Interpret as a generic IP address (A or AAAA). Returns
    /// `None` if the record is neither.
    #[must_use]
    pub fn as_ip(&self) -> Option<IpAddr> {
        self.as_ipv4()
            .map(IpAddr::V4)
            .or_else(|| self.as_ipv6().map(IpAddr::V6))
    }
}

/// Encode a single-question query. The agent only ever asks one
/// question per packet (RFC 1035 §4.1.2 technically allows more
/// but no recursive resolver supports it correctly in 2024).
///
/// The recursion-desired bit is set, OPT (EDNS0) is NOT
/// appended — the recursive resolver in front of us is expected
/// to be doing the larger-message coordination upstream.
///
/// # Errors
///
/// Returns [`DnsError::QueryInvalid`] for names that violate
/// RFC 1035 limits: empty label, label longer than 63 octets,
/// total wire length over 255 octets, or a label containing the
/// reserved top-two bits.
pub fn encode_query(id: u16, name: &str, qtype: QType) -> Result<Vec<u8>, DnsError> {
    let qname = encode_name(name)?;
    let mut buf = Vec::with_capacity(12 + qname.len() + 4);

    // Header — RD set, everything else cleared. 1 question, 0 of
    // everything else.
    buf.extend_from_slice(&id.to_be_bytes());
    buf.extend_from_slice(&0x0100u16.to_be_bytes()); // RD=1
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    buf.extend_from_slice(&qname);
    buf.extend_from_slice(&qtype.to_wire().to_be_bytes());
    buf.extend_from_slice(&CLASS_IN.to_be_bytes());

    Ok(buf)
}

/// Decode the header section of a DNS message. The remaining
/// sections are parsed lazily via [`parse_question`] and
/// [`parse_records`].
///
/// # Errors
///
/// Returns [`DnsError::WireFormat`] if the buffer is shorter
/// than 12 bytes.
// The four section counters (`qd_count`, `an_count`, `ns_count`,
// `ar_count`) and the flag bits (`qr`, `rd`, `ra`) match the
// names in RFC 1035 §4.1.1. Renaming any of them to please
// clippy's similar-names heuristic would drift the code away
// from the spec a reader has open alongside it, so the lint is
// silenced at the function level with a justification rather
// than per-binding.
#[allow(clippy::similar_names)]
pub fn parse_header(buf: &[u8]) -> Result<Header, DnsError> {
    if buf.len() < 12 {
        return Err(DnsError::WireFormat(format!(
            "header truncated: {} < 12",
            buf.len()
        )));
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let qr = (flags & 0x8000) != 0;
    let tc = (flags & 0x0200) != 0;
    let rd = (flags & 0x0100) != 0;
    let ra = (flags & 0x0080) != 0;
    let rcode = RCode::from_wire(u8::try_from(flags & 0x000F).unwrap_or(0));
    let qd_count = u16::from_be_bytes([buf[4], buf[5]]);
    let an_count = u16::from_be_bytes([buf[6], buf[7]]);
    let ns_count = u16::from_be_bytes([buf[8], buf[9]]);
    let ar_count = u16::from_be_bytes([buf[10], buf[11]]);

    Ok(Header {
        id,
        qr,
        tc,
        rd,
        ra,
        rcode,
        qd_count,
        an_count,
        ns_count,
        ar_count,
    })
}

/// Parse the question section. Returns the (decompressed) qname,
/// qtype, qclass, and the absolute message offset of the next
/// byte to read.
///
/// # Errors
///
/// Returns [`DnsError::WireFormat`] on truncated or malformed
/// input.
pub fn parse_question(buf: &[u8], offset: usize) -> Result<(String, QType, u16, usize), DnsError> {
    let (name, next) = parse_name(buf, offset)?;
    if next + 4 > buf.len() {
        return Err(DnsError::WireFormat("question truncated".into()));
    }
    let qtype = QType::from_wire(u16::from_be_bytes([buf[next], buf[next + 1]]));
    let qclass = u16::from_be_bytes([buf[next + 2], buf[next + 3]]);
    Ok((name, qtype, qclass, next + 4))
}

/// Parse `count` resource records starting at `offset`. Returns
/// the parsed records and the absolute offset of the next byte.
///
/// # Errors
///
/// Returns [`DnsError::WireFormat`] on truncated or malformed
/// input.
pub fn parse_records(
    buf: &[u8],
    offset: usize,
    count: u16,
) -> Result<(Vec<Record>, usize), DnsError> {
    let mut out = Vec::with_capacity(count as usize);
    let mut pos = offset;
    for _ in 0..count {
        let (name, next) = parse_name(buf, pos)?;
        if next + 10 > buf.len() {
            return Err(DnsError::WireFormat("record header truncated".into()));
        }
        let rtype = QType::from_wire(u16::from_be_bytes([buf[next], buf[next + 1]]));
        let class = u16::from_be_bytes([buf[next + 2], buf[next + 3]]);
        let ttl = u32::from_be_bytes([buf[next + 4], buf[next + 5], buf[next + 6], buf[next + 7]]);
        let rdlen = u16::from_be_bytes([buf[next + 8], buf[next + 9]]) as usize;
        let rdata_start = next + 10;
        let rdata_end = rdata_start + rdlen;
        if rdata_end > buf.len() {
            return Err(DnsError::WireFormat(format!(
                "rdata truncated: rdlen={rdlen}, remaining={}",
                buf.len() - rdata_start
            )));
        }
        out.push(Record {
            name,
            rtype,
            class,
            ttl,
            rdata: buf[rdata_start..rdata_end].to_vec(),
        });
        pos = rdata_end;
    }
    Ok((out, pos))
}

/// RFC 1035 §3.1 — encode a dotted name into the wire form
/// (length-prefixed labels, terminating null).
fn encode_name(name: &str) -> Result<Vec<u8>, DnsError> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(DnsError::QueryInvalid("empty name".into()));
    }
    let mut buf = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(DnsError::QueryInvalid("empty label".into()));
        }
        let bytes = label.as_bytes();
        if bytes.len() > 63 {
            return Err(DnsError::QueryInvalid(format!(
                "label too long: {} > 63",
                bytes.len()
            )));
        }
        let len_byte = u8::try_from(bytes.len()).map_err(|_| {
            // Unreachable given the > 63 check above, but the
            // explicit error preserves the invariant under
            // future refactors.
            DnsError::QueryInvalid("label length out of u8 range".into())
        })?;
        if len_byte & 0xC0 != 0 {
            return Err(DnsError::QueryInvalid(
                "label length top bits reserved".into(),
            ));
        }
        buf.push(len_byte);
        buf.extend_from_slice(bytes);
    }
    buf.push(0);
    if buf.len() > 255 {
        return Err(DnsError::QueryInvalid(format!(
            "name too long: {} > 255",
            buf.len()
        )));
    }
    Ok(buf)
}

/// RFC 1035 §3.1 / §4.1.4 — decode a name with compression
/// pointer support. Returns the dotted name and the absolute
/// offset of the byte AFTER the original name's terminator (the
/// post-pointer offset, NOT the offset the pointer pointed to).
fn parse_name(buf: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut out = String::new();
    let mut pos = start;
    let mut next_after_pointer: Option<usize> = None;
    let mut jumps = 0;
    loop {
        if pos >= buf.len() {
            return Err(DnsError::WireFormat("name extends past message".into()));
        }
        let byte = buf[pos];
        if byte == 0 {
            pos += 1;
            break;
        }
        if byte & 0xC0 == 0xC0 {
            // Compression pointer: 14 bits of offset.
            if pos + 1 >= buf.len() {
                return Err(DnsError::WireFormat("name pointer truncated".into()));
            }
            let target = usize::from(u16::from_be_bytes([byte & 0x3F, buf[pos + 1]]));
            if target >= buf.len() {
                return Err(DnsError::WireFormat(format!(
                    "name pointer out of range: {target} >= {}",
                    buf.len()
                )));
            }
            if next_after_pointer.is_none() {
                next_after_pointer = Some(pos + 2);
            }
            pos = target;
            jumps += 1;
            // Bound the number of jumps so a maliciously
            // crafted self-referential pointer chain cannot
            // wedge the parser. 32 is well above any
            // legitimate message — names are at most 127
            // labels and the longest legitimate compression
            // chain is one level deep in practice.
            if jumps > 32 {
                return Err(DnsError::WireFormat(
                    "name compression chain too deep".into(),
                ));
            }
            continue;
        }
        if byte & 0xC0 != 0 {
            return Err(DnsError::WireFormat(
                "label length top bits reserved".into(),
            ));
        }
        let len = byte as usize;
        let label_start = pos + 1;
        let label_end = label_start + len;
        if label_end > buf.len() {
            return Err(DnsError::WireFormat("label extends past message".into()));
        }
        let label = std::str::from_utf8(&buf[label_start..label_end])
            .map_err(|_| DnsError::WireFormat("label not UTF-8".into()))?;
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(label);
        pos = label_end;
        if out.len() > 255 {
            return Err(DnsError::WireFormat("name too long".into()));
        }
    }
    let next = next_after_pointer.unwrap_or(pos);
    Ok((out, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qtype::QType;

    #[test]
    fn encode_query_basic() {
        let buf = encode_query(0x1234, "example.com", QType::A).expect("encode");
        // Header: id=1234, flags=0100 (RD), 1/0/0/0
        assert_eq!(&buf[0..2], &[0x12, 0x34]);
        assert_eq!(&buf[2..4], &[0x01, 0x00]);
        assert_eq!(&buf[4..6], &[0x00, 0x01]);
        // QNAME: 7 e x a m p l e 3 c o m 0
        let want_name: &[u8] = &[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];
        assert_eq!(&buf[12..12 + want_name.len()], want_name);
        // QTYPE=A (1), QCLASS=IN (1)
        let tail = &buf[12 + want_name.len()..];
        assert_eq!(tail, &[0, 1, 0, 1]);
    }

    #[test]
    fn encode_name_rejects_empty() {
        assert!(matches!(encode_name(""), Err(DnsError::QueryInvalid(_))));
        assert!(matches!(encode_name("."), Err(DnsError::QueryInvalid(_))));
    }

    #[test]
    fn encode_name_rejects_double_dot() {
        assert!(matches!(
            encode_name("foo..bar"),
            Err(DnsError::QueryInvalid(_))
        ));
    }

    #[test]
    fn encode_name_rejects_long_label() {
        let label = "a".repeat(64);
        assert!(matches!(
            encode_name(&format!("{label}.com")),
            Err(DnsError::QueryInvalid(_))
        ));
    }

    #[test]
    fn encode_name_rejects_long_total() {
        // 4 * (63 + 1) = 256 wire bytes, plus the terminating
        // null pushes well past 255. Pick label lengths that
        // also satisfy the individual-label limit.
        let label63 = "a".repeat(63);
        let name = format!("{label63}.{label63}.{label63}.{label63}");
        assert!(matches!(encode_name(&name), Err(DnsError::QueryInvalid(_))));
    }

    #[test]
    fn parse_header_smoke() {
        let mut buf = vec![0; 12];
        buf[0..2].copy_from_slice(&0x4242u16.to_be_bytes());
        // QR=1, RA=1, RCODE=NXDOMAIN(3)
        buf[2..4].copy_from_slice(&0x8083u16.to_be_bytes());
        buf[4..6].copy_from_slice(&1u16.to_be_bytes());
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        let h = parse_header(&buf).expect("hdr");
        assert_eq!(h.id, 0x4242);
        assert!(h.qr);
        assert!(h.ra);
        assert_eq!(h.rcode, RCode::NxDomain);
        assert_eq!(h.qd_count, 1);
        assert_eq!(h.an_count, 2);
    }

    #[test]
    fn parse_header_truncated() {
        assert!(parse_header(&[0; 11]).is_err());
    }

    #[test]
    fn parse_question_decodes_qname() {
        // Manually craft: header + question for example.com A IN
        let mut msg = vec![0u8; 12];
        msg.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        let (name, qt, qc, next) = parse_question(&msg, 12).expect("q");
        assert_eq!(name, "example.com");
        assert_eq!(qt, QType::A);
        assert_eq!(qc, CLASS_IN);
        assert_eq!(next, msg.len());
    }

    #[test]
    fn parse_records_handles_compression_pointer() {
        // Header (12 bytes)
        let mut msg = vec![0u8; 12];
        msg[6..8].copy_from_slice(&1u16.to_be_bytes()); // an_count=1
        // QNAME at offset 12: "example.com"
        msg.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // Now answer record at current offset: use a compression
        // pointer back to offset 12 (0xC00C)
        msg.extend_from_slice(&[0xC0, 0x0C]);
        // TYPE=A, CLASS=IN, TTL=300, RDLEN=4, RDATA=93.184.216.34
        msg.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 93, 184, 216, 34]);

        let (recs, _next) = parse_records(&msg, 12 + 13, 1).expect("rec");
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.name, "example.com");
        assert_eq!(r.rtype, QType::A);
        assert_eq!(r.class, CLASS_IN);
        assert_eq!(r.ttl, 300);
        assert_eq!(r.as_ipv4(), Some(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn parse_records_handles_aaaa() {
        let mut msg = vec![0u8; 12];
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        msg.extend_from_slice(&[0xC0, 0x0C]);
        // TYPE=AAAA(28), CLASS=IN, TTL=300, RDLEN=16, RDATA=2606:2800:220:1:248:1893:25c8:1946
        msg.extend_from_slice(&[0, 28, 0, 1, 0, 0, 1, 0x2C, 0, 16]);
        msg.extend_from_slice(&[
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xC8,
            0x19, 0x46,
        ]);

        let (recs, _) = parse_records(&msg, 12 + 13, 1).expect("rec");
        let ip = recs[0].as_ipv6().expect("AAAA rdata decoded");
        assert_eq!(ip.octets()[0..2], [0x26, 0x06]);
    }

    #[test]
    fn parse_records_rejects_pointer_loop() {
        // Construct a deliberately self-referential pointer at
        // offset 12 → 12. The bounded-jumps guard must reject it
        // rather than spinning forever.
        let mut msg = vec![0u8; 12];
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0xC0, 0x0C]); // points back to offset 12 (itself)
        msg.extend_from_slice(&[0, 1, 0, 1, 0, 0, 1, 0x2C, 0, 4, 1, 2, 3, 4]);
        let r = parse_records(&msg, 12, 1);
        assert!(r.is_err());
    }

    #[test]
    fn parse_records_rejects_rdata_overflow() {
        let mut msg = vec![0u8; 12];
        msg[6..8].copy_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&[0]); // root name
        // TYPE=A, CLASS=IN, TTL=0, RDLEN=99 (way past buffer end)
        msg.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0, 0, 99, 1, 2, 3, 4]);
        let r = parse_records(&msg, 12, 1);
        assert!(r.is_err());
    }
}

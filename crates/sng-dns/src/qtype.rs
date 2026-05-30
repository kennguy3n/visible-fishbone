//! DNS query types and response codes.
//!
//! These are RFC 1035 §3.2.2 / §3.2.3 wire constants. We expose
//! them as typed enums so the rest of the crate does not pass raw
//! `u16`s around; the wire-format encoder/decoder converts at the
//! crate boundary.

use std::fmt;

/// DNS query type. The variants cover the subset the agent
/// actually resolves on behalf of endpoints; record types the
/// resolver may legitimately encounter on the wire but which the
/// agent never originates are folded into [`Self::Other`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum QType {
    /// `A` — RFC 1035 IPv4 host address.
    A,
    /// `AAAA` — RFC 3596 IPv6 host address.
    Aaaa,
    /// `CNAME` — RFC 1035 canonical name alias.
    Cname,
    /// `TXT` — RFC 1035 free-form text record.
    Txt,
    /// `MX` — RFC 1035 mail exchange.
    Mx,
    /// `SRV` — RFC 2782 service location.
    Srv,
    /// `NS` — RFC 1035 authoritative name server.
    Ns,
    /// `PTR` — RFC 1035 reverse-resolution pointer.
    Ptr,
    /// `SOA` — RFC 1035 start-of-authority.
    Soa,
    /// `HTTPS` — RFC 9460 service binding for HTTP/3 / ECH
    /// bootstrap. Worth surfacing distinctly because modern
    /// browsers query it alongside every A/AAAA, and a missing
    /// answer materially changes connection setup.
    Https,
    /// Any wire type the agent does not originate but the
    /// upstream may legitimately return. Carries the raw
    /// numeric code so dashboards can still bucket it.
    Other(u16),
}

impl QType {
    /// RFC 1035 numeric wire value.
    #[must_use]
    pub const fn to_wire(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Https => 65,
            Self::Other(v) => v,
        }
    }

    /// Inverse of [`Self::to_wire`].
    #[must_use]
    pub const fn from_wire(v: u16) -> Self {
        match v {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            65 => Self::Https,
            other => Self::Other(other),
        }
    }

    /// IANA mnemonic (`A` / `AAAA` / `CNAME` / …). The
    /// [`sng_core::DnsEvent::qtype`] wire field stores this
    /// string form, not the numeric type code.
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::A => "A".into(),
            Self::Aaaa => "AAAA".into(),
            Self::Cname => "CNAME".into(),
            Self::Txt => "TXT".into(),
            Self::Mx => "MX".into(),
            Self::Srv => "SRV".into(),
            Self::Ns => "NS".into(),
            Self::Ptr => "PTR".into(),
            Self::Soa => "SOA".into(),
            Self::Https => "HTTPS".into(),
            Self::Other(v) => format!("TYPE{v}"),
        }
    }
}

impl fmt::Display for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

/// DNS response code (RFC 1035 §4.1.1, RFC 2136 extension).
///
/// We surface the full IANA-allocated 4-bit space, but lower
/// codes (above 5) are exceedingly rare on the public Internet;
/// the `Other` variant carries the raw value for completeness.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum RCode {
    /// `NOERROR` — query succeeded.
    NoError,
    /// `FORMERR` — upstream rejected the query as malformed.
    FormErr,
    /// `SERVFAIL` — upstream resolver internal error / DNSSEC
    /// validation failure.
    ServFail,
    /// `NXDOMAIN` — authoritative name server says the name
    /// does not exist.
    NxDomain,
    /// `NOTIMP` — query type not implemented by the upstream.
    NotImp,
    /// `REFUSED` — upstream refused to answer (policy, ACL,
    /// rate limit).
    Refused,
    /// Any other RFC 1035 §4.1.1 / RFC 2136 RCODE.
    Other(u8),
}

impl RCode {
    /// RFC 1035 4-bit wire value (we store as `u8` for ergonomic
    /// reasons; only the low nibble carries information).
    #[must_use]
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::NoError => 0,
            Self::FormErr => 1,
            Self::ServFail => 2,
            Self::NxDomain => 3,
            Self::NotImp => 4,
            Self::Refused => 5,
            Self::Other(v) => v,
        }
    }

    /// Inverse of [`Self::to_wire`]. Mask to the low nibble to
    /// match the wire format precisely; callers that have
    /// already extracted the nibble can use the variant
    /// constructors directly.
    #[must_use]
    pub const fn from_wire(v: u8) -> Self {
        match v & 0x0F {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NxDomain,
            4 => Self::NotImp,
            5 => Self::Refused,
            other => Self::Other(other),
        }
    }

    /// IANA mnemonic suitable for [`sng_core::DnsEvent::response_code`].
    #[must_use]
    pub fn as_str(&self) -> String {
        match self {
            Self::NoError => "NOERROR".into(),
            Self::FormErr => "FORMERR".into(),
            Self::ServFail => "SERVFAIL".into(),
            Self::NxDomain => "NXDOMAIN".into(),
            Self::NotImp => "NOTIMP".into(),
            Self::Refused => "REFUSED".into(),
            Self::Other(v) => format!("RCODE{v}"),
        }
    }

    /// Whether this RCODE indicates an upstream/server-side
    /// failure (FORMERR / SERVFAIL / NOTIMP / REFUSED).
    /// NXDOMAIN is NOT a failure — it is a legitimate negative
    /// answer.
    #[must_use]
    pub const fn is_upstream_failure(self) -> bool {
        matches!(
            self,
            Self::FormErr | Self::ServFail | Self::NotImp | Self::Refused
        )
    }
}

impl fmt::Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qtype_wire_roundtrip() {
        for q in [
            QType::A,
            QType::Aaaa,
            QType::Cname,
            QType::Txt,
            QType::Mx,
            QType::Srv,
            QType::Ns,
            QType::Ptr,
            QType::Soa,
            QType::Https,
        ] {
            assert_eq!(QType::from_wire(q.to_wire()), q, "roundtrip {q:?}");
        }
    }

    #[test]
    fn qtype_other_preserves_code() {
        let q = QType::from_wire(257);
        assert_eq!(q, QType::Other(257));
        assert_eq!(q.to_wire(), 257);
        assert_eq!(q.as_str(), "TYPE257");
    }

    #[test]
    fn rcode_wire_roundtrip() {
        for r in [
            RCode::NoError,
            RCode::FormErr,
            RCode::ServFail,
            RCode::NxDomain,
            RCode::NotImp,
            RCode::Refused,
        ] {
            assert_eq!(RCode::from_wire(r.to_wire()), r);
        }
    }

    #[test]
    fn rcode_masks_low_nibble() {
        // Upper nibble bits must be ignored — the wire format only
        // ever stores RCODE in bits 0..4 of the header byte.
        assert_eq!(RCode::from_wire(0xF3), RCode::NxDomain);
    }

    #[test]
    fn rcode_is_upstream_failure() {
        assert!(RCode::ServFail.is_upstream_failure());
        assert!(RCode::FormErr.is_upstream_failure());
        assert!(RCode::Refused.is_upstream_failure());
        assert!(RCode::NotImp.is_upstream_failure());
        // NXDOMAIN is a legitimate negative answer — NOT a failure.
        assert!(!RCode::NxDomain.is_upstream_failure());
        assert!(!RCode::NoError.is_upstream_failure());
    }

    #[test]
    fn qtype_mnemonics_match_iana() {
        assert_eq!(QType::A.as_str(), "A");
        assert_eq!(QType::Aaaa.as_str(), "AAAA");
        assert_eq!(QType::Https.as_str(), "HTTPS");
    }
}

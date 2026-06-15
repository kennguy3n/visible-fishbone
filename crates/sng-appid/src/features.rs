//! Connection feature inputs and match outputs for the matcher.
//!
//! These types are the stable boundary between the data plane (which
//! observes a connection and fills in whatever features it cheaply
//! has) and the matcher (which maps those features to an application
//! identity). Every field is optional or bounded so the data plane can
//! call the matcher on a partially observed connection without
//! allocating or copying the packet.

use serde::{Deserialize, Serialize};

/// The maximum number of leading connection bytes the matcher inspects.
///
/// Byte-probe signatures are capped at this many bytes, and the data
/// plane never needs to hand the matcher more than this — a hostile
/// peer cannot make the matcher scan an unbounded prefix.
pub const MAX_PROBE_BYTES: usize = 16;

/// The maximum number of DNS-style labels the matcher will split a host
/// name into when doing suffix matching. A name with more labels than
/// this still matches on its rightmost [`MAX_HOST_LABELS`] labels, so
/// an adversary cannot force super-linear work with a deeply nested
/// name.
pub const MAX_HOST_LABELS: usize = 12;

/// Layer-4 transport an observed connection runs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol (includes QUIC, which rides UDP/443).
    Udp,
}

impl Transport {
    /// Parses a lowercase transport token, returning `None` for an
    /// unrecognised value so a catalog loader can reject it explicitly
    /// rather than silently defaulting.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }

    /// The canonical lowercase token for this transport.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// Features observed for a single connection, handed to the matcher.
///
/// All borrowed so the caller passes references into its own buffers
/// without copying. The matcher treats every field as untrusted input
/// and bounds the work it does on each.
#[derive(Debug, Clone, Copy, Default)]
pub struct ConnFeatures<'a> {
    /// TLS Server Name Indication, if a ClientHello was observed.
    pub sni: Option<&'a str>,
    /// JA3 TLS-fingerprint hash (lowercase hex), if computed.
    pub ja3: Option<&'a str>,
    /// HTTP Host header, if the connection was plaintext HTTP.
    pub host: Option<&'a str>,
    /// Leading bytes of the connection payload (only the first
    /// [`MAX_PROBE_BYTES`] are ever inspected).
    pub first_bytes: Option<&'a [u8]>,
    /// Destination port, if known.
    pub port: Option<u16>,
    /// Layer-4 transport, if known.
    pub transport: Option<Transport>,
}

impl<'a> ConnFeatures<'a> {
    /// Convenience constructor for the common TLS case: a connection
    /// identified by SNI on a port.
    #[must_use]
    pub fn from_sni(sni: &'a str, port: u16) -> Self {
        Self {
            sni: Some(sni),
            port: Some(port),
            transport: Some(Transport::Tcp),
            ..Self::default()
        }
    }

    /// Convenience constructor for the plaintext-HTTP case.
    #[must_use]
    pub fn from_host(host: &'a str, port: u16) -> Self {
        Self {
            host: Some(host),
            port: Some(port),
            transport: Some(Transport::Tcp),
            ..Self::default()
        }
    }
}

/// A single best-match result from the matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppMatch {
    /// Stable application identifier, e.g. `microsoft.teams`.
    pub app_id: String,
    /// Coarse application category, e.g. `collaboration`.
    pub category: String,
    /// Confidence in `[0, 100]`. Higher means a more specific signal
    /// (an exact SNI beats an apex-suffix match beats a port-only
    /// guess).
    pub confidence: u8,
}

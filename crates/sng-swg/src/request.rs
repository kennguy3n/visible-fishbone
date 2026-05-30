//! HTTP request / response observation types.
//!
//! The SWG brain doesn't speak HTTP itself — that's
//! Envoy's job. The brain receives a small structured
//! record per observation (URL, method, server status,
//! response sha256 if known) and produces a posture +
//! a telemetry event.

use crate::error::SwgError;
use std::net::IpAddr;
use url::Url;

/// What the producer is asking the SWG to do.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ObservationPhase {
    /// The client has issued the request but the
    /// response is not yet available. The producer wants
    /// to know whether to forward / MITM / drop. Malware
    /// verdict will be `None` (no payload yet).
    Request,
    /// The response is back; the producer wants the
    /// final verdict including malware scan results.
    Response,
}

/// HTTP request / response observation.
#[derive(Clone, Debug)]
pub struct HttpObservation {
    /// Stable per-session identifier — the proxy
    /// generates one per HTTP transaction.
    pub session_id: u64,
    /// Client address.
    pub client_ip: IpAddr,
    /// Server address (resolved upstream).
    pub server_ip: IpAddr,
    /// HTTP method.
    pub method: String,
    /// Full request URL. Parsed once via [`Self::url`].
    pub url: String,
    /// Host header (may differ from URL host when the
    /// client uses Host-override).
    pub host: String,
    /// Server-Name-Indication on the TLS handshake (if
    /// any). Carried separately so the SWG can correlate
    /// SNI ↔ Host mismatches.
    pub sni: Option<String>,
    /// Negotiated TLS version (when intercepted). `None`
    /// for plain HTTP.
    pub tls_version: Option<String>,
    /// Phase the producer is asking about.
    pub phase: ObservationPhase,
    /// Response status, when known. `None` for
    /// [`ObservationPhase::Request`].
    pub status_code: Option<u16>,
    /// Response content-type, when known.
    pub content_type: Option<String>,
    /// Response body sha256 (hex), when known.
    pub response_sha256: Option<String>,
    /// Bytes transferred (response body length).
    pub response_bytes: u64,
    /// Monotonic millisecond timestamp.
    pub now_ms: u64,
}

impl HttpObservation {
    /// Construct an observation with `Default::default`
    /// for the optional fields. Producers usually use the
    /// struct-literal form; this helper is for tests.
    #[must_use]
    pub fn new(session_id: u64, method: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            session_id,
            client_ip: IpAddr::from([0, 0, 0, 0]),
            server_ip: IpAddr::from([0, 0, 0, 0]),
            method: method.into(),
            url: url.into(),
            host: String::new(),
            sni: None,
            tls_version: None,
            phase: ObservationPhase::Request,
            status_code: None,
            content_type: None,
            response_sha256: None,
            response_bytes: 0,
            now_ms: 0,
        }
    }

    /// Parse the URL string into a [`Url`].
    ///
    /// # Errors
    ///
    /// - [`SwgError::InvalidUrl`] when the URL string is
    ///   not a valid absolute URL.
    pub fn url(&self) -> Result<Url, SwgError> {
        Url::parse(&self.url).map_err(|e| SwgError::InvalidUrl(format!("{}: {e}", self.url)))
    }

    /// Resolve the effective host for category /
    /// reputation lookup. Priority: parsed URL host →
    /// `Host` header → SNI.
    ///
    /// The returned host is always **port-stripped** and
    /// ASCII-lowercased so it can feed directly into the
    /// suffix-walking category / reputation providers
    /// (which key on `example.com`, not `example.com:8443`).
    ///
    /// Host string shapes handled:
    ///
    /// - bare domain: `example.com` → `example.com`
    /// - domain + port: `example.com:8443` → `example.com`
    /// - IPv4: `203.0.113.1` → `203.0.113.1`
    /// - IPv4 + port: `203.0.113.1:8443` → `203.0.113.1`
    /// - bracketed IPv6: `[::1]` → `[::1]`
    /// - bracketed IPv6 + port: `[::1]:8443` → `[::1]`
    /// - bare IPv6 (no brackets, no port): `::1` → `::1`
    ///
    /// # Errors
    ///
    /// - [`SwgError::InvalidUrl`] when no usable host is
    ///   available on any source.
    pub fn effective_host(&self) -> Result<String, SwgError> {
        if let Ok(u) = self.url() {
            if let Some(h) = u.host_str() {
                // `url::Url::host_str` already strips the
                // port; just lowercase.
                return Ok(h.to_ascii_lowercase());
            }
        }
        if !self.host.is_empty() {
            return Ok(strip_port(&self.host).to_ascii_lowercase());
        }
        if let Some(s) = &self.sni {
            if !s.is_empty() {
                // SNI per TLS spec never carries a port, but
                // run it through `strip_port` anyway so a
                // misbehaving producer can't break the
                // suffix-walk.
                return Ok(strip_port(s).to_ascii_lowercase());
            }
        }
        Err(SwgError::InvalidUrl(format!(
            "no host on url={} host={} sni={:?}",
            self.url, self.host, self.sni
        )))
    }
}

/// Strip the optional `:PORT` suffix from a host string
/// while preserving the bracketed-IPv6 form. Used by
/// [`HttpObservation::effective_host`] for the `Host` /
/// SNI fallback paths, where the producer may pass a
/// port-bearing authority (`example.com:8443`,
/// `[2001:db8::1]:443`) and we need just the host part
/// for the suffix-walking category / reputation lookup.
///
/// Shape detection:
///
/// - If the input starts with `[`, treat it as a
///   bracketed IPv6 literal; trim the `:PORT` that
///   follows the closing `]` if any, and return the
///   bracketed form (including brackets).
/// - Else if the input contains exactly one `:`, treat
///   it as `host:port` and return the part before the
///   colon.
/// - Else (zero or 2+ colons unbracketed) return the
///   input unchanged. Two-or-more colons without brackets
///   is almost certainly a bare IPv6 literal (`::1`,
///   `2001:db8::1`); we don't try to guess whether the
///   trailing component is a port — the only correct way
///   to embed a port on IPv6 is the bracketed form.
fn strip_port(input: &str) -> &str {
    if let Some(rest) = input.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            // Return the full bracketed literal,
            // discarding anything after the `]` (which
            // would be `:PORT` per RFC 3986 authority
            // syntax).
            return &input[..=end + 1];
        }
        // Malformed: starts with `[` but no `]`. Return
        // unchanged so the downstream lookup misses
        // explicitly rather than silently chopping bytes.
        return input;
    }
    // Bare host. A single colon means `host:port`; zero
    // or 2+ colons unbracketed means it's almost certainly
    // a bare IPv6 literal or just colon-less.
    let colon_count = input.bytes().filter(|&b| b == b':').count();
    if colon_count == 1 {
        if let Some(idx) = input.rfind(':') {
            return &input[..idx];
        }
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn url_parses_valid_https() {
        let obs = HttpObservation::new(1, "GET", "https://example.com/path?q=1");
        let u = obs.url().unwrap();
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("example.com"));
        assert_eq!(u.path(), "/path");
    }

    #[test]
    fn url_parse_fails_on_invalid() {
        let obs = HttpObservation::new(1, "GET", "not a url");
        assert!(matches!(obs.url(), Err(SwgError::InvalidUrl(_))));
    }

    #[test]
    fn effective_host_prefers_url_host() {
        let mut obs = HttpObservation::new(1, "GET", "https://EXAMPLE.com/x");
        obs.host = "other.org".into();
        obs.sni = Some("third.net".into());
        assert_eq!(obs.effective_host().unwrap(), "example.com");
    }

    #[test]
    fn effective_host_falls_back_to_host_header() {
        // URL without a host (relative form would fail
        // parse, so use scheme-less hostless).
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.host = "Header.Example".into();
        assert_eq!(obs.effective_host().unwrap(), "header.example");
    }

    #[test]
    fn effective_host_strips_port_from_host_header() {
        // Pins the port-stripping contract for the Host
        // header fallback path. The suffix-walking
        // category / reputation lookup keys on
        // `example.com`, not `example.com:8443`, so the
        // brain MUST drop the port before handing off.
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.host = "Example.com:8443".into();
        assert_eq!(obs.effective_host().unwrap(), "example.com");
    }

    #[test]
    fn effective_host_strips_port_from_ipv4_host_header() {
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.host = "203.0.113.1:8443".into();
        assert_eq!(obs.effective_host().unwrap(), "203.0.113.1");
    }

    #[test]
    fn effective_host_preserves_bracketed_ipv6_host_header() {
        // Bracketed IPv6 with port: the brackets are
        // retained (consistent with `url::Host` semantics)
        // and the trailing `:PORT` is stripped.
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.host = "[2001:db8::1]:8443".into();
        assert_eq!(obs.effective_host().unwrap(), "[2001:db8::1]");
    }

    #[test]
    fn effective_host_preserves_bare_ipv6_host_header() {
        // Bare IPv6 (no brackets, no port): leave alone.
        // The `:` count > 1 disambiguates from
        // `host:port`. A producer sending bare IPv6 in a
        // Host header is technically malformed (RFC 3986
        // requires brackets in authority form), but we
        // still pass it through unchanged so the lookup
        // sees the operator's intended host.
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.host = "2001:db8::1".into();
        assert_eq!(obs.effective_host().unwrap(), "2001:db8::1");
    }

    #[test]
    fn effective_host_strips_port_from_sni() {
        // Per TLS spec SNI never carries a port, but if a
        // misbehaving producer sticks one in we still
        // strip it so the suffix-walk works.
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.sni = Some("Sni.Example:443".into());
        assert_eq!(obs.effective_host().unwrap(), "sni.example");
    }

    #[test]
    fn effective_host_falls_back_to_sni() {
        let mut obs = HttpObservation::new(1, "GET", "data:,hello");
        obs.sni = Some("Sni.Example".into());
        assert_eq!(obs.effective_host().unwrap(), "sni.example");
    }

    #[test]
    fn effective_host_errors_when_no_source() {
        let obs = HttpObservation::new(1, "GET", "data:,hello");
        assert!(matches!(obs.effective_host(), Err(SwgError::InvalidUrl(_))));
    }

    #[test]
    fn observation_phase_eq() {
        assert_eq!(ObservationPhase::Request, ObservationPhase::Request);
        assert_ne!(ObservationPhase::Request, ObservationPhase::Response);
    }
}

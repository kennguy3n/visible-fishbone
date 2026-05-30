//! Per-query types passed through the filter chain and resolver.
//!
//! [`DnsQuery`] is the agent-facing representation of a single
//! recursive lookup the endpoint asked for. The wire form is
//! parsed by [`crate::wire::parse_question`] at the UDP listener
//! boundary; everything downstream of that point manipulates the
//! parsed [`DnsQuery`] instead of raw bytes.
//!
//! [`DnsResponse`] is the synthesized or resolver-returned
//! answer, again in a decoded form so [`crate::service`] can
//! emit a [`sng_core::DnsEvent`] from it without re-parsing the
//! wire bytes.

use std::net::IpAddr;

use crate::qtype::{QType, RCode};
use crate::wire::Record;

/// Single DNS question driving the filter chain + resolver.
///
/// The name is stored as a canonical lowercase form with the
/// trailing root dot stripped. The [`DnsQuery::new`] constructor
/// is the single source of canonicalization; downstream filters
/// MUST compare against `self.name` directly and MUST NOT
/// re-canonicalize, because the canonical form is the
/// equivalence-class anchor for the filter feeds.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct DnsQuery {
    /// Canonical lowercase QNAME without trailing dot. The
    /// canonical form is what reputation / category / sinkhole
    /// feeds index on.
    pub name: String,
    /// Wire-format query type.
    pub qtype: QType,
    /// Optional client identifier the listener stamped on the
    /// query for tenant attribution. The DNS subsystem itself
    /// does not interpret it, but downstream telemetry does.
    pub client_id: Option<String>,
}

impl DnsQuery {
    /// Construct a query, canonicalizing the name. Trailing
    /// root-dot is stripped; upper-case ASCII labels are folded
    /// to lowercase. The non-ASCII path is left untouched (the
    /// agent expects punycode-encoded IDN labels from the
    /// endpoint resolver stub).
    #[must_use]
    pub fn new(name: &str, qtype: QType) -> Self {
        Self {
            name: canonicalize_name(name),
            qtype,
            client_id: None,
        }
    }

    /// Builder-style attach of a client identifier. Used by the
    /// UDP listener to thread the tenant-scoped identity through
    /// to the [`sng_core::DnsEvent`] emitted at the end.
    #[must_use]
    pub fn with_client(mut self, client: impl Into<String>) -> Self {
        self.client_id = Some(client.into());
        self
    }
}

/// Canonicalize a DNS name for filter-feed comparison.
///
/// The agent's filter feeds are indexed on lowercase ASCII names
/// without a trailing dot. Punycode-encoded IDN labels are
/// already lowercase by construction (RFC 3492 §4) so we leave
/// non-ASCII alone — a feed entry that uses U-labels would be
/// loaded canonicalized by [`crate::reputation`] /
/// [`crate::sinkhole`] / [`crate::category`] in the same way.
#[must_use]
pub fn canonicalize_name(name: &str) -> String {
    // Strip surrounding ASCII whitespace first. Operator-supplied
    // feeds occasionally have a trailing `\n`, leading tab, or a
    // line that is whitespace-only after a CSV/newline split;
    // those should canonicalize to the empty string so the
    // caller's `!n.is_empty()` filter drops them rather than
    // letting `" "` or `"\t"` enter the lookup set.
    let stripped = name.trim();
    let trimmed = stripped.trim_end_matches('.');
    // Fast path: already lowercase ASCII (the common case).
    if trimmed.chars().all(|c| !c.is_ascii_uppercase()) {
        return trimmed.to_string();
    }
    trimmed.to_ascii_lowercase()
}

/// Returns true if `name` is equal to `feed_entry` or is a
/// proper subdomain of `feed_entry` (label-aligned suffix
/// match). Used by [`crate::category`] and [`crate::sinkhole`]
/// to match a query name against a feed entry without
/// suffering the false-positive class of a string-suffix match
/// (`evil.example` would otherwise match `goodevil.example`).
///
/// Both inputs MUST already be canonical
/// ([`canonicalize_name`]); this function does not
/// re-canonicalize.
#[must_use]
pub fn domain_suffix_match(name: &str, feed_entry: &str) -> bool {
    if feed_entry.is_empty() {
        return false;
    }
    if name == feed_entry {
        return true;
    }
    // `name` is a proper subdomain of `feed_entry` iff
    // `name` ends with `.<feed_entry>` (the leading dot is the
    // label boundary that prevents the `goodevil.example`
    // false positive).
    name.len() > feed_entry.len() + 1
        && name.ends_with(feed_entry)
        && name.as_bytes()[name.len() - feed_entry.len() - 1] == b'.'
}

/// Resolver / filter-chain output. Mirrors the wire response
/// shape but in decoded form so the [`crate::service`] layer can
/// extract verdict context for telemetry without re-parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsResponse {
    /// Response code (`NOERROR` / `NXDOMAIN` / `SERVFAIL` / …).
    pub rcode: RCode,
    /// Answer records the resolver returned, or the synthetic
    /// answer the filter chain inserted (for sinkhole hits).
    pub answers: Vec<Record>,
    /// Authority section records the resolver returned. Usually
    /// empty for the answer path the agent cares about.
    pub authority: Vec<Record>,
    /// First A/AAAA IP across `answers`, if any. Cached so the
    /// filter chain / service does not re-walk the answer list.
    pub primary_ip: Option<IpAddr>,
    /// Upstream resolver that produced the answer
    /// (`addr:port`), or `None` for synthetic responses (sinkhole
    /// hits, NXDOMAIN forcings).
    pub upstream: Option<String>,
}

impl DnsResponse {
    /// Synthesize an NXDOMAIN response with no answer / authority
    /// records. Used by [`crate::filter`] for reputation hits and
    /// blocked-category responses where we want the endpoint to
    /// treat the name as non-existent.
    #[must_use]
    pub fn nxdomain() -> Self {
        Self {
            rcode: RCode::NxDomain,
            answers: Vec::new(),
            authority: Vec::new(),
            primary_ip: None,
            upstream: None,
        }
    }

    /// Synthesize a NOERROR response carrying a single A / AAAA
    /// answer for a sinkhole hit. The TTL is short (5 minutes is
    /// the canonical sinkhole TTL; long enough to survive
    /// retries, short enough that lifting the block takes
    /// effect quickly) and the class is fixed to IN.
    #[must_use]
    pub fn sinkhole(name: &str, qtype: QType, ip: IpAddr) -> Self {
        let rdata = match ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        Self {
            rcode: RCode::NoError,
            answers: vec![Record {
                name: name.to_string(),
                rtype: qtype,
                class: crate::wire::CLASS_IN,
                ttl: 300,
                rdata,
            }],
            authority: Vec::new(),
            primary_ip: Some(ip),
            upstream: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_strips_trailing_dot() {
        assert_eq!(canonicalize_name("example.com."), "example.com");
        assert_eq!(canonicalize_name("example.com"), "example.com");
    }

    #[test]
    fn canonicalize_lowercases_ascii() {
        assert_eq!(canonicalize_name("Example.COM"), "example.com");
        assert_eq!(canonicalize_name("WWW.Microsoft.com."), "www.microsoft.com");
    }

    #[test]
    fn canonicalize_preserves_non_ascii() {
        // Punycode-encoded IDN is already lowercase ASCII.
        assert_eq!(
            canonicalize_name("xn--nxasmq6b.example.com"),
            "xn--nxasmq6b.example.com"
        );
    }

    #[test]
    fn new_canonicalizes() {
        let q = DnsQuery::new("WWW.Example.Com.", QType::A);
        assert_eq!(q.name, "www.example.com");
        assert_eq!(q.qtype, QType::A);
        assert!(q.client_id.is_none());
    }

    #[test]
    fn with_client_attaches_identity() {
        let q = DnsQuery::new("example.com", QType::A).with_client("device-42");
        assert_eq!(q.client_id.as_deref(), Some("device-42"));
    }

    #[test]
    fn nxdomain_synth_is_empty() {
        let r = DnsResponse::nxdomain();
        assert_eq!(r.rcode, RCode::NxDomain);
        assert!(r.answers.is_empty());
        assert!(r.authority.is_empty());
        assert!(r.primary_ip.is_none());
        assert!(r.upstream.is_none());
    }

    #[test]
    fn sinkhole_synth_carries_a_record() {
        let ip: IpAddr = "10.255.0.1".parse().unwrap();
        let r = DnsResponse::sinkhole("evil.example", QType::A, ip);
        assert_eq!(r.rcode, RCode::NoError);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].name, "evil.example");
        assert_eq!(r.answers[0].rtype, QType::A);
        assert_eq!(r.answers[0].ttl, 300);
        assert_eq!(r.primary_ip, Some(ip));
    }

    #[test]
    fn sinkhole_synth_carries_aaaa_record() {
        let ip: IpAddr = "fc00::1".parse().unwrap();
        let r = DnsResponse::sinkhole("evil.example", QType::Aaaa, ip);
        assert_eq!(r.answers[0].rtype, QType::Aaaa);
        assert_eq!(r.answers[0].rdata.len(), 16);
    }

    #[test]
    fn suffix_match_label_aligned() {
        assert!(domain_suffix_match("evil.example", "evil.example"));
        assert!(domain_suffix_match("sub.evil.example", "evil.example"));
        assert!(domain_suffix_match(
            "deep.nested.evil.example",
            "evil.example"
        ));
    }

    #[test]
    fn suffix_match_rejects_non_label_boundary() {
        // The classic false-positive a string-suffix match
        // would let through: `goodevil.example` shares the
        // suffix `evil.example` but is a different domain.
        assert!(!domain_suffix_match("goodevil.example", "evil.example"));
        assert!(!domain_suffix_match("evilxexample", "evil.example"));
        // Shorter than feed: cannot match.
        assert!(!domain_suffix_match("example", "evil.example"));
        // Empty feed: never matches (degenerate).
        assert!(!domain_suffix_match("anything", ""));
    }
}

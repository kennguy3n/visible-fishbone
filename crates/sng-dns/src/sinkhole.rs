//! Sinkhole filter: redirect known-bad domains to a controlled
//! IP (typically an internal "this is blocked" landing page).
//!
//! Distinct from [`crate::reputation`] which returns NXDOMAIN —
//! a sinkhole hit is intentionally a positive answer so the
//! endpoint connects to OUR sink address and we get a flow
//! telemetry record we can correlate with the DNS event. This is
//! the canonical "DNS sinkhole" technique described in
//! ARCHITECTURE.md §4.5 and used by enterprise DNS firewalls
//! (RPZ et al.).

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use async_trait::async_trait;
use sng_core::envelope::Verdict;

use crate::filter::{Filter, FilterDecision};
use crate::qtype::{QType, RCode};
use crate::query::{DnsQuery, canonicalize_name};

/// Sinkhole filter.
///
/// Holds a canonical lowercase set of domains plus the two IPs
/// (v4 + v6) the synthesized answer should return. When a query
/// name (or any of its suffix labels — sinkhole matches are
/// "this name OR anything under it") hits the set, we
/// short-circuit with a synthetic A or AAAA pointing at the sink.
#[derive(Debug)]
pub struct Sinkhole {
    entries: HashSet<String>,
    sink_v4: Ipv4Addr,
    sink_v6: Ipv6Addr,
}

impl Sinkhole {
    /// Build a sinkhole from a list of names + the two sink
    /// addresses.
    ///
    /// Names are canonicalized via [`canonicalize_name`] so a
    /// feed entry of `Evil.Example.` and a query for
    /// `evil.example` resolve to the same set member.
    /// Entries that are empty after canonicalization are skipped
    /// (the empty string is not a valid DNS name).
    #[must_use]
    pub fn new(
        names: impl IntoIterator<Item = String>,
        sink_v4: Ipv4Addr,
        sink_v6: Ipv6Addr,
    ) -> Self {
        let entries = names
            .into_iter()
            .map(|n| canonicalize_name(&n))
            .filter(|n| !n.is_empty())
            .collect();
        Self {
            entries,
            sink_v4,
            sink_v6,
        }
    }

    /// Number of entries. Used by `replace` paths to confirm the
    /// new feed loaded successfully before swapping it in.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the sinkhole has zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Test whether the given canonical name (or any of its
    /// suffix domains) is sinkholed. Walks the labels from most
    /// specific to least specific, stopping as soon as one
    /// matches. Worst case is bounded by the number of labels in
    /// the name (≤ 127 per RFC 1035 §2.3.4).
    #[must_use]
    pub fn matches(&self, canonical: &str) -> bool {
        let mut current = canonical;
        loop {
            if self.entries.contains(current) {
                return true;
            }
            match current.find('.') {
                Some(idx) => current = &current[idx + 1..],
                None => return false,
            }
        }
    }

    fn sink_for(&self, qtype: QType) -> Option<IpAddr> {
        match qtype {
            QType::A => Some(IpAddr::V4(self.sink_v4)),
            QType::Aaaa => Some(IpAddr::V6(self.sink_v6)),
            // For any other qtype (CNAME / TXT / MX / …) the
            // sinkhole has no synthetic answer to fabricate, so
            // we return NOERROR with no answer record. That's
            // the right shape: the endpoint sees the name as
            // existing but with no records of the requested
            // type, which is functionally equivalent to "the
            // service is unavailable" without revealing whether
            // we are blocking.
            _ => None,
        }
    }
}

#[async_trait]
impl Filter for Sinkhole {
    fn name(&self) -> &'static str {
        "sinkhole"
    }

    async fn check(&self, query: &DnsQuery) -> FilterDecision {
        if !self.matches(&query.name) {
            return FilterDecision::Pass;
        }
        FilterDecision::ShortCircuit {
            verdict: Verdict::Deny,
            rcode: RCode::NoError,
            synthetic_ip: self.sink_for(query.qtype),
            reason: "sinkhole match".into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::ChainOutcome;
    use crate::filter::FilterChain;
    use std::sync::Arc;

    fn sink() -> Sinkhole {
        Sinkhole::new(
            ["Evil.Example.".into(), "blocked.test".into()],
            Ipv4Addr::new(10, 0, 0, 1),
            "fc00::1".parse().unwrap(),
        )
    }

    #[test]
    fn canonicalization_at_load_time() {
        let s = sink();
        // Original ALL-CAPS + trailing dot was canonicalized.
        assert!(s.matches("evil.example"));
        assert!(s.matches("blocked.test"));
    }

    #[test]
    fn suffix_match_blocks_subdomain() {
        let s = sink();
        assert!(s.matches("c2.evil.example"));
        assert!(s.matches("deep.nested.evil.example"));
        assert!(!s.matches("goodevil.example"));
        assert!(!s.matches("evilxexample"));
    }

    #[test]
    fn no_match_for_unrelated_name() {
        let s = sink();
        assert!(!s.matches("good.example"));
        assert!(!s.matches("safe.test"));
    }

    #[tokio::test]
    async fn a_query_returns_sink_v4() {
        let s = sink();
        let q = DnsQuery::new("evil.example", QType::A);
        match s.check(&q).await {
            FilterDecision::ShortCircuit {
                verdict,
                rcode,
                synthetic_ip,
                ..
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(rcode, RCode::NoError);
                assert_eq!(synthetic_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn aaaa_query_returns_sink_v6() {
        let s = sink();
        let q = DnsQuery::new("evil.example", QType::Aaaa);
        match s.check(&q).await {
            FilterDecision::ShortCircuit { synthetic_ip, .. } => {
                assert_eq!(synthetic_ip, Some(IpAddr::V6("fc00::1".parse().unwrap())));
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cname_query_returns_noerror_no_answer() {
        let s = sink();
        let q = DnsQuery::new("evil.example", QType::Cname);
        match s.check(&q).await {
            FilterDecision::ShortCircuit {
                rcode,
                synthetic_ip,
                ..
            } => {
                // We still short-circuit so the endpoint sees a
                // "no records of this type" response (NOERROR
                // with no answer section) — the sinkhole has no
                // synthetic CNAME to inject.
                assert_eq!(rcode, RCode::NoError);
                assert!(synthetic_ip.is_none());
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pass_for_non_matching_name() {
        let s = sink();
        let q = DnsQuery::new("good.example", QType::A);
        assert_eq!(s.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn empty_list_passes_everything() {
        let s = Sinkhole::new(
            std::iter::empty(),
            Ipv4Addr::new(10, 0, 0, 1),
            "fc00::1".parse().unwrap(),
        );
        assert!(s.is_empty());
        let q = DnsQuery::new("evil.example", QType::A);
        assert_eq!(s.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn end_to_end_through_filter_chain() {
        let s = sink();
        let chain = FilterChain::new(vec![Arc::new(s)]);
        let q = DnsQuery::new("evil.example", QType::A);
        let outcome = chain.evaluate(&q).await;
        match outcome {
            ChainOutcome::ShortCircuit {
                verdict,
                rcode,
                synthetic_ip,
                filter,
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(rcode, RCode::NoError);
                assert_eq!(synthetic_ip, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
                assert_eq!(filter, "sinkhole");
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }
}

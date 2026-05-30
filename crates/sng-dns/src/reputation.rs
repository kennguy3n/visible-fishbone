//! Reputation filter: blocks queries whose name appears on a
//! threat-intel feed.
//!
//! Distinct from [`crate::sinkhole`] in two ways:
//!
//! 1. Response shape — reputation returns NXDOMAIN (the name
//!    "does not exist" from the client's point of view). Sinkhole
//!    returns a positive A / AAAA pointing at an internal sink
//!    so we can correlate the follow-up flow.
//! 2. Match semantics — reputation matches the EXACT canonical
//!    name only. Operators feeding domain-suffix wildcards into
//!    a reputation list should put them on the sinkhole list
//!    instead; reputation is meant for the "we have IOC for THIS
//!    specific FQDN" case where a parent-domain false-positive
//!    would be catastrophic.
//!
//! The feed is held in an [`ArcSwap`] so the operator can reload
//! the list without disturbing in-flight queries: build a new
//! `Reputation` (which is cheap because the inner set is the
//! only owned state) and call [`Reputation::replace_entries`].

use std::collections::HashSet;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sng_core::envelope::Verdict;

use crate::filter::{Filter, FilterDecision};
use crate::qtype::RCode;
use crate::query::{DnsQuery, canonicalize_name};

/// Reputation filter.
///
/// Holds a single set of canonical lowercase FQDNs in an
/// [`ArcSwap`] so feed reloads don't tear the in-flight read
/// path. The set is intentionally a [`HashSet`] rather than a
/// trie: reputation feeds are typically O(10k) entries, well
/// under the size where a trie's constant-factor savings pay
/// off, and the HashSet's O(1) exact-match is the right shape
/// for the no-wildcard contract this filter enforces.
pub struct Reputation {
    entries: ArcSwap<HashSet<String>>,
}

impl std::fmt::Debug for Reputation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reputation")
            .field("len", &self.entries.load().len())
            .finish()
    }
}

impl Reputation {
    /// Build a reputation filter from an iterator of names.
    ///
    /// Each name is canonicalized via [`canonicalize_name`] so a
    /// feed entry of `Evil.Example.` and a query for
    /// `evil.example` collide correctly.
    pub fn new<I, S>(names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            entries: ArcSwap::from_pointee(canonicalize_set(names)),
        }
    }

    /// Build an empty reputation filter. Useful for the
    /// pre-feed-load / disabled-tenant cases where the chain
    /// still wants a slot for reputation but the operator
    /// hasn't loaded a feed yet.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: ArcSwap::from_pointee(HashSet::new()),
        }
    }

    /// Replace the canonical name set atomically. In-flight
    /// queries continue against the previous snapshot; the next
    /// query sees the new set.
    pub fn replace_entries<I, S>(&self, names: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.entries.store(Arc::new(canonicalize_set(names)));
    }

    /// Current entry count. Used by the supervisor's
    /// "feed-stale" health check and by tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.load().len()
    }

    /// Whether the current feed has any entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.load().is_empty()
    }
}

fn canonicalize_set<I, S>(names: I) -> HashSet<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    names
        .into_iter()
        .map(|n| canonicalize_name(n.as_ref()))
        .filter(|n| !n.is_empty())
        .collect()
}

#[async_trait]
impl Filter for Reputation {
    fn name(&self) -> &'static str {
        "reputation"
    }

    async fn check(&self, query: &DnsQuery) -> FilterDecision {
        // Exact-match only. Suffix-match belongs on sinkhole.
        let snapshot = self.entries.load();
        if snapshot.contains(&query.name) {
            FilterDecision::ShortCircuit {
                verdict: Verdict::Deny,
                rcode: RCode::NxDomain,
                synthetic_ip: None,
                reason: std::borrow::Cow::Borrowed("reputation hit"),
            }
        } else {
            FilterDecision::Pass
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filter::{ChainOutcome, FilterChain};
    use crate::qtype::QType;

    fn reps() -> Reputation {
        Reputation::new(["evil.example", "Bad.Example.Net."])
    }

    #[tokio::test]
    async fn short_circuit_on_exact_canonical_match() {
        let r = reps();
        let q = DnsQuery::new("evil.example", QType::A);
        let outcome = r.check(&q).await;
        match outcome {
            FilterDecision::ShortCircuit {
                verdict,
                rcode,
                synthetic_ip,
                ..
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(rcode, RCode::NxDomain);
                assert_eq!(synthetic_ip, None);
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn canonicalizes_feed_entry_on_construction() {
        // Feed had `Bad.Example.Net.` with mixed-case + trailing dot.
        // Query asks `bad.example.net` (already canonical).
        let r = reps();
        let q = DnsQuery::new("bad.example.net", QType::A);
        assert!(matches!(
            r.check(&q).await,
            FilterDecision::ShortCircuit { .. }
        ));
    }

    #[tokio::test]
    async fn no_suffix_match_for_reputation() {
        // Sinkhole would suffix-match `sub.evil.example` against
        // `evil.example`. Reputation MUST NOT.
        let r = reps();
        let q = DnsQuery::new("sub.evil.example", QType::A);
        assert_eq!(r.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn empty_feed_passes_everything() {
        let r = Reputation::empty();
        assert!(r.is_empty());
        let q = DnsQuery::new("evil.example", QType::A);
        assert_eq!(r.check(&q).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn replace_entries_atomically_publishes_new_feed() {
        let r = reps();
        let q_new = DnsQuery::new("freshly.bad", QType::A);
        // Before reload: pass.
        assert_eq!(r.check(&q_new).await, FilterDecision::Pass);
        r.replace_entries(["freshly.bad"]);
        // After reload: short-circuit.
        assert!(matches!(
            r.check(&q_new).await,
            FilterDecision::ShortCircuit { .. }
        ));
        // Old entries are NOT preserved: replace_entries is
        // overwrite-semantics, not merge.
        let q_old = DnsQuery::new("evil.example", QType::A);
        assert_eq!(r.check(&q_old).await, FilterDecision::Pass);
    }

    #[tokio::test]
    async fn ignores_empty_feed_lines() {
        // Operator-supplied feeds occasionally have blank lines
        // after a parser splits on newlines. The canonicalizer
        // collapses these to empty strings; the set must drop
        // them rather than treating "" as a valid entry.
        let r = Reputation::new(["", "evil.example", "  "]);
        assert_eq!(r.len(), 1);
    }

    #[tokio::test]
    async fn end_to_end_through_filter_chain() {
        let chain = FilterChain::new(vec![Arc::new(reps())]);
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
                assert_eq!(rcode, RCode::NxDomain);
                assert_eq!(synthetic_ip, None);
                assert_eq!(filter, "reputation");
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
    }
}

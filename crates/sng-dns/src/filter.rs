//! Filter trait + hot-swappable chain.
//!
//! Each filter inspects a [`DnsQuery`] and returns a
//! [`FilterDecision`]:
//!
//! - [`FilterDecision::Pass`] — let the next filter run; if all
//!   filters pass, the resolver answers the query upstream.
//! - [`FilterDecision::ShortCircuit`] — synthesize a response
//!   immediately (sinkhole / reputation NXDOMAIN /
//!   blocked-category response); the resolver is bypassed.
//! - [`FilterDecision::Observe`] — keep resolving upstream, but
//!   stamp the filter's verdict on the emitted
//!   [`sng_core::DnsEvent`] (e.g. an inspect-and-log decision).
//!
//! The chain is held in an [`ArcSwap`] so reputation / category /
//! sinkhole feed reloads can replace the active filter set
//! atomically without disturbing in-flight queries.

use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use async_trait::async_trait;
use sng_core::envelope::Verdict;

use crate::qtype::RCode;
use crate::query::DnsQuery;

/// Outcome of a single filter's check against a query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilterDecision {
    /// No opinion; advance to the next filter.
    Pass,
    /// Short-circuit: synthesize the response described here.
    ///
    /// The chain stops evaluating after this decision; the
    /// resolver is bypassed. Used by sinkhole (synthetic A/AAAA
    /// pointing at a sink IP) and reputation (NXDOMAIN).
    ShortCircuit {
        /// Verdict to stamp on the emitted DnsEvent.
        verdict: Verdict,
        /// Wire RCODE to put on the synthesized response.
        rcode: RCode,
        /// If the synthesized response is a positive answer
        /// (typically a sinkhole hit), the IP to put in the A or
        /// AAAA RDATA. None means "respond with no answer record"
        /// (NXDOMAIN / NOERROR-no-answer).
        synthetic_ip: Option<IpAddr>,
        /// Human-readable reason for the short-circuit. Stamped
        /// onto the trace span only, NOT onto the emitted
        /// [`sng_core::DnsEvent`] (which keeps the schema lean —
        /// the verdict carries enough signal for downstream
        /// dashboards).
        reason: Cow<'static, str>,
    },
    /// Resolve upstream as normal, but the filter wants its
    /// verdict stamped onto the emitted DnsEvent (e.g. a "log"
    /// rule that does not block).
    Observe {
        /// Verdict to stamp on the emitted DnsEvent.
        verdict: Verdict,
        /// Filter-specific reason, used for tracing only.
        reason: Cow<'static, str>,
    },
}

/// A single stage in the DNS filter chain.
///
/// Filters are checked in declaration order; the first
/// non-[`FilterDecision::Pass`] result wins for short-circuits.
/// [`FilterDecision::Observe`] verdicts are layered — the
/// "highest severity" observation wins per
/// [`FilterChain::evaluate`].
#[async_trait]
pub trait Filter: Send + Sync + 'static {
    /// Stable name for tracing / metrics. Matches the dotted
    /// lowercase namespace used by the rest of the workspace
    /// (e.g. `"sinkhole"`, `"reputation"`, `"category"`).
    fn name(&self) -> &'static str;

    /// Inspect the query and return a decision.
    async fn check(&self, query: &DnsQuery) -> FilterDecision;
}

/// Per-tenant filter chain.
///
/// Wrapped in [`ArcSwap`] so reload paths (reputation feed
/// refresh, category map upgrade, sinkhole list reload) can
/// publish a new chain atomically. Readers see a consistent
/// snapshot for the duration of a single [`Self::evaluate`].
pub struct FilterChain {
    filters: ArcSwap<Vec<Arc<dyn Filter>>>,
}

impl std::fmt::Debug for FilterChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let snapshot = self.filters.load();
        f.debug_struct("FilterChain")
            .field("len", &snapshot.len())
            .field(
                "filters",
                &snapshot.iter().map(|f| f.name()).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// Outcome of evaluating the entire chain against a query.
#[derive(Clone, Debug)]
pub enum ChainOutcome {
    /// One filter short-circuited; the resolver is bypassed and
    /// the listener emits the synthesized response below.
    ShortCircuit {
        /// Verdict to stamp on the emitted DnsEvent.
        verdict: Verdict,
        /// Wire RCODE for the synthetic response.
        rcode: RCode,
        /// Optional synthetic A / AAAA RDATA (sinkhole IP).
        synthetic_ip: Option<IpAddr>,
        /// Name of the filter that short-circuited. Used for
        /// tracing / metrics only.
        filter: &'static str,
    },
    /// No filter short-circuited; the resolver is invoked
    /// upstream. The aggregated verdict is the strongest
    /// observation any filter emitted (`Deny > Inspect > Log >
    /// Alert > Allow`) — see [`combine_verdicts`].
    ResolveAndObserve {
        /// Verdict to stamp on the emitted DnsEvent. Defaults to
        /// [`Verdict::Allow`] when no filter offered an opinion.
        verdict: Verdict,
    },
}

impl FilterChain {
    /// Build a new chain. The provided filters are evaluated in
    /// order; pushing the cheapest / highest-hit-rate filter to
    /// the front (typically sinkhole) is the right shape for
    /// production hot paths.
    #[must_use]
    pub fn new(filters: Vec<Arc<dyn Filter>>) -> Self {
        Self {
            filters: ArcSwap::from_pointee(filters),
        }
    }

    /// Atomically replace the filter set. Used on feed-reload
    /// paths; in-flight queries continue running against the
    /// previous snapshot and the next query sees the new chain.
    pub fn replace(&self, new_filters: Vec<Arc<dyn Filter>>) {
        self.filters.store(Arc::new(new_filters));
    }

    /// Number of filters in the current snapshot. Useful for
    /// metrics / assertion in tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.filters.load().len()
    }

    /// Whether the current snapshot has any filters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.filters.load().is_empty()
    }

    /// Evaluate the chain against `query`. The first filter to
    /// return [`FilterDecision::ShortCircuit`] wins; observations
    /// from earlier passes are folded into the final verdict
    /// only on the resolve path.
    pub async fn evaluate(&self, query: &DnsQuery) -> ChainOutcome {
        // Snapshot the chain ONCE per evaluation. arc-swap's
        // load() is wait-free and the resulting Guard derefs to
        // an &Vec<Arc<dyn Filter>> that is pinned for the
        // lifetime of the snapshot — a concurrent replace() will
        // not affect this evaluation.
        let snapshot = self.filters.load();
        let mut observed: Verdict = Verdict::Allow;
        let mut observation_seen = false;
        for filter in snapshot.iter() {
            match filter.check(query).await {
                FilterDecision::Pass => {}
                FilterDecision::ShortCircuit {
                    verdict,
                    rcode,
                    synthetic_ip,
                    reason: _,
                } => {
                    tracing::debug!(
                        target: "sng_dns",
                        filter = filter.name(),
                        name = %query.name,
                        qtype = %query.qtype,
                        verdict = ?verdict,
                        "filter chain short-circuit"
                    );
                    return ChainOutcome::ShortCircuit {
                        verdict,
                        rcode,
                        synthetic_ip,
                        filter: filter.name(),
                    };
                }
                FilterDecision::Observe { verdict, reason: _ } => {
                    observed = combine_verdicts(observed, verdict);
                    observation_seen = true;
                }
            }
        }
        if observation_seen {
            tracing::trace!(
                target: "sng_dns",
                name = %query.name,
                qtype = %query.qtype,
                verdict = ?observed,
                "filter chain observed verdict"
            );
        }
        ChainOutcome::ResolveAndObserve { verdict: observed }
    }
}

/// Fold two verdicts into the "strongest" of the pair.
///
/// "Strongest" is defined by the
/// `Deny > Inspect > Log > Alert > Allow` ordering: a `Deny`
/// always wins, otherwise the more-attention-required verdict
/// wins so an `Inspect` observation does not get swallowed by a
/// later `Allow`-no-opinion stage. Mirrors the
/// `sng_policy_eval::Verdict::is_blocking()` semantics for the
/// blocking case while preserving non-blocking severity ordering.
#[must_use]
pub fn combine_verdicts(a: Verdict, b: Verdict) -> Verdict {
    fn rank(v: Verdict) -> u8 {
        match v {
            // Higher = stronger / wins.
            Verdict::Deny => 4,
            Verdict::Inspect => 3,
            Verdict::Log => 2,
            Verdict::Alert => 1,
            Verdict::Allow => 0,
        }
    }
    if rank(a) >= rank(b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::qtype::QType;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingPass {
        name: &'static str,
        count: Arc<AtomicUsize>,
    }
    #[async_trait]
    impl Filter for CountingPass {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn check(&self, _q: &DnsQuery) -> FilterDecision {
            self.count.fetch_add(1, Ordering::SeqCst);
            FilterDecision::Pass
        }
    }

    struct ShortCircuitDeny;
    #[async_trait]
    impl Filter for ShortCircuitDeny {
        fn name(&self) -> &'static str {
            "test_short_circuit"
        }
        async fn check(&self, _q: &DnsQuery) -> FilterDecision {
            FilterDecision::ShortCircuit {
                verdict: Verdict::Deny,
                rcode: RCode::NxDomain,
                synthetic_ip: None,
                reason: "test".into(),
            }
        }
    }

    struct ObserveAs(Verdict);
    #[async_trait]
    impl Filter for ObserveAs {
        fn name(&self) -> &'static str {
            "test_observe"
        }
        async fn check(&self, _q: &DnsQuery) -> FilterDecision {
            FilterDecision::Observe {
                verdict: self.0,
                reason: "test".into(),
            }
        }
    }

    #[tokio::test]
    async fn pass_only_chain_returns_allow_with_no_observation() {
        let count = Arc::new(AtomicUsize::new(0));
        let chain = FilterChain::new(vec![
            Arc::new(CountingPass {
                name: "a",
                count: count.clone(),
            }) as Arc<dyn Filter>,
            Arc::new(CountingPass {
                name: "b",
                count: count.clone(),
            }),
        ]);
        let q = DnsQuery::new("example.com", QType::A);
        let out = chain.evaluate(&q).await;
        match out {
            ChainOutcome::ResolveAndObserve { verdict } => assert_eq!(verdict, Verdict::Allow),
            other => panic!("expected ResolveAndObserve, got {other:?}"),
        }
        // Every filter must run.
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn short_circuit_stops_chain_immediately() {
        let count = Arc::new(AtomicUsize::new(0));
        let chain = FilterChain::new(vec![
            Arc::new(ShortCircuitDeny) as Arc<dyn Filter>,
            Arc::new(CountingPass {
                name: "after",
                count: count.clone(),
            }),
        ]);
        let q = DnsQuery::new("blocked.example", QType::A);
        let out = chain.evaluate(&q).await;
        match out {
            ChainOutcome::ShortCircuit {
                verdict, filter, ..
            } => {
                assert_eq!(verdict, Verdict::Deny);
                assert_eq!(filter, "test_short_circuit");
            }
            other => panic!("expected ShortCircuit, got {other:?}"),
        }
        // The second filter must NOT run.
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn observations_fold_to_strongest_non_blocking() {
        let chain = FilterChain::new(vec![
            Arc::new(ObserveAs(Verdict::Log)) as Arc<dyn Filter>,
            Arc::new(ObserveAs(Verdict::Inspect)),
            Arc::new(ObserveAs(Verdict::Alert)),
        ]);
        let q = DnsQuery::new("inspect.example", QType::A);
        match chain.evaluate(&q).await {
            ChainOutcome::ResolveAndObserve { verdict } => {
                assert_eq!(verdict, Verdict::Inspect);
            }
            other => panic!("expected ResolveAndObserve, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn replace_publishes_new_chain_atomically() {
        let count_a = Arc::new(AtomicUsize::new(0));
        let count_b = Arc::new(AtomicUsize::new(0));
        let chain = FilterChain::new(vec![Arc::new(CountingPass {
            name: "a",
            count: count_a.clone(),
        }) as Arc<dyn Filter>]);
        let q = DnsQuery::new("example.com", QType::A);
        let _ = chain.evaluate(&q).await;
        assert_eq!(count_a.load(Ordering::SeqCst), 1);
        assert_eq!(count_b.load(Ordering::SeqCst), 0);

        chain.replace(vec![Arc::new(CountingPass {
            name: "b",
            count: count_b.clone(),
        }) as Arc<dyn Filter>]);

        let _ = chain.evaluate(&q).await;
        // Old filter no longer fires; new filter does.
        assert_eq!(count_a.load(Ordering::SeqCst), 1);
        assert_eq!(count_b.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn combine_verdicts_obeys_severity_order() {
        // Deny dominates everything.
        assert_eq!(
            combine_verdicts(Verdict::Allow, Verdict::Deny),
            Verdict::Deny
        );
        assert_eq!(
            combine_verdicts(Verdict::Deny, Verdict::Inspect),
            Verdict::Deny
        );
        // Inspect > Log > Alert > Allow.
        assert_eq!(
            combine_verdicts(Verdict::Inspect, Verdict::Log),
            Verdict::Inspect
        );
        assert_eq!(combine_verdicts(Verdict::Log, Verdict::Alert), Verdict::Log);
        assert_eq!(
            combine_verdicts(Verdict::Alert, Verdict::Allow),
            Verdict::Alert
        );
        // Idempotent on equal.
        assert_eq!(combine_verdicts(Verdict::Log, Verdict::Log), Verdict::Log);
    }
}

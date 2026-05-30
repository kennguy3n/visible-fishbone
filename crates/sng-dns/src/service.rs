//! DNS service: wire the listener, filter chain, resolver, and
//! telemetry emission together.
//!
//! The agent / edge runs one [`DnsService`] per tenant scope.
//! The service:
//!
//! 1. Receives a [`DnsQuery`] from the upstream listener (the
//!    UDP listener in production; an in-process queue in tests).
//! 2. Runs the query through the [`FilterChain`] snapshot.
//! 3. On [`ChainOutcome::ShortCircuit`]: synthesizes the
//!    response immediately (no upstream resolver call). Emits a
//!    [`sng_core::DnsEvent`] with the filter's verdict, zero
//!    latency, and no upstream label.
//! 4. On [`ChainOutcome::ResolveAndObserve`]: invokes the
//!    injected [`Resolver`], measures latency from BEFORE the
//!    resolver call to AFTER the response (or error), and emits
//!    a [`sng_core::DnsEvent`] carrying both the observed
//!    verdict and the live latency / upstream label.
//!
//! Both paths produce exactly one [`TelemetryEvent::Dns`] per
//! handled query. A resolver-error path produces a DnsEvent
//! with `response_code = "SERVFAIL"` (or the mapped upstream
//! RCODE) and the verdict the filter chain offered.
//!
//! The service has NO direct dependency on the wire format —
//! the listener is responsible for parsing UDP packets into
//! [`DnsQuery`] and turning the resulting [`DnsResponse`] back
//! into wire bytes. This keeps the service trivially testable
//! against an in-process queue.

use std::sync::Arc;
use std::time::Instant;

use sng_core::envelope::Verdict;
use sng_core::events::DnsEvent;
use sng_telemetry::source::TelemetryEvent;

use crate::error::DnsError;
use crate::filter::{ChainOutcome, FilterChain};
use crate::qtype::RCode;
use crate::query::{DnsQuery, DnsResponse};
use crate::resolver::Resolver;

/// One-shot per-query outcome. Returned by
/// [`DnsService::handle_query`] so the listener can use the
/// decoded [`DnsResponse`] to build a wire reply.
#[derive(Clone, Debug)]
pub struct HandledQuery {
    /// The response to write back to the client. On a
    /// short-circuit this is the synthesized response (NXDOMAIN
    /// or sinkhole A/AAAA). On the resolve path this is the
    /// upstream's response (or, when the upstream errored, a
    /// synthesised SERVFAIL).
    pub response: DnsResponse,
    /// Whether the filter chain short-circuited (and therefore
    /// the upstream resolver was NOT consulted). Used by the
    /// listener for span / metric annotation.
    pub short_circuited: bool,
    /// The filter that produced the short-circuit, if any.
    /// `None` on the resolve path.
    pub short_circuit_filter: Option<&'static str>,
}

/// DNS service: the orchestrator.
///
/// Holds a shared filter-chain snapshot and a resolver. Events
/// are emitted into a [`tokio::sync::mpsc::Sender`] that the
/// telemetry pipeline drains on its own task. The service does
/// NOT block on telemetry emission — a full channel results in
/// a `try_send` failure that is downgraded to a WARN log and
/// the query is still answered. This is the right trade-off:
/// the agent must keep resolving DNS even when the egress side
/// is back-pressured.
pub struct DnsService<R: Resolver> {
    chain: Arc<FilterChain>,
    resolver: Arc<R>,
    tx: tokio::sync::mpsc::Sender<TelemetryEvent>,
}

impl<R: Resolver> std::fmt::Debug for DnsService<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `resolver` is intentionally not formatted — the
        // [`Resolver`] trait does not require `Debug`, and the
        // upstream label / type-name is not generally useful
        // for the agent's diagnostic output. We surface the
        // chain composition and the telemetry channel capacity
        // instead.
        f.debug_struct("DnsService")
            .field("chain", &*self.chain)
            .field("resolver", &std::any::type_name::<R>())
            .field("tx_capacity", &self.tx.capacity())
            .finish()
    }
}

impl<R: Resolver> DnsService<R> {
    /// Build a service around the given chain + resolver. `tx`
    /// is the producer half of the telemetry pipeline channel
    /// (typically obtained via [`sng_telemetry::source::ChannelSource::new`]).
    #[must_use]
    pub fn new(
        chain: Arc<FilterChain>,
        resolver: Arc<R>,
        tx: tokio::sync::mpsc::Sender<TelemetryEvent>,
    ) -> Self {
        Self {
            chain,
            resolver,
            tx,
        }
    }

    /// Handle one query end-to-end. Runs the filter chain,
    /// resolves upstream if needed, and emits exactly one
    /// [`TelemetryEvent::Dns`] for the listener.
    pub async fn handle_query(&self, query: &DnsQuery) -> HandledQuery {
        match self.chain.evaluate(query).await {
            ChainOutcome::ShortCircuit {
                verdict,
                rcode,
                synthetic_ip,
                filter,
            } => self.handle_short_circuit(query, verdict, rcode, synthetic_ip, filter),
            ChainOutcome::ResolveAndObserve { verdict } => {
                self.handle_resolve(query, verdict).await
            }
        }
    }

    /// Synthesize a response for a [`ChainOutcome::ShortCircuit`]
    /// outcome and emit the corresponding [`DnsEvent`].
    fn handle_short_circuit(
        &self,
        query: &DnsQuery,
        verdict: Verdict,
        rcode: RCode,
        synthetic_ip: Option<std::net::IpAddr>,
        filter: &'static str,
    ) -> HandledQuery {
        let response = match (rcode, synthetic_ip) {
            (RCode::NxDomain, _) => DnsResponse::nxdomain(),
            (RCode::NoError, Some(ip)) => DnsResponse::sinkhole(&query.name, query.qtype, ip),
            // NOERROR-no-answer (e.g. sinkhole hit on an
            // unsupported qtype like MX): build an empty
            // positive response. This is the "name exists but no
            // records of this type" shape and is exactly what a
            // real resolver would return for a sinkhole entry's
            // MX query.
            (RCode::NoError, None) => DnsResponse {
                rcode: RCode::NoError,
                answers: Vec::new(),
                authority: Vec::new(),
                primary_ip: None,
                upstream: None,
            },
            // Any other rcode the filter chain wants to emit
            // (Refused, ServFail) is preserved verbatim. The
            // listener still wraps it in a wire response.
            (other, _) => DnsResponse {
                rcode: other,
                answers: Vec::new(),
                authority: Vec::new(),
                primary_ip: None,
                upstream: None,
            },
        };
        self.emit(DnsEvent {
            query: query.name.clone(),
            qtype: query.qtype.to_string(),
            response_code: response.rcode.to_string(),
            verdict,
            latency_ms: 0,
            upstream: None,
        });
        HandledQuery {
            response,
            short_circuited: true,
            short_circuit_filter: Some(filter),
        }
    }

    /// Run the upstream resolver, emit the corresponding
    /// [`DnsEvent`], and synthesize a SERVFAIL response on
    /// resolver error. The observed verdict from the filter
    /// chain is escalated from [`Verdict::Allow`] to
    /// [`Verdict::Alert`] on the error path so resolver outages
    /// surface in the alerting dashboard; stronger chain-level
    /// verdicts are preserved.
    async fn handle_resolve(&self, query: &DnsQuery, verdict: Verdict) -> HandledQuery {
        let start = Instant::now();
        let resolved = self.resolver.resolve(query).await;
        let latency_ms = u32::try_from(start.elapsed().as_millis()).unwrap_or(u32::MAX);
        match resolved {
            Ok(response) => {
                self.emit(DnsEvent {
                    query: query.name.clone(),
                    qtype: query.qtype.to_string(),
                    response_code: response.rcode.to_string(),
                    verdict,
                    latency_ms,
                    upstream: response.upstream.clone(),
                });
                HandledQuery {
                    response,
                    short_circuited: false,
                    short_circuit_filter: None,
                }
            }
            Err(err) => self.handle_resolver_error(query, verdict, latency_ms, &err),
        }
    }

    /// Common error tail of [`Self::handle_resolve`]. Extracted
    /// so the resolve path stays short and so the verdict
    /// escalation contract is in one place.
    fn handle_resolver_error(
        &self,
        query: &DnsQuery,
        verdict: Verdict,
        latency_ms: u32,
        err: &DnsError,
    ) -> HandledQuery {
        let rcode_str = match err {
            DnsError::UpstreamRcode { rcode } => RCode::from_wire(*rcode).to_string(),
            _ => "SERVFAIL".to_string(),
        };
        tracing::warn!(
            target: "sng_dns",
            name = %query.name,
            qtype = %query.qtype,
            error = %err,
            "resolver error; returning SERVFAIL to client"
        );
        // Verdict ESCALATION on resolver error: if the filter
        // chain only observed `Allow` we surface the failure on
        // the emitted DnsEvent with the supervised
        // [`Verdict::Alert`] so the upstream dashboard groups
        // resolver errors with other alerting signals. If the
        // chain observed something stronger (Inspect / Log /
        // Deny) we keep that — the operator's intent overrides
        // the recovery-time signal.
        let effective_verdict = if matches!(verdict, Verdict::Allow) {
            Verdict::Alert
        } else {
            verdict
        };
        let synthetic = DnsResponse {
            rcode: RCode::ServFail,
            answers: Vec::new(),
            authority: Vec::new(),
            primary_ip: None,
            upstream: None,
        };
        self.emit(DnsEvent {
            query: query.name.clone(),
            qtype: query.qtype.to_string(),
            response_code: rcode_str,
            verdict: effective_verdict,
            latency_ms,
            upstream: None,
        });
        HandledQuery {
            response: synthetic,
            short_circuited: false,
            short_circuit_filter: None,
        }
    }

    /// Fire-and-warn telemetry emission. A full channel is a
    /// soft failure — we log + drop the event rather than block
    /// the resolution path. The pipeline's spool already
    /// implements oldest-drop backpressure semantics; this
    /// front-end choice extends those semantics to the producer
    /// side so a slow drain cannot stall DNS resolution.
    fn emit(&self, event: DnsEvent) {
        if let Err(err) = self.tx.try_send(TelemetryEvent::Dns(event)) {
            tracing::warn!(
                target: "sng_dns",
                error = %err,
                "telemetry channel full or closed; dropping DnsEvent"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::{Category, CategoryAction, CategoryDb};
    use crate::filter::FilterChain;
    use crate::qtype::QType;
    use crate::reputation::Reputation;
    use crate::resolver::StaticResolver;
    use crate::wire::{CLASS_IN, Record};
    use std::net::{IpAddr, Ipv4Addr};

    fn drain(rx: &mut tokio::sync::mpsc::Receiver<TelemetryEvent>) -> Vec<DnsEvent> {
        let mut out = Vec::new();
        while let Ok(ev) = rx.try_recv() {
            if let TelemetryEvent::Dns(d) = ev {
                out.push(d);
            }
        }
        out
    }

    #[tokio::test]
    async fn short_circuit_reputation_emits_nxdomain_event() {
        let chain = Arc::new(FilterChain::new(vec![Arc::new(Reputation::new([
            "malicious.example".to_string(),
        ]))]));
        let resolver = Arc::new(StaticResolver::new("test-upstream"));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let svc = DnsService::new(chain, resolver, tx);

        let q = DnsQuery::new("malicious.example", QType::A);
        let out = svc.handle_query(&q).await;

        assert!(out.short_circuited);
        assert_eq!(out.short_circuit_filter, Some("reputation"));
        assert_eq!(out.response.rcode, RCode::NxDomain);

        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].query, "malicious.example");
        assert_eq!(events[0].response_code, "NXDOMAIN");
        assert_eq!(events[0].verdict, Verdict::Deny);
        assert_eq!(events[0].latency_ms, 0);
        assert!(events[0].upstream.is_none());
    }

    #[tokio::test]
    async fn resolve_path_emits_observed_verdict_with_latency_and_upstream() {
        // Category filter set to "Log" on `news` category — the
        // chain observes verdict = Log, resolves upstream, and
        // emits an event with Log + the resolver's latency and
        // upstream label.
        let mut actions = std::collections::HashMap::new();
        actions.insert("news".to_string(), CategoryAction::Log);
        let db = CategoryDb::build([("news", "bbc.co.uk")], actions);
        let chain = Arc::new(FilterChain::new(vec![Arc::new(Category::new(db))]));

        let resolver = StaticResolver::new("test-upstream-A");
        let answer_ip: IpAddr = "151.101.0.81".parse().unwrap();
        resolver.install(
            "news.bbc.co.uk",
            QType::A,
            DnsResponse {
                rcode: RCode::NoError,
                answers: vec![Record {
                    name: "news.bbc.co.uk".into(),
                    rtype: QType::A,
                    class: CLASS_IN,
                    ttl: 60,
                    rdata: Ipv4Addr::new(151, 101, 0, 81).octets().to_vec(),
                }],
                authority: Vec::new(),
                primary_ip: Some(answer_ip),
                upstream: None,
            },
        );
        let resolver = Arc::new(resolver);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let svc = DnsService::new(chain, resolver, tx);

        let q = DnsQuery::new("news.bbc.co.uk", QType::A);
        let out = svc.handle_query(&q).await;
        assert!(!out.short_circuited);
        assert!(out.short_circuit_filter.is_none());
        assert_eq!(out.response.rcode, RCode::NoError);
        assert_eq!(out.response.primary_ip, Some(answer_ip));

        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].query, "news.bbc.co.uk");
        assert_eq!(events[0].response_code, "NOERROR");
        assert_eq!(events[0].verdict, Verdict::Log);
        assert_eq!(events[0].upstream.as_deref(), Some("test-upstream-A"));
    }

    #[tokio::test]
    async fn resolver_error_emits_servfail_and_escalates_allow_to_alert() {
        // No filter, no upstream entry → StaticResolver returns
        // NXDOMAIN, NOT an error. To force the error path we
        // use a custom resolver that returns Io.
        struct FailingResolver;
        #[async_trait::async_trait]
        impl Resolver for FailingResolver {
            async fn resolve(&self, _q: &DnsQuery) -> Result<DnsResponse, DnsError> {
                Err(DnsError::Io("simulated upstream timeout".into()))
            }
        }
        let chain = Arc::new(FilterChain::new(Vec::new()));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let svc = DnsService::new(chain, Arc::new(FailingResolver), tx);

        let q = DnsQuery::new("anything.example", QType::A);
        let out = svc.handle_query(&q).await;
        assert!(!out.short_circuited);
        assert_eq!(out.response.rcode, RCode::ServFail);

        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].response_code, "SERVFAIL");
        // Allow → Alert escalation when the upstream errored.
        assert_eq!(events[0].verdict, Verdict::Alert);
    }

    #[tokio::test]
    async fn telemetry_channel_full_does_not_block_resolution() {
        // Capacity 1, fill it. Next emit must drop the event
        // (logged WARN) but the query must still be answered.
        let chain = Arc::new(FilterChain::new(vec![Arc::new(Reputation::new([
            "x.example".to_string(),
        ]))]));
        let resolver = Arc::new(StaticResolver::new("up"));
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let svc = DnsService::new(chain, resolver, tx);

        let q = DnsQuery::new("x.example", QType::A);
        let _first = svc.handle_query(&q).await; // fills channel
        let second = svc.handle_query(&q).await; // would block — must drop
        assert!(second.short_circuited);
        assert_eq!(second.response.rcode, RCode::NxDomain);

        // Channel only carried the first event.
        let events = drain(&mut rx);
        assert_eq!(events.len(), 1);
    }
}

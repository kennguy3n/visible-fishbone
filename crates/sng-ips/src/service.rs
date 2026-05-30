//! IPS orchestrator.
//!
//! [`IpsService`] is the brain the firewall datapath calls
//! into when it has a payload to inspect. The service:
//!
//! 1. Resolves / creates the per-flow
//!    [`crate::reassembly::ReassemblyBuffer`] keyed by
//!    `flow_id`.
//! 2. Appends the new bytes to the appropriate direction
//!    on that buffer.
//! 3. Scans the buffer's currently-assembled view against
//!    the active [`crate::matcher::SignatureSet`].
//! 4. For each [`crate::matcher::IpsHit`] not previously
//!    seen on this flow (within the dedup TTL), emits one
//!    [`sng_core::events::IpsEvent`] through the telemetry
//!    channel — `try_send`, never blocking the data path.
//! 5. Folds the surviving hits' actions and, when the
//!    folded action is **terminal** (`Drop` / `Reset` /
//!    `Block`), returns an [`InspectionDecision`] whose
//!    `verdict_escalation` carries a deny
//!    [`FwVerdict`]. The firewall data path applies it.
//!
//! Hot-swappable signature set: [`IpsService::reload_signatures`]
//! swaps the underlying [`arc_swap::ArcSwap`] without
//! taking any data-path lock. Readers see the old set
//! until the next observation; no torn reads.

use arc_swap::ArcSwap;
use lru::LruCache;
use parking_lot::Mutex;
use sng_core::events::IpsEvent;
use sng_fw::flow::{FlowKey, IpProtocol};
use sng_fw::verdict::{FwVerdict, VerdictReason};
use sng_telemetry::TelemetryEvent;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::error::IpsError;
use crate::matcher::{IpsHit, ScanContext, SignatureSet};
use crate::reassembly::{Direction, ReassemblyConfig, ReassemblyTable};
use crate::signature::{Action, Severity, Signature};
use crate::stats::IpsStats;

/// One payload observation from the data path. Producers
/// (the firewall, the SWG sniffer, the user-space pcap
/// demuxer) construct one per inspection-eligible packet.
#[derive(Clone, Debug)]
pub struct PayloadObservation<'a> {
    /// Stable per-flow identifier. The firewall already
    /// computes one for conntrack; reusing it here means
    /// the IPS reassembly buffer is keyed the same as
    /// conntrack.
    pub flow_id: u64,
    /// 5-tuple the firewall observed on the wire. The IPS
    /// uses [`FlowKey::protocol`] and ports to filter
    /// signatures, and the IPs to populate the alert
    /// [`IpsEvent::src_ip`] / [`IpsEvent::dst_ip`].
    pub flow_key: FlowKey,
    /// Direction this payload was observed in.
    pub direction: Direction,
    /// The payload bytes (TCP segment data / UDP datagram
    /// payload / etc.). The service appends these to the
    /// per-flow reassembly buffer before scanning.
    pub payload: &'a [u8],
    /// Monotonic millisecond timestamp. The service uses
    /// this to drive the per-flow / per-sid dedup window.
    pub now_ms: u64,
}

/// Result of one observation. The data path consults
/// [`InspectionDecision::verdict_escalation`]; if it is
/// `Some(v)`, the path replaces its allow verdict with `v`.
#[derive(Clone, Debug, Default)]
pub struct InspectionDecision {
    /// Verdict escalation, if any. `Some(Verdict::Deny(_))`
    /// when at least one matched signature has a terminal
    /// action (`Drop` / `Reset` / `Block`). `None` for
    /// alert-only matches or no match.
    pub verdict_escalation: Option<FwVerdict>,
    /// Number of signature hits the matcher returned (pre-
    /// dedup). Surfaced for unit tests and for downstream
    /// metrics consumers that want a "raw hits" view.
    pub raw_hits: usize,
    /// Number of unique (flow, sid) tuples the service
    /// actually emitted alerts for. `<= raw_hits`.
    pub emitted_alerts: usize,
}

/// Configuration for [`IpsService`].
#[derive(Clone, Debug)]
pub struct IpsServiceConfig {
    /// Max number of flows the reassembly table holds. LRU
    /// evicts the least-recently-accessed flow when full.
    pub max_flows: usize,
    /// Per-direction sliding window of bytes the reassembly
    /// buffer keeps. Older bytes are dropped + counted on
    /// [`IpsStats::record_reassembly_overflow`].
    pub reassembly_window_bytes: usize,
    /// Per-(flow, sid) dedup TTL. The same signature firing
    /// twice on the same flow inside this window emits only
    /// one alert. `Duration::ZERO` disables dedup.
    pub dedup_ttl: Duration,
    /// Max number of (flow, sid) dedup entries to keep at
    /// any one time. Beyond this, the oldest entry is
    /// evicted. Bounds memory in long-running deployments.
    pub dedup_capacity: usize,
}

impl Default for IpsServiceConfig {
    fn default() -> Self {
        Self {
            max_flows: 131_072,
            reassembly_window_bytes: 64 * 1024,
            dedup_ttl: Duration::from_secs(30),
            dedup_capacity: 65_536,
        }
    }
}

/// The IPS service.
///
/// Cheap to share via [`Arc`] — the inner data is the
/// reassembly table (its own locking), the
/// [`ArcSwap<SignatureSet>`] (lock-free read), the
/// dedup table (own mutex), the stats counters (atomics),
/// and the telemetry sender (clone-cheap mpsc handle).
#[derive(Debug)]
pub struct IpsService {
    signatures: ArcSwap<SignatureSet>,
    reassembly: Arc<ReassemblyTable>,
    dedup: Mutex<DedupTable>,
    telemetry: mpsc::Sender<TelemetryEvent>,
    stats: Arc<IpsStats>,
    cfg: IpsServiceConfig,
}

impl IpsService {
    /// Construct an IPS service with an initial (compiled)
    /// signature set, a stats handle, and a telemetry
    /// sender. The reassembly table is sized from
    /// [`IpsServiceConfig::max_flows`].
    #[must_use]
    pub fn new(
        signatures: SignatureSet,
        cfg: IpsServiceConfig,
        stats: Arc<IpsStats>,
        telemetry: mpsc::Sender<TelemetryEvent>,
    ) -> Self {
        let table = ReassemblyTable::new(
            cfg.max_flows,
            ReassemblyConfig {
                window_bytes: cfg.reassembly_window_bytes,
            },
        );
        let dedup = DedupTable::new(cfg.dedup_capacity);
        Self {
            signatures: ArcSwap::new(Arc::new(signatures)),
            reassembly: Arc::new(table),
            dedup: Mutex::new(dedup),
            telemetry,
            stats,
            cfg,
        }
    }

    /// Stats handle. Cheap to clone, all-atomic reads.
    #[must_use]
    pub fn stats(&self) -> &Arc<IpsStats> {
        &self.stats
    }

    /// Reassembly table handle. Mainly for tests / ops
    /// dashboards that want to introspect the per-flow
    /// buffers.
    #[must_use]
    pub fn reassembly(&self) -> &Arc<ReassemblyTable> {
        &self.reassembly
    }

    /// Compile + atomically install a new signature set.
    /// The data path picks up the new set on the very next
    /// [`Self::observe_payload`] call; in-flight scans run
    /// against the previously-installed set.
    ///
    /// # Errors
    ///
    /// - [`IpsError::InvalidSignature`] when one of the
    ///   signatures fails to compile (regex error / no
    ///   patterns / etc.). The previously-installed set
    ///   stays in place.
    pub fn reload_signatures(&self, candidates: Vec<Signature>) -> Result<(), IpsError> {
        match SignatureSet::compile(candidates) {
            Ok(set) => {
                self.signatures.store(Arc::new(set));
                self.stats.record_bundle_load();
                Ok(())
            }
            Err(e) => {
                self.stats.record_bundle_load_failure();
                Err(e)
            }
        }
    }

    /// Number of signatures currently active.
    #[must_use]
    pub fn signature_count(&self) -> usize {
        self.signatures.load().len()
    }

    /// Drop the reassembly buffer for the given flow. Call
    /// from the data path when the flow closes (TCP FIN /
    /// RST / conntrack idle sweep).
    pub fn on_flow_closed(&self, flow_id: u64) {
        self.reassembly.drop_flow(flow_id);
    }

    /// Maintenance tick — called by the producer on a
    /// 1s cadence. Sweeps the dedup table for stale
    /// entries. The reassembly table is swept by the data
    /// path when flows close.
    pub fn tick(&self, now_ms: u64) {
        let ttl_ms = u64::try_from(self.cfg.dedup_ttl.as_millis()).unwrap_or(u64::MAX);
        let mut g = self.dedup.lock();
        g.sweep(now_ms, ttl_ms);
    }

    /// Observe one payload. Returns the inspection
    /// decision.
    ///
    /// Hot path. Does not allocate when there are no
    /// matches.
    pub fn observe_payload(&self, obs: &PayloadObservation<'_>) -> InspectionDecision {
        self.stats.record_payload_scanned(obs.payload.len() as u64);

        // Append into the reassembly buffer and remember how
        // much we dropped from the window. We borrow the
        // buffer as an `Arc` so the scan runs outside the
        // table lock.
        let buf = self.reassembly.get_or_create(obs.flow_id);
        let dropped = buf.append(obs.direction, obs.payload);
        if dropped > 0 {
            self.stats.record_reassembly_overflow(dropped as u64);
        }

        // Snapshot the active signature set.
        let sigs = self.signatures.load();
        if sigs.is_empty() {
            return InspectionDecision::default();
        }

        // Scan under the buffer's read lock. Closures
        // returning Vec is fine — the lock is released as
        // soon as the closure returns.
        let ctx_protocol = obs.flow_key.protocol;
        let sport = obs.flow_key.source_port;
        let dport = obs.flow_key.destination_port;
        let raw_hits: Vec<IpsHit> = buf.with_payload(obs.direction, |payload| {
            let ctx = ScanContext {
                protocol: ctx_protocol,
                source_port: sport,
                destination_port: dport,
                payload,
            };
            sigs.scan(ctx)
        });

        if raw_hits.is_empty() {
            return InspectionDecision::default();
        }

        // Per-(flow, sid) dedup. Suppressed hits do not
        // emit alerts but DO contribute to the action fold
        // — a flow that keeps re-matching a "drop" rule
        // should keep being dropped even if we stop
        // emitting alerts.
        let ttl_ms = u64::try_from(self.cfg.dedup_ttl.as_millis()).unwrap_or(u64::MAX);
        let mut emitted_alerts = 0usize;
        let mut folded: Option<Action> = None;
        let mut top_severity = Severity::Info;
        let mut top_sid: u32 = 0;
        let mut top_msg = String::new();
        // Parallel to `raw_hits`: `true` means the hit
        // passed dedup and must emit a telemetry alert in
        // the post-lock submit pass. Computed under the
        // dedup lock so the lock is held only for the
        // bookkeeping, not for the telemetry channel
        // send. Decoupling decision from emit via a flag
        // vector avoids any reliance on per-key timestamp
        // equality, which is unsafe when multiple
        // observations on the same flow arrive at the
        // same millisecond.
        let mut emit_flags: Vec<bool> = Vec::with_capacity(raw_hits.len());
        {
            let mut dedup = self.dedup.lock();
            for hit in &raw_hits {
                folded = Some(match folded {
                    Some(prev) => IpsHit::fold_action(prev, hit.action),
                    None => hit.action,
                });
                if hit.severity >= top_severity {
                    top_severity = hit.severity;
                    top_sid = hit.sid;
                    top_msg.clone_from(&hit.msg);
                }
                let key = DedupKey {
                    flow_id: obs.flow_id,
                    sid: hit.sid,
                };
                let emit = dedup.should_emit(key, obs.now_ms, ttl_ms);
                emit_flags.push(emit);
                if emit {
                    emitted_alerts += 1;
                } else {
                    self.stats.record_suppressed_dup_hit();
                }
            }
        }

        // Telemetry submit pass — lock-free relative to the
        // dedup map. Iterate raw_hits alongside the
        // pre-computed emit flags so we replay exactly the
        // decisions the dedup pass made.
        if emitted_alerts > 0 {
            for (hit, &emit) in raw_hits.iter().zip(emit_flags.iter()) {
                if !emit {
                    continue;
                }
                let event = build_ips_event(&obs.flow_key, hit);
                if self.telemetry.try_send(TelemetryEvent::Ips(event)).is_err() {
                    self.stats.record_telemetry_drop();
                }
            }
        }

        let action = folded.unwrap_or(Action::Alert);
        self.stats.record_hit(action);

        let verdict_escalation = if is_terminal(action) {
            Some(FwVerdict::deny(VerdictReason::PolicyMatch(format!(
                "ips:sid={top_sid}"
            ))))
        } else {
            None
        };

        InspectionDecision {
            verdict_escalation,
            raw_hits: raw_hits.len(),
            emitted_alerts,
        }
    }
}

/// Terminal actions block the flow; alert-only matches
/// allow the flow but emit an alert.
const fn is_terminal(a: Action) -> bool {
    matches!(a, Action::Drop | Action::Reset | Action::Block)
}

fn build_ips_event(key: &FlowKey, hit: &IpsHit) -> IpsEvent {
    IpsEvent {
        rule_id: hit.sid.to_string(),
        signature: hit.msg.clone(),
        severity: severity_wire_str(hit.severity).to_string(),
        action: action_wire_str(hit.action).to_string(),
        src_ip: key.source_ip.to_string(),
        dst_ip: key.destination_ip.to_string(),
        protocol: protocol_wire_str(key.protocol).to_string(),
    }
}

const fn severity_wire_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

const fn action_wire_str(a: Action) -> &'static str {
    match a {
        Action::Alert => "alert",
        Action::Drop => "drop",
        Action::Reset => "reset",
        Action::Block => "block",
    }
}

const fn protocol_wire_str(p: IpProtocol) -> &'static str {
    p.as_str()
}

/// (Flow, SID) key for the dedup table.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
struct DedupKey {
    flow_id: u64,
    sid: u32,
}

/// Bounded last-seen table that decides whether a
/// `(flow, sid)` hit should emit an alert.
///
/// Backed by an [`lru::LruCache`] so both insert and
/// eviction are O(1). The previous design (`HashMap` +
/// linear-scan-for-min on insert) was O(n) per insert
/// once the table reached `capacity` — that turns into a
/// real latency bottleneck under signature-hit storms
/// because the data path holds the dedup mutex across the
/// eviction scan. The LRU order (most-recently-touched
/// at front) is a strictly better proxy for "stale" than
/// last-seen-timestamp anyway, since the data path always
/// touches an entry on every hit.
#[derive(Debug)]
struct DedupTable {
    inner: LruCache<DedupKey, u64>,
}

impl DedupTable {
    fn new(capacity: usize) -> Self {
        // `NonZeroUsize::MIN` is the canonical const 1 used as
        // the fallback when the caller asks for a zero-capacity
        // table (e.g. test config). The `unwrap_or(MIN)` keeps the
        // call site out of both `expect_used` and `unwrap_used`
        // clippy lints; `.max(1)` then constrains LruCache to its
        // smallest legal size rather than degrading silently.
        let capacity = NonZeroUsize::new(capacity.max(1)).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: LruCache::new(capacity),
        }
    }

    /// Returns `true` if the alert should emit. Updates the
    /// last-seen timestamp on emit. `ttl_ms == 0` always
    /// emits (dedup disabled).
    fn should_emit(&mut self, key: DedupKey, now_ms: u64, ttl_ms: u64) -> bool {
        if ttl_ms == 0 {
            self.touch(key, now_ms);
            return true;
        }
        // `peek` does NOT bump the LRU order — important
        // when the entry exists but is still fresh and we
        // want to leave the dedup window unchanged.
        let last = self.inner.peek(&key).copied();
        match last {
            Some(t) if now_ms.saturating_sub(t) < ttl_ms => false,
            _ => {
                self.touch(key, now_ms);
                true
            }
        }
    }

    fn touch(&mut self, key: DedupKey, now_ms: u64) {
        // `LruCache::put` handles both the insert-or-update
        // semantics AND the O(1) eviction of the
        // least-recently-touched entry when at capacity.
        self.inner.put(key, now_ms);
    }

    /// Drop entries older than `ttl_ms` relative to `now_ms`.
    ///
    /// Implementation walks the cache from the tail (LRU
    /// end) and pops while the entry is stale; once a
    /// non-stale entry is hit we stop, because everything
    /// closer to the head was touched at least as
    /// recently (LRU order tracks last-bump time, and
    /// `touch` is the only path that bumps — see
    /// `should_emit`). This keeps the sweep
    /// O(stale-count) rather than O(n).
    fn sweep(&mut self, now_ms: u64, ttl_ms: u64) {
        if ttl_ms == 0 {
            return;
        }
        while let Some((_, &t)) = self.inner.peek_lru() {
            if now_ms.saturating_sub(t) < ttl_ms {
                break;
            }
            self.inner.pop_lru();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{Anchor, Pattern, PortFilter, Severity, Signature};
    use pretty_assertions::assert_eq;
    use std::net::IpAddr;

    fn key_tcp(sport: u16, dport: u16) -> FlowKey {
        FlowKey {
            source_ip: "10.0.0.1".parse::<IpAddr>().unwrap(),
            destination_ip: "10.0.0.2".parse::<IpAddr>().unwrap(),
            source_port: sport,
            destination_port: dport,
            protocol: IpProtocol::Tcp,
        }
    }

    fn literal_sig(sid: u32, needle: &[u8], action: Action) -> Signature {
        Signature {
            sid,
            msg: format!("sid-{sid}"),
            severity: Severity::Medium,
            action,
            protocol: IpProtocol::Tcp,
            ports: PortFilter::default(),
            patterns: vec![Pattern::Literal(needle.to_vec())],
            anchor: Anchor::default(),
        }
    }

    fn mk_service(sigs: Vec<Signature>) -> (IpsService, mpsc::Receiver<TelemetryEvent>) {
        let set = SignatureSet::compile(sigs).unwrap();
        let (tx, rx) = mpsc::channel(64);
        let svc = IpsService::new(
            set,
            IpsServiceConfig::default(),
            Arc::new(IpsStats::default()),
            tx,
        );
        (svc, rx)
    }

    #[test]
    fn empty_signature_set_returns_no_decision() {
        let (svc, mut rx) = mk_service(vec![]);
        let obs = PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"GET / HTTP/1.1\r\n",
            now_ms: 1_000,
        };
        let d = svc.observe_payload(&obs);
        assert_eq!(d.raw_hits, 0);
        assert_eq!(d.emitted_alerts, 0);
        assert!(d.verdict_escalation.is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn alert_action_emits_event_but_no_verdict_escalation() {
        let (svc, mut rx) = mk_service(vec![literal_sig(1001, b"BADWORD", Action::Alert)]);
        let obs = PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"hello BADWORD world",
            now_ms: 1_000,
        };
        let d = svc.observe_payload(&obs);
        assert_eq!(d.raw_hits, 1);
        assert_eq!(d.emitted_alerts, 1);
        assert!(d.verdict_escalation.is_none());
        let ev = rx.try_recv().unwrap();
        match ev {
            TelemetryEvent::Ips(e) => {
                assert_eq!(e.rule_id, "1001");
                assert_eq!(e.action, "alert");
                assert_eq!(e.protocol, "tcp");
            }
            _ => panic!("expected Ips event"),
        }
    }

    #[test]
    fn terminal_action_emits_event_and_escalates_verdict() {
        let (svc, mut rx) = mk_service(vec![literal_sig(2002, b"EXPLOIT", Action::Drop)]);
        let obs = PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"prefix EXPLOIT suffix",
            now_ms: 1_000,
        };
        let d = svc.observe_payload(&obs);
        assert_eq!(d.raw_hits, 1);
        assert_eq!(d.emitted_alerts, 1);
        let v = d.verdict_escalation.expect("expected deny escalation");
        assert_eq!(v.disposition, sng_core::envelope::Verdict::Deny);
        assert!(matches!(v.reason, VerdictReason::PolicyMatch(_)));
        let ev = rx.try_recv().unwrap();
        match ev {
            TelemetryEvent::Ips(e) => assert_eq!(e.action, "drop"),
            _ => panic!("expected Ips event"),
        }
    }

    #[test]
    fn dedup_window_suppresses_repeat_alerts_on_same_flow() {
        let (svc, mut rx) = mk_service(vec![literal_sig(3003, b"DUP", Action::Alert)]);
        let key = key_tcp(40000, 80);
        let first = PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"DUP",
            now_ms: 1_000,
        };
        let d1 = svc.observe_payload(&first);
        assert_eq!(d1.emitted_alerts, 1);
        let _ev = rx.try_recv().unwrap();
        // Reset buffer so the next append doesn't keep DUP
        // still matching the old bytes.
        svc.on_flow_closed(1);
        let again = PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"DUP",
            now_ms: 1_500,
        };
        let d2 = svc.observe_payload(&again);
        assert_eq!(d2.raw_hits, 1);
        assert_eq!(d2.emitted_alerts, 0);
        assert!(rx.try_recv().is_err());
        assert_eq!(svc.stats.snapshot().suppressed_dup_hits, 1);
    }

    #[test]
    fn dedup_window_expires_alert_emits_again() {
        let cfg = IpsServiceConfig {
            dedup_ttl: Duration::from_millis(100),
            ..IpsServiceConfig::default()
        };
        let set = SignatureSet::compile(vec![literal_sig(4004, b"DUP2", Action::Alert)]).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let svc = IpsService::new(set, cfg, Arc::new(IpsStats::default()), tx);
        let key = key_tcp(40000, 80);
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"DUP2",
            now_ms: 1_000,
        });
        let _ = rx.try_recv().unwrap();
        svc.on_flow_closed(1);
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"DUP2",
            now_ms: 1_050,
        });
        // Still inside the 100ms window.
        assert!(rx.try_recv().is_err());
        svc.on_flow_closed(1);
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"DUP2",
            now_ms: 2_000,
        });
        let _ = rx.try_recv().unwrap();
    }

    #[test]
    fn different_flows_do_not_share_dedup_state() {
        let (svc, mut rx) = mk_service(vec![literal_sig(5005, b"X", Action::Alert)]);
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"X",
            now_ms: 1_000,
        });
        let _ = rx.try_recv().unwrap();
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 2,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"X",
            now_ms: 1_000,
        });
        let _ = rx.try_recv().unwrap();
    }

    #[test]
    fn reload_signatures_swaps_set_atomically() {
        let (svc, _rx) = mk_service(vec![literal_sig(6006, b"OLD", Action::Alert)]);
        assert_eq!(svc.signature_count(), 1);
        svc.reload_signatures(vec![
            literal_sig(7007, b"NEW1", Action::Drop),
            literal_sig(7008, b"NEW2", Action::Block),
        ])
        .unwrap();
        assert_eq!(svc.signature_count(), 2);
        assert_eq!(svc.stats.snapshot().bundle_loads, 1);
        assert_eq!(svc.stats.snapshot().bundle_load_failures, 0);
    }

    #[test]
    fn reload_signatures_failure_keeps_old_set() {
        let (svc, _rx) = mk_service(vec![literal_sig(8008, b"KEEP", Action::Alert)]);
        // No patterns is an invalid signature.
        let bad = Signature {
            sid: 9009,
            msg: "bad".into(),
            severity: Severity::Low,
            action: Action::Alert,
            protocol: IpProtocol::Tcp,
            ports: PortFilter::default(),
            patterns: vec![],
            anchor: Anchor::default(),
        };
        let err = svc.reload_signatures(vec![bad]).unwrap_err();
        assert!(matches!(err, IpsError::InvalidSignature { .. }));
        assert_eq!(svc.signature_count(), 1, "old set must stay in place");
        assert_eq!(svc.stats.snapshot().bundle_load_failures, 1);
    }

    #[test]
    fn telemetry_full_drops_alert_and_counts_it() {
        // Channel of size 1; fill it, then trigger a hit.
        let set = SignatureSet::compile(vec![literal_sig(1010, b"X", Action::Alert)]).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        // Pre-fill the channel so try_send fails.
        tx.try_send(TelemetryEvent::Ips(IpsEvent {
            rule_id: "0".into(),
            signature: "pad".into(),
            severity: "info".into(),
            action: "alert".into(),
            src_ip: "0.0.0.0".into(),
            dst_ip: "0.0.0.0".into(),
            protocol: "tcp".into(),
        }))
        .unwrap();
        let svc = IpsService::new(
            set,
            IpsServiceConfig::default(),
            Arc::new(IpsStats::default()),
            tx,
        );
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"X",
            now_ms: 1_000,
        });
        assert_eq!(svc.stats.snapshot().telemetry_drops, 1);
        // Drain the pad event.
        let _ = rx.try_recv().unwrap();
    }

    #[test]
    fn tick_sweeps_expired_dedup_entries() {
        let cfg = IpsServiceConfig {
            dedup_ttl: Duration::from_millis(100),
            ..IpsServiceConfig::default()
        };
        let set = SignatureSet::compile(vec![literal_sig(1011, b"S", Action::Alert)]).unwrap();
        let (tx, _rx) = mpsc::channel(64);
        let svc = IpsService::new(set, cfg, Arc::new(IpsStats::default()), tx);
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"S",
            now_ms: 1_000,
        });
        assert_eq!(svc.dedup.lock().inner.len(), 1);
        // Tick well past the TTL.
        svc.tick(10_000);
        assert_eq!(svc.dedup.lock().inner.len(), 0);
    }

    #[test]
    fn flow_close_drops_reassembly_state() {
        let (svc, _rx) = mk_service(vec![literal_sig(1012, b"Z", Action::Alert)]);
        let _ = svc.observe_payload(&PayloadObservation {
            flow_id: 42,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"Z",
            now_ms: 1_000,
        });
        assert_eq!(svc.reassembly.len(), 1);
        svc.on_flow_closed(42);
        assert_eq!(svc.reassembly.len(), 0);
    }

    #[test]
    fn dedup_ttl_zero_disables_dedup() {
        let cfg = IpsServiceConfig {
            dedup_ttl: Duration::ZERO,
            ..IpsServiceConfig::default()
        };
        let set = SignatureSet::compile(vec![literal_sig(1013, b"R", Action::Alert)]).unwrap();
        let (tx, mut rx) = mpsc::channel(64);
        let svc = IpsService::new(set, cfg, Arc::new(IpsStats::default()), tx);
        for ts in [1_000_u64, 1_001, 1_002, 1_003] {
            svc.on_flow_closed(1);
            let _ = svc.observe_payload(&PayloadObservation {
                flow_id: 1,
                flow_key: key_tcp(40000, 80),
                direction: Direction::Originator,
                payload: b"R",
                now_ms: ts,
            });
        }
        let mut emitted = 0;
        while rx.try_recv().is_ok() {
            emitted += 1;
        }
        assert_eq!(emitted, 4);
    }

    #[test]
    fn fold_action_prefers_more_severe() {
        let sigs = vec![
            literal_sig(2001, b"A", Action::Alert),
            literal_sig(2002, b"B", Action::Drop),
        ];
        let (svc, _rx) = mk_service(sigs);
        let d = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key_tcp(40000, 80),
            direction: Direction::Originator,
            payload: b"A and B",
            now_ms: 1_000,
        });
        assert_eq!(d.raw_hits, 2);
        // The drop wins; verdict_escalation is Some(deny).
        assert!(d.verdict_escalation.is_some());
    }

    #[test]
    fn dedup_table_evicts_lru_at_capacity() {
        // Pin the architectural contract for the
        // bounded LRU dedup table: at capacity, the
        // least-recently-touched key is evicted in O(1).
        let mut tbl = DedupTable::new(2);
        let a = DedupKey { flow_id: 1, sid: 1 };
        let b = DedupKey { flow_id: 2, sid: 1 };
        let c = DedupKey { flow_id: 3, sid: 1 };
        // a + b take the only two slots.
        assert!(tbl.should_emit(a, 100, 0));
        assert!(tbl.should_emit(b, 101, 0));
        assert!(tbl.inner.contains(&a));
        assert!(tbl.inner.contains(&b));
        // Touch `a` to bump it to MRU. Adding `c` should
        // then evict `b` (now LRU) — NOT `a`.
        assert!(tbl.should_emit(a, 102, 0));
        assert!(tbl.should_emit(c, 103, 0));
        assert!(tbl.inner.contains(&a));
        assert!(!tbl.inner.contains(&b));
        assert!(tbl.inner.contains(&c));
        assert_eq!(tbl.inner.len(), 2);
    }

    #[test]
    fn two_observations_at_same_ms_emit_correct_signature() {
        // Pin the architectural contract for the
        // dedup/emit decoupling: when two observations on
        // the same flow arrive at the SAME millisecond and
        // a previously-seen signature reappears alongside
        // a NEW signature, the new one must emit and the
        // repeat one must NOT.
        let sigs = vec![
            literal_sig(7001, b"AAA", Action::Alert),
            literal_sig(7002, b"BBB", Action::Alert),
        ];
        let (svc, mut rx) = mk_service(sigs);
        let key = key_tcp(40000, 80);
        // Observation 1: only sig 7001 fires.
        let d1 = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"AAA",
            now_ms: 5_000,
        });
        assert_eq!(d1.emitted_alerts, 1);
        let ev1 = rx.try_recv().unwrap();
        match ev1 {
            TelemetryEvent::Ips(e) => assert_eq!(e.rule_id, "7001"),
            _ => panic!("expected Ips event"),
        }
        // Clear flow state so the next observation sees a
        // fresh payload (not a buffered re-match of AAA).
        svc.on_flow_closed(1);
        // Observation 2 at the SAME now_ms=5_000: both
        // sig 7001 (suppressed by dedup) and sig 7002
        // (new) fire on the matcher pass.
        let d2 = svc.observe_payload(&PayloadObservation {
            flow_id: 1,
            flow_key: key,
            direction: Direction::Originator,
            payload: b"AAA-BBB",
            now_ms: 5_000,
        });
        assert_eq!(d2.raw_hits, 2);
        assert_eq!(d2.emitted_alerts, 1);
        let ev2 = rx.try_recv().unwrap();
        match ev2 {
            TelemetryEvent::Ips(e) => {
                // The bug emitted "7001" here (replaying
                // the dedup decision via timestamp
                // equality), not "7002". After the fix the
                // suppressed sig must NOT re-emit and the
                // new sig must.
                assert_eq!(e.rule_id, "7002");
                assert_eq!(e.action, "alert");
            }
            _ => panic!("expected Ips event"),
        }
        // Exactly one telemetry event on this observation.
        assert!(rx.try_recv().is_err());
        // Exactly one suppression accounted for.
        assert_eq!(svc.stats.snapshot().suppressed_dup_hits, 1);
    }

    #[test]
    fn dedup_table_sweep_drops_only_stale_at_tail() {
        // Pin the architectural contract for the
        // O(stale-count) sweep: it walks from the LRU
        // end, popping stale entries, and stops at the
        // first non-stale one.
        let mut tbl = DedupTable::new(8);
        for (i, ts) in [(1_u64, 100_u64), (2, 200), (3, 300), (4, 400)] {
            assert!(tbl.should_emit(DedupKey { flow_id: i, sid: 1 }, ts, 0,));
        }
        // Cutoff: anything older than now-150 is stale.
        // now=350, ttl=150 → keep entries newer than 200.
        // 100 is stale, 200 is stale (350 - 200 == 150,
        // not < 150), 300 and 400 are fresh.
        tbl.sweep(350, 150);
        assert!(!tbl.inner.contains(&DedupKey { flow_id: 1, sid: 1 }));
        assert!(!tbl.inner.contains(&DedupKey { flow_id: 2, sid: 1 }));
        assert!(tbl.inner.contains(&DedupKey { flow_id: 3, sid: 1 }));
        assert!(tbl.inner.contains(&DedupKey { flow_id: 4, sid: 1 }));
    }
}

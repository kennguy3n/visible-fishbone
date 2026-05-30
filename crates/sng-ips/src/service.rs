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
use parking_lot::Mutex;
use sng_core::events::IpsEvent;
use sng_fw::flow::{FlowKey, IpProtocol};
use sng_fw::verdict::{FwVerdict, VerdictReason};
use sng_telemetry::TelemetryEvent;
use std::collections::HashMap;
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
                if dedup.should_emit(key, obs.now_ms, ttl_ms) {
                    // Hold the dedup lock only long enough
                    // to record the emission; the actual
                    // telemetry submit happens after the
                    // lock is released so a saturated
                    // pipeline can't stall other producers.
                    emitted_alerts += 1;
                } else {
                    self.stats.record_suppressed_dup_hit();
                }
            }
        }

        // Telemetry submit pass — lock-free relative to the
        // dedup map.
        if emitted_alerts > 0 {
            let mut emitted_this_pass = 0usize;
            for hit in &raw_hits {
                // Repeat the dedup check via a peek so we
                // emit exactly the hits we counted above.
                // The dedup table won't change between the
                // two checks because no other observation
                // is in flight for this (flow, sid) — the
                // service is called serially per flow at
                // the data-path layer.
                let key = DedupKey {
                    flow_id: obs.flow_id,
                    sid: hit.sid,
                };
                if !self.dedup.lock().was_emitted_at(key, obs.now_ms) {
                    continue;
                }
                if emitted_this_pass >= emitted_alerts {
                    break;
                }
                emitted_this_pass += 1;
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

/// Bounded last-seen table that decides whether an
/// (flow, sid) hit should emit an alert.
#[derive(Debug)]
struct DedupTable {
    capacity: usize,
    map: HashMap<DedupKey, u64>,
}

impl DedupTable {
    fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            map: HashMap::new(),
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
        let last = self.map.get(&key).copied();
        match last {
            Some(t) if now_ms.saturating_sub(t) < ttl_ms => false,
            _ => {
                self.touch(key, now_ms);
                true
            }
        }
    }

    /// Did this (flow, sid) record its emit at exactly
    /// `now_ms`? Used in the post-lock telemetry submit
    /// loop to find the hits the dedup pass selected.
    fn was_emitted_at(&self, key: DedupKey, now_ms: u64) -> bool {
        self.map.get(&key) == Some(&now_ms)
    }

    fn touch(&mut self, key: DedupKey, now_ms: u64) {
        if self.map.len() >= self.capacity && !self.map.contains_key(&key) {
            // Evict oldest by last-seen.
            let victim = self.map.iter().min_by_key(|(_, t)| **t).map(|(k, _)| *k);
            if let Some(v) = victim {
                self.map.remove(&v);
            }
        }
        self.map.insert(key, now_ms);
    }

    /// Drop entries older than `ttl_ms` relative to `now_ms`.
    fn sweep(&mut self, now_ms: u64, ttl_ms: u64) {
        if ttl_ms == 0 {
            return;
        }
        self.map.retain(|_, t| now_ms.saturating_sub(*t) < ttl_ms);
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
        assert_eq!(svc.dedup.lock().map.len(), 1);
        // Tick well past the TTL.
        svc.tick(10_000);
        assert_eq!(svc.dedup.lock().map.len(), 0);
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
}

//! The firewall service ties conntrack, the verdict cache,
//! the app-id resolver, the policy adapter, the telemetry
//! emitter, and the stats counters together. Producers (the
//! packet observer, the user-space pcap demuxer, eBPF
//! perf-ringbuf reader) call [`FwService::observe_packet`];
//! the service does the rest:
//!
//! 1. Resolve / refine app id from the (optional) first-payload
//!    segment via [`crate::appid::AppIdResolver`].
//! 2. Look up or create the flow in [`crate::conntrack::ConnTable`].
//! 3. If the flow is brand-new, evaluate policy through
//!    [`crate::policy::FwPolicyAdapter`] and cache the verdict
//!    in [`crate::verdict::VerdictCache`].
//! 4. If the flow has TCP flags, advance the state machine.
//! 5. Credit the observed byte count to the originator or
//!    responder counter.
//! 6. Emit a [`sng_core::events::FlowEvent`] through
//!    [`sng_telemetry::PipelineHandle::try_submit`] (never
//!    blocks the data path; full pipeline → drop + counter).
//! 7. Return the firewall verdict to the caller so the data
//!    path can apply it.
//!
//! Maintenance: [`FwService::tick`] runs the conntrack idle
//! sweep + the verdict-cache expiry sweep + emits a closing
//! [`sng_core::events::FlowEvent`] for every flow the
//! sweeper drops. Producers should call it on a 1s cadence
//! from a dedicated task.

use sng_core::envelope::Verdict;
use sng_core::events::FlowEvent;
use sng_telemetry::TelemetryEvent;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::appid::{AppId, AppIdResolver};
use crate::conntrack::{ConnTable, LookupOutcome};
use crate::error::FwError;
use crate::flow::{FlowDirection, FlowKey, FlowState};
use crate::policy::{FlowIdentity, FwPolicyAdapter};
use crate::stats::FwStats;
use crate::verdict::{FwVerdict, VerdictCache, VerdictReason};

/// One observation of a packet on a flow. Producers
/// construct this from their packet metadata (5-tuple, TCP
/// flags if applicable, the optional first-payload segment
/// for app-id sniffing, the byte count).
#[derive(Clone, Debug)]
pub struct PacketObservation<'a> {
    /// 5-tuple as observed on the wire. The service flips
    /// originator/responder semantics based on existing
    /// conntrack entries.
    pub key: FlowKey,
    /// Direction the producer believes the packet is in.
    /// Used only on first observation to populate the new
    /// flow's [`FlowState::direction`].
    pub direction: FlowDirection,
    /// Optional first-payload segment for app-id sniffing.
    /// Should be the *bytes after the TCP header* if
    /// available, empty otherwise.
    pub payload: &'a [u8],
    /// TCP flags byte if the protocol is TCP. `None` for
    /// UDP / ICMP / other. The service advances the TCP
    /// state machine only when this is set.
    pub tcp_flags: Option<u8>,
    /// Byte count to credit to the appropriate side of the
    /// flow.
    pub bytes: u64,
    /// Monotonic millisecond timestamp the producer
    /// observed the packet at. The service uses this to
    /// update last_seen and to drive cache TTL / conntrack
    /// idle.
    pub now_ms: u64,
}

/// Result of processing one packet observation.
#[derive(Clone, Debug)]
pub struct PacketDecision {
    /// The firewall verdict for this flow. Cached after the
    /// first packet so subsequent observations short-circuit.
    pub verdict: FwVerdict,
    /// The app id the resolver settled on (may be `Unknown`
    /// when the producer has no payload).
    pub app_id: AppId,
    /// Whether the flow is brand new (policy was evaluated)
    /// or existing (cache hit). Useful for downstream
    /// dashboards.
    pub is_new_flow: bool,
}

/// Orchestrator. Owns conntrack, the verdict cache, the
/// app-id resolver, the policy adapter, the telemetry
/// pipeline handle, and the stats counters.
///
/// The telemetry sink is a raw [`mpsc::Sender`] rather than
/// a [`sng_telemetry::PipelineHandle`] so the firewall
/// doesn't pull in the pipeline's pcap-ring dependency (the
/// firewall never records raw packets — that's the IPS
/// crate's job). The Sender's other end is owned by the
/// production [`sng_telemetry::Pipeline`] task; in tests
/// the receiver is held by the test itself.
#[derive(Debug)]
pub struct FwService {
    conntrack: Arc<ConnTable>,
    verdict_cache: Arc<VerdictCache>,
    app_id: AppIdResolver,
    policy: FwPolicyAdapter,
    telemetry: mpsc::Sender<TelemetryEvent>,
    stats: Arc<FwStats>,
    /// Identity the firewall has on the local agent. The
    /// service threads this into every policy evaluation so
    /// the engine has site/device/user context. Updated
    /// out-of-band by the enrollment layer.
    identity: Arc<parking_lot::RwLock<FlowIdentity>>,
}

impl FwService {
    /// Construct a service with the supplied dependencies.
    ///
    /// Callers are expected to construct the conntrack table +
    /// verdict cache once at startup and share Arcs across the
    /// orchestrator and any maintenance tasks.
    #[must_use]
    pub fn new(
        conntrack: Arc<ConnTable>,
        verdict_cache: Arc<VerdictCache>,
        app_id: AppIdResolver,
        policy: FwPolicyAdapter,
        telemetry: mpsc::Sender<TelemetryEvent>,
        stats: Arc<FwStats>,
    ) -> Self {
        Self {
            conntrack,
            verdict_cache,
            app_id,
            policy,
            telemetry,
            stats,
            identity: Arc::new(parking_lot::RwLock::new(FlowIdentity::default())),
        }
    }

    /// Replace the identity used for subsequent policy
    /// evaluations. Cheap — copies on write.
    pub fn set_identity(&self, identity: FlowIdentity) {
        *self.identity.write() = identity;
    }

    /// Snapshot of the stats counters.
    #[must_use]
    pub fn stats(&self) -> &Arc<FwStats> {
        &self.stats
    }

    /// Snapshot of the conntrack table size.
    #[must_use]
    pub fn conntrack(&self) -> &Arc<ConnTable> {
        &self.conntrack
    }

    /// Process one packet observation. Returns the verdict
    /// the data path should apply.
    ///
    /// # Errors
    ///
    /// [`FwError::ConntrackFull`] when conntrack is at
    /// capacity and eviction couldn't free a slot. The
    /// caller should fail the flow closed.
    pub fn observe_packet(&self, obs: &PacketObservation<'_>) -> Result<PacketDecision, FwError> {
        let (outcome, entry) =
            self.conntrack
                .lookup_or_create(obs.key, obs.direction, obs.now_ms)?;

        // Resolve / refine the app id. On a brand new flow
        // we run the port heuristic + SNI sniff. On an
        // existing flow we leave the stored app id alone
        // unless we have a TLS-without-SNI that the new
        // payload can promote.
        // Surface capacity-pressure evictions to ops via
        // FwStats so undersized conntrack tables become
        // visible on dashboards. The ConnTable doesn't hold
        // an Arc<FwStats> directly (it lives a layer below);
        // the outcome variant carries the count instead.
        if let LookupOutcome::Created {
            evicted_for_capacity,
        } = outcome
        {
            for _ in 0..evicted_for_capacity {
                self.stats.record_flow_evicted_capacity();
            }
        }
        let stored_app = entry.state.app_id.clone();
        let resolved_app = if outcome.is_created() {
            let r = self.app_id.resolve(&obs.key, obs.payload).unwrap_or_else(|e| {
                tracing::debug!(error = ?e, "app-id sniff failed; defaulting to port heuristic");
                self.app_id.port.classify(&obs.key)
            });
            self.stats.record_flow_created();
            r
        } else {
            match stored_app {
                Some(AppId::Tls { sni: None }) if !obs.payload.is_empty() => self
                    .app_id
                    .refine(AppId::Tls { sni: None }, obs.payload)
                    .unwrap_or(AppId::Tls { sni: None }),
                Some(app) => app,
                None => AppId::Unknown,
            }
        };

        // Verdict: hit the cache; on miss, run policy and
        // populate the cache.
        let cache_key = match outcome {
            LookupOutcome::ExistingReverse => entry.flow_key,
            _ => obs.key,
        };
        let (verdict, is_new) = if let Some(v) = self.verdict_cache.get(&cache_key, obs.now_ms) {
            self.stats.record_cache_hit();
            (v, false)
        } else {
            self.stats.record_cache_miss();
            self.stats.record_policy_eval();
            let identity = self.identity.read().clone();
            let v = match self
                .policy
                .evaluate(&entry.flow_key, &resolved_app, &identity)
            {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = ?e, "policy evaluator unavailable; failing closed");
                    self.stats.record_policy_failure();
                    FwVerdict::deny(VerdictReason::FailClosed)
                }
            };
            self.verdict_cache.insert(cache_key, v.clone(), obs.now_ms);
            (v, outcome.is_created())
        };
        self.stats.record_verdict(verdict.disposition);

        // Update flow state: TCP state machine, byte counts,
        // last seen, app id. The closure runs under the
        // conntrack mutex; `with_entry` returns `false` only
        // when the entry has been swept away between the
        // `lookup_or_create` above and now (a concurrent
        // tick() racing with this observe_packet call). When
        // that happens we credit a `record_state_update_race`
        // counter so ops can detect the rare collision
        // pattern (it would mean conntrack is sweeping more
        // aggressively than the data path can re-create
        // flows, e.g. timeouts set too short).
        let is_reverse = matches!(outcome, LookupOutcome::ExistingReverse);
        let updated = self.conntrack.with_entry(&entry.flow_key, |state| {
            if let Some(flags) = obs.tcp_flags {
                state.advance_tcp(flags);
            }
            if is_reverse {
                state.observe_responder(obs.bytes, obs.now_ms);
            } else {
                state.observe_originator(obs.bytes, obs.now_ms);
            }
            state.app_id = Some(resolved_app.clone());
        });
        if !updated {
            self.stats.record_state_update_race();
        }

        // Emit a per-packet flow event for telemetry. The
        // pipeline applies its own dedup + redact + enrich;
        // we just fire-and-forget. Full pipeline = drop +
        // counter (we never block the data path on
        // telemetry).
        let event = self.build_flow_event(&entry.flow_key, &resolved_app, &verdict, obs.now_ms);
        self.emit_event(event);

        Ok(PacketDecision {
            verdict,
            app_id: resolved_app,
            is_new_flow: is_new,
        })
    }

    /// Run periodic maintenance: idle-sweep conntrack,
    /// sweep-expired verdict cache, emit closing FlowEvents
    /// for the dropped conntrack entries. Producers should
    /// call this on a 1s cadence.
    pub fn tick(&self, now_ms: u64) {
        let dropped = self.conntrack.sweep_idle(now_ms);
        for entry in &dropped {
            self.stats.record_flow_evicted_idle();
            // Final event for the flow with whatever verdict
            // the cache still holds (if any). If the cache
            // entry expired alongside the conntrack entry,
            // we use a synthetic "bypass" verdict to ensure
            // the event has the right shape.
            let app = entry.state.app_id.clone().unwrap_or(AppId::Unknown);
            let v = self
                .verdict_cache
                .get(&entry.flow_key, now_ms)
                .unwrap_or_else(|| FwVerdict::allow(VerdictReason::Bypass));
            let ev =
                Self::build_flow_event_from_state(&entry.flow_key, &entry.state, &app, &v, now_ms);
            self.emit_event(ev);
        }
        let _expired = self.verdict_cache.sweep_expired(now_ms);
    }

    /// Trigger a policy-bundle reload. Drops every cached
    /// verdict so the new bundle's rules apply on the next
    /// packet for each existing flow. Producers should call
    /// this from the policy puller's "bundle changed" hook.
    pub fn on_policy_reload(&self) {
        self.verdict_cache.clear_all();
    }

    /// Compose a [`FlowEvent`] from the live state of a flow.
    /// Used on every packet.
    fn build_flow_event(
        &self,
        key: &FlowKey,
        app: &AppId,
        verdict: &FwVerdict,
        now_ms: u64,
    ) -> FlowEvent {
        let entry = self.conntrack.snapshot(key);
        let (bytes_in, bytes_out, duration_ms) = entry.as_ref().map_or((0, 0, 0), |e| {
            (
                e.state.bytes_in(),
                e.state.bytes_out(),
                e.state.duration_ms(),
            )
        });
        let _ = now_ms;
        let fields = key.to_event_fields();
        FlowEvent {
            src_ip: fields.src_ip,
            dst_ip: fields.dst_ip,
            src_port: fields.src_port,
            dst_port: fields.dst_port,
            protocol: fields.protocol.to_owned(),
            app_id: Some(app.as_str().to_owned()),
            verdict: verdict.to_wire(),
            score: verdict.score,
            bytes_in,
            bytes_out,
            duration_ms,
        }
    }

    /// Build an event from an already-snapshot'd state — used
    /// by [`Self::tick`] which has the [`FlowState`] in hand
    /// from the conntrack sweep.
    ///
    /// Free of `&self` because no instance state is read —
    /// callers don't need a method-on-self, but keeping it
    /// as an associated fn keeps it grouped with the other
    /// [`FlowEvent`] builders for the data path.
    fn build_flow_event_from_state(
        key: &FlowKey,
        state: &FlowState,
        app: &AppId,
        verdict: &FwVerdict,
        now_ms: u64,
    ) -> FlowEvent {
        let _ = now_ms;
        let fields = key.to_event_fields();
        FlowEvent {
            src_ip: fields.src_ip,
            dst_ip: fields.dst_ip,
            src_port: fields.src_port,
            dst_port: fields.dst_port,
            protocol: fields.protocol.to_owned(),
            app_id: Some(app.as_str().to_owned()),
            verdict: verdict.to_wire(),
            score: verdict.score,
            bytes_in: state.bytes_in(),
            bytes_out: state.bytes_out(),
            duration_ms: state.duration_ms(),
        }
    }

    /// Emit a [`FlowEvent`] into the telemetry pipeline.
    /// Drops on backpressure (the data path is never
    /// blocked on telemetry).
    fn emit_event(&self, event: FlowEvent) {
        match self.telemetry.try_send(TelemetryEvent::Flow(event)) {
            Ok(()) => self.stats.record_telemetry_emit(),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_telemetry_drop();
                tracing::debug!("telemetry pipeline full; dropping FlowEvent");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.stats.record_telemetry_drop();
                tracing::warn!("telemetry pipeline closed; dropping FlowEvent");
            }
        }
    }
}

/// Convert a [`Verdict`] to whether the data path should
/// forward the packet. Mirrors
/// [`FwVerdict::permits_traffic`] but on the wire-level
/// type so callers that have a bare `Verdict` (e.g. from
/// the cache) can re-check without round-tripping through
/// [`FwVerdict`].
#[must_use]
pub const fn verdict_permits_traffic(v: Verdict) -> bool {
    matches!(
        v,
        Verdict::Allow | Verdict::Alert | Verdict::Log | Verdict::Inspect
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::appid::PortHeuristicResolver;
    use crate::conntrack::ConnTableConfig;
    use crate::flow::IpProtocol;
    use crate::verdict::VerdictCacheConfig;
    use sng_core::policy::BundleTarget;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    /// Construct a service backed by a real PolicyEngine
    /// loaded from a synthesised default-deny bundle. The
    /// telemetry sink is a real mpsc channel; the test
    /// itself holds the receiver and can drain it to verify
    /// emitted FlowEvents. Returned receiver MUST be kept
    /// alive across the test or the next `try_send` will see
    /// a `Closed` error and the drop counter will spike.
    fn service_with_default_deny_policy()
    -> (FwService, Arc<FwStats>, mpsc::Receiver<TelemetryEvent>) {
        let conntrack = Arc::new(ConnTable::new(ConnTableConfig {
            max_entries: 64,
            ..ConnTableConfig::default()
        }));
        let verdict_cache = Arc::new(VerdictCache::new(VerdictCacheConfig {
            max_entries: 64,
            ttl: Duration::from_secs(10),
        }));
        let app_id = AppIdResolver {
            port: PortHeuristicResolver::with_well_known(),
            sni: crate::appid::SniExtractor,
        };
        let body = test_helpers::default_deny_bundle();
        let engine = Arc::new(
            sng_policy_eval::PolicyEngine::from_body(&body, BundleTarget::Endpoint)
                .expect("engine constructs from synth bundle"),
        );
        let policy = FwPolicyAdapter::new(engine);
        let (tx, rx) = mpsc::channel(64);
        let stats = Arc::new(FwStats::new());
        let svc = FwService::new(conntrack, verdict_cache, app_id, policy, tx, stats.clone());
        (svc, stats, rx)
    }

    fn flow_key_443() -> FlowKey {
        FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            54321,
            443,
            IpProtocol::Tcp,
        )
        .unwrap()
    }

    #[test]
    fn first_observation_creates_flow_and_evaluates_policy() {
        let (svc, stats, _rx) = service_with_default_deny_policy();
        let obs = PacketObservation {
            key: flow_key_443(),
            direction: FlowDirection::Egress,
            payload: &[],
            tcp_flags: Some(0x02),
            bytes: 60,
            now_ms: 1_000,
        };
        let decision = svc.observe_packet(&obs).expect("decision");
        assert!(decision.is_new_flow);
        // The default bundle has no rules and a default-deny
        // posture configured in synth_signed_bundle, so the
        // verdict is Deny.
        assert_eq!(
            decision.verdict.disposition,
            sng_core::envelope::Verdict::Deny
        );
        let snap = stats.snapshot();
        assert_eq!(snap.flows_created, 1);
        assert_eq!(snap.verdict_cache_misses, 1);
        assert_eq!(snap.policy_evaluations, 1);
        assert_eq!(snap.verdict_denies, 1);
    }

    #[test]
    fn second_observation_hits_verdict_cache() {
        let (svc, stats, _rx) = service_with_default_deny_policy();
        let key = flow_key_443();
        let obs = |now_ms| PacketObservation {
            key,
            direction: FlowDirection::Egress,
            payload: &[],
            tcp_flags: Some(0x02),
            bytes: 60,
            now_ms,
        };
        svc.observe_packet(&obs(1_000)).unwrap();
        svc.observe_packet(&obs(1_100)).unwrap();
        let snap = stats.snapshot();
        assert_eq!(snap.flows_created, 1);
        assert_eq!(snap.verdict_cache_misses, 1);
        assert_eq!(snap.verdict_cache_hits, 1);
        assert_eq!(snap.policy_evaluations, 1);
    }

    #[test]
    fn reverse_packet_credits_responder_counter() {
        let (svc, _stats, _rx) = service_with_default_deny_policy();
        let fwd = flow_key_443();
        svc.observe_packet(&PacketObservation {
            key: fwd,
            direction: FlowDirection::Egress,
            payload: &[],
            tcp_flags: Some(0x02),
            bytes: 100,
            now_ms: 1_000,
        })
        .unwrap();
        svc.observe_packet(&PacketObservation {
            key: fwd.reverse(),
            direction: FlowDirection::Ingress,
            payload: &[],
            tcp_flags: Some(0x12),
            bytes: 200,
            now_ms: 1_100,
        })
        .unwrap();
        let snap = svc.conntrack.snapshot(&fwd).expect("entry present");
        assert_eq!(snap.state.bytes_originator, 100);
        assert_eq!(snap.state.bytes_responder, 200);
    }

    #[test]
    fn tick_drops_expired_flow_and_emits_final_event() {
        let (svc, stats, _rx) = service_with_default_deny_policy();
        svc.observe_packet(&PacketObservation {
            key: FlowKey::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                54321,
                53,
                IpProtocol::Udp,
            )
            .unwrap(),
            direction: FlowDirection::Egress,
            payload: &[],
            tcp_flags: None,
            bytes: 50,
            now_ms: 0,
        })
        .unwrap();
        // Tick well past the stateless idle (60s default).
        svc.tick(120_000);
        let snap = stats.snapshot();
        assert_eq!(snap.flows_evicted_idle, 1);
        assert!(snap.telemetry_events_emitted >= 1);
    }

    #[test]
    fn policy_reload_drops_cache_so_next_packet_re_evals() {
        let (svc, stats, _rx) = service_with_default_deny_policy();
        svc.observe_packet(&PacketObservation {
            key: flow_key_443(),
            direction: FlowDirection::Egress,
            payload: &[],
            tcp_flags: Some(0x02),
            bytes: 60,
            now_ms: 1_000,
        })
        .unwrap();
        // Force a policy reload.
        svc.on_policy_reload();
        // The same flow now misses the cache.
        svc.observe_packet(&PacketObservation {
            key: flow_key_443(),
            direction: FlowDirection::Egress,
            payload: &[],
            tcp_flags: Some(0x10),
            bytes: 60,
            now_ms: 1_100,
        })
        .unwrap();
        let snap = stats.snapshot();
        assert_eq!(snap.policy_evaluations, 2);
        assert_eq!(snap.verdict_cache_misses, 2);
    }

    #[test]
    fn verdict_permits_traffic_follows_disposition() {
        assert!(verdict_permits_traffic(Verdict::Allow));
        assert!(verdict_permits_traffic(Verdict::Alert));
        assert!(verdict_permits_traffic(Verdict::Log));
        assert!(verdict_permits_traffic(Verdict::Inspect));
        assert!(!verdict_permits_traffic(Verdict::Deny));
    }

    /// Test-only helpers shared across cases. The bundle
    /// constructor mirrors `sng-policy-eval`'s own internal
    /// `encode_bundle` helper — the engine's `from_body`
    /// path decodes the MessagePack wire shape directly, so
    /// reconstructing it here exercises real bundle decode
    /// rather than mocking the algorithm under test.
    mod test_helpers {
        use chrono::Utc;
        use serde::Serialize;
        use sng_core::policy::BundleTarget;

        #[derive(Serialize)]
        struct WireBundle<'a> {
            #[serde(rename = "v")]
            v: u8,
            #[serde(rename = "t")]
            t: BundleTarget,
            #[serde(rename = "g")]
            g: &'a str,
            #[serde(rename = "gv")]
            gv: i64,
            #[serde(rename = "c")]
            c: &'a str,
            #[serde(rename = "d")]
            d: &'a str,
            #[serde(rename = "r", with = "serde_bytes")]
            r: &'a [u8],
            #[serde(
                rename = "st",
                with = "serde_bytes",
                skip_serializing_if = "<[u8]>::is_empty"
            )]
            st: &'a [u8],
            #[serde(rename = "ts")]
            ts: chrono::DateTime<Utc>,
        }

        /// Build a bundle body for `BundleTarget::Endpoint`
        /// with no rules and a default-deny posture. Used by
        /// the service tests to get a real PolicyEngine that
        /// returns `Verdict::Deny` on every flow — which
        /// distinguishes "policy ran" from "fail closed",
        /// the latter of which would surface as a
        /// `VerdictReason::FailClosed` rather than a
        /// `VerdictReason::PolicyMatch`.
        pub(super) fn default_deny_bundle() -> Vec<u8> {
            let rules_json = serde_json::to_vec::<[u8; 0]>(&[]).unwrap();
            let wire = WireBundle {
                v: 1,
                t: BundleTarget::Endpoint,
                g: "550e8400-e29b-41d4-a716-446655440000",
                gv: 1,
                c: "sng-fw-test",
                d: "deny",
                r: &rules_json,
                st: &[],
                ts: Utc::now(),
            };
            rmp_serde::to_vec_named(&wire).unwrap()
        }
    }
}

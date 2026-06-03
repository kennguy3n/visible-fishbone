//! Rolling-window deduplication of telemetry events.
//!
//! The same observation can arrive at the pipeline more than
//! once for several reasons:
//!
//! * The producing subsystem retries internally and the retry
//!   path is not idempotent (e.g. the DNS resolver retries a
//!   query on EAGAIN and emits a DnsEvent for each attempt).
//! * Two collection paths overlap — the kernel-side flow
//!   collector and the userspace eBPF tap both fire for the
//!   same 5-tuple.
//! * A buggy producer never deduplicates its own emission
//!   stream.
//!
//! The dedup stage rejects an event whose **content fingerprint**
//! (a hash of the producer-relevant fields, see
//! [`Fingerprint::compute`]) has been seen inside the rolling
//! window. It does NOT use the wire `event_id` because every
//! retry path mints a fresh id — that's the producer's chosen
//! identifier and is not what dedup keys on.
//!
//! The window is a fixed-duration TTL (default 30s). Entries
//! older than the window are evicted lazily on each call to
//! [`Dedup::observe`] and proactively from a periodic prune.

use std::collections::HashMap;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::{Duration, Instant};

use sng_core::events::{
    AgentEvent, DnsEvent, FlowEvent, HttpEvent, IpsEvent, SdwanEvent, ZtnaEvent,
};

use crate::source::TelemetryEvent;

/// A stable, in-process-only content fingerprint of a
/// [`TelemetryEvent`]. The fingerprint is **not** suitable for
/// cross-process or cross-boot comparison (it depends on the
/// std-library DefaultHasher which carries no portability
/// guarantees) — it is keyed only as an in-memory dedup key
/// inside a single agent process.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Fingerprint(pub u64);

impl Fingerprint {
    /// Compute a fingerprint over the producer-relevant fields
    /// of the event. Two events with identical
    /// [`Self::compute`] outputs are considered duplicates by
    /// the dedup stage.
    #[must_use]
    pub fn compute(event: &TelemetryEvent) -> Self {
        let mut h = DefaultHasher::new();
        // Discriminator so a Flow and a Dns that happen to hash
        // their content to the same bytes don't collide.
        match event {
            TelemetryEvent::Flow(e) => {
                0u8.hash(&mut h);
                hash_flow(e, &mut h);
            }
            TelemetryEvent::Dns(e) => {
                1u8.hash(&mut h);
                hash_dns(e, &mut h);
            }
            TelemetryEvent::Http(e) => {
                2u8.hash(&mut h);
                hash_http(e, &mut h);
            }
            TelemetryEvent::Ips(e) => {
                3u8.hash(&mut h);
                hash_ips(e, &mut h);
            }
            TelemetryEvent::Ztna(e) => {
                4u8.hash(&mut h);
                hash_ztna(e, &mut h);
            }
            TelemetryEvent::Sdwan(e) => {
                5u8.hash(&mut h);
                hash_sdwan(e, &mut h);
            }
            TelemetryEvent::Agent(e) => {
                6u8.hash(&mut h);
                hash_agent(e, &mut h);
            }
        }
        Self(h.finish())
    }
}

fn hash_flow(e: &FlowEvent, h: &mut DefaultHasher) {
    e.src_ip.hash(h);
    e.dst_ip.hash(h);
    e.src_port.hash(h);
    e.dst_port.hash(h);
    e.protocol.hash(h);
    e.app_id.hash(h);
    // Bytes / duration deliberately NOT hashed: dedup must
    // collapse "same flow observed twice" into one record, and
    // the byte counters differ between an in-flight observation
    // and the final flow-close observation. The verdict IS
    // hashed because a verdict change implies a new policy
    // decision and is worth a separate event.
    (e.verdict as u8).hash(h);
}

fn hash_dns(e: &DnsEvent, h: &mut DefaultHasher) {
    e.query.hash(h);
    e.qtype.hash(h);
    e.response_code.hash(h);
    (e.verdict as u8).hash(h);
    // latency_ms / upstream excluded — same query observed twice
    // (e.g. cache miss then cache hit) should dedup.
}

fn hash_http(e: &HttpEvent, h: &mut DefaultHasher) {
    e.method.hash(h);
    e.url.hash(h);
    e.host.hash(h);
    e.status_code.hash(h);
    (e.verdict as u8).hash(h);
    // tls_version / sni / content_type / bytes excluded —
    // identical request observed twice should dedup.
}

fn hash_ips(e: &IpsEvent, h: &mut DefaultHasher) {
    e.rule_id.hash(h);
    e.signature.hash(h);
    e.severity.hash(h);
    e.action.hash(h);
    e.src_ip.hash(h);
    e.dst_ip.hash(h);
    e.protocol.hash(h);
}

fn hash_ztna(e: &ZtnaEvent, h: &mut DefaultHasher) {
    e.device_id.hash(h);
    e.app_id.hash(h);
    e.posture_result.hash(h);
    // Both `decision` ("allow" / "deny") and `reason`
    // (the detailed bucket label, e.g. `mfa_stale`,
    // `device_posture_insufficient`, `tenant_mismatch`)
    // participate in the dedup key. Without `reason`, two
    // denies on the same (device, app) for different
    // structural reasons would collapse to one wire event
    // and dashboards would lose the per-cause breakdown.
    e.decision.hash(h);
    e.reason.hash(h);
    e.identity_verified.hash(h);
}

fn hash_sdwan(e: &SdwanEvent, h: &mut DefaultHasher) {
    e.path_id.hash(h);
    e.steering_decision.hash(h);
    // Latency/loss/jitter/score deliberately excluded — same
    // steering decision observed twice with slightly different
    // probe metrics should dedup. A change in steering_decision
    // is what's worth reporting.
}

fn hash_agent(e: &AgentEvent, h: &mut DefaultHasher) {
    e.device_id.hash(h);
    e.event_type.hash(h);
    (e.platform as u8).hash(h);
    // posture_snapshot excluded — agent posture events should
    // dedup on (device, event_type, platform) inside the
    // window. A change in event_type (started → posture →
    // stopped) is what's worth reporting.
}

/// Rolling-window event deduplicator.
///
/// Tracks fingerprints inside a configurable TTL. On
/// [`Self::observe`], returns `true` when the event is new (and
/// records the fingerprint) or `false` when the fingerprint is
/// still inside the window (duplicate).
///
/// Eviction is lazy on every observe call AND a public
/// [`Self::prune`] is provided for the pipeline to call on a
/// periodic tick — important for low-volume streams where the
/// lazy eviction would otherwise leave stale entries occupying
/// memory.
#[derive(Debug)]
pub struct Dedup {
    window: Duration,
    /// Soft cap on the number of fingerprints kept. The cap
    /// triggers an early-eviction sweep when reached so a
    /// pathological producer flooding the window cannot grow the
    /// map without bound. Default: 100_000.
    max_entries: usize,
    seen: HashMap<Fingerprint, Instant>,
}

/// Default rolling window: 30 seconds. Tuned for the agent's
/// typical retry budget (DNS / TCP) — anything longer than this
/// is treated as a genuinely new observation.
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(30);

/// Default soft cap on dedup map size.
pub const DEFAULT_MAX_ENTRIES: usize = 100_000;

impl Default for Dedup {
    fn default() -> Self {
        Self::new(DEFAULT_WINDOW, DEFAULT_MAX_ENTRIES)
    }
}

impl Dedup {
    /// New deduplicator with the given window and soft cap.
    /// Panics if `window` is zero (a zero window would dedup
    /// every event regardless of arrival order, which is never
    /// what the caller wants).
    #[must_use]
    pub fn new(window: Duration, max_entries: usize) -> Self {
        assert!(
            !window.is_zero(),
            "dedup window must be non-zero; pipeline configures a window of at least 1ms"
        );
        Self {
            window,
            max_entries: max_entries.max(1),
            seen: HashMap::new(),
        }
    }

    /// Configured window.
    #[must_use]
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Number of fingerprints currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when no fingerprints are currently tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Observe an event. Returns `true` if the event is novel
    /// (and records its fingerprint), `false` if a non-expired
    /// copy is already in the window.
    pub fn observe(&mut self, event: &TelemetryEvent) -> bool {
        let now = Instant::now();
        let fp = Fingerprint::compute(event);
        self.observe_at(fp, now)
    }

    /// Observe a fingerprint at a specific instant. Exposed for
    /// tests so they can drive time deterministically rather than
    /// relying on real-world `Instant::now()`.
    pub fn observe_at(&mut self, fp: Fingerprint, now: Instant) -> bool {
        if let Some(last) = self.seen.get(&fp).copied() {
            if now.duration_since(last) < self.window {
                // Refresh the timestamp so a high-rate duplicate
                // doesn't fall out of the window between hits and
                // then immediately get re-admitted on the next
                // observation. The protocol-level invariant is
                // "no fingerprint passes inside the rolling
                // window", which means the window slides with
                // each duplicate hit.
                self.seen.insert(fp, now);
                return false;
            }
        }
        if self.seen.len() >= self.max_entries {
            self.prune_at(now);
            // After pruning we still cap at max_entries —
            // evicting the oldest 10% as headroom keeps the map
            // from oscillating between full and one-under-cap on
            // every insert.
            if self.seen.len() >= self.max_entries {
                self.evict_oldest(self.max_entries / 10);
            }
        }
        self.seen.insert(fp, now);
        true
    }

    /// Evict all entries older than the window. The pipeline
    /// calls this on a periodic tick so the map doesn't keep
    /// stale entries indefinitely on low-volume event streams.
    pub fn prune(&mut self) {
        self.prune_at(Instant::now());
    }

    fn prune_at(&mut self, now: Instant) {
        let window = self.window;
        self.seen
            .retain(|_, last| now.duration_since(*last) < window);
    }

    fn evict_oldest(&mut self, n: usize) {
        if n == 0 || self.seen.is_empty() {
            return;
        }
        let mut entries: Vec<(Fingerprint, Instant)> =
            self.seen.iter().map(|(k, v)| (*k, *v)).collect();
        entries.sort_by_key(|(_, t)| *t);
        for (fp, _) in entries.into_iter().take(n) {
            self.seen.remove(&fp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sng_core::envelope::{Platform, Verdict};
    use sng_core::events::FlowEvent;

    fn sample_flow() -> TelemetryEvent {
        TelemetryEvent::Flow(FlowEvent {
            src_ip: "10.0.0.1".into(),
            dst_ip: "1.1.1.1".into(),
            src_port: 51_234,
            dst_port: 443,
            protocol: "tcp".into(),
            app_id: Some("microsoft.teams".into()),
            verdict: Verdict::Allow,
            score: Some(0.42),
            bytes_in: 1_024,
            bytes_out: 2_048,
            duration_ms: 1_500,
        })
    }

    fn agent(et: &str) -> TelemetryEvent {
        TelemetryEvent::Agent(sng_core::events::AgentEvent {
            device_id: "d1".into(),
            event_type: et.into(),
            posture_snapshot: None,
            reason: String::new(),
            platform: Platform::Linux,
        })
    }

    #[test]
    fn fingerprint_ignores_byte_counters_on_flow() {
        let TelemetryEvent::Flow(mut a) = sample_flow() else {
            unreachable!("sample_flow returns Flow variant");
        };
        let mut b = a.clone();
        b.bytes_in = 99_999;
        b.bytes_out = 99_999;
        b.duration_ms = 9_999;
        // Same flow observed twice with different byte counters
        // should produce identical fingerprints (dedup invariant).
        let fa = Fingerprint::compute(&TelemetryEvent::Flow(a.clone()));
        let fb = Fingerprint::compute(&TelemetryEvent::Flow(b));
        assert_eq!(fa, fb);
        // But a different verdict IS material.
        a.verdict = Verdict::Deny;
        let fc = Fingerprint::compute(&TelemetryEvent::Flow(a));
        assert_ne!(fa, fc);
    }

    #[test]
    fn fingerprint_distinguishes_event_classes() {
        // A Flow and an Agent with hashable content that happens
        // to collide in their inner-hash output must still
        // fingerprint differently due to the class discriminator.
        let f = sample_flow();
        let a = agent("started");
        assert_ne!(Fingerprint::compute(&f), Fingerprint::compute(&a));
    }

    #[test]
    fn dedup_rejects_inside_window_accepts_after() {
        let mut d = Dedup::new(Duration::from_millis(100), 1024);
        let ev = sample_flow();
        let t0 = Instant::now();
        let fp = Fingerprint::compute(&ev);
        assert!(d.observe_at(fp, t0));
        // Same fingerprint, just inside window.
        assert!(!d.observe_at(fp, t0 + Duration::from_millis(50)));
        // Same fingerprint, exactly at the window boundary.
        // Boundary is exclusive (< window), so this admits.
        assert!(d.observe_at(fp, t0 + Duration::from_millis(150)));
    }

    #[test]
    fn dedup_sliding_window_extends_on_duplicate() {
        // Each duplicate hit refreshes the window. The pipeline
        // must NEVER let a high-rate duplicate stream re-admit
        // just because the absolute clock crossed the original
        // observation's window boundary.
        let mut d = Dedup::new(Duration::from_millis(100), 1024);
        let fp = Fingerprint::compute(&sample_flow());
        let t0 = Instant::now();
        assert!(d.observe_at(fp, t0));
        // Hit at t+50ms — extends window to t+150ms.
        assert!(!d.observe_at(fp, t0 + Duration::from_millis(50)));
        // At t+120ms (would be past original window) but inside
        // the refreshed window — still rejected.
        assert!(!d.observe_at(fp, t0 + Duration::from_millis(120)));
        // At t+250ms — past refreshed window from t+120, admit.
        assert!(d.observe_at(fp, t0 + Duration::from_millis(250)));
    }

    #[test]
    fn prune_drops_stale_entries() {
        let mut d = Dedup::new(Duration::from_millis(100), 1024);
        let t0 = Instant::now();
        d.observe_at(Fingerprint(1), t0);
        d.observe_at(Fingerprint(2), t0);
        d.observe_at(Fingerprint(3), t0 + Duration::from_millis(60));
        // Advance past the first two entries' window (age=140ms,
        // window=100ms → drop) but not past entry 3 (age=80ms,
        // still inside the window → keep). Boundary-relevant
        // detail: the keep predicate is strict-less-than the
        // window, matching observe_at's "duplicate within
        // window" rule.
        d.prune_at(t0 + Duration::from_millis(140));
        assert_eq!(d.len(), 1);
    }

    #[test]
    fn max_entries_triggers_eviction() {
        let mut d = Dedup::new(Duration::from_secs(60), 10);
        let t0 = Instant::now();
        // Fill the map to capacity with strictly-increasing
        // timestamps so the eviction order is well-defined.
        for i in 0..10_u64 {
            d.observe_at(Fingerprint(i), t0 + Duration::from_micros(i));
        }
        assert_eq!(d.len(), 10);
        // 11th distinct fingerprint triggers eviction. With a
        // 60s window, prune_at evicts nothing, so the cap path
        // (evict_oldest) must kick in.
        d.observe_at(Fingerprint(10_u64), t0 + Duration::from_secs(1));
        assert!(d.len() <= 10);
    }

    #[test]
    #[should_panic(expected = "non-zero")]
    fn zero_window_panics() {
        let _ = Dedup::new(Duration::ZERO, 1);
    }
}

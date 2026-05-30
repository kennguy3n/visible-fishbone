//! Per-flow verdict types and the verdict cache.
//!
//! [`FwVerdict`] is the firewall's internal verdict shape —
//! richer than [`sng_core::envelope::Verdict`] because it
//! carries the reason a flow was denied (for telemetry
//! `score` and `app_id` annotations) and distinguishes
//! "this is the very first verdict on a new flow" from
//! "we're re-applying the established verdict to a
//! subsequent packet". The wire-level
//! [`sng_core::envelope::Verdict`] is the dispatch verdict
//! the firewall sends downstream — every [`FwVerdict`]
//! collapses to a single `Verdict` via
//! [`FwVerdict::to_wire`].
//!
//! [`VerdictCache`] is the hot-path lookup that avoids
//! re-querying the policy evaluator on every packet of an
//! established flow. The cache is keyed on
//! [`crate::flow::FlowKey`] and stores
//! `(FwVerdict, expires_at_ms)` pairs. The cache is hot-swappable
//! via [`VerdictCache::swap`] so policy bundle reloads in
//! [`sng_policy_eval`] are reflected at the next packet without
//! tearing down conntrack.

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sng_core::envelope::Verdict;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::flow::FlowKey;

/// The reason the firewall produced a particular verdict.
/// Surfaced onto the telemetry envelope so downstream
/// dashboards can break "denies" into actionable buckets
/// (this site / this rule / this category) instead of a
/// single counter.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictReason {
    /// A specific rule in the active policy bundle matched
    /// and produced the verdict. The string is the rule's
    /// `rule_id` — stable across bundle versions so an
    /// operator can correlate telemetry with the policy
    /// editor.
    PolicyMatch(String),
    /// No rule matched; the verdict is the bundle's default
    /// posture. The string is the policy domain
    /// (`ngfw` / `swg` / `dns` / …) so operators can see
    /// which domain's default was applied.
    PolicyDefault(String),
    /// The flow was already known in conntrack and the
    /// firewall short-circuited to the cached verdict
    /// without re-evaluating policy.
    CachedEstablished,
    /// The policy evaluator was unavailable (no bundle
    /// loaded, reload race) — the firewall fell back to
    /// the configured fail-closed verdict.
    FailClosed,
    /// The flow was deemed safe at the L3 layer and bypassed
    /// further inspection (e.g. trusted broadcast traffic on
    /// an internal segment).
    Bypass,
}

impl VerdictReason {
    /// Compact wire-form for the reason. Stable across
    /// bundles; downstream consumers index on the literal
    /// strings.
    #[must_use]
    pub fn as_label(&self) -> String {
        match self {
            Self::PolicyMatch(rule_id) => format!("policy.match:{rule_id}"),
            Self::PolicyDefault(domain) => format!("policy.default:{domain}"),
            Self::CachedEstablished => "cache.established".into(),
            Self::FailClosed => "policy.fail_closed".into(),
            Self::Bypass => "bypass".into(),
        }
    }
}

/// Per-flow verdict the firewall computes. Distinguishes
/// the wire-level disposition (Allow / Deny / Inspect / …)
/// from the reason and from the resolved app id.
///
/// Does NOT derive `Eq` because the optional `score` carries an
/// `f32` and `f32` is not totally ordered (NaN). The verdict
/// constructors reject non-finite scores (see [`Self::with_score`])
/// so a `FwVerdict` instance in practice has a totally ordered
/// score field, but the typesystem invariant only holds at the
/// constructor — callers that mutate `score` directly are NOT
/// covered, so we deliberately stay on `PartialEq` to keep the
/// type honest.
#[derive(Clone, Debug, PartialEq)]
pub struct FwVerdict {
    /// The wire-level [`sng_core::envelope::Verdict`] that
    /// will land on the [`FlowEvent`]'s `vd` field.
    pub disposition: Verdict,
    /// Why the firewall produced this verdict. Surfaced as
    /// label string on the telemetry envelope.
    pub reason: VerdictReason,
    /// Optional risk score / confidence (0.0..=1.0). The
    /// policy evaluator emits a score when applying a
    /// rule that includes a threat-intel weight; otherwise
    /// `None` and downstream consumers don't render a
    /// score column.
    pub score: Option<f32>,
}

impl FwVerdict {
    /// Construct an allow verdict with no risk score.
    #[must_use]
    pub fn allow(reason: VerdictReason) -> Self {
        Self {
            disposition: Verdict::Allow,
            reason,
            score: None,
        }
    }

    /// Construct a deny verdict.
    #[must_use]
    pub fn deny(reason: VerdictReason) -> Self {
        Self {
            disposition: Verdict::Deny,
            reason,
            score: None,
        }
    }

    /// Construct a verdict requesting deeper inspection
    /// (e.g. send the flow through IPS).
    #[must_use]
    pub fn inspect(reason: VerdictReason) -> Self {
        Self {
            disposition: Verdict::Inspect,
            reason,
            score: None,
        }
    }

    /// Construct an alert verdict (allow but flag).
    #[must_use]
    pub fn alert(reason: VerdictReason) -> Self {
        Self {
            disposition: Verdict::Alert,
            reason,
            score: None,
        }
    }

    /// Construct a log-only verdict (allow + observe).
    #[must_use]
    pub fn log(reason: VerdictReason) -> Self {
        Self {
            disposition: Verdict::Log,
            reason,
            score: None,
        }
    }

    /// Attach a confidence / risk score. Clamped to
    /// `[0.0, 1.0]` and `NaN` is converted to `None` —
    /// since `NaN` is not a valid JSON number, accepting it
    /// would later poison the telemetry encoder.
    #[must_use]
    pub fn with_score(mut self, score: f32) -> Self {
        if score.is_finite() {
            self.score = Some(score.clamp(0.0, 1.0));
        } else {
            self.score = None;
        }
        self
    }

    /// Project to the wire-level verdict.
    #[must_use]
    pub const fn to_wire(&self) -> Verdict {
        self.disposition
    }

    /// Whether this verdict should permit the flow to
    /// continue. A wrapper around the wire disposition that
    /// the data path can use without having to enumerate
    /// every variant. `Alert` and `Log` permit traffic;
    /// `Deny` blocks it; `Inspect` is treated as permit-with-
    /// further-inspection (the inspection happens
    /// out-of-band in the IPS / DPI module).
    #[must_use]
    pub const fn permits_traffic(&self) -> bool {
        matches!(
            self.disposition,
            Verdict::Allow | Verdict::Alert | Verdict::Log | Verdict::Inspect
        )
    }
}

/// Configuration for the verdict cache.
#[derive(Clone, Debug)]
pub struct VerdictCacheConfig {
    /// Maximum number of entries the cache holds. When the
    /// cache reaches capacity, the oldest entry is evicted
    /// regardless of TTL. Defaults to 65_536, sized for a
    /// busy edge VM with tens of thousands of concurrent
    /// flows.
    pub max_entries: usize,
    /// How long a verdict stays cached before it expires
    /// and is re-queried from the policy evaluator. Defaults
    /// to 60s, which matches the conntrack TCP-established
    /// idle timeout default; on long-lived connections the
    /// cache refreshes once per minute so policy changes
    /// take effect within a bounded window.
    pub ttl: Duration,
}

impl Default for VerdictCacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 65_536,
            ttl: Duration::from_secs(60),
        }
    }
}

/// Per-flow verdict cache backed by an ArcSwap-wrapped
/// `HashMap`. The data path takes a snapshot via
/// [`VerdictCache::get`] without acquiring a lock — only
/// inserts and the periodic sweep need the mutex.
///
/// Note: ArcSwap is here so the cache contents can be
/// hot-swapped on policy reload (call
/// [`VerdictCache::clear_all`]); the underlying map mutates
/// under a mutex per-insert. Reads are lock-free.
#[derive(Debug)]
pub struct VerdictCache {
    config: VerdictCacheConfig,
    /// Lock-free read path: snapshots are cheap clones of
    /// `Arc<Map>` — every reader gets a consistent view at
    /// the cost of an atomic load. The map is replaced
    /// wholesale on `clear_all`, which scales because
    /// `clear_all` is rare (only on policy reload).
    map: ArcSwap<HashMap<FlowKey, CacheEntry>>,
    /// Serializes inserts and TTL sweeps. Short critical
    /// sections, no `.await` under the lock.
    write_guard: Mutex<()>,
}

/// A cached verdict + its expiry deadline.
#[derive(Clone, Debug, PartialEq)]
struct CacheEntry {
    verdict: FwVerdict,
    expires_at_ms: u64,
}

impl VerdictCache {
    /// Construct an empty cache with the given config.
    #[must_use]
    pub fn new(config: VerdictCacheConfig) -> Self {
        Self {
            config,
            map: ArcSwap::from_pointee(HashMap::new()),
            write_guard: Mutex::new(()),
        }
    }

    /// Convenience constructor with default config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(VerdictCacheConfig::default())
    }

    /// Look up a cached verdict. Returns `None` if the
    /// entry is absent or has expired. The expiry check
    /// uses `now_ms` rather than querying the system clock
    /// so callers can drive deterministic tests.
    #[must_use]
    pub fn get(&self, key: &FlowKey, now_ms: u64) -> Option<FwVerdict> {
        let snapshot = self.map.load();
        let entry = snapshot.get(key)?;
        if entry.expires_at_ms <= now_ms {
            return None;
        }
        Some(entry.verdict.clone())
    }

    /// Insert (or replace) a verdict for `key`. The verdict
    /// expires at `now_ms + config.ttl`. If the cache is at
    /// capacity, evicts the oldest entry first.
    pub fn insert(&self, key: FlowKey, verdict: FwVerdict, now_ms: u64) {
        let ttl_ms = u64::try_from(self.config.ttl.as_millis()).unwrap_or(u64::MAX);
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let _guard = self.write_guard.lock();
        let snapshot = self.map.load();
        let mut next: HashMap<FlowKey, CacheEntry> = (**snapshot).clone();
        if !next.contains_key(&key) && next.len() >= self.config.max_entries {
            // Evict the entry with the soonest expiry. This
            // doubles as a TTL sweep — anything already
            // expired wins the eviction lottery.
            if let Some((evict_key, _)) = next
                .iter()
                .min_by_key(|(_, e)| e.expires_at_ms)
                .map(|(k, e)| (*k, e.clone()))
            {
                next.remove(&evict_key);
            }
        }
        next.insert(
            key,
            CacheEntry {
                verdict,
                expires_at_ms,
            },
        );
        self.map.store(Arc::new(next));
    }

    /// Drop every entry. Used on policy reload — the new
    /// bundle may produce different verdicts for flows the
    /// cache currently holds, so the safest thing is to
    /// re-query on the next packet.
    pub fn clear_all(&self) {
        let _guard = self.write_guard.lock();
        self.map.store(Arc::new(HashMap::new()));
    }

    /// Drop entries whose `expires_at_ms` is `<= now_ms`.
    /// Returns the number of entries dropped. Called by
    /// the service's periodic maintenance task.
    pub fn sweep_expired(&self, now_ms: u64) -> usize {
        let _guard = self.write_guard.lock();
        let snapshot = self.map.load();
        if snapshot.is_empty() {
            return 0;
        }
        let mut next: HashMap<FlowKey, CacheEntry> = (**snapshot).clone();
        let before = next.len();
        next.retain(|_, entry| entry.expires_at_ms > now_ms);
        let removed = before - next.len();
        if removed > 0 {
            self.map.store(Arc::new(next));
        }
        removed
    }

    /// Current number of cached entries (including expired
    /// ones that haven't been swept yet).
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.load().len()
    }

    /// Whether the cache holds zero entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::IpProtocol;
    use std::net::{IpAddr, Ipv4Addr};

    fn key_for_port(port: u16) -> FlowKey {
        FlowKey::new(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            54321,
            port,
            IpProtocol::Tcp,
        )
        .unwrap()
    }

    #[test]
    fn verdict_reason_label_format() {
        assert_eq!(
            VerdictReason::PolicyMatch("rule-99".into()).as_label(),
            "policy.match:rule-99"
        );
        assert_eq!(
            VerdictReason::PolicyDefault("dns".into()).as_label(),
            "policy.default:dns"
        );
        assert_eq!(
            VerdictReason::CachedEstablished.as_label(),
            "cache.established"
        );
        assert_eq!(VerdictReason::FailClosed.as_label(), "policy.fail_closed");
        assert_eq!(VerdictReason::Bypass.as_label(), "bypass");
    }

    #[test]
    fn fw_verdict_constructors_set_disposition() {
        let v = FwVerdict::allow(VerdictReason::Bypass);
        assert_eq!(v.disposition, Verdict::Allow);
        let v = FwVerdict::deny(VerdictReason::FailClosed);
        assert_eq!(v.disposition, Verdict::Deny);
        let v = FwVerdict::inspect(VerdictReason::PolicyMatch("ips".into()));
        assert_eq!(v.disposition, Verdict::Inspect);
        let v = FwVerdict::alert(VerdictReason::PolicyMatch("alert-only".into()));
        assert_eq!(v.disposition, Verdict::Alert);
        let v = FwVerdict::log(VerdictReason::PolicyDefault("ngfw".into()));
        assert_eq!(v.disposition, Verdict::Log);
    }

    #[test]
    fn with_score_clamps_to_unit_interval() {
        let v = FwVerdict::deny(VerdictReason::FailClosed).with_score(1.5);
        assert_eq!(v.score, Some(1.0));
        let v = FwVerdict::deny(VerdictReason::FailClosed).with_score(-0.5);
        assert_eq!(v.score, Some(0.0));
        let v = FwVerdict::deny(VerdictReason::FailClosed).with_score(0.7);
        assert_eq!(v.score, Some(0.7));
    }

    #[test]
    fn with_score_rejects_non_finite() {
        // NaN / Infinity are not valid JSON numbers; the
        // setter must keep them out of the score field so a
        // later telemetry serialisation doesn't fail at
        // runtime.
        let v = FwVerdict::deny(VerdictReason::FailClosed).with_score(f32::NAN);
        assert_eq!(v.score, None);
        let v = FwVerdict::deny(VerdictReason::FailClosed).with_score(f32::INFINITY);
        assert_eq!(v.score, None);
        let v = FwVerdict::deny(VerdictReason::FailClosed).with_score(f32::NEG_INFINITY);
        assert_eq!(v.score, None);
    }

    #[test]
    fn permits_traffic_is_true_for_allow_alert_log_inspect() {
        for r in [
            VerdictReason::Bypass,
            VerdictReason::PolicyDefault("ngfw".into()),
        ] {
            assert!(FwVerdict::allow(r.clone()).permits_traffic());
            assert!(FwVerdict::alert(r.clone()).permits_traffic());
            assert!(FwVerdict::log(r.clone()).permits_traffic());
            assert!(FwVerdict::inspect(r.clone()).permits_traffic());
        }
    }

    #[test]
    fn permits_traffic_is_false_for_deny() {
        assert!(!FwVerdict::deny(VerdictReason::FailClosed).permits_traffic());
    }

    #[test]
    fn cache_lookup_hits_when_present_and_fresh() {
        let cache = VerdictCache::with_defaults();
        let k = key_for_port(443);
        cache.insert(k, FwVerdict::allow(VerdictReason::Bypass), 1_000);
        let hit = cache.get(&k, 2_000).expect("hit expected");
        assert_eq!(hit.disposition, Verdict::Allow);
    }

    #[test]
    fn cache_lookup_misses_when_absent() {
        let cache = VerdictCache::with_defaults();
        let k = key_for_port(443);
        assert!(cache.get(&k, 0).is_none());
    }

    #[test]
    fn cache_expires_after_ttl() {
        let cfg = VerdictCacheConfig {
            max_entries: 8,
            ttl: Duration::from_secs(1),
        };
        let cache = VerdictCache::new(cfg);
        let k = key_for_port(443);
        cache.insert(k, FwVerdict::allow(VerdictReason::Bypass), 0);
        // Just before TTL.
        assert!(cache.get(&k, 999).is_some());
        // Exactly at TTL — boundary is exclusive.
        assert!(cache.get(&k, 1_000).is_none());
        // Past TTL.
        assert!(cache.get(&k, 2_000).is_none());
    }

    #[test]
    fn cache_clear_all_drops_every_entry() {
        let cache = VerdictCache::with_defaults();
        cache.insert(key_for_port(80), FwVerdict::allow(VerdictReason::Bypass), 0);
        cache.insert(
            key_for_port(443),
            FwVerdict::allow(VerdictReason::Bypass),
            0,
        );
        assert_eq!(cache.len(), 2);
        cache.clear_all();
        assert!(cache.is_empty());
    }

    #[test]
    fn cache_evicts_oldest_when_at_capacity() {
        let cfg = VerdictCacheConfig {
            max_entries: 2,
            ttl: Duration::from_secs(10),
        };
        let cache = VerdictCache::new(cfg);
        cache.insert(key_for_port(80), FwVerdict::allow(VerdictReason::Bypass), 0);
        cache.insert(
            key_for_port(443),
            FwVerdict::allow(VerdictReason::Bypass),
            100,
        );
        // Cache full. Inserting a third forces an eviction —
        // the entry with the soonest expiry (port 80 at
        // t=10000) loses.
        cache.insert(
            key_for_port(22),
            FwVerdict::allow(VerdictReason::Bypass),
            500,
        );
        assert_eq!(cache.len(), 2);
        // The 80 entry (inserted earliest, expiring earliest)
        // must be gone.
        assert!(cache.get(&key_for_port(80), 600).is_none());
        // The 443 + 22 entries must still be present.
        assert!(cache.get(&key_for_port(443), 600).is_some());
        assert!(cache.get(&key_for_port(22), 600).is_some());
    }

    #[test]
    fn cache_replace_does_not_evict() {
        let cfg = VerdictCacheConfig {
            max_entries: 2,
            ttl: Duration::from_secs(10),
        };
        let cache = VerdictCache::new(cfg);
        cache.insert(key_for_port(80), FwVerdict::allow(VerdictReason::Bypass), 0);
        cache.insert(
            key_for_port(443),
            FwVerdict::allow(VerdictReason::Bypass),
            100,
        );
        // Replace existing key — must not trigger eviction.
        cache.insert(
            key_for_port(80),
            FwVerdict::deny(VerdictReason::FailClosed),
            200,
        );
        assert_eq!(cache.len(), 2);
        let v = cache.get(&key_for_port(80), 500).unwrap();
        assert_eq!(v.disposition, Verdict::Deny);
    }

    #[test]
    fn sweep_expired_returns_count_and_drops_entries() {
        let cfg = VerdictCacheConfig {
            max_entries: 8,
            ttl: Duration::from_secs(1),
        };
        let cache = VerdictCache::new(cfg);
        cache.insert(key_for_port(80), FwVerdict::allow(VerdictReason::Bypass), 0);
        cache.insert(
            key_for_port(443),
            FwVerdict::allow(VerdictReason::Bypass),
            500,
        );
        cache.insert(
            key_for_port(22),
            FwVerdict::allow(VerdictReason::Bypass),
            2_000,
        );
        assert_eq!(cache.len(), 3);
        // Sweep at t=1100 — 80 expired at t=1000, 443 expired
        // at t=1500, 22 expires at t=3000. Should drop 1.
        let removed = cache.sweep_expired(1_100);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 2);
        assert!(cache.get(&key_for_port(80), 1_100).is_none());
    }

    #[test]
    fn sweep_expired_on_empty_returns_zero() {
        let cache = VerdictCache::with_defaults();
        assert_eq!(cache.sweep_expired(123_456), 0);
    }
}

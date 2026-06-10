//! Active-session tracking for continuous adaptive ZTNA.
//!
//! [`ZtnaService::evaluate`](crate::service::ZtnaService::evaluate)
//! is a *stateless, per-request* decision — it has no memory of the
//! sessions it has admitted. That is the right shape for the hot
//! path (it keeps the brain trivially shareable across `sng-edge`
//! producer instances behind a single `Arc<ZtnaService>`), but it
//! means a grant made at access time is never revisited: a device
//! whose disk encryption is switched off, a user whose MFA lapses,
//! or a device that is later revoked all keep their already-open
//! sessions until the *next* access request happens to re-run the
//! evaluator.
//!
//! [`SessionTracker`] closes that gap. The producer records an
//! [`AccessGrant`] for every session it opens on an `Allow`
//! decision and drops it when the session ends. The companion
//! [`ReevalLoop`](crate::reeval::ReevalLoop) periodically walks the
//! tracker, re-runs the evaluator for each live grant, and revokes
//! the ones whose verdict has flipped to deny.
//!
//! # Scale + concurrency
//!
//! The fleet target is thousands of concurrent sessions per tenant
//! across ~5000 tenants — millions of live grants. A single
//! `Mutex<HashMap>` would serialise every session open / close /
//! re-eval behind one lock. The tracker therefore *shards* the key
//! space across many independently-locked maps
//! ([`SessionTracker::with_shards`]); a session touches exactly one
//! shard, so unrelated sessions on different shards never contend.
//!
//! The re-evaluation sweep reads one shard at a time
//! ([`SessionTracker::shard_grants`]), cloning that shard's grants
//! and releasing its lock *before* evaluating them, so the
//! (in-memory but non-trivial) evaluation never blocks session
//! opens / closes, and peak sweep memory is bounded to a single
//! shard's worth of grants rather than the whole table.
//!
//! # Tenant isolation
//!
//! Every grant carries its `tenant_id`. The tracker itself is a
//! flat key space (session ids are globally unique opaque
//! producer-minted tokens), but every read that could surface
//! cross-tenant data — [`SessionTracker::tenant_session_count`] —
//! filters on `tenant_id`, and the re-evaluation path re-runs the
//! full evaluator (which enforces the cross-tenant guard) rather
//! than trusting the cached grant. A grant can never widen access
//! beyond what a fresh evaluation would grant.

use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::policy::ZtnaDecisionReason;
use crate::request::AccessRequest;

/// Default shard count. A power of two so the `& (n - 1)` fast path
/// in `SessionTracker::shard_index` holds. 64 shards keeps
/// per-shard lock contention low for the thousands-per-tenant /
/// thousands-of-tenants fleet while staying a trivial fixed
/// allocation (64 `HashMap`s) for the small single-tenant
/// deployments that share the same binary.
pub const DEFAULT_SHARDS: usize = 64;

/// A tracked, currently-active ZTNA session.
///
/// Holds everything the re-evaluation loop needs to re-run the
/// evaluator without consulting the producer again: the original
/// [`AccessRequest`] (carrying app / device / user ids plus the
/// network context the contextual-access checks gate on) and the
/// owning `tenant_id`. The request's `now_ms` is the *grant-time*
/// timestamp; [`Self::reeval_request`] rebuilds a request stamped
/// with the current clock for each re-evaluation so the freshness
/// budgets (MFA / posture age) are measured against "now", not
/// against when the session opened.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessGrant {
    /// Opaque, globally-unique session identifier minted by the
    /// producer (`sng-edge`). The tracker key.
    pub session_id: String,
    /// Tenant that owns the session. Carried so reads can be
    /// tenant-scoped and revocation events can be attributed
    /// without a second provider lookup.
    pub tenant_id: String,
    /// The access request that produced the original `Allow`.
    /// Re-used (with a refreshed timestamp) on every
    /// re-evaluation.
    pub request: AccessRequest,
    /// Monotonic millisecond timestamp when the grant was first
    /// recorded.
    pub granted_at_ms: u64,
    /// Monotonic millisecond timestamp of the most recent
    /// (re-)evaluation. Equals [`Self::granted_at_ms`] until the
    /// first sweep touches the grant.
    pub last_eval_ms: u64,
    /// Verdict reason at the most recent evaluation. Starts at
    /// [`ZtnaDecisionReason::Allow`] — a grant only exists because
    /// access was allowed — and is refreshed by the re-eval loop.
    pub last_reason: ZtnaDecisionReason,
}

impl AccessGrant {
    /// Construct a grant for a freshly-allowed session. The grant
    /// is stamped as evaluated "now" (`granted_at_ms`) with an
    /// [`ZtnaDecisionReason::Allow`] verdict, since a grant is only
    /// recorded on an allow.
    #[must_use]
    pub fn new(
        session_id: impl Into<String>,
        tenant_id: impl Into<String>,
        request: AccessRequest,
        granted_at_ms: u64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            tenant_id: tenant_id.into(),
            request,
            granted_at_ms,
            last_eval_ms: granted_at_ms,
            last_reason: ZtnaDecisionReason::Allow,
        }
    }

    /// The device id this session runs on.
    #[must_use]
    pub fn device_id(&self) -> &str {
        &self.request.device_id
    }

    /// The user id this session belongs to.
    #[must_use]
    pub fn user_id(&self) -> &str {
        &self.request.user_id
    }

    /// The application this session targets.
    #[must_use]
    pub fn app_id(&self) -> &str {
        &self.request.app_id
    }

    /// Build an [`AccessRequest`] for re-evaluation: a clone of the
    /// grant-time request with its timestamp advanced to `now_ms`
    /// so MFA / posture freshness is measured against the current
    /// clock. The network context (source IP / country / network
    /// type) is preserved — those signals are properties of the
    /// session's transport, which does not change for the life of
    /// the session.
    #[must_use]
    pub fn reeval_request(&self, now_ms: u64) -> AccessRequest {
        let mut req = self.request.clone();
        req.now_ms = now_ms;
        req
    }
}

/// One shard of the tracker: the session map plus a secondary
/// `device_id -> session_ids` index over the sessions held *in this
/// shard*.
///
/// The index lets the out-of-cycle posture-push path
/// ([`SessionTracker::sessions_for_device`]) find a device's
/// sessions with a single `HashMap` lookup per shard instead of
/// scanning every grant — the difference between O(shards) and
/// O(total sessions) when a posture push fires. It is kept in
/// lockstep with `grants` under the same lock, so it can never
/// reference a session that is no longer present, and empty
/// device sets are pruned so the index does not leak memory as
/// devices churn.
#[derive(Debug, Default)]
struct Shard {
    grants: HashMap<String, AccessGrant>,
    by_device: HashMap<String, HashSet<String>>,
}

/// Outcome of [`SessionTracker::remove_if_unchanged`] — a removal
/// guarded against a concurrent re-record of the same session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardedRemoval {
    /// The stored grant was still the generation the caller
    /// evaluated and was removed; carries the removed grant. Boxed
    /// so the common `Superseded` / `Absent` outcomes don't pay for
    /// the grant's size on every return.
    Removed(Box<AccessGrant>),
    /// A grant is still present but is a *newer* generation than the
    /// caller evaluated — the producer re-recorded the session (e.g.
    /// a step-up re-auth) between the caller's clone and this call,
    /// so the stale verdict was discarded and the fresh grant left in
    /// place for the next evaluation.
    Superseded,
    /// No grant was present for the session id (the producer closed
    /// the session concurrently).
    Absent,
}

impl Shard {
    /// Insert or replace a grant, keeping the device index
    /// consistent. Replacing a session that previously pointed at a
    /// different device de-indexes the stale device entry first, so
    /// the index never points a device at a session that has since
    /// moved.
    fn insert(&mut self, grant: AccessGrant) {
        let session_id = grant.session_id.clone();
        let device_id = grant.device_id().to_owned();
        if let Some(prev) = self.grants.insert(session_id.clone(), grant)
            && prev.device_id() != device_id.as_str()
        {
            self.deindex(prev.device_id(), &session_id);
        }
        self.by_device
            .entry(device_id)
            .or_default()
            .insert(session_id);
    }

    /// Remove a grant and its device-index entry.
    fn remove(&mut self, session_id: &str) -> Option<AccessGrant> {
        let grant = self.grants.remove(session_id)?;
        self.deindex(grant.device_id(), session_id);
        Some(grant)
    }

    /// Remove a grant only if the one currently stored is still the
    /// generation the caller evaluated, identified by
    /// [`AccessGrant::granted_at_ms`]. See
    /// [`SessionTracker::remove_if_unchanged`] for the rationale.
    fn remove_if_unchanged(
        &mut self,
        session_id: &str,
        expected_granted_at_ms: u64,
    ) -> GuardedRemoval {
        match self.grants.get(session_id) {
            None => GuardedRemoval::Absent,
            // A different generation is stored: the producer
            // re-recorded the session (step-up re-auth) after the
            // caller cloned its grant. Leave the fresh grant in place.
            Some(current) if current.granted_at_ms != expected_granted_at_ms => {
                GuardedRemoval::Superseded
            }
            // Same generation: remove it (reusing `remove` so the
            // device index is pruned identically). The `None` arm is
            // unreachable under the held lock but handled totally.
            Some(_) => match self.remove(session_id) {
                Some(grant) => GuardedRemoval::Removed(Box::new(grant)),
                None => GuardedRemoval::Absent,
            },
        }
    }

    /// Drop `session_id` from `device_id`'s index set, pruning the
    /// set entirely when it becomes empty.
    fn deindex(&mut self, device_id: &str, session_id: &str) {
        if let Some(sessions) = self.by_device.get_mut(device_id) {
            sessions.remove(session_id);
            if sessions.is_empty() {
                self.by_device.remove(device_id);
            }
        }
    }
}

/// Sharded, thread-safe store of active [`AccessGrant`]s.
///
/// Cheap to share via [`std::sync::Arc`]; all interior mutability
/// lives behind per-shard [`parking_lot::Mutex`]es. See the module
/// docs for the scale / isolation rationale.
#[derive(Debug)]
pub struct SessionTracker {
    shards: Box<[Mutex<Shard>]>,
    /// Cached `shards.len()`; always a power of two so the index
    /// computation can mask instead of divide.
    mask: usize,
}

impl Default for SessionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionTracker {
    /// Construct a tracker with [`DEFAULT_SHARDS`] shards.
    #[must_use]
    pub fn new() -> Self {
        Self::with_shards(DEFAULT_SHARDS)
    }

    /// Construct a tracker with `requested` shards, rounded up to
    /// the next power of two (minimum 1). More shards reduce lock
    /// contention at the cost of a fixed `HashMap`-per-shard
    /// allocation; the default of 64 suits the fleet target.
    #[must_use]
    pub fn with_shards(requested: usize) -> Self {
        let count = requested.max(1).next_power_of_two();
        let mut shards = Vec::with_capacity(count);
        for _ in 0..count {
            shards.push(Mutex::new(Shard::default()));
        }
        Self {
            shards: shards.into_boxed_slice(),
            mask: count - 1,
        }
    }

    /// Number of shards. Exposed so the re-evaluation loop can walk
    /// the tracker one shard at a time via [`Self::shard_grants`].
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    fn shard_index(&self, session_id: &str) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        session_id.hash(&mut hasher);
        // `mask` is `len - 1` for a power-of-two `len`, so masking
        // is equivalent to `% len` but branch-free. The masked
        // value is `<= mask < usize::MAX`, so the `u64 -> usize`
        // narrowing cannot lose information; `try_from` makes that
        // total without an `as` cast (the `unwrap_or` arm is
        // unreachable and harmlessly falls back to shard 0).
        usize::try_from(hasher.finish() & (self.mask as u64)).unwrap_or(0)
    }

    /// Record (insert or replace) a grant. Keyed by
    /// [`AccessGrant::session_id`]; re-recording the same session
    /// id overwrites the prior grant (e.g. the producer refreshing
    /// the cached request after a step-up re-auth).
    pub fn record(&self, grant: AccessGrant) {
        let idx = self.shard_index(&grant.session_id);
        self.shards[idx].lock().insert(grant);
    }

    /// Remove and return the grant for `session_id`, if present.
    /// Called by the producer on session end and by the re-eval
    /// loop when a verdict flips to deny.
    pub fn remove(&self, session_id: &str) -> Option<AccessGrant> {
        let idx = self.shard_index(session_id);
        self.shards[idx].lock().remove(session_id)
    }

    /// Remove a session **only if** the grant currently stored is
    /// still the one the caller evaluated, identified by its
    /// [`AccessGrant::granted_at_ms`] generation stamp.
    ///
    /// The re-eval sweep clones a grant, evaluates it without holding
    /// the shard lock, and then acts on the verdict. On a flip to
    /// deny it must tear the session down — but an unconditional
    /// [`Self::remove`] would also delete a grant the producer
    /// *re-recorded* in that window (a step-up re-auth that refreshed
    /// the credentials the sweep just judged stale), silently dropping
    /// a now-valid session. This guarded remove mirrors the in-place
    /// [`Self::mark_evaluated`] on the retain path: it commits the
    /// revocation only against the exact generation it evaluated. A
    /// re-record bumps `granted_at_ms`, so a newer grant yields
    /// [`GuardedRemoval::Superseded`] and survives to be judged on its
    /// own merits next sweep; a missing grant yields
    /// [`GuardedRemoval::Absent`]. Revoking still fails safe — at
    /// worst a regression waits one extra sweep — while a legitimate
    /// re-auth is never collateral.
    pub fn remove_if_unchanged(
        &self,
        session_id: &str,
        expected_granted_at_ms: u64,
    ) -> GuardedRemoval {
        let idx = self.shard_index(session_id);
        self.shards[idx]
            .lock()
            .remove_if_unchanged(session_id, expected_granted_at_ms)
    }

    /// Return a clone of the grant for `session_id`, if present.
    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<AccessGrant> {
        let idx = self.shard_index(session_id);
        self.shards[idx].lock().grants.get(session_id).cloned()
    }

    /// True iff `session_id` is currently tracked.
    #[must_use]
    pub fn contains(&self, session_id: &str) -> bool {
        let idx = self.shard_index(session_id);
        self.shards[idx].lock().grants.contains_key(session_id)
    }

    /// Total number of tracked sessions across all shards.
    ///
    /// Sums the per-shard lengths under their individual locks, so
    /// the result is a near-instantaneous estimate rather than a
    /// globally-consistent snapshot: concurrent opens / closes on
    /// shards already counted are not reflected. Intended for ops
    /// gauges, not for coordination.
    #[must_use]
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().grants.len()).sum()
    }

    /// True iff no sessions are tracked. See [`Self::len`] for the
    /// consistency caveat.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|s| s.lock().grants.is_empty())
    }

    /// Count the sessions owned by `tenant_id`.
    ///
    /// Scans every shard (O(total sessions)); intended for
    /// per-tenant ops gauges and quota checks, not the hot path.
    #[must_use]
    pub fn tenant_session_count(&self, tenant_id: &str) -> usize {
        self.shards
            .iter()
            .map(|s| {
                s.lock()
                    .grants
                    .values()
                    .filter(|g| g.tenant_id == tenant_id)
                    .count()
            })
            .sum()
    }

    /// Refresh the evaluation metadata of a tracked session in
    /// place: its [`AccessGrant::last_eval_ms`] and
    /// [`AccessGrant::last_reason`]. No-op if the session is no
    /// longer tracked.
    ///
    /// Returns `true` if the session was still present (and stamped),
    /// `false` if it had already been removed — the re-eval loop uses
    /// this to count a session that vanished mid-sweep (a producer
    /// close racing the sweep) distinctly from one it actually
    /// retained, so [`SweepStats`](crate::reeval::SweepStats) stays
    /// accurate under the clone-then-evaluate TOCTOU window.
    ///
    /// Used by the re-evaluation loop to stamp a retained session
    /// without re-recording the whole grant — so a concurrent
    /// producer update to the grant's `request` (e.g. a step-up
    /// re-auth) is preserved rather than clobbered by a sweep that
    /// read a now-stale clone.
    pub fn mark_evaluated(
        &self,
        session_id: &str,
        now_ms: u64,
        reason: ZtnaDecisionReason,
    ) -> bool {
        let idx = self.shard_index(session_id);
        if let Some(grant) = self.shards[idx].lock().grants.get_mut(session_id) {
            grant.last_eval_ms = now_ms;
            grant.last_reason = reason;
            true
        } else {
            false
        }
    }

    /// Clone the grants held in shard `idx`.
    ///
    /// The shard lock is held only for the duration of the clone
    /// and released before the caller inspects the result, so the
    /// re-evaluation loop can evaluate the returned grants without
    /// blocking session opens / closes on that shard. Returns an
    /// empty vector when `idx` is out of range.
    #[must_use]
    pub fn shard_grants(&self, idx: usize) -> Vec<AccessGrant> {
        match self.shards.get(idx) {
            Some(shard) => shard.lock().grants.values().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// Clone every grant for sessions running on `device_id`.
    ///
    /// Used by the out-of-cycle posture-push path to re-evaluate
    /// only the sessions affected by a single device's posture
    /// change instead of sweeping the whole tracker. Backed by the
    /// per-shard device index, so the cost is O(shards) lookups plus
    /// O(sessions-on-device) clones — independent of the total
    /// session count, which matters when a posture push fires
    /// against a tracker holding millions of grants.
    #[must_use]
    pub fn sessions_for_device(&self, device_id: &str) -> Vec<AccessGrant> {
        let mut out = Vec::new();
        for shard in &self.shards {
            let guard = shard.lock();
            let Some(session_ids) = guard.by_device.get(device_id) else {
                continue;
            };
            out.reserve(session_ids.len());
            for sid in session_ids {
                if let Some(grant) = guard.grants.get(sid) {
                    out.push(grant.clone());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn grant(session: &str, tenant: &str, device: &str, user: &str) -> AccessGrant {
        let req = AccessRequest::new("wiki", device, user, 1_000);
        AccessGrant::new(session, tenant, req, 1_000)
    }

    #[test]
    fn record_then_get_returns_grant() {
        let t = SessionTracker::new();
        t.record(grant("s1", "t1", "dev-1", "alice"));
        let got = t.get("s1").expect("recorded session present");
        assert_eq!(got.session_id, "s1");
        assert_eq!(got.tenant_id, "t1");
        assert_eq!(got.device_id(), "dev-1");
        assert_eq!(got.user_id(), "alice");
        assert_eq!(got.app_id(), "wiki");
        assert_eq!(got.last_reason, ZtnaDecisionReason::Allow);
    }

    #[test]
    fn remove_returns_and_deletes() {
        let t = SessionTracker::new();
        t.record(grant("s1", "t1", "dev-1", "alice"));
        let removed = t.remove("s1").expect("present before remove");
        assert_eq!(removed.session_id, "s1");
        assert!(t.get("s1").is_none());
        assert!(t.remove("s1").is_none());
    }

    #[test]
    fn remove_if_unchanged_removes_matching_generation() {
        let t = SessionTracker::new();
        let g = grant("s1", "t1", "dev-1", "alice"); // granted_at_ms = 1_000
        t.record(g.clone());
        match t.remove_if_unchanged("s1", g.granted_at_ms) {
            GuardedRemoval::Removed(removed) => assert_eq!(removed.session_id, "s1"),
            other => panic!("expected Removed, got {other:?}"),
        }
        assert!(t.get("s1").is_none());
        // Device index pruned with the grant.
        assert!(t.sessions_for_device("dev-1").is_empty());
    }

    #[test]
    fn remove_if_unchanged_supersedes_rerecorded_generation() {
        let t = SessionTracker::new();
        let stale = grant("s1", "t1", "dev-1", "alice"); // granted_at_ms = 1_000
        t.record(stale.clone());
        // Producer re-records the same session (step-up re-auth) with a
        // newer grant generation before the guarded remove lands.
        let req = AccessRequest::new("wiki", "dev-1", "alice", 5_000);
        let refreshed = AccessGrant::new("s1", "t1", req, 5_000);
        t.record(refreshed);
        // The stale verdict must not delete the refreshed grant.
        assert_eq!(
            t.remove_if_unchanged("s1", stale.granted_at_ms),
            GuardedRemoval::Superseded
        );
        let kept = t.get("s1").expect("refreshed grant survives");
        assert_eq!(kept.granted_at_ms, 5_000);
        // Device index still points at the live session.
        let on_device = t.sessions_for_device("dev-1");
        assert_eq!(on_device.len(), 1);
        assert_eq!(on_device[0].session_id, "s1");
    }

    #[test]
    fn remove_if_unchanged_absent_when_missing() {
        let t = SessionTracker::new();
        assert_eq!(
            t.remove_if_unchanged("ghost", 1_000),
            GuardedRemoval::Absent
        );
    }

    #[test]
    fn record_same_session_id_overwrites() {
        let t = SessionTracker::new();
        t.record(grant("s1", "t1", "dev-1", "alice"));
        t.record(grant("s1", "t1", "dev-2", "alice"));
        assert_eq!(t.len(), 1);
        assert_eq!(t.get("s1").unwrap().device_id(), "dev-2");
    }

    #[test]
    fn len_and_is_empty_track_population() {
        let t = SessionTracker::new();
        assert!(t.is_empty());
        assert_eq!(t.len(), 0);
        for i in 0..100 {
            t.record(grant(&format!("s{i}"), "t1", "dev-1", "alice"));
        }
        assert!(!t.is_empty());
        assert_eq!(t.len(), 100);
    }

    #[test]
    fn shards_round_up_to_power_of_two() {
        assert_eq!(SessionTracker::with_shards(1).shard_count(), 1);
        assert_eq!(SessionTracker::with_shards(3).shard_count(), 4);
        assert_eq!(SessionTracker::with_shards(64).shard_count(), 64);
        assert_eq!(SessionTracker::with_shards(100).shard_count(), 128);
        // Zero is clamped to a single shard rather than panicking.
        assert_eq!(SessionTracker::with_shards(0).shard_count(), 1);
    }

    #[test]
    fn shard_grants_partition_covers_every_session() {
        let t = SessionTracker::with_shards(8);
        for i in 0..500 {
            t.record(grant(&format!("s{i}"), "t1", "dev-1", "alice"));
        }
        let swept: usize = (0..t.shard_count()).map(|i| t.shard_grants(i).len()).sum();
        assert_eq!(swept, 500, "every session must appear in exactly one shard");
        // Out-of-range shard index yields an empty vector.
        assert!(t.shard_grants(t.shard_count()).is_empty());
    }

    #[test]
    fn tenant_session_count_is_isolated() {
        let t = SessionTracker::new();
        t.record(grant("s1", "t1", "dev-1", "alice"));
        t.record(grant("s2", "t1", "dev-2", "bob"));
        t.record(grant("s3", "t2", "dev-3", "carol"));
        assert_eq!(t.tenant_session_count("t1"), 2);
        assert_eq!(t.tenant_session_count("t2"), 1);
        assert_eq!(t.tenant_session_count("t3"), 0);
    }

    #[test]
    fn sessions_for_device_filters() {
        let t = SessionTracker::new();
        t.record(grant("s1", "t1", "dev-1", "alice"));
        t.record(grant("s2", "t1", "dev-1", "alice"));
        t.record(grant("s3", "t1", "dev-2", "bob"));
        let mut for_dev1: Vec<String> = t
            .sessions_for_device("dev-1")
            .into_iter()
            .map(|g| g.session_id)
            .collect();
        for_dev1.sort();
        assert_eq!(for_dev1, vec!["s1".to_owned(), "s2".to_owned()]);
        assert_eq!(t.sessions_for_device("dev-3").len(), 0);
    }

    #[test]
    fn reeval_request_advances_clock_preserving_context() {
        let req = AccessRequest::new("wiki", "dev-1", "alice", 1_000).with_network(
            Some("203.0.113.5".to_owned()),
            Some("US".to_owned()),
            Some(crate::request::NetworkType::Corporate),
        );
        let g = AccessGrant::new("s1", "t1", req, 1_000);
        let re = g.reeval_request(9_000);
        assert_eq!(re.now_ms, 9_000);
        assert_eq!(re.source_country.as_deref(), Some("US"));
        assert_eq!(
            re.network_type,
            Some(crate::request::NetworkType::Corporate)
        );
        assert_eq!(re.source_ip.as_deref(), Some("203.0.113.5"));
        // The stored grant is untouched.
        assert_eq!(g.request.now_ms, 1_000);
    }
}

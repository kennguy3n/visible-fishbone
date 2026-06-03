//! SD-WAN orchestrator.
//!
//! [`SdwanService`] is the brain that the data path /
//! sng-edge consults per steerable flow. Flow:
//!
//! 1. Producer calls [`SdwanService::evaluate`] with a
//!    [`crate::request::SteeringRequest`] and the
//!    current wall-clock millisecond timestamp.
//! 2. Service queries the [`crate::path::PathProvider`]
//!    for paths eligible for the requested traffic
//!    class. An empty candidate set short-circuits to
//!    [`SteeringReason::NoAvailablePath`].
//! 3. Service joins each candidate with its most-recent
//!    [`crate::probe::PathProbe`] from the
//!    [`crate::probe::ProbeProvider`], discarding stale
//!    probes (older than `policy.probe_max_age_ms`).
//! 4. Service partitions the fresh candidates into
//!    in-budget (every metric inside the policy's SLO
//!    floor) and out-of-budget (some metric exceeded a
//!    floor). The lowest-scoring in-budget candidate
//!    wins; if none are in-budget, the lowest-scoring
//!    out-of-budget candidate wins with reason
//!    [`SteeringReason::FallbackBelowFloor`]. If every
//!    candidate is stale, reason
//!    [`SteeringReason::AllProbesStale`].
//! 5. Service consults the sticky-flow cache: if this
//!    `flow_key` was selected recently (within
//!    `policy.sticky_window_ms`) and the previously-
//!    selected path is still eligible + fresh +
//!    in-budget, the prior choice wins with reason
//!    [`SteeringReason::StickyPinned`] instead of
//!    [`SteeringReason::Best`].
//! 6. Service maps the decision to an
//!    [`sng_core::envelope::Verdict`] and emits one
//!    [`sng_core::events::SdwanEvent`] through the
//!    telemetry channel — `try_send`, never blocking.
//! 7. Service bumps the appropriate
//!    [`crate::stats::SdwanStats`] reason counter,
//!    updates the sticky-flow cache when a path was
//!    selected, and returns the decision.
//!
//! The whole call is **sync** — no I/O. Providers
//! refresh their state off the request path (the BFD
//! ingestor pushes probes into the
//! [`crate::probe::ProbeProvider`]; the bundle adapter
//! swaps policies through
//! [`crate::policy::SdwanPolicyHolder::try_replace`]).
//!
//! ## Sticky-flow cache details
//!
//! The cache is a `parking_lot::Mutex<HashMap<String, StickyEntry>>`
//! keyed by `flow_key`. It is **bounded** — the service
//! evicts entries whose `pinned_until_ms` has elapsed on
//! the next eviction sweep. The mutex is held only for
//! the read/write per evaluation; the data path's
//! latency profile is dominated by the score computation,
//! not the cache lookup.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::Mutex;
use tokio::sync::mpsc;

use sng_core::envelope::Verdict;
use sng_core::events::SdwanEvent;
use sng_telemetry::TelemetryEvent;

use crate::app_steering::AppSteeringTable;
use crate::cellular::CellularBudget;
use crate::decision::{SteeringDecision, SteeringReason};
use crate::error::SdwanError;
use crate::failover::FailoverEngine;
use crate::path::{Path, PathId, PathProvider, StaticPathProvider};
use crate::policy::{SdwanPolicy, SdwanPolicyHolder};
use crate::probe::{PathProbe, ProbeProvider, StaticProbeProvider};
use crate::request::SteeringRequest;
use crate::score::{ScoreBreakdown, score_path};
use crate::sla::SlaMonitor;
use crate::stats::SdwanStats;

/// Map a [`SteeringDecision`] to the wire [`Verdict`]
/// the data path consumes.
///
/// A selected path → [`Verdict::Allow`]; a no-path /
/// stale-probe decision → [`Verdict::Deny`]. The SD-WAN
/// brain doesn't produce `Alert` or `Inspect` — those
/// belong to the security brains (IPS / SWG).
#[must_use]
pub fn decision_to_verdict(decision: &SteeringDecision) -> Verdict {
    if decision.reason.is_selected() {
        Verdict::Allow
    } else {
        Verdict::Deny
    }
}

/// Configuration for [`SdwanService`].
#[derive(Clone, Debug)]
pub struct SdwanServiceConfig {
    /// Maximum number of concurrent steered flows the
    /// brain advertises. The brain doesn't enforce this
    /// itself — the data path does — but the value is
    /// surfaced for the producer's shed-load logic.
    pub max_flows: usize,
    /// Maximum number of sticky-flow entries the brain
    /// retains. The eviction sweep keeps the map size
    /// bounded so a very high-cardinality `flow_key`
    /// stream (e.g. one per 5-tuple over a long
    /// observation window) can't grow the map without
    /// bound between sweeps.
    ///
    /// The value is clamped to a minimum of `1` by
    /// [`Self::normalize`] (applied automatically by
    /// [`SdwanServiceBuilder::with_config`] and
    /// [`SdwanServiceBuilder::build`]). A capacity of
    /// `0` would otherwise let the sweep oscillate
    /// between `0` and `1` entry on every insert because
    /// `g.len() >= 0` always holds — the cache would be
    /// effectively disabled but each insert would still
    /// pay the sweep cost. Operators who want to disable
    /// stickiness entirely should instead set
    /// [`crate::SdwanPolicy::sticky_window_ms`] to `0`,
    /// which short-circuits the cache lookup at the
    /// entry to `finalise`.
    pub sticky_cache_capacity: usize,
}

impl Default for SdwanServiceConfig {
    fn default() -> Self {
        Self {
            max_flows: 131_072,
            sticky_cache_capacity: 65_536,
        }
    }
}

impl SdwanServiceConfig {
    /// Clamp fields that would otherwise produce
    /// surprising runtime behavior into a safe range.
    ///
    /// Currently:
    ///
    /// - `sticky_cache_capacity` is clamped to `>= 1`.
    ///   `0` is documented as 'disable stickiness' but
    ///   the natural reading produces oscillation rather
    ///   than disablement; the intended way to disable
    ///   sticky-flow is `SdwanPolicy::sticky_window_ms =
    ///   0`. We clamp here so a misconfigured deployment
    ///   doesn't silently churn the cache.
    ///
    /// Idempotent — calling `.normalize()` twice on the
    /// same config returns the same shape as calling it
    /// once.
    #[must_use]
    pub fn normalize(mut self) -> Self {
        self.sticky_cache_capacity = self.sticky_cache_capacity.max(1);
        self
    }
}

/// Builder for [`SdwanService`]. Mirrors `SwgServiceBuilder`
/// / `ZtnaServiceBuilder` so call sites that wire one
/// subsystem can wire the others with the same idioms.
#[allow(missing_debug_implementations)]
pub struct SdwanServiceBuilder {
    cfg: SdwanServiceConfig,
    policy: Arc<SdwanPolicyHolder>,
    paths: Arc<dyn PathProvider>,
    probes: Arc<dyn ProbeProvider>,
    stats: Arc<SdwanStats>,
    sla_monitor: Option<Arc<SlaMonitor>>,
    failover: Option<Arc<FailoverEngine>>,
    app_steering: Option<Arc<AppSteeringTable>>,
    cellular_budget: Option<Arc<CellularBudget>>,
}

impl SdwanServiceBuilder {
    /// Initialise with empty providers + default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cfg: SdwanServiceConfig::default(),
            policy: Arc::new(SdwanPolicyHolder::default()),
            paths: Arc::new(StaticPathProvider::empty()),
            probes: Arc::new(StaticProbeProvider::empty()),
            stats: Arc::new(SdwanStats::default()),
            sla_monitor: None,
            failover: None,
            app_steering: None,
            cellular_budget: None,
        }
    }

    /// Override the config. The config is passed through
    /// [`SdwanServiceConfig::normalize`] so callers that
    /// pass `sticky_cache_capacity = 0` (which would
    /// otherwise oscillate the sticky cache) get the
    /// clamped-to-1 value installed.
    #[must_use]
    pub fn with_config(mut self, cfg: SdwanServiceConfig) -> Self {
        self.cfg = cfg.normalize();
        self
    }

    /// Override the policy holder.
    #[must_use]
    pub fn with_policy(mut self, policy: Arc<SdwanPolicyHolder>) -> Self {
        self.policy = policy;
        self
    }

    /// Override the path provider.
    #[must_use]
    pub fn with_path_provider(mut self, p: Arc<dyn PathProvider>) -> Self {
        self.paths = p;
        self
    }

    /// Override the probe provider.
    #[must_use]
    pub fn with_probe_provider(mut self, p: Arc<dyn ProbeProvider>) -> Self {
        self.probes = p;
        self
    }

    /// Override the stats handle.
    #[must_use]
    pub fn with_stats(mut self, stats: Arc<SdwanStats>) -> Self {
        self.stats = stats;
        self
    }

    /// Attach an SLA monitor (see [`crate::sla::SlaMonitor`]).
    /// Optional — when unset the service performs no
    /// sustained-breach detection. The monitor is built by
    /// the caller (it needs a clone of the telemetry
    /// sender) and shared in; the caller spawns
    /// [`crate::sla::SlaMonitor::run`] and bridges emitted
    /// violations to [`Self::with_failover`].
    #[must_use]
    pub fn with_sla_monitor(mut self, monitor: Arc<SlaMonitor>) -> Self {
        self.sla_monitor = Some(monitor);
        self
    }

    /// Attach a dual-WAN failover engine (see
    /// [`crate::failover::FailoverEngine`]). Optional. The
    /// engine is pre-validated by its constructor, so this
    /// stays infallible and chainable.
    #[must_use]
    pub fn with_failover(mut self, engine: Arc<FailoverEngine>) -> Self {
        self.failover = Some(engine);
        self
    }

    /// Attach an application-aware steering table (see
    /// [`crate::app_steering::AppSteeringTable`]). Optional.
    #[must_use]
    pub fn with_app_steering(mut self, table: Arc<AppSteeringTable>) -> Self {
        self.app_steering = Some(table);
        self
    }

    /// Attach a cellular data-cap budget (see
    /// [`crate::cellular::CellularBudget`]) for the
    /// last-resort 4G/5G backup. Optional.
    #[must_use]
    pub fn with_cellular_budget(mut self, budget: Arc<CellularBudget>) -> Self {
        self.cellular_budget = Some(budget);
        self
    }

    /// Build the service. `telemetry` is the egress
    /// channel — every evaluation `try_send`s one
    /// [`sng_core::events::SdwanEvent`] here.
    ///
    /// The config is normalised one last time so callers
    /// that mutated `self.cfg` directly between
    /// `with_config` and `build` still get a safe shape.
    #[must_use]
    pub fn build(self, telemetry: mpsc::Sender<TelemetryEvent>) -> SdwanService {
        SdwanService {
            cfg: self.cfg.normalize(),
            policy: self.policy,
            paths: self.paths,
            probes: self.probes,
            stats: self.stats,
            telemetry,
            sticky: Arc::new(Mutex::new(HashMap::new())),
            evictions: Arc::new(AtomicU64::new(0)),
            sla_monitor: self.sla_monitor,
            failover: self.failover,
            app_steering: self.app_steering,
            cellular_budget: self.cellular_budget,
        }
    }
}

impl Default for SdwanServiceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// The SD-WAN service. Cheap to share via [`Arc`] —
/// every internal handle is clone-cheap.
#[derive(Clone)]
pub struct SdwanService {
    cfg: SdwanServiceConfig,
    policy: Arc<SdwanPolicyHolder>,
    paths: Arc<dyn PathProvider>,
    probes: Arc<dyn ProbeProvider>,
    stats: Arc<SdwanStats>,
    telemetry: mpsc::Sender<TelemetryEvent>,
    // Sticky-flow cache. The map is keyed by
    // [`crate::request::SteeringRequest::flow_key`] —
    // the producer's stable per-flow identifier (5-tuple
    // hash, app-flow id, etc.) — NOT by [`PathId`]. The
    // value carries the previously-selected
    // [`PathId`] plus the pin's expiry, so the next
    // request for the same flow can short-circuit
    // re-scoring (see `sticky_lookup` / `sticky_insert`
    // below). Keying by flow rather than path is what
    // makes the cache a flow-pinning mechanism — keying
    // by path would only let us memoise per-path
    // recently-computed state, which is not what
    // sticky-flow means. The value type is `String`
    // (instead of holding a `&str` borrow) because the
    // map outlives any one request's `flow_key` slice.
    // Production calls hold the mutex for microseconds.
    sticky: Arc<Mutex<HashMap<String, StickyPin>>>,
    // Eviction counter — exposed for observability so
    // operators can see how often the sticky cache is
    // being pruned.
    evictions: Arc<AtomicU64>,
    // Optional competitive-depth components. Each is
    // `None` unless wired via the builder; the core
    // `evaluate` path is unchanged when they are absent.
    // They are held as shared handles so the data path /
    // background tasks (SLA monitor loop, failover health
    // bridge) can consult them lock-free.
    sla_monitor: Option<Arc<SlaMonitor>>,
    failover: Option<Arc<FailoverEngine>>,
    app_steering: Option<Arc<AppSteeringTable>>,
    cellular_budget: Option<Arc<CellularBudget>>,
}

/// Per-flow sticky-pin cache entry.
///
/// Holds the path id of the last selected path for a
/// flow plus the absolute wall-clock millisecond
/// timestamp after which the pin no longer applies. The
/// path id is stored as a thin `String` wrapper rather
/// than an `Arc<Path>` so a policy reload that drops a
/// path is observed at the next evaluation
/// (`paths.get(path_id)` returns `None`, the stale
/// sticky entry is retired silently).
#[derive(Clone, Debug)]
struct StickyPin {
    path_id: PathId,
    pinned_until_ms: u64,
}

impl std::fmt::Debug for SdwanService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SdwanService")
            .field("cfg", &self.cfg)
            .field("policy", &"<policy>")
            .field("paths", &"<provider>")
            .field("probes", &"<provider>")
            .field("stats", &self.stats)
            .field("evictions", &self.evictions.load(Ordering::Relaxed))
            .field("sla_monitor", &self.sla_monitor.is_some())
            .field("failover", &self.failover.is_some())
            .field("app_steering", &self.app_steering.is_some())
            .field("cellular_budget", &self.cellular_budget.is_some())
            .finish_non_exhaustive()
    }
}

impl SdwanService {
    /// Stats handle.
    #[must_use]
    pub fn stats(&self) -> &Arc<SdwanStats> {
        &self.stats
    }

    /// Policy holder handle.
    #[must_use]
    pub fn policy(&self) -> &Arc<SdwanPolicyHolder> {
        &self.policy
    }

    /// The attached SLA monitor, if any.
    #[must_use]
    pub fn sla_monitor(&self) -> Option<&Arc<SlaMonitor>> {
        self.sla_monitor.as_ref()
    }

    /// The attached failover engine, if any. The data path
    /// reads [`crate::failover::FailoverEngine::active`]
    /// (a single atomic load) to learn the currently-active
    /// underlay for the failover group.
    #[must_use]
    pub fn failover(&self) -> Option<&Arc<FailoverEngine>> {
        self.failover.as_ref()
    }

    /// The attached application-aware steering table, if
    /// any.
    #[must_use]
    pub fn app_steering(&self) -> Option<&Arc<AppSteeringTable>> {
        self.app_steering.as_ref()
    }

    /// The attached cellular data-cap budget, if any.
    #[must_use]
    pub fn cellular_budget(&self) -> Option<&Arc<CellularBudget>> {
        self.cellular_budget.as_ref()
    }

    /// Configured max flow count.
    #[must_use]
    pub fn max_flows(&self) -> usize {
        self.cfg.max_flows
    }

    /// Cumulative sticky-cache evictions observed.
    /// Exposed so dashboards can spot a cache being
    /// driven into thrash by a high-cardinality
    /// `flow_key` stream.
    #[must_use]
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }

    /// Reload the active SD-WAN policy. Validates the
    /// candidate via [`SdwanPolicy::validate`] before
    /// installing it. A failed validation leaves the
    /// previously-loaded policy active, records a
    /// [`SdwanStats::record_bundle_load_failure`], and
    /// returns the error.
    ///
    /// ## Sticky-cache handling on transition to
    /// `sticky_window_ms == 0`
    ///
    /// When the new policy disables stickiness
    /// (`sticky_window_ms == 0`), this method **drops
    /// every entry currently in the sticky-flow cache**
    /// and adds the dropped count to [`Self::evictions`].
    /// Without this, entries written under the prior
    /// (non-zero) window would survive indefinitely:
    /// `evaluate` skips `sticky_lookup` under the same
    /// guard and `finalise` skips `sticky_insert` under
    /// the same guard, so no future code path would
    /// observe (and therefore prune) them. The entries
    /// have no functional effect on path selection while
    /// stickiness is disabled — both selection guards
    /// short-circuit before they touch the cache — but
    /// they would corrupt the cache's
    /// "size = current sticky-pinned flow count"
    /// invariant that operator dashboards and the
    /// in-crate test suite rely on. Clearing here keeps
    /// `sticky.len()` honest the moment the operator
    /// disables stickiness, and the eviction-counter
    /// bump leaves an audit trail of when the drop
    /// happened. Reloads where the new policy keeps a
    /// non-zero window (including a window *shorter* than
    /// the previous one) leave the cache untouched —
    /// existing pins continue to honour their original
    /// absolute `pinned_until_ms` wall-clock expiry; this
    /// is by design and exercised by
    /// `sticky_pin_survives_in_place_policy_reload`.
    ///
    /// # Errors
    ///
    /// - [`SdwanError::InvalidPolicy`] when the candidate
    ///   policy fails [`SdwanPolicy::validate`].
    pub fn reload_policy(&self, policy: SdwanPolicy) -> Result<(), SdwanError> {
        // Snapshot the disable-flag before handing
        // ownership to `try_replace`. We use the
        // candidate's flag (not the previous policy's)
        // because the swap is the point at which
        // selection starts honouring the new
        // `sticky_window_ms == 0` semantics; entries
        // written under the old window are now orphans
        // from the new policy's perspective regardless of
        // what the old policy said.
        let new_disables_sticky = policy.sticky_window_ms == 0;
        match self.policy.try_replace(policy) {
            Ok(()) => {
                if new_disables_sticky {
                    // Take the lock once, snapshot the
                    // length, then clear. The mutex is
                    // dropped before `fetch_add` so the
                    // evaluation hot path is never blocked
                    // by an evictions-bookkeeping write.
                    // `g.len()` always fits a u64 — the
                    // cache is capped by
                    // `SdwanServiceConfig::sticky_cache_capacity`
                    // (a `usize`) and we never store more
                    // entries than fit on the host.
                    let dropped = {
                        let mut g = self.sticky.lock();
                        let n = g.len() as u64;
                        g.clear();
                        n
                    };
                    if dropped > 0 {
                        self.evictions.fetch_add(dropped, Ordering::Relaxed);
                    }
                }
                self.stats.record_bundle_load();
                Ok(())
            }
            Err(e) => {
                self.stats.record_bundle_load_failure();
                Err(e)
            }
        }
    }

    /// Record a failed bundle reload. The bundle adapter
    /// calls this when bundle decode itself fails
    /// (before it has an `SdwanPolicy` to hand to
    /// [`Self::reload_policy`]).
    pub fn record_bundle_load_failure(&self) {
        self.stats.record_bundle_load_failure();
    }

    /// Evaluate one steering request.
    ///
    /// Sync, bounded-allocation. Per-call allocations on
    /// the steady-state path are dominated by the
    /// `PathProvider::candidates` return — a fresh
    /// `Vec<Arc<Path>>` whose length is the count of
    /// paths eligible for `request.traffic_class` (one
    /// `Arc` clone per eligible path). Beyond that, the
    /// function allocates only for the one [`SdwanEvent`]
    /// handed to telemetry (and only when telemetry
    /// actually accepts the event — a dropped `try_send`
    /// returns the unsent event so no downstream
    /// allocator is touched). Production catalogs hold
    /// a small constant number of underlays (typically
    /// well under 16 per tenant), so the per-call vector
    /// is a fixed-size, short-lived allocation rather
    /// than a growth surface.
    ///
    /// Provider implementations that need to drop the
    /// per-call `Vec` allocation entirely (e.g. for an
    /// MPSC-bound data-path running at millions of
    /// evaluations per second) can offer a borrow-shaped
    /// API in a future revision; the current
    /// [`PathProvider`] trait shape returns owned
    /// `Arc<Path>` so the borrow checker doesn't tie the
    /// scoring loop to the provider's internal lock.
    ///
    /// # Errors
    ///
    /// This function never returns an error. The
    /// signature is reserved for future provider-failure
    /// paths; today, the brain encodes every outcome
    /// inside [`SteeringDecision`] so the data path has
    /// a single shape to handle. Provider misses (an
    /// empty path table, an empty probe table) collapse
    /// to a [`SteeringReason::NoAvailablePath`] /
    /// [`SteeringReason::AllProbesStale`] decision.
    // `clippy::float_cmp` is suppressed at the function
    // level because the score tie-break inside this
    // function intentionally uses strict `==` (see the
    // long-form comment at the `breakdown.total ==
    // prev.total` site) — an epsilon-window compare
    // would let two paths with distinguishable but very
    // close scores fall into the tie-break path and
    // silently override the primary `<`-ordering. Both
    // sides of the equality are guaranteed finite by
    // `probe_is_usable` + `score_path`'s overflow clamp
    // upstream. Hand-attribute-on-expressions is
    // unstable, so the allow lives on the whole
    // function.
    #[allow(clippy::float_cmp)]
    pub fn evaluate(&self, request: &SteeringRequest) -> SteeringDecision {
        // Snapshot the policy exactly once for the whole
        // evaluation. The same `Arc<SdwanPolicy>` is then
        // threaded through `finalise` so the sticky-pin
        // duration written into the cache matches the
        // policy used for scoring + floor checks, even if
        // a `reload_policy` lands between the two reads
        // on another thread. The lock-free `ArcSwap`
        // design still applies: a swap mid-evaluation is
        // safe, it just lands on the *next* evaluation.
        let policy_snap = self.policy.snapshot();
        let candidates = self.paths.candidates(request.traffic_class);

        // Step 1: empty candidate set → no-available-path.
        if candidates.is_empty() {
            return self.finalise(
                request,
                SteeringDecision::no_path(SteeringReason::NoAvailablePath, request.traffic_class),
                &policy_snap,
            );
        }

        // Step 2: try sticky-pin first. If the previously-
        // selected path is still eligible + fresh +
        // in-budget, we keep the flow pinned to avoid
        // re-pinning TCP sessions every probe cycle.
        //
        // Short-circuit when stickiness is disabled
        // (`policy.sticky_window_ms == 0`). The cache is
        // guaranteed empty in that mode because
        // `finalise` skips `sticky_insert` under the same
        // guard (see comment at the `sticky_insert` call
        // site below) — so `sticky_lookup` would return
        // `None` after paying an uncontended mutex
        // acquire/release on every evaluation. This
        // mirrors the producer-side guard exactly so a
        // future change to one branch surfaces a
        // structural asymmetry rather than a silent perf
        // regression.
        if policy_snap.sticky_window_ms > 0 {
            if let Some(pinned) = self.sticky_lookup(&request.flow_key, request.now_ms) {
                if let Some(sticky_decision) =
                    self.try_sticky(&pinned, &candidates, &policy_snap, request)
                {
                    return self.finalise(request, sticky_decision, &policy_snap);
                }
            }
        }

        // Step 3: score every candidate that has a fresh,
        // usable probe; remember the best in-budget
        // candidate and the best out-of-budget fallback
        // separately.
        //
        // Two filters apply before scoring:
        //
        // 1. Freshness — `is_fresh` rejects probes older
        //    than `policy_snap.probe_max_age_ms`. A stale
        //    probe contains no information about the
        //    *current* state of the path.
        // 2. Usability — `probe_is_usable` rejects probes
        //    carrying non-finite metric values (NaN /
        //    ±INFINITY on `latency_ms`, `loss_pct`, or
        //    `jitter_ms`). `PathProbe::new_checked` rejects
        //    these at construction, but `PathProbe::new`
        //    (the doc-comment "unchecked" constructor used
        //    by adapters that have already validated
        //    upstream) does not — so a misbehaving adapter
        //    can mint a probe whose metric is NaN. Scoring
        //    such a probe via `score_path` collapses the
        //    total to `worst()` (`+INFINITY`) — and if it
        //    is the sole candidate, the selector would
        //    pick it as a `FallbackBelowFloor` winner with
        //    a `+INFINITY` score on the wire event. That
        //    is the wrong fail-mode: a probe whose metric
        //    is NaN tells us *nothing* about the path's
        //    health, so the selector must treat it as
        //    unusable (same shape as stale) and fall
        //    through to `AllProbesStale` rather than
        //    selecting a path with infinite-score
        //    telemetry. The `had_usable_candidate` flag
        //    drives that fall-through.
        let mut best_in_budget: Option<(Arc<Path>, ScoreBreakdown)> = None;
        let mut best_fallback: Option<(Arc<Path>, ScoreBreakdown)> = None;
        let mut had_usable_candidate = false;

        for path in &candidates {
            let Some(probe) = self.probes.get(&path.id) else {
                continue;
            };
            if !probe.is_fresh(request.now_ms, policy_snap.probe_max_age_ms) {
                continue;
            }
            if !probe_is_usable(&probe) {
                continue;
            }
            had_usable_candidate = true;
            let breakdown = score_path(&probe, &policy_snap.weights, path.static_bias);
            let in_budget = policy_snap.within_latency_floor(probe.latency_ms)
                && policy_snap.within_loss_floor(probe.loss_pct)
                && policy_snap.within_jitter_floor(probe.jitter_ms);
            if in_budget {
                // Tie-break on `path.id` for deterministic
                // selection across runs. Reasoning: HashMap
                // iteration order is implementation-defined,
                // so two paths with mathematically equal
                // scores would otherwise pick "whichever the
                // map yields first this call", which churns
                // dashboards and complicates regression
                // tests. Using `<=` here would also pick the
                // *last* candidate encountered (still
                // non-deterministic on HashMap order); the
                // explicit `path.id < prev_path.id` tie-break
                // gives a stable winner (lex-smallest id).
                // Cost: one extra `PathId` compare on a true
                // numeric tie, which is rare in practice
                // (probes vary by milliseconds).
                //
                // The `==` branch below uses strict
                // float equality intentionally — see the
                // function-level `clippy::float_cmp` allow
                // on `evaluate` for the full rationale.
                if best_in_budget.as_ref().is_none_or(|(prev_path, prev)| {
                    breakdown.total < prev.total
                        || (breakdown.total == prev.total && path.id < prev_path.id)
                }) {
                    best_in_budget = Some((Arc::clone(path), breakdown));
                }
            } else if best_fallback.as_ref().is_none_or(|(prev_path, prev)| {
                breakdown.total < prev.total
                    || (breakdown.total == prev.total && path.id < prev_path.id)
            }) {
                best_fallback = Some((Arc::clone(path), breakdown));
            }
        }

        // Step 4: no candidate had a usable probe at all
        // (every probe was either stale or non-finite).
        // `AllProbesStale` is the wire-stable label for
        // both shapes — see the variant doc on
        // `SteeringReason::AllProbesStale`.
        if !had_usable_candidate {
            return self.finalise(
                request,
                SteeringDecision::no_path(SteeringReason::AllProbesStale, request.traffic_class),
                &policy_snap,
            );
        }

        // Step 5: in-budget winner; else fallback winner;
        // else (every candidate had a fresh probe but
        // all were out of budget AND no in-budget was
        // found) → fallback winner is what we have.
        let (winner, reason) = if let Some((path, score)) = best_in_budget {
            (Some((path, score)), SteeringReason::Best)
        } else if let Some((path, score)) = best_fallback {
            (Some((path, score)), SteeringReason::FallbackBelowFloor)
        } else {
            // Defensive: should be unreachable because
            // `had_usable_candidate` is true iff we
            // populated at least one of the two
            // best_* slots above. The `debug_assert!`
            // ensures a logic regression that breaks
            // this invariant trips loudly in tests /
            // debug builds; release builds fall through
            // to a fail-closed AllProbesStale rather
            // than panicking on the production data
            // path.
            debug_assert!(
                false,
                "evaluate: had_usable_candidate=true but both best_in_budget and best_fallback are None (invariant broken)"
            );
            (None, SteeringReason::AllProbesStale)
        };

        let decision = match winner {
            Some((path, score)) => {
                SteeringDecision::selected(path.id.clone(), reason, score, request.traffic_class)
            }
            None => SteeringDecision::no_path(reason, request.traffic_class),
        };
        self.finalise(request, decision, &policy_snap)
    }

    /// Common tail of `evaluate`: bump stats, emit
    /// telemetry, update the sticky cache. Kept private
    /// so the call sites stay terse.
    ///
    /// `policy` is the same snapshot the evaluation was
    /// scored against — passed in (not re-snapshotted)
    /// so the sticky-pin window written into the cache
    /// is consistent with the policy the decision was
    /// made under, even if `reload_policy` lands on
    /// another thread between the evaluation start and
    /// the cache write.
    fn finalise(
        &self,
        request: &SteeringRequest,
        decision: SteeringDecision,
        policy: &SdwanPolicy,
    ) -> SteeringDecision {
        self.stats.record_decision(&decision.reason);
        // Look up the raw probe for the selected path
        // so the emitted event carries the wire-shape
        // probe metrics (`lat` / `loss` / `jit`), not
        // the weighted score components. A path that
        // disappeared from the probe provider between
        // selection and emission falls back to zeroes
        // — this is observability, not the verdict.
        let probe = decision.path_id.as_ref().and_then(|id| self.probes.get(id));
        // Update sticky cache on a path selection.
        //
        // Short-circuit when stickiness is disabled
        // (`policy.sticky_window_ms == 0`). Without this
        // guard, `sticky_insert` would still execute and
        // write `pinned_until_ms = now_ms + 0 = now_ms`
        // into the cache — an entry that's *already
        // expired* by the time the next `sticky_lookup`
        // runs (because `lookup` keeps entries whose
        // `pinned_until_ms > now_ms`, and `T > T` is
        // false). The entry has no functional effect on
        // selection, but every insert still pays the
        // mutex acquire + the eviction-sweep cost when
        // we hit capacity. Skipping the insert wholesale
        // is the only way to honour the
        // `SdwanServiceConfig::sticky_cache_capacity`
        // doc contract that promises this exact
        // short-circuit on `sticky_window_ms == 0`.
        if policy.sticky_window_ms > 0 {
            if let Some(path_id) = &decision.path_id {
                let pinned_until_ms = request.now_ms.saturating_add(policy.sticky_window_ms);
                self.sticky_insert(
                    request.flow_key.clone(),
                    path_id.clone(),
                    request.now_ms,
                    pinned_until_ms,
                );
            }
        }
        // Build + emit telemetry event.
        let event = build_sdwan_event(&decision, probe.as_ref());
        if self
            .telemetry
            .try_send(TelemetryEvent::Sdwan(event))
            .is_err()
        {
            self.stats.record_telemetry_drop();
        }
        decision
    }

    /// Lookup the sticky-pin entry for `flow_key`,
    /// returning `Some(path_id)` if the pin is still
    /// inside its window at `now_ms`.
    fn sticky_lookup(&self, flow_key: &str, now_ms: u64) -> Option<PathId> {
        let mut g = self.sticky.lock();
        let entry = g.get(flow_key)?;
        if entry.pinned_until_ms > now_ms {
            Some(entry.path_id.clone())
        } else {
            // Expired — remove on read so the map
            // doesn't accumulate dead entries between
            // explicit sweeps.
            g.remove(flow_key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert / overwrite the sticky-pin entry. Triggers
    /// a single-step eviction sweep when the cache
    /// reaches its capacity, to keep the upper bound
    /// honest under high-cardinality flow_key streams.
    ///
    /// `now_ms` is the request's wall-clock timestamp —
    /// the eviction sweep uses it as the freshness
    /// threshold so still-valid entries (those whose
    /// `pinned_until_ms` is in the future relative to
    /// `now_ms`) survive the sweep. Passing the new
    /// entry's `pinned_until_ms` as the threshold would
    /// wipe nearly the entire cache, defeating the
    /// sticky-pin feature.
    fn sticky_insert(&self, flow_key: String, path_id: PathId, now_ms: u64, pinned_until_ms: u64) {
        let mut g = self.sticky.lock();
        // Re-pinning an existing flow is an overwrite
        // (no size increase), so it must NOT trigger an
        // eviction sweep. The sweep is only needed when
        // we'd otherwise grow the map past capacity —
        // i.e. when the key is genuinely new. Skipping
        // the sweep on re-pin is critical: under
        // sustained sticky-pinned load at capacity, every
        // re-evaluation calls `sticky_insert` for the
        // selected flow, and an unconditional sweep here
        // would needlessly drop *another* flow's pin on
        // every request — exactly the kind of flapping
        // the sticky-pin feature exists to prevent.
        if !g.contains_key(&flow_key) && g.len() >= self.cfg.sticky_cache_capacity {
            // Sweep *expired* entries first — keep entries
            // whose `pinned_until_ms` is still in the
            // future relative to the *current* time
            // (`now_ms`), drop the rest. If no entry is
            // expired, fall through and evict one
            // arbitrary entry to make room — rare in
            // practice (it requires `capacity` distinct
            // flows arriving inside one sticky window),
            // and the alternative (refusing to insert)
            // would silently break the sticky-pin
            // contract for the new flow.
            let before = g.len();
            g.retain(|_, e| e.pinned_until_ms > now_ms);
            let removed = before - g.len();
            if removed > 0 {
                self.evictions.fetch_add(removed as u64, Ordering::Relaxed);
            }
            if g.len() >= self.cfg.sticky_cache_capacity {
                // Still full — evict one arbitrary
                // entry.
                if let Some(k) = g.keys().next().cloned() {
                    g.remove(&k);
                    self.evictions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        g.insert(
            flow_key,
            StickyPin {
                path_id,
                pinned_until_ms,
            },
        );
    }

    /// Try to honour a sticky-pin against the current
    /// candidate set. Returns `Some(decision)` only when
    /// the pinned path is still eligible + fresh +
    /// usable + in-budget.
    ///
    /// # Why `probe_is_usable` runs alongside the floors
    ///
    /// The floor methods are already self-defending —
    /// [`SdwanPolicy::within_latency_floor`],
    /// [`SdwanPolicy::within_loss_floor`], and
    /// [`SdwanPolicy::within_jitter_floor`] each
    /// `return false` on `!is_finite()`, which rejects
    /// NaN AND ±INFINITY in one check, regardless of
    /// whether a `max_*` cap is configured. So a sticky
    /// path whose probe carries a non-finite metric
    /// would already be dropped from the pin via the
    /// floor checks alone.
    ///
    /// `probe_is_usable` is therefore *not* load-bearing
    /// for the INFINITY-without-floor edge case the
    /// floors used to miss (that gap closed when the
    /// floors moved from `is_nan()` to `is_finite()` —
    /// see `crates/sng-sdwan/src/policy.rs`). It stays
    /// here for two orthogonal reasons:
    ///
    /// 1. **Defense in depth** — if a future refactor
    ///    weakens the floors back to `is_nan()`-only
    ///    (or adds a new non-finite hot path), the
    ///    sticky branch fails closed on non-finite input
    ///    at the explicit guard rather than via the
    ///    floors' implicit invariant.
    /// 2. **Semantic clarity** — `probe_is_usable`
    ///    encodes "this probe carries no information
    ///    about the path", which is a different
    ///    classification from "this probe shows the path
    ///    failed a floor". Surfacing the unusable case
    ///    explicitly lets the sticky branch drop the pin
    ///    and re-score (rather than reaffirming a pin
    ///    on an information-free signal), and it mirrors
    ///    the `had_usable_candidate` partition in
    ///    [`Self::evaluate`].
    fn try_sticky(
        &self,
        pinned: &PathId,
        candidates: &[Arc<Path>],
        policy: &SdwanPolicy,
        request: &SteeringRequest,
    ) -> Option<SteeringDecision> {
        let path = candidates.iter().find(|p| p.id == *pinned)?;
        let probe = self.probes.get(&path.id)?;
        if !probe.is_fresh(request.now_ms, policy.probe_max_age_ms) {
            return None;
        }
        if !probe_is_usable(&probe) {
            return None;
        }
        if !policy.within_latency_floor(probe.latency_ms)
            || !policy.within_loss_floor(probe.loss_pct)
            || !policy.within_jitter_floor(probe.jitter_ms)
        {
            return None;
        }
        let breakdown = score_path(&probe, &policy.weights, path.static_bias);
        Some(SteeringDecision::selected(
            path.id.clone(),
            SteeringReason::StickyPinned,
            breakdown,
            request.traffic_class,
        ))
    }
}

/// True iff every metric on `probe` is finite.
///
/// `PathProbe::new_checked` rejects non-finite metrics
/// (NaN / ±INFINITY on latency / loss / jitter) at
/// construction time, but the doc-comment "unchecked"
/// `PathProbe::new` constructor — which adapters that
/// validate upstream are free to call — does not. The
/// selector therefore re-checks before scoring so a
/// misbehaving adapter that bypasses `new_checked`
/// cannot (a) mint a non-finite total that lands on the
/// wire [`SteeringDecision::score`] (which feeds
/// dashboards as a numeric metric) or (b) become the
/// only available `FallbackBelowFloor` winner with an
/// `+INFINITY` score. NaN probes carry no information
/// about path health, so the architecturally correct
/// fail-mode is to treat them identically to stale
/// probes — fall through to `AllProbesStale` if the NaN
/// probe is the sole candidate.
fn probe_is_usable(probe: &PathProbe) -> bool {
    probe.latency_ms.is_finite() && probe.loss_pct.is_finite() && probe.jitter_ms.is_finite()
}

/// Build a wire-shape [`SdwanEvent`] from a decision and
/// the raw probe used to score the winning path. The
/// `SdwanEvent` wire schema (see
/// [`sng_core::events::SdwanEvent`]) expects the probe
/// metrics themselves (`lat`, `loss`, `jit`) — NOT the
/// weighted score components — so dashboards can compare
/// path quality across runs even if the score weights
/// change.
///
/// Kept free-standing so it can be unit-tested without a
/// full [`SdwanService`].
fn build_sdwan_event(decision: &SteeringDecision, probe: Option<&PathProbe>) -> SdwanEvent {
    let (path_id, latency_ms, loss_pct, jitter_ms, score) =
        match (&decision.path_id, decision.score, probe) {
            (Some(id), Some(s), Some(p)) => (
                id.as_str().to_string(),
                p.latency_ms,
                p.loss_pct,
                p.jitter_ms,
                s.total,
            ),
            (Some(id), Some(s), None) => {
                // Path was selected but its probe vanished
                // between selection and emission (probe
                // provider state mutated between the
                // selector's read and our re-read). Emit
                // zeroes for the metrics; the verdict
                // already shipped — this is observability,
                // not the decision.
                (id.as_str().to_string(), 0.0, 0.0, 0.0, s.total)
            }
            _ => (String::new(), 0.0, 0.0, 0.0, 0.0),
        };
    SdwanEvent {
        path_id,
        latency_ms,
        loss_pct,
        jitter_ms,
        score,
        steering_decision: decision.reason.as_str().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::TrafficClass;
    use crate::policy::ScoreWeights;
    use pretty_assertions::assert_eq;
    use tokio::sync::mpsc;

    const NOW: u64 = 10_000;

    fn telemetry() -> (mpsc::Sender<TelemetryEvent>, mpsc::Receiver<TelemetryEvent>) {
        mpsc::channel(64)
    }

    fn build(
        policy: SdwanPolicy,
        paths: Vec<Path>,
        probes: Vec<(PathId, PathProbe)>,
    ) -> (SdwanService, mpsc::Receiver<TelemetryEvent>) {
        let (tx, rx) = telemetry();
        let svc = SdwanServiceBuilder::new()
            .with_policy(Arc::new(SdwanPolicyHolder::try_new(policy).unwrap()))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths(paths)))
            .with_probe_provider(Arc::new(StaticProbeProvider::from_probes(probes)))
            .build(tx);
        (svc, rx)
    }

    fn req(flow: &str, class: TrafficClass, now_ms: u64) -> SteeringRequest {
        SteeringRequest {
            flow_key: flow.into(),
            tenant_id: "t1".into(),
            traffic_class: class,
            now_ms,
        }
    }

    #[test]
    fn selects_best_in_budget_candidate() {
        // Two candidates, both fresh + in-budget. The
        // lower-scoring one must win with reason Best.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ],
            vec![
                (PathId::new("mpls"), PathProbe::new(10.0, 0.1, 0.5, NOW)),
                (PathId::new("inet"), PathProbe::new(30.0, 0.5, 2.0, NOW)),
            ],
        );
        let d = svc.evaluate(&req("flow-1", TrafficClass::Interactive, NOW));
        assert_eq!(d.path_id, Some(PathId::new("mpls")));
        assert_eq!(d.reason, SteeringReason::Best);
        let stats = svc.stats().snapshot();
        assert_eq!(stats.requests_evaluated, 1);
        assert_eq!(stats.reason_best, 1);
        assert!(stats.invariant_holds());
    }

    #[test]
    fn falls_back_when_best_scoring_exceeds_floor() {
        // The lowest-scoring path is *out* of latency
        // floor; the selector falls through to the
        // higher-scoring but in-budget candidate. The
        // returned reason must be FallbackBelowFloor
        // (note: this happens when there's NO in-budget
        // candidate; if any in-budget exists, it wins).
        let policy = SdwanPolicy {
            max_latency_ms: Some(20.0),
            ..SdwanPolicy::default()
        };
        let (svc, _rx) = build(
            policy,
            vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ],
            vec![
                (PathId::new("mpls"), PathProbe::new(50.0, 0.0, 0.0, NOW)),
                (PathId::new("inet"), PathProbe::new(80.0, 0.0, 0.0, NOW)),
            ],
        );
        let d = svc.evaluate(&req("flow-fb", TrafficClass::Interactive, NOW));
        // Best-scoring of the two out-of-budget
        // candidates is `mpls` (50ms < 80ms).
        assert_eq!(d.path_id, Some(PathId::new("mpls")));
        assert_eq!(d.reason, SteeringReason::FallbackBelowFloor);
        let stats = svc.stats().snapshot();
        assert_eq!(stats.reason_fallback_below_floor, 1);
        assert!(stats.invariant_holds());
    }

    #[test]
    fn no_paths_returns_no_available_path() {
        let (svc, _rx) = build(SdwanPolicy::default(), Vec::new(), Vec::new());
        let d = svc.evaluate(&req("flow-np", TrafficClass::Bulk, NOW));
        assert_eq!(d.path_id, None);
        assert_eq!(d.reason, SteeringReason::NoAvailablePath);
        assert!(d.score.is_none());
        let stats = svc.stats().snapshot();
        assert_eq!(stats.reason_no_available_path, 1);
        assert!(stats.invariant_holds());
    }

    #[test]
    fn class_mismatch_returns_no_available_path() {
        // Path exists but is eligible for a different
        // class — selector must return NoAvailablePath.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![Path::new("mpls", [TrafficClass::Bulk])],
            vec![(PathId::new("mpls"), PathProbe::new(5.0, 0.0, 0.0, NOW))],
        );
        let d = svc.evaluate(&req("flow-cm", TrafficClass::RealTime, NOW));
        assert_eq!(d.reason, SteeringReason::NoAvailablePath);
    }

    #[test]
    fn all_probes_stale_returns_stale_reason() {
        // Path exists, eligible for the class, but its
        // probe is older than the policy budget.
        let policy = SdwanPolicy {
            probe_max_age_ms: 100,
            ..SdwanPolicy::default()
        };
        let (svc, _rx) = build(
            policy,
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(
                PathId::new("mpls"),
                PathProbe::new(5.0, 0.0, 0.0, NOW - 1_000),
            )],
        );
        let d = svc.evaluate(&req("flow-stale", TrafficClass::Interactive, NOW));
        assert_eq!(d.path_id, None);
        assert_eq!(d.reason, SteeringReason::AllProbesStale);
        let stats = svc.stats().snapshot();
        assert_eq!(stats.reason_all_probes_stale, 1);
        assert!(stats.invariant_holds());
    }

    #[test]
    fn missing_probe_treated_as_stale() {
        // Path is registered, eligible, but no probe
        // record exists. Same fail-closed semantics as
        // stale probe.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            Vec::new(),
        );
        let d = svc.evaluate(&req("flow-noprobe", TrafficClass::Interactive, NOW));
        assert_eq!(d.reason, SteeringReason::AllProbesStale);
    }

    #[test]
    fn sticky_pin_kicks_in_on_second_evaluation_within_same_service() {
        // Cross-evaluation sticky pinning on a SINGLE
        // service instance: the first evaluation pins the
        // flow to `mpls` (the better path under the
        // initial probe values); the underlying probe
        // table then swaps so `inet` is the better path;
        // the second evaluation, well within the sticky
        // window, must STILL return `mpls` with reason
        // [`SteeringReason::StickyPinned`].
        //
        // Two test-only details that keep this exercising
        // the right invariant:
        // 1. A `MutableProbeProvider` (defined in this
        //    test module) lets us mutate the probe table
        //    *between* `evaluate` calls without rebuilding
        //    the service, so the sticky cache (which
        //    lives on the service) actually carries
        //    across the two evaluations.
        // 2. We assert `d1.reason == Best` AND
        //    `d2.reason == StickyPinned` to distinguish
        //    "sticky pin honored" from "selector
        //    re-picked the same path by coincidence".
        //
        // The cross-policy-reload variant of this case is
        // covered separately by
        // `sticky_pin_survives_in_place_policy_reload`.
        let probes = Arc::new(MutableProbeProvider::from_probes([
            (PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
            (PathId::new("inet"), PathProbe::new(100.0, 0.0, 0.0, NOW)),
        ]));
        let (tx, _rx) = telemetry();
        let svc = SdwanServiceBuilder::new()
            .with_policy(Arc::new(
                SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap(),
            ))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths(vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ])))
            .with_probe_provider(Arc::clone(&probes) as Arc<dyn ProbeProvider>)
            .build(tx);

        let d1 = svc.evaluate(&req("flow-s", TrafficClass::Interactive, NOW));
        assert_eq!(d1.path_id, Some(PathId::new("mpls")));
        assert_eq!(d1.reason, SteeringReason::Best);

        // Swap the probe table so `inet` is now the
        // better path. Without sticky-pin, the next
        // evaluation would switch.
        probes.set(PathId::new("mpls"), PathProbe::new(100.0, 0.0, 0.0, NOW));
        probes.set(PathId::new("inet"), PathProbe::new(10.0, 0.0, 0.0, NOW));

        let d2 = svc.evaluate(&req("flow-s", TrafficClass::Interactive, NOW + 1_000));
        assert_eq!(d2.path_id, Some(PathId::new("mpls")));
        assert_eq!(d2.reason, SteeringReason::StickyPinned);
    }

    #[test]
    fn sticky_pin_expires_after_window() {
        // Two evaluations spanning more than the sticky
        // window (default 30_000 ms): the second call
        // must NOT see StickyPinned. To keep the probe
        // fresh across both calls, the policy raises
        // probe_max_age_ms to cover the 35-second gap,
        // and the probe is observed at the later time.
        let policy = SdwanPolicy {
            probe_max_age_ms: 100_000,
            ..SdwanPolicy::default()
        };
        let (svc, _rx) = build(
            policy,
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(
                PathId::new("mpls"),
                PathProbe::new(10.0, 0.0, 0.0, NOW + 95_000),
            )],
        );
        // First call pins the flow for sticky_window_ms
        // = 30_000 ms past NOW + 60_000.
        let d1 = svc.evaluate(&req("flow-x", TrafficClass::Interactive, NOW + 60_000));
        assert_eq!(d1.reason, SteeringReason::Best);
        // Second call is 35 s later — pinned_until_ms
        // has elapsed, so the lookup evicts and the
        // selector runs a fresh selection. Expect Best
        // (not StickyPinned).
        let d2 = svc.evaluate(&req("flow-x", TrafficClass::Interactive, NOW + 95_000));
        assert_eq!(d2.reason, SteeringReason::Best);
        // And the eviction counter ticked.
        assert!(svc.evictions() >= 1);
    }

    #[test]
    fn sticky_pin_skipped_when_path_no_longer_eligible() {
        // First call pins. Path table reloads remove the
        // pinned path. Second call must NOT sticky to
        // the (now-missing) path — it must run a fresh
        // selection.
        let (svc1, _rx1) = build(
            SdwanPolicy::default(),
            vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ],
            vec![
                (PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
                (PathId::new("inet"), PathProbe::new(20.0, 0.0, 0.0, NOW)),
            ],
        );
        let d1 = svc1.evaluate(&req("flow-r", TrafficClass::Interactive, NOW));
        assert_eq!(d1.path_id, Some(PathId::new("mpls")));

        // Rebuild without mpls in the catalog. The
        // previous sticky entry pointed at mpls, but
        // mpls is gone — the selector should fall
        // through to Best on inet.
        let (svc2, _rx2) = build(
            SdwanPolicy::default(),
            vec![Path::new("inet", [TrafficClass::Interactive])],
            vec![(PathId::new("inet"), PathProbe::new(20.0, 0.0, 0.0, NOW))],
        );
        // (svc2 has its own sticky cache, so we have to
        // simulate the "first call after policy reload"
        // shape. The flow_key is the same, but svc2
        // never saw it before.)
        let d2 = svc2.evaluate(&req("flow-r", TrafficClass::Interactive, NOW + 1_000));
        assert_eq!(d2.path_id, Some(PathId::new("inet")));
        assert_eq!(d2.reason, SteeringReason::Best);
    }

    #[test]
    fn sticky_cache_capacity_sweep_keeps_still_valid_entries() {
        // Regression test for the eviction-threshold bug:
        // when the cache reaches its capacity, the sweep
        // must use the request's `now_ms` (current time)
        // as the eviction threshold — not the new
        // entry's future `pinned_until_ms`. Using the
        // future threshold would wipe every entry whose
        // expiration is before the new entry's
        // expiration (i.e. nearly the entire cache),
        // defeating the sticky-pin feature.
        //
        // Test shape: fill the cache to capacity with
        // entries that are STILL VALID at `now_ms`,
        // insert one more, and verify those still-valid
        // entries survived the sweep (only when the
        // arbitrary-eviction fallback runs should we lose
        // an entry, and exactly one).
        let (tx, _rx) = telemetry();
        let svc = SdwanServiceBuilder::new()
            .with_config(SdwanServiceConfig {
                sticky_cache_capacity: 4,
                ..SdwanServiceConfig::default()
            })
            .with_policy(Arc::new(
                SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap(),
            ))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths([Path::new(
                "mpls",
                [TrafficClass::Interactive],
            )])))
            .with_probe_provider(Arc::new(StaticProbeProvider::from_probes([(
                PathId::new("mpls"),
                PathProbe::new(10.0, 0.0, 0.0, NOW),
            )])))
            .build(tx);

        // Fill cache to capacity. All four entries are
        // still valid at NOW (their pinned_until_ms is
        // NOW + sticky_window_ms = NOW + 30_000).
        for i in 0..4 {
            let flow = format!("flow-{i}");
            let _ = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW));
        }
        assert_eq!(svc.sticky.lock().len(), 4);
        let evictions_before = svc.evictions();

        // Insert one more entry at NOW. The sweep should
        // NOT wipe the four valid entries — they have
        // pinned_until_ms = NOW + 30_000 > NOW. The
        // fall-through arbitrary-eviction runs and
        // removes exactly one entry (no expired entries
        // to harvest), making room for the new one.
        let _ = svc.evaluate(&req("flow-new", TrafficClass::Interactive, NOW));
        let cache = svc.sticky.lock();
        // Cache should be at capacity (4), holding the
        // new entry plus three of the original four.
        assert_eq!(cache.len(), 4, "cache should remain at capacity");
        assert!(
            cache.contains_key("flow-new"),
            "new entry should have been inserted"
        );
        let survivors = (0..4)
            .filter(|i| cache.contains_key(&format!("flow-{i}")))
            .count();
        assert_eq!(
            survivors, 3,
            "exactly three of the original four entries should survive (one evicted by the arbitrary-eviction fallback)"
        );
        drop(cache);
        // Exactly one eviction recorded (the arbitrary
        // fallback).
        assert_eq!(
            svc.evictions() - evictions_before,
            1,
            "exactly one eviction should have been recorded (not the four-of-four wipe the bug would cause)"
        );
    }

    /// Regression test for the doc/code mismatch
    /// surfaced by Devin Review. The
    /// [`SdwanServiceConfig::sticky_cache_capacity`] doc
    /// claims `sticky_window_ms == 0` "short-circuits the
    /// cache lookup at the entry to `finalise`", but the
    /// pre-fix code still ran `sticky_insert` with
    /// `pinned_until_ms = now_ms + 0 = now_ms` — an
    /// already-expired entry that paid the mutex acquire
    /// and the capacity-sweep cost on every evaluation.
    /// This test pins the short-circuit so zero-window
    /// policies never insert into the sticky cache.
    #[test]
    fn sticky_window_zero_skips_sticky_insert() {
        let policy = SdwanPolicy {
            sticky_window_ms: 0,
            ..SdwanPolicy::default()
        };
        let (svc, _rx) = build(
            policy,
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW))],
        );

        // Hammer the service from many distinct flows.
        // With a non-zero window, every evaluation
        // inserts a sticky entry. With sticky_window_ms
        // == 0, the doc promises a short-circuit, so the
        // cache must remain empty no matter how many
        // requests we process.
        for i in 0..32 {
            let flow = format!("flow-zero-{i}");
            let d = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW));
            assert_eq!(
                d.path_id,
                Some(PathId::new("mpls")),
                "every selection should still pick mpls"
            );
            assert_eq!(
                d.reason,
                SteeringReason::Best,
                "no sticky pin should ever fire (the cache is empty)"
            );
        }

        // Cache size is 0. Pre-fix, this would be 32
        // (one entry per flow_key, all with
        // `pinned_until_ms = now_ms` and therefore
        // expired-on-arrival on any lookup).
        assert_eq!(
            svc.sticky.lock().len(),
            0,
            "sticky_window_ms == 0 must short-circuit the insert wholesale; cache should be empty"
        );
        // And no evictions, because no inserts happened.
        // Pre-fix, with 32 inserts at capacity 65_536 we
        // wouldn't hit the sweep — but a deployment
        // running with a tighter cap would have paid an
        // eviction sweep on every flap. Confirm the
        // counter is untouched here as the cleanest
        // observable signal.
        assert_eq!(svc.evictions(), 0);
    }

    /// Companion symmetry test: with `sticky_window_ms ==
    /// 0` the producer-side guard in `finalise` already
    /// keeps the cache empty, but the consumer-side
    /// guard in `evaluate` still has work to do — without
    /// it, every `evaluate` call would pay an uncontended
    /// `parking_lot::Mutex` acquire/release inside
    /// `sticky_lookup` only to walk an empty `HashMap`.
    /// This test exercises the producer-side
    /// short-circuit (no inserts ever happened) plus
    /// asserts the consumer-side short-circuit explicitly
    /// by pre-seeding the cache and confirming
    /// `sticky_lookup` is bypassed: with
    /// `sticky_window_ms == 0` the seeded pin must be
    /// ignored.
    #[test]
    fn sticky_window_zero_skips_sticky_lookup() {
        let policy = SdwanPolicy {
            sticky_window_ms: 0,
            ..SdwanPolicy::default()
        };
        let (svc, _rx) = build(
            policy,
            vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("ix", [TrafficClass::Interactive]),
            ],
            vec![
                (PathId::new("mpls"), PathProbe::new(50.0, 1.0, 5.0, NOW)),
                (PathId::new("ix"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
            ],
        );

        // Pre-seed: pretend a prior policy with a long
        // sticky window pinned this flow to the slow mpls
        // path. With `sticky_window_ms == 0` the consumer
        // guard must skip the lookup entirely — the
        // selection must fall through to the main scoring
        // loop and pick the lower-scoring `ix` path,
        // proving the seeded pin was NOT consulted.
        svc.sticky.lock().insert(
            "flow-seed".to_string(),
            super::StickyPin {
                path_id: PathId::new("mpls"),
                pinned_until_ms: NOW + 60_000,
            },
        );

        let d = svc.evaluate(&req("flow-seed", TrafficClass::Interactive, NOW));
        assert_eq!(
            d.path_id,
            Some(PathId::new("ix")),
            "sticky_window_ms == 0 must short-circuit sticky_lookup; \
             the seeded pin to mpls must NOT be honoured"
        );
        assert_eq!(d.reason, SteeringReason::Best);
    }

    /// Companion test: with a non-zero window, the cache
    /// fills as expected — confirms the short-circuit
    /// guard fires *only* on the zero case, not as a
    /// silent disable of the feature.
    #[test]
    fn sticky_window_nonzero_still_populates_cache() {
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW))],
        );
        for i in 0..5 {
            let flow = format!("flow-nonzero-{i}");
            let _ = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW));
        }
        assert_eq!(
            svc.sticky.lock().len(),
            5,
            "non-zero window must populate the cache normally"
        );
    }

    #[test]
    fn sticky_pin_survives_in_place_policy_reload() {
        // Devin Review noted that the sticky-across-reload
        // case wasn't covered: the previous tests built a
        // new SdwanService (which has its own empty
        // sticky cache) for the second evaluation. The
        // realistic operator path is a `reload_policy()`
        // call on the *same* service. The sticky cache
        // lives on the service, not on the policy holder,
        // so a policy swap must preserve the cache.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ],
            vec![
                (PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
                (PathId::new("inet"), PathProbe::new(100.0, 0.0, 0.0, NOW)),
            ],
        );
        // First call pins to mpls (it scores lower).
        let d1 = svc.evaluate(&req("flow-reload", TrafficClass::Interactive, NOW));
        assert_eq!(d1.path_id, Some(PathId::new("mpls")));
        assert_eq!(d1.reason, SteeringReason::Best);

        // Reload the policy in place. Reuse the default
        // policy with a tweaked sticky window so the
        // semantic change is observable; the sticky cache
        // on `svc` must NOT be cleared by this swap.
        svc.reload_policy(SdwanPolicy {
            sticky_window_ms: 60_000,
            ..SdwanPolicy::default()
        })
        .expect("reload should succeed");

        // Second call within the sticky window on the
        // same service: must observe the prior pin and
        // return StickyPinned, not re-select.
        let d2 = svc.evaluate(&req("flow-reload", TrafficClass::Interactive, NOW + 5_000));
        assert_eq!(d2.path_id, Some(PathId::new("mpls")));
        assert_eq!(d2.reason, SteeringReason::StickyPinned);
    }

    /// Devin Review (PR #32 sweep) flagged that the
    /// sticky cache had no cleanup path when an operator
    /// reloaded the policy with `sticky_window_ms = 0`:
    /// the producer-side guard in `finalise` and the
    /// consumer-side guard in `evaluate` both
    /// short-circuit the cache, so entries written under
    /// the prior (non-zero) window would survive
    /// indefinitely until the operator re-enabled
    /// stickiness or the process restarted. The fix is
    /// in `reload_policy`: when the new policy has
    /// `sticky_window_ms == 0`, drop every entry and
    /// bump `evictions` by the dropped count. This test
    /// exercises that contract on a populated cache.
    #[test]
    fn reload_to_zero_sticky_window_clears_cache_and_bumps_evictions() {
        let (svc, _rx) = build(
            // Start with a non-zero window so the cache
            // can actually populate; the build helper's
            // default policy has a non-zero
            // `sticky_window_ms`, but we make the
            // intent explicit here so future-default
            // drift doesn't silently invalidate the
            // setup.
            SdwanPolicy {
                sticky_window_ms: 60_000,
                ..SdwanPolicy::default()
            },
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW))],
        );

        // Populate the cache with 7 distinct flows.
        for i in 0..7 {
            let flow = format!("flow-precleartest-{i}");
            let _ = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW));
        }
        assert_eq!(
            svc.sticky.lock().len(),
            7,
            "precondition: cache should be populated before the reload"
        );
        let evictions_before = svc.evictions();

        // Reload to a policy with `sticky_window_ms = 0`.
        // The cache must be drained as a side-effect of
        // the reload, and `evictions` must grow by
        // exactly the dropped count so dashboards can
        // attribute the drop.
        svc.reload_policy(SdwanPolicy {
            sticky_window_ms: 0,
            ..SdwanPolicy::default()
        })
        .expect("reload to zero-window policy must succeed");

        assert_eq!(
            svc.sticky.lock().len(),
            0,
            "reload to sticky_window_ms == 0 must drop every cache entry; \
             otherwise the cache reports stale entries that no future code \
             path will observe or prune"
        );
        assert_eq!(
            svc.evictions(),
            evictions_before + 7,
            "evictions counter must record exactly the dropped count \
             so operator dashboards can correlate the drop to the reload"
        );

        // Subsequent evaluations must NOT repopulate the
        // cache (the producer-side guard in `finalise`
        // still short-circuits under the new policy).
        for i in 0..3 {
            let flow = format!("flow-postcleartest-{i}");
            let _ = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW + 100));
        }
        assert_eq!(
            svc.sticky.lock().len(),
            0,
            "cache must stay empty after the reload to zero-window: \
             `finalise`'s sticky_window_ms > 0 guard still gates all inserts"
        );
    }

    /// Reloading to a policy that keeps stickiness
    /// *enabled* (even with a different non-zero window)
    /// must leave the cache intact. This is the negative
    /// companion to `reload_to_zero_sticky_window_clears_cache_*`
    /// — we don't want the clear-on-disable code path
    /// to over-trigger and wipe the cache on any window
    /// change. Together with
    /// `sticky_pin_survives_in_place_policy_reload`
    /// (which asserts pin honour across reload) this
    /// pins down the full reload-policy×sticky-state
    /// matrix.
    #[test]
    fn reload_with_nonzero_sticky_window_preserves_cache_and_evictions() {
        let (svc, _rx) = build(
            SdwanPolicy {
                sticky_window_ms: 60_000,
                ..SdwanPolicy::default()
            },
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW))],
        );

        // Populate the cache.
        for i in 0..5 {
            let flow = format!("flow-preserved-{i}");
            let _ = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW));
        }
        assert_eq!(svc.sticky.lock().len(), 5);
        let evictions_before = svc.evictions();

        // Reload to a shorter (but still non-zero) window.
        // The clear-on-disable path must NOT fire here:
        // existing pins continue to honour their original
        // absolute `pinned_until_ms` wall-clock expiry.
        svc.reload_policy(SdwanPolicy {
            sticky_window_ms: 30_000,
            ..SdwanPolicy::default()
        })
        .expect("reload to shorter-but-nonzero-window policy must succeed");

        assert_eq!(
            svc.sticky.lock().len(),
            5,
            "reload to a non-zero window must not drop existing entries"
        );
        assert_eq!(
            svc.evictions(),
            evictions_before,
            "evictions counter must not move on a non-zero-window reload"
        );

        // And the entries must still actually serve
        // sticky-pin lookups under the new policy.
        let d = svc.evaluate(&req(
            "flow-preserved-0",
            TrafficClass::Interactive,
            NOW + 1_000,
        ));
        assert_eq!(d.reason, SteeringReason::StickyPinned);
    }

    /// Idempotency check: a reload to `sticky_window_ms ==
    /// 0` when the cache is already empty (e.g. because
    /// the previous policy was also zero-window) must
    /// succeed without touching the evictions counter.
    /// Without the `dropped > 0` guard inside
    /// `reload_policy`, the counter would still record a
    /// `fetch_add(0)` — harmless functionally, but the
    /// explicit zero-skip is documented behaviour and
    /// worth pinning down.
    #[test]
    fn reload_to_zero_sticky_window_on_empty_cache_is_a_no_op() {
        let (svc, _rx) = build(
            SdwanPolicy {
                sticky_window_ms: 0,
                ..SdwanPolicy::default()
            },
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW))],
        );

        assert_eq!(svc.sticky.lock().len(), 0);
        let evictions_before = svc.evictions();

        svc.reload_policy(SdwanPolicy {
            sticky_window_ms: 0,
            ..SdwanPolicy::default()
        })
        .expect("idempotent zero-window reload must succeed");

        assert_eq!(svc.sticky.lock().len(), 0);
        assert_eq!(
            svc.evictions(),
            evictions_before,
            "no entries dropped means evictions must not move"
        );
    }

    #[test]
    fn repinning_existing_flow_at_capacity_does_not_evict_others() {
        // Regression test for BUG_0001: under sustained
        // sticky-pinned load with the cache at capacity,
        // re-pinning an *already-cached* flow_key must
        // NOT trigger the eviction sweep — a HashMap
        // insert on an existing key is an overwrite, not
        // a growth. The bug was that `sticky_insert`
        // checked `g.len() >= capacity` unconditionally,
        // so every re-pin would needlessly evict a
        // different flow's pin, defeating the sticky-pin
        // contract for the evicted flow on its next
        // evaluation.
        let (tx, _rx) = telemetry();
        let svc = SdwanServiceBuilder::new()
            .with_config(SdwanServiceConfig {
                sticky_cache_capacity: 4,
                ..SdwanServiceConfig::default()
            })
            .with_policy(Arc::new(
                SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap(),
            ))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths([Path::new(
                "mpls",
                [TrafficClass::Interactive],
            )])))
            .with_probe_provider(Arc::new(StaticProbeProvider::from_probes([(
                PathId::new("mpls"),
                PathProbe::new(10.0, 0.0, 0.0, NOW),
            )])))
            .build(tx);

        // Fill cache to capacity with 4 distinct flows.
        for i in 0..4 {
            let flow = format!("flow-{i}");
            let _ = svc.evaluate(&req(&flow, TrafficClass::Interactive, NOW));
        }
        assert_eq!(svc.sticky.lock().len(), 4);
        let evictions_before = svc.evictions();

        // Re-pin flow-0 (an existing key) at capacity.
        // The bug would trigger the sweep + arbitrary
        // eviction here, dropping one of flow-1/2/3.
        // The fix skips the sweep entirely because the
        // key already exists in the map.
        let _ = svc.evaluate(&req("flow-0", TrafficClass::Interactive, NOW + 100));
        assert_eq!(
            svc.sticky.lock().len(),
            4,
            "re-pinning an existing key must not change cache size"
        );
        for i in 0..4 {
            assert!(
                svc.sticky.lock().contains_key(&format!("flow-{i}")),
                "flow-{i} should still be in the cache after re-pinning flow-0"
            );
        }
        assert_eq!(
            svc.evictions(),
            evictions_before,
            "no eviction should have been recorded for an in-place re-pin at capacity"
        );

        // Re-pin flow-0 many more times; cache stays
        // intact, eviction count never grows.
        for _ in 0..100 {
            let _ = svc.evaluate(&req("flow-0", TrafficClass::Interactive, NOW + 200));
        }
        assert_eq!(svc.evictions(), evictions_before);
        assert_eq!(svc.sticky.lock().len(), 4);
    }

    #[test]
    fn nan_metric_path_loses_to_finite_path() {
        // Path with a NaN probe metric must never beat
        // a path with finite metrics — score_path
        // collapses NaN to +inf and the selector picks
        // the finite candidate.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![
                Path::new("nan-path", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ],
            vec![
                (
                    PathId::new("nan-path"),
                    PathProbe::new(f32::NAN, 0.0, 0.0, NOW),
                ),
                (PathId::new("inet"), PathProbe::new(50.0, 1.0, 1.0, NOW)),
            ],
        );
        let d = svc.evaluate(&req("flow-nan", TrafficClass::Interactive, NOW));
        assert_eq!(d.path_id, Some(PathId::new("inet")));
        assert_eq!(d.reason, SteeringReason::Best);
    }

    #[test]
    fn emits_raw_probe_metrics_not_score_components() {
        // Heavily-weighted policy so the score components
        // would visibly diverge from the raw probe
        // values. Verify the emitted event carries the
        // raw values from the probe (matching the
        // SdwanEvent wire schema), not the weighted
        // components from the score breakdown.
        let policy = SdwanPolicy {
            weights: ScoreWeights {
                latency: 100.0,
                loss: 10.0,
                jitter: 50.0,
            },
            ..SdwanPolicy::default()
        };
        let (tx, mut rx) = mpsc::channel(4);
        let svc = SdwanServiceBuilder::new()
            .with_policy(Arc::new(SdwanPolicyHolder::try_new(policy).unwrap()))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths([Path::new(
                "mpls",
                [TrafficClass::Interactive],
            )])))
            .with_probe_provider(Arc::new(StaticProbeProvider::from_probes([(
                PathId::new("mpls"),
                PathProbe::new(12.0, 0.5, 2.5, NOW),
            )])))
            .build(tx);
        let _ = svc.evaluate(&req("flow-emit", TrafficClass::Interactive, NOW));
        let ev = rx.try_recv().expect("telemetry event");
        let TelemetryEvent::Sdwan(ev) = ev else {
            panic!("expected Sdwan event, got {ev:?}")
        };
        // Raw probe metrics — NOT weighted score
        // components.
        assert_eq!(ev.path_id, "mpls");
        assert_eq!(ev.latency_ms, 12.0);
        assert_eq!(ev.loss_pct, 0.5);
        assert_eq!(ev.jitter_ms, 2.5);
        // Total score is still the weighted composite
        // (the wire schema's `sc` field).
        assert_eq!(ev.score, 100.0 * 12.0 + 10.0 * 0.5 + 50.0 * 2.5);
        assert_eq!(ev.steering_decision, "best");
    }

    #[test]
    fn no_path_decision_emits_empty_path_id() {
        let (tx, mut rx) = mpsc::channel(4);
        let svc = SdwanServiceBuilder::new().build(tx);
        let _ = svc.evaluate(&req("flow-nop", TrafficClass::Bulk, NOW));
        let TelemetryEvent::Sdwan(ev) = rx.try_recv().expect("event") else {
            panic!("expected Sdwan event")
        };
        assert_eq!(ev.path_id, "");
        assert_eq!(ev.latency_ms, 0.0);
        assert_eq!(ev.loss_pct, 0.0);
        assert_eq!(ev.jitter_ms, 0.0);
        assert_eq!(ev.score, 0.0);
        assert_eq!(ev.steering_decision, "no_available_path");
    }

    #[test]
    fn telemetry_dropped_when_channel_full() {
        // Channel of size 1; pre-fill it so try_send
        // saturates; verify the evaluation still
        // succeeds and bumps the drop counter.
        let (tx, rx) = mpsc::channel(1);
        // Pre-fill with one event.
        tx.try_send(TelemetryEvent::Sdwan(SdwanEvent {
            path_id: String::new(),
            latency_ms: 0.0,
            loss_pct: 0.0,
            jitter_ms: 0.0,
            score: 0.0,
            steering_decision: "test".into(),
        }))
        .unwrap();

        let svc = SdwanServiceBuilder::new()
            .with_path_provider(Arc::new(StaticPathProvider::from_paths([Path::new(
                "mpls",
                [TrafficClass::Interactive],
            )])))
            .with_probe_provider(Arc::new(StaticProbeProvider::from_probes([(
                PathId::new("mpls"),
                PathProbe::new(10.0, 0.0, 0.0, NOW),
            )])))
            .build(tx);

        let _ = svc.evaluate(&req("flow-drop", TrafficClass::Interactive, NOW));
        let stats = svc.stats().snapshot();
        assert_eq!(stats.telemetry_drops, 1);
        // Decision counters still bumped — telemetry
        // saturation must never affect the verdict.
        assert_eq!(stats.requests_evaluated, 1);
        assert!(stats.invariant_holds());
        drop(rx);
    }

    #[test]
    fn reload_policy_rejects_invalid_and_preserves_previous() {
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![Path::new("mpls", [TrafficClass::Bulk])],
            vec![(PathId::new("mpls"), PathProbe::new(5.0, 0.0, 0.0, NOW))],
        );
        let before = svc.policy().snapshot();
        let bad = SdwanPolicy {
            probe_max_age_ms: 0,
            ..SdwanPolicy::default()
        };
        let err = svc.reload_policy(bad).unwrap_err();
        assert!(matches!(err, SdwanError::InvalidPolicy(_)));
        let after = svc.policy().snapshot();
        assert!(Arc::ptr_eq(&before, &after));
        let stats = svc.stats().snapshot();
        assert_eq!(stats.bundle_load_failures, 1);
        assert_eq!(stats.bundle_loads, 0);
    }

    #[test]
    fn reload_policy_installs_valid_candidate() {
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![Path::new("mpls", [TrafficClass::Bulk])],
            vec![(PathId::new("mpls"), PathProbe::new(5.0, 0.0, 0.0, NOW))],
        );
        let new = SdwanPolicy {
            probe_max_age_ms: 1_234,
            ..SdwanPolicy::default()
        };
        svc.reload_policy(new).unwrap();
        let after = svc.policy().snapshot();
        assert_eq!(after.probe_max_age_ms, 1_234);
        let stats = svc.stats().snapshot();
        assert_eq!(stats.bundle_loads, 1);
        assert_eq!(stats.bundle_load_failures, 0);
    }

    #[test]
    fn decision_to_verdict_allow_on_selected_deny_otherwise() {
        let sel = SteeringDecision::selected(
            PathId::new("mpls"),
            SteeringReason::Best,
            ScoreBreakdown::new(1.0, 0.0, 0.0, 0.0, 1.0),
            TrafficClass::Interactive,
        );
        assert_eq!(decision_to_verdict(&sel), Verdict::Allow);

        let denied =
            SteeringDecision::no_path(SteeringReason::AllProbesStale, TrafficClass::Interactive);
        assert_eq!(decision_to_verdict(&denied), Verdict::Deny);
    }

    #[test]
    fn service_config_normalize_clamps_zero_capacity_to_one() {
        // `sticky_cache_capacity = 0` would let the
        // `g.len() >= capacity` sweep fire on every
        // insert and produce 0↔1 oscillation. Normalize
        // clamps it to 1 so a misconfigured deployment
        // doesn't silently churn the cache.
        let cfg = SdwanServiceConfig {
            max_flows: 16,
            sticky_cache_capacity: 0,
        }
        .normalize();
        assert_eq!(cfg.sticky_cache_capacity, 1);
        // Idempotent: calling normalize a second time
        // doesn't move the value any further.
        let cfg = cfg.normalize();
        assert_eq!(cfg.sticky_cache_capacity, 1);
    }

    #[test]
    fn service_config_normalize_preserves_nonzero_capacity() {
        let cfg = SdwanServiceConfig {
            max_flows: 16,
            sticky_cache_capacity: 7,
        }
        .normalize();
        assert_eq!(cfg.sticky_cache_capacity, 7);
    }

    #[test]
    fn builder_with_config_zero_capacity_does_not_oscillate() {
        // Regression: prior to `SdwanServiceConfig::normalize`
        // a deployment that set `sticky_cache_capacity = 0`
        // would have the sticky cache oscillate between
        // 0 and 1 entries on every insert (sweep fires
        // unconditionally because `len() >= 0`). After
        // normalize, the cache holds at least one entry.
        let (svc, _rx) = {
            let policy = SdwanPolicy {
                sticky_window_ms: 10_000,
                ..SdwanPolicy::default()
            };
            let holder = SdwanPolicyHolder::default();
            holder.try_replace(policy).expect("valid policy");
            let paths = StaticPathProvider::from_paths(vec![Path::new(
                "mpls",
                [TrafficClass::Interactive],
            )]);
            let probes = StaticProbeProvider::from_probes(vec![(
                PathId::new("mpls"),
                PathProbe::new(10.0, 0.0, 0.0, NOW),
            )]);
            let (tx, rx) = telemetry();
            let svc = SdwanServiceBuilder::new()
                .with_config(SdwanServiceConfig {
                    max_flows: 16,
                    // Operator-typo'd value that previously
                    // produced oscillation.
                    sticky_cache_capacity: 0,
                })
                .with_policy(Arc::new(holder))
                .with_path_provider(Arc::new(paths))
                .with_probe_provider(Arc::new(probes))
                .build(tx);
            (svc, rx)
        };
        // Two distinct flows pin in the same window.
        let _ = svc.evaluate(&req("flow-a", TrafficClass::Interactive, NOW));
        let _ = svc.evaluate(&req("flow-b", TrafficClass::Interactive, NOW + 1));
        // With capacity clamped to 1, the second insert
        // evicts the first (LRU-style eviction sweep) —
        // but the cache still holds 1 entry, NOT 0.
        // Re-evaluating the same flow within the sticky
        // window observes the pin (cache wasn't wiped).
        let dec_b2 = svc.evaluate(&req("flow-b", TrafficClass::Interactive, NOW + 2));
        assert_eq!(
            dec_b2.path_id.as_ref().map(PathId::as_str),
            Some("mpls"),
            "with normalised capacity the sticky cache stays live"
        );
    }

    #[test]
    fn evictions_counter_bumps_on_expired_lookup() {
        // Insert a sticky entry that's already expired,
        // then lookup at a `now_ms` past the expiry.
        // The lookup should evict it and bump the
        // counter.
        let (svc, _rx) = build(
            SdwanPolicy {
                sticky_window_ms: 100,
                ..SdwanPolicy::default()
            },
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW))],
        );
        // First eval pins for 100ms.
        let _ = svc.evaluate(&req("flow-e", TrafficClass::Interactive, NOW));
        assert_eq!(svc.evictions(), 0);
        // Re-eval well past the sticky window — the
        // sticky_lookup should evict.
        let _ = svc.evaluate(&req("flow-e", TrafficClass::Interactive, NOW + 1_000));
        assert!(svc.evictions() >= 1);
    }

    #[test]
    fn nan_metric_sole_candidate_falls_through_to_all_probes_stale() {
        // A path whose probe carries a NaN metric must
        // NOT be selected as a `FallbackBelowFloor`
        // winner, even if it is the only candidate.
        // The selector treats unusable probes (non-finite
        // metrics) identically to stale ones, so the
        // outcome is `AllProbesStale` — fail-closed
        // rather than emitting a `+INFINITY` score on the
        // wire event. See `probe_is_usable` and the
        // doc on `SteeringReason::AllProbesStale`.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![Path::new("mpls", [TrafficClass::Interactive])],
            vec![(PathId::new("mpls"), PathProbe::new(f32::NAN, 0.0, 0.0, NOW))],
        );
        let d = svc.evaluate(&req("flow-nan", TrafficClass::Interactive, NOW));
        assert_eq!(d.path_id, None);
        assert_eq!(d.reason, SteeringReason::AllProbesStale);
        assert!(d.score.is_none());
    }

    #[test]
    fn nan_metric_candidate_loses_to_finite_candidate() {
        // When a NaN-metric path coexists with a healthy
        // finite-metric path, the healthy one wins
        // outright — the NaN candidate is filtered before
        // scoring rather than competing on a `worst()`
        // collapsed score.
        let (svc, _rx) = build(
            SdwanPolicy::default(),
            vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ],
            vec![
                (PathId::new("mpls"), PathProbe::new(f32::NAN, 0.0, 0.0, NOW)),
                (PathId::new("inet"), PathProbe::new(20.0, 0.1, 0.5, NOW)),
            ],
        );
        let d = svc.evaluate(&req("flow-mixed", TrafficClass::Interactive, NOW));
        assert_eq!(d.path_id, Some(PathId::new("inet")));
        assert_eq!(d.reason, SteeringReason::Best);
        // Score is finite — proves the NaN candidate did
        // not leak through scoring.
        let score = d.score.expect("inet path selected → score present");
        assert!(score.total.is_finite());
    }

    #[test]
    fn sticky_pin_drops_when_pinned_path_probe_turns_infinite() {
        // Regression test: the sticky-pin path was
        // missing the `probe_is_usable` guard that the
        // main scoring loop applies, so a misbehaving
        // adapter that minted an `INFINITY`-metric probe
        // on a sticky-pinned path would keep the flow
        // pinned and emit an `INFINITY`-total
        // `SdwanEvent` on the wire (the floor checks let
        // INFINITY through when `max_*` is `None` because
        // `Option::is_none_or` returns true without
        // calling the closure on the None case).
        //
        // The correct behavior is to drop the sticky pin
        // when the pinned probe becomes non-finite, fall
        // through to the main scoring loop, and select
        // whichever candidate still has a usable probe.
        //
        // Scenario:
        // 1. First eval pins `mpls` (better than `inet`).
        // 2. The `mpls` probe is mutated to carry an
        //    INFINITY latency — but loss/jitter stay
        //    zero and no floor is configured, so the
        //    floor checks alone would NOT reject it.
        // 3. Second eval, well within the sticky window,
        //    must drop the sticky pin (because the pinned
        //    probe is now unusable), re-score, and pick
        //    `inet` with reason `Best`. The wire score
        //    must be finite — proving INFINITY did not
        //    leak through.
        let probes = Arc::new(MutableProbeProvider::from_probes([
            (PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
            (PathId::new("inet"), PathProbe::new(50.0, 0.0, 0.0, NOW)),
        ]));
        let (tx, _rx) = telemetry();
        let svc = SdwanServiceBuilder::new()
            .with_policy(Arc::new(
                SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap(),
            ))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths(vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ])))
            .with_probe_provider(Arc::clone(&probes) as Arc<dyn ProbeProvider>)
            .build(tx);

        // Pin `mpls`.
        let d1 = svc.evaluate(&req("flow-inf", TrafficClass::Interactive, NOW));
        assert_eq!(d1.path_id, Some(PathId::new("mpls")));
        assert_eq!(d1.reason, SteeringReason::Best);

        // Mutate `mpls` to INFINITY latency. The default
        // policy has `max_latency_ms: None` so the
        // latency floor check alone would NOT reject it
        // (this is the exact gap the fix closes).
        probes.set(
            PathId::new("mpls"),
            PathProbe::new(f32::INFINITY, 0.0, 0.0, NOW + 1_000),
        );

        let d2 = svc.evaluate(&req("flow-inf", TrafficClass::Interactive, NOW + 1_000));
        // The sticky pin was dropped; the selector
        // re-scored and `inet` is now the only candidate
        // with a usable probe.
        assert_eq!(d2.path_id, Some(PathId::new("inet")));
        assert_eq!(d2.reason, SteeringReason::Best);
        let score = d2.score.expect("inet selected → score present");
        assert!(
            score.total.is_finite(),
            "sticky path must NOT leak INFINITY into the wire score; got {}",
            score.total
        );
    }

    #[test]
    fn sticky_pin_drops_when_pinned_path_probe_turns_nan() {
        // Symmetric companion to
        // `sticky_pin_drops_when_pinned_path_probe_turns_infinite`.
        // The floor checks DO reject NaN early (via each
        // floor's explicit `is_nan()` early-return), so
        // before the fix this case was already covered
        // by the floor checks alone — but the
        // `probe_is_usable` guard now provides the
        // primary defense, and this test pins the
        // contract so a future refactor that loosens
        // the floor's NaN handling (e.g. moving NaN
        // handling out of the floor functions into a
        // dedicated `validate` step) does not silently
        // regress the sticky path.
        let probes = Arc::new(MutableProbeProvider::from_probes([
            (PathId::new("mpls"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
            (PathId::new("inet"), PathProbe::new(50.0, 0.0, 0.0, NOW)),
        ]));
        let (tx, _rx) = telemetry();
        let svc = SdwanServiceBuilder::new()
            .with_policy(Arc::new(
                SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap(),
            ))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths(vec![
                Path::new("mpls", [TrafficClass::Interactive]),
                Path::new("inet", [TrafficClass::Interactive]),
            ])))
            .with_probe_provider(Arc::clone(&probes) as Arc<dyn ProbeProvider>)
            .build(tx);

        let d1 = svc.evaluate(&req("flow-nan-sticky", TrafficClass::Interactive, NOW));
        assert_eq!(d1.path_id, Some(PathId::new("mpls")));

        probes.set(
            PathId::new("mpls"),
            PathProbe::new(f32::NAN, 0.0, 0.0, NOW + 1_000),
        );

        let d2 = svc.evaluate(&req(
            "flow-nan-sticky",
            TrafficClass::Interactive,
            NOW + 1_000,
        ));
        assert_eq!(d2.path_id, Some(PathId::new("inet")));
        assert_eq!(d2.reason, SteeringReason::Best);
        let score = d2.score.expect("inet selected → score present");
        assert!(score.total.is_finite());
    }

    #[test]
    fn equal_scored_paths_break_ties_deterministically_by_path_id() {
        // Two paths with identical probes produce
        // identical scores. The selector must
        // deterministically prefer the lex-smaller
        // `PathId` ("alpha" < "beta") so dashboards and
        // regression tests don't see HashMap iteration
        // order leak into the decision.
        //
        // Re-running the same evaluation many times must
        // ALWAYS pick the same winner — there is no
        // sticky-pin protection here because each
        // iteration uses a fresh service (no carry-over
        // between calls).
        for _ in 0..32 {
            let (svc, _rx) = build(
                SdwanPolicy::default(),
                vec![
                    Path::new("beta", [TrafficClass::Interactive]),
                    Path::new("alpha", [TrafficClass::Interactive]),
                ],
                vec![
                    (PathId::new("beta"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
                    (PathId::new("alpha"), PathProbe::new(10.0, 0.0, 0.0, NOW)),
                ],
            );
            let d = svc.evaluate(&req("flow-tied", TrafficClass::Interactive, NOW));
            assert_eq!(d.path_id, Some(PathId::new("alpha")));
            assert_eq!(d.reason, SteeringReason::Best);
        }
    }

    /// Test-only probe provider whose backing map is
    /// behind a [`parking_lot::Mutex`]. Lets a single
    /// test mutate the probe table between `evaluate`
    /// calls — required for tests that need to observe
    /// the *service's* sticky cache (which lives on the
    /// service) across an underlying probe change.
    /// Production calls always use
    /// [`crate::probe::StaticProbeProvider`].
    #[derive(Debug, Default)]
    struct MutableProbeProvider {
        by_id: Mutex<HashMap<PathId, PathProbe>>,
    }

    impl MutableProbeProvider {
        fn from_probes<I>(probes: I) -> Self
        where
            I: IntoIterator<Item = (PathId, PathProbe)>,
        {
            let mut map = HashMap::new();
            for (id, probe) in probes {
                map.insert(id, probe);
            }
            Self {
                by_id: Mutex::new(map),
            }
        }

        fn set(&self, id: PathId, probe: PathProbe) {
            self.by_id.lock().insert(id, probe);
        }
    }

    impl ProbeProvider for MutableProbeProvider {
        fn get(&self, path_id: &PathId) -> Option<PathProbe> {
            self.by_id.lock().get(path_id).copied()
        }
    }

    // --- Optional competitive-depth component wiring ------

    use crate::app_steering::{AppSteeringRule, AppSteeringTable};
    use crate::cellular::CellularBudget;
    use crate::failover::{FailbackMode, FailoverEngine, FailoverPolicy};
    use crate::sla::{SlaClass, SlaMonitor, SlaPolicy, SlaPolicySet, SlaWatch};

    #[test]
    fn builder_wires_optional_components_and_core_still_evaluates() {
        let (tx, _rx) = telemetry();
        let probes: Arc<dyn ProbeProvider> = Arc::new(StaticProbeProvider::from_probes([(
            PathId::new("mpls"),
            PathProbe::new(5.0, 0.0, 1.0, NOW),
        )]));
        let stats = Arc::new(SdwanStats::default());
        let monitor = Arc::new(SlaMonitor::new(
            SlaPolicySet::default_templates(),
            probes.clone(),
            vec![SlaWatch::new("mpls", SlaClass::BusinessCritical)],
            tx.clone(),
            stats.clone(),
        ));
        let failover = Arc::new(
            FailoverEngine::new(FailoverPolicy::new(
                PathId::new("mpls"),
                [PathId::new("inet")],
            ))
            .unwrap(),
        );
        let app_steering = Arc::new(AppSteeringTable::from_rules([AppSteeringRule::new(
            "zoom",
            [PathId::new("inet")],
            SlaClass::RealTime,
        )]));
        let cellular = Arc::new(CellularBudget::metered(1_000));

        let svc = SdwanServiceBuilder::new()
            .with_policy(Arc::new(
                SdwanPolicyHolder::try_new(SdwanPolicy::default()).unwrap(),
            ))
            .with_path_provider(Arc::new(StaticPathProvider::from_paths(vec![Path::new(
                "mpls",
                [TrafficClass::Interactive],
            )])))
            .with_probe_provider(probes)
            .with_stats(stats)
            .with_sla_monitor(monitor)
            .with_failover(failover)
            .with_app_steering(app_steering)
            .with_cellular_budget(cellular)
            .build(tx);

        assert!(svc.sla_monitor().is_some());
        assert!(svc.failover().is_some());
        assert!(svc.app_steering().is_some());
        assert!(svc.cellular_budget().is_some());

        // Core selection is unchanged by the optional wiring.
        let decision = svc.evaluate(&req("f1", TrafficClass::Interactive, NOW));
        assert_eq!(decision.reason, SteeringReason::Best);
        assert_eq!(decision.path_id, Some(PathId::new("mpls")));
    }

    #[test]
    fn sla_violation_bridges_to_failover_switch() {
        // End-to-end: a sustained SLA breach on the primary,
        // detected by the monitor, drives the failover engine
        // to switch the active path to the backup.
        let (tx, _rx) = telemetry();
        let probes: Arc<dyn ProbeProvider> = Arc::new(StaticProbeProvider::from_probes([
            // Primary breaches the business-critical latency
            // SLA (50 ms); backup is healthy.
            (PathId::new("mpls"), PathProbe::new(120.0, 0.0, 1.0, NOW)),
            (PathId::new("inet"), PathProbe::new(20.0, 0.0, 1.0, NOW)),
        ]));
        let stats = Arc::new(SdwanStats::default());
        let monitor = SlaMonitor::new(
            SlaPolicySet::from_policies([(
                SlaClass::BusinessCritical,
                SlaPolicy {
                    max_latency_ms: Some(50.0),
                    consecutive_breaches: 1,
                    ..SlaPolicy::default()
                },
            )]),
            probes,
            vec![SlaWatch::new("mpls", SlaClass::BusinessCritical)],
            tx,
            stats,
        );
        let failover = FailoverEngine::new(
            FailoverPolicy::new(PathId::new("mpls"), [PathId::new("inet")])
                .with_failback(FailbackMode::Immediate),
        )
        .unwrap();

        assert_eq!(failover.active(), PathId::new("mpls"));

        // One tick detects the breach; bridge each emitted
        // violation into the failover engine.
        for violation in monitor.tick(NOW) {
            failover.on_violation(&violation.path_id, violation.observed_at_ms);
        }

        assert_eq!(failover.active(), PathId::new("inet"));
        assert_eq!(failover.switches(), 1);
    }
}

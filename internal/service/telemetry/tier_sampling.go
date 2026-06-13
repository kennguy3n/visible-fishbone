// Package telemetry — tier_sampling.go layers an activity-tier-aware
// policy on top of the deterministic AdaptiveSampler (sampling.go).
//
// WS-4 problem (docs/scaling.md §3.3): clickhouse_rows_written is the
// single largest cost meter at fleet scale (~26,500 rows/s at 5000
// tenants). The autotuner (autotune.go) tunes batch size globally and
// the adaptive sampler / row limiter cap a *noisy* tenant, but nothing
// reduces what a DORMANT trial writes — a tenant with little/no traffic
// should write near-zero telemetry rows beyond security-relevant events.
//
// This file adds a per-tenant policy keyed on the tenancy.Classifier's
// activity tier:
//
//   - TierActive  : full fidelity. The sampler's existing behaviour is
//     unchanged (multiplier 1.0); security-relevant events are pinned.
//   - TierIdle    : reduced sampling. The base keep probability is
//     scaled by IdleMultiplier (deterministic, de-bias-exact).
//   - TierDormant : security-events-only. Every non-security,
//     non-compliance event is dropped; IPS / ZTNA / DLP events and the
//     inspect_full compliance record are still kept at 1:1.
//
// It composes with — and never fights — the autotuner: the policy only
// shrinks the per-event keep set, lowering the row rate the autotuner
// observes, which is a one-sided change (fewer inserts, never more), so
// there is no oscillation. The tier signal itself is resolved from a
// cheap in-memory snapshot (MapTierResolver) refreshed out-of-band by
// TierRefresher, so the consumer hot path does no I/O.
//
// SAFETY INVARIANTS (never violated, in any tier):
//
//   - Security-relevant events (EventClassIPS / EventClassZTNA /
//     EventClassDLP) are always kept at rate 1.0. This is a conservative
//     superset of "IPS / ZTNA-deny / DLP-violation": the predicate works
//     off the envelope's EventClass alone, so the hot path never decodes
//     a payload to find a verdict, and a class that *might* carry a deny
//     is preserved whole.
//   - The inspect_full compliance floor (mandatorySampleRateFloor) holds
//     in every tier, so a dormant tenant's legally-required audit record
//     is never shed.
//   - An unknown tenant (not yet in the resolver snapshot) fails safe to
//     TierActive — full fidelity — so a classification gap does MORE
//     work, never less. This mirrors tenancy.Classifier's own fail-safe.
package telemetry

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// DefaultIdleSampleMultiplier scales the base keep probability for an
// idle-tier tenant. 0.25 keeps a quarter of what the same event would
// keep on an active tenant (de-biased exactly by 1/rate), so an idle
// trial's telemetry cost drops ~4× while every dimension stays
// represented. Conservative on purpose: idle tenants are reachable
// again (a user logging back in flips them active within one refresh
// window), so we reduce rather than collapse their fidelity.
const DefaultIdleSampleMultiplier = 0.25

// DefaultDormantSampleMultiplier scales the base keep probability for a
// dormant-tier tenant. 0 means "security-events-only": every event that
// is neither security-relevant nor compliance-floored is dropped, so a
// dormant trial's steady-state row rate collapses to its (near-zero)
// security stream. The safety invariants above keep IPS/ZTNA/DLP and
// inspect_full at 1:1 regardless of this value.
const DefaultDormantSampleMultiplier = 0.0

// DefaultTierRefreshInterval bounds how stale a tenant's tier signal can
// be on the hot path. The activity recorder updates last_active_at on
// the data-plane touch, so a waking dormant tenant is re-classified
// active within one interval. 60s keeps the staleness window small
// while loading the (id, last_active_at) projection — one indexed scan
// (repository.TenantRepository.ListTenantActivity) — at most once a
// minute per replica.
const DefaultTierRefreshInterval = 60 * time.Second

// isSecurityRelevantEventClass reports whether an event class must never
// be sampled away on cost grounds. It is the conservative WS-4 security
// predicate: IPS detections, ZTNA access decisions (which carry the
// deny verdicts), and endpoint DLP signals are all preserved whole, off
// the envelope's EventClass alone so the hot path never decodes a
// payload to inspect a verdict. Every other class is eligible for
// tier-based shedding.
func isSecurityRelevantEventClass(c schema.EventClass) bool {
	switch c {
	case schema.EventClassIPS, schema.EventClassZTNA, schema.EventClassDLP:
		return true
	default:
		return false
	}
}

// TierResolver supplies a tenant's current activity tier on the consumer
// hot path. It is the seam between the data-plane sampler and the
// control-plane activity projection.
//
// HOT-PATH CONTRACT: ResolveTier is called once per event, so it MUST be
// cheap, non-blocking, and in-memory — never a synchronous DB/RPC call.
// The shipped MapTierResolver is a single atomic snapshot read.
//
// ResolveTier returns (tier, true) when the tenant is known and
// (TierActive, false) when it is not; the policy treats "unknown" as a
// fail-safe to full fidelity, so a resolver need not synthesise a tier
// for a tenant it has never seen.
type TierResolver interface {
	ResolveTier(ctx context.Context, tenantID uuid.UUID) (tenancy.Tier, bool)
}

// MapTierResolver is the production TierResolver: a copy-on-write
// snapshot of tenant → tier, swapped atomically by TierRefresher each
// cycle. Reads are lock-free (one atomic load + one map read), so the
// hot path pays no contention even while a refresh is in flight. A nil
// *MapTierResolver is a valid resolver that knows no tenants (every
// lookup misses → fail-safe active), so wiring it is optional.
type MapTierResolver struct {
	snap atomic.Pointer[map[uuid.UUID]tenancy.Tier]
}

// NewMapTierResolver constructs a resolver seeded with an initial
// tenant→tier map (may be nil/empty). The map is copied defensively so
// the caller may retain and mutate the argument.
func NewMapTierResolver(initial map[uuid.UUID]tenancy.Tier) *MapTierResolver {
	r := &MapTierResolver{}
	next := copyTierMap(initial)
	r.snap.Store(&next)
	return r
}

// Replace atomically swaps the resolver's entire tenant→tier snapshot.
// TierRefresher calls it once per cycle with the freshly classified
// fleet. The map is copied defensively, so the caller may reuse its
// argument. A nil receiver is a no-op (an unwired resolver).
func (r *MapTierResolver) Replace(next map[uuid.UUID]tenancy.Tier) {
	if r == nil {
		return
	}
	copied := copyTierMap(next)
	r.snap.Store(&copied)
}

// ResolveTier implements TierResolver with a single atomic load and one
// map read. A nil receiver, an empty snapshot, or an unknown tenant all
// report (TierActive, false) — the fail-safe the policy relies on.
func (r *MapTierResolver) ResolveTier(_ context.Context, tenantID uuid.UUID) (tenancy.Tier, bool) {
	if r == nil {
		return tenancy.TierActive, false
	}
	m := r.snap.Load()
	if m == nil {
		return tenancy.TierActive, false
	}
	t, ok := (*m)[tenantID]
	if !ok {
		return tenancy.TierActive, false
	}
	return t, true
}

// Len reports the number of tenants in the current snapshot. For
// metrics / tests; not on the hot path.
func (r *MapTierResolver) Len() int {
	if r == nil {
		return 0
	}
	m := r.snap.Load()
	if m == nil {
		return 0
	}
	return len(*m)
}

func copyTierMap(m map[uuid.UUID]tenancy.Tier) map[uuid.UUID]tenancy.Tier {
	out := make(map[uuid.UUID]tenancy.Tier, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TierSamplingConfig configures a TierSamplingPolicy.
type TierSamplingConfig struct {
	// Resolver supplies each tenant's activity tier. Required: a nil
	// resolver yields a policy that classifies every tenant as active
	// (full fidelity), i.e. an effective no-op.
	Resolver TierResolver
	// IdleMultiplier scales the base keep probability for idle-tier
	// tenants. <= 0 uses DefaultIdleSampleMultiplier; values are
	// clamped to (0,1]. (A zero idle multiplier would make idle behave
	// like dormant, which the dormant tier already expresses, so it is
	// treated as "unset" rather than "drop everything".)
	IdleMultiplier float64
	// DormantMultiplier scales the base keep probability for
	// dormant-tier tenants. Defaults to DefaultDormantSampleMultiplier
	// (0 — security-events-only). Clamped to [0,1]; the security and
	// compliance floors apply on top regardless.
	DormantMultiplier float64
}

// TierSamplingPolicy holds the per-tier keep multipliers and the tier
// resolver. It carries no mutable state, so it is safe to share across
// partition samplers. A nil *TierSamplingPolicy is a valid no-op: the
// sampler behaves exactly as it did before WS-4 (DecideClass path), so
// the feature is fully default-OFF when no policy is wired.
type TierSamplingPolicy struct {
	resolver   TierResolver
	idleMult   float64
	dormantMlt float64
}

// NewTierSamplingPolicy constructs a policy from cfg, applying the
// package defaults for any unset multiplier.
func NewTierSamplingPolicy(cfg TierSamplingConfig) *TierSamplingPolicy {
	idle := cfg.IdleMultiplier
	if idle <= 0 {
		idle = DefaultIdleSampleMultiplier
	}
	if idle > 1 {
		idle = 1
	}
	dormant := cfg.DormantMultiplier
	if dormant < 0 {
		dormant = 0
	}
	if dormant > 1 {
		dormant = 1
	}
	return &TierSamplingPolicy{
		resolver:   cfg.Resolver,
		idleMult:   idle,
		dormantMlt: dormant,
	}
}

// tierFor resolves a tenant's tier, failing safe to TierActive when the
// resolver is nil or the tenant is unknown (a classification gap does
// full-fidelity work, never less).
func (p *TierSamplingPolicy) tierFor(ctx context.Context, tenantID uuid.UUID) tenancy.Tier {
	if p == nil || p.resolver == nil {
		return tenancy.TierActive
	}
	t, ok := p.resolver.ResolveTier(ctx, tenantID)
	if !ok {
		return tenancy.TierActive
	}
	return t
}

// multiplier returns the keep-probability scale for a tier. Active is
// always 1.0 (no change); idle and dormant use the configured factors.
func (p *TierSamplingPolicy) multiplier(tier tenancy.Tier) float64 {
	switch tier {
	case tenancy.TierIdle:
		return p.idleMult
	case tenancy.TierDormant:
		return p.dormantMlt
	default:
		return 1.0
	}
}

// TenantActivityLister is the (id, last_active_at) projection the tier
// refresher classifies once per cycle. repository.TenantRepository
// satisfies it; it is the same cheap, indexed scan the sweep planner
// already reads, so the refresh adds no new query shape.
type TenantActivityLister interface {
	ListTenantActivity(ctx context.Context) ([]repository.TenantActivity, error)
}

// TierRefresher periodically rebuilds the MapTierResolver snapshot from
// the tenant activity projection, classifying each tenant with the
// tenancy.Classifier. It runs on every control-plane replica (the
// telemetry consumer is per-replica, not leader-only), so the hot path
// always has a local, bounded-staleness tier signal.
//
// The refresh is a single indexed scan plus an in-memory classification
// pass — no per-tenant fan-out — so it stays cheap even at 5000 tenants.
type TierRefresher struct {
	lister     TenantActivityLister
	classifier tenancy.Classifier
	resolver   *MapTierResolver
	interval   time.Duration
	now        func() time.Time
	logger     *slog.Logger
}

// TierRefresherConfig configures a TierRefresher.
type TierRefresherConfig struct {
	// Lister supplies the tenant activity projection. Required.
	Lister TenantActivityLister
	// Classifier buckets each tenant. Defaults to the tenancy package
	// defaults (IdleAfter 24h, DormantAfter 14d) when zero — the same
	// classifier the sweep planner uses, so tiers agree across the
	// control plane.
	Classifier tenancy.Classifier
	// Resolver is the snapshot the refresher swaps each cycle. Required.
	Resolver *MapTierResolver
	// Interval is the refresh cadence. Defaults to
	// DefaultTierRefreshInterval when <= 0.
	Interval time.Duration
	// NowFunc returns the current time. Injected for tests; production
	// passes time.Now.
	NowFunc func() time.Time
	// Logger receives refresh-failure warnings. Defaults to the slog
	// default logger when nil.
	Logger *slog.Logger
}

// NewTierRefresher constructs a refresher from cfg, applying defaults.
func NewTierRefresher(cfg TierRefresherConfig) *TierRefresher {
	classifier := cfg.Classifier
	if classifier.IdleAfter <= 0 || classifier.DormantAfter <= classifier.IdleAfter {
		classifier = tenancy.DefaultPlanner().Classifier
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultTierRefreshInterval
	}
	now := cfg.NowFunc
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &TierRefresher{
		lister:     cfg.Lister,
		classifier: classifier,
		resolver:   cfg.Resolver,
		interval:   interval,
		now:        now,
		logger:     logger,
	}
}

// Run refreshes the snapshot once immediately, then every Interval until
// ctx is cancelled. It is intended to run in its own goroutine. A failed
// refresh is logged and retried on the next tick — the previous snapshot
// stays in effect, so a transient projection failure never blanks the
// tier signal (which would fail-safe the whole fleet to active anyway).
func (r *TierRefresher) Run(ctx context.Context) {
	if r == nil || r.lister == nil || r.resolver == nil {
		return
	}
	if err := r.refresh(ctx); err != nil && ctx.Err() == nil {
		r.logger.Warn("telemetry: tier refresh failed", slog.Any("error", err))
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.refresh(ctx); err != nil && ctx.Err() == nil {
				r.logger.Warn("telemetry: tier refresh failed", slog.Any("error", err))
			}
		}
	}
}

// refresh loads the activity projection, classifies every tenant, and
// atomically swaps the resolver snapshot.
func (r *TierRefresher) refresh(ctx context.Context) error {
	acts, err := r.lister.ListTenantActivity(ctx)
	if err != nil {
		return err
	}
	now := r.now()
	next := make(map[uuid.UUID]tenancy.Tier, len(acts))
	for _, a := range acts {
		next[a.ID] = r.classifier.Classify(now, a.LastActiveAt)
	}
	r.resolver.Replace(next)
	return nil
}

// Package telemetry — sampling.go implements adaptive, deterministic
// per-tenant telemetry sampling. It sits in the consumer hot path
// between decode and the hot/cold writers and decides, per event,
// whether to keep (write) or drop the event so a high-volume tenant
// cannot swamp ClickHouse with low-information-density events.
//
// Why sampling in addition to the PerTenantLimiter (consumer.go):
//
//   - The PerTenantLimiter is *hard back-pressure*: it Naks
//     over-budget events so JetStream redelivers them later, and
//     eventually routes them to the DLQ once MaxDeliver is hit. That
//     protects the writers but it neither reduces the total work
//     (every event is still processed, just later) nor preserves a
//     statistically faithful picture — the events that lose the
//     redelivery race are dropped arbitrarily.
//   - Sampling is *load shedding with de-bias*: when a tenant's
//     arrival rate exceeds their tier budget, we deterministically
//     keep a representative fraction of events and drop the rest
//     immediately (Ack, never redeliver). The kept events carry the
//     keep probability so analytics can multiply aggregates by
//     1/SampleRate to recover the tenant's true volume. This cuts
//     ClickHouse write volume for the noisy tenant by 30-50%+ while
//     preserving visibility (every dimension is still represented in
//     proportion).
//
// Determinism is the load-bearing property. The keep/drop decision
// for an event is a pure function of (EventID, keep probability):
//
//	keep  <=>  hashFraction(EventID) < keepProb
//
// Two consequences follow, both of which the architecture relies on:
//
//  1. **Redelivery stability.** JetStream is at-least-once; the same
//     EventID can be redelivered. A coin-flip sampler would make
//     inconsistent decisions across redeliveries, corrupting the
//     1/SampleRate de-bias weight and racing the dedup ring. A hash
//     sampler always reaches the same verdict for the same event at
//     a given rate.
//  2. **Monotone (consistent) sampling.** Because the decision is a
//     threshold on a fixed per-event hash fraction, the set kept at
//     rate p1 is a strict subset of the set kept at p2 > p1. Raising
//     or lowering the adaptive rate never reshuffles which events
//     are kept — it only widens or narrows the threshold — so the
//     sampled stream stays coherent as the rate adapts.
//
// The rate adapts per tenant on a fixed window: each window's keep
// probability is computed from the *previous* window's observed
// arrival rate versus the tenant's tier budget (a LimitResolver,
// shared with the PerTenantLimiter so budgets stay consistent).
// Computing the rate from arrivals (not kept events) makes it a
// stable fixed point — a steadily over-budget tenant holds a steady
// keep probability rather than oscillating.
package telemetry

import (
	"context"
	"hash/fnv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// DefaultSamplingWindow is the per-tenant rate-estimation window.
// Each window's keep probability is derived from the arrival rate
// observed over the prior window. Ten seconds smooths sub-second
// bursts (an edge replaying its spool) without lagging a sustained
// volume change by more than one window.
const DefaultSamplingWindow = 10 * time.Second

// DefaultMinSampleRate is the floor on the adaptive keep
// probability. Even a tenant emitting orders of magnitude over their
// budget keeps at least this fraction of events, so the hot store
// never loses total visibility into them — the de-bias weight
// (1/rate) stays finite and the tenant remains queryable. 0.05 keeps
// 1-in-20 at the extreme, enough to retain every active dimension on
// a busy tenant while still shedding 95% of the flood.
const DefaultMinSampleRate = 0.05

// SamplerConfig configures an AdaptiveSampler.
type SamplerConfig struct {
	// Resolver supplies each tenant's steady-state events-per-second
	// budget (TenantLimit.Rate). Sampling engages only when a
	// tenant's observed arrival rate exceeds this budget. A nil
	// resolver defaults to the package default budget
	// (DefaultTenantRateLimit / DefaultTenantBurstSize), matching the
	// PerTenantLimiter's default.
	Resolver LimitResolver
	// Window is the rate-estimation window. Defaults to
	// DefaultSamplingWindow when zero.
	Window time.Duration
	// MinSampleRate is the floor on the adaptive keep probability.
	// Defaults to DefaultMinSampleRate when zero. Values are clamped
	// to (0,1].
	MinSampleRate float64
	// NowFunc returns the current time. Injected so tests can pin the
	// clock; production passes time.Now.
	NowFunc func() time.Time
}

// AdaptiveSampler makes deterministic per-tenant keep/drop decisions.
// Construct via NewAdaptiveSampler. Safe for concurrent use. A nil
// *AdaptiveSampler is a valid no-op (keeps every event at rate 1.0),
// so wiring it onto the Service is optional.
type AdaptiveSampler struct {
	resolver LimitResolver
	window   time.Duration
	minRate  float64
	now      func() time.Time

	mu      sync.RWMutex
	tenants map[uuid.UUID]*samplerState
}

// samplerState is one tenant's rate-estimation window. The keep
// probability is held stable for the lifetime of a window and
// recomputed at the boundary from the just-closed window's arrival
// count, so every event in a window shares one de-bias weight.
type samplerState struct {
	mu          sync.Mutex
	windowStart time.Time
	arrivals    int64
	keepProb    float64
}

// NewAdaptiveSampler constructs a sampler from cfg. A zero-value
// config yields a usable sampler with the package defaults.
func NewAdaptiveSampler(cfg SamplerConfig) *AdaptiveSampler {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = StaticLimitResolver{Limit: TenantLimit{
			Rate:  DefaultTenantRateLimit,
			Burst: DefaultTenantBurstSize,
		}}
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultSamplingWindow
	}
	minRate := cfg.MinSampleRate
	if minRate <= 0 {
		minRate = DefaultMinSampleRate
	}
	if minRate > 1 {
		minRate = 1
	}
	now := cfg.NowFunc
	if now == nil {
		now = time.Now
	}
	return &AdaptiveSampler{
		resolver: resolver,
		window:   window,
		minRate:  minRate,
		now:      now,
		tenants:  make(map[uuid.UUID]*samplerState),
	}
}

// ForPartition returns a sibling sampler that shares this sampler's
// budget resolver, window, and floor but owns an independent
// per-tenant state map. Mirrors PerTenantLimiter.ForPartition: a
// tenant is pinned to exactly one telemetry partition, so the
// per-partition state maps are disjoint and there is no
// cross-partition lock contention, while budgets stay globally
// consistent through the shared resolver. Returns nil on a nil
// receiver so callers can clone an optional sampler without a nil
// check.
func (s *AdaptiveSampler) ForPartition() *AdaptiveSampler {
	if s == nil {
		return nil
	}
	return &AdaptiveSampler{
		resolver: s.resolver,
		window:   s.window,
		minRate:  s.minRate,
		now:      s.now,
		tenants:  make(map[uuid.UUID]*samplerState),
	}
}

// Decide reports whether to keep the event identified by eventID for
// the given tenant, and the keep probability (sampling rate) that was
// applied. A kept event MUST be stamped with the returned rate so
// analytics can de-bias (each kept event represents 1/rate events).
//
// The decision is deterministic: for a fixed tenant keep probability,
// the same eventID always yields the same verdict. A nil sampler
// keeps everything at rate 1.0.
func (s *AdaptiveSampler) Decide(ctx context.Context, tenantID, eventID uuid.UUID) (keep bool, sampleRate float64) {
	if s == nil {
		return true, 1.0
	}
	p := s.keepProb(ctx, tenantID)
	if p >= 1.0 {
		return true, 1.0
	}
	if hashFraction(eventID) < p {
		return true, p
	}
	return false, p
}

// keepProb returns the keep probability for the tenant's current
// window, rolling the window and recomputing the probability from the
// just-closed window's arrival rate when the window has elapsed. It
// records this call as one arrival.
func (s *AdaptiveSampler) keepProb(ctx context.Context, tenantID uuid.UUID) float64 {
	st := s.stateFor(tenantID)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := s.now()
	if st.windowStart.IsZero() {
		// First event for this tenant: no history, keep everything.
		st.windowStart = now
		st.keepProb = 1.0
	} else if elapsed := now.Sub(st.windowStart); elapsed >= s.window {
		observed := float64(st.arrivals) / elapsed.Seconds()
		st.keepProb = s.computeKeepProb(ctx, tenantID, observed)
		st.windowStart = now
		st.arrivals = 0
	}
	st.arrivals++
	return st.keepProb
}

// computeKeepProb maps an observed arrival rate (events/sec) to a
// keep probability given the tenant's budget. At or under budget
// (or with an unlimited / unconfigured budget) it keeps everything;
// over budget it keeps budget/observed so the kept volume lands at
// roughly the budget, clamped to the [minRate,1] floor so visibility
// is never fully lost.
func (s *AdaptiveSampler) computeKeepProb(ctx context.Context, tenantID uuid.UUID, observed float64) float64 {
	limit := s.resolver.Resolve(ctx, tenantID)
	if limit.Rate == rate.Inf {
		return 1.0
	}
	budget := float64(limit.Rate)
	if budget <= 0 || observed <= budget {
		return 1.0
	}
	p := budget / observed
	if p < s.minRate {
		p = s.minRate
	}
	if p > 1 {
		p = 1
	}
	return p
}

// stateFor returns (creating if necessary) the per-tenant sampler
// state. The hot path (existing tenant) takes the read lock only.
func (s *AdaptiveSampler) stateFor(tenantID uuid.UUID) *samplerState {
	s.mu.RLock()
	st, ok := s.tenants[tenantID]
	s.mu.RUnlock()
	if ok {
		return st
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the write lock in case of a concurrent create.
	if st, ok := s.tenants[tenantID]; ok {
		return st
	}
	st = &samplerState{}
	s.tenants[tenantID] = st
	return st
}

// SamplerSnapshot is a read-only view of one tenant's current keep
// probability, for the /metrics handler and tests.
type SamplerSnapshot struct {
	Tenant   uuid.UUID
	KeepProb float64
}

// Snapshot returns the current per-tenant keep probabilities.
func (s *AdaptiveSampler) Snapshot() map[uuid.UUID]SamplerSnapshot {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uuid.UUID]SamplerSnapshot, len(s.tenants))
	for id, st := range s.tenants {
		st.mu.Lock()
		out[id] = SamplerSnapshot{Tenant: id, KeepProb: st.keepProb}
		st.mu.Unlock()
	}
	return out
}

// hashFraction maps a UUID to a uniformly-distributed fraction in
// [0,1) using a seedless FNV-1a hash. Seedless (unlike maphash) is
// essential: the fraction must be identical across process restarts
// and across partitions so the keep/drop decision for an event is
// globally reproducible. The top 53 bits are used so the quotient is
// exactly representable as a float64.
func hashFraction(id uuid.UUID) float64 {
	h := fnv.New64a()
	_, _ = h.Write(id[:])
	return float64(h.Sum64()>>11) / float64(uint64(1)<<53)
}

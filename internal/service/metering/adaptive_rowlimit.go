package metering

// adaptive_rowlimit.go adds a *self-calibrating* per-tenant ClickHouse
// row-write cap on top of the token-bucket machinery in adapter.go.
//
// Why adaptive, not static. The static ClickHouseRowLimiter caps every
// tenant at the same operator-chosen rows/sec. That is the right shield
// against an absolute flood, but it is a blunt instrument across 5000
// heterogeneous SME tenants: a 20-seat shop and a 2000-seat enterprise
// have normal row rates two orders of magnitude apart, so any single
// static cap is simultaneously too loose for the small tenant (a
// compromised edge can 50× its normal volume and still sit under the
// global cap) and too tight for the large one (its legitimate peak trips
// the cap). The cost-control and abuse-detection goal is "don't let a
// tenant write dramatically more than *it normally does*", which is a
// per-tenant, relative threshold.
//
// The threshold. We track each tenant's own recent row-write rate and
// cap admission at a multiple of the trailing MEDIAN of that rate
// (2× by default — see DefaultAdaptiveRowThresholdMultiplier):
//
//	cap_rows_per_sec = clamp(2 × median(recent per-window rates))
//
// The median (not the mean) is the load-bearing choice: it is robust to
// the very outliers we are trying to catch. A handful of spike windows
// barely move the median, so the cap stays anchored to the tenant's
// genuine baseline and the spike is shed; the mean would be dragged up
// by the spike and *widen* the cap exactly when it should hold. Because
// the estimate feeds off *offered* load (every AllowN call is observed,
// admitted or not), a throttled tenant cannot ratchet its own cap
// upward — the median reflects demand, not what got through, so there is
// no runaway feedback loop. A sustained, genuine increase still earns a
// higher cap as it works through the trailing window; a transient burst
// does not.
//
// Cost & bounded memory. The estimator keeps O(SampleWindows) float64s
// per tenant (a tiny ring) and recomputes the median only at a window
// roll (every ~10s per active tenant), caching the resolved RowLimit so
// the hot-path ResolveRowLimit is a lock-read of a precomputed value —
// honouring the RowLimitResolver hot-path contract. Per-tenant state is
// retained for the limiter's lifetime, bounded by the customer count
// (low thousands), exactly like the underlying bucket map; there is no
// per-tenant goroutine and no background sweeper, so the design adds no
// operational surface at 5000 tenants.

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// Adaptive row-limit defaults. Each is overridable via
// AdaptiveRowLimitConfig; the zero value of the config yields all of
// these.
const (
	// DefaultAdaptiveRowWindow is the per-tenant rate-estimation
	// window. One per-window rate (rows admitted-or-offered ÷ window
	// seconds) becomes one median sample. 10s matches the telemetry
	// sampler window and autotune interval so all three cost-control
	// loops observe the same volume epoch.
	DefaultAdaptiveRowWindow = 10 * time.Second
	// DefaultAdaptiveRowSampleWindows is the number of recent windows
	// the trailing median spans. 12 windows × 10s = a 2-minute trailing
	// horizon: long enough that a short burst is a clear minority of
	// samples (so the median ignores it), short enough that a genuine
	// sustained shift earns a new cap within a couple of minutes.
	DefaultAdaptiveRowSampleWindows = 12
	// DefaultAdaptiveRowThresholdMultiplier is the "2×" in
	// 2× trailing median: a tenant may sustain up to twice its own
	// median row rate before the cap engages.
	DefaultAdaptiveRowThresholdMultiplier = 2.0
	// DefaultAdaptiveRowMinRate floors the adaptive cap so a quiet
	// tenant (tiny median) still keeps a usable steady-state budget and
	// is not throttled to near-zero by 2× a near-zero median.
	DefaultAdaptiveRowMinRate rate.Limit = 200
	// DefaultAdaptiveRowMaxRate ceilings the adaptive cap as a safety
	// rail: even a tenant whose median is pathologically high cannot
	// have its cap track unbounded and threaten the shared hot tier.
	DefaultAdaptiveRowMaxRate rate.Limit = 100000
	// DefaultAdaptiveRowInitialRate is the cap applied during a tenant's
	// cold start, before it has closed a full estimation window and so
	// has no median yet. Set to the static default so a new tenant
	// behaves exactly like the non-adaptive limiter until its baseline
	// is learned.
	DefaultAdaptiveRowInitialRate = DefaultClickHouseRowRateLimit
	// DefaultAdaptiveRowBurstSeconds sizes the token-bucket burst as a
	// number of seconds of the (adaptive) steady-state rate, so the
	// burst headroom scales with the tenant rather than being a single
	// global constant. 10s absorbs an edge flushing its on-disk spool
	// on reconnect.
	DefaultAdaptiveRowBurstSeconds = 10
	// DefaultAdaptiveRowMinBurst / DefaultAdaptiveRowMaxBurst bound the
	// derived burst. The min mirrors the static limiter's burst so a
	// small tenant keeps the same one-shot headroom; the max caps a
	// large tenant's instantaneous admission so a burst cannot dump an
	// unbounded slug of rows into a single window.
	DefaultAdaptiveRowMinBurst = DefaultClickHouseRowBurst
	DefaultAdaptiveRowMaxBurst = 500000
)

// AdaptiveRowLimitConfig configures an AdaptiveRowLimiter. The zero
// value is valid and yields the package defaults for every field.
type AdaptiveRowLimitConfig struct {
	// Window is the per-tenant rate-estimation window. Defaults to
	// DefaultAdaptiveRowWindow.
	Window time.Duration
	// SampleWindows is the trailing-median horizon in windows. Defaults
	// to DefaultAdaptiveRowSampleWindows. Clamped to >= 1.
	SampleWindows int
	// ThresholdMultiplier multiplies the trailing median to form the
	// cap. Defaults to DefaultAdaptiveRowThresholdMultiplier. Clamped to
	// > 0.
	ThresholdMultiplier float64
	// MinRate / MaxRate clamp the adaptive steady-state cap. Default to
	// DefaultAdaptiveRowMinRate / DefaultAdaptiveRowMaxRate.
	MinRate rate.Limit
	MaxRate rate.Limit
	// InitialRate is the cold-start cap before a median exists. Defaults
	// to DefaultAdaptiveRowInitialRate.
	InitialRate rate.Limit
	// BurstSeconds derives the burst as BurstSeconds × rate. Defaults to
	// DefaultAdaptiveRowBurstSeconds. Clamped to >= 1.
	BurstSeconds int
	// MinBurst / MaxBurst clamp the derived burst. Default to
	// DefaultAdaptiveRowMinBurst / DefaultAdaptiveRowMaxBurst.
	MinBurst int
	MaxBurst int
	// NowFunc returns the current time; injected so tests can pin the
	// clock. Defaults to time.Now. It governs BOTH the estimator's
	// window roll and the underlying bucket's token math, so a pinned
	// clock makes the whole AllowN path deterministic.
	NowFunc func() time.Time
}

func (c AdaptiveRowLimitConfig) withDefaults() AdaptiveRowLimitConfig {
	if c.Window <= 0 {
		c.Window = DefaultAdaptiveRowWindow
	}
	if c.SampleWindows < 1 {
		c.SampleWindows = DefaultAdaptiveRowSampleWindows
	}
	if c.ThresholdMultiplier <= 0 {
		c.ThresholdMultiplier = DefaultAdaptiveRowThresholdMultiplier
	}
	if c.MinRate <= 0 {
		c.MinRate = DefaultAdaptiveRowMinRate
	}
	if c.MaxRate <= 0 {
		c.MaxRate = DefaultAdaptiveRowMaxRate
	}
	if c.MaxRate < c.MinRate {
		c.MaxRate = c.MinRate
	}
	if c.InitialRate <= 0 {
		c.InitialRate = DefaultAdaptiveRowInitialRate
	}
	if c.BurstSeconds < 1 {
		c.BurstSeconds = DefaultAdaptiveRowBurstSeconds
	}
	if c.MinBurst < 1 {
		c.MinBurst = DefaultAdaptiveRowMinBurst
	}
	if c.MaxBurst < 1 {
		c.MaxBurst = DefaultAdaptiveRowMaxBurst
	}
	if c.MaxBurst < c.MinBurst {
		c.MaxBurst = c.MinBurst
	}
	if c.NowFunc == nil {
		c.NowFunc = time.Now
	}
	return c
}

// medianRateTracker estimates each tenant's trailing-median row rate and
// resolves it into a RowLimit. It implements RowLimitResolver so it can
// drive the existing ClickHouseRowLimiter directly: as a tenant's median
// moves, ResolveRowLimit returns a new RowLimit and the bucket rebuilds
// its rate in place (refreshLocked) — no bucket churn, no lost tokens.
type medianRateTracker struct {
	cfg AdaptiveRowLimitConfig

	mu     sync.RWMutex
	states map[uuid.UUID]*tenantRateState
}

// tenantRateState is one tenant's rolling rate estimate. The hot path
// reads cachedLimit under stMu (a single struct copy); the window roll
// (write) happens at most once per Window per active tenant.
type tenantRateState struct {
	stMu        sync.Mutex
	windowStart time.Time
	windowRows  int64

	// samples is a ring of the most recent per-window rates
	// (rows/sec). len(samples) grows to cfg.SampleWindows then the
	// oldest is overwritten (next is the write cursor).
	samples []float64
	next    int

	// cachedLimit is the RowLimit resolved from the current median,
	// recomputed at each window roll. Before the first roll it holds the
	// cold-start InitialRate limit.
	cachedLimit RowLimit
}

func newMedianRateTracker(cfg AdaptiveRowLimitConfig) *medianRateTracker {
	return &medianRateTracker{
		cfg:    cfg,
		states: make(map[uuid.UUID]*tenantRateState),
	}
}

// stateFor returns (creating on first touch) the tenant's rate state.
// Hot path (existing tenant) takes only the read lock.
func (t *medianRateTracker) stateFor(id uuid.UUID) *tenantRateState {
	t.mu.RLock()
	st, ok := t.states[id]
	t.mu.RUnlock()
	if ok {
		return st
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if st, ok = t.states[id]; ok {
		return st
	}
	st = &tenantRateState{
		samples:     make([]float64, 0, t.cfg.SampleWindows),
		cachedLimit: t.capFromRate(t.cfg.InitialRate),
	}
	t.states[id] = st
	return st
}

// observe records `rows` of offered load for the tenant at time now,
// rolling the estimation window (and recomputing the cached cap from the
// new trailing median) when the window has elapsed. Offered — not merely
// admitted — load is recorded so a throttled tenant cannot ratchet its
// own cap upward.
func (t *medianRateTracker) observe(id uuid.UUID, rows int64, now time.Time) {
	if rows <= 0 {
		return
	}
	st := t.stateFor(id)
	st.stMu.Lock()
	defer st.stMu.Unlock()
	if st.windowStart.IsZero() {
		st.windowStart = now
	} else if elapsed := now.Sub(st.windowStart); elapsed >= t.cfg.Window {
		rateSample := float64(st.windowRows) / elapsed.Seconds()
		t.pushSampleLocked(st, rateSample)
		median := t.medianRateLocked(st)
		capRate := rate.Limit(float64(median) * t.cfg.ThresholdMultiplier)
		st.cachedLimit = t.capFromRate(capRate)
		st.windowStart = now
		st.windowRows = 0
	}
	st.windowRows += rows
}

// pushSampleLocked appends one per-window rate to the ring. Caller holds
// st.stMu.
func (t *medianRateTracker) pushSampleLocked(st *tenantRateState, sample float64) {
	if len(st.samples) < t.cfg.SampleWindows {
		st.samples = append(st.samples, sample)
		return
	}
	st.samples[st.next] = sample
	st.next = (st.next + 1) % t.cfg.SampleWindows
}

// medianRateLocked returns the median of the ring's samples. Caller
// holds st.stMu. Returns 0 when no samples exist (handled by the
// MinRate clamp in capFromRate).
func (t *medianRateTracker) medianRateLocked(st *tenantRateState) rate.Limit {
	n := len(st.samples)
	if n == 0 {
		return 0
	}
	tmp := make([]float64, n)
	copy(tmp, st.samples)
	sort.Float64s(tmp)
	var med float64
	if n%2 == 1 {
		med = tmp[n/2]
	} else {
		med = (tmp[n/2-1] + tmp[n/2]) / 2
	}
	return rate.Limit(med)
}

// capFromRate turns an already-multiplied cap rate into the bounded
// RowLimit: the steady-state rate is clamped to [MinRate,MaxRate], and
// the burst is BurstSeconds × rate clamped to [MinBurst,MaxBurst]. The
// 2× (ThresholdMultiplier) is applied by the caller to the median, so
// this helper is reused unchanged for the cold-start InitialRate, which
// is the cap directly and must NOT be multiplied.
func (t *medianRateTracker) capFromRate(capRate rate.Limit) RowLimit {
	r := capRate
	if r < t.cfg.MinRate {
		r = t.cfg.MinRate
	}
	if r > t.cfg.MaxRate {
		r = t.cfg.MaxRate
	}
	burst := int(float64(r) * float64(t.cfg.BurstSeconds))
	if burst < t.cfg.MinBurst {
		burst = t.cfg.MinBurst
	}
	if burst > t.cfg.MaxBurst {
		burst = t.cfg.MaxBurst
	}
	return RowLimit{Rate: r, Burst: burst}
}

// ResolveRowLimit returns the tenant's current adaptive cap. Hot-path
// safe: a single read-locked struct copy of the precomputed cap.
func (t *medianRateTracker) ResolveRowLimit(_ context.Context, tenantID uuid.UUID) RowLimit {
	st := t.stateFor(tenantID)
	st.stMu.Lock()
	defer st.stMu.Unlock()
	return st.cachedLimit
}

// AdaptiveRowLimiter is a per-tenant ClickHouse row-write limiter whose
// cap tracks 2× each tenant's trailing-median row rate. It satisfies the
// telemetry RowWriteLimiter interface (AllowN), so it drops into
// Service.WithClickHouseRowLimiter in place of the static limiter.
//
// It composes the static ClickHouseRowLimiter rather than reimplementing
// the bucket: the embedded limiter owns the token math and the
// rebuild-in-place-on-budget-change path, while this type owns the
// estimator that feeds it a moving budget. A nil *AdaptiveRowLimiter is
// a valid no-op (always allows), matching the optional-dependency
// contract of the rest of the limiter family.
type AdaptiveRowLimiter struct {
	tracker *medianRateTracker
	inner   *ClickHouseRowLimiter
}

// NewAdaptiveRowLimiter builds an adaptive limiter from cfg. The zero
// config yields the package defaults.
func NewAdaptiveRowLimiter(cfg AdaptiveRowLimitConfig) *AdaptiveRowLimiter {
	cfg = cfg.withDefaults()
	tracker := newMedianRateTracker(cfg)
	inner := NewClickHouseRowLimiter(tracker, withRowLimiterClock(cfg.NowFunc))
	return &AdaptiveRowLimiter{tracker: tracker, inner: inner}
}

// AllowN observes the offered load, then reports whether the tenant may
// write `rows` ClickHouse rows under its current adaptive cap, consuming
// that budget when it returns true. Never blocks. A non-positive count
// always allows; a nil tenant is rejected (delegated to the inner
// limiter). A nil receiver always allows.
func (l *AdaptiveRowLimiter) AllowN(ctx context.Context, tenantID uuid.UUID, rows int64) bool {
	if l == nil || rows <= 0 {
		return true
	}
	if tenantID != uuid.Nil {
		l.tracker.observe(tenantID, rows, l.tracker.cfg.NowFunc())
	}
	return l.inner.AllowN(ctx, tenantID, rows)
}

// WaitN observes the offered load, then blocks until the tenant has
// accrued enough budget to write `rows` rows under its current adaptive
// cap (or ctx is cancelled). Mirrors ClickHouseRowLimiter.WaitN for
// callers that prefer back-pressure to shedding. A nil receiver is a
// no-op.
func (l *AdaptiveRowLimiter) WaitN(ctx context.Context, tenantID uuid.UUID, rows int64) error {
	if l == nil || rows <= 0 {
		return nil
	}
	if tenantID != uuid.Nil {
		l.tracker.observe(tenantID, rows, l.tracker.cfg.NowFunc())
	}
	return l.inner.WaitN(ctx, tenantID, rows)
}

// Snapshot returns the current per-tenant resolved caps, for the
// /metrics surface and tests. Nil receiver yields nil.
func (l *AdaptiveRowLimiter) Snapshot() map[uuid.UUID]RowLimitSnapshot {
	if l == nil {
		return nil
	}
	return l.inner.Snapshot()
}

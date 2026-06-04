package metering

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ErrBudgetExceeded is the sentinel returned (wrapped) by CheckBudget
// when a meter's hard limit would be exceeded by the requested amount.
// Handlers map it to HTTP 429 with a `budget_exceeded` error code.
var ErrBudgetExceeded = errors.New("metering: budget exceeded")

// BudgetLimit is one meter's soft / hard limit and reset cadence. A
// non-positive limit means "unbounded" for that side, so an operator
// can set a soft alert without a hard cap (or vice versa).
type BudgetLimit struct {
	Meter     Meter
	SoftLimit int64
	HardLimit int64
	Period    Period
}

// unbounded reports whether the hard limit is effectively disabled.
func (b BudgetLimit) hardUnbounded() bool { return b.HardLimit <= 0 }
func (b BudgetLimit) softUnbounded() bool { return b.SoftLimit <= 0 }

// Decision is the outcome of a budget check.
type Decision struct {
	// Allowed is false only when the hard limit would be exceeded.
	Allowed bool
	// SoftExceeded is true when usage crossed the soft limit (the
	// operation is still allowed; an alert is raised).
	SoftExceeded bool
	// HardExceeded mirrors !Allowed and is set when the hard limit
	// would be crossed.
	HardExceeded bool
	Meter        Meter
	Limit        BudgetLimit
	// Used is the current-period consumption before this operation.
	Used int64
	// Projected is Used + the requested amount.
	Projected int64
}

// CurrentReader is the slice of MeteringService the BudgetEnforcer
// needs: the live current-period value of a meter. Declared as an
// interface so the enforcer can be unit-tested without a full
// MeteringService.
type CurrentReader interface {
	Current(ctx context.Context, tenantID uuid.UUID, meter Meter) int64
}

// TierResolver resolves a tenant's commercial tier so the enforcer can
// pick the right default budgets. Satisfied by an adapter over the
// tenant repository in production.
type TierResolver interface {
	TenantTier(ctx context.Context, tenantID uuid.UUID) (repository.TenantTier, error)
}

// BudgetStore persists per-tenant budget overrides (tenant_budgets).
type BudgetStore interface {
	// TenantBudgets returns every override row for a tenant.
	TenantBudgets(ctx context.Context, tenantID uuid.UUID) ([]BudgetLimit, error)
	// UpsertTenantBudget writes (inserts or replaces) one override.
	UpsertTenantBudget(ctx context.Context, tenantID uuid.UUID, limit BudgetLimit) error
	// UpsertTenantBudgets writes (inserts or replaces) a batch of
	// overrides atomically — all rows commit together or none do.
	UpsertTenantBudgets(ctx context.Context, tenantID uuid.UUID, limits []BudgetLimit) error
}

// tierDefaults holds the built-in per-tier, per-meter hard limits.
// Values come straight from the Session K spec; soft limits default to
// softLimitFraction of the hard limit. Token budgets are not given by
// the spec, so they are derived at ~1,000 tokens per LLM call (a
// conservative average for the summariser / NL-query workloads) and
// noted as a reasonable default in the PR description.
//
// Spec tiers (Micro / Core / Upper SME) map onto the repository's
// tenant tiers (starter / professional / enterprise) — the codebase
// has no "SME" tier names.
var tierDefaults = map[repository.TenantTier]map[Meter]BudgetLimit{
	repository.TenantTierStarter: {
		MeterLLMCalls:      {HardLimit: 1_000, Period: PeriodMonthly},
		MeterLLMTokensUsed: {HardLimit: 1_000_000, Period: PeriodMonthly},
		MeterURLCatLookups: {HardLimit: 100_000, Period: PeriodDaily},
	},
	repository.TenantTierProfessional: {
		MeterLLMCalls:      {HardLimit: 5_000, Period: PeriodMonthly},
		MeterLLMTokensUsed: {HardLimit: 5_000_000, Period: PeriodMonthly},
		MeterURLCatLookups: {HardLimit: 500_000, Period: PeriodDaily},
	},
	repository.TenantTierEnterprise: {
		MeterLLMCalls:      {HardLimit: 20_000, Period: PeriodMonthly},
		MeterLLMTokensUsed: {HardLimit: 20_000_000, Period: PeriodMonthly},
		MeterURLCatLookups: {HardLimit: 2_000_000, Period: PeriodDaily},
	},
}

// softLimitFraction is the fraction of the hard limit used as the soft
// (alert) limit when only a hard limit is configured.
const softLimitFraction = 0.8

// cacheTTL bounds how long a resolved per-tenant budget set is trusted
// before a refresh, so an out-of-band tier change or override
// propagates without a process restart.
const cacheTTL = 5 * time.Minute

// tenantBudgetCache is a tenant's resolved limits plus the freshness
// deadline.
type tenantBudgetCache struct {
	limits   map[Meter]BudgetLimit
	loadedAt time.Time
}

// BudgetEnforcer turns a meter reading into an allow / soft / hard
// decision against per-tenant budgets. Limits resolve in precedence
// order: explicit tenant override → tier default → configured global
// default → unbounded.
type BudgetEnforcer struct {
	usage    CurrentReader
	store    BudgetStore
	tiers    TierResolver
	periodOf PeriodResolver
	logger   *slog.Logger
	now      func() time.Time

	// globalDefaults are config-supplied per-meter hard limits applied
	// when neither an override nor a tier default exists. Read-only
	// after construction.
	globalDefaults map[Meter]int64

	// optErrs accumulates validation errors raised by options during
	// construction; NewBudgetEnforcer fails if any were recorded, so an
	// invalid config (e.g. a typo'd meter name) fails boot rather than
	// being silently dropped.
	optErrs []error

	mu    sync.RWMutex
	cache map[uuid.UUID]tenantBudgetCache

	softAlerts atomic.Int64
	hardBlocks atomic.Int64
}

// BudgetOption customises a BudgetEnforcer.
type BudgetOption func(*BudgetEnforcer)

// WithGlobalDefaults sets the config-supplied per-meter fallback hard
// limits (from cfg.Metering.DefaultBudgets). Keys are meter names. An
// unknown meter name or a non-positive limit is a construction error
// (recorded on the enforcer and surfaced by NewBudgetEnforcer) rather
// than being silently dropped — a typo in METERING_DEFAULT_BUDGETS
// fails boot, matching the strict-parse contract of the config layer
// that produced this map.
func WithGlobalDefaults(d map[string]int64) BudgetOption {
	return func(b *BudgetEnforcer) {
		if len(d) == 0 {
			return
		}
		m := make(map[Meter]int64, len(d))
		for k, v := range d {
			meter := Meter(k)
			if !meter.Valid() {
				b.optErrs = append(b.optErrs, fmt.Errorf("unknown meter %q", k))
				continue
			}
			if v <= 0 {
				b.optErrs = append(b.optErrs, fmt.Errorf("meter %q: default budget must be positive, got %d", k, v))
				continue
			}
			m[meter] = v
		}
		b.globalDefaults = m
	}
}

// WithBudgetPeriodResolver overrides the meter→period mapping.
func WithBudgetPeriodResolver(r PeriodResolver) BudgetOption {
	return func(b *BudgetEnforcer) {
		if r != nil {
			b.periodOf = r
		}
	}
}

// withBudgetClock overrides the wall clock; test-only.
func withBudgetClock(now func() time.Time) BudgetOption {
	return func(b *BudgetEnforcer) {
		if now != nil {
			b.now = now
		}
	}
}

// NewBudgetEnforcer constructs a BudgetEnforcer. usage, store and tiers
// must not be nil.
func NewBudgetEnforcer(usage CurrentReader, store BudgetStore, tiers TierResolver, logger *slog.Logger, opts ...BudgetOption) (*BudgetEnforcer, error) {
	if usage == nil {
		return nil, fmt.Errorf("metering: budget: usage reader must not be nil")
	}
	if store == nil {
		return nil, fmt.Errorf("metering: budget: store must not be nil")
	}
	if tiers == nil {
		return nil, fmt.Errorf("metering: budget: tier resolver must not be nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	b := &BudgetEnforcer{
		usage:    usage,
		store:    store,
		tiers:    tiers,
		periodOf: DefaultMeterPeriod,
		logger:   logger,
		now:      time.Now,
		cache:    make(map[uuid.UUID]tenantBudgetCache),
	}
	for _, opt := range opts {
		opt(b)
	}
	if len(b.optErrs) > 0 {
		return nil, fmt.Errorf("metering: budget: invalid global defaults: %w", errors.Join(b.optErrs...))
	}
	return b, nil
}

// cloneLimits returns a shallow copy of a resolved limit set.
// BudgetLimit is a value type, so copying the map fully detaches it
// from the cache — callers may freely mutate the result.
func cloneLimits(in map[Meter]BudgetLimit) map[Meter]BudgetLimit {
	out := make(map[Meter]BudgetLimit, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// resolveLimits returns the tenant's resolved per-meter limits, using
// the cache when fresh and reloading (tier + overrides) otherwise. A
// reload failure falls back to the stale cache entry when present, or
// to tier-less global defaults, so a transient DB error degrades to
// the safest available budget rather than failing the hot path.
//
// The returned map MAY alias the cached entry, so callers MUST treat
// it as read-only. The sole hot-path caller (CheckBudget) only reads;
// the public TenantBudgets accessor returns a defensive copy instead.
func (b *BudgetEnforcer) resolveLimits(ctx context.Context, tenantID uuid.UUID) map[Meter]BudgetLimit {
	now := b.now()
	b.mu.RLock()
	entry, ok := b.cache[tenantID]
	b.mu.RUnlock()
	if ok && now.Sub(entry.loadedAt) < cacheTTL {
		return entry.limits
	}

	limits, err := b.loadLimits(ctx, tenantID)
	if err != nil {
		b.logger.WarnContext(ctx, "metering: budget resolve failed; using fallback",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		if ok {
			return entry.limits
		}
		return b.globalDefaultLimits()
	}
	b.mu.Lock()
	b.cache[tenantID] = tenantBudgetCache{limits: limits, loadedAt: now}
	b.mu.Unlock()
	return limits
}

// loadLimits builds the full per-meter limit set for a tenant from the
// tier defaults, the configured global defaults, and the persisted
// overrides (highest precedence).
func (b *BudgetEnforcer) loadLimits(ctx context.Context, tenantID uuid.UUID) (map[Meter]BudgetLimit, error) {
	tier, err := b.tiers.TenantTier(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("resolve tier: %w", err)
	}
	limits := b.globalDefaultLimits()
	for meter, lim := range tierDefaults[tier] {
		limits[meter] = b.normalise(meter, lim)
	}
	overrides, err := b.store.TenantBudgets(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("load overrides: %w", err)
	}
	for _, o := range overrides {
		if !o.Meter.Valid() {
			continue
		}
		limits[o.Meter] = b.normalise(o.Meter, o)
	}
	return limits, nil
}

// globalDefaultLimits materialises the config-supplied per-meter hard
// limits into a fresh map (so callers can mutate their copy).
func (b *BudgetEnforcer) globalDefaultLimits() map[Meter]BudgetLimit {
	limits := make(map[Meter]BudgetLimit, len(b.globalDefaults)+len(AllMeters))
	for meter, hard := range b.globalDefaults {
		limits[meter] = b.normalise(meter, BudgetLimit{Meter: meter, HardLimit: hard})
	}
	return limits
}

// normalise fills in a derived soft limit and the meter's period when
// they are not explicitly set, and stamps the meter name.
func (b *BudgetEnforcer) normalise(meter Meter, lim BudgetLimit) BudgetLimit {
	lim.Meter = meter
	if !lim.Period.Valid() {
		lim.Period = b.periodOf(meter)
	}
	if lim.softUnbounded() && !lim.hardUnbounded() {
		lim.SoftLimit = int64(float64(lim.HardLimit) * softLimitFraction)
	}
	return lim
}

// CheckBudget evaluates a prospective consumption of `amount` units of
// `meter` for `tenantID`. It never blocks on the DB on the hot path
// once the tenant's limits are cached. On a hard-limit breach it
// returns a Decision with Allowed=false AND a wrapped ErrBudgetExceeded
// so callers can branch on either the structured decision or errors.Is.
func (b *BudgetEnforcer) CheckBudget(ctx context.Context, meter Meter, tenantID uuid.UUID, amount int64) (Decision, error) {
	if tenantID == uuid.Nil {
		return Decision{}, fmt.Errorf("metering: check budget: tenant id must not be nil")
	}
	if !meter.Valid() {
		return Decision{}, fmt.Errorf("metering: check budget: unknown meter %q", meter)
	}
	if amount < 0 {
		amount = 0
	}
	used := b.usage.Current(ctx, tenantID, meter)
	projected := used + amount

	limits := b.resolveLimits(ctx, tenantID)
	lim, hasLimit := limits[meter]
	dec := Decision{Allowed: true, Meter: meter, Limit: lim, Used: used, Projected: projected}
	if !hasLimit {
		// No budget configured for this meter → unbounded.
		return dec, nil
	}

	if !lim.hardUnbounded() && projected > lim.HardLimit {
		dec.Allowed = false
		dec.HardExceeded = true
		b.hardBlocks.Add(1)
		b.logger.WarnContext(ctx, "metering: hard budget exceeded",
			slog.String("tenant_id", tenantID.String()),
			slog.String("meter", string(meter)),
			slog.Int64("used", used),
			slog.Int64("amount", amount),
			slog.Int64("hard_limit", lim.HardLimit))
		return dec, fmt.Errorf("%w: meter=%s used=%d requested=%d hard_limit=%d",
			ErrBudgetExceeded, meter, used, amount, lim.HardLimit)
	}
	if !lim.softUnbounded() && projected > lim.SoftLimit {
		dec.SoftExceeded = true
		b.softAlerts.Add(1)
		b.logger.WarnContext(ctx, "metering: soft budget exceeded",
			slog.String("tenant_id", tenantID.String()),
			slog.String("meter", string(meter)),
			slog.Int64("used", used),
			slog.Int64("amount", amount),
			slog.Int64("soft_limit", lim.SoftLimit))
	}
	return dec, nil
}

// SetTenantBudget persists a per-tenant override and refreshes the
// cache so the new limit takes effect immediately. The period defaults
// to the meter's natural period when unset.
func (b *BudgetEnforcer) SetTenantBudget(ctx context.Context, tenantID uuid.UUID, limit BudgetLimit) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("metering: set budget: tenant id must not be nil")
	}
	if !limit.Meter.Valid() {
		return fmt.Errorf("metering: set budget: unknown meter %q", limit.Meter)
	}
	if limit.SoftLimit < 0 || limit.HardLimit < 0 {
		return fmt.Errorf("metering: set budget: limits must be non-negative")
	}
	if !limit.hardUnbounded() && !limit.softUnbounded() && limit.SoftLimit > limit.HardLimit {
		return fmt.Errorf("metering: set budget: soft limit (%d) must not exceed hard limit (%d)", limit.SoftLimit, limit.HardLimit)
	}
	if !limit.Period.Valid() {
		limit.Period = b.periodOf(limit.Meter)
	}
	if err := b.store.UpsertTenantBudget(ctx, tenantID, limit); err != nil {
		return fmt.Errorf("metering: set budget: %w", err)
	}
	// Drop the cache entry so the next check reloads with the override.
	b.mu.Lock()
	delete(b.cache, tenantID)
	b.mu.Unlock()
	return nil
}

// SetTenantBudgets persists a batch of per-tenant overrides atomically
// (all or nothing) and invalidates the cache once so the new limits
// take effect on the next check. Every override is fully validated
// before any write, and duplicate meters within the batch collapse to
// the last occurrence so the underlying single-statement upsert never
// touches the same row twice.
func (b *BudgetEnforcer) SetTenantBudgets(ctx context.Context, tenantID uuid.UUID, limits []BudgetLimit) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("metering: set budgets: tenant id must not be nil")
	}
	if len(limits) == 0 {
		return fmt.Errorf("metering: set budgets: at least one override is required")
	}
	deduped := make(map[Meter]BudgetLimit, len(limits))
	order := make([]Meter, 0, len(limits))
	for _, limit := range limits {
		if !limit.Meter.Valid() {
			return fmt.Errorf("metering: set budgets: unknown meter %q", limit.Meter)
		}
		if limit.SoftLimit < 0 || limit.HardLimit < 0 {
			return fmt.Errorf("metering: set budgets: limits must be non-negative")
		}
		if !limit.hardUnbounded() && !limit.softUnbounded() && limit.SoftLimit > limit.HardLimit {
			return fmt.Errorf("metering: set budgets: soft limit (%d) must not exceed hard limit (%d)", limit.SoftLimit, limit.HardLimit)
		}
		if !limit.Period.Valid() {
			limit.Period = b.periodOf(limit.Meter)
		}
		if _, seen := deduped[limit.Meter]; !seen {
			order = append(order, limit.Meter)
		}
		deduped[limit.Meter] = limit
	}
	batch := make([]BudgetLimit, 0, len(order))
	for _, m := range order {
		batch = append(batch, deduped[m])
	}
	if err := b.store.UpsertTenantBudgets(ctx, tenantID, batch); err != nil {
		return fmt.Errorf("metering: set budgets: %w", err)
	}
	b.mu.Lock()
	delete(b.cache, tenantID)
	b.mu.Unlock()
	return nil
}

// TenantBudgets returns the resolved, effective limits for a tenant
// (defaults merged with overrides). The returned map is a private copy
// the caller may freely mutate without affecting the cache.
func (b *BudgetEnforcer) TenantBudgets(ctx context.Context, tenantID uuid.UUID) (map[Meter]BudgetLimit, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("metering: tenant budgets: tenant id must not be nil")
	}
	limits, err := b.loadLimits(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("metering: tenant budgets: %w", err)
	}
	b.mu.Lock()
	b.cache[tenantID] = tenantBudgetCache{limits: limits, loadedAt: b.now()}
	b.mu.Unlock()
	return cloneLimits(limits), nil
}

// BudgetStats reports the cumulative soft-alert and hard-block counts.
type BudgetStats struct {
	SoftAlerts int64
	HardBlocks int64
}

// Stats returns the enforcer's alert / block counters.
func (b *BudgetEnforcer) Stats() BudgetStats {
	return BudgetStats{SoftAlerts: b.softAlerts.Load(), HardBlocks: b.hardBlocks.Load()}
}

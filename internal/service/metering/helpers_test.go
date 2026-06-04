package metering

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// fakeStore is an in-memory UsageStore + BudgetStore double used by the
// unit tests. BatchUpsertUsage is additive (matching the production
// contract), so a replayed flush cannot lose counts. All methods are
// mutex-guarded so the store is safe under the race detector when the
// MeteringService flush loop runs concurrently.
type fakeStore struct {
	mu    sync.Mutex
	usage map[usageKey]*usageRow
	// budgets holds per-tenant override rows keyed by (tenant, meter).
	budgets map[uuid.UUID]map[Meter]BudgetLimit

	// Error injection knobs (nil => succeed).
	failBatch         error
	failTenantBudgets error
	failPlatform      error

	// Call counters for assertions.
	batchCalls int
}

type usageKey struct {
	tenant uuid.UUID
	meter  Meter
	start  int64 // unix seconds of period_start
}

type usageRow struct {
	tenant uuid.UUID
	meter  Meter
	start  time.Time
	end    time.Time
	value  int64
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		usage:   make(map[usageKey]*usageRow),
		budgets: make(map[uuid.UUID]map[Meter]BudgetLimit),
	}
}

func (f *fakeStore) BatchUpsertUsage(_ context.Context, deltas []UsageDelta) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.batchCalls++
	if f.failBatch != nil {
		return f.failBatch
	}
	for _, d := range deltas {
		k := usageKey{tenant: d.TenantID, meter: d.Meter, start: d.PeriodStart.UTC().Unix()}
		row, ok := f.usage[k]
		if !ok {
			row = &usageRow{tenant: d.TenantID, meter: d.Meter, start: d.PeriodStart.UTC(), end: d.PeriodEnd.UTC()}
			f.usage[k] = row
		}
		row.value += d.Delta
	}
	return nil
}

func (f *fakeStore) TenantPeriodUsage(_ context.Context, tenantID uuid.UUID, meter Meter, periodStart time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := usageKey{tenant: tenantID, meter: meter, start: periodStart.UTC().Unix()}
	if row, ok := f.usage[k]; ok {
		return row.value, nil
	}
	return 0, nil
}

func (f *fakeStore) TenantCurrentUsage(_ context.Context, tenantID uuid.UUID, at time.Time) ([]UsageRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	at = at.UTC()
	var out []UsageRecord
	for _, row := range f.usage {
		if row.tenant != tenantID {
			continue
		}
		if at.Before(row.start) || !at.Before(row.end) {
			continue
		}
		out = append(out, row.record())
	}
	return out, nil
}

func (f *fakeStore) TenantUsageHistory(_ context.Context, tenantID uuid.UUID, _ int) ([]UsageRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []UsageRecord
	for _, row := range f.usage {
		if row.tenant != tenantID {
			continue
		}
		out = append(out, row.record())
	}
	return out, nil
}

func (f *fakeStore) PlatformCurrentUsage(_ context.Context, at time.Time) ([]UsageRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPlatform != nil {
		return nil, f.failPlatform
	}
	at = at.UTC()
	var out []UsageRecord
	for _, row := range f.usage {
		if at.Before(row.start) || !at.Before(row.end) {
			continue
		}
		out = append(out, row.record())
	}
	return out, nil
}

func (f *fakeStore) TenantBudgets(_ context.Context, tenantID uuid.UUID) ([]BudgetLimit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failTenantBudgets != nil {
		return nil, f.failTenantBudgets
	}
	var out []BudgetLimit
	for _, lim := range f.budgets[tenantID] {
		out = append(out, lim)
	}
	return out, nil
}

func (f *fakeStore) UpsertTenantBudget(_ context.Context, tenantID uuid.UUID, limit BudgetLimit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.budgets[tenantID] == nil {
		f.budgets[tenantID] = make(map[Meter]BudgetLimit)
	}
	f.budgets[tenantID][limit.Meter] = limit
	return nil
}

func (r *usageRow) record() UsageRecord {
	return UsageRecord{
		TenantID:    r.tenant,
		Meter:       r.meter,
		PeriodStart: r.start,
		PeriodEnd:   r.end,
		Value:       r.value,
	}
}

// fakeTiers is a static TierResolver.
type fakeTiers struct {
	tier repository.TenantTier
	err  error
	// per-tenant overrides; falls back to `tier` when absent.
	byTenant map[uuid.UUID]repository.TenantTier
}

func (f fakeTiers) TenantTier(_ context.Context, tenantID uuid.UUID) (repository.TenantTier, error) {
	if f.err != nil {
		return "", f.err
	}
	if t, ok := f.byTenant[tenantID]; ok {
		return t, nil
	}
	return f.tier, nil
}

// staticCurrent is a CurrentReader returning a fixed value, for budget
// tests that do not need a full MeteringService.
type staticCurrent struct {
	values map[Meter]int64
}

func (s staticCurrent) Current(_ context.Context, _ uuid.UUID, meter Meter) int64 {
	return s.values[meter]
}

// fixedClock returns a clock function pinned to t.
func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

package metering

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// countingTiers wraps a TierResolver and records how the metering layer
// reaches it, so a test can prove the platform report resolves tiers in
// a bounded number of batched calls rather than one per-tenant lookup.
type countingTiers struct {
	inner       TierResolver
	singleCalls int
	batchCalls  int
}

func (c *countingTiers) TenantTier(ctx context.Context, id uuid.UUID) (repository.TenantTier, error) {
	c.singleCalls++
	return c.inner.TenantTier(ctx, id)
}

func (c *countingTiers) TenantTiersBatch(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID]repository.TenantTier, error) {
	c.batchCalls++
	return c.inner.TenantTiersBatch(ctx, ids)
}

// legacyPlatformReport reproduces the pre-batch PlatformReport algorithm
// exactly — group the system-scoped usage rows in first-seen order,
// then per tenant resolve tier (TenantTier) and budgets (TenantBudgets)
// one round trip at a time before folding the per-tenant report into the
// platform totals. It is the oracle the batched implementation must stay
// byte-identical to.
func legacyPlatformReport(ctx context.Context, t *testing.T, store *fakeStore, enf *BudgetEnforcer, tiers TierResolver, calc *CostCalculator, now time.Time) PlatformCostReport {
	t.Helper()
	rows, err := store.PlatformCurrentUsage(ctx, now)
	if err != nil {
		t.Fatalf("PlatformCurrentUsage: %v", err)
	}
	byTenant := make(map[uuid.UUID][]UsageRecord)
	order := make([]uuid.UUID, 0)
	for _, row := range rows {
		if _, seen := byTenant[row.TenantID]; !seen {
			order = append(order, row.TenantID)
		}
		byTenant[row.TenantID] = append(byTenant[row.TenantID], row)
	}
	rep := PlatformCostReport{GeneratedAt: now}
	for _, tid := range order {
		tier, err := tiers.TenantTier(ctx, tid)
		if err != nil {
			t.Fatalf("TenantTier: %v", err)
		}
		limits, err := enf.TenantBudgets(ctx, tid)
		if err != nil {
			t.Fatalf("TenantBudgets: %v", err)
		}
		tr := calc.BuildReport(tid, tier, byTenant[tid], limits)
		rep.Tenants = append(rep.Tenants, tr)
		rep.TotalCostUSD += tr.TotalCostUSD
		rep.ProjectedMonthlyCostUSD += tr.ProjectedMonthlyCostUSD
		rep.TotalRevenueUSD += tr.MonthlyRevenueUSD
	}
	rep.TenantCount = len(rep.Tenants)
	rep.TotalCostUSD = round2(rep.TotalCostUSD)
	rep.ProjectedMonthlyCostUSD = round2(rep.ProjectedMonthlyCostUSD)
	rep.TotalRevenueUSD = round2(rep.TotalRevenueUSD)
	rep.TotalMarginUSD = round2(rep.TotalRevenueUSD - rep.ProjectedMonthlyCostUSD)
	return rep
}

// seedPlatformFixture records a mixed multi-tenant fixture: several
// tiers, multiple meters per tenant, and per-tenant budget overrides on
// some tenants, so the report exercises tier defaults, global defaults,
// and overrides together. Tenant ids are deterministic (uuid.NewSHA1)
// so the system-scoped ORDER BY tenant_id is stable across runs.
func seedPlatformFixture(ctx context.Context, t *testing.T, svc *MeteringService, store *fakeStore, n int) []uuid.UUID {
	t.Helper()
	// Tenant tiers are resolved independently by newFixtureTiers; this
	// fixture only seeds usage and budget-override rows.
	ns := uuid.MustParse("00000000-0000-0000-0000-0000000000aa")
	ids := make([]uuid.UUID, 0, n)
	for i := 0; i < n; i++ {
		id := uuid.NewSHA1(ns, []byte{byte(i)})
		ids = append(ids, id)
		_ = svc.Record(ctx, id, MeterLLMTokensUsed, int64(100_000*(i+1)))
		_ = svc.Record(ctx, id, MeterURLCatLookups, int64(10_000*(i+1)))
		_ = svc.Record(ctx, id, MeterClickHouseRowsWritten, int64(250_000*(i+1)))
		// Override the LLM-calls budget on every third tenant so the
		// override-merge precedence is exercised, not just tier defaults.
		if i%3 == 0 {
			if store.budgets[id] == nil {
				store.budgets[id] = make(map[Meter]BudgetLimit)
			}
			store.budgets[id][MeterLLMCalls] = BudgetLimit{
				Meter:     MeterLLMCalls,
				HardLimit: int64(42_000 + i),
				Period:    PeriodMonthly,
			}
		}
	}
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	return ids
}

func newFixtureTiers(ids []uuid.UUID) fakeTiers {
	ns := uuid.MustParse("00000000-0000-0000-0000-0000000000aa")
	tierCycle := []repository.TenantTier{
		repository.TenantTierStarter,
		repository.TenantTierProfessional,
		repository.TenantTierEnterprise,
	}
	byTenant := make(map[uuid.UUID]repository.TenantTier, len(ids))
	for i := range ids {
		byTenant[uuid.NewSHA1(ns, []byte{byte(i)})] = tierCycle[i%len(tierCycle)]
	}
	return fakeTiers{byTenant: byTenant}
}

// TestPlatformReportBatchedMatchesLegacy proves the batched PlatformReport
// is byte-identical (reflect.DeepEqual) to the original per-tenant
// algorithm for a mixed multi-tenant fixture.
func TestPlatformReportBatchedMatchesLegacy(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	ctx := context.Background()

	ids := seedPlatformFixture(ctx, t, svc, store, 7)
	tiers := newFixtureTiers(ids)
	enf := mustEnforcer(t, svc, store, tiers)
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))

	// Oracle is computed before the batched run so neither mutates the
	// other's view (both read the same deterministic store state).
	want := legacyPlatformReport(ctx, t, store, enf, tiers, calc, now)

	reports, err := NewReports(svc, enf, store, tiers, calc, withReportsClock(fixedClock(now)))
	if err != nil {
		t.Fatalf("NewReports: %v", err)
	}
	got, err := reports.PlatformReport(ctx)
	if err != nil {
		t.Fatalf("PlatformReport: %v", err)
	}

	if got.TenantCount != 7 {
		t.Fatalf("tenant count = %d, want 7", got.TenantCount)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("batched PlatformReport diverged from legacy:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestPlatformReportBatchedIssuesBoundedLookups proves the loop no longer
// issues per-tenant tier/budget round trips: the per-tenant methods are
// never called, and the number of batched lookups is constant regardless
// of tenant count (O(1), not O(N)).
func TestPlatformReportBatchedIssuesBoundedLookups(t *testing.T) {
	runFor := func(n int) (tierBatch, tierSingle, budgetBatch, budgetSingle int) {
		store := newFakeStore()
		now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
		svc := mustService(t, store, withClock(fixedClock(now)))
		ctx := context.Background()
		ids := seedPlatformFixture(ctx, t, svc, store, n)
		tiers := &countingTiers{inner: newFixtureTiers(ids)}
		enf := mustEnforcer(t, svc, store, tiers)
		calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
		reports, err := NewReports(svc, enf, store, tiers, calc, withReportsClock(fixedClock(now)))
		if err != nil {
			t.Fatalf("NewReports: %v", err)
		}
		if _, err := reports.PlatformReport(ctx); err != nil {
			t.Fatalf("PlatformReport(n=%d): %v", n, err)
		}
		return tiers.batchCalls, tiers.singleCalls, store.tenantBudgetsBatchCalls, store.tenantBudgetsCalls
	}

	small := struct{ tierBatch, tierSingle, budgetBatch, budgetSingle int }{}
	large := small
	small.tierBatch, small.tierSingle, small.budgetBatch, small.budgetSingle = runFor(3)
	large.tierBatch, large.tierSingle, large.budgetBatch, large.budgetSingle = runFor(30)

	// Per-tenant lookups must never fire on the platform path.
	if small.tierSingle != 0 || large.tierSingle != 0 {
		t.Fatalf("TenantTier called per-tenant: n=3 -> %d, n=30 -> %d", small.tierSingle, large.tierSingle)
	}
	if small.budgetSingle != 0 || large.budgetSingle != 0 {
		t.Fatalf("TenantBudgets called per-tenant: n=3 -> %d, n=30 -> %d", small.budgetSingle, large.budgetSingle)
	}
	// Batched lookup counts must be identical for 3 and 30 tenants —
	// proving they are O(1) in tenant count, not O(N).
	if small.tierBatch != large.tierBatch {
		t.Fatalf("tier batch calls scale with N: n=3 -> %d, n=30 -> %d", small.tierBatch, large.tierBatch)
	}
	if small.budgetBatch != large.budgetBatch {
		t.Fatalf("budget batch calls scale with N: n=3 -> %d, n=30 -> %d", small.budgetBatch, large.budgetBatch)
	}
	// The override table is read in exactly one batched query.
	if large.budgetBatch != 1 {
		t.Fatalf("override batch query count = %d, want 1", large.budgetBatch)
	}
	// Tier is resolved exactly once: PlatformReport resolves the tier
	// map for BuildReport and threads it into the budget batch via
	// TenantBudgetsBatchWithTiers, so the enforcer does not re-resolve
	// tiers. One batched tier call total, independent of N.
	if large.tierBatch != 1 {
		t.Fatalf("tier batch call count = %d, want 1", large.tierBatch)
	}
}

// TestTenantBudgetsBatchWithTiersMatchesSelfResolving proves the
// tier-supplied batch path returns byte-identical limits to the
// self-resolving batch path, and that supplying the tier map skips tier
// resolution entirely (no extra TierResolver round trips).
func TestTenantBudgetsBatchWithTiersMatchesSelfResolving(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	ctx := context.Background()
	ids := seedPlatformFixture(ctx, t, svc, store, 6)
	tiers := &countingTiers{inner: newFixtureTiers(ids)}
	enf := mustEnforcer(t, svc, store, tiers)

	// Self-resolving path resolves tiers itself.
	want, err := enf.TenantBudgetsBatch(ctx, ids)
	if err != nil {
		t.Fatalf("TenantBudgetsBatch: %v", err)
	}
	if tiers.batchCalls == 0 {
		t.Fatal("expected self-resolving TenantBudgetsBatch to resolve tiers")
	}

	tierMap, err := tiers.TenantTiersBatch(ctx, ids)
	if err != nil {
		t.Fatalf("TenantTiersBatch: %v", err)
	}
	before := tiers.batchCalls
	got, err := enf.TenantBudgetsBatchWithTiers(ctx, ids, tierMap)
	if err != nil {
		t.Fatalf("TenantBudgetsBatchWithTiers: %v", err)
	}
	// WithTiers must not resolve tiers again.
	if tiers.batchCalls != before {
		t.Fatalf("WithTiers re-resolved tiers: batchCalls %d -> %d", before, tiers.batchCalls)
	}
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("WithTiers limits differ from self-resolving limits:\n want=%v\n got =%v", want, got)
	}
}

// TestTenantBudgetsBatchWithTiersMissingTierAborts proves that supplying
// a tier map that omits a requested tenant aborts the call rather than
// silently assembling that tenant on global defaults only — preserving
// the abort-the-whole-report contract.
func TestTenantBudgetsBatchWithTiersMissingTierAborts(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	ctx := context.Background()
	ids := seedPlatformFixture(ctx, t, svc, store, 3)
	enf := mustEnforcer(t, svc, store, newFixtureTiers(ids))

	// Tier map covers only the first tenant.
	partial := map[uuid.UUID]repository.TenantTier{ids[0]: repository.TenantTierStarter}
	if _, err := enf.TenantBudgetsBatchWithTiers(ctx, ids, partial); err == nil {
		t.Fatal("expected abort when a requested tenant's tier is missing from the supplied map")
	}
	// The abort must be all-or-nothing: no override query is issued when
	// the tier map is incomplete, so the batch has zero side effects.
	if store.tenantBudgetsBatchCalls != 0 {
		t.Fatalf("override query issued on aborted batch: %d calls, want 0", store.tenantBudgetsBatchCalls)
	}
}

// TestPlatformReportBatchedTierErrorAborts proves a batched tier lookup
// failure aborts the whole report rather than emitting a partial total.
func TestPlatformReportBatchedTierErrorAborts(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	ctx := context.Background()
	_ = seedPlatformFixture(ctx, t, svc, store, 4)

	tiers := fakeTiers{err: errors.New("tier backend down")}
	enf := mustEnforcer(t, svc, store, tiers)
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	reports, _ := NewReports(svc, enf, store, tiers, calc, withReportsClock(fixedClock(now)))

	if _, err := reports.PlatformReport(ctx); err == nil {
		t.Fatal("expected PlatformReport to abort on a batched tier lookup error")
	}
}

// TestPlatformReportBatchedBudgetErrorAborts proves a batched override
// lookup failure (tiers resolve fine) aborts the whole report.
func TestPlatformReportBatchedBudgetErrorAborts(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	ctx := context.Background()
	ids := seedPlatformFixture(ctx, t, svc, store, 4)

	store.failTenantBudgetsBatch = errors.New("override backend down")
	tiers := newFixtureTiers(ids)
	enf := mustEnforcer(t, svc, store, tiers)
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	reports, _ := NewReports(svc, enf, store, tiers, calc, withReportsClock(fixedClock(now)))

	if _, err := reports.PlatformReport(ctx); err == nil {
		t.Fatal("expected PlatformReport to abort on a batched override lookup error")
	}
}

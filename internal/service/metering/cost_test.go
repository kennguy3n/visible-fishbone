package metering

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func TestMeterCostUSDPerMeter(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts)
	cases := []struct {
		meter Meter
		value int64
		want  float64
	}{
		{MeterLLMTokensUsed, 1_000_000, 2.0},           // 1M tokens * $0.002/1K
		{MeterLLMCalls, 5000, 0},                       // $0 per call by default
		{MeterURLCatLookups, 10_000, 1.0},              // 10K * $0.10/1K
		{MeterMalwareScans, 2000, 2.0},                 // 2000 * $0.001
		{MeterBandwidthProxiedBytes, bytesPerGB, 0.09}, // 1 GB * $0.09
		{MeterClickHouseRowsWritten, 1_000_000, 0.20},  // 1M rows * $0.20/1M
		{MeterS3BytesArchived, bytesPerGB, 0.023},      // 1 GB-month * $0.023
		{Meter("unknown"), 1000, 0},                    // unknown → 0
		{MeterLLMTokensUsed, 0, 0},                     // zero → 0
	}
	for _, tc := range cases {
		got := c.MeterCostUSD(tc.meter, tc.value)
		if !approx(got, tc.want) {
			t.Errorf("MeterCostUSD(%s, %d) = %v, want %v", tc.meter, tc.value, got, tc.want)
		}
	}
}

func TestZeroValueUnitCostsUsesDefaults(t *testing.T) {
	c := NewCostCalculator(UnitCosts{})
	if !approx(c.MeterCostUSD(MeterLLMTokensUsed, 1_000_000), 2.0) {
		t.Fatal("zero-value UnitCosts should fall back to DefaultUnitCosts")
	}
}

func TestBuildReportProjectionAndMargin(t *testing.T) {
	// Pin "now" to the middle of a 30-day month (June): day 15 noon.
	// For a monthly meter, ~ (14.5/30) of the period has elapsed.
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	c := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	tid := uuid.New()

	usage := []UsageRecord{
		{Meter: MeterLLMTokensUsed, Value: 1_000_000},
	}
	limits := map[Meter]BudgetLimit{
		MeterLLMTokensUsed: {Meter: MeterLLMTokensUsed, HardLimit: 5_000_000, Period: PeriodMonthly},
	}
	rep := c.BuildReport(tid, repository.TenantTierStarter, usage, limits)

	if len(rep.Lines) != 1 {
		t.Fatalf("lines = %d, want 1", len(rep.Lines))
	}
	line := rep.Lines[0]
	if line.Usage != 1_000_000 {
		t.Fatalf("usage = %d", line.Usage)
	}
	if !approx(line.CostUSD, 2.0) {
		t.Fatalf("cost = %v, want 2.0", line.CostUSD)
	}
	// Projection must extrapolate beyond current usage (period not over).
	if line.ProjectedUsage <= line.Usage {
		t.Fatalf("projected %d should exceed current %d", line.ProjectedUsage, line.Usage)
	}
	// Utilization = projected / hard limit, between 0 and 1 here.
	if line.BudgetUtilization <= 0 {
		t.Fatalf("utilization = %v, want > 0", line.BudgetUtilization)
	}
	// Revenue/margin for starter tier ($99/mo).
	if !approx(rep.MonthlyRevenueUSD, 99) {
		t.Fatalf("revenue = %v, want 99", rep.MonthlyRevenueUSD)
	}
	if !approx(rep.MarginUSD, round2(99-rep.ProjectedMonthlyCostUSD)) {
		t.Fatalf("margin mismatch: %v", rep.MarginUSD)
	}
}

func TestBuildReportOverBudgetFlag(t *testing.T) {
	now := time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC) // late in month
	c := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	usage := []UsageRecord{{Meter: MeterLLMCalls, Value: 9000}}
	limits := map[Meter]BudgetLimit{
		MeterLLMCalls: {Meter: MeterLLMCalls, HardLimit: 5000, Period: PeriodMonthly},
	}
	rep := c.BuildReport(uuid.New(), repository.TenantTierProfessional, usage, limits)
	if !rep.Lines[0].OverBudget {
		t.Fatalf("projected usage should be over the 5000 hard limit: %+v", rep.Lines[0])
	}
}

// --- Reports orchestrator ------------------------------------------------

func TestNewReportsValidatesDeps(t *testing.T) {
	store := newFakeStore()
	svc := mustService(t, store)
	enf := mustEnforcer(t, svc, store, fakeTiers{tier: repository.TenantTierStarter})
	calc := NewCostCalculator(DefaultUnitCosts)
	if _, err := NewReports(nil, enf, store, fakeTiers{}, calc); err == nil {
		t.Fatal("expected error for nil usage")
	}
	if _, err := NewReports(svc, enf, store, fakeTiers{}, nil); err == nil {
		t.Fatal("expected error for nil calc")
	}
}

func TestReportsTenantReport(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	enf := mustEnforcer(t, svc, store, fakeTiers{tier: repository.TenantTierStarter})
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	reports, err := NewReports(svc, enf, store, fakeTiers{tier: repository.TenantTierStarter}, calc)
	if err != nil {
		t.Fatalf("NewReports: %v", err)
	}
	ctx := context.Background()
	tid := uuid.New()
	_ = svc.Record(ctx, tid, MeterLLMTokensUsed, 250_000)

	rep, err := reports.TenantReport(ctx, tid)
	if err != nil {
		t.Fatalf("TenantReport: %v", err)
	}
	if rep.TenantID != tid {
		t.Fatalf("tenant id mismatch")
	}
	if rep.Tier != repository.TenantTierStarter {
		t.Fatalf("tier = %s", rep.Tier)
	}
	var found bool
	for _, l := range rep.Lines {
		if l.Meter == MeterLLMTokensUsed {
			found = true
			if l.Usage != 250_000 {
				t.Fatalf("usage = %d, want 250000", l.Usage)
			}
		}
	}
	if !found {
		t.Fatal("expected an llm_tokens_used line")
	}
}

func TestReportsTenantReportNilTenant(t *testing.T) {
	store := newFakeStore()
	svc := mustService(t, store)
	enf := mustEnforcer(t, svc, store, fakeTiers{tier: repository.TenantTierStarter})
	reports, _ := NewReports(svc, enf, store, fakeTiers{tier: repository.TenantTierStarter}, NewCostCalculator(DefaultUnitCosts))
	if _, err := reports.TenantReport(context.Background(), uuid.Nil); err == nil {
		t.Fatal("expected error for nil tenant")
	}
}

func TestReportsPlatformReportAggregates(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	t1, t2 := uuid.New(), uuid.New()
	tiers := fakeTiers{byTenant: map[uuid.UUID]repository.TenantTier{
		t1: repository.TenantTierStarter,
		t2: repository.TenantTierEnterprise,
	}}
	enf := mustEnforcer(t, svc, store, tiers)
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	reports, err := NewReports(svc, enf, store, tiers, calc)
	if err != nil {
		t.Fatalf("NewReports: %v", err)
	}
	ctx := context.Background()
	_ = svc.Record(ctx, t1, MeterLLMTokensUsed, 100_000)
	_ = svc.Record(ctx, t2, MeterLLMTokensUsed, 200_000)
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	rep, err := reports.PlatformReport(ctx)
	if err != nil {
		t.Fatalf("PlatformReport: %v", err)
	}
	if rep.TenantCount != 2 {
		t.Fatalf("tenant count = %d, want 2", rep.TenantCount)
	}
	// Revenue = 99 (starter) + 1999 (enterprise).
	if !approx(rep.TotalRevenueUSD, 2098) {
		t.Fatalf("total revenue = %v, want 2098", rep.TotalRevenueUSD)
	}
	if !approx(rep.TotalMarginUSD, round2(rep.TotalRevenueUSD-rep.ProjectedMonthlyCostUSD)) {
		t.Fatalf("margin mismatch: %v", rep.TotalMarginUSD)
	}
}

func TestReportsPlatformReportPropagatesTierError(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	tiers := fakeTiers{err: errors.New("tenant lookup failed")}
	enf := mustEnforcer(t, svc, store, tiers)
	reports, _ := NewReports(svc, enf, store, tiers, NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now))))
	ctx := context.Background()
	_ = svc.Record(ctx, uuid.New(), MeterLLMTokensUsed, 10_000)
	_ = svc.Flush(ctx)

	if _, err := reports.PlatformReport(ctx); err == nil {
		t.Fatal("expected PlatformReport to propagate the tier lookup error")
	}
}

package metering

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestNATSStorageCostUSD(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts)
	cases := []struct {
		bytes int64
		want  float64
	}{
		{0, 0},
		{-1, 0},
		{bytesPerGB, 0.10},     // 1 GB-month * $0.10
		{10 * bytesPerGB, 1.0}, // 10 GB-month * $0.10
	}
	for _, tc := range cases {
		if got := c.NATSStorageCostUSD(tc.bytes); !approx(got, tc.want) {
			t.Errorf("NATSStorageCostUSD(%d) = %v, want %v", tc.bytes, got, tc.want)
		}
	}
}

func TestProjectInfraMonthlyCostGaugesAndFlow(t *testing.T) {
	// Pin now to the middle of a 30-day month so the ClickHouse flow
	// roughly doubles when projected, while the NATS/S3 gauges are
	// priced as-is (storage cost does not extrapolate).
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	c := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	tid := uuid.New()

	sample := InfraUsageSample{
		TenantID:                 tid,
		ClickHouseRowsThisPeriod: 5_000_000, // half a month in
		NATSStreamBytes:          2 * bytesPerGB,
		S3ArchiveBytes:           50 * bytesPerGB,
	}
	got := c.ProjectInfraMonthlyCost(sample)

	if got.TenantID != tid {
		t.Fatalf("tenant id mismatch")
	}
	// Flow: ~10M rows projected for the full month -> ~$2.00.
	if got.ClickHouseProjectedRows <= sample.ClickHouseRowsThisPeriod {
		t.Fatalf("clickhouse rows should project beyond in-period count: %d", got.ClickHouseProjectedRows)
	}
	if got.ClickHouseMonthlyUSD < 1.9 || got.ClickHouseMonthlyUSD > 2.2 {
		t.Fatalf("clickhouse monthly = %v, want ~2.0", got.ClickHouseMonthlyUSD)
	}
	// Gauge: NATS 2 GB * $0.10 = $0.20, priced as-is (no extrapolation).
	if !approx(got.NATSMonthlyUSD, 0.20) {
		t.Fatalf("nats monthly = %v, want 0.20", got.NATSMonthlyUSD)
	}
	// Gauge: S3 50 GB * $0.023 = $1.15.
	if !approx(got.S3MonthlyUSD, 1.15) {
		t.Fatalf("s3 monthly = %v, want 1.15", got.S3MonthlyUSD)
	}
	if !approx(got.TotalMonthlyUSD, round2(got.ClickHouseMonthlyUSD+got.NATSMonthlyUSD+got.S3MonthlyUSD)) {
		t.Fatalf("total mismatch: %v", got.TotalMonthlyUSD)
	}
}

func TestProjectInfraMonthlyCostDailyPeriodIsMonthlyConsistent(t *testing.T) {
	// A daily-period ClickHouse count must project to a *monthly* row
	// figure whose cost equals ClickHouseMonthlyUSD — i.e. the reported
	// rows and dollars stay internally consistent for sub-monthly
	// periods, not just the monthly default.
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC) // mid-day, mid 30-day month
	c := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))

	sample := InfraUsageSample{
		TenantID:                 uuid.New(),
		ClickHouseRowsThisPeriod: 1_000_000, // ~half a day in
		ClickHousePeriod:         PeriodDaily,
	}
	got := c.ProjectInfraMonthlyCost(sample)

	// ~2M rows/day * 30 days = ~60M rows/month.
	if got.ClickHouseProjectedRows < 55_000_000 || got.ClickHouseProjectedRows > 65_000_000 {
		t.Fatalf("daily projection should reach ~60M monthly rows, got %d", got.ClickHouseProjectedRows)
	}
	// The reported monthly cost must be the cost of the reported monthly
	// rows — no hidden second extrapolation factor.
	wantUSD := round2(c.MeterCostUSD(MeterClickHouseRowsWritten, got.ClickHouseProjectedRows))
	if !approx(got.ClickHouseMonthlyUSD, wantUSD) {
		t.Fatalf("monthly cost %v inconsistent with projected rows %d (want %v)",
			got.ClickHouseMonthlyUSD, got.ClickHouseProjectedRows, wantUSD)
	}
}

func TestProjectInfraMonthlyCostZeroSample(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts)
	got := c.ProjectInfraMonthlyCost(InfraUsageSample{})
	if got.ClickHouseProjectedRows != 0 || got.TotalMonthlyUSD != 0 {
		t.Fatalf("empty sample should cost nothing: %+v", got)
	}
}

func TestAggregateInfraCostSumsPerDriver(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	c := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	samples := []InfraUsageSample{
		{TenantID: uuid.New(), NATSStreamBytes: bytesPerGB, S3ArchiveBytes: 10 * bytesPerGB},
		{TenantID: uuid.New(), NATSStreamBytes: 3 * bytesPerGB, S3ArchiveBytes: 20 * bytesPerGB},
	}
	agg := c.AggregateInfraCost(samples)

	if agg.TenantCount != 2 {
		t.Fatalf("tenant count = %d, want 2", agg.TenantCount)
	}
	// NATS: (1+3) GB * $0.10 = $0.40.
	if !approx(agg.NATSMonthlyUSD, 0.40) {
		t.Fatalf("nats total = %v, want 0.40", agg.NATSMonthlyUSD)
	}
	// S3: (10+20) GB * $0.023 = $0.69.
	if !approx(agg.S3MonthlyUSD, 0.69) {
		t.Fatalf("s3 total = %v, want 0.69", agg.S3MonthlyUSD)
	}
	if !approx(agg.TotalMonthlyUSD, round2(agg.ClickHouseMonthlyUSD+agg.NATSMonthlyUSD+agg.S3MonthlyUSD)) {
		t.Fatalf("total mismatch: %v", agg.TotalMonthlyUSD)
	}
}

func TestZeroValueUnitCostsIncludesNATS(t *testing.T) {
	c := NewCostCalculator(UnitCosts{})
	if !approx(c.NATSStorageCostUSD(bytesPerGB), 0.10) {
		t.Fatal("zero-value UnitCosts should fall back to DefaultUnitCosts for NATS")
	}
}

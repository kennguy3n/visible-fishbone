package main

import (
	"math"
	"testing"
)

func approx(a, b, tol float64) bool { return math.Abs(a-b) <= tol }

func TestComputeCostZeroDuration(t *testing.T) {
	b := ResourceUsage{DurationSecs: 0, EventsProcessed: 100}.ComputeCost(DefaultPricing())
	if b.TotalMonthlyUSD != 0 || b.PerUserMonthlyUSD != 0 || b.EventsPerMonth != 0 {
		t.Fatalf("zero-duration window must yield zeroed cost, got %+v", b)
	}
}

func TestComputeCostNodeBilling(t *testing.T) {
	// 1s window, no storage, just cluster nodes: cost is purely
	// node-hours so it is independent of the (tiny) window length.
	p := DefaultPricing()
	u := ResourceUsage{
		DurationSecs:  1,
		Tenants:       10,
		NATSNodeCount: 3,
		CHNodeCount:   2,
	}
	b := u.ComputeCost(p)
	wantNATS := 3 * p.EC2NodeHourlyUSD * HoursPerMonth
	wantCH := 2 * p.EC2NodeHourlyUSD * HoursPerMonth
	if !approx(b.NATSMonthlyUSD, wantNATS, 1e-6) {
		t.Errorf("NATS monthly = %v, want %v", b.NATSMonthlyUSD, wantNATS)
	}
	if !approx(b.ClickHouseMonthlyUSD, wantCH, 1e-6) {
		t.Errorf("CH monthly = %v, want %v", b.ClickHouseMonthlyUSD, wantCH)
	}
	// 10 tenants, default users-per-tenant fallback (1) -> 10 users.
	wantPerUser := (wantNATS + wantCH) / 10
	if !approx(b.PerUserMonthlyUSD, wantPerUser, 1e-6) {
		t.Errorf("per-user = %v, want %v", b.PerUserMonthlyUSD, wantPerUser)
	}
}

func TestComputeCostStorageAndCompression(t *testing.T) {
	p := DefaultPricing()
	// 1s window: 1,000,000 archive bytes compressed from 4,000,000.
	u := ResourceUsage{
		DurationSecs:        1,
		EventsProcessed:     1000,
		Tenants:             1,
		UsersPerTenant:      1,
		RetentionDays:       30, // 1 month retained
		CHDiskBytes:         2000,
		S3Objects:           2,
		S3CompressedBytes:   1_000_000,
		S3UncompressedBytes: 4_000_000,
	}
	b := u.ComputeCost(p)

	if !approx(b.CompressionRatio, 4.0, 1e-9) {
		t.Errorf("compression ratio = %v, want 4", b.CompressionRatio)
	}
	if !approx(b.BytesPerEventCH, 2.0, 1e-9) {
		t.Errorf("bytes/event = %v, want 2", b.BytesPerEventCH)
	}
	// Monthly S3 bytes = 1e6 * SecondsPerMonth; retained 1 month.
	monthlyS3GB := 1_000_000 * SecondsPerMonth / bytesPerGB
	wantStorage := monthlyS3GB * p.S3StorageGBMonthUSD
	monthlyObjects := 2.0 * SecondsPerMonth
	wantPut := monthlyObjects / 1000 * p.S3PutPer1000USD
	if !approx(b.S3MonthlyUSD, wantStorage+wantPut, 1e-6) {
		t.Errorf("S3 monthly = %v, want %v", b.S3MonthlyUSD, wantStorage+wantPut)
	}
	if b.EventsPerMonth != 1000*SecondsPerMonth {
		t.Errorf("events/month = %v, want %v", b.EventsPerMonth, 1000*SecondsPerMonth)
	}
}

func TestRetentionMonthsDefault(t *testing.T) {
	if got := (ResourceUsage{}).retentionMonths(); !approx(got, 2.0, 1e-9) {
		t.Errorf("default retentionMonths = %v, want 2 (60 days)", got)
	}
	if got := (ResourceUsage{RetentionDays: 90}).retentionMonths(); !approx(got, 3.0, 1e-9) {
		t.Errorf("90-day retentionMonths = %v, want 3", got)
	}
}

func TestCostSectionVerdict(t *testing.T) {
	// Per-user cost below the upper bound -> PASS on the judged row.
	b := CostBreakdown{PerUserMonthlyUSD: 0.50}
	s := CostSection(b, TargetCostPerUserMonthUSD, competitorCostPerUserMonthUSD)
	var found bool
	for _, m := range s.Metrics {
		if m.Name == "cost / user / month" {
			found = true
			if m.Verdict != VerdictPass {
				t.Errorf("verdict = %s, want PASS", m.Verdict)
			}
		}
	}
	if !found {
		t.Fatal("cost / user / month row missing")
	}
}

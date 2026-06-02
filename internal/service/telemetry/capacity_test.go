package telemetry_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
)

func TestCapacity_AnalyzeUsage_Empty(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()
	f := svc.AnalyzeUsage(context.Background(), tid, nil, 30)
	if f.DailyAvg != 0 {
		t.Errorf("daily_avg = %f, want 0", f.DailyAvg)
	}
	if f.ProjectedTotal != 0 {
		t.Errorf("projected_total = %f, want 0", f.ProjectedTotal)
	}
}

func TestCapacity_AnalyzeUsage_Flat(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	usage := make([]telemetry.TenantUsage, 10)
	for i := range usage {
		usage[i] = telemetry.TenantUsage{
			TenantID:  tid,
			Date:      base.AddDate(0, 0, i),
			EventsDay: 1000,
		}
	}
	f := svc.AnalyzeUsage(context.Background(), tid, usage, 30)
	if f.DailyAvg != 1000 {
		t.Errorf("daily_avg = %f, want 1000", f.DailyAvg)
	}
	if f.GrowthRatePerDay != 0 {
		t.Errorf("growth_rate = %f, want 0", f.GrowthRatePerDay)
	}
	if f.ProjectedTotal != 30000 {
		t.Errorf("projected_total = %f, want 30000", f.ProjectedTotal)
	}
}

func TestCapacity_AnalyzeUsage_Growing(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	usage := []telemetry.TenantUsage{
		{TenantID: tid, Date: base, EventsDay: 100},
		{TenantID: tid, Date: base.AddDate(0, 0, 10), EventsDay: 200},
	}
	f := svc.AnalyzeUsage(context.Background(), tid, usage, 30)
	if f.GrowthRatePerDay != 10 {
		t.Errorf("growth_rate = %f, want 10", f.GrowthRatePerDay)
	}
	if f.ProjectedTotal <= 0 {
		t.Error("projected_total should be positive for growing usage")
	}
}

func TestCapacity_CheckThresholds(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()

	// 85% of starter (10k) → should trigger 80% threshold only.
	alerts := svc.CheckThresholds(context.Background(), tid, 8500, "starter")
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	if alerts[0].Threshold != 0.80 {
		t.Errorf("threshold = %f, want 0.80", alerts[0].Threshold)
	}

	// 96% → should trigger all three thresholds.
	alerts = svc.CheckThresholds(context.Background(), tid, 9600, "starter")
	if len(alerts) != 3 {
		t.Errorf("alerts = %d, want 3", len(alerts))
	}
}

func TestCapacity_CheckThresholds_UnknownTier(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()
	alerts := svc.CheckThresholds(context.Background(), tid, 5000, "unknown")
	if len(alerts) != 0 {
		t.Errorf("alerts = %d for unknown tier, want 0", len(alerts))
	}
}

func TestCapacity_RecommendTier(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()

	// 85% of starter → recommend professional.
	rec := svc.RecommendTier(context.Background(), tid, 8500, "starter")
	if rec == nil {
		t.Fatal("expected recommendation")
	}
	if rec.RecommendTier != "professional" {
		t.Errorf("recommend = %q, want professional", rec.RecommendTier)
	}
	if rec.UsagePercent != 85 {
		t.Errorf("usage_pct = %f, want 85", rec.UsagePercent)
	}

	// 50% of starter → no recommendation.
	rec = svc.RecommendTier(context.Background(), tid, 5000, "starter")
	if rec != nil {
		t.Error("no recommendation expected at 50%")
	}
}

func TestCapacity_GenerateReport(t *testing.T) {
	svc := telemetry.NewCapacityService(nil)
	tid := uuid.New()
	base := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	usage := []telemetry.TenantUsage{
		{TenantID: tid, Date: base, EventsDay: 9000},
		{TenantID: tid, Date: base.AddDate(0, 0, 7), EventsDay: 9500},
	}

	report := svc.GenerateReport(context.Background(), tid, usage, "starter", 30)
	if report.TenantID != tid {
		t.Error("wrong tenant_id")
	}
	if len(report.Alerts) == 0 {
		t.Error("expected alerts for usage near limit")
	}
	if report.Recommendation == nil {
		t.Error("expected tier recommendation")
	}
	if math.IsNaN(report.Forecast.DailyAvg) {
		t.Error("daily_avg is NaN")
	}
}

package metering

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestAssessPerUserCostBands(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts)
	tid := uuid.New()
	cases := []struct {
		name     string
		monthly  float64
		seats    int
		wantBand PerUserCostBand
		wantPer  float64
	}{
		{"within band midpoint", 75, 100, PerUserCostWithin, 0.75},
		{"at floor is within", 30, 100, PerUserCostWithin, 0.30},
		{"at ceiling is within", 120, 100, PerUserCostWithin, 1.20},
		{"under floor", 20, 100, PerUserCostUnder, 0.20},
		{"over ceiling", 200, 100, PerUserCostOver, 2.0},
		{"zero seats undefined", 50, 0, "", 0},
		{"negative cost undefined", -5, 100, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.AssessPerUserCost(tid, tc.monthly, tc.seats)
			if got.Band != tc.wantBand {
				t.Errorf("band = %q, want %q", got.Band, tc.wantBand)
			}
			if !approx(got.CostPerUserUSD, tc.wantPer) {
				t.Errorf("cost/user = %v, want %v", got.CostPerUserUSD, tc.wantPer)
			}
		})
	}
}

// fakeReporter and fakeHistory drive the detector without a DB.
type fakeReporter struct {
	report TenantCostReport
	err    error
}

func (f fakeReporter) TenantReport(context.Context, uuid.UUID) (TenantCostReport, error) {
	return f.report, f.err
}

type fakeHistory struct {
	rows []UsageRecord
	err  error
}

func (f fakeHistory) UsageHistory(context.Context, uuid.UUID, int) ([]UsageRecord, error) {
	return f.rows, f.err
}

// monthlyHistory builds trailing complete-month usage rows for a meter,
// counting back from the month before `now`. values[0] is the most
// recent complete month.
func monthlyHistory(now time.Time, meter Meter, values ...int64) []UsageRecord {
	cur := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	out := make([]UsageRecord, 0, len(values))
	for i, v := range values {
		start := cur.AddDate(0, -(i + 1), 0)
		out = append(out, UsageRecord{
			Meter:       meter,
			PeriodStart: start,
			PeriodEnd:   start.AddDate(0, 1, 0),
			Value:       v,
		})
	}
	return out
}

func newDetector(t *testing.T, rep TenantCostReport, hist []UsageRecord, now time.Time, cfg AnomalyConfig) *CostAnomalyDetector {
	t.Helper()
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	d, err := NewCostAnomalyDetector(fakeReporter{report: rep}, fakeHistory{rows: hist}, calc, cfg)
	if err != nil {
		t.Fatalf("NewCostAnomalyDetector: %v", err)
	}
	d.now = fixedClock(now)
	return d
}

func TestTenantAnomaliesRatioDetection(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tid := uuid.New()

	// Baseline: bandwidth ~ $9.00/mo (100 GB) for 3 complete months.
	hist := monthlyHistory(now, MeterBandwidthProxiedBytes,
		100*bytesPerGB, 100*bytesPerGB, 100*bytesPerGB)

	// Live report projects $90.00/mo (1000 GB) — a 10x spike → critical.
	rep := TenantCostReport{
		TenantID: tid,
		Lines: []CostLine{
			{Meter: MeterBandwidthProxiedBytes, MonthlyCostUSD: 90.0},
		},
	}
	d := newDetector(t, rep, hist, now, AnomalyConfig{})

	got, err := d.TenantAnomalies(context.Background(), tid)
	if err != nil {
		t.Fatalf("TenantAnomalies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 anomaly, got %d (%+v)", len(got), got)
	}
	a := got[0]
	if a.Meter != MeterBandwidthProxiedBytes {
		t.Errorf("meter = %s", a.Meter)
	}
	if a.Severity != AnomalyCritical {
		t.Errorf("severity = %s, want critical (ratio %v)", a.Severity, a.Ratio)
	}
	if !approx(a.BaselineMonthlyUSD, 9.0) {
		t.Errorf("baseline = %v, want 9.0", a.BaselineMonthlyUSD)
	}
	if a.BaselineMonths != 3 {
		t.Errorf("baseline months = %d, want 3", a.BaselineMonths)
	}
}

func TestTenantAnomaliesWithinBaselineNotFlagged(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tid := uuid.New()
	hist := monthlyHistory(now, MeterBandwidthProxiedBytes,
		100*bytesPerGB, 120*bytesPerGB, 80*bytesPerGB)
	// Projected $10.80/mo (120 GB) — within normal variation of the
	// ~$9.00 median, well below the 2x warn ratio.
	rep := TenantCostReport{
		TenantID: tid,
		Lines:    []CostLine{{Meter: MeterBandwidthProxiedBytes, MonthlyCostUSD: 10.80}},
	}
	d := newDetector(t, rep, hist, now, AnomalyConfig{})
	got, err := d.TenantAnomalies(context.Background(), tid)
	if err != nil {
		t.Fatalf("TenantAnomalies: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no anomaly, got %+v", got)
	}
}

func TestTenantAnomaliesNewSpendFloor(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tid := uuid.New()
	// No history for this meter at all → baseline 0. Projected $6/mo
	// clears the $5 new-spend floor → warning.
	rep := TenantCostReport{
		TenantID: tid,
		Lines:    []CostLine{{Meter: MeterLLMTokensUsed, MonthlyCostUSD: 6.0}},
	}
	d := newDetector(t, rep, nil, now, AnomalyConfig{})
	got, err := d.TenantAnomalies(context.Background(), tid)
	if err != nil {
		t.Fatalf("TenantAnomalies: %v", err)
	}
	if len(got) != 1 || got[0].Severity != AnomalyWarning {
		t.Fatalf("want 1 warning new-spend anomaly, got %+v", got)
	}
	if got[0].Ratio != 0 {
		t.Errorf("new-spend anomaly ratio = %v, want 0", got[0].Ratio)
	}
}

func TestTenantAnomaliesBelowNewSpendFloorIgnored(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tid := uuid.New()
	rep := TenantCostReport{
		TenantID: tid,
		Lines:    []CostLine{{Meter: MeterLLMTokensUsed, MonthlyCostUSD: 1.0}},
	}
	d := newDetector(t, rep, nil, now, AnomalyConfig{})
	got, err := d.TenantAnomalies(context.Background(), tid)
	if err != nil {
		t.Fatalf("TenantAnomalies: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no anomaly under new-spend floor, got %+v", got)
	}
}

func TestTenantAnomaliesIncompleteMonthExcludedFromBaseline(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tid := uuid.New()
	// Two complete months at 10 GB, plus an in-progress June row that
	// (if wrongly counted) would skew the baseline. The detector must
	// drop the current month.
	hist := monthlyHistory(now, MeterBandwidthProxiedBytes, 100*bytesPerGB, 100*bytesPerGB)
	curMonth := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	hist = append(hist, UsageRecord{
		Meter:       MeterBandwidthProxiedBytes,
		PeriodStart: curMonth,
		PeriodEnd:   curMonth.AddDate(0, 1, 0),
		Value:       1000 * bytesPerGB,
	})
	rep := TenantCostReport{
		TenantID: tid,
		Lines:    []CostLine{{Meter: MeterBandwidthProxiedBytes, MonthlyCostUSD: 90.0}},
	}
	d := newDetector(t, rep, hist, now, AnomalyConfig{})
	got, err := d.TenantAnomalies(context.Background(), tid)
	if err != nil {
		t.Fatalf("TenantAnomalies: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 anomaly, got %+v", got)
	}
	if got[0].BaselineMonths != 2 || !approx(got[0].BaselineMonthlyUSD, 9.0) {
		t.Errorf("baseline = %v over %d months, want 9.0 over 2", got[0].BaselineMonthlyUSD, got[0].BaselineMonths)
	}
}

func TestTenantAnomaliesPropagatesErrors(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tid := uuid.New()
	calc := NewCostCalculator(DefaultUnitCosts, withCostClock(fixedClock(now)))
	sentinel := errors.New("boom")
	d, err := NewCostAnomalyDetector(fakeReporter{err: sentinel}, fakeHistory{}, calc, AnomalyConfig{})
	if err != nil {
		t.Fatalf("NewCostAnomalyDetector: %v", err)
	}
	if _, err := d.TenantAnomalies(context.Background(), tid); !errors.Is(err, sentinel) {
		t.Fatalf("want sentinel error, got %v", err)
	}
}

func TestNewCostAnomalyDetectorNilDeps(t *testing.T) {
	calc := NewCostCalculator(DefaultUnitCosts)
	if _, err := NewCostAnomalyDetector(nil, fakeHistory{}, calc, AnomalyConfig{}); err == nil {
		t.Error("want error for nil reporter")
	}
	if _, err := NewCostAnomalyDetector(fakeReporter{}, nil, calc, AnomalyConfig{}); err == nil {
		t.Error("want error for nil history")
	}
	if _, err := NewCostAnomalyDetector(fakeReporter{}, fakeHistory{}, nil, AnomalyConfig{}); err == nil {
		t.Error("want error for nil calc")
	}
}

func TestMedian(t *testing.T) {
	cases := []struct {
		in   []float64
		want float64
	}{
		{nil, 0},
		{[]float64{5}, 5},
		{[]float64{3, 1, 2}, 2},
		{[]float64{4, 1, 3, 2}, 2.5},
	}
	for _, tc := range cases {
		if got := median(tc.in); !approx(got, tc.want) {
			t.Errorf("median(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

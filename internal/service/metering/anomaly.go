package metering

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// Cost-anomaly detection and the per-user infra-cost target band.
//
// These extend the metering service's budget guardrails (which gate a
// single meter against a fixed per-tier limit) with two cost-control
// levers the Session 2B SME model needs:
//
//   - CostAnomalyDetector compares a tenant's *projected* monthly spend
//     per meter against its own trailing baseline, so a sudden change
//     in traffic mix (e.g. a misbehaving client driving policy
//     evaluations or proxied bandwidth far above its norm) is alerted
//     on even when it is still nominally under the hard budget.
//   - PerUserCostAssessment scores a tenant's projected monthly infra
//     cost against the $0.30–$1.20 per-user target band so an operator
//     can see at a glance whether a tenant is inside the SME envelope.
//
// Both are read-only and tenant-scoped via the readers they wrap; they
// add no new persistence.

// PerUserCostBand classifies a tenant's projected per-user monthly infra
// cost relative to the SME target envelope.
type PerUserCostBand string

const (
	// PerUserCostUnder means the per-user cost is below the target
	// floor — healthy margin, though it can also flag a tenant whose
	// seat count is overstated relative to real usage.
	PerUserCostUnder PerUserCostBand = "under"
	// PerUserCostWithin means the per-user cost sits inside the target
	// band.
	PerUserCostWithin PerUserCostBand = "within"
	// PerUserCostOver means the per-user cost exceeds the target ceiling
	// — the tenant is eroding margin and should be investigated.
	PerUserCostOver PerUserCostBand = "over"
)

const (
	// TargetCostPerUserMinUSD and TargetCostPerUserMaxUSD bound the
	// Session 2B SME infrastructure-cost target of $0.30–$1.20 per user
	// per month. They are the acceptance envelope the cost model is
	// steered toward (10–20% cloud-proxied traffic, the rest direct).
	TargetCostPerUserMinUSD = 0.30
	TargetCostPerUserMaxUSD = 1.20
)

// PerUserCostAssessment scores a tenant's projected monthly infra cost
// against the per-user target band.
type PerUserCostAssessment struct {
	TenantID uuid.UUID `json:"tenant_id"`
	// Seats is the seat count the cost was divided across.
	Seats int `json:"seats"`
	// MonthlyCostUSD is the tenant's projected monthly infra cost.
	MonthlyCostUSD float64 `json:"monthly_cost_usd"`
	// CostPerUserUSD is MonthlyCostUSD / Seats.
	CostPerUserUSD float64 `json:"cost_per_user_usd"`
	// Band classifies CostPerUserUSD against the target envelope.
	Band PerUserCostBand `json:"band"`
}

// AssessPerUserCost divides a tenant's projected monthly infra cost
// across its seats and classifies the result against the SME target
// band. A non-positive seat count yields a zero assessment with an
// empty band, since per-user cost is undefined without seats.
func (c *CostCalculator) AssessPerUserCost(tenantID uuid.UUID, monthlyCostUSD float64, seats int) PerUserCostAssessment {
	a := PerUserCostAssessment{TenantID: tenantID, Seats: seats, MonthlyCostUSD: round2(monthlyCostUSD)}
	if seats <= 0 || monthlyCostUSD < 0 {
		return a
	}
	a.CostPerUserUSD = round4(monthlyCostUSD / float64(seats))
	switch {
	case a.CostPerUserUSD < TargetCostPerUserMinUSD:
		a.Band = PerUserCostUnder
	case a.CostPerUserUSD > TargetCostPerUserMaxUSD:
		a.Band = PerUserCostOver
	default:
		a.Band = PerUserCostWithin
	}
	return a
}

// AnomalySeverity ranks how far a meter's projected spend has diverged
// from its trailing baseline.
type AnomalySeverity string

const (
	// AnomalyWarning is a moderate divergence worth surfacing.
	AnomalyWarning AnomalySeverity = "warning"
	// AnomalyCritical is a severe divergence that likely needs action.
	AnomalyCritical AnomalySeverity = "critical"
)

// CostAnomaly is one meter whose projected monthly cost diverges from
// its trailing baseline beyond the detector's threshold.
type CostAnomaly struct {
	TenantID uuid.UUID `json:"tenant_id"`
	Meter    Meter     `json:"meter"`
	// BaselineMonthlyUSD is the median monthly cost of this meter over
	// the complete trailing months used as the baseline.
	BaselineMonthlyUSD float64 `json:"baseline_monthly_usd"`
	// ProjectedMonthlyUSD is the current period's projected monthly cost
	// for this meter (from the live cost report).
	ProjectedMonthlyUSD float64 `json:"projected_monthly_usd"`
	// Ratio is ProjectedMonthlyUSD / BaselineMonthlyUSD. It is 0 when
	// the baseline is zero (a newly-active meter), in which case the
	// anomaly is reported on the absolute-floor rule instead.
	Ratio float64 `json:"ratio"`
	// BaselineMonths is the number of complete months that fed the
	// baseline median.
	BaselineMonths int             `json:"baseline_months"`
	Severity       AnomalySeverity `json:"severity"`
}

// AnomalyConfig tunes cost-anomaly detection. The zero value is
// completed with DefaultAnomalyConfig values by NewAnomalyDetector.
type AnomalyConfig struct {
	// WarnRatio is the projected/baseline ratio at or above which a
	// warning anomaly is raised. Must be > 1.
	WarnRatio float64
	// CriticalRatio is the ratio at or above which the anomaly is
	// escalated to critical. Must be >= WarnRatio.
	CriticalRatio float64
	// MinBaselineUSD is the dollar floor a meter's projected monthly
	// cost must clear before a ratio anomaly is raised. It suppresses
	// noise from meters whose absolute spend is rounding-level even when
	// the ratio looks large (e.g. $0.01 → $0.05).
	MinBaselineUSD float64
	// NewSpendFloorUSD is the projected monthly cost above which a meter
	// with no historical baseline (median 0) is flagged as a new-spend
	// anomaly. Without this, a meter that switches on mid-month would
	// never alert because its baseline is undefined.
	NewSpendFloorUSD float64
	// MinBaselineMonths is the minimum number of complete trailing
	// months required before a ratio baseline is trusted.
	MinBaselineMonths int
	// LookbackMonths is how many trailing months of history to pull.
	LookbackMonths int
}

// DefaultAnomalyConfig is the built-in detector tuning.
var DefaultAnomalyConfig = AnomalyConfig{
	WarnRatio:         2.0,
	CriticalRatio:     4.0,
	MinBaselineUSD:    1.0,
	NewSpendFloorUSD:  5.0,
	MinBaselineMonths: 2,
	LookbackMonths:    6,
}

func (cfg AnomalyConfig) withDefaults() AnomalyConfig {
	d := DefaultAnomalyConfig
	if cfg.WarnRatio > 1 {
		d.WarnRatio = cfg.WarnRatio
	}
	if cfg.CriticalRatio >= d.WarnRatio {
		d.CriticalRatio = cfg.CriticalRatio
	}
	if cfg.MinBaselineUSD > 0 {
		d.MinBaselineUSD = cfg.MinBaselineUSD
	}
	if cfg.NewSpendFloorUSD > 0 {
		d.NewSpendFloorUSD = cfg.NewSpendFloorUSD
	}
	if cfg.MinBaselineMonths > 0 {
		d.MinBaselineMonths = cfg.MinBaselineMonths
	}
	if cfg.LookbackMonths > 0 {
		d.LookbackMonths = cfg.LookbackMonths
	}
	return d
}

// tenantReporter produces a tenant's live cost report; satisfied by
// *Reports.
type tenantReporter interface {
	TenantReport(ctx context.Context, tenantID uuid.UUID) (TenantCostReport, error)
}

// usageHistoryReader returns a tenant's monthly-aggregated trailing
// usage; satisfied by *MeteringService.
type usageHistoryReader interface {
	UsageHistory(ctx context.Context, tenantID uuid.UUID, months int) ([]UsageRecord, error)
}

// CostAnomalyDetector compares a tenant's live projected per-meter
// spend against its own trailing baseline and reports divergences. It
// composes the existing Reports orchestrator (for the live projection)
// and the MeteringService usage history; it holds only read surfaces so
// it is safe to share.
type CostAnomalyDetector struct {
	reports tenantReporter
	history usageHistoryReader
	calc    *CostCalculator
	cfg     AnomalyConfig
	now     func() time.Time
}

// NewCostAnomalyDetector wires a detector. reports, history and calc
// must be non-nil. A zero-value cfg is completed with
// DefaultAnomalyConfig.
func NewCostAnomalyDetector(reports tenantReporter, history usageHistoryReader, calc *CostCalculator, cfg AnomalyConfig) (*CostAnomalyDetector, error) {
	if reports == nil || history == nil || calc == nil {
		return nil, fmt.Errorf("metering: anomaly detector: reports, history and calc must be non-nil")
	}
	return &CostAnomalyDetector{
		reports: reports,
		history: history,
		calc:    calc,
		cfg:     cfg.withDefaults(),
		now:     time.Now,
	}, nil
}

// TenantAnomalies returns the cost anomalies for one tenant, comparing
// its live projected per-meter monthly cost against the median monthly
// cost of the same meter over the complete trailing months. Anomalies
// are returned in deterministic meter order.
func (d *CostAnomalyDetector) TenantAnomalies(ctx context.Context, tenantID uuid.UUID) ([]CostAnomaly, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("metering: anomaly detector: tenant id must not be nil")
	}
	report, err := d.reports.TenantReport(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("metering: anomaly detector: report: %w", err)
	}
	hist, err := d.history.UsageHistory(ctx, tenantID, d.cfg.LookbackMonths)
	if err != nil {
		return nil, fmt.Errorf("metering: anomaly detector: history: %w", err)
	}
	return d.detect(tenantID, report, hist, d.now()), nil
}

// detect is the pure comparison core, separated from I/O so it is
// directly unit-testable. currentMonthStart is derived from `now` and
// excludes the in-progress month from the baseline (it is incomplete
// and would understate the median).
func (d *CostAnomalyDetector) detect(tenantID uuid.UUID, report TenantCostReport, hist []UsageRecord, now time.Time) []CostAnomaly {
	currentMonthStart := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)

	// Group complete-month costs per meter.
	costsByMeter := make(map[Meter][]float64)
	for _, r := range hist {
		if !r.PeriodStart.UTC().Before(currentMonthStart) {
			continue // skip the in-progress (or future) month
		}
		costsByMeter[r.Meter] = append(costsByMeter[r.Meter], d.calc.MeterCostUSD(r.Meter, r.Value))
	}

	var out []CostAnomaly
	for _, line := range report.Lines {
		projected := line.MonthlyCostUSD
		samples := costsByMeter[line.Meter]
		baseline := median(samples)

		var anomaly CostAnomaly
		switch {
		case baseline >= d.cfg.MinBaselineUSD && len(samples) >= d.cfg.MinBaselineMonths:
			ratio := projected / baseline
			if ratio < d.cfg.WarnRatio || projected < d.cfg.MinBaselineUSD {
				continue
			}
			anomaly = CostAnomaly{
				Ratio:    round4(ratio),
				Severity: severityForRatio(ratio, d.cfg),
			}
		case projected >= d.cfg.NewSpendFloorUSD:
			// New or previously-negligible meter that has switched on to
			// a material spend: flag it without a ratio (baseline ~0).
			anomaly = CostAnomaly{Severity: AnomalyWarning}
		default:
			continue
		}

		anomaly.TenantID = tenantID
		anomaly.Meter = line.Meter
		anomaly.BaselineMonthlyUSD = round2(baseline)
		anomaly.ProjectedMonthlyUSD = round2(projected)
		anomaly.BaselineMonths = len(samples)
		out = append(out, anomaly)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Meter < out[j].Meter })
	return out
}

// severityForRatio maps a projected/baseline ratio to a severity.
func severityForRatio(ratio float64, cfg AnomalyConfig) AnomalySeverity {
	if ratio >= cfg.CriticalRatio {
		return AnomalyCritical
	}
	return AnomalyWarning
}

// median returns the median of vs, or 0 for an empty slice. It does not
// mutate the input.
func median(vs []float64) float64 {
	n := len(vs)
	if n == 0 {
		return 0
	}
	sorted := make([]float64, n)
	copy(sorted, vs)
	sort.Float64s(sorted)
	mid := n / 2
	if n%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

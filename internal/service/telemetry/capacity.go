package telemetry

import (
	"context"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
)

// TierLimit defines the events-per-day cap for a billing tier.
type TierLimit struct {
	Name  string
	Limit float64
}

// DefaultTierLimits defines per-tier event budgets.
var DefaultTierLimits = []TierLimit{
	{Name: "starter", Limit: 10_000},
	{Name: "professional", Limit: 100_000},
	{Name: "enterprise", Limit: 1_000_000},
}

// DefaultThresholds are the percentage thresholds for alerts.
var DefaultThresholds = []float64{0.80, 0.90, 0.95}

// TenantUsage captures daily telemetry volume for a tenant.
type TenantUsage struct {
	TenantID  uuid.UUID `json:"tenant_id"`
	Date      time.Time `json:"date"`
	EventsDay float64   `json:"events_day"`
}

// GrowthForecast projects future storage consumption.
type GrowthForecast struct {
	TenantID         uuid.UUID `json:"tenant_id"`
	DailyAvg         float64   `json:"daily_avg"`
	GrowthRatePerDay float64   `json:"growth_rate_per_day"`
	ProjectedInDays  int       `json:"projected_in_days"`
	ProjectedTotal   float64   `json:"projected_total"`
}

// TierRecommendation suggests a tier upgrade based on trajectory.
type TierRecommendation struct {
	TenantID       uuid.UUID `json:"tenant_id"`
	CurrentTier    string    `json:"current_tier"`
	RecommendTier  string    `json:"recommend_tier"`
	Reason         string    `json:"reason"`
	UsagePercent   float64   `json:"usage_percent"`
}

// ThresholdAlert is raised when a tenant approaches its tier limit.
type ThresholdAlert struct {
	TenantID    uuid.UUID `json:"tenant_id"`
	Threshold   float64   `json:"threshold"`
	CurrentPct  float64   `json:"current_pct"`
	EventsDay   float64   `json:"events_day"`
	TierLimit   float64   `json:"tier_limit"`
}

// CapacityReport aggregates capacity analysis for a tenant.
type CapacityReport struct {
	TenantID        uuid.UUID           `json:"tenant_id"`
	Usage           []TenantUsage       `json:"usage"`
	Forecast        GrowthForecast      `json:"forecast"`
	Alerts          []ThresholdAlert    `json:"alerts"`
	Recommendation  *TierRecommendation `json:"recommendation,omitempty"`
}

// CapacityService analyses telemetry volume trends and projects
// storage consumption.
type CapacityService struct {
	logger     *slog.Logger
	nowFunc    func() time.Time
	tierLimits []TierLimit
	thresholds []float64
}

// NewCapacityService returns a ready-to-use capacity planner.
func NewCapacityService(logger *slog.Logger) *CapacityService {
	if logger == nil {
		logger = slog.Default()
	}
	return &CapacityService{
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
		tierLimits: DefaultTierLimits,
		thresholds: DefaultThresholds,
	}
}

// SetNowFunc overrides the clock for testing.
func (s *CapacityService) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		s.nowFunc = fn
	}
}

// SetTierLimits overrides the tier limits.
func (s *CapacityService) SetTierLimits(limits []TierLimit) {
	if len(limits) > 0 {
		s.tierLimits = limits
	}
}

// SetThresholds overrides the alert thresholds.
func (s *CapacityService) SetThresholds(t []float64) {
	if len(t) > 0 {
		s.thresholds = t
	}
}

// AnalyzeUsage computes the growth forecast from a series of daily
// usage snapshots. Uses linear regression over the trailing window.
func (s *CapacityService) AnalyzeUsage(
	_ context.Context,
	tenantID uuid.UUID,
	usage []TenantUsage,
	projectionDays int,
) GrowthForecast {
	if projectionDays <= 0 {
		projectionDays = 30
	}
	forecast := GrowthForecast{
		TenantID:        tenantID,
		ProjectedInDays: projectionDays,
	}
	if len(usage) == 0 {
		return forecast
	}

	// Compute daily average.
	var total float64
	for _, u := range usage {
		total += u.EventsDay
	}
	forecast.DailyAvg = total / float64(len(usage))

	// Linear growth rate: (last - first) / days.
	if len(usage) > 1 {
		days := usage[len(usage)-1].Date.Sub(usage[0].Date).Hours() / 24
		if days > 0 {
			forecast.GrowthRatePerDay = (usage[len(usage)-1].EventsDay - usage[0].EventsDay) / days
		}
	}

	// Project total events over the projection window.
	forecast.ProjectedTotal = forecast.DailyAvg*float64(projectionDays) +
		forecast.GrowthRatePerDay*float64(projectionDays)*float64(projectionDays+1)/2

	return forecast
}

// CheckThresholds evaluates current usage against tier limits and
// returns alerts for breached thresholds.
func (s *CapacityService) CheckThresholds(
	_ context.Context,
	tenantID uuid.UUID,
	currentEventsDay float64,
	tier string,
) []ThresholdAlert {
	limit := s.tierLimit(tier)
	if limit <= 0 {
		return nil
	}
	pct := currentEventsDay / limit
	var alerts []ThresholdAlert
	for _, t := range s.thresholds {
		if pct >= t {
			alerts = append(alerts, ThresholdAlert{
				TenantID:   tenantID,
				Threshold:  t,
				CurrentPct: math.Round(pct*10000) / 100, // percent with 2 decimals
				EventsDay:  currentEventsDay,
				TierLimit:  limit,
			})
		}
	}
	return alerts
}

// RecommendTier suggests a tier upgrade based on current usage.
func (s *CapacityService) RecommendTier(
	_ context.Context,
	tenantID uuid.UUID,
	currentEventsDay float64,
	currentTier string,
) *TierRecommendation {
	currentLimit := s.tierLimit(currentTier)
	if currentLimit <= 0 {
		return nil
	}
	pct := currentEventsDay / currentLimit
	if pct < 0.80 {
		return nil
	}

	// Find the next tier with enough headroom.
	for _, tl := range s.tierLimits {
		if tl.Limit > currentLimit && currentEventsDay/tl.Limit < 0.80 {
			return &TierRecommendation{
				TenantID:      tenantID,
				CurrentTier:   currentTier,
				RecommendTier: tl.Name,
				Reason:        "usage exceeds 80% of current tier limit",
				UsagePercent:  math.Round(pct*10000) / 100,
			}
		}
	}
	return nil
}

// GenerateReport produces a full capacity analysis report.
func (s *CapacityService) GenerateReport(
	ctx context.Context,
	tenantID uuid.UUID,
	usage []TenantUsage,
	tier string,
	projectionDays int,
) CapacityReport {
	forecast := s.AnalyzeUsage(ctx, tenantID, usage, projectionDays)

	currentAvg := forecast.DailyAvg
	alerts := s.CheckThresholds(ctx, tenantID, currentAvg, tier)
	rec := s.RecommendTier(ctx, tenantID, currentAvg, tier)

	return CapacityReport{
		TenantID:       tenantID,
		Usage:          usage,
		Forecast:       forecast,
		Alerts:         alerts,
		Recommendation: rec,
	}
}

func (s *CapacityService) tierLimit(tier string) float64 {
	for _, tl := range s.tierLimits {
		if tl.Name == tier {
			return tl.Limit
		}
	}
	return 0
}

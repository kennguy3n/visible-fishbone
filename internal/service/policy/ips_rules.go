package policy

// ips_rules.go is the control-plane management surface for the
// enhanced Suricata IPS rule subsystem (Workstream 3, Step 2). The
// edge (crates/sng-ips) categorises every Suricata rule into a threat
// class and can drop a whole category via
// crate sng_ips::rules::CategorySelection; this service persists the
// per-tenant category enablement the edge enforces and the per-category
// daily hit stats the operator UI renders.
//
// Division of labour with the edge
// ---------------------------------
// The edge owns the *mechanism*: classifying rules and filtering a
// rule set by an enabled-category set (a pure transform, fully unit
// tested in the crate). This service owns the *policy*: which
// categories a tenant has enabled (stored as explicit overrides over a
// default-enabled baseline) and the hit counters. EnabledCategories
// compiles the persisted overrides into the exact set the edge's
// CategorySelection expects, so the two never drift — the category id
// strings here are identical to the crate's RuleCategory serde ids.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IPSRuleCategory is a Suricata rule threat class. The string values
// are wire-identical to the edge's sng_ips::rules::RuleCategory serde
// ids and to the CHECK constraint in migration 050.
type IPSRuleCategory string

const (
	IPSCategoryMalware         IPSRuleCategory = "malware"
	IPSCategoryExploit         IPSRuleCategory = "exploit"
	IPSCategoryLateralMovement IPSRuleCategory = "lateral_movement"
	IPSCategoryC2              IPSRuleCategory = "c2"
	IPSCategoryExfiltration    IPSRuleCategory = "exfiltration"
	IPSCategoryDoS             IPSRuleCategory = "dos"
	IPSCategoryOther           IPSRuleCategory = "other"
)

// AllIPSRuleCategories is every category an operator can toggle, in a
// stable display order. Mirrors RuleCategory::all() on the edge.
func AllIPSRuleCategories() []IPSRuleCategory {
	return []IPSRuleCategory{
		IPSCategoryMalware,
		IPSCategoryExploit,
		IPSCategoryLateralMovement,
		IPSCategoryC2,
		IPSCategoryExfiltration,
		IPSCategoryDoS,
		IPSCategoryOther,
	}
}

// IsValid reports whether c is one of the known categories.
func (c IPSRuleCategory) IsValid() bool {
	switch c {
	case IPSCategoryMalware, IPSCategoryExploit, IPSCategoryLateralMovement,
		IPSCategoryC2, IPSCategoryExfiltration, IPSCategoryDoS, IPSCategoryOther:
		return true
	}
	return false
}

// ErrUnknownIPSCategory is returned when a caller names a category
// that is not in the known set. The handler layer maps it to 400.
var ErrUnknownIPSCategory = errors.New("policy: unknown IPS rule category")

// IPSCategoryStatus is the management-API view of one category for a
// tenant: whether it is enabled and how many rule hits it has seen
// over the recent window.
type IPSCategoryStatus struct {
	Category IPSRuleCategory `json:"category"`
	Enabled  bool            `json:"enabled"`
	// HitsToday and HitsWindow are pulled from the daily stats table.
	// HitsWindow sums every day in the requested lookback (default 7).
	HitsToday  int64 `json:"hits_today"`
	HitsWindow int64 `json:"hits_window"`
}

// IPSDailyHits is one (category, day, hits) point for the per-category
// "hits/day" series the operator UI charts.
type IPSDailyHits struct {
	Category IPSRuleCategory `json:"category"`
	Day      time.Time       `json:"day"`
	Hits     int64           `json:"hits"`
}

// IPSRuleService is the per-tenant IPS rule-category management
// service. It is intentionally thin over the repository: the policy
// (default-enabled baseline + override overlay) lives here so both the
// management API and the bundle compiler get a single, consistent view.
type IPSRuleService struct {
	repo   repository.IPSRuleCategoryRepository
	logger *slog.Logger
	clock  func() time.Time
}

// NewIPSRuleService constructs the service over a repository. A nil
// logger defaults to slog.Default().
func NewIPSRuleService(repo repository.IPSRuleCategoryRepository, logger *slog.Logger) *IPSRuleService {
	if logger == nil {
		logger = slog.Default()
	}
	return &IPSRuleService{
		repo:   repo,
		logger: logger,
		clock:  time.Now,
	}
}

// overridesByCategory loads the tenant's explicit overrides into a
// map keyed by category string.
func (s *IPSRuleService) overridesByCategory(
	ctx context.Context,
	tenantID uuid.UUID,
) (map[string]bool, error) {
	rows, err := s.repo.ListSelections(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list ips category selections: %w", err)
	}
	out := make(map[string]bool, len(rows))
	for _, r := range rows {
		out[r.Category] = r.Enabled
	}
	return out, nil
}

// EnabledCategories returns the set of categories currently enabled for
// the tenant: every category is enabled by default (fail-open) unless an
// explicit override disables it. This is the exact set the edge's
// CategorySelection enforces, so the bundle compiler passes it straight
// through.
func (s *IPSRuleService) EnabledCategories(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]IPSRuleCategory, error) {
	overrides, err := s.overridesByCategory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []IPSRuleCategory
	for _, c := range AllIPSRuleCategories() {
		enabled, ok := overrides[string(c)]
		if !ok || enabled {
			out = append(out, c)
		}
	}
	return out, nil
}

// ListCategories returns the enablement + recent hit stats for every
// category. lookback bounds the hit window (clamped to [1, 90] days;
// 0 means the 7-day default).
func (s *IPSRuleService) ListCategories(
	ctx context.Context,
	tenantID uuid.UUID,
	lookback time.Duration,
) ([]IPSCategoryStatus, error) {
	overrides, err := s.overridesByCategory(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	days := clampLookbackDays(lookback)
	now := s.clock().UTC()
	since := now.AddDate(0, 0, -(days - 1))
	stats, err := s.repo.StatsSince(ctx, tenantID, since)
	if err != nil {
		return nil, fmt.Errorf("ips category stats: %w", err)
	}
	today := dayStart(now)
	windowByCat := make(map[string]int64)
	todayByCat := make(map[string]int64)
	for _, st := range stats {
		windowByCat[st.Category] += st.Hits
		if dayStart(st.Day.UTC()).Equal(today) {
			todayByCat[st.Category] += st.Hits
		}
	}
	out := make([]IPSCategoryStatus, 0, len(AllIPSRuleCategories()))
	for _, c := range AllIPSRuleCategories() {
		enabled, ok := overrides[string(c)]
		if !ok {
			enabled = true // default-enabled baseline
		}
		out = append(out, IPSCategoryStatus{
			Category:   c,
			Enabled:    enabled,
			HitsToday:  todayByCat[string(c)],
			HitsWindow: windowByCat[string(c)],
		})
	}
	return out, nil
}

// SetCategoryEnabled enables or disables one category for a tenant.
// Returns ErrUnknownIPSCategory for an unrecognised category.
func (s *IPSRuleService) SetCategoryEnabled(
	ctx context.Context,
	tenantID uuid.UUID,
	category IPSRuleCategory,
	enabled bool,
) error {
	if !category.IsValid() {
		return ErrUnknownIPSCategory
	}
	if _, err := s.repo.SetEnabled(ctx, tenantID, string(category), enabled); err != nil {
		return fmt.Errorf("set ips category enabled: %w", err)
	}
	s.logger.Info("ips rule category toggled",
		slog.String("tenant_id", tenantID.String()),
		slog.String("category", string(category)),
		slog.Bool("enabled", enabled),
	)
	return nil
}

// RecordHits increments the daily hit counter for a category. Called by
// the IPS alert ingestion path as Suricata alerts are normalised.
// Returns ErrUnknownIPSCategory for an unrecognised category.
func (s *IPSRuleService) RecordHits(
	ctx context.Context,
	tenantID uuid.UUID,
	category IPSRuleCategory,
	when time.Time,
	n int64,
) error {
	if !category.IsValid() {
		return ErrUnknownIPSCategory
	}
	if n <= 0 {
		return nil
	}
	if err := s.repo.AddHits(ctx, tenantID, string(category), when, n); err != nil {
		return fmt.Errorf("record ips category hits: %w", err)
	}
	return nil
}

// DailyHits returns the per-category daily hit series since the start
// of the lookback window, newest day first. Drives the operator
// "hits/day" chart.
func (s *IPSRuleService) DailyHits(
	ctx context.Context,
	tenantID uuid.UUID,
	lookback time.Duration,
) ([]IPSDailyHits, error) {
	days := clampLookbackDays(lookback)
	since := s.clock().UTC().AddDate(0, 0, -(days - 1))
	stats, err := s.repo.StatsSince(ctx, tenantID, since)
	if err != nil {
		return nil, fmt.Errorf("ips daily hits: %w", err)
	}
	out := make([]IPSDailyHits, 0, len(stats))
	for _, st := range stats {
		out = append(out, IPSDailyHits{
			Category: IPSRuleCategory(st.Category),
			Day:      st.Day.UTC(),
			Hits:     st.Hits,
		})
	}
	// Newest day first, then category — deterministic for snapshot tests.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Day.Equal(out[j].Day) {
			return out[i].Day.After(out[j].Day)
		}
		return out[i].Category < out[j].Category
	})
	return out, nil
}

// clampLookbackDays converts a lookback duration into a whole-day count
// in [1, 90], defaulting to 7 when the duration is non-positive.
func clampLookbackDays(d time.Duration) int {
	if d <= 0 {
		return 7
	}
	days := int((d + 24*time.Hour - time.Nanosecond) / (24 * time.Hour)) // ceil
	if days < 1 {
		days = 1
	}
	if days > 90 {
		days = 90
	}
	return days
}

// dayStart truncates a timestamp to midnight UTC.
func dayStart(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

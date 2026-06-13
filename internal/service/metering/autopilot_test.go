package metering

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// --- test doubles ---------------------------------------------------------

type apReporter struct {
	reports map[uuid.UUID]TenantCostReport
	err     error
}

func (f *apReporter) TenantReport(_ context.Context, tenantID uuid.UUID) (TenantCostReport, error) {
	if f.err != nil {
		return TenantCostReport{}, f.err
	}
	r, ok := f.reports[tenantID]
	if !ok {
		return TenantCostReport{TenantID: tenantID, Tier: repository.TenantTierStarter}, nil
	}
	return r, nil
}

type apAnomalies struct {
	byTenant map[uuid.UUID][]CostAnomaly
	err      error
	// reports captures the report passed in, so a test can assert the
	// autopilot reuses the report it already priced rather than forcing
	// a second fetch.
	mu      sync.Mutex
	reports []TenantCostReport
}

func (f *apAnomalies) AnomaliesForReport(_ context.Context, tenantID uuid.UUID, report TenantCostReport) ([]CostAnomaly, error) {
	f.mu.Lock()
	f.reports = append(f.reports, report)
	f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.byTenant[tenantID], nil
}

type capCall struct {
	tenantID uuid.UUID
	limit    BudgetLimit
}

type apCapManager struct {
	mu    sync.Mutex
	calls []capCall
	err   error
}

func (f *apCapManager) SetTenantBudget(_ context.Context, tenantID uuid.UUID, limit BudgetLimit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, capCall{tenantID: tenantID, limit: limit})
	return nil
}

func (f *apCapManager) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

type apGate struct {
	mode     AutoActMode
	byTenant map[uuid.UUID]AutoActMode
}

func (f apGate) AutoAct(_ context.Context, tenantID uuid.UUID) AutoActMode {
	if m, ok := f.byTenant[tenantID]; ok {
		return m
	}
	return f.mode
}

type apAudit struct {
	mu      sync.Mutex
	entries []repository.AuditEntry
	err     error
}

func (f *apAudit) Append(_ context.Context, tenantID uuid.UUID, e repository.AuditEntry) (repository.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return repository.AuditEntry{}, f.err
	}
	e.TenantID = tenantID
	f.entries = append(f.entries, e)
	return e, nil
}

func (f *apAudit) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.entries)
}

type apLister struct {
	tenants []repository.Tenant
	err     error
}

func (f *apLister) List(_ context.Context, page repository.Page) (repository.PageResult[repository.Tenant], error) {
	if f.err != nil {
		return repository.PageResult[repository.Tenant]{}, f.err
	}
	// Single page; cursor empty signals done.
	return repository.PageResult[repository.Tenant]{Items: f.tenants}, nil
}

// --- helpers --------------------------------------------------------------

func newTestAutopilot(t *testing.T, r *apReporter, a *apAnomalies, c *apCapManager) *MarginAutopilot {
	t.Helper()
	e, err := NewMarginAutopilot(r, a, c, nil)
	if err != nil {
		t.Fatalf("NewMarginAutopilot: %v", err)
	}
	return e
}

func findRec(recs []Recommendation, kind RecommendationKind) (Recommendation, bool) {
	for _, r := range recs {
		if r.Kind == kind {
			return r, true
		}
	}
	return Recommendation{}, false
}

// healthyStarterReport: positive margin, every meter well within its
// tier ceiling — the engine must emit nothing for it.
func healthyStarterReport(id uuid.UUID) TenantCostReport {
	return TenantCostReport{
		TenantID:                id,
		Tier:                    repository.TenantTierStarter,
		MonthlyRevenueUSD:       99,
		ProjectedMonthlyCostUSD: 20,
		MarginUSD:               79,
		MarginPct:               0.79,
		Lines: []CostLine{
			{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 100_000, MonthlyCostUSD: 10, HardLimit: 1_000_000},
			{Meter: MeterLLMCalls, Period: PeriodMonthly, ProjectedUsage: 100, MonthlyCostUSD: 10, HardLimit: 1_000},
		},
	}
}

// --- tests ----------------------------------------------------------------

func TestNewMarginAutopilotRequiresDeps(t *testing.T) {
	t.Parallel()
	if _, err := NewMarginAutopilot(nil, &apAnomalies{}, &apCapManager{}, nil); err == nil {
		t.Fatal("expected error for nil reporter")
	}
	if _, err := NewMarginAutopilot(&apReporter{}, nil, &apCapManager{}, nil); err == nil {
		t.Fatal("expected error for nil anomalies")
	}
	if _, err := NewMarginAutopilot(&apReporter{}, &apAnomalies{}, nil, nil); err == nil {
		t.Fatal("expected error for nil budgets")
	}
}

// A trial tenant projected to exhaust a meter whose cap already enforces
// at the tier ceiling must produce the right RecEnforceBudgetCap
// recommendation — recommend-only, no destructive action.
func TestBudgetBreachProducesRecommendation(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:                id,
			Tier:                    repository.TenantTierStarter,
			MonthlyRevenueUSD:       99,
			ProjectedMonthlyCostUSD: 40,
			MarginUSD:               59,
			MarginPct:               0.6,
			Lines: []CostLine{
				// Projected 2M tokens vs the 1M starter ceiling; the cap is
				// already pinned at the ceiling (enforcing).
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 2_000_000, MonthlyCostUSD: 40, HardLimit: 1_000_000, OverBudget: true},
			},
		},
	}}
	caps := &apCapManager{}
	audit := &apAudit{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetAuditLog(audit)
	// No gate → recommend-only.

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	rec, ok := findRec(recs, RecEnforceBudgetCap)
	if !ok {
		t.Fatalf("expected an enforce_budget_cap recommendation, got %+v", recs)
	}
	if rec.Mode != RecModeRecommend {
		t.Errorf("mode = %q, want recommend", rec.Mode)
	}
	if rec.Applied {
		t.Error("recommendation should not be applied")
	}
	if rec.Meter != MeterLLMTokensUsed {
		t.Errorf("meter = %q, want %q", rec.Meter, MeterLLMTokensUsed)
	}
	if rec.CapHardLimit != 1_000_000 {
		t.Errorf("cap hard limit = %d, want 1000000", rec.CapHardLimit)
	}
	if rec.Severity != SeverityCritical { // 2M >= 2x ceiling => critical
		t.Errorf("severity = %q, want critical", rec.Severity)
	}
	if caps.callCount() != 0 {
		t.Errorf("recommend mode must not mutate budgets, got %d cap writes", caps.callCount())
	}
	if audit.count() == 0 {
		t.Error("expected an audit entry for the recommendation")
	}
}

// An opted-in (rollout=enforce) trial tenant whose meter is uncapped (or
// loosened above the ceiling) gets the hard cap installed/tightened to
// the tier ceiling.
func TestOptedInTenantGetsCapEnforced(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:                id,
			Tier:                    repository.TenantTierStarter,
			MonthlyRevenueUSD:       99,
			ProjectedMonthlyCostUSD: 60,
			MarginUSD:               39,
			MarginPct:               0.39,
			Lines: []CostLine{
				// Uncapped (HardLimit 0) but projected past the 1M ceiling.
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 1_500_000, MonthlyCostUSD: 60, HardLimit: 0},
			},
		},
	}}
	caps := &apCapManager{}
	audit := &apAudit{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetAuditLog(audit)
	e.SetGate(apGate{mode: AutoActEnforce})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	rec, ok := findRec(recs, RecEnforceBudgetCap)
	if !ok {
		t.Fatalf("expected an enforce_budget_cap recommendation, got %+v", recs)
	}
	if rec.Mode != RecModeAuto {
		t.Errorf("mode = %q, want auto", rec.Mode)
	}
	if !rec.Applied {
		t.Error("recommendation should be applied")
	}
	if caps.callCount() != 1 {
		t.Fatalf("expected exactly one cap write, got %d", caps.callCount())
	}
	got := caps.calls[0]
	if got.tenantID != id {
		t.Errorf("cap write tenant = %s, want %s", got.tenantID, id)
	}
	if got.limit.Meter != MeterLLMTokensUsed || got.limit.HardLimit != 1_000_000 {
		t.Errorf("cap write = %+v, want meter=%s hard=1000000", got.limit, MeterLLMTokensUsed)
	}
	if got.limit.Period != PeriodMonthly {
		t.Errorf("cap write period = %q, want monthly", got.limit.Period)
	}
	if s := e.Stats(); s.CapsEnforced != 1 {
		t.Errorf("CapsEnforced = %d, want 1", s.CapsEnforced)
	}
}

// A healthy tenant (positive margin, within all ceilings, no anomalies)
// must generate no recommendations and write nothing — no noise.
func TestHealthyTenantGetsNothing(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{id: healthyStarterReport(id)}}
	caps := &apCapManager{}
	audit := &apAudit{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetAuditLog(audit)
	e.SetGate(apGate{mode: AutoActEnforce}) // even opted-in, nothing to do

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("healthy tenant produced %d recommendations: %+v", len(recs), recs)
	}
	if caps.callCount() != 0 {
		t.Errorf("healthy tenant triggered %d cap writes", caps.callCount())
	}
	if audit.count() != 0 {
		t.Errorf("healthy tenant produced %d audit entries", audit.count())
	}
}

// rollout=monitor must dry-run the auto action: a recommendation is
// produced but no budget is mutated.
func TestMonitorModeDoesNotEnforce(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:          id,
			Tier:              repository.TenantTierStarter,
			MonthlyRevenueUSD: 99,
			MarginUSD:         50,
			Lines: []CostLine{
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 1_500_000, MonthlyCostUSD: 30, HardLimit: 0},
			},
		},
	}}
	caps := &apCapManager{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetGate(apGate{mode: AutoActDryRun})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	rec, ok := findRec(recs, RecEnforceBudgetCap)
	if !ok {
		t.Fatalf("expected an enforce_budget_cap recommendation, got %+v", recs)
	}
	if rec.Mode != RecModeRecommend || rec.Applied {
		t.Errorf("monitor dry-run must be recommend/!applied, got mode=%q applied=%v", rec.Mode, rec.Applied)
	}
	if caps.callCount() != 0 {
		t.Errorf("monitor dry-run must not mutate budgets, got %d cap writes", caps.callCount())
	}
}

// A trial meter whose effective cap is already at/below the ceiling does
// not get rewritten even when opted-in: the breach is already contained,
// so the auto action would be cosmetic. The recommendation is emitted
// recommend-only (an upsell/review signal).
func TestEnforceSkipsAlreadyTightCap(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:          id,
			Tier:              repository.TenantTierStarter,
			MonthlyRevenueUSD: 99,
			MarginUSD:         50,
			Lines: []CostLine{
				// Cap already at the ceiling; projected exceeds it.
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 1_200_000, MonthlyCostUSD: 30, HardLimit: 1_000_000, OverBudget: true},
			},
		},
	}}
	caps := &apCapManager{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetGate(apGate{mode: AutoActEnforce})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	rec, ok := findRec(recs, RecEnforceBudgetCap)
	if !ok {
		t.Fatalf("expected an enforce_budget_cap recommendation, got %+v", recs)
	}
	if rec.Mode != RecModeRecommend || rec.Applied {
		t.Errorf("already-tight cap must stay recommend/!applied, got mode=%q applied=%v", rec.Mode, rec.Applied)
	}
	if caps.callCount() != 0 {
		t.Errorf("must not rewrite an already-tight cap, got %d cap writes", caps.callCount())
	}
}

// When an operator override has moved a meter onto a different budget
// period than its tier default, the tier ceiling (denominated in the
// default period) and the cost-report projection (denominated in the
// override period) are not comparable. The autopilot must defer to the
// operator: emit no enforce_budget_cap recommendation and never pin the
// cross-period ceiling onto the overridden budget, even under enforce.
func TestPeriodMismatchSkipsBudgetEnforcement(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:          id,
			Tier:              repository.TenantTierStarter,
			MonthlyRevenueUSD: 99,
			MarginUSD:         50,
			Lines: []CostLine{
				// URLCatLookups ceiling is 100k DAILY, but this tenant's
				// effective budget resolves monthly (operator override),
				// with a 3M monthly cap and a 2.5M monthly projection.
				{Meter: MeterURLCatLookups, Period: PeriodMonthly, ProjectedUsage: 2_500_000, MonthlyCostUSD: 30, HardLimit: 3_000_000, OverBudget: false},
			},
		},
	}}
	caps := &apCapManager{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetGate(apGate{mode: AutoActEnforce})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	if rec, ok := findRec(recs, RecEnforceBudgetCap); ok {
		t.Errorf("must not emit a cross-period budget recommendation, got %+v", rec)
	}
	if caps.callCount() != 0 {
		t.Errorf("must not clobber a cross-period override, got %d cap writes", caps.callCount())
	}
}

// The autopilot prices a tenant once and hands that same report to the
// anomaly detector, instead of triggering a second TenantReport fetch.
func TestAnomalyEvaluationReusesReport(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	want := TenantCostReport{
		TenantID:          id,
		Tier:              repository.TenantTierStarter,
		MonthlyRevenueUSD: 99,
		MarginUSD:         50,
		Lines:             []CostLine{{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 100, MonthlyCostUSD: 1, HardLimit: 1_000_000}},
	}
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{id: want}}
	anom := &apAnomalies{}
	e := newTestAutopilot(t, rep, anom, &apCapManager{})

	if _, err := e.EvaluateTenant(context.Background(), id); err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	if len(anom.reports) != 1 {
		t.Fatalf("anomaly detector called %d times, want exactly 1 (no redundant fetch)", len(anom.reports))
	}
	if anom.reports[0].TenantID != want.TenantID || anom.reports[0].MarginUSD != want.MarginUSD {
		t.Errorf("anomaly detector got a different report than the one priced: %+v", anom.reports[0])
	}
}

// If the cap write fails under enforce, the action fails safe to a
// recommendation rather than aborting the evaluation.
func TestEnforceFailsafeOnCapError(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:          id,
			Tier:              repository.TenantTierStarter,
			MonthlyRevenueUSD: 99,
			MarginUSD:         50,
			Lines: []CostLine{
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 1_500_000, MonthlyCostUSD: 30, HardLimit: 0},
			},
		},
	}}
	caps := &apCapManager{err: errors.New("store down")}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetGate(apGate{mode: AutoActEnforce})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant must not fail on cap write error: %v", err)
	}
	rec, ok := findRec(recs, RecEnforceBudgetCap)
	if !ok {
		t.Fatalf("expected an enforce_budget_cap recommendation, got %+v", recs)
	}
	if rec.Mode != RecModeRecommend || rec.Applied {
		t.Errorf("failed enforce must degrade to recommend/!applied, got mode=%q applied=%v", rec.Mode, rec.Applied)
	}
}

// A loss-making tenant gets a throttle recommendation for its most
// expensive meter plus an upsell signal — both recommend-only even when
// opted into auto-enforce (auto-throttling a paying tenant is unsafe).
func TestLossMakingTenantThrottleAndUpsell(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:                id,
			Tier:                    repository.TenantTierProfessional,
			MonthlyRevenueUSD:       499,
			ProjectedMonthlyCostUSD: 650,
			MarginUSD:               -151,
			MarginPct:               -0.30,
			Lines: []CostLine{
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 4_000_000, MonthlyCostUSD: 200, HardLimit: 5_000_000},
				{Meter: MeterBandwidthProxiedBytes, Period: PeriodMonthly, ProjectedUsage: 9_000_000, MonthlyCostUSD: 450, HardLimit: 0},
			},
		},
	}}
	caps := &apCapManager{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	e.SetGate(apGate{mode: AutoActEnforce})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	throttle, ok := findRec(recs, RecThrottleMeter)
	if !ok {
		t.Fatalf("expected a throttle_meter recommendation, got %+v", recs)
	}
	if throttle.Meter != MeterBandwidthProxiedBytes {
		t.Errorf("throttle meter = %q, want the most expensive %q", throttle.Meter, MeterBandwidthProxiedBytes)
	}
	if throttle.Mode != RecModeRecommend || throttle.Applied {
		t.Error("throttle must be recommend-only and never applied")
	}
	upsell, ok := findRec(recs, RecOpenUpsell)
	if !ok {
		t.Fatalf("expected an open_upsell recommendation, got %+v", recs)
	}
	if upsell.Mode != RecModeRecommend {
		t.Error("upsell must be recommend-only")
	}
	// Non-trial tenant: no budget-cap action at all.
	if _, ok := findRec(recs, RecEnforceBudgetCap); ok {
		t.Error("non-trial tenant must not get a budget-cap recommendation")
	}
	if caps.callCount() != 0 {
		t.Errorf("loss-making path must never mutate budgets, got %d cap writes", caps.callCount())
	}
}

// A flagged cost anomaly produces a recommend-only review recommendation
// with the detector's severity carried through.
func TestAnomalyProducesReviewRecommendation(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{id: healthyStarterReport(id)}}
	anom := &apAnomalies{byTenant: map[uuid.UUID][]CostAnomaly{
		id: {{
			TenantID:            id,
			Meter:               MeterURLCatLookups,
			BaselineMonthlyUSD:  5,
			ProjectedMonthlyUSD: 30,
			Severity:            AnomalyCritical,
		}},
	}}
	e := newTestAutopilot(t, rep, anom, &apCapManager{})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	rec, ok := findRec(recs, RecReviewAnomaly)
	if !ok {
		t.Fatalf("expected a review_anomaly recommendation, got %+v", recs)
	}
	if rec.Mode != RecModeRecommend {
		t.Error("anomaly review must be recommend-only")
	}
	if rec.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", rec.Severity)
	}
	if rec.Meter != MeterURLCatLookups {
		t.Errorf("meter = %q, want %q", rec.Meter, MeterURLCatLookups)
	}
}

// An anomaly read failure must not drop the budget/margin recommendations
// already computed for the tenant.
func TestAnomalyErrorDoesNotDropOtherRecs(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:          id,
			Tier:              repository.TenantTierStarter,
			MonthlyRevenueUSD: 99,
			MarginUSD:         50,
			Lines: []CostLine{
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 2_000_000, MonthlyCostUSD: 40, HardLimit: 1_000_000, OverBudget: true},
			},
		},
	}}
	anom := &apAnomalies{err: errors.New("history unavailable")}
	e := newTestAutopilot(t, rep, anom, &apCapManager{})

	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	if _, ok := findRec(recs, RecEnforceBudgetCap); !ok {
		t.Errorf("budget recommendation must survive an anomaly read failure, got %+v", recs)
	}
}

// A failed cost report aborts the evaluation (it is the engine's
// foundational read; without it there is nothing to decide on).
func TestReportErrorAbortsEvaluation(t *testing.T) {
	t.Parallel()
	rep := &apReporter{err: errors.New("pool exhausted")}
	e := newTestAutopilot(t, rep, &apAnomalies{}, &apCapManager{})
	if _, err := e.EvaluateTenant(context.Background(), uuid.New()); err == nil {
		t.Fatal("expected an error when the cost report fails")
	}
}

func TestEvaluateTenantRejectsNilID(t *testing.T) {
	t.Parallel()
	e := newTestAutopilot(t, &apReporter{}, &apAnomalies{}, &apCapManager{})
	if _, err := e.EvaluateTenant(context.Background(), uuid.Nil); err == nil {
		t.Fatal("expected an error for the nil tenant id")
	}
}

// Reconcile evaluates every active tenant and skips suspended/deleted
// ones, and the activity-tiered planner reduces the per-cycle fan-out on
// later cycles while cycle 0 still does a full sweep.
func TestReconcileActivityTiered(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	active := now.Add(-1 * time.Hour)        // TierActive
	idle := now.Add(-48 * time.Hour)         // TierIdle
	dormant := now.Add(-30 * 24 * time.Hour) // TierDormant

	activeID, idleID, dormantID, suspendedID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	tenants := []repository.Tenant{
		{ID: activeID, Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter, LastActiveAt: &active},
		{ID: idleID, Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter, LastActiveAt: &idle},
		{ID: dormantID, Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter, LastActiveAt: &dormant},
		{ID: suspendedID, Status: repository.TenantStatusSuspended, Tier: repository.TenantTierStarter, LastActiveAt: &active},
	}
	reports := map[uuid.UUID]TenantCostReport{}
	for _, tn := range tenants {
		reports[tn.ID] = healthyStarterReport(tn.ID)
	}
	rep := &apReporter{reports: reports}
	e := newTestAutopilot(t, rep, &apAnomalies{}, &apCapManager{})
	e.SetTenantLister(&apLister{tenants: tenants})
	e.SetClock(fixedClock(now))
	planner := tenancy.DefaultPlanner()
	e.WithDormancyPlanner(&planner)

	// Cycle 0: full sweep over the three active tenants (suspended skipped).
	if err := e.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile cycle 0: %v", err)
	}
	if s := e.Stats(); s.TenantsVisited != 3 {
		t.Fatalf("cycle 0 visited = %d, want 3", s.TenantsVisited)
	}

	// Cycle 1: active visited; idle (every 10) and dormant (every 100)
	// both skipped.
	if err := e.Reconcile(context.Background()); err != nil {
		t.Fatalf("Reconcile cycle 1: %v", err)
	}
	s := e.Stats()
	if s.TenantsVisited != 4 { // 3 from cycle 0 + 1 active on cycle 1
		t.Errorf("after cycle 1 visited = %d, want 4", s.TenantsVisited)
	}
	if s.SkippedIdle != 1 {
		t.Errorf("SkippedIdle = %d, want 1", s.SkippedIdle)
	}
	if s.SkippedDormant != 1 {
		t.Errorf("SkippedDormant = %d, want 1", s.SkippedDormant)
	}
	if s.Cycles != 2 {
		t.Errorf("Cycles = %d, want 2", s.Cycles)
	}
}

// Without a planner the sweep visits every active tenant every cycle —
// the fail-safe "more work, never less" default.
func TestReconcileNoPlannerVisitsAll(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	old := now.Add(-365 * 24 * time.Hour)
	a, b := uuid.New(), uuid.New()
	tenants := []repository.Tenant{
		{ID: a, Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter, LastActiveAt: &old},
		{ID: b, Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter, LastActiveAt: nil},
	}
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{a: healthyStarterReport(a), b: healthyStarterReport(b)}}
	e := newTestAutopilot(t, rep, &apAnomalies{}, &apCapManager{})
	e.SetTenantLister(&apLister{tenants: tenants})
	e.SetClock(fixedClock(now))

	for i := 0; i < 3; i++ {
		if err := e.Reconcile(context.Background()); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
	}
	if s := e.Stats(); s.TenantsVisited != 6 { // 2 tenants * 3 cycles
		t.Errorf("visited = %d, want 6", s.TenantsVisited)
	}
}

func TestReconcileRequiresLister(t *testing.T) {
	t.Parallel()
	e := newTestAutopilot(t, &apReporter{}, &apAnomalies{}, &apCapManager{})
	if err := e.Reconcile(context.Background()); err == nil {
		t.Fatal("expected an error when no tenant lister is wired")
	}
}

// A nil gate keeps the engine recommend-only even when a meter would
// otherwise be an enforce candidate.
func TestNilGateIsRecommendOnly(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	rep := &apReporter{reports: map[uuid.UUID]TenantCostReport{
		id: {
			TenantID:          id,
			Tier:              repository.TenantTierStarter,
			MonthlyRevenueUSD: 99,
			MarginUSD:         50,
			Lines: []CostLine{
				{Meter: MeterLLMTokensUsed, Period: PeriodMonthly, ProjectedUsage: 1_500_000, MonthlyCostUSD: 30, HardLimit: 0},
			},
		},
	}}
	caps := &apCapManager{}
	e := newTestAutopilot(t, rep, &apAnomalies{}, caps)
	// No gate wired.
	recs, err := e.EvaluateTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("EvaluateTenant: %v", err)
	}
	rec, ok := findRec(recs, RecEnforceBudgetCap)
	if !ok {
		t.Fatalf("expected an enforce_budget_cap recommendation, got %+v", recs)
	}
	if rec.Applied || rec.Mode != RecModeRecommend {
		t.Error("nil gate must be recommend-only")
	}
	if caps.callCount() != 0 {
		t.Errorf("nil gate must not mutate budgets, got %d cap writes", caps.callCount())
	}
}

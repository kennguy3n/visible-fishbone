package metering

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// Margin/cost autopilot (WS-7).
//
// The metering engine already SURFACES underwater tenants (the cost
// report's negative MarginUSD), over-budget meters (CostLine.OverBudget)
// and run-rate surges (CostAnomalyDetector). Acting on any of them was
// entirely manual. At ~5000 trials that does not scale, so this engine
// turns those read-only signals into actionable, audited NoOps
// recommendations and — for a tenant that has explicitly opted in via
// the staged-rollout gate — a single narrow, fail-safe auto action.
//
// Coach-first by construction:
//
//   - RECOMMEND is the default for every tenant and every action. The
//     engine writes a structured Recommendation and an immutable audit
//     entry and takes NO destructive action.
//   - The ONLY auto-eligible (state-changing) action is tightening a
//     TRIAL tenant's hard budget cap down to its tier policy ceiling on
//     a meter it is projected to blow past — and only when the tenant's
//     margin_autopilot rollout state is enforce. It is fail-safe: it
//     only ever installs a missing cap or tightens a loosened one to the
//     policy ceiling, never raises or removes a cap, and never writes
//     when the existing cap is already at least as tight (so it can
//     never be cosmetic churn).
//   - Throttling a paying tenant's meter and opening an upsell signal
//     are recommend-only regardless of opt-in: auto-throttling live
//     capacity could break a customer's business, so a human decides
//     (mirrors the CASB NoOps engine keeping the block verb recommend-
//     only). Cost anomalies are likewise recommend-only — they need
//     investigation, not blind enforcement.
//
// It reuses the existing meter / budget / anomaly / cost-report types
// wholesale and invents no billing system: every dollar figure is the
// projection the cost report already computes.

// RecommendationKind enumerates the autopilot's action categories.
type RecommendationKind string

const (
	// RecEnforceBudgetCap — a TRIAL tenant is projected to exhaust a
	// meter's tier policy ceiling. Recommend (and, when opted in,
	// auto-apply) pinning the hard cap at that ceiling.
	RecEnforceBudgetCap RecommendationKind = "enforce_budget_cap"
	// RecThrottleMeter — a loss-making tenant's single most expensive
	// meter. Recommend throttling it. Always recommend-only.
	RecThrottleMeter RecommendationKind = "throttle_meter"
	// RecOpenUpsell — a loss-making tenant whose projected cost exceeds
	// its tier revenue. Recommend opening an upsell signal. Always
	// recommend-only (non-destructive by nature).
	RecOpenUpsell RecommendationKind = "open_upsell"
	// RecReviewAnomaly — a flagged cost anomaly (run-rate surge vs the
	// trailing baseline). Recommend investigation. Always recommend-only.
	RecReviewAnomaly RecommendationKind = "review_anomaly"
)

// RecommendationMode distinguishes a recommendation an operator must act
// on from an action the engine applied automatically. It mirrors
// repository.ActionMode (the CASB NoOps vocabulary) without coupling the
// two pipelines.
type RecommendationMode string

const (
	RecModeRecommend RecommendationMode = "recommend"
	RecModeAuto      RecommendationMode = "auto"
)

// RecommendationSeverity ranks how urgently a recommendation needs
// attention.
type RecommendationSeverity string

const (
	SeverityInfo     RecommendationSeverity = "info"
	SeverityWarning  RecommendationSeverity = "warning"
	SeverityCritical RecommendationSeverity = "critical"
)

// Recommendation is one actionable, audited verdict the autopilot
// emitted for a tenant. It is the durable record (mirrored into the
// audit log) AND the value returned to a caller (operator console /
// on-demand evaluation), so it carries both the decision and the
// numeric context that justified it.
type Recommendation struct {
	TenantID uuid.UUID             `json:"tenant_id"`
	Tier     repository.TenantTier `json:"tier"`
	Kind     RecommendationKind    `json:"kind"`
	// Meter is the meter the recommendation concerns, or "" for a
	// tenant-wide one (open_upsell).
	Meter    Meter                  `json:"meter,omitempty"`
	Mode     RecommendationMode     `json:"mode"`
	Severity RecommendationSeverity `json:"severity"`
	// Applied is true only when Mode==auto AND the engine actually
	// mutated state (wrote a tightened/installed budget cap). A
	// recommendation, a monitor dry-run, or an auto action that found the
	// cap already tight enough all leave it false.
	Applied bool `json:"applied"`
	// CapHardLimit is the hard cap (per the meter's period) the engine
	// set or recommends, for RecEnforceBudgetCap. 0 otherwise.
	CapHardLimit int64 `json:"cap_hard_limit,omitempty"`
	// ProjectedMonthlyCostUSD is the tenant's projected monthly cost
	// (open_upsell / throttle) or the meter's (enforce/anomaly).
	ProjectedMonthlyCostUSD float64 `json:"projected_monthly_cost_usd,omitempty"`
	// MarginUSD / MarginPct are the tenant-level margin figures, set on
	// loss-driven recommendations (throttle / upsell).
	MarginUSD float64   `json:"margin_usd,omitempty"`
	MarginPct float64   `json:"margin_pct,omitempty"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// AutoActMode is the resolved opt-in decision for a tenant's narrow auto
// action, decoupled from the rollout package so metering does not depend
// on it. The wiring layer maps a rollout state onto these.
type AutoActMode int

const (
	// AutoActRecommend is the default: recommend-only, no enforcement.
	// A nil gate resolves here, so the safe posture holds when the gate
	// is not wired.
	AutoActRecommend AutoActMode = iota
	// AutoActDryRun records the would-have auto action as a recommendation
	// and takes no enforcement action (rollout=monitor).
	AutoActDryRun
	// AutoActEnforce applies the narrow auto action (rollout=enforce).
	AutoActEnforce
)

// AutopilotGate resolves whether a tenant has opted into the narrow auto
// action. It is the staged-enablement seam: *rollout.Service is adapted
// onto it at the wiring site. A nil gate means recommend-only for every
// tenant — the fail-safe default that keeps a fresh deployment from ever
// auto-mutating a budget on upgrade.
type AutopilotGate interface {
	AutoAct(ctx context.Context, tenantID uuid.UUID) AutoActMode
}

// autopilotReporter produces a tenant's live cost report (margin,
// per-meter projection and effective caps). Satisfied by *Reports.
type autopilotReporter interface {
	TenantReport(ctx context.Context, tenantID uuid.UUID) (TenantCostReport, error)
}

// autopilotAnomalyReader returns a tenant's cost anomalies given an
// already-built cost report, so the autopilot can reuse the report it
// just priced instead of forcing a second TenantReport round trip.
// Satisfied by *CostAnomalyDetector.
type autopilotAnomalyReader interface {
	AnomaliesForReport(ctx context.Context, tenantID uuid.UUID, report TenantCostReport) ([]CostAnomaly, error)
}

// autopilotCapManager is the narrow budget surface the engine needs to
// apply a cap. Satisfied by *BudgetEnforcer. SetTenantBudget is the only
// mutating call the autopilot ever makes.
type autopilotCapManager interface {
	SetTenantBudget(ctx context.Context, tenantID uuid.UUID, limit BudgetLimit) error
}

// autopilotAuditSink is the optional audit-log boundary. Satisfied by
// repository.AuditLogRepository. A nil sink disables audit (the
// recommendation is still returned to the caller), so the audit plane is
// never a hard dependency.
type autopilotAuditSink interface {
	Append(ctx context.Context, tenantID uuid.UUID, e repository.AuditEntry) (repository.AuditEntry, error)
}

// autopilotTenantLister enumerates tenants for the periodic sweep.
// Satisfied by repository.TenantRepository.
type autopilotTenantLister interface {
	List(ctx context.Context, page repository.Page) (repository.PageResult[repository.Tenant], error)
}

// MarginAutopilot is the per-tenant margin/cost NoOps engine. It is
// stateless beyond its dependencies (and the sweep cycle counter /
// stats) and safe for concurrent use.
type MarginAutopilot struct {
	reports   autopilotReporter
	anomalies autopilotAnomalyReader
	budgets   autopilotCapManager
	tenants   autopilotTenantLister // required only for Reconcile
	gate      AutopilotGate         // nil => recommend-only
	audit     autopilotAuditSink    // nil => no audit sink
	planner   *tenancy.SweepPlanner // nil => visit every active tenant
	logger    *slog.Logger
	nowFunc   func() time.Time

	// trialTiers is the set of tiers treated as "trial" for the
	// budget-cap auto action. Defaults to {starter} — the entry tier the
	// 5000-SME model's dormant trials live on.
	trialTiers map[repository.TenantTier]bool

	stats autopilotCounters
}

// NewMarginAutopilot constructs the engine. reports, anomalies and
// budgets are required; tenants (the sweep enumerator), gate, audit and
// planner are optional and wired via the With/Set methods.
func NewMarginAutopilot(
	reports autopilotReporter,
	anomalies autopilotAnomalyReader,
	budgets autopilotCapManager,
	logger *slog.Logger,
) (*MarginAutopilot, error) {
	if reports == nil || anomalies == nil || budgets == nil {
		return nil, fmt.Errorf("metering: margin autopilot: reports, anomalies and budgets must be non-nil")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &MarginAutopilot{
		reports:    reports,
		anomalies:  anomalies,
		budgets:    budgets,
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
		trialTiers: map[repository.TenantTier]bool{repository.TenantTierStarter: true},
	}, nil
}

// SetClock overrides the wall clock for tests.
func (e *MarginAutopilot) SetClock(f func() time.Time) {
	if f != nil {
		e.nowFunc = f
	}
}

// SetGate wires the staged-enablement gate for the narrow auto action.
// A nil gate keeps the recommend-only default.
func (e *MarginAutopilot) SetGate(g AutopilotGate) { e.gate = g }

// SetAuditLog wires the optional audit-log sink.
func (e *MarginAutopilot) SetAuditLog(a autopilotAuditSink) { e.audit = a }

// SetTenantLister wires the tenant enumerator the Reconcile sweep needs.
func (e *MarginAutopilot) SetTenantLister(l autopilotTenantLister) { e.tenants = l }

// SetTrialTiers overrides which tiers are treated as trial for the
// budget-cap auto action. Empty input is ignored (the default holds).
func (e *MarginAutopilot) SetTrialTiers(tiers ...repository.TenantTier) {
	if len(tiers) == 0 {
		return
	}
	m := make(map[repository.TenantTier]bool, len(tiers))
	for _, t := range tiers {
		m[t] = true
	}
	e.trialTiers = m
}

// WithDormancyPlanner makes the periodic Reconcile sweep activity-tiered
// using the shared SweepPlanner: active tenants are re-evaluated every
// cycle, idle/dormant ones at a reduced cadence, instead of re-pricing
// all ~5000 tenants every cycle. A nil planner keeps the legacy
// every-active-tenant fan-out, so wiring is fail-safe. The planner still
// bounds how stale any tier's evaluation can get, so a runaway dormant
// trial is always caught within that bound. Returns the receiver for
// chaining.
func (e *MarginAutopilot) WithDormancyPlanner(planner *tenancy.SweepPlanner) *MarginAutopilot {
	if planner != nil {
		e.planner = planner
	}
	return e
}

// EvaluateTenant runs the full pipeline for one tenant: it prices the
// tenant, derives the budget / margin / anomaly recommendations, applies
// the narrow auto action when the tenant has opted in, and audits every
// recommendation. The returned slice is the same set that was audited.
// A healthy tenant yields an empty slice and writes nothing.
func (e *MarginAutopilot) EvaluateTenant(ctx context.Context, tenantID uuid.UUID) ([]Recommendation, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	report, err := e.reports.TenantReport(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("metering: autopilot: tenant report: %w", err)
	}
	now := e.nowFunc()
	mode := e.autoActMode(ctx, tenantID)

	var recs []Recommendation
	recs = append(recs, e.budgetRecommendations(ctx, tenantID, report, mode, now)...)
	recs = append(recs, e.marginRecommendations(tenantID, report, now)...)
	recs = append(recs, e.anomalyRecommendations(ctx, tenantID, report, now)...)

	for i := range recs {
		e.record(ctx, recs[i])
	}
	return recs, nil
}

// budgetRecommendations emits a RecEnforceBudgetCap for each meter a
// TRIAL tenant is projected to blow past its tier policy ceiling on. The
// auto action (opted-in tenants only) pins the hard cap at the ceiling,
// and only when that is an install (no cap today) or a tightening (the
// effective cap is looser than the ceiling) — never a cosmetic rewrite
// and never a loosening.
func (e *MarginAutopilot) budgetRecommendations(
	ctx context.Context,
	tenantID uuid.UUID,
	report TenantCostReport,
	mode AutoActMode,
	now time.Time,
) []Recommendation {
	if !e.trialTiers[report.Tier] {
		// Budget-cap enforcement is scoped to trial tenants. A paying
		// tenant breaching its own cap is an upsell/throttle signal,
		// surfaced by the margin path, not an enforcement target.
		return nil
	}
	var out []Recommendation
	for _, line := range report.Lines {
		ceiling, ceilingPeriod, ok := tierCeilingHardLimit(report.Tier, line.Meter)
		if !ok || ceiling <= 0 {
			continue // no tier policy ceiling for this meter; nothing to enforce against
		}
		if line.Period != ceilingPeriod {
			// The tier ceiling is denominated in ceilingPeriod, but this
			// tenant's effective budget for the meter resolves to a
			// different period (an operator override changed it). The cost
			// report's ProjectedUsage is computed for line.Period, so
			// comparing it against — or pinning the cap to — a ceiling from
			// another window would enforce a wildly wrong limit (e.g. a
			// daily 100k ceiling onto a monthly budget). Defer to the
			// operator and skip this meter; the breach is still surfaced by
			// the margin path when it drives the tenant underwater.
			continue
		}
		if line.ProjectedUsage <= ceiling {
			continue // on track to stay within the ceiling — healthy on this meter
		}
		// The trial is projected to exhaust the policy ceiling on this
		// meter. Decide whether the auto action would change state:
		// install (uncapped) or tighten (effective cap looser than the
		// ceiling). An effective cap already at/below the ceiling already
		// contains the breach, so the auto action is a no-op there.
		effective := line.HardLimit // 0 == unbounded
		needsWrite := effective == 0 || effective > ceiling

		rec := Recommendation{
			TenantID:                tenantID,
			Tier:                    report.Tier,
			Kind:                    RecEnforceBudgetCap,
			Meter:                   line.Meter,
			Mode:                    RecModeRecommend,
			Severity:                budgetSeverity(line.ProjectedUsage, ceiling),
			CapHardLimit:            ceiling,
			ProjectedMonthlyCostUSD: line.MonthlyCostUSD,
			CreatedAt:               now,
		}

		switch {
		case !needsWrite:
			rec.Reason = fmt.Sprintf(
				"trial projected to exhaust %s tier cap (projected %d > ceiling %d); hard cap %d already enforces — recommend upsell or review",
				line.Meter, line.ProjectedUsage, ceiling, effective)
		case mode == AutoActEnforce:
			if err := e.budgets.SetTenantBudget(ctx, tenantID, BudgetLimit{
				Meter:     line.Meter,
				HardLimit: ceiling,
				Period:    ceilingPeriod,
			}); err != nil {
				e.logger.WarnContext(ctx, "metering: autopilot cap enforce failed; degrading to recommendation",
					slog.String("tenant_id", tenantID.String()),
					slog.String("meter", string(line.Meter)),
					slog.Any("error", err))
				rec.Reason = fmt.Sprintf(
					"trial projected to exhaust %s tier cap; cap enforcement failed (%v) — recommendation only",
					line.Meter, err)
			} else {
				rec.Mode = RecModeAuto
				rec.Applied = true
				verb := "tightened"
				if effective == 0 {
					verb = "installed"
				}
				rec.Reason = fmt.Sprintf(
					"trial projected to exhaust %s tier cap (projected %d > ceiling %d); auto-%s hard cap to %d",
					line.Meter, line.ProjectedUsage, ceiling, verb, ceiling)
			}
		case mode == AutoActDryRun:
			rec.Reason = fmt.Sprintf(
				"trial projected to exhaust %s tier cap (projected %d > ceiling %d); [rollout=monitor dry-run: would set hard cap to %d; withheld]",
				line.Meter, line.ProjectedUsage, ceiling, ceiling)
		default: // AutoActRecommend
			rec.Reason = fmt.Sprintf(
				"trial projected to exhaust %s tier cap (projected %d > ceiling %d); recommend setting hard cap to %d (opt in to margin_autopilot to auto-apply)",
				line.Meter, line.ProjectedUsage, ceiling, ceiling)
		}
		out = append(out, rec)
	}
	return out
}

// marginRecommendations emits the loss-making signals: a throttle
// recommendation for the single most expensive meter and an upsell
// signal. Both are recommend-only (auto-throttling a paying tenant's
// live capacity could break their business). A tenant with no tier
// revenue has an undefined margin and is skipped.
func (e *MarginAutopilot) marginRecommendations(tenantID uuid.UUID, report TenantCostReport, now time.Time) []Recommendation {
	if report.MonthlyRevenueUSD <= 0 || report.MarginUSD >= 0 {
		return nil
	}
	sev := SeverityWarning
	// Cost at or above 2x revenue (margin pct <= -1) is a severe bleed.
	if report.MarginPct <= -1 {
		sev = SeverityCritical
	}
	var out []Recommendation
	if top, ok := mostExpensiveLine(report); ok {
		out = append(out, Recommendation{
			TenantID:                tenantID,
			Tier:                    report.Tier,
			Kind:                    RecThrottleMeter,
			Meter:                   top.Meter,
			Mode:                    RecModeRecommend,
			Severity:                sev,
			ProjectedMonthlyCostUSD: top.MonthlyCostUSD,
			MarginUSD:               report.MarginUSD,
			MarginPct:               report.MarginPct,
			Reason: fmt.Sprintf(
				"tenant is loss-making (margin $%.2f, %.0f%%); most expensive meter is %s at $%.2f/mo — recommend throttling it",
				report.MarginUSD, report.MarginPct*100, top.Meter, top.MonthlyCostUSD),
			CreatedAt: now,
		})
	}
	out = append(out, Recommendation{
		TenantID:                tenantID,
		Tier:                    report.Tier,
		Kind:                    RecOpenUpsell,
		Mode:                    RecModeRecommend,
		Severity:                sev,
		ProjectedMonthlyCostUSD: report.ProjectedMonthlyCostUSD,
		MarginUSD:               report.MarginUSD,
		MarginPct:               report.MarginPct,
		Reason: fmt.Sprintf(
			"tenant is loss-making (projected cost $%.2f > tier revenue $%.2f); recommend opening an upsell signal",
			report.ProjectedMonthlyCostUSD, report.MonthlyRevenueUSD),
		CreatedAt: now,
	})
	return out
}

// anomalyRecommendations turns each flagged cost anomaly into a
// recommend-only review signal. An anomaly read failure is logged and
// skipped so it never drops the budget/margin recommendations the caller
// already computed.
func (e *MarginAutopilot) anomalyRecommendations(ctx context.Context, tenantID uuid.UUID, report TenantCostReport, now time.Time) []Recommendation {
	anomalies, err := e.anomalies.AnomaliesForReport(ctx, tenantID, report)
	if err != nil {
		e.logger.WarnContext(ctx, "metering: autopilot anomaly read failed; skipping anomaly recommendations",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", err))
		return nil
	}
	out := make([]Recommendation, 0, len(anomalies))
	for _, a := range anomalies {
		out = append(out, Recommendation{
			TenantID:                tenantID,
			Tier:                    report.Tier,
			Kind:                    RecReviewAnomaly,
			Meter:                   a.Meter,
			Mode:                    RecModeRecommend,
			Severity:                anomalySeverity(a.Severity),
			ProjectedMonthlyCostUSD: a.ProjectedMonthlyUSD,
			Reason: fmt.Sprintf(
				"cost anomaly on %s: projected $%.2f/mo vs baseline $%.2f/mo (%s) — recommend review",
				a.Meter, a.ProjectedMonthlyUSD, a.BaselineMonthlyUSD, a.Severity),
			CreatedAt: now,
		})
	}
	return out
}

// Reconcile sweeps active tenants once, evaluating each. Intended to run
// on a leader-only schedule. When a dormancy planner is configured the
// sweep is activity-tiered: a tenant whose tier is not due this cycle is
// skipped, collapsing the cost of re-pricing thousands of quiet trials
// every interval. Cycle 0 visits every tenant, and the planner bounds
// how stale any tier's evaluation can get, so a runaway dormant trial is
// always caught within that bound — the sweep fails safe toward MORE
// work, never less. Per-tenant errors are logged and counted; the sweep
// continues so one tenant cannot starve the rest.
//
// It returns an AutopilotSweep describing the work done by THIS pass
// (per-sweep, not cumulative), so the caller can log meaningful single-
// sweep figures; the lifetime counters Stats exposes are advanced in
// parallel for the /stats endpoint.
func (e *MarginAutopilot) Reconcile(ctx context.Context) (AutopilotSweep, error) {
	if e.tenants == nil {
		return AutopilotSweep{}, fmt.Errorf("metering: autopilot: Reconcile requires a tenant lister")
	}
	// cycle is 0-based for the planner's cadence gate; stats.cycles is
	// the 1-based lifetime count Stats reports. Derive both from one
	// increment so they can never drift.
	cycle := e.stats.cycles.Add(1) - 1
	now := e.nowFunc()

	sweep := AutopilotSweep{Cycle: cycle + 1}
	var page repository.Page
	for {
		res, err := e.tenants.List(ctx, page)
		if err != nil {
			return sweep, fmt.Errorf("metering: autopilot: list tenants: %w", err)
		}
		for _, t := range res.Items {
			if t.Status != repository.TenantStatusActive {
				continue
			}
			if e.planner != nil {
				tier := e.planner.Classify(now, t.LastActiveAt)
				if !e.planner.ShouldVisit(tier, cycle) {
					e.countSkip(tier)
					sweep.countSkip(tier)
					continue
				}
			}
			e.stats.tenantsVisited.Add(1)
			sweep.TenantsVisited++
			recs, err := e.EvaluateTenant(ctx, t.ID)
			if err != nil {
				e.stats.evalErrors.Add(1)
				sweep.EvalErrors++
				e.logger.WarnContext(ctx, "metering: autopilot evaluate tenant failed",
					slog.String("tenant_id", t.ID.String()),
					slog.Any("error", err))
			} else {
				sweep.countRecommendations(recs)
			}
			if err := ctx.Err(); err != nil {
				return sweep, err
			}
		}
		if res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	if e.planner != nil && (sweep.SkippedIdle+sweep.SkippedDormant) > 0 {
		e.logger.DebugContext(ctx, "metering: autopilot activity-tiered sweep",
			slog.Int64("cycle", sweep.Cycle),
			slog.Int64("visited", sweep.TenantsVisited),
			slog.Int64("skipped", sweep.SkippedIdle+sweep.SkippedDormant))
	}
	return sweep, nil
}

// autoActMode resolves the tenant's opt-in decision once per evaluation.
// A nil gate is recommend-only — the fail-safe default.
func (e *MarginAutopilot) autoActMode(ctx context.Context, tenantID uuid.UUID) AutoActMode {
	if e.gate == nil {
		return AutoActRecommend
	}
	return e.gate.AutoAct(ctx, tenantID)
}

// record updates the stats counters and appends the audit entry (when a
// sink is wired). Audit/stat bookkeeping never fails the evaluation.
func (e *MarginAutopilot) record(ctx context.Context, rec Recommendation) {
	e.stats.recommendations.Add(1)
	switch rec.Kind {
	case RecEnforceBudgetCap:
		e.stats.enforceBudgetCap.Add(1)
		if rec.Applied {
			e.stats.capsEnforced.Add(1)
		}
	case RecThrottleMeter:
		e.stats.throttleMeter.Add(1)
	case RecOpenUpsell:
		e.stats.openUpsell.Add(1)
	case RecReviewAnomaly:
		e.stats.reviewAnomaly.Add(1)
	}
	e.auditRecommendation(ctx, rec)
}

func (e *MarginAutopilot) auditRecommendation(ctx context.Context, rec Recommendation) {
	if e.audit == nil {
		return
	}
	action := "metering.autopilot_recommend"
	if rec.Applied {
		action = "metering.autopilot_enforce"
	}
	details, err := json.Marshal(rec)
	if err != nil {
		// A Recommendation is plain data; a marshal failure is not
		// expected, but never let it abort the evaluation.
		e.logger.WarnContext(ctx, "metering: autopilot audit marshal failed",
			slog.String("tenant_id", rec.TenantID.String()),
			slog.Any("error", err))
		return
	}
	if _, err := e.audit.Append(ctx, rec.TenantID, repository.AuditEntry{
		TenantID:     rec.TenantID,
		Action:       action,
		ResourceType: "tenant_margin",
		Details:      details,
	}); err != nil {
		e.logger.WarnContext(ctx, "metering: autopilot audit append failed",
			slog.String("tenant_id", rec.TenantID.String()),
			slog.String("action", action),
			slog.Any("error", err))
	}
}

func (e *MarginAutopilot) countSkip(tier tenancy.Tier) {
	switch tier {
	case tenancy.TierIdle:
		e.stats.skippedIdle.Add(1)
	case tenancy.TierDormant:
		e.stats.skippedDormant.Add(1)
	}
}

// autopilotCounters holds the engine's lifetime instrumentation. Atomic
// so the leader sweep and any concurrent on-demand evaluation can update
// them race-free. Snapshotted via Stats.
type autopilotCounters struct {
	cycles           atomic.Int64
	tenantsVisited   atomic.Int64
	skippedIdle      atomic.Int64
	skippedDormant   atomic.Int64
	evalErrors       atomic.Int64
	recommendations  atomic.Int64
	enforceBudgetCap atomic.Int64
	throttleMeter    atomic.Int64
	openUpsell       atomic.Int64
	reviewAnomaly    atomic.Int64
	capsEnforced     atomic.Int64
}

// AutopilotStats is a point-in-time snapshot of the engine counters. It
// is the metric that PROVES the cost/efficiency curve moved: TenantsVisited
// vs SkippedIdle/SkippedDormant shows the per-cycle fan-out the dormancy
// planner removed, and the per-kind / CapsEnforced counters show the
// underwater/over-budget/anomalous tenants being acted on automatically.
type AutopilotStats struct {
	Cycles           int64 `json:"cycles"`
	TenantsVisited   int64 `json:"tenants_visited"`
	SkippedIdle      int64 `json:"skipped_idle"`
	SkippedDormant   int64 `json:"skipped_dormant"`
	EvalErrors       int64 `json:"eval_errors"`
	Recommendations  int64 `json:"recommendations"`
	EnforceBudgetCap int64 `json:"enforce_budget_cap"`
	ThrottleMeter    int64 `json:"throttle_meter"`
	OpenUpsell       int64 `json:"open_upsell"`
	ReviewAnomaly    int64 `json:"review_anomaly"`
	CapsEnforced     int64 `json:"caps_enforced"`
}

// AutopilotSweep is the summary of a SINGLE Reconcile pass — the work
// that one sweep did, not the lifetime totals. Reconcile returns it so a
// caller can log meaningful per-sweep figures (cumulative Stats counters
// grow monotonically and would misreport a single sweep's workload).
type AutopilotSweep struct {
	// Cycle is the 1-based number of this sweep over the engine's
	// lifetime (the first sweep is cycle 1).
	Cycle            int64 `json:"cycle"`
	TenantsVisited   int64 `json:"tenants_visited"`
	SkippedIdle      int64 `json:"skipped_idle"`
	SkippedDormant   int64 `json:"skipped_dormant"`
	EvalErrors       int64 `json:"eval_errors"`
	Recommendations  int64 `json:"recommendations"`
	EnforceBudgetCap int64 `json:"enforce_budget_cap"`
	ThrottleMeter    int64 `json:"throttle_meter"`
	OpenUpsell       int64 `json:"open_upsell"`
	ReviewAnomaly    int64 `json:"review_anomaly"`
	CapsEnforced     int64 `json:"caps_enforced"`
}

func (s *AutopilotSweep) countSkip(tier tenancy.Tier) {
	switch tier {
	case tenancy.TierIdle:
		s.SkippedIdle++
	case tenancy.TierDormant:
		s.SkippedDormant++
	}
}

// countRecommendations folds one tenant's recommendations into the
// per-sweep tally, mirroring the per-kind lifetime bookkeeping in record.
func (s *AutopilotSweep) countRecommendations(recs []Recommendation) {
	for _, rec := range recs {
		s.Recommendations++
		switch rec.Kind {
		case RecEnforceBudgetCap:
			s.EnforceBudgetCap++
			if rec.Applied {
				s.CapsEnforced++
			}
		case RecThrottleMeter:
			s.ThrottleMeter++
		case RecOpenUpsell:
			s.OpenUpsell++
		case RecReviewAnomaly:
			s.ReviewAnomaly++
		}
	}
}

// Stats returns a snapshot of the engine's lifetime counters.
func (e *MarginAutopilot) Stats() AutopilotStats {
	return AutopilotStats{
		Cycles:           e.stats.cycles.Load(),
		TenantsVisited:   e.stats.tenantsVisited.Load(),
		SkippedIdle:      e.stats.skippedIdle.Load(),
		SkippedDormant:   e.stats.skippedDormant.Load(),
		EvalErrors:       e.stats.evalErrors.Load(),
		Recommendations:  e.stats.recommendations.Load(),
		EnforceBudgetCap: e.stats.enforceBudgetCap.Load(),
		ThrottleMeter:    e.stats.throttleMeter.Load(),
		OpenUpsell:       e.stats.openUpsell.Load(),
		ReviewAnomaly:    e.stats.reviewAnomaly.Load(),
		CapsEnforced:     e.stats.capsEnforced.Load(),
	}
}

// --- pure helpers ---------------------------------------------------------

// tierCeilingHardLimit returns the built-in per-tier hard limit for a
// meter — the policy ceiling the autopilot pins a runaway trial's cap to.
// It reads the same tierDefaults table the BudgetEnforcer resolves
// against, so the autopilot can never invent a cap the budget policy does
// not already define. ok is false when the tier/meter has no default.
func tierCeilingHardLimit(tier repository.TenantTier, meter Meter) (int64, Period, bool) {
	byMeter, ok := tierDefaults[tier]
	if !ok {
		return 0, "", false
	}
	lim, ok := byMeter[meter]
	if !ok || lim.HardLimit <= 0 {
		return 0, "", false
	}
	return lim.HardLimit, lim.Period, true
}

// mostExpensiveLine returns the cost line with the greatest projected
// monthly cost, or ok=false when no line carries a positive cost.
func mostExpensiveLine(report TenantCostReport) (CostLine, bool) {
	var top CostLine
	found := false
	for _, line := range report.Lines {
		if line.MonthlyCostUSD <= 0 {
			continue
		}
		if !found || line.MonthlyCostUSD > top.MonthlyCostUSD {
			top = line
			found = true
		}
	}
	return top, found
}

// budgetSeverity escalates to critical once the projection runs at or
// above 2x the policy ceiling — a severe runaway, not a marginal one.
func budgetSeverity(projected, ceiling int64) RecommendationSeverity {
	if ceiling > 0 && projected >= 2*ceiling {
		return SeverityCritical
	}
	return SeverityWarning
}

// anomalySeverity maps the detector's severity onto the autopilot's.
func anomalySeverity(s AnomalySeverity) RecommendationSeverity {
	if s == AnomalyCritical {
		return SeverityCritical
	}
	return SeverityWarning
}

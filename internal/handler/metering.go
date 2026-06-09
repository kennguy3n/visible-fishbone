// Package handler — metering.go owns the REST surface for the
// cost-metering and budget-guardrail subsystem (Session K):
//
//   - GET  /api/v1/tenants/{tenant_id}/usage         — current-period usage by meter
//   - GET  /api/v1/tenants/{tenant_id}/usage/history — trailing monthly aggregates
//   - GET  /api/v1/tenants/{tenant_id}/cost-anomalies — per-meter spend anomalies
//   - GET  /api/v1/tenants/{tenant_id}/cost          — per-tenant infra cost projection
//   - PUT  /api/v1/tenants/{tenant_id}/budgets       — set per-tenant budget overrides
//   - GET  /api/v1/admin/cost-report                 — platform-wide cost report (MSP/admin only)
//
// The tenant-scoped routes inherit RequireTenant via
// MountTenantScoped, so a JWT bound to tenant-A cannot read or mutate
// tenant-B's budgets by forging the path. The admin cost-report is not
// tenant-scoped; it is gated on an explicit platform-scoped RBAC grant
// (metering:read_platform_report) via AuthorizePlatform, mirroring the
// PoP / MSP / compliance admin surfaces. Absence of a tenant_id claim
// is necessary but NOT sufficient — the caller must additionally hold a
// platform-scoped role carrying the permission (or the platform
// wildcard), so a future non-admin tenant-less token cannot read the
// platform-wide cost / revenue / margin breakdown.
package handler

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/metering"
)

// MeteringUsageReader is the read surface the handler needs from the
// MeteringService. Declared here (rather than depending on the
// concrete service) so tests can stub it.
type MeteringUsageReader interface {
	CurrentUsage(ctx context.Context, tenantID uuid.UUID) ([]metering.UsageRecord, error)
	UsageHistory(ctx context.Context, tenantID uuid.UUID, months int) ([]metering.UsageRecord, error)
}

// MeteringBudgetService is the budget read / write surface the handler
// needs from the BudgetEnforcer.
type MeteringBudgetService interface {
	TenantBudgets(ctx context.Context, tenantID uuid.UUID) (map[metering.Meter]metering.BudgetLimit, error)
	// SetTenantBudgets applies a batch of overrides atomically (all or
	// nothing), so a mid-batch store failure cannot leave a partially
	// applied set behind.
	SetTenantBudgets(ctx context.Context, tenantID uuid.UUID, limits []metering.BudgetLimit) error
}

// MeteringPlatformReporter is the platform-wide report surface the
// admin cost-report endpoint needs (satisfied by *metering.Reports).
type MeteringPlatformReporter interface {
	PlatformReport(ctx context.Context) (metering.PlatformCostReport, error)
}

// MeteringAnomalyDetector is the per-tenant cost-anomaly surface the
// cost-anomaly endpoint needs (satisfied by
// *metering.CostAnomalyDetector).
type MeteringAnomalyDetector interface {
	TenantAnomalies(ctx context.Context, tenantID uuid.UUID) ([]metering.CostAnomaly, error)
}

// MeteringInfraReporter is the per-tenant cost-projection surface the
// tenant cost endpoints need (satisfied by *metering.Reports). It
// covers both the infrastructure breakdown (TenantInfraProjection,
// driving the /cost route) and the per-meter cost report
// (TenantReport, driving the /cost-report route). Both are scoped to a
// single tenant and RLS-enforced at the route layer, so neither leaks
// another tenant's spend.
type MeteringInfraReporter interface {
	TenantInfraProjection(ctx context.Context, tenantID uuid.UUID) (metering.InfraCostProjection, error)
	TenantReport(ctx context.Context, tenantID uuid.UUID) (metering.TenantCostReport, error)
}

// permMeteringReadPlatformReport is the platform-scoped permission the
// admin cost-report endpoint requires. It is platform-scoped (the
// report spans every tenant), so an MSP- or tenant-scoped grant does
// NOT satisfy it — only a platform-scoped role with this permission
// (or the platform wildcard "*"). The PlatformAuthorizer interface is
// shared with the PoP admin surface (see pop.go).
const permMeteringReadPlatformReport = "metering:read_platform_report"

// MeteringHandler exposes the cost-metering REST surface.
type MeteringHandler struct {
	usage     MeteringUsageReader
	budgets   MeteringBudgetService
	reporter  MeteringPlatformReporter
	anomalies MeteringAnomalyDetector
	infra     MeteringInfraReporter
	authz     PlatformAuthorizer
}

// NewMeteringHandler wires the handler. Any nil dependency disables the
// routes that need it (Register skips a nil handler entirely), so a
// deployment without metering wired can still boot. The admin
// cost-report route additionally requires authz: a nil authorizer
// leaves it unregistered (it 404s) rather than serving platform-wide
// cost data behind a weaker gate.
func NewMeteringHandler(usage MeteringUsageReader, budgets MeteringBudgetService, reporter MeteringPlatformReporter, anomalies MeteringAnomalyDetector, infra MeteringInfraReporter, authz PlatformAuthorizer) *MeteringHandler {
	return &MeteringHandler{usage: usage, budgets: budgets, reporter: reporter, anomalies: anomalies, infra: infra, authz: authz}
}

// Register attaches the metering routes.
func (h *MeteringHandler) Register(mux *http.ServeMux) {
	if h == nil {
		return
	}
	if h.usage != nil && h.budgets != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/usage", h.getUsage)
	}
	if h.usage != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/usage/history", h.getUsageHistory)
	}
	if h.anomalies != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/cost-anomalies", h.getCostAnomalies)
	}
	if h.infra != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/cost", h.getCost)
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/cost-report", h.getCostReport)
	}
	if h.budgets != nil {
		MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/budgets", h.putBudgets)
	}
	if h.reporter != nil && h.authz != nil {
		mux.HandleFunc("GET /api/v1/admin/cost-report", h.adminCostReport)
	}
}

const (
	// historyDefaultMonths is the trailing window returned by the
	// usage-history endpoint when ?months= is unset.
	historyDefaultMonths = 6
	// historyMaxMonths caps the window so a caller cannot ask for an
	// unbounded scan.
	historyMaxMonths = 36
)

// --- wire types -----------------------------------------------------------

type usageLineResponse struct {
	Meter     string `json:"meter"`
	Period    string `json:"period"`
	Used      int64  `json:"used"`
	SoftLimit int64  `json:"soft_limit,omitempty"`
	HardLimit int64  `json:"hard_limit,omitempty"`
	// SoftExceeded / HardExceeded compare the raw mid-period usage
	// against the limits (what has been consumed so far).
	SoftExceeded bool `json:"soft_exceeded"`
	HardExceeded bool `json:"hard_exceeded"`
	// Projected is the elapsed-fraction extrapolation of Used to the
	// end of the period — the steady-state run rate. ProjectedSoft/
	// HardExceeded compare it against the limits, so a budget gauge can
	// warn that a tenant is *on track* to breach before it actually
	// has. This is the figure the cost report uses for projected spend.
	Projected             int64 `json:"projected"`
	ProjectedSoftExceeded bool  `json:"projected_soft_exceeded"`
	ProjectedHardExceeded bool  `json:"projected_hard_exceeded"`
}

type usageResponse struct {
	TenantID    uuid.UUID           `json:"tenant_id"`
	GeneratedAt time.Time           `json:"generated_at"`
	Lines       []usageLineResponse `json:"lines"`
}

type usageHistoryLine struct {
	Meter       string    `json:"meter"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Value       int64     `json:"value"`
}

type usageHistoryResponse struct {
	TenantID uuid.UUID          `json:"tenant_id"`
	Months   int                `json:"months"`
	Lines    []usageHistoryLine `json:"lines"`
}

type costAnomalyLine struct {
	Meter               string  `json:"meter"`
	Severity            string  `json:"severity"`
	BaselineMonthlyUSD  float64 `json:"baseline_monthly_usd"`
	ProjectedMonthlyUSD float64 `json:"projected_monthly_usd"`
	Ratio               float64 `json:"ratio"`
	BaselineMonths      int     `json:"baseline_months"`
}

type costAnomaliesResponse struct {
	TenantID  uuid.UUID         `json:"tenant_id"`
	Anomalies []costAnomalyLine `json:"anomalies"`
}

type budgetOverrideRequest struct {
	Meter     string `json:"meter"`
	SoftLimit int64  `json:"soft_limit"`
	HardLimit int64  `json:"hard_limit"`
	Period    string `json:"period,omitempty"`
}

type putBudgetsRequest struct {
	Budgets []budgetOverrideRequest `json:"budgets"`
}

type budgetResponseLine struct {
	Meter     string `json:"meter"`
	Period    string `json:"period"`
	SoftLimit int64  `json:"soft_limit"`
	HardLimit int64  `json:"hard_limit"`
}

type budgetsResponse struct {
	TenantID uuid.UUID            `json:"tenant_id"`
	Budgets  []budgetResponseLine `json:"budgets"`
}

// --- handlers -------------------------------------------------------------

// getUsage returns the tenant's current-period usage for every known
// meter, annotated with the resolved soft / hard budget.
func (h *MeteringHandler) getUsage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	records, err := h.usage.CurrentUsage(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	limits, err := h.budgets.TenantBudgets(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}

	usedByMeter := make(map[metering.Meter]int64, len(records))
	for _, rec := range records {
		usedByMeter[rec.Meter] += rec.Value
	}

	now := time.Now().UTC()
	lines := make([]usageLineResponse, 0, len(metering.AllMeters))
	for _, meter := range metering.AllMeters {
		used := usedByMeter[meter]
		lim, hasLimit := limits[meter]
		period := metering.DefaultMeterPeriod(meter)
		if hasLimit && lim.Period.Valid() {
			period = lim.Period
		}
		projected := metering.ProjectToPeriodEnd(used, period, now)
		line := usageLineResponse{
			Meter:     string(meter),
			Period:    string(period),
			Used:      used,
			Projected: projected,
		}
		if hasLimit {
			if lim.HardLimit > 0 {
				line.HardLimit = lim.HardLimit
				line.HardExceeded = used > lim.HardLimit
				line.ProjectedHardExceeded = projected > lim.HardLimit
			}
			if lim.SoftLimit > 0 {
				line.SoftLimit = lim.SoftLimit
				line.SoftExceeded = used > lim.SoftLimit
				line.ProjectedSoftExceeded = projected > lim.SoftLimit
			}
		}
		lines = append(lines, line)
	}

	WriteJSON(w, http.StatusOK, usageResponse{
		TenantID:    tenantID,
		GeneratedAt: time.Now().UTC(),
		Lines:       lines,
	})
}

// getUsageHistory returns the tenant's trailing monthly usage
// aggregates. The window is controlled by ?months= (default 6, capped
// at 36).
func (h *MeteringHandler) getUsageHistory(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	months := historyDefaultMonths
	if q := r.URL.Query().Get("months"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n <= 0 {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "months must be a positive integer")
			return
		}
		months = n
		if months > historyMaxMonths {
			months = historyMaxMonths
		}
	}

	records, err := h.usage.UsageHistory(r.Context(), tenantID, months)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	lines := make([]usageHistoryLine, len(records))
	for i, rec := range records {
		lines[i] = usageHistoryLine{
			Meter:       string(rec.Meter),
			PeriodStart: rec.PeriodStart,
			PeriodEnd:   rec.PeriodEnd,
			Value:       rec.Value,
		}
	}
	WriteJSON(w, http.StatusOK, usageHistoryResponse{
		TenantID: tenantID,
		Months:   months,
		Lines:    lines,
	})
}

// getCostAnomalies returns the per-meter cost anomalies for the tenant:
// meters whose live projected monthly spend diverges from the tenant's
// own trailing baseline beyond the detector's threshold. Tenant-scoped
// (the path tenant_id is enforced by MountTenantScoped), so a tenant
// only sees its own anomalies.
func (h *MeteringHandler) getCostAnomalies(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	found, err := h.anomalies.TenantAnomalies(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	lines := make([]costAnomalyLine, len(found))
	for i, a := range found {
		lines[i] = costAnomalyLine{
			Meter:               string(a.Meter),
			Severity:            string(a.Severity),
			BaselineMonthlyUSD:  a.BaselineMonthlyUSD,
			ProjectedMonthlyUSD: a.ProjectedMonthlyUSD,
			Ratio:               a.Ratio,
			BaselineMonths:      a.BaselineMonths,
		}
	}
	WriteJSON(w, http.StatusOK, costAnomaliesResponse{TenantID: tenantID, Anomalies: lines})
}

// getCost returns the tenant's projected monthly infrastructure cost
// broken down per backend driver (ClickHouse / NATS / S3), the input to
// the dashboard's infra-cost-breakdown panel. Tenant-scoped: the path
// tenant_id is enforced by MountTenantScoped (RequireTenant), and the
// underlying projection reads only this tenant's usage, so a tenant
// cannot observe another's infrastructure spend. The InfraCostProjection
// is serialised directly — its JSON tags are the dashboard's contract.
func (h *MeteringHandler) getCost(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	projection, err := h.infra.TenantInfraProjection(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, projection)
}

// getCostReport returns the tenant's per-meter cost report for the
// current period: usage, projected usage, cost and projected monthly
// cost per meter, plus the tenant's projected monthly total, revenue
// and margin. It is the tenant-scoped counterpart to the platform
// /admin/cost-report (which spans the whole fleet): the path tenant_id
// is enforced by MountTenantScoped, so a tenant only ever reads its own
// report. This is the source for the dashboard's "projected monthly
// cost" / margin summary cards and the cost columns of the usage table.
// The TenantCostReport is serialised directly — its JSON tags are the
// dashboard's contract.
func (h *MeteringHandler) getCostReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	report, err := h.infra.TenantReport(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

// putBudgets applies one or more per-tenant budget overrides, then
// returns the tenant's full resolved budget set. The whole request is
// validated before any write, and the overrides are persisted in a
// single atomic batch, so neither a malformed entry nor a mid-batch
// store failure can leave a partially-applied set.
func (h *MeteringHandler) putBudgets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req putBudgetsRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if len(req.Budgets) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "at least one budget override is required")
		return
	}

	overrides := make([]metering.BudgetLimit, 0, len(req.Budgets))
	for _, b := range req.Budgets {
		meter := metering.Meter(b.Meter)
		if !meter.Valid() {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "unknown meter: "+b.Meter)
			return
		}
		if b.SoftLimit < 0 || b.HardLimit < 0 {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "limits must be non-negative")
			return
		}
		if b.HardLimit > 0 && b.SoftLimit > 0 && b.SoftLimit > b.HardLimit {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "soft_limit must not exceed hard_limit")
			return
		}
		var period metering.Period
		if b.Period != "" {
			period = metering.Period(b.Period)
			if !period.Valid() {
				WriteError(w, http.StatusBadRequest, "invalid_argument", "invalid period: "+b.Period)
				return
			}
		}
		overrides = append(overrides, metering.BudgetLimit{
			Meter:     meter,
			SoftLimit: b.SoftLimit,
			HardLimit: b.HardLimit,
			Period:    period,
		})
	}

	if err := h.budgets.SetTenantBudgets(r.Context(), tenantID, overrides); err != nil {
		WriteRepositoryError(w, err)
		return
	}

	resolved, err := h.budgets.TenantBudgets(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	lines := make([]budgetResponseLine, 0, len(resolved))
	for _, meter := range metering.AllMeters {
		lim, ok := resolved[meter]
		if !ok {
			continue
		}
		lines = append(lines, budgetResponseLine{
			Meter:     string(meter),
			Period:    string(lim.Period),
			SoftLimit: lim.SoftLimit,
			HardLimit: lim.HardLimit,
		})
	}
	WriteJSON(w, http.StatusOK, budgetsResponse{TenantID: tenantID, Budgets: lines})
}

// adminCostReport returns the platform-wide cost report. Platform
// admin only: the caller must hold the metering:read_platform_report
// permission via a platform-scoped role.
func (h *MeteringHandler) adminCostReport(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permMeteringReadPlatformReport) {
		return
	}
	report, err := h.reporter.PlatformReport(r.Context())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

// requirePlatform gates a platform-scoped metering route on an explicit
// RBAC grant. Returns true when the request may proceed, false (after
// writing the response) otherwise. Mirrors PoPHandler.requirePlatform /
// MSPHandler.requirePlatformPermission: an authenticated user identity
// is required, and AuthorizePlatform must grant the permission against
// a platform-scoped role (an MSP- or tenant-scoped grant does not
// qualify).
func (h *MeteringHandler) requirePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	// Defense in depth: a platform operator's JWT carries no tenant_id,
	// so a tenant-bound credential is refused outright before the RBAC
	// lookup. This is necessary but NOT sufficient — the grant check
	// below is the real gate.
	if middleware.TenantIDFromContext(r.Context()) != uuid.Nil {
		WriteError(w, http.StatusForbidden, "platform_forbidden",
			"platform-scoped metering routes are not accessible to tenant-bound credentials")
		return false
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped metering routes require an authenticated user identity")
		return false
	}
	allowed, err := h.authz.AuthorizePlatform(r.Context(), userID, permission)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "authorization_failed",
			"failed to evaluate platform authorization")
		return false
	}
	if !allowed {
		WriteError(w, http.StatusForbidden, "platform_forbidden",
			"credentials do not authorise platform-scoped metering operations")
		return false
	}
	return true
}

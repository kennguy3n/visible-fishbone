// Package handler — metering.go owns the REST surface for the
// cost-metering and budget-guardrail subsystem (Session K):
//
//   - GET  /api/v1/tenants/{tenant_id}/usage         — current-period usage by meter
//   - GET  /api/v1/tenants/{tenant_id}/usage/history — trailing monthly aggregates
//   - PUT  /api/v1/tenants/{tenant_id}/budgets       — set per-tenant budget overrides
//   - GET  /api/v1/admin/cost-report                 — platform-wide cost report (MSP/admin only)
//
// The three tenant-scoped routes inherit RequireTenant via
// MountTenantScoped, so a JWT bound to tenant-A cannot read or mutate
// tenant-B's budgets by forging the path. The admin cost-report is not
// tenant-scoped; it is gated on a platform-admin credential — a JWT
// with no tenant_id claim — mirroring how the auth chain leaves
// TenantIDFromContext == uuid.Nil for global operators (see
// middleware/tenant.go). A tenant-bound caller is refused with 403.
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
	SetTenantBudget(ctx context.Context, tenantID uuid.UUID, limit metering.BudgetLimit) error
}

// MeteringPlatformReporter is the platform-wide report surface the
// admin cost-report endpoint needs (satisfied by *metering.Reports).
type MeteringPlatformReporter interface {
	PlatformReport(ctx context.Context) (metering.PlatformCostReport, error)
}

// MeteringHandler exposes the cost-metering REST surface.
type MeteringHandler struct {
	usage    MeteringUsageReader
	budgets  MeteringBudgetService
	reporter MeteringPlatformReporter
}

// NewMeteringHandler wires the handler. Any nil dependency disables the
// routes that need it (Register skips a nil handler entirely), so a
// deployment without metering wired can still boot.
func NewMeteringHandler(usage MeteringUsageReader, budgets MeteringBudgetService, reporter MeteringPlatformReporter) *MeteringHandler {
	return &MeteringHandler{usage: usage, budgets: budgets, reporter: reporter}
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
	if h.budgets != nil {
		MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/budgets", h.putBudgets)
	}
	if h.reporter != nil {
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
	Meter        string `json:"meter"`
	Period       string `json:"period"`
	Used         int64  `json:"used"`
	SoftLimit    int64  `json:"soft_limit,omitempty"`
	HardLimit    int64  `json:"hard_limit,omitempty"`
	SoftExceeded bool   `json:"soft_exceeded"`
	HardExceeded bool   `json:"hard_exceeded"`
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

	lines := make([]usageLineResponse, 0, len(metering.AllMeters))
	for _, meter := range metering.AllMeters {
		used := usedByMeter[meter]
		lim, hasLimit := limits[meter]
		period := metering.DefaultMeterPeriod(meter)
		if hasLimit && lim.Period.Valid() {
			period = lim.Period
		}
		line := usageLineResponse{
			Meter:  string(meter),
			Period: string(period),
			Used:   used,
		}
		if hasLimit {
			if lim.HardLimit > 0 {
				line.HardLimit = lim.HardLimit
				line.HardExceeded = used > lim.HardLimit
			}
			if lim.SoftLimit > 0 {
				line.SoftLimit = lim.SoftLimit
				line.SoftExceeded = used > lim.SoftLimit
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

// putBudgets applies one or more per-tenant budget overrides, then
// returns the tenant's full resolved budget set. The whole request is
// validated before any write so a malformed entry cannot leave a
// partially-applied set.
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

	for _, limit := range overrides {
		if err := h.budgets.SetTenantBudget(r.Context(), tenantID, limit); err != nil {
			WriteRepositoryError(w, err)
			return
		}
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

// adminCostReport returns the platform-wide cost report. MSP/admin
// only: a tenant-bound credential is refused.
func (h *MeteringHandler) adminCostReport(w http.ResponseWriter, r *http.Request) {
	if !requirePlatformAdmin(w, r) {
		return
	}
	report, err := h.reporter.PlatformReport(r.Context())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

// requirePlatformAdmin enforces that the caller is a platform-admin
// (global) credential rather than a tenant-scoped one. The auth chain
// binds a tenant_id onto the context for tenant credentials; a global
// operator's JWT carries none, leaving TenantIDFromContext == Nil.
// Returns false (and writes 403) when a tenant-bound caller is seen.
func requirePlatformAdmin(w http.ResponseWriter, r *http.Request) bool {
	if middleware.TenantIDFromContext(r.Context()) != uuid.Nil {
		WriteError(w, http.StatusForbidden, "forbidden", "platform admin privileges required")
		return false
	}
	return true
}

package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/metering"
)

// --- fakes implementing the handler's narrow interfaces ------------------

type fakeUsageReader struct {
	current []metering.UsageRecord
	history []metering.UsageRecord
	err     error
}

func (f fakeUsageReader) CurrentUsage(_ context.Context, tenantID uuid.UUID) ([]metering.UsageRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.current, nil
}

func (f fakeUsageReader) UsageHistory(_ context.Context, tenantID uuid.UUID, _ int) ([]metering.UsageRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.history, nil
}

type fakeBudgetService struct {
	limits map[metering.Meter]metering.BudgetLimit
	sets   []metering.BudgetLimit
}

func (f *fakeBudgetService) TenantBudgets(_ context.Context, _ uuid.UUID) (map[metering.Meter]metering.BudgetLimit, error) {
	return f.limits, nil
}

func (f *fakeBudgetService) SetTenantBudgets(_ context.Context, _ uuid.UUID, limits []metering.BudgetLimit) error {
	if f.limits == nil {
		f.limits = make(map[metering.Meter]metering.BudgetLimit)
	}
	for _, limit := range limits {
		f.sets = append(f.sets, limit)
		f.limits[limit.Meter] = limit
	}
	return nil
}

type fakeReporter struct {
	report metering.PlatformCostReport
	called bool
}

func (f *fakeReporter) PlatformReport(_ context.Context) (metering.PlatformCostReport, error) {
	f.called = true
	return f.report, nil
}

type fakeAnomalyDetector struct {
	anomalies []metering.CostAnomaly
	gotTenant uuid.UUID
}

func (f *fakeAnomalyDetector) TenantAnomalies(_ context.Context, tenantID uuid.UUID) ([]metering.CostAnomaly, error) {
	f.gotTenant = tenantID
	return f.anomalies, nil
}

// --- harness -------------------------------------------------------------

const meteringJWTSecret = "test-jwt-secret-key"

func newMeteringTestRouter(usage handler.MeteringUsageReader, budgets handler.MeteringBudgetService, reporter handler.MeteringPlatformReporter) http.Handler {
	// Default to a granting authorizer so the admin route is registered
	// and reachable; tests that exercise the authorization gate use
	// newMeteringTestRouterAuthz with an explicit double.
	return newMeteringTestRouterAuthz(usage, budgets, reporter, platformAuthz{allow: true})
}

func newMeteringTestRouterAuthz(usage handler.MeteringUsageReader, budgets handler.MeteringBudgetService, reporter handler.MeteringPlatformReporter, authz handler.PlatformAuthorizer) http.Handler {
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    meteringJWTSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	return handler.NewRouter(handler.RouterDeps{
		Config:   cfg,
		Metering: handler.NewMeteringHandler(usage, budgets, reporter, nil, nil, authz),
	})
}

func newMeteringAnomalyTestRouter(anomalies handler.MeteringAnomalyDetector) http.Handler {
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    meteringJWTSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	return handler.NewRouter(handler.RouterDeps{
		Config:   cfg,
		Metering: handler.NewMeteringHandler(fakeUsageReader{}, &fakeBudgetService{}, nil, anomalies, nil, platformAuthz{allow: true}),
	})
}

func newMeteringInfraTestRouter(infra handler.MeteringInfraReporter) http.Handler {
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    meteringJWTSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	return handler.NewRouter(handler.RouterDeps{
		Config:   cfg,
		Metering: handler.NewMeteringHandler(fakeUsageReader{}, &fakeBudgetService{}, nil, nil, infra, platformAuthz{allow: true}),
	})
}

// fakeInfraReporter records the tenant it was queried for so tests can
// assert tenant-scoping, and returns a canned projection / cost report.
type fakeInfraReporter struct {
	projection metering.InfraCostProjection
	report     metering.TenantCostReport
	gotTenant  uuid.UUID
}

func (f *fakeInfraReporter) TenantInfraProjection(_ context.Context, tenantID uuid.UUID) (metering.InfraCostProjection, error) {
	f.gotTenant = tenantID
	proj := f.projection
	proj.TenantID = tenantID
	return proj, nil
}

func (f *fakeInfraReporter) TenantReport(_ context.Context, tenantID uuid.UUID) (metering.TenantCostReport, error) {
	f.gotTenant = tenantID
	rep := f.report
	rep.TenantID = tenantID
	return rep, nil
}

func meteringToken(t *testing.T, tenantID string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": "sng-control",
		"aud": "sng-control",
		"sub": uuid.New().String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(meteringJWTSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

// --- tests ---------------------------------------------------------------

func TestMeteringGetUsage(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	usage := fakeUsageReader{current: []metering.UsageRecord{
		{Meter: metering.MeterLLMCalls, Value: 600},
	}}
	budgets := &fakeBudgetService{limits: map[metering.Meter]metering.BudgetLimit{
		metering.MeterLLMCalls: {Meter: metering.MeterLLMCalls, SoftLimit: 800, HardLimit: 1000, Period: metering.PeriodMonthly},
	}}
	router := newMeteringTestRouter(usage, budgets, nil)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tid.String()+"/usage", meteringToken(t, tid.String()), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Lines []struct {
			Meter     string `json:"meter"`
			Used      int64  `json:"used"`
			HardLimit int64  `json:"hard_limit"`
		} `json:"lines"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var seen bool
	for _, l := range resp.Lines {
		if l.Meter == string(metering.MeterLLMCalls) {
			seen = true
			if l.Used != 600 || l.HardLimit != 1000 {
				t.Fatalf("llm_calls line = %+v", l)
			}
		}
	}
	if !seen {
		t.Fatal("expected llm_calls line in usage response")
	}
}

// TestMeteringGetUsageProjection pins the projected end-of-period
// fields: the handler must extrapolate mid-period usage to the period
// end and flag a *projected* breach even when the raw accumulator is
// still under the limit. Assertions are wall-clock-robust (they re-use
// the exported projection and only assert invariants), so the test is
// stable on any day of the month.
func TestMeteringGetUsageProjection(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	// A monthly meter consuming 600 against a 800 soft / 1000 hard
	// budget. Whatever the date, the projection extrapolates upward.
	const used, soft, hard = 600, 800, 1000
	usage := fakeUsageReader{current: []metering.UsageRecord{
		{Meter: metering.MeterLLMCalls, Value: used},
	}}
	budgets := &fakeBudgetService{limits: map[metering.Meter]metering.BudgetLimit{
		metering.MeterLLMCalls: {Meter: metering.MeterLLMCalls, SoftLimit: soft, HardLimit: hard, Period: metering.PeriodMonthly},
	}}
	router := newMeteringTestRouter(usage, budgets, nil)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tid.String()+"/usage", meteringToken(t, tid.String()), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Lines []struct {
			Meter                 string `json:"meter"`
			Used                  int64  `json:"used"`
			SoftLimit             int64  `json:"soft_limit"`
			HardLimit             int64  `json:"hard_limit"`
			SoftExceeded          bool   `json:"soft_exceeded"`
			Projected             int64  `json:"projected"`
			ProjectedSoftExceeded bool   `json:"projected_soft_exceeded"`
			ProjectedHardExceeded bool   `json:"projected_hard_exceeded"`
		} `json:"lines"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	var seen bool
	for _, l := range resp.Lines {
		if l.Meter != string(metering.MeterLLMCalls) {
			continue
		}
		seen = true
		// Invariant 1: projection never understates the accumulator.
		if l.Projected < l.Used {
			t.Fatalf("projected %d < used %d", l.Projected, l.Used)
		}
		// Invariant 2: it matches the exported projection model.
		want := metering.ProjectToPeriodEnd(l.Used, metering.PeriodMonthly, time.Now().UTC())
		if l.Projected != want {
			// Allow a 1-unit drift from the ceil at a period-second
			// boundary between handler and test clocks.
			if diff := l.Projected - want; diff < -1 || diff > 1 {
				t.Fatalf("projected = %d, want ~%d", l.Projected, want)
			}
		}
		// Invariant 3: the projected-breach flags are consistent with
		// the projected value and the limits.
		if (l.Projected > l.SoftLimit) != l.ProjectedSoftExceeded {
			t.Fatalf("projected_soft_exceeded=%v but projected=%d soft=%d", l.ProjectedSoftExceeded, l.Projected, l.SoftLimit)
		}
		if (l.Projected > l.HardLimit) != l.ProjectedHardExceeded {
			t.Fatalf("projected_hard_exceeded=%v but projected=%d hard=%d", l.ProjectedHardExceeded, l.Projected, l.HardLimit)
		}
		// The raw accumulator is below soft, so the *current* breach
		// flag must be false — the projection is what carries the early
		// warning.
		if l.SoftExceeded {
			t.Fatalf("soft_exceeded should be false for used=%d soft=%d", l.Used, l.SoftLimit)
		}
	}
	if !seen {
		t.Fatal("expected llm_calls line in usage response")
	}
}

func TestMeteringGetUsageHistoryInvalidMonths(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	router := newMeteringTestRouter(fakeUsageReader{}, &fakeBudgetService{}, nil)
	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tid.String()+"/usage/history?months=-1", meteringToken(t, tid.String()), nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestMeteringPutBudgets(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	budgets := &fakeBudgetService{}
	router := newMeteringTestRouter(fakeUsageReader{}, budgets, nil)

	rec := doJSON(t, router, http.MethodPut,
		"/api/v1/tenants/"+tid.String()+"/budgets", meteringToken(t, tid.String()),
		map[string]any{
			"budgets": []map[string]any{
				{"meter": "llm_calls", "soft_limit": 80, "hard_limit": 100, "period": "monthly"},
			},
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if len(budgets.sets) != 1 || budgets.sets[0].HardLimit != 100 {
		t.Fatalf("override not applied: %+v", budgets.sets)
	}
}

func TestMeteringPutBudgetsRejectsUnknownMeter(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	budgets := &fakeBudgetService{}
	router := newMeteringTestRouter(fakeUsageReader{}, budgets, nil)
	rec := doJSON(t, router, http.MethodPut,
		"/api/v1/tenants/"+tid.String()+"/budgets", meteringToken(t, tid.String()),
		map[string]any{"budgets": []map[string]any{{"meter": "bogus", "hard_limit": 1}}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if len(budgets.sets) != 0 {
		t.Fatal("no override should have been written for an invalid request")
	}
}

func TestMeteringCrossTenantPathForbidden(t *testing.T) {
	t.Parallel()
	tokenTenant := uuid.New()
	pathTenant := uuid.New() // different tenant in the path
	router := newMeteringTestRouter(fakeUsageReader{}, &fakeBudgetService{}, nil)
	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+pathTenant.String()+"/usage", meteringToken(t, tokenTenant.String()), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant access status = %d, want 403", rec.Code)
	}
}

func TestMeteringAdminCostReportRequiresPlatformAdmin(t *testing.T) {
	t.Parallel()
	reporter := &fakeReporter{report: metering.PlatformCostReport{TenantCount: 3, TotalRevenueUSD: 2098}}
	// Granting authorizer: a platform-scoped operator holding
	// metering:read_platform_report.
	router := newMeteringTestRouterAuthz(fakeUsageReader{}, &fakeBudgetService{}, reporter, platformAuthz{allow: true})

	// Tenant-bound token → 403 (RequireTenant binds a tenant_id, but the
	// platform gate also rejects it since it carries no platform grant).
	rec := doJSON(t, router, http.MethodGet, "/api/v1/admin/cost-report", meteringToken(t, uuid.New().String()), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant token status = %d, want 403", rec.Code)
	}
	if reporter.called {
		t.Fatal("reporter must not run for a forbidden caller")
	}

	// Global (no tenant_id) token WITH the platform grant → 200.
	rec = doJSON(t, router, http.MethodGet, "/api/v1/admin/cost-report", meteringToken(t, ""), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin token status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !reporter.called {
		t.Fatal("reporter should have run for a platform admin")
	}
}

// TestMeteringAdminCostReportDeniesTenantlessWithoutGrant pins the fix
// for the Devin Review finding that the admin cost-report was gated on
// the mere absence of a tenant_id claim. A tenant-less token that does
// NOT hold the platform grant must be refused (403) and the reporter
// must not run — absence of a tenant_id is necessary but not
// sufficient.
func TestMeteringAdminCostReportDeniesTenantlessWithoutGrant(t *testing.T) {
	t.Parallel()
	reporter := &fakeReporter{report: metering.PlatformCostReport{TenantCount: 3}}
	router := newMeteringTestRouterAuthz(fakeUsageReader{}, &fakeBudgetService{}, reporter, platformAuthz{allow: false})

	rec := doJSON(t, router, http.MethodGet, "/api/v1/admin/cost-report", meteringToken(t, ""), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant-less, ungranted status = %d, want 403", rec.Code)
	}
	if reporter.called {
		t.Fatal("reporter must not run without the platform grant")
	}
}

func TestMeteringGetCostAnomalies(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	det := &fakeAnomalyDetector{anomalies: []metering.CostAnomaly{
		{
			TenantID:            tid,
			Meter:               metering.MeterBandwidthProxiedBytes,
			Severity:            metering.AnomalyCritical,
			BaselineMonthlyUSD:  9.0,
			ProjectedMonthlyUSD: 90.0,
			Ratio:               10,
			BaselineMonths:      3,
		},
	}}
	router := newMeteringAnomalyTestRouter(det)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tid.String()+"/cost-anomalies", meteringToken(t, tid.String()), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Anomalies []struct {
			Meter               string  `json:"meter"`
			Severity            string  `json:"severity"`
			ProjectedMonthlyUSD float64 `json:"projected_monthly_usd"`
		} `json:"anomalies"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Anomalies) != 1 {
		t.Fatalf("want 1 anomaly, got %+v", resp.Anomalies)
	}
	if resp.Anomalies[0].Meter != string(metering.MeterBandwidthProxiedBytes) || resp.Anomalies[0].Severity != "critical" {
		t.Fatalf("unexpected anomaly line: %+v", resp.Anomalies[0])
	}
	if det.gotTenant != tid {
		t.Fatalf("detector called with %s, want path tenant %s", det.gotTenant, tid)
	}
}

// TestMeteringCostAnomaliesCrossTenantForbidden confirms the
// cost-anomalies route is tenant-scoped: a tenant-A token cannot read
// tenant-B's anomalies via the path.
func TestMeteringCostAnomaliesCrossTenantForbidden(t *testing.T) {
	t.Parallel()
	pathTenant := uuid.New()
	tokenTenant := uuid.New()
	det := &fakeAnomalyDetector{}
	router := newMeteringAnomalyTestRouter(det)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+pathTenant.String()+"/cost-anomalies", meteringToken(t, tokenTenant.String()), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if det.gotTenant != uuid.Nil {
		t.Fatal("detector must not run on a cross-tenant path")
	}
}

func TestMeteringGetCost(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	infra := &fakeInfraReporter{projection: metering.InfraCostProjection{
		ClickHouseMonthlyUSD: 2.0,
		NATSMonthlyUSD:       0.2,
		S3MonthlyUSD:         0.05,
		TotalMonthlyUSD:      2.25,
	}}
	router := newMeteringInfraTestRouter(infra)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tid.String()+"/cost", meteringToken(t, tid.String()), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TenantID             string  `json:"tenant_id"`
		ClickHouseMonthlyUSD float64 `json:"clickhouse_monthly_usd"`
		NATSMonthlyUSD       float64 `json:"nats_monthly_usd"`
		S3MonthlyUSD         float64 `json:"s3_monthly_usd"`
		TotalMonthlyUSD      float64 `json:"total_monthly_usd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != tid.String() {
		t.Fatalf("tenant_id = %s, want %s", resp.TenantID, tid)
	}
	if resp.ClickHouseMonthlyUSD != 2.0 || resp.NATSMonthlyUSD != 0.2 ||
		resp.S3MonthlyUSD != 0.05 || resp.TotalMonthlyUSD != 2.25 {
		t.Fatalf("unexpected projection: %+v", resp)
	}
	if infra.gotTenant != tid {
		t.Fatalf("reporter called with %s, want path tenant %s", infra.gotTenant, tid)
	}
}

// TestMeteringCostCrossTenantForbidden confirms the cost route enforces
// tenant isolation: a tenant-A token cannot read tenant-B's infra cost
// via the path, and the underlying projection never runs.
func TestMeteringCostCrossTenantForbidden(t *testing.T) {
	t.Parallel()
	pathTenant := uuid.New()
	tokenTenant := uuid.New()
	infra := &fakeInfraReporter{}
	router := newMeteringInfraTestRouter(infra)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+pathTenant.String()+"/cost", meteringToken(t, tokenTenant.String()), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if infra.gotTenant != uuid.Nil {
		t.Fatal("reporter must not run on a cross-tenant path")
	}
}

func TestMeteringGetCostReport(t *testing.T) {
	t.Parallel()
	tid := uuid.New()
	infra := &fakeInfraReporter{report: metering.TenantCostReport{
		Tier:                    repository.TenantTierProfessional,
		TotalCostUSD:            12.34,
		ProjectedMonthlyCostUSD: 25.00,
		MonthlyRevenueUSD:       99.00,
		MarginUSD:               74.00,
		MarginPct:               0.7475,
		Lines: []metering.CostLine{{
			Meter:            metering.MeterLLMTokensUsed,
			Period:           metering.PeriodMonthly,
			Usage:            1000,
			CostUSD:          1.50,
			ProjectedUsage:   3000,
			ProjectedCostUSD: 4.50,
			MonthlyCostUSD:   4.50,
		}},
	}}
	router := newMeteringInfraTestRouter(infra)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tid.String()+"/cost-report", meteringToken(t, tid.String()), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		TenantID                string  `json:"tenant_id"`
		ProjectedMonthlyCostUSD float64 `json:"projected_monthly_cost_usd"`
		MarginPct               float64 `json:"margin_pct"`
		Lines                   []struct {
			Meter   string  `json:"meter"`
			CostUSD float64 `json:"cost_usd"`
		} `json:"lines"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.TenantID != tid.String() {
		t.Fatalf("tenant_id = %s, want %s", resp.TenantID, tid)
	}
	if resp.ProjectedMonthlyCostUSD != 25.00 || resp.MarginPct != 0.7475 {
		t.Fatalf("unexpected report totals: %+v", resp)
	}
	if len(resp.Lines) != 1 || resp.Lines[0].CostUSD != 1.50 {
		t.Fatalf("unexpected cost lines: %+v", resp.Lines)
	}
	if infra.gotTenant != tid {
		t.Fatalf("reporter called with %s, want path tenant %s", infra.gotTenant, tid)
	}
}

// TestMeteringCostReportCrossTenantForbidden confirms the per-tenant
// cost-report route enforces tenant isolation: a tenant-A token cannot
// read tenant-B's cost report, and the reporter never runs.
func TestMeteringCostReportCrossTenantForbidden(t *testing.T) {
	t.Parallel()
	pathTenant := uuid.New()
	tokenTenant := uuid.New()
	infra := &fakeInfraReporter{}
	router := newMeteringInfraTestRouter(infra)

	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+pathTenant.String()+"/cost-report", meteringToken(t, tokenTenant.String()), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if infra.gotTenant != uuid.Nil {
		t.Fatal("reporter must not run on a cross-tenant path")
	}
}

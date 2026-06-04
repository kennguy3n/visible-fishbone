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

func (f *fakeBudgetService) SetTenantBudget(_ context.Context, _ uuid.UUID, limit metering.BudgetLimit) error {
	f.sets = append(f.sets, limit)
	if f.limits == nil {
		f.limits = make(map[metering.Meter]metering.BudgetLimit)
	}
	f.limits[limit.Meter] = limit
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

// --- harness -------------------------------------------------------------

const meteringJWTSecret = "test-jwt-secret-key"

func newMeteringTestRouter(usage handler.MeteringUsageReader, budgets handler.MeteringBudgetService, reporter handler.MeteringPlatformReporter) http.Handler {
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
		Metering: handler.NewMeteringHandler(usage, budgets, reporter),
	})
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
	router := newMeteringTestRouter(fakeUsageReader{}, &fakeBudgetService{}, reporter)

	// Tenant-bound token → 403.
	rec := doJSON(t, router, http.MethodGet, "/api/v1/admin/cost-report", meteringToken(t, uuid.New().String()), nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant token status = %d, want 403", rec.Code)
	}
	if reporter.called {
		t.Fatal("reporter must not run for a forbidden caller")
	}

	// Global (no tenant_id) token → 200.
	rec = doJSON(t, router, http.MethodGet, "/api/v1/admin/cost-report", meteringToken(t, ""), nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin token status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !reporter.called {
		t.Fatal("reporter should have run for a platform admin")
	}
}

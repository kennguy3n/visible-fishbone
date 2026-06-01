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
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/alert"
)

// newBaselineAlertTestRouter wires a minimal router exposing the
// baseline + alert handlers backed by the in-memory store. JWT
// secret + tenant are returned so tests can sign requests under
// the production middleware stack (the same path real operators
// hit).
func newBaselineAlertTestRouter(t *testing.T) (http.Handler, *memory.Store, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t",
			Status: repository.TenantStatusActive,
			Tier:   repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	baselineRepo := memory.NewBaselineModelRepository(store)
	alertRepo := memory.NewAlertRepository(store)
	suppRepo := memory.NewAlertSuppressionRepository(store)
	fbRepo := memory.NewAlertFeedbackRepository(store)
	router := alert.NewRouter(alertRepo, suppRepo, nil, alert.Options{})
	fb := alert.NewFeedback(fbRepo, alertRepo, baselineRepo, alert.FeedbackTuningOptions{})

	jwtSecret := "test-jwt-secret-key"
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    jwtSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	r := handler.NewRouter(handler.RouterDeps{
		Config:   cfg,
		Baseline: handler.NewBaselineHandler(baselineRepo, nil),
		Alert:    handler.NewAlertHandler(router, fb, nil),
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       uuid.New().String(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return r, store, tenantID, signed
}

func seedAlert(t *testing.T, store *memory.Store, tenantID uuid.UUID) repository.Alert {
	t.Helper()
	alertRepo := memory.NewAlertRepository(store)
	now := time.Now().UTC().Truncate(time.Second)
	a := repository.Alert{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Kind:           "anomaly.bytes_total",
		Severity:       repository.AlertSeverityWarning,
		Dimension:      "bytes_total",
		ObservedValue:  1000,
		BaselineMean:   100,
		BaselineStdDev: 50,
		ZScore:         4.2,
		WindowStart:    now.Add(-5 * time.Minute),
		WindowEnd:      now,
		Summary:        "Welford z=4.2 over 100 samples",
		State:          repository.AlertStateOpen,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	saved, err := alertRepo.Create(context.Background(), tenantID, a)
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	return saved
}

func TestBaselineHandler_ListAndUpdateThreshold(t *testing.T) {
	t.Parallel()
	router, store, tenantID, token := newBaselineAlertTestRouter(t)
	repo := memory.NewBaselineModelRepository(store)
	now := time.Now().UTC().Truncate(time.Second)
	model := repository.BaselineModel{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Dimension:      "bytes_total",
		WindowSeconds:  300,
		Samples:        100,
		Mean:           42,
		M2:             8000,
		EWMA:           42,
		EWMAVar:        16,
		Alpha:          0.1,
		ZThreshold:     3.0,
		LastObservedAt: now,
		LastUpdatedAt:  now,
	}
	if _, err := repo.Upsert(context.Background(), tenantID, model); err != nil {
		t.Fatalf("seed baseline: %v", err)
	}

	rr := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/baselines", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var listResp struct {
		Items []struct {
			Dimension     string  `json:"dimension"`
			WindowSeconds int     `json:"window_seconds"`
			ZThreshold    float64 `json:"z_threshold"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(listResp.Items) != 1 || listResp.Items[0].Dimension != "bytes_total" {
		t.Fatalf("list payload missing baseline: %+v", listResp)
	}

	put := doJSON(t, router, http.MethodPut,
		"/api/v1/tenants/"+tenantID.String()+"/baselines/bytes_total/300/threshold",
		token, map[string]any{"z_threshold": 4.5})
	if put.Code != http.StatusOK {
		t.Fatalf("threshold expected 200, got %d: %s", put.Code, put.Body.String())
	}

	got := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/baselines/bytes_total/300", token, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("get expected 200, got %d: %s", got.Code, got.Body.String())
	}
	var one struct {
		ZThreshold float64 `json:"z_threshold"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &one); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if one.ZThreshold != 4.5 {
		t.Fatalf("threshold not persisted: %v", one.ZThreshold)
	}
}

func TestBaselineHandler_GetNotFound(t *testing.T) {
	t.Parallel()
	router, _, tenantID, token := newBaselineAlertTestRouter(t)
	rr := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/baselines/bytes_total/300", token, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestAlertHandler_LifecycleAndSuppression(t *testing.T) {
	t.Parallel()
	router, store, tenantID, token := newBaselineAlertTestRouter(t)
	a := seedAlert(t, store, tenantID)

	rr := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/alerts", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	ack := doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+a.ID.String()+"/acknowledge",
		token, nil)
	if ack.Code != http.StatusOK {
		t.Fatalf("ack expected 200, got %d: %s", ack.Code, ack.Body.String())
	}

	res := doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+a.ID.String()+"/resolve",
		token, nil)
	if res.Code != http.StatusOK {
		t.Fatalf("resolve expected 200, got %d: %s", res.Code, res.Body.String())
	}

	kind := "anomaly.bytes_total"
	cs := doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/alert-suppressions", token,
		map[string]any{"kind": kind, "reason": "load test"})
	if cs.Code != http.StatusCreated {
		t.Fatalf("create suppression expected 201, got %d: %s", cs.Code, cs.Body.String())
	}
	var created struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(cs.Body.Bytes(), &created)
	if created.ID == "" {
		t.Fatalf("suppression id missing: %s", cs.Body.String())
	}
	ls := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/alert-suppressions", token, nil)
	if ls.Code != http.StatusOK {
		t.Fatalf("list suppressions expected 200, got %d: %s", ls.Code, ls.Body.String())
	}
	ds := doJSON(t, router, http.MethodDelete,
		"/api/v1/tenants/"+tenantID.String()+"/alert-suppressions/"+created.ID,
		token, nil)
	if ds.Code != http.StatusNoContent {
		t.Fatalf("delete suppression expected 204, got %d: %s", ds.Code, ds.Body.String())
	}
}

func TestAlertHandler_FeedbackRoundTrip(t *testing.T) {
	t.Parallel()
	router, store, tenantID, token := newBaselineAlertTestRouter(t)
	a := seedAlert(t, store, tenantID)

	sub := doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+a.ID.String()+"/feedback", token,
		map[string]any{"decision": "false_positive", "notes": "noise from health-check probes"})
	if sub.Code != http.StatusCreated {
		t.Fatalf("submit expected 201, got %d: %s", sub.Code, sub.Body.String())
	}

	get := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+a.ID.String()+"/feedback", token, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("get expected 200, got %d: %s", get.Code, get.Body.String())
	}
	var fbResp struct {
		Decision string `json:"decision"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &fbResp); err != nil {
		t.Fatalf("decode feedback: %v", err)
	}
	if fbResp.Decision != "false_positive" {
		t.Fatalf("wrong decision: %v", fbResp.Decision)
	}

	del := doJSON(t, router, http.MethodDelete,
		"/api/v1/tenants/"+tenantID.String()+"/alerts/"+a.ID.String()+"/feedback", token, nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete expected 204, got %d: %s", del.Code, del.Body.String())
	}
}

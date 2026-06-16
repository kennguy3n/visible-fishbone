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
	"github.com/kennguy3n/visible-fishbone/internal/service/dem"
)

func newDEMTestRouter(t *testing.T) (http.Handler, *alert.Router, uuid.UUID, string) {
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

	demRepo := memory.NewDEMRepository(store)
	alertRepo := memory.NewAlertRepository(store)
	suppRepo := memory.NewAlertSuppressionRepository(store)
	router := alert.NewRouter(alertRepo, suppRepo, nil, alert.Options{})
	svc, err := dem.NewService(demRepo, router, dem.DefaultConfig())
	if err != nil {
		t.Fatalf("new dem service: %v", err)
	}

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
		Config: cfg,
		DEM:    handler.NewDEMHandler(svc, nil),
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
	return r, router, tenantID, signed
}

func TestDEMHandler_EffectiveTargets(t *testing.T) {
	t.Parallel()
	r, _, tenantID, token := newDEMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dem"

	rr := doJSON(t, r, http.MethodGet, base+"/targets", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list targets: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Items []struct {
			TargetKey string `json:"target_key"`
			Managed   bool   `json:"managed"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != len(dem.ManagedDefaultTargets()) {
		t.Fatalf("got %d targets, want %d", len(resp.Items), len(dem.ManagedDefaultTargets()))
	}
	for _, it := range resp.Items {
		if !it.Managed {
			t.Fatalf("default target %s not flagged managed", it.TargetKey)
		}
	}
}

func TestDEMHandler_TargetCRUD(t *testing.T) {
	t.Parallel()
	r, _, tenantID, token := newDEMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dem"

	// Create.
	create := doJSON(t, r, http.MethodPost, base+"/targets", token, map[string]any{
		"target_key": "wiki", "name": "Wiki", "probe_kind": "https",
		"address": "https://wiki.test", "enabled": true,
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", create.Code, create.Body.String())
	}
	var created struct {
		ID              string `json:"id"`
		IntervalSeconds int    `json:"interval_seconds"`
		TimeoutMs       int    `json:"timeout_ms"`
		Managed         bool   `json:"managed"`
	}
	if err := json.Unmarshal(create.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" || created.Managed {
		t.Fatalf("created target malformed: %s", create.Body.String())
	}
	if created.IntervalSeconds != dem.DefaultProbeIntervalSeconds || created.TimeoutMs != dem.DefaultProbeTimeoutMs {
		t.Fatalf("defaults not applied: %+v", created)
	}

	// Get.
	get := doJSON(t, r, http.MethodGet, base+"/targets/"+created.ID, token, nil)
	if get.Code != http.StatusOK {
		t.Fatalf("get: %d %s", get.Code, get.Body.String())
	}

	// Update.
	upd := doJSON(t, r, http.MethodPut, base+"/targets/"+created.ID, token, map[string]any{
		"target_key": "wiki", "name": "Wiki v2", "probe_kind": "https",
		"address": "https://wiki.test", "enabled": true,
		"interval_seconds": 120, "timeout_ms": 3000,
	})
	if upd.Code != http.StatusOK {
		t.Fatalf("update: %d %s", upd.Code, upd.Body.String())
	}

	// Delete.
	del := doJSON(t, r, http.MethodDelete, base+"/targets/"+created.ID, token, nil)
	if del.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", del.Code, del.Body.String())
	}

	// Get after delete -> 404.
	gone := doJSON(t, r, http.MethodGet, base+"/targets/"+created.ID, token, nil)
	if gone.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after delete, got %d", gone.Code)
	}
}

func TestDEMHandler_CreateTargetValidation(t *testing.T) {
	t.Parallel()
	r, _, tenantID, token := newDEMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dem"

	bad := doJSON(t, r, http.MethodPost, base+"/targets", token, map[string]any{
		"target_key": "x", "name": "X", "probe_kind": "https", // missing address
	})
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d %s", bad.Code, bad.Body.String())
	}
}

func TestDEMHandler_IngestAndScores(t *testing.T) {
	t.Parallel()
	r, _, tenantID, token := newDEMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dem"
	nowMs := uint64(time.Now().UnixMilli())

	ing := doJSON(t, r, http.MethodPost, base+"/results", token, map[string]any{
		"results": []map[string]any{
			{"target_key": "zoom", "target_name": "Zoom", "probe_kind": "https", "success": true, "total_ms": 20, "http_status": 200, "observed_at_ms": nowMs},
			{"target_key": "zoom", "target_name": "Zoom", "probe_kind": "https", "success": true, "total_ms": 25, "http_status": 200, "observed_at_ms": nowMs},
		},
	})
	if ing.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", ing.Code, ing.Body.String())
	}
	var ingResp struct {
		Accepted int `json:"accepted"`
		Scores   []struct {
			TargetKey    string  `json:"target_key"`
			Score        float64 `json:"score"`
			Availability float64 `json:"availability"`
		} `json:"scores"`
	}
	if err := json.Unmarshal(ing.Body.Bytes(), &ingResp); err != nil {
		t.Fatalf("decode ingest: %v", err)
	}
	if ingResp.Accepted != 2 || len(ingResp.Scores) != 1 {
		t.Fatalf("ingest summary: %+v", ingResp)
	}
	if ingResp.Scores[0].Availability != 1 || ingResp.Scores[0].Score < 99 {
		t.Fatalf("unexpected score: %+v", ingResp.Scores[0])
	}

	// Latest scores reflect the ingest.
	latest := doJSON(t, r, http.MethodGet, base+"/scores", token, nil)
	if latest.Code != http.StatusOK {
		t.Fatalf("latest: %d %s", latest.Code, latest.Body.String())
	}
	var latestResp struct {
		Items []struct {
			TargetKey string `json:"target_key"`
		} `json:"items"`
	}
	if err := json.Unmarshal(latest.Body.Bytes(), &latestResp); err != nil {
		t.Fatalf("decode latest: %v", err)
	}
	if len(latestResp.Items) != 1 || latestResp.Items[0].TargetKey != "zoom" {
		t.Fatalf("latest scores: %+v", latestResp)
	}

	// Timeseries returns the sample.
	ts := doJSON(t, r, http.MethodGet, base+"/scores/timeseries?target_key=zoom", token, nil)
	if ts.Code != http.StatusOK {
		t.Fatalf("timeseries: %d %s", ts.Code, ts.Body.String())
	}
}

func TestDEMHandler_IngestEmptyRejected(t *testing.T) {
	t.Parallel()
	r, _, tenantID, token := newDEMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dem"
	rr := doJSON(t, r, http.MethodPost, base+"/results", token, map[string]any{"results": []any{}})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty batch, got %d %s", rr.Code, rr.Body.String())
	}
}

func TestDEMHandler_ListAlerts(t *testing.T) {
	t.Parallel()
	r, router, tenantID, token := newDEMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dem"
	now := time.Now().UTC().Truncate(time.Second)

	// Seed a DEM degradation alert through the real router.
	if _, err := router.Emit(context.Background(), tenantID, repository.Alert{
		Kind:          dem.ExperienceDegradedKind,
		Severity:      repository.AlertSeverityCritical,
		Dimension:     "zoom",
		ObservedValue: 0,
		WindowStart:   now.Add(-5 * time.Minute),
		WindowEnd:     now,
		WindowSeconds: 300,
		Summary:       "Experience degraded for Zoom",
		State:         repository.AlertStateOpen,
	}); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	// A non-DEM alert that must NOT appear in the DEM alert listing.
	if _, err := router.Emit(context.Background(), tenantID, repository.Alert{
		Kind:          "anomaly.bytes_total",
		Severity:      repository.AlertSeverityWarning,
		Dimension:     "bytes_total",
		WindowStart:   now.Add(-5 * time.Minute),
		WindowEnd:     now,
		WindowSeconds: 300,
		Summary:       "unrelated",
		State:         repository.AlertStateOpen,
	}); err != nil {
		t.Fatalf("seed unrelated alert: %v", err)
	}

	rr := doJSON(t, r, http.MethodGet, base+"/alerts", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list alerts: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Items []struct {
			Kind      string `json:"kind"`
			Dimension string `json:"dimension"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Kind != dem.ExperienceDegradedKind {
		t.Fatalf("DEM alert listing scoped wrong: %+v", resp.Items)
	}
}

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
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

func newComplianceTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-compliance",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	svc := compliance.NewReportService(
		memory.NewComplianceReportRepository(store),
		nil,
	)

	jwtSecret := "test-jwt-secret-key"
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    jwtSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	router := handler.NewRouter(handler.RouterDeps{
		Config:     cfg,
		Compliance: handler.NewComplianceHandler(svc),
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       userID.String(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return router, tenantID, signed
}

func TestComplianceHandler_GenerateAndGet(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/compliance/reports"

	rec := doJSON(t, router, http.MethodPost, path+"/generate", token, map[string]any{
		"framework": "SOC2",
		"dlp":       true,
		"browser":   true,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("generate: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var report map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	reportID := report["id"].(string)

	rec = doJSON(t, router, http.MethodGet, path+"/"+reportID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rec.Code)
	}
}

func TestComplianceHandler_List(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/compliance/reports"

	rec := doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}
}

func TestComplianceHandler_Evidence(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/compliance/reports"

	rec := doJSON(t, router, http.MethodPost, path+"/generate", token, map[string]any{
		"framework": "HIPAA",
		"casb":      true,
	})
	var report map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &report)
	reportID := report["id"].(string)

	rec = doJSON(t, router, http.MethodGet, path+"/"+reportID+"/evidence", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("evidence: expected 200, got %d", rec.Code)
	}
}

func TestComplianceHandler_InvalidFramework(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/compliance/reports"

	rec := doJSON(t, router, http.MethodPost, path+"/generate", token, map[string]any{
		"framework": "INVALID",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid framework: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

package handler_test

import (
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
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

func newDLPTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	store.SetClock(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) })
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(t.Context(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-dlp",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	svc := dlp.New(
		memory.NewDLPPolicyRepository(store),
		memory.NewDLPFingerprintRepository(store),
		memory.NewDLPMatchRepository(store),
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
		Config: cfg,
		DLP:    handler.NewDLPHandler(svc),
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

func TestDLPHandler_PolicyCRUD(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/policies"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":   "PCI Test",
		"rules":  []map[string]string{{"type": "regex", "pattern": "credit_card", "sensitivity_level": "high"}},
		"action": "block",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d — %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	policyID := created["id"].(string)

	// GET
	rec = doJSON(t, router, http.MethodGet, base+"/"+policyID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d", rec.Code)
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	var listResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	items := listResp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("list: expected 1 item, got %d", len(items))
	}

	// PATCH
	rec = doJSON(t, router, http.MethodPatch, base+"/"+policyID, token, map[string]any{
		"name": "Updated PCI",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update: want 200, got %d — %s", rec.Code, rec.Body.String())
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, base+"/"+policyID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}

	// GET after delete → 404
	rec = doJSON(t, router, http.MethodGet, base+"/"+policyID, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: want 404, got %d", rec.Code)
	}
}

func TestDLPHandler_TestPolicy(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/policies"

	// Create a policy first.
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":   "SSN Detector",
		"rules":  []map[string]string{{"type": "regex", "pattern": "ssn_us", "sensitivity_level": "high"}},
		"action": "block",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d", rec.Code)
	}
	var created map[string]any
	json.Unmarshal(rec.Body.Bytes(), &created)
	policyID := created["id"].(string)

	// Test with matching content.
	rec = doJSON(t, router, http.MethodPost, base+"/"+policyID+"/test", token, map[string]any{
		"content": "SSN: 123-45-6789",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("test: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var testResp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &testResp)
	if testResp["matched"] != true {
		t.Fatal("expected matched=true")
	}
}

func TestDLPHandler_Templates(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPTestRouter(t)

	// List templates.
	rec := doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/dlp/templates", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list templates: want 200, got %d", rec.Code)
	}
	var listResp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &listResp)
	items := listResp["items"].([]any)
	if len(items) == 0 {
		t.Fatal("expected at least one template")
	}

	// Apply PCI-DSS template.
	rec = doJSON(t, router, http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/dlp/templates/pci-dss/apply", token, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("apply template: want 201, got %d — %s", rec.Code, rec.Body.String())
	}
}

func TestDLPHandler_Classify(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp"

	// Create a policy first.
	doJSON(t, router, http.MethodPost, base+"/policies", token, map[string]any{
		"name":   "Email Detector",
		"rules":  []map[string]string{{"type": "regex", "pattern": "email", "sensitivity_level": "low"}},
		"action": "log",
	})

	// Classify content.
	rec := doJSON(t, router, http.MethodPost, base+"/classify", token, map[string]any{
		"content_type": "text/plain",
		"content":      "Contact: alice@example.com",
		"metadata":     map[string]string{"filename": "test.txt"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("classify: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var classifyResp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &classifyResp)
	if classifyResp["action"] != "log" {
		t.Errorf("expected action 'log', got %q", classifyResp["action"])
	}
}

func TestDLPHandler_Fingerprints(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/fingerprints"

	// Register fingerprint.
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":         "earnings-q1",
		"content_type": "text/plain",
		"content":      "quarterly earnings report for Q1 2025 with revenue and profit projections",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: want 201, got %d — %s", rec.Code, rec.Body.String())
	}

	// List fingerprints.
	rec = doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	var listResp map[string]any
	json.Unmarshal(rec.Body.Bytes(), &listResp)
	items := listResp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(items))
	}
}

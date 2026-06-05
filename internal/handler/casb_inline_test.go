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
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// newInlineCASBTestRouter builds a router with the inline-CASB rule
// CRUD routes wired, exercising the full path:
// handler -> service -> repository adapter -> memory repository.
func newInlineCASBTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	discovery := casb.New(
		memory.NewCASBConnectorRepository(store),
		memory.NewCASBDiscoveredAppRepository(store),
		memory.NewCASBPostureCheckRepository(store),
		memory.NewAuditLogRepository(store),
		casb.PluginRegistry{},
		nil,
	)
	inlineSvc := casb.NewInline(
		casb.NewRepositoryInlineRuleStore(memory.NewInlineCASBRuleRepository(store)),
		memory.NewAuditLogRepository(store),
		nil,
	)
	casbHandler := handler.NewCASBHandler(discovery)
	casbHandler.SetInlineService(inlineSvc)

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
		CASB:   casbHandler,
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

func TestCASBHandler_InlineRule_CreateGetListUpdateDelete(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newInlineCASBTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/casb/inline-rules"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"app_id":   "m365",
		"action":   "share",
		"verdict":  "block",
		"enabled":  true,
		"priority": 100,
		"conditions": map[string]any{
			"file_type":      "docx",
			"size_threshold": 10485760,
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatalf("create returned empty id: %+v", created)
	}
	if created["app_id"] != "m365" || created["action"] != "share" || created["verdict"] != "block" {
		t.Errorf("unexpected create payload: %+v", created)
	}

	// GET
	rec = doJSON(t, router, http.MethodGet, path+"/"+id, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("LIST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("list count = %d, want 1", len(list.Items))
	}

	// PATCH — disable + change verdict
	rec = doJSON(t, router, http.MethodPatch, path+"/"+id, token, map[string]any{
		"enabled": false,
		"verdict": "log",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var patched map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched["verdict"] != "log" {
		t.Errorf("verdict = %q, want log", patched["verdict"])
	}
	if patched["enabled"] != false {
		t.Errorf("enabled = %v, want false", patched["enabled"])
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, path+"/"+id, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, router, http.MethodGet, path+"/"+id, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET-after-delete status = %d, want 404", rec.Code)
	}
}

func TestCASBHandler_InlineRule_RejectsInvalidApp(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newInlineCASBTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/casb/inline-rules"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"app_id":  "not-a-real-app",
		"action":  "upload",
		"verdict": "allow",
		"enabled": true,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid app status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

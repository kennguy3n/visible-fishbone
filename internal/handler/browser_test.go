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
	"github.com/kennguy3n/visible-fishbone/internal/service/browser"
)

func newBrowserTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
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

	svc := browser.New(
		memory.NewBrowserPolicyRepository(store),
		memory.NewAuditLogRepository(store),
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
		Config:  cfg,
		Browser: handler.NewBrowserHandler(svc),
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

func TestBrowserHandler_CRUD(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newBrowserTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/browser-policies"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"name":    "block-downloads",
		"action":  "block",
		"scope":   "user",
		"enabled": true,
		"rules": []map[string]any{
			{"type": "download", "action": "block", "condition": "*.exe"},
		},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.BrowserPolicyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID == "" {
		t.Fatal("expected non-empty ID")
	}
	if created.Name != "block-downloads" {
		t.Fatalf("name = %q, want block-downloads", created.Name)
	}

	// GET
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d", rec.Code)
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("LIST status = %d", rec.Code)
	}

	// PATCH
	rec = doJSON(t, router, http.MethodPatch, path+"/"+created.ID, token, map[string]any{
		"name": "updated-name",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var updated handler.BrowserPolicyResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &updated)
	if updated.Name != "updated-name" {
		t.Fatalf("name = %q, want updated-name", updated.Name)
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d", rec.Code)
	}

	// Confirm deleted
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET after delete = %d, want 404", rec.Code)
	}
}

func TestBrowserHandler_MissingName(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newBrowserTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/browser-policies"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"action": "block",
		"scope":  "user",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

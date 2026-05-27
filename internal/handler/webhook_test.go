package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/webhook"
)

// newWebhookTestRouter wires a real router (handler + middleware
// stack including JWT auth) backed by memory repos so HTTP tests
// exercise the same call path as production.
func newWebhookTestRouter(t *testing.T) (http.Handler, *memory.Store, uuid.UUID, uuid.UUID, string) {
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

	svc := webhook.New(
		memory.NewWebhookEndpointRepository(store),
		memory.NewWebhookDeliveryRepository(store),
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
		Config:   cfg,
		Webhooks: handler.NewWebhookHandler(svc),
	})

	// Mint a JWT carrying user + tenant claims so middleware Auth
	// resolves the same identity the handler will audit.
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
	return router, store, tenantID, userID, signed
}

func doJSON(t *testing.T, h http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestWebhookHandler_CreateGetListUpdateDelete(t *testing.T) {
	t.Parallel()
	router, store, tenantID, userID, token := newWebhookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/webhooks"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"url":    "https://example.com/hook",
		"events": []string{"tenant.created"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.WebhookEndpointResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" || created.Secret == "" {
		t.Fatalf("create missing id/secret: %+v", created)
	}
	if created.TenantID != tenantID.String() {
		t.Errorf("tenant_id = %q", created.TenantID)
	}

	// GET
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got handler.WebhookEndpointResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if got.Secret != "" {
		t.Errorf("GET must not echo the secret, got %q", got.Secret)
	}
	if got.URL != "https://example.com/hook" {
		t.Errorf("url = %q", got.URL)
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("LIST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []handler.WebhookEndpointResponse `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Errorf("list count = %d, want 1", len(list.Items))
	}
	for _, it := range list.Items {
		if it.Secret != "" {
			t.Errorf("LIST must not echo secret on %s", it.ID)
		}
	}

	// PATCH (status disable)
	rec = doJSON(t, router, http.MethodPatch, path+"/"+created.ID, token, map[string]any{
		"status": "disabled",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var updated handler.WebhookEndpointResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if updated.Status != "disabled" {
		t.Errorf("status = %q, want disabled", updated.Status)
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// GET 404 after delete
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET-after-delete status = %d, want 404", rec.Code)
	}

	// Audit trail must record actor=userID for both create and delete.
	audit := memory.NewAuditLogRepository(store)
	page, err := audit.List(context.Background(), tenantID, repository.AuditFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(page.Items) == 0 {
		t.Fatal("audit log empty")
	}
	for _, e := range page.Items {
		if e.ActorID == nil || *e.ActorID != userID {
			t.Errorf("audit entry %s actor = %v, want %v", e.Action, e.ActorID, userID)
		}
	}
}

func TestWebhookHandler_CreateRejectsInvalidURL(t *testing.T) {
	t.Parallel()
	router, _, tenantID, _, token := newWebhookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/webhooks"
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"url":    "ftp://nope",
		"events": []string{"x"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookHandler_UnauthenticatedRejected(t *testing.T) {
	t.Parallel()
	router, _, tenantID, _, _ := newWebhookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/webhooks"
	rec := doJSON(t, router, http.MethodGet, path, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestWebhookHandler_CrossTenantIsolation(t *testing.T) {
	t.Parallel()
	router, store, tenantA, _, tokenA := newWebhookTestRouter(t)

	// Provision tenant B + a separate user/token for it.
	tenantB := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantB, Name: "Other", Slug: "other",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant B: %v", err)
	}
	pathA := "/api/v1/tenants/" + tenantA.String() + "/webhooks"
	rec := doJSON(t, router, http.MethodPost, pathA, tokenA, map[string]any{
		"url":    "https://example.com/hook",
		"events": []string{"x"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.WebhookEndpointResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Tenant B's user attempting GET on tenant A's endpoint must 404.
	tokenB := mintJWT(t, "test-jwt-secret-key", uuid.New(), tenantB)
	rec = doJSON(t, router, http.MethodGet,
		"/api/v1/tenants/"+tenantB.String()+"/webhooks/"+created.ID, tokenB, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("cross-tenant GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func mintJWT(t *testing.T, secret string, userID, tenantID uuid.UUID) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       userID.String(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

func TestWebhookHandler_ListDeliveriesEmpty(t *testing.T) {
	t.Parallel()
	router, _, tenantID, _, token := newWebhookTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/webhooks"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"url":    "https://example.com/hook",
		"events": []string{"tenant.created"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d", rec.Code)
	}
	var created handler.WebhookEndpointResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID+"/deliveries", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("deliveries GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []handler.WebhookDeliveryResponse `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 0 {
		t.Errorf("deliveries = %d, want 0", len(resp.Items))
	}
	if !strings.Contains(rec.Body.String(), "items") {
		t.Errorf("response body missing items key: %s", rec.Body.String())
	}
}

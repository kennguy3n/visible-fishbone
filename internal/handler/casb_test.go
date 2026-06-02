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

// stubCASBPlugin is the minimum CASBConnectorPlugin for handler tests.
type stubCASBPlugin struct {
	kind    repository.CASBConnectorType
	testErr error
}

func (s *stubCASBPlugin) Type() repository.CASBConnectorType { return s.kind }
func (s *stubCASBPlugin) Connect(_ context.Context, _ json.RawMessage, _ []byte) error {
	return nil
}
func (s *stubCASBPlugin) ListUsers(_ context.Context, _ json.RawMessage, _ []byte) ([]casb.SaaSUser, error) {
	return []casb.SaaSUser{{ID: "u1", Email: "a@b.com", DisplayName: "Alice", Active: true}}, nil
}
func (s *stubCASBPlugin) ListActivity(_ context.Context, _ json.RawMessage, _ []byte, _ string) ([]casb.ActivityEvent, error) {
	return []casb.ActivityEvent{{ID: "ev1", Actor: "a@b.com", Action: "login", Timestamp: time.Now()}}, nil
}
func (s *stubCASBPlugin) AssessPosture(_ context.Context, _ json.RawMessage, _ []byte) (casb.PostureReport, error) {
	return casb.PostureReport{
		Checks:    []casb.PostureCheck{{Name: "mfa", Status: casb.CheckStatusPass, Evidence: "ok"}},
		RiskScore: 80,
	}, nil
}
func (s *stubCASBPlugin) Test(_ context.Context, _ json.RawMessage, _ []byte) error {
	return s.testErr
}

func newCASBTestRouter(t *testing.T, testErr error) (
	http.Handler, uuid.UUID, string,
) {
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

	stub := &stubCASBPlugin{kind: repository.CASBConnectorM365, testErr: testErr}
	svc := casb.New(
		memory.NewCASBConnectorRepository(store),
		memory.NewCASBDiscoveredAppRepository(store),
		memory.NewCASBPostureCheckRepository(store),
		memory.NewAuditLogRepository(store),
		casb.PluginRegistry{repository.CASBConnectorM365: stub},
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
		CASB:   handler.NewCASBHandler(svc),
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

func TestCASBHandler_CreateGetListUpdateDelete(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newCASBTestRouter(t, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/casb/connectors"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "m365",
		"name":   "azure-prod",
		"config": map[string]string{"tenant_id": "az-tid", "client_id": "cid"},
		"secret": json.RawMessage(`{"client_secret":"s3cr3t"}`),
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
	if _, exists := created["secret"]; exists {
		t.Errorf("CREATE response leaked `secret` field")
	}
	if got, _ := created["secret_set"].(bool); !got {
		t.Errorf("secret_set = false on create; want true")
	}
	if created["type"] != "m365" {
		t.Errorf("type = %q", created["type"])
	}

	// GET — secret must never be present
	rec = doJSON(t, router, http.MethodGet, path+"/"+id, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if _, exists := got["secret"]; exists {
		t.Errorf("GET response leaked `secret` field")
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
	for _, it := range list.Items {
		if _, exists := it["secret"]; exists {
			t.Errorf("LIST item leaked `secret`")
		}
	}

	// PATCH — rename
	rec = doJSON(t, router, http.MethodPatch, path+"/"+id, token, map[string]any{
		"name": "azure-prod-renamed",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var patched map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if patched["name"] != "azure-prod-renamed" {
		t.Errorf("name = %q", patched["name"])
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

func TestCASBHandler_TestEndpoint(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newCASBTestRouter(t, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/casb/connectors"

	// Create a connector first.
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "m365",
		"name":   "test-conn",
		"config": map[string]string{"tenant_id": "tid", "client_id": "cid"},
		"secret": json.RawMessage(`{"client_secret":"s"}`),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d", rec.Code)
	}
	var c map[string]any
	json.Unmarshal(rec.Body.Bytes(), &c)
	id := c["id"].(string)

	// POST /test
	rec = doJSON(t, router, http.MethodPost, path+"/"+id+"/test", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("TEST status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCASBHandler_SyncEndpoint(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newCASBTestRouter(t, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/casb/connectors"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "m365",
		"name":   "sync-conn",
		"config": map[string]string{"tenant_id": "tid", "client_id": "cid"},
		"secret": json.RawMessage(`{"client_secret":"s"}`),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d", rec.Code)
	}
	var c map[string]any
	json.Unmarshal(rec.Body.Bytes(), &c)
	id := c["id"].(string)

	// POST /sync
	rec = doJSON(t, router, http.MethodPost, path+"/"+id+"/sync", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("SYNC status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestCASBHandler_RejectsInvalidType(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newCASBTestRouter(t, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/casb/connectors"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type": "invalid_connector",
		"name": "bad",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid type status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

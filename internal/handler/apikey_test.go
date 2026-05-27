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
	"github.com/kennguy3n/visible-fishbone/internal/service/apikey"
)

// newAPIKeyTestRouter wires a real router + JWT auth against
// memory repos so the apikey handler runs end-to-end through the
// production middleware stack.
func newAPIKeyTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
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

	svc := apikey.New(
		memory.NewTenantAPIKeyRepository(store),
		memory.NewAuditLogRepository(store),
		apikey.WithAsyncTouch(func(fn func()) { fn() }),
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
		Config:       cfg,
		APIKeys:      handler.NewAPIKeyHandler(svc),
		APIKeyLookup: svc,
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

func TestAPIKeyHandler_CreateReturnsPlaintextOnce(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newAPIKeyTestRouter(t)
	rr := doJSON(t, router, http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/api-keys", token, map[string]any{
		"name":    "ci-bot",
		"subject": "bot:ci",
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var created struct {
		ID        string `json:"id"`
		Plaintext string `json:"plaintext"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if created.Plaintext == "" {
		t.Fatalf("plaintext missing from Create response")
	}
	if created.Status != "active" {
		t.Fatalf("status should be active, got %q", created.Status)
	}

	// Subsequent Get must NOT include the plaintext.
	got := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/api-keys/"+created.ID, token, nil)
	if got.Code != http.StatusOK {
		t.Fatalf("Get: expected 200, got %d", got.Code)
	}
	var ret map[string]any
	if err := json.Unmarshal(got.Body.Bytes(), &ret); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v, ok := ret["plaintext"]; ok && v != "" {
		t.Fatalf("plaintext must be omitted from Get, got %v", v)
	}
}

func TestAPIKeyHandler_RevokedKeyRejectsAuth(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newAPIKeyTestRouter(t)
	create := doJSON(t, router, http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/api-keys", token, map[string]any{
		"name": "x", "subject": "y",
	})
	if create.Code != http.StatusCreated {
		t.Fatalf("Create: %d %s", create.Code, create.Body.String())
	}
	var created struct {
		ID        string `json:"id"`
		Plaintext string `json:"plaintext"`
	}
	_ = json.Unmarshal(create.Body.Bytes(), &created)

	// Use the freshly minted key to authenticate a follow-up
	// request — confirms the Auth middleware -> APIKeyLookup -> svc
	// path works end-to-end before we revoke.
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/api-keys/"+created.ID, nil)
	req.Header.Set("X-SNG-API-Key", created.Plaintext)
	rr := &responseRecorder{}
	rr.reset()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid API key, got %d: %s", rr.Code, rr.body)
	}

	// Revoke and try again — should be 401.
	rev := doJSON(t, router, http.MethodDelete, "/api/v1/tenants/"+tenantID.String()+"/api-keys/"+created.ID, token, nil)
	if rev.Code != http.StatusNoContent {
		t.Fatalf("Revoke: expected 204, got %d", rev.Code)
	}
	req2, _ := http.NewRequest(http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/api-keys", nil)
	req2.Header.Set("X-SNG-API-Key", created.Plaintext)
	rr.reset()
	router.ServeHTTP(rr, req2)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("revoked key should return 401, got %d: %s", rr.Code, rr.body)
	}
}

func TestAPIKeyHandler_ListExcludesPlaintext(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newAPIKeyTestRouter(t)
	for i := 0; i < 2; i++ {
		rr := doJSON(t, router, http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/api-keys", token, map[string]any{
			"name": "k", "subject": "s",
		})
		if rr.Code != http.StatusCreated {
			t.Fatalf("Create: %d", rr.Code)
		}
	}
	rr := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/api-keys", token, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("List: expected 200, got %d", rr.Code)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(resp.Items))
	}
	for _, it := range resp.Items {
		if v, ok := it["plaintext"]; ok && v != "" {
			t.Fatalf("List item should omit plaintext, got %v", v)
		}
	}
}

func TestAPIKeyHandler_RejectsBadExpiresAt(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newAPIKeyTestRouter(t)
	rr := doJSON(t, router, http.MethodPost, "/api/v1/tenants/"+tenantID.String()+"/api-keys", token, map[string]any{
		"name": "x", "subject": "y", "expires_at": "not-a-timestamp",
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

// responseRecorder is a minimal http.ResponseWriter that captures
// status + body without pulling in httptest. We use it for the
// raw API-key-as-credential test because httptest.ResponseRecorder
// shares helpers with the JWT-bearing helper above.
type responseRecorder struct {
	Code   int
	body   string
	header http.Header
}

func (r *responseRecorder) reset() {
	r.Code = 0
	r.body = ""
	r.header = http.Header{}
}

func (r *responseRecorder) Header() http.Header {
	if r.header == nil {
		r.header = http.Header{}
	}
	return r.header
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body += string(b)
	return len(b), nil
}

func (r *responseRecorder) WriteHeader(c int) { r.Code = c }

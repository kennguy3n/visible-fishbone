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
	"github.com/kennguy3n/visible-fishbone/internal/service/rbi"
	"github.com/kennguy3n/visible-fishbone/internal/service/residency"
	"github.com/kennguy3n/visible-fishbone/internal/service/sandbox"
)

const testSandboxSHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

func newSandboxRBITestRouter(t *testing.T, rbiProxyURL string) (http.Handler, uuid.UUID, string) {
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

	sandboxSvc := sandbox.NewService(
		memory.NewSandboxVerdictRepository(store),
		sandbox.WithCache(sandbox.NewCache()),
	)
	rbiSvc := rbi.NewService(
		memory.NewRBISessionRepository(store),
		rbi.WithProxy(rbi.ProxyConfig{BaseURL: rbiProxyURL}),
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
		Sandbox: handler.NewSandboxHandler(sandboxSvc),
		RBI:     handler.NewRBIHandler(rbiSvc),
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

func TestSandboxHandler_SubmitNoProvider_AndLookup(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newSandboxRBITestRouter(t, "")
	base := "/api/v1/tenants/" + tenantID.String() + "/sandbox"

	// Submit with no provider configured -> 202 Accepted, pending.
	rec := doJSON(t, router, http.MethodPost, base+"/submit", token, map[string]any{
		"sha256":         testSandboxSHA,
		"filename":       "evil.exe",
		"content_base64": "QUJDRA==", // "ABCD"
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}

	// Provider status -> not configured.
	rec = doJSON(t, router, http.MethodGet, base+"/provider", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("provider status: expected 200, got %d", rec.Code)
	}
	var status struct {
		Configured bool `json:"configured"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Configured {
		t.Fatal("expected provider not configured")
	}

	// Get the pending verdict by digest.
	rec = doJSON(t, router, http.MethodGet, base+"/verdicts/"+testSandboxSHA, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get verdict: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// List verdicts.
	rec = doJSON(t, router, http.MethodGet, base+"/verdicts", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list verdicts: expected 200, got %d", rec.Code)
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 verdict, got %d", len(list.Items))
	}
}

func TestSandboxHandler_InvalidSHA(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newSandboxRBITestRouter(t, "")
	base := "/api/v1/tenants/" + tenantID.String() + "/sandbox"

	rec := doJSON(t, router, http.MethodPost, base+"/submit", token, map[string]any{
		"sha256": "not-a-valid-hash",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid sha, got %d", rec.Code)
	}
}

func TestSandboxHandler_GetUnknown_NotFound(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newSandboxRBITestRouter(t, "")
	base := "/api/v1/tenants/" + tenantID.String() + "/sandbox"

	rec := doJSON(t, router, http.MethodGet, base+"/verdicts/"+testSandboxSHA, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown digest, got %d", rec.Code)
	}
}

func TestRBIHandler_CreateGetListClose(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newSandboxRBITestRouter(t, "https://rbi.example.com")
	base := "/api/v1/tenants/" + tenantID.String() + "/rbi/sessions"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"target_url": "https://gambling.example",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID       string `json:"id"`
		ProxyURL string `json:"proxy_url"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ProxyURL == "" {
		t.Fatal("expected proxy URL")
	}
	if created.Status != "active" {
		t.Fatalf("expected active, got %s", created.Status)
	}

	// GET
	rec = doJSON(t, router, http.MethodGet, base+"/"+created.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d", rec.Code)
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rec.Code)
	}

	// CLOSE
	rec = doJSON(t, router, http.MethodDelete, base+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("close: expected 204, got %d", rec.Code)
	}
}

func TestRBIHandler_CreateNotConfigured(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newSandboxRBITestRouter(t, "")
	base := "/api/v1/tenants/" + tenantID.String() + "/rbi/sessions"

	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"target_url": "https://x.com",
	})
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when RBI not configured, got %d", rec.Code)
	}
}

func TestRBIHandler_PolicyProbe(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newSandboxRBITestRouter(t, "https://rbi.example.com")
	path := "/api/v1/tenants/" + tenantID.String() + "/rbi/policy"

	rec := doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("policy: expected 200, got %d", rec.Code)
	}
	var probe struct {
		Configured bool `json:"configured"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &probe); err != nil {
		t.Fatal(err)
	}
	if !probe.Configured {
		t.Fatal("expected configured=true")
	}
}

// denyResidencyGuard is a residency guard that always rejects, used to
// drive the handler's residency-violation path.
type denyResidencyGuard struct{}

func (denyResidencyGuard) Check(_ context.Context, _ uuid.UUID) error {
	return residency.ErrResidencyViolation
}

// TestRBIHandler_ArtifactResidencyViolation verifies that when the
// fail-closed residency guard rejects an artifact write, the handler
// surfaces a distinct 403 residency_violation rather than a generic
// 500. The artifact policy permits the transfer so the request clears
// the policy gate and reaches the residency check.
func TestRBIHandler_ArtifactResidencyViolation(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	rbiSvc := rbi.NewService(
		memory.NewRBISessionRepository(store),
		rbi.WithProxy(rbi.ProxyConfig{BaseURL: "https://rbi.example.com"}),
		rbi.WithArtifactRepo(memory.NewRBIArtifactRepository(store)),
		rbi.WithArtifactPolicy(rbi.ArtifactPolicy{FileUpload: true}),
		rbi.WithResidencyGuard(denyResidencyGuard{}),
	)

	// Create an active session directly so the artifact has a parent.
	sess, err := rbiSvc.CreateSession(context.Background(), tenantID, rbi.CreateSessionInput{TargetURL: "https://x.example"}, nil)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	jwtSecret := "test-jwt-secret-key"
	router := handler.NewRouter(handler.RouterDeps{
		Config: &config.Config{Auth: config.Auth{
			JWTSecret: jwtSecret, JWTIssuer: "sng-control", JWTAudience: "sng-control", APIKeyHeader: "X-SNG-API-Key",
		}},
		RBI: handler.NewRBIHandler(rbiSvc),
	})
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "sng-control", "aud": "sng-control", "sub": uuid.NewString(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	path := "/api/v1/tenants/" + tenantID.String() + "/rbi/sessions/" + sess.ID.String() + "/artifacts"
	rec := doJSON(t, router, http.MethodPost, path, signed, map[string]any{
		"kind": "file_upload", "direction": "outbound", "filename": "p.pdf",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on residency violation, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Error.Code != "residency_violation" {
		t.Fatalf("expected error code residency_violation, got %q (%s)", body.Error.Code, rec.Body.String())
	}
}

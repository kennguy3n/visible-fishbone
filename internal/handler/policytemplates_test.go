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
	"github.com/kennguy3n/visible-fishbone/internal/service/policytemplates"
)

const policyTemplateTestJWTSecret = "test-jwt-secret-key"

// signPolicyTemplateToken mints a signed HS256 token for the test
// router. A "tenant_id" claim binds the caller to that tenant (the
// per-tenant routes and the cross-tenant scope check observe it);
// omit it to model a platform/global operator with no tenant binding.
func signPolicyTemplateToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"] = "sng-control"
	claims["aud"] = "sng-control"
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
	if _, ok := claims["sub"]; !ok {
		claims["sub"] = uuid.NewString()
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).
		SignedString([]byte(policyTemplateTestJWTSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

func newPolicyTemplateTestRouter(t *testing.T, opts ...handler.PolicyTemplateOption) (http.Handler, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-policytemplates",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	svc := policytemplates.New(memory.NewPolicyTemplateRepository(), nil)

	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    policyTemplateTestJWTSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	router := handler.NewRouter(handler.RouterDeps{
		Config:          cfg,
		PolicyTemplates: handler.NewPolicyTemplateHandler(svc, opts...),
	})

	// A tenant-bound token: fine for the per-tenant routes, and the
	// cross-tenant tests that need a platform operator mint their own
	// token without a tenant_id claim.
	signed := signPolicyTemplateToken(t, jwt.MapClaims{"tenant_id": tenantID.String()})
	return router, tenantID, signed
}

func TestPolicyTemplateHandler_ListCatalog(t *testing.T) {
	t.Parallel()
	router, _, token := newPolicyTemplateTestRouter(t)

	rec := doJSON(t, router, http.MethodGet, "/api/v1/policy-templates", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// 1 baseline + 8 industries + 5 compliance regimes.
	if len(body.Items) != 14 {
		t.Fatalf("expected 14 catalog templates, got %d", len(body.Items))
	}
}

func TestPolicyTemplateHandler_GetTemplate(t *testing.T) {
	t.Parallel()
	router, _, token := newPolicyTemplateTestRouter(t)

	// Template IDs carry a slash; the {id...} wildcard must capture it.
	rec := doJSON(t, router, http.MethodGet, "/api/v1/policy-templates/industry/finance", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var tmpl map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &tmpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tmpl["id"] != "industry/finance" {
		t.Fatalf("expected id industry/finance, got %v", tmpl["id"])
	}
}

func TestPolicyTemplateHandler_GetTemplateNotFound(t *testing.T) {
	t.Parallel()
	router, _, token := newPolicyTemplateTestRouter(t)

	rec := doJSON(t, router, http.MethodGet, "/api/v1/policy-templates/industry/nope", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown template: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyTemplateHandler_Preview(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPolicyTemplateTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/policy-templates/preview"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"industry": "finance",
		"country":  "DE",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Regime      string          `json:"regime"`
		TemplateIDs []string        `json:"template_ids"`
		GraphHash   string          `json:"graph_hash"`
		Graph       json.RawMessage `json:"graph"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Regime != "eu-gdpr" {
		t.Errorf("DE should resolve to eu-gdpr, got %q", body.Regime)
	}
	if body.GraphHash == "" {
		t.Error("expected non-empty graph hash")
	}
	if len(body.Graph) == 0 {
		t.Error("preview must include the rendered graph")
	}
}

func TestPolicyTemplateHandler_PreviewInvalid(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPolicyTemplateTestRouter(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/policy-templates/preview"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"industry": "finance",
		"country":  "ZZ", // unsupported country
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsupported country: expected 400, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestPolicyTemplateHandler_ApplyIdempotentAndGet(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newPolicyTemplateTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/policy-templates"

	// 404 before any apply.
	rec := doJSON(t, router, http.MethodGet, base+"/applied", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("pre-apply get: expected 404, got %d: %s", rec.Code, rec.Body.String())
	}

	// First apply.
	rec = doJSON(t, router, http.MethodPost, base+"/apply", token, map[string]any{
		"industry": "healthcare",
		"country":  "GB",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("apply: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var first struct {
		Regime    string `json:"regime"`
		GraphHash string `json:"graph_hash"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &first)
	if first.Regime != "uk-dpa" {
		t.Errorf("GB should resolve to uk-dpa, got %q", first.Regime)
	}

	// Re-apply the same selection: idempotent, same hash.
	rec = doJSON(t, router, http.MethodPost, base+"/apply", token, map[string]any{
		"industry": "healthcare",
		"country":  "GB",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-apply: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var second struct {
		GraphHash string `json:"graph_hash"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &second)
	if second.GraphHash != first.GraphHash {
		t.Errorf("idempotent re-apply changed hash: %q -> %q", first.GraphHash, second.GraphHash)
	}

	// GetApplied now returns the stored baseline.
	rec = doJSON(t, router, http.MethodGet, base+"/applied", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get applied: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

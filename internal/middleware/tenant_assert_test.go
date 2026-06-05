package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

func TestAssertTenantContext_RejectsUnscopedCredential(t *testing.T) {
	called := false
	h := AssertTenantContext(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))

	// No tenant bound to the context → fail closed with 403.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/policies", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if called {
		t.Fatal("handler should not run without a tenant-scoped credential")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}

func TestAssertTenantContext_StampsExpectedTenant(t *testing.T) {
	tid := uuid.New()
	var seen string
	var ok bool
	h := AssertTenantContext(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, ok = postgres.ExpectedTenantFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/policies", nil)
	req = req.WithContext(withTenantID(req.Context(), tid))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !ok || seen != tid.String() {
		t.Errorf("expected RLS tenant = %q (ok=%v), want %q", seen, ok, tid.String())
	}
}

func TestRequireTenant_StampsExpectedTenant(t *testing.T) {
	tid := uuid.New()
	var seen string
	var ok bool
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, ok = postgres.ExpectedTenantFromContext(r.Context())
	})
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/tenants/{tenant_id}/x", RequireTenant("tenant_id")(inner))

	// Credential carries the matching tenant claim.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+tid.String()+"/x", nil)
	req = req.WithContext(withTenantID(req.Context(), tid))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !ok || seen != tid.String() {
		t.Errorf("expected RLS tenant = %q (ok=%v), want %q", seen, ok, tid.String())
	}
}

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/appid"
)

// stubCatalogService is an in-memory AppIDCatalogService for handler
// tests. Each field controls one method's result.
type stubCatalogService struct {
	version      repository.AppIDCatalogVersion
	versionErr   error
	bundle       appid.SignedBundle
	bundleVer    repository.AppIDCatalogVersion
	bundleErr    error
	versions     []repository.AppIDCatalogVersion
	versionsErr  error
	republished  repository.AppIDCatalogVersion
	republishErr error
	republishGot string
}

func (s *stubCatalogService) CurrentVersion(context.Context) (repository.AppIDCatalogVersion, error) {
	return s.version, s.versionErr
}

func (s *stubCatalogService) CurrentBundle(context.Context) (appid.SignedBundle, repository.AppIDCatalogVersion, error) {
	return s.bundle, s.bundleVer, s.bundleErr
}

func (s *stubCatalogService) ListVersions(context.Context, int) ([]repository.AppIDCatalogVersion, error) {
	return s.versions, s.versionsErr
}

func (s *stubCatalogService) Republish(_ context.Context, note string) (repository.AppIDCatalogVersion, error) {
	s.republishGot = note
	return s.republished, s.republishErr
}

// stubAuthz is a PlatformAuthorizer that returns a fixed decision.
type stubAuthz struct {
	allow bool
	err   error
}

func (a stubAuthz) AuthorizePlatform(context.Context, uuid.UUID, string) (bool, error) {
	return a.allow, a.err
}

const testTenant = "11111111-1111-1111-1111-111111111111"

// withUser injects an authenticated user id into the request context,
// as the auth middleware would.
func withUser(r *http.Request) *http.Request {
	ctx := middleware.WithUserIDForTest(r.Context(), uuid.New())
	return r.WithContext(ctx)
}

func newCatalogMux(svc AppIDCatalogService, authz PlatformAuthorizer) *http.ServeMux {
	mux := http.NewServeMux()
	NewAppIDHandler(svc, authz).Register(mux)
	return mux
}

func TestAppIDRegisterNilDisablesRoutes(t *testing.T) {
	mux := newCatalogMux(nil, stubAuthz{allow: true})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+testTenant+"/appid/catalog/bundle", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when service is nil, got %d", rec.Code)
	}
}

func TestAppIDTenantBundleHappyPath(t *testing.T) {
	svc := &stubCatalogService{
		bundle: appid.SignedBundle{Algorithm: appid.Algorithm, Payload: "cGF5", Signature: "c2ln", PublicKey: "cHVi"},
		bundleVer: repository.AppIDCatalogVersion{
			Serial: 100, SchemaVersion: 1, AppCount: 215, Checksum: "abc", CreatedAt: time.Now(),
		},
	}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+testTenant+"/appid/catalog/bundle", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp CatalogBundleResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Version.Serial != 100 || resp.Version.AppCount != 215 {
		t.Fatalf("unexpected version: %+v", resp.Version)
	}
	if resp.Bundle.Payload != "cGF5" || resp.Bundle.Algorithm != appid.Algorithm {
		t.Fatalf("unexpected bundle: %+v", resp.Bundle)
	}
}

func TestAppIDTenantBundleDegradesTo503(t *testing.T) {
	svc := &stubCatalogService{bundleErr: repository.ErrNotFound}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+testTenant+"/appid/catalog/bundle", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 when catalog unseeded, got %d", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("expected Retry-After header on 503")
	}
}

func TestAppIDTenantMismatchForbidden(t *testing.T) {
	svc := &stubCatalogService{bundleVer: repository.AppIDCatalogVersion{Serial: 1}}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	// Bind a credential to a DIFFERENT tenant than the path tenant.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+testTenant+"/appid/catalog/bundle", nil)
	ctx := middleware.WithTenantIDForTest(req.Context(), uuid.New())
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on tenant mismatch, got %d", rec.Code)
	}
}

func TestAppIDAdminPublishRequiresPlatform(t *testing.T) {
	svc := &stubCatalogService{republished: repository.AppIDCatalogVersion{Serial: 7}}
	mux := newCatalogMux(svc, stubAuthz{allow: false})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/admin/appid/catalog/versions", nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without platform grant, got %d", rec.Code)
	}
}

func TestAppIDAdminPublishUnauthenticated(t *testing.T) {
	svc := &stubCatalogService{}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	// No user id in context.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/appid/catalog/versions", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without user identity, got %d", rec.Code)
	}
}

func TestAppIDAdminPublishHappyPath(t *testing.T) {
	svc := &stubCatalogService{republished: repository.AppIDCatalogVersion{Serial: 7, AppCount: 215}}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	body := strings.NewReader(`{"note":"rotate signing key"}`)
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/admin/appid/catalog/versions", body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	if svc.republishGot != "rotate signing key" {
		t.Fatalf("note not forwarded: %q", svc.republishGot)
	}
	var resp CatalogVersionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Serial != 7 {
		t.Fatalf("unexpected serial: %d", resp.Serial)
	}
}

func TestAppIDAdminPublishEmptyBodyOK(t *testing.T) {
	svc := &stubCatalogService{republished: repository.AppIDCatalogVersion{Serial: 8}}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	req := withUser(httptest.NewRequest(http.MethodPost, "/api/v1/admin/appid/catalog/versions", nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 with empty body, got %d (%s)", rec.Code, rec.Body.String())
	}
	if svc.republishGot != "" {
		t.Fatalf("expected empty note, got %q", svc.republishGot)
	}
}

func TestAppIDAdminListVersions(t *testing.T) {
	svc := &stubCatalogService{versions: []repository.AppIDCatalogVersion{
		{Serial: 9}, {Serial: 8},
	}}
	mux := newCatalogMux(svc, stubAuthz{allow: true})
	req := withUser(httptest.NewRequest(http.MethodGet, "/api/v1/admin/appid/catalog/versions", nil))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp CatalogVersionsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Versions) != 2 || resp.Versions[0].Serial != 9 {
		t.Fatalf("unexpected versions: %+v", resp.Versions)
	}
}

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// newTestTenantHandler wires a TenantHandler against the in-memory
// repositories. Returns the handler and a tenant seeded with a
// non-empty Region so tests can exercise the PATCH-clear path.
func newTestTenantHandler(t *testing.T, region string) (*TenantHandler, repository.Tenant) {
	t.Helper()
	store := memory.NewStore()
	repo := memory.NewTenantRepository(store)
	audit := memory.NewAuditLogRepository(store)
	svc := tenant.New(repo, audit, nil)
	seed, err := svc.Create(context.Background(), repository.Tenant{
		Name:   "Acme",
		Slug:   "acme",
		Region: region,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return NewTenantHandler(svc), seed
}

// patchTenant drives the handler's update method end-to-end, with
// the path value populated the same way Go's pattern mux would
// after route matching.
func patchTenant(t *testing.T, h *TenantHandler, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch,
		"/api/v1/tenants/"+id, bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", id)
	rec := httptest.NewRecorder()
	h.update(rec, req)
	return rec
}

// TestTenantPATCH_ClearRegion is the regression test for the PR6
// round-4 Devin Review finding: the previous TenantUpdateRequest
// used `Region string` with an `if req.Region != ""` guard, so an
// operator who set Region by mistake during onboarding could never
// remove it through the API — the only recourse was a manual
// `UPDATE tenants SET region=” WHERE id=...`, defeating the
// point of the PATCH endpoint.
//
// The fix changes Region to `*string`: nil = "field absent, leave
// alone", non-nil = "apply, including the empty string". This
// test sends `"region": ""` and asserts the persisted Region is
// now empty.
func TestTenantPATCH_ClearRegion(t *testing.T) {
	t.Parallel()
	h, seed := newTestTenantHandler(t, "us-east-1")
	if seed.Region != "us-east-1" {
		t.Fatalf("seed precondition: Region = %q, want %q", seed.Region, "us-east-1")
	}

	rec := patchTenant(t, h, seed.ID.String(), `{"region":""}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp TenantResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Region != "" {
		t.Errorf("Region = %q, want \"\" (PATCH with explicit empty string must clear)",
			resp.Region)
	}
}

// TestTenantPATCH_OmittedRegionLeavesItUnchanged guards the other
// half of the contract: a PATCH that does NOT mention `region` at
// all must leave the existing value alone. Without the *string
// pointer this is the *only* path the old code supported; we keep
// the assertion so a future refactor that "simplifies" Region
// back to a plain string can't quietly break the
// absent-vs-empty distinction in the other direction.
func TestTenantPATCH_OmittedRegionLeavesItUnchanged(t *testing.T) {
	t.Parallel()
	h, seed := newTestTenantHandler(t, "eu-west-1")

	rec := patchTenant(t, h, seed.ID.String(), `{"name":"Acme Renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp TenantResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Name != "Acme Renamed" {
		t.Errorf("Name = %q, want %q", resp.Name, "Acme Renamed")
	}
	if resp.Region != "eu-west-1" {
		t.Errorf("Region = %q, want %q (omitting `region` must leave it alone)",
			resp.Region, "eu-west-1")
	}
}

// TestTenantPATCH_ChangeRegion confirms the everyday case still
// works after the pointer refactor: a non-empty value overrides
// the existing one.
func TestTenantPATCH_ChangeRegion(t *testing.T) {
	t.Parallel()
	h, seed := newTestTenantHandler(t, "us-east-1")

	rec := patchTenant(t, h, seed.ID.String(), `{"region":"ap-south-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp TenantResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Region != "ap-south-1" {
		t.Errorf("Region = %q, want %q", resp.Region, "ap-south-1")
	}
}

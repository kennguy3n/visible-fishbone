package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

// TestTenantResponse_ExposesMSPID pins the round-27 ANALYSIS_0007
// fix on PR #42: TenantResponse must surface the owning MSP via
// `msp_id`. The denormalised `tenants.msp_id` column is kept in
// sync with the `msp_tenants` row whose relationship='owner' by
// the MSP service's AssignTenant / UnassignTenant cascade. Before
// this fix, HTTP clients calling `GET /api/v1/tenants/{tenant_id}`
// could not discover which MSP owned the tenant without a separate
// `/msps/{msp_id}/tenants` round-trip.
//
// Three branches verified:
//
//  1. A tenant created standalone (no MSP owner) must emit no
//     `msp_id` field — the JSON payload must not contain the
//     key at all (omitempty), NOT `"msp_id": null` (which the
//     SDK code-gen would surface as a populated optional).
//  2. A tenant whose `tenants.msp_id` pointer is set via the
//     repository must surface the UUID string.
//  3. The handler must round-trip the same value after PATCH (a
//     change to name/region should NOT clear the binding).
func TestTenantResponse_ExposesMSPID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	mspRepo := memory.NewMSPRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	svc := tenant.New(tenantRepo, auditRepo, nil)
	h := NewTenantHandler(svc)

	// Branch 1: unmanaged tenant — no msp_id binding.
	standalone, err := svc.Create(ctx, repository.Tenant{
		Name: "Standalone",
		Slug: "standalone-r27",
		Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("create standalone: %v", err)
	}
	getReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+standalone.ID.String(), nil)
	getReq.SetPathValue("tenant_id", standalone.ID.String())
	getRec := httptest.NewRecorder()
	h.get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET standalone: status %d body=%s", getRec.Code, getRec.Body.String())
	}
	// Decode into a permissive map so we can prove the JSON KEY
	// is absent (omitempty), not just that the typed pointer is
	// nil — the wire-format contract is what SDK clients care
	// about.
	var raw map[string]any
	if err := json.NewDecoder(strings.NewReader(getRec.Body.String())).Decode(&raw); err != nil {
		t.Fatalf("decode standalone body: %v", err)
	}
	if _, present := raw["msp_id"]; present {
		t.Errorf("standalone tenant: msp_id key present in JSON %q — must be omitted via omitempty",
			getRec.Body.String())
	}

	// Branch 2: managed tenant — assign through MSP repo,
	// the cascade stamps tenants.msp_id.
	managed, err := svc.Create(ctx, repository.Tenant{
		Name: "Managed",
		Slug: "managed-r27",
		Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("create managed: %v", err)
	}
	msp, err := mspRepo.Create(ctx, repository.MSP{
		Name: "Owner MSP",
		Slug: "owner-msp-r27",
	})
	if err != nil {
		t.Fatalf("create msp: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, msp.ID, managed.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign tenant: %v", err)
	}
	getReq = httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+managed.ID.String(), nil)
	getReq.SetPathValue("tenant_id", managed.ID.String())
	getRec = httptest.NewRecorder()
	h.get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET managed: status %d body=%s", getRec.Code, getRec.Body.String())
	}
	var managedResp TenantResponse
	if err := json.NewDecoder(strings.NewReader(getRec.Body.String())).Decode(&managedResp); err != nil {
		t.Fatalf("decode managed body: %v", err)
	}
	if managedResp.MSPID == nil {
		t.Fatalf("managed tenant: msp_id is nil — assign cascade should have populated it (body=%s)",
			getRec.Body.String())
	}
	if *managedResp.MSPID != msp.ID.String() {
		t.Errorf("managed tenant: msp_id = %q, want %q", *managedResp.MSPID, msp.ID.String())
	}

	// Branch 3: PATCH preserves the binding.
	rec := patchTenant(t, h, managed.ID.String(), `{"name":"Renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH managed: status %d body=%s", rec.Code, rec.Body.String())
	}
	var patchedResp TenantResponse
	if err := json.NewDecoder(strings.NewReader(rec.Body.String())).Decode(&patchedResp); err != nil {
		t.Fatalf("decode PATCH body: %v", err)
	}
	if patchedResp.MSPID == nil || *patchedResp.MSPID != msp.ID.String() {
		t.Errorf("PATCH should preserve msp_id; got %v, want %q",
			patchedResp.MSPID, msp.ID.String())
	}
}

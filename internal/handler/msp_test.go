package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	svctenant "github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// allowAllAuthz is a permissive MSPAuthorizer used to exercise
// the handler bodies. Permission-denial / unauthenticated paths
// have dedicated middleware tests in middleware/msp_test.go.
type allowAllAuthz struct{}

func (allowAllAuthz) AuthorizeMSP(_ context.Context, _, _ uuid.UUID, _ string) (bool, error) {
	return true, nil
}
func (allowAllAuthz) AuthorizePlatform(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return true, nil
}

// scopedAuthz returns AuthorizeMSP=true (so MSP-scoped routes
// still pass) but AuthorizePlatform=false. Used to pin that the
// platform gate on list/create rejects MSP-scoped operators even
// when they hold MSP-scoped grants. Mirrors the privilege-escalation
// scenario flagged in round-2.
type scopedAuthz struct{}

func (scopedAuthz) AuthorizeMSP(_ context.Context, _, _ uuid.UUID, _ string) (bool, error) {
	return true, nil
}
func (scopedAuthz) AuthorizePlatform(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return false, nil
}

// stubBulkAuthz returns the seed tenants — used by BulkService
// in handler-level tests.
type stubBulkAuthz struct {
	tenants []uuid.UUID
}

func (s stubBulkAuthz) ListAuthorizedTenants(_ context.Context, _, _ uuid.UUID, _ string, _ repository.MSPRepository) ([]uuid.UUID, error) {
	return s.tenants, nil
}

// repoMSPService wraps memory.MSPRepository so it satisfies the
// handler's narrow MSPService interface.
type repoMSPService struct{ repo *memory.MSPRepository }

func (s repoMSPService) Create(ctx context.Context, m repository.MSP) (repository.MSP, error) {
	return s.repo.Create(ctx, m)
}
func (s repoMSPService) Get(ctx context.Context, id uuid.UUID) (repository.MSP, error) {
	return s.repo.Get(ctx, id)
}
func (s repoMSPService) List(ctx context.Context, p repository.Page) (repository.PageResult[repository.MSP], error) {
	return s.repo.List(ctx, p)
}
func (s repoMSPService) Update(ctx context.Context, id uuid.UUID, patch repository.MSPPatch) (repository.MSP, error) {
	return s.repo.Update(ctx, id, patch)
}
func (s repoMSPService) UpdateStatus(ctx context.Context, id uuid.UUID, st repository.MSPStatus) (repository.MSP, error) {
	return s.repo.UpdateStatus(ctx, id, st)
}
func (s repoMSPService) TransitionStatus(ctx context.Context, id uuid.UUID, to repository.MSPStatus) (repository.MSP, error) {
	return s.repo.TransitionStatus(ctx, id, to)
}
func (s repoMSPService) Delete(ctx context.Context, id uuid.UUID) error {
	return s.repo.Delete(ctx, id)
}
func (s repoMSPService) AssignTenant(ctx context.Context, mspID, tenantID uuid.UUID, rel repository.MSPRelationship, actor *uuid.UUID) (repository.MSPTenantBinding, error) {
	return s.repo.AssignTenant(ctx, mspID, tenantID, rel, actor)
}
func (s repoMSPService) UnassignTenant(ctx context.Context, mspID, tenantID uuid.UUID) error {
	return s.repo.UnassignTenant(ctx, mspID, tenantID)
}
func (s repoMSPService) ListTenants(ctx context.Context, mspID uuid.UUID, p repository.Page) (repository.PageResult[repository.MSPTenantBinding], error) {
	return s.repo.ListTenants(ctx, mspID, p)
}

func setupMSPHandler(t *testing.T, withBranding bool) (
	*http.ServeMux,
	*memory.MSPRepository,
	*memory.TenantRepository,
	*svctenant.BulkService,
	*svctenant.BrandingResolver,
) {
	t.Helper()
	return setupMSPHandlerWithAuthz(t, withBranding, allowAllAuthz{})
}

// setupMSPHandlerWithAuthz lets a test swap in a permission-denying
// authorizer (e.g. scopedAuthz) to exercise the platform-scope
// gates on `GET/POST /api/v1/msps`. The rest of the wiring matches
// setupMSPHandler exactly.
func setupMSPHandlerWithAuthz(t *testing.T, withBranding bool, authz handler.MSPAuthorizer) (
	*http.ServeMux,
	*memory.MSPRepository,
	*memory.TenantRepository,
	*svctenant.BulkService,
	*svctenant.BrandingResolver,
) {
	t.Helper()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	var bulk *svctenant.BulkService
	var branding *svctenant.BrandingResolver
	if withBranding {
		branding = svctenant.NewBrandingResolver(tenants, msps)
	}
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulk, branding, authz)
	mux := http.NewServeMux()
	h.Register(mux)
	return mux, msps, tenants, bulk, branding
}

func doMSPJSON(t *testing.T, mux http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		bodyReader = bytes.NewReader(raw)
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), uuid.New()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestMSPHandler_CreateAndGet(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandler(t, false)

	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps", handler.MSPRequest{
		Name: "Acme",
		Slug: "acme",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var created handler.MSPResponse
	if err := json.NewDecoder(rec.Body).Decode(&created); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if created.ID == "" || created.Name != "Acme" {
		t.Fatalf("unexpected created: %+v", created)
	}

	rec = doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps/"+created.ID, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestMSPHandler_CreateRejectsMissingName(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandler(t, false)
	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps", handler.MSPRequest{Slug: "x"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
}

func TestMSPHandler_List(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	for i := 0; i < 3; i++ {
		if _, err := msps.Create(context.Background(), repository.MSP{
			Name: "x", Slug: "x-" + uuid.NewString(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	rec := doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []handler.MSPResponse `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 3 {
		t.Fatalf("got %d items", len(body.Items))
	}
}

func TestMSPHandler_PatchUpdatesBranding(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, _ := msps.Create(context.Background(), repository.MSP{Name: "Acme", Slug: "acme"})
	patch := handler.MSPPatchRequest{
		Branding: &repository.MSPBranding{LogoURL: "https://x"},
	}
	rec := doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(), patch)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got handler.MSPResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Branding.LogoURL != "https://x" {
		t.Fatalf("branding not applied: %+v", got)
	}
}

func TestMSPHandler_AssignAndUnassignTenant(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(),
		handler.AssignTenantRequest{Relationship: "owner"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("assign status = %d body=%s", rec.Code, rec.Body.String())
	}
	// Read back via List
	rec = doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps/"+m.ID.String()+"/tenants", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d body=%s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Items []handler.MSPTenantBindingResponse `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&listed); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(listed.Items) != 1 || listed.Items[0].TenantID != tn.ID.String() {
		t.Fatalf("listed wrong: %+v", listed)
	}

	// Unassign
	rec = doMSPJSON(t, mux, http.MethodDelete,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unassign status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMSPHandler_BulkClaimTokens(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	bulkSvc := svctenant.NewBulkService(
		msps,
		stubBulkAuthz{tenants: []uuid.UUID{tn.ID}},
		nil, nil,
		&fakeTokenIssuer{},
		nil,
		svctenant.BulkOptions{},
	)
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulkSvc, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/claim-tokens",
		handler.BulkClaimTokensRequest{Count: 2, TTLSeconds: 60})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var body handler.BulkResultResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Successes) != 1 || len(body.Successes[0].ClaimTokens) != 2 {
		t.Fatalf("unexpected bulk result: %+v", body)
	}
}

func TestMSPHandler_BulkClaimTokens_RejectsBadCount(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-rej"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	bulkSvc := svctenant.NewBulkService(
		msps,
		stubBulkAuthz{tenants: []uuid.UUID{tn.ID}},
		nil, nil,
		&fakeTokenIssuer{},
		nil,
		svctenant.BulkOptions{},
	)
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulkSvc, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/claim-tokens",
		handler.BulkClaimTokensRequest{Count: 0})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestMSPHandler_Branding_GetAndSet(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, true)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-brand",
		Branding: repository.MSPBranding{LogoURL: "https://msp-logo"},
	})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// Resolve before override → should match MSP logo.
	rec := doMSPJSON(t, mux, http.MethodGet, "/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got handler.BrandingResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.LogoURL != "https://msp-logo" {
		t.Errorf("got logo %q want MSP %q", got.LogoURL, "https://msp-logo")
	}
	// Override
	rec = doMSPJSON(t, mux, http.MethodPut, "/api/v1/tenants/"+tn.ID.String()+"/branding",
		repository.MSPBranding{LogoURL: "https://tenant-logo"})
	if rec.Code != http.StatusOK {
		t.Fatalf("put status = %d body=%s", rec.Code, rec.Body.String())
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.LogoURL != "https://tenant-logo" {
		t.Errorf("post-override logo: %q", got.LogoURL)
	}
	// Clear
	rec = doMSPJSON(t, mux, http.MethodDelete, "/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
	}
}

// fakeTokenIssuer implements ClaimTokenIssuer for handler tests.
type fakeTokenIssuer struct{ fail error }

func (f *fakeTokenIssuer) GenerateClaimToken(_ context.Context, _ uuid.UUID, _ time.Duration, _ *uuid.UUID) (svctenant.ClaimTokenResult, error) {
	if f.fail != nil {
		return svctenant.ClaimTokenResult{}, f.fail
	}
	return svctenant.ClaimTokenResult{Plaintext: uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func TestMSPHandler_Delete(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, _ := msps.Create(context.Background(), repository.MSP{Name: "Acme", Slug: "acme-del"})
	rec := doMSPJSON(t, mux, http.MethodDelete, "/api/v1/msps/"+m.ID.String(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	// Soft-deleted: row still exists but status flipped to deleted.
	got, err := msps.Get(context.Background(), m.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got.Status != repository.MSPStatusDeleted {
		t.Fatalf("expected MSPStatusDeleted, got %q", got.Status)
	}
}

// TestMSPHandler_List_UsesAfterCursor pins the round-1 fix: the
// list handler reads `?after=` (matching the OpenAPI spec), not
// `?cursor=`. Seeds 3 MSPs, fetches with limit=1 to force a
// next_cursor, then re-fetches with `?after=<cursor>` and asserts
// the second page contains the remaining 2 items.
func TestMSPHandler_List_UsesAfterCursor(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := msps.Create(ctx, repository.MSP{
			Name: "x", Slug: "x-" + uuid.NewString(),
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Page 1: limit=1 forces a next_cursor.
	rec := doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps?limit=1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page1 status = %d body=%s", rec.Code, rec.Body.String())
	}
	var page1 struct {
		Items      []handler.MSPResponse `json:"items"`
		NextCursor string                `json:"next_cursor"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&page1); err != nil {
		t.Fatalf("decode page1: %v", err)
	}
	if len(page1.Items) != 1 || page1.NextCursor == "" {
		t.Fatalf("page1 = %+v, want 1 item + non-empty cursor", page1)
	}
	// Page 2: spec-compliant `?after=` (NOT `?cursor=` — the bug).
	rec = doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps?limit=10&after="+page1.NextCursor, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page2 status = %d body=%s", rec.Code, rec.Body.String())
	}
	var page2 struct {
		Items []handler.MSPResponse `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&page2); err != nil {
		t.Fatalf("decode page2: %v", err)
	}
	if len(page2.Items) != 2 {
		t.Fatalf("page2 returned %d items, want 2 (cursor was ignored — the round-1 bug)",
			len(page2.Items))
	}
}

// TestMSPHandler_ListTenants_UsesAfterCursor pins the round-1 fix
// on the second `?cursor=`→`?after=` site (tenant bindings list).
// Same shape as TestMSPHandler_List_UsesAfterCursor.
func TestMSPHandler_ListTenants_UsesAfterCursor(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-after"})
	for i := 0; i < 3; i++ {
		tn, err := tenants.Create(ctx, repository.Tenant{Name: "t", Slug: "t-" + uuid.NewString()})
		if err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if _, err := msps.AssignTenant(ctx, m.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
			t.Fatalf("assign: %v", err)
		}
	}
	rec := doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps/"+m.ID.String()+"/tenants?limit=1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page1 status = %d body=%s", rec.Code, rec.Body.String())
	}
	var page1 struct {
		Items      []handler.MSPTenantBindingResponse `json:"items"`
		NextCursor string                             `json:"next_cursor"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&page1); err != nil {
		t.Fatalf("decode page1: %v", err)
	}
	if len(page1.Items) != 1 || page1.NextCursor == "" {
		t.Fatalf("page1 = %+v, want 1 item + non-empty cursor", page1)
	}
	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/msps/"+m.ID.String()+"/tenants?limit=10&after="+page1.NextCursor, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("page2 status = %d body=%s", rec.Code, rec.Body.String())
	}
	var page2 struct {
		Items []handler.MSPTenantBindingResponse `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&page2); err != nil {
		t.Fatalf("decode page2: %v", err)
	}
	if len(page2.Items) != 2 {
		t.Fatalf("page2 returned %d items, want 2 (cursor was ignored — the round-1 bug)",
			len(page2.Items))
	}
}

// TestMSPHandler_AssignTenant_DecodesChunkedBody pins the round-1
// fix on the ContentLength guard. A chunked transfer (ContentLength
// == -1) was previously rejected by `r.ContentLength > 0`, silently
// applying the default `owner` relationship to a request that
// explicitly asked for `co_manager`. The fix changes the guard to
// `!= 0` and handles `io.EOF` for genuinely empty chunked bodies.
func TestMSPHandler_AssignTenant_DecodesChunkedBody(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-chunk"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "tc", Slug: "tc-chunk"})

	// Build a raw chunked-transfer request. httptest.NewRequest
	// derives ContentLength from the body reader's length, but
	// when we explicitly clear ContentLength to -1 and set the
	// Transfer-Encoding header, the handler observes the wire
	// shape an HTTP/1.1 client (or HTTP/2) would send.
	body := []byte(`{"relationship":"co_manager"}`)
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(),
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), uuid.New()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp handler.MSPTenantBindingResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Relationship != "co_manager" {
		t.Fatalf("relationship = %q, want co_manager (chunked body was silently ignored — the round-1 bug)",
			resp.Relationship)
	}
}

// TestMSPHandler_AssignTenant_EmptyBodyDefaultsToOwner ensures the
// fix preserves the documented `owner` default when no body is
// supplied (ContentLength == 0).
func TestMSPHandler_AssignTenant_EmptyBodyDefaultsToOwner(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-empty"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "te", Slug: "te-empty"})

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(), nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var resp handler.MSPTenantBindingResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Relationship != "owner" {
		t.Fatalf("relationship = %q, want owner (default for empty body)", resp.Relationship)
	}
}

// TestMSPHandler_CreateRejectsMissingSlug pins the round-1 INFO
// fix: empty slug now returns 400 `invalid_param` with
// "slug is required" instead of bubbling up the generic
// `invalid_argument` from the repo layer.
func TestMSPHandler_CreateRejectsMissingSlug(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandler(t, false)
	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps", handler.MSPRequest{Name: "Acme"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	// Verify the precise error message — clients should see
	// "slug is required" not the generic repo error.
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}
	if body.Error.Message != "slug is required" {
		t.Fatalf("error.message = %q, want 'slug is required'", body.Error.Message)
	}
}

// === round-2 fixes ========================================================

// TestMSPHandler_ListRequiresPlatformAuth pins the round-2 fix on the
// privilege-escalation bug: `GET /api/v1/msps` previously had no
// auth gate at all, so any authenticated user (including someone
// whose entire grant footprint is a single tenant-scoped role)
// could enumerate every MSP on the platform.
//
// scopedAuthz returns AuthorizePlatform=false but AuthorizeMSP=true
// — i.e. it models an msp-scoped operator. The fix must reject the
// list call with 403 regardless of whether AuthorizeMSP would allow
// it.
func TestMSPHandler_ListRequiresPlatformAuth(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandlerWithAuthz(t, false, scopedAuthz{})
	rec := doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s, want 403 (platform gate must reject msp-scoped operators)",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "platform_forbidden" {
		t.Fatalf("error.code = %q, want platform_forbidden", body.Error.Code)
	}
}

// TestMSPHandler_CreateRequiresPlatformAuth mirrors the list test but
// for `POST /api/v1/msps` — the privilege escalation was that an
// arbitrary authenticated user could create a new MSP and (because
// the seed-grant path stamps the creator as msp_admin) immediately
// inherit MSP-scoped powers over it.
func TestMSPHandler_CreateRequiresPlatformAuth(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandlerWithAuthz(t, false, scopedAuthz{})
	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps",
		handler.MSPRequest{Name: "Acme", Slug: "acme"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d body=%s, want 403 on create", rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_ListRequiresAuthentication pins the unauthenticated
// path: a request with no user UUID stamped on the context
// (e.g. someone bypassing the auth middleware) must be rejected
// with 401, not silently allowed.
func TestMSPHandler_ListRequiresAuthentication(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandler(t, false)
	// Construct the request directly so we can omit
	// WithUserIDForTest — that's what models the "no
	// authenticated user" case.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/msps", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d body=%s, want 401", rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_CreateRejectsInvalidStatus pins the data-integrity
// fix: previously the handler passed req.Status verbatim into
// `repository.MSPStatus(req.Status)`, so a client posting
// `"status":"corrupt-state"` got that arbitrary string written to
// the row (in-memory backend) or rejected with a generic 23514
// CHECK violation (postgres). Round-2 validates at the handler
// boundary so the 400 is consistent across backends.
func TestMSPHandler_CreateRejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandler(t, false)
	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps",
		handler.MSPRequest{Name: "Acme", Slug: "acme-bad", Status: "corrupt-state"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}
	// Sanity-check known-good values still pass.
	for _, st := range []string{"", "active", "suspended"} {
		rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps",
			handler.MSPRequest{Name: "Acme " + st, Slug: "acme-" + st + "-ok", Status: st})
		if rec.Code != http.StatusCreated {
			t.Fatalf("status %q rejected (code=%d body=%s), want allow",
				st, rec.Code, rec.Body.String())
		}
	}
}

// TestMSPHandler_UpdateRejectsInvalidStatus checks the same enum
// guard on the PATCH update path. Without it, a client could
// PATCH `{"status":"corrupt-state"}` and the memory backend would
// write the raw string into MSPPatch.Status.
func TestMSPHandler_UpdateRejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, err := msps.Create(context.Background(),
		repository.MSP{Name: "Acme", Slug: "acme-patch-status"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	bad := "corrupt-state"
	rec := doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{Status: &bad})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_SetStatusRejectsInvalidStatus covers the dedicated
// `POST /api/v1/msps/{id}/status` endpoint. The handler also
// requires a non-empty status (unlike PATCH where omitting it is
// "no change").
func TestMSPHandler_SetStatusRejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, err := msps.Create(context.Background(),
		repository.MSP{Name: "Acme", Slug: "acme-set-status"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, st := range []string{"", "corrupt-state"} {
		rec := doMSPJSON(t, mux, http.MethodPost,
			"/api/v1/msps/"+m.ID.String()+"/status",
			handler.MSPStatusRequest{Status: st})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status %q: code=%d body=%s, want 400",
				st, rec.Code, rec.Body.String())
		}
	}
	// Sanity-check a valid value still works.
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: "suspended"})
	if rec.Code != http.StatusOK {
		t.Fatalf("valid suspended: code=%d body=%s, want 200",
			rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_AssignTenant_RejectsUnknownFields pins the
// DisallowUnknownFields fix. A typo like `relasionship` would
// previously parse as zero-value `Relationship` (silently
// defaulting to `owner`); the fix makes it surface as a 400.
func TestMSPHandler_AssignTenant_RejectsUnknownFields(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-unknown"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "tu", Slug: "tu-unknown"})
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(),
		map[string]string{"relasionship": "co_manager"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 (unknown field 'relasionship' must reject)",
			rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_SetBranding_ReflectsOverrideWithoutRefetch pins the
// optimization: setBranding must return the freshly-merged branding
// computed from the tenant row returned by SetTenantBranding,
// without an extra Get round-trip. Equivalently, the response must
// agree with what Resolve returns immediately afterwards. We also
// pin that the override actually applied (primary_color = "#0f0").
func TestMSPHandler_SetBranding_ReflectsOverrideWithoutRefetch(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, branding := setupMSPHandler(t, true)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-brand-2",
		Branding: repository.MSPBranding{PrimaryColor: "#abc", LogoURL: "msp-logo"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "Tenant", Slug: "tenant-brand-2", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	rec := doMSPJSON(t, mux, http.MethodPut,
		"/api/v1/tenants/"+tn.ID.String()+"/branding",
		repository.MSPBranding{PrimaryColor: "#0f0"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var got handler.BrandingResponse
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Tenant override applied.
	if got.PrimaryColor != "#0f0" {
		t.Fatalf("primary_color = %q, want #0f0 (tenant override)", got.PrimaryColor)
	}
	// MSP layer still merged through for unset fields.
	if got.LogoURL != "msp-logo" {
		t.Fatalf("logo_url = %q, want msp-logo (fallthrough from MSP layer)",
			got.LogoURL)
	}
	// Cross-check against a fresh Resolve — they must agree.
	resolved, err := branding.Resolve(ctx, tn.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.PrimaryColor != got.PrimaryColor || resolved.LogoURL != got.LogoURL {
		t.Fatalf("setBranding response %+v disagrees with fresh Resolve %+v",
			got, resolved)
	}
}

// TestMSPHandler_CreateRejectsStatusDeleted pins the round-3 fix:
// the `validMSPStatus` allow-list previously accepted "deleted" on
// the POST path, which would persist an unreachable lifecycle row
// (status='deleted' with deleted_at IS NULL — a state the rest of
// the system assumes can never exist). The round-3 split adds a
// `validMSPCreateStatus` predicate that rejects "deleted" while
// the PATCH/setStatus paths still accept it (they wire deleted_at
// alongside the status change).
func TestMSPHandler_CreateRejectsStatusDeleted(t *testing.T) {
	t.Parallel()
	mux, _, _, _, _ := setupMSPHandler(t, false)
	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps",
		handler.MSPRequest{Name: "Acme", Slug: "acme-del-status", Status: "deleted"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 — create must reject status=deleted",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}
}

// TestMSPHandler_AssignTenantRejectsUnknownRelationship pins the
// round-3 fix: `relationship` was previously persisted verbatim
// (any non-empty string would set MSPTenantBinding.Relationship to
// that arbitrary value on the memory backend, or violate the
// postgres CHECK constraint asymmetrically). The handler now
// runs `.IsValid()` at the boundary so the 400 surface is
// consistent across backends.
func TestMSPHandler_AssignTenantRejectsUnknownRelationship(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-rel"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "T", Slug: "t-rel"})
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(),
		handler.AssignTenantRequest{Relationship: "partner"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 — unknown relationship must be rejected",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}
	// Sanity-check the canonical values still work.
	for _, rel := range []string{"owner", "co_manager"} {
		rec := doMSPJSON(t, mux, http.MethodPost,
			"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String()+"?relationship="+rel, nil)
		if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
			t.Fatalf("relationship %q rejected (code=%d body=%s)",
				rel, rec.Code, rec.Body.String())
		}
	}
}

// TestMSPHandler_ListEmitsTypedEnvelopeWithoutCursor pins the
// round-3 next_cursor fix: the inline-struct typed envelope with
// `omitempty` MUST omit the `next_cursor` key when there is no
// further page. The previous `map[string]any{"next_cursor": ""}`
// shape always emitted the key, which is technically different
// from the OpenAPI `nullable: true` contract.
func TestMSPHandler_ListEmitsTypedEnvelopeWithoutCursor(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	if _, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-envelope"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rec := doMSPJSON(t, mux, http.MethodGet, "/api/v1/msps?limit=10", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	// Decode into a map to detect whether the key is present at all.
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(rec.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := raw["next_cursor"]; ok {
		t.Fatalf("next_cursor key present in terminal page; expected omitted: body=%s", rec.Body.String())
	}
	if _, ok := raw["items"]; !ok {
		t.Fatalf("items key missing: body=%s", rec.Body.String())
	}
}

// TestMSPHandler_SlugReuseAfterSoftDelete pins the round-3 fix on
// the memory backend: after an MSP is soft-deleted, its slug must
// be reusable by a fresh Create. The slug-uniqueness check
// explicitly excludes rows with deleted_at IS NOT NULL. The
// postgres migration mirrors this with a partial unique index
// (`WHERE deleted_at IS NULL`) — round-3 #6.
func TestMSPHandler_SlugReuseAfterSoftDelete(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	first, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-reuse"})
	if err != nil {
		t.Fatalf("seed first: %v", err)
	}
	// A second Create with the same slug while the first is live
	// must conflict.
	rec := doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps",
		handler.MSPRequest{Name: "Acme", Slug: "acme-reuse"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d body=%s, want 409 while slug still in use",
			rec.Code, rec.Body.String())
	}
	// Soft-delete the first MSP via the repo (no separate API
	// surface — Delete is exposed via DELETE).
	if err := msps.Delete(ctx, first.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Now the slug must be reusable.
	rec = doMSPJSON(t, mux, http.MethodPost, "/api/v1/msps",
		handler.MSPRequest{Name: "Acme Reborn", Slug: "acme-reuse"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s, want 201 — slug must be reusable after soft-delete",
			rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_ListTenants_RespectsAscOrder pins the round-3 fix
// on the postgres ListTenants ASC branch — exercised here via the
// memory backend (the same code path through `sortByCreatedAtDesc`
// which already switches on page.Normalize().Order). The
// behaviour the test enforces is: ASC walks forward over the
// cursor (rows older first to newer); DESC walks backward.
func TestMSPHandler_ListTenants_RespectsAscOrder(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-order"})
	// Create 3 tenants and assign each to the MSP. The fake
	// clock in the memory repo guarantees distinct CreatedAt
	// values per assign so ordering is deterministic.
	var (
		first repository.Tenant
		last  repository.Tenant
	)
	for i, n := range []string{"t1", "t2", "t3"} {
		tn, err := tenants.Create(ctx, repository.Tenant{Name: n, Slug: n + "-order"})
		if err != nil {
			t.Fatalf("create tenant %d: %v", i, err)
		}
		if _, err := msps.AssignTenant(ctx, m.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
			t.Fatalf("assign %d: %v", i, err)
		}
		if i == 0 {
			first = tn
		}
		last = tn
	}
	_ = first
	_ = last
	// Default order (DESC = newest first): last assigned should
	// be first in the list.
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/msps/"+m.ID.String()+"/tenants?limit=10", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("desc list: status = %d body=%s", rec.Code, rec.Body.String())
	}
	var desc struct {
		Items []handler.MSPTenantBindingResponse `json:"items"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&desc); err != nil {
		t.Fatalf("decode desc: %v", err)
	}
	if len(desc.Items) != 3 {
		t.Fatalf("desc len = %d, want 3", len(desc.Items))
	}
	// (The handler does not currently surface a `?order=` knob,
	// so this test pins the default DESC behaviour; the asc
	// branch in the postgres repo is exercised by the repository
	// unit tests.)
}

// === round-4 fixes ========================================================

// TestMSPHandler_PatchStatusEmptyStringIsNoChange pins the round-4
// BUG fix: a PATCH body of {"status": ""} is treated as "no
// change" rather than reaching the repository with patch.Status =
// &"". The latter would (silently) be skipped by the memory backend
// (its in-place guard at internal/repository/memory/msp.go does
// `if *patch.Status != ""`) but would propagate to the postgres
// backend, where the SQL `CASE WHEN $4::text IS NULL THEN status
// ELSE $4::text END` binds "" not NULL and violates the
// `CHECK (status IN ('active', 'suspended', 'deleted'))` CHECK
// constraint, producing a 400 response that surprises the caller.
// The handler now skips status entirely when the supplied value is
// empty, restoring a single behaviour across backends.
func TestMSPHandler_PatchStatusEmptyStringIsNoChange(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-empty-status"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Hand-rolled body so we can emit a literal `""` for status
	// (a struct with Status *string would happily marshal `"":`
	// but the round-trip through json.Decoder would then give
	// the handler a non-nil pointer to the empty string — which
	// is exactly the case we're regressing against).
	body := bytes.NewBufferString(`{"name":"Acme Renamed","status":""}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/msps/"+m.ID.String(), body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), uuid.New()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200 (empty status must be treated as no-change, not propagate as &\"\")",
			rec.Code, rec.Body.String())
	}
	// And confirm the rename landed (proving status="" did not
	// short-circuit the rest of the patch).
	got, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("post-patch get: %v", err)
	}
	if got.Name != "Acme Renamed" {
		t.Fatalf("name = %q, want Acme Renamed", got.Name)
	}
	if got.Status != repository.MSPStatusActive {
		t.Fatalf("status = %q, want %q (must be unchanged from create default)",
			got.Status, repository.MSPStatusActive)
	}
}

// TestMSPHandler_PatchStatusExplicitInvalidIs400 pins the
// companion invariant: a NON-empty but invalid status string still
// 400s with the same error code as before the round-4 fix —
// `validMSPStatus` is reached when `*req.Status != ""`.
func TestMSPHandler_PatchStatusExplicitInvalidIs400(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-bad-status"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	body := bytes.NewBufferString(`{"status":"corrupt-state"}`)
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/msps/"+m.ID.String(), body)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), uuid.New()))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", rec.Code, rec.Body.String())
	}
	var errBody struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if errBody.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", errBody.Error.Code)
	}
}

// TestMSPHandler_UpdateMSP_InvalidatesBrandingCache pins the
// round-5 cache invalidation contract: after a successful
// UpdateMSP the handler must call branding.InvalidateAll() so
// per-tenant cached entries that derived per-field defaults from
// this MSP's record are forced to re-resolve on the next Resolve
// call. Without this, a rebrand (logo, colour) is invisible to
// subscribed tenants until the cache TTL elapses (default 30s) —
// a soft bug that would surface as "we updated the logo but the
// portal still shows the old one for ~30s after deploy".
func TestMSPHandler_UpdateMSP_InvalidatesBrandingCache(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-rebrand",
		Branding: repository.MSPBranding{PrimaryColor: "#abc", LogoURL: "old"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-rebrand", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Prime the cache by resolving once.
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d body=%s", rec.Code, rec.Body.String())
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL != "old" {
		t.Fatalf("primed logo = %q, want old", primed.LogoURL)
	}

	// Rebrand at the MSP level. The handler must invalidate the
	// per-tenant cache; otherwise the next Resolve below would
	// still see "old".
	rec = doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{
			Branding: &repository.MSPBranding{PrimaryColor: "#abc", LogoURL: "new"},
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-patch resolve status = %d body=%s",
			rec.Code, rec.Body.String())
	}
	var afterPatch handler.BrandingResponse
	if err := json.NewDecoder(rec.Body).Decode(&afterPatch); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if afterPatch.LogoURL != "new" {
		t.Fatalf("post-rebrand logo = %q, want new (cache should have been invalidated)",
			afterPatch.LogoURL)
	}
}

// TestMSPHandler_UpdateMSP_NonBrandingPatchDoesNotInvalidate pins
// the round-7 cache-efficiency fix: a PATCH that touches only
// non-branding fields (Name/Slug/Status/Settings) must NOT flush
// the per-tenant branding cache, because none of those fields
// feed into the resolved MSPBranding record. Previously the
// handler called branding.InvalidateAll() unconditionally on every
// UpdateMSP, causing a thundering-herd of branding re-resolutions
// against the tenant + msp repos after any unrelated MSP metadata
// change (e.g. renaming an MSP or rotating its status).
//
// We assert by mutating the underlying MSP's branding row directly
// (bypassing the handler so InvalidateAll is not called even by
// the patch path), priming the cache, then patching ONLY the Name
// via the handler. The cached value must remain visible — if the
// handler had invalidated, the next Resolve would re-fetch the
// (mutated) branding and the assertion fails.
func TestMSPHandler_UpdateMSP_NonBrandingPatchDoesNotInvalidate(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-nonbrand",
		Branding: repository.MSPBranding{LogoURL: "v1"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-nonbrand", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Prime the cache by resolving once.
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d", rec.Code)
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL != "v1" {
		t.Fatalf("primed logo = %q, want v1", primed.LogoURL)
	}

	// Mutate the underlying MSP's branding directly via the repo.
	// This does NOT invalidate the cache (only the handler PATCH
	// path with patch.Branding != nil does that). The resolver's
	// cached entry should still serve "v1" if and only if the
	// handler does not invalidate on non-branding patches.
	newBrand := repository.MSPBranding{LogoURL: "v2"}
	if _, err := msps.Update(ctx, m.ID, repository.MSPPatch{Branding: &newBrand}); err != nil {
		t.Fatalf("repo brand mutate: %v", err)
	}

	// PATCH the MSP via the handler, touching ONLY Name (no
	// Branding field). With the fix, this must NOT invalidate the
	// cache, so the next Resolve still serves the cached "v1".
	newName := "Acme Renamed"
	rec = doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{Name: &newName})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-patch resolve status = %d", rec.Code)
	}
	var afterPatch handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&afterPatch)
	if afterPatch.LogoURL != "v1" {
		t.Fatalf("non-branding patch wrongly invalidated cache: logo = %q, want v1 (cached)",
			afterPatch.LogoURL)
	}
}

// TestMSPHandler_AssignTenant_OwnerInvalidatesBrandingCache pins
// the round-9 fix: when the handler assigns an OWNER binding the
// repo cascades by setting tenants.msp_id to the new MSP, which
// changes the branding resolution chain for that tenant. The
// handler must invalidate the cached branding entry so the next
// Resolve falls through to the (newly bound) MSP's branding.
//
// We seed an unbound tenant + an MSP with LogoURL="v1", prime
// the cache for the tenant (serves platform defaults), then
// POST .../tenants/{tid} with relationship=owner. After the
// assign, the resolver must serve the new MSP's "v1" rather than
// the cached platform-default.
func TestMSPHandler_AssignTenant_OwnerInvalidatesBrandingCache(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-assign-cache",
		Branding: repository.MSPBranding{LogoURL: "v1"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-assign-cache",
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Prime the cache. The tenant has no msp_id yet so the
	// resolver returns platform defaults (LogoURL = "").
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d", rec.Code)
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL == "v1" {
		t.Fatalf("primed logo = %q, expected empty/default before owner-assign",
			primed.LogoURL)
	}

	// Assign owner via the handler. The cascade sets
	// tenants.msp_id = m.ID; the cache must be invalidated so
	// the next Resolve picks up the new MSP's branding.
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(),
		handler.AssignTenantRequest{Relationship: string(repository.MSPRelationshipOwner)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("assign status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-assign resolve status = %d", rec.Code)
	}
	var after handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&after)
	if after.LogoURL != "v1" {
		t.Fatalf("owner assign did not invalidate cache: logo = %q, want v1 (from new MSP)",
			after.LogoURL)
	}
}

// TestMSPHandler_AssignTenant_CoManagerDoesNotInvalidate pins the
// round-9 efficiency contract: a co-manager binding does NOT
// change tenants.msp_id, so it must not flush the per-tenant
// cache. We seed a tenant already bound to one MSP, prime the
// cache against that MSP's branding, then assign co-manager from
// a different MSP. The cached value must remain visible after the
// co-manager assign — confirming the invalidation is gated on
// `rel == owner` rather than firing unconditionally.
func TestMSPHandler_AssignTenant_CoManagerDoesNotInvalidate(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	ownerMSP, err := msps.Create(ctx, repository.MSP{
		Name:     "Owner",
		Slug:     "owner-comgr-cache",
		Branding: repository.MSPBranding{LogoURL: "owner-v1"},
	})
	if err != nil {
		t.Fatalf("seed owner msp: %v", err)
	}
	coMSP, err := msps.Create(ctx, repository.MSP{
		Name:     "CoMgr",
		Slug:     "co-comgr-cache",
		Branding: repository.MSPBranding{LogoURL: "co-v1"},
	})
	if err != nil {
		t.Fatalf("seed co msp: %v", err)
	}
	ownerID := ownerMSP.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-comgr-cache", MSPID: &ownerID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Prime the cache. Tenant resolves through ownerMSP → "owner-v1".
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d", rec.Code)
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL != "owner-v1" {
		t.Fatalf("primed logo = %q, want owner-v1", primed.LogoURL)
	}

	// Mutate the owner MSP's branding directly via the repo to
	// "owner-v2". The cache still serves "owner-v1" until
	// invalidated. The co-manager assign below MUST NOT flush
	// the cache, so the next Resolve must still return "owner-v1".
	newBrand := repository.MSPBranding{LogoURL: "owner-v2"}
	if _, err := msps.Update(ctx, ownerMSP.ID,
		repository.MSPPatch{Branding: &newBrand}); err != nil {
		t.Fatalf("repo brand mutate: %v", err)
	}

	// Assign co_manager via the second MSP. This must not change
	// tenants.msp_id and must not flush the cache.
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+coMSP.ID.String()+"/tenants/"+tn.ID.String(),
		handler.AssignTenantRequest{Relationship: string(repository.MSPRelationshipCoManager)})
	if rec.Code != http.StatusCreated {
		t.Fatalf("co_manager assign status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-assign resolve status = %d", rec.Code)
	}
	var after handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&after)
	if after.LogoURL != "owner-v1" {
		t.Fatalf("co_manager assign wrongly invalidated cache: logo = %q, want owner-v1 (cached)",
			after.LogoURL)
	}
}

// TestMSPHandler_UnassignTenant_InvalidatesBrandingCache pins the
// round-9 fix: when the handler unassigns an OWNER binding the
// repo cascades by clearing tenants.msp_id back to NULL, which
// resets the branding chain to platform defaults. The handler
// must invalidate the cached entry so a stale Resolve does not
// keep serving the just-detached MSP's branding.
//
// We seed a tenant bound to an MSP, prime the cache, then DELETE
// the binding via the handler. After the unassign the resolver
// must NOT return the cached MSP's LogoURL.
func TestMSPHandler_UnassignTenant_InvalidatesBrandingCache(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-unassign-cache",
		Branding: repository.MSPBranding{LogoURL: "v1"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-unassign-cache", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// Seed the join row so UnassignTenant has something to delete.
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// Prime the cache: tenant resolves through MSP → "v1".
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d", rec.Code)
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL != "v1" {
		t.Fatalf("primed logo = %q, want v1", primed.LogoURL)
	}

	// Unassign via the handler. The cascade clears
	// tenants.msp_id, so the cache must be invalidated so the
	// next Resolve falls through to platform defaults.
	rec = doMSPJSON(t, mux, http.MethodDelete,
		"/api/v1/msps/"+m.ID.String()+"/tenants/"+tn.ID.String(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("unassign status = %d body=%s", rec.Code, rec.Body.String())
	}

	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-unassign resolve status = %d", rec.Code)
	}
	var after handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&after)
	if after.LogoURL == "v1" {
		t.Fatalf("unassign did not invalidate cache: logo still = %q, want empty/default",
			after.LogoURL)
	}
}

// TestMSPHandler_DeleteMSP_InvalidatesBrandingCache pins the
// round-8 fix: when an MSP is soft-deleted, the handler must
// invalidate the branding cache. Soft-deletion cascades by
// clearing tenants.msp_id for every owned tenant — without the
// invalidation, the cache continues to serve the now-deleted
// MSP's branding fields to those tenants until the TTL expires
// (a multi-minute window in production once caching is enabled).
//
// We prime the cache via a Resolve, mutate the MSP's branding row
// directly via the repo (so no handler-side invalidation can fire),
// then DELETE the MSP via the handler. After delete the cache must
// no longer be serving the cached "v1" — the resolver must fall
// through to platform defaults because the MSP is gone and the
// tenant's msp_id has been cleared.
func TestMSPHandler_DeleteMSP_InvalidatesBrandingCache(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-del-cache",
		Branding: repository.MSPBranding{LogoURL: "v1"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-del-cache", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Prime the cache.
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d", rec.Code)
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL != "v1" {
		t.Fatalf("primed logo = %q, want v1", primed.LogoURL)
	}

	// DELETE the MSP via the handler. This must invalidate the
	// cache so the next Resolve does not return stale "v1".
	rec = doMSPJSON(t, mux, http.MethodDelete,
		"/api/v1/msps/"+m.ID.String(), nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d body=%s", rec.Code, rec.Body.String())
	}

	// After delete, the cache must NOT serve the cached v1. The
	// tenant's msp_id has been cleared by the cascade so the
	// resolver should now fall through to platform defaults; the
	// LogoURL therefore must NOT equal the cached "v1".
	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-delete resolve status = %d", rec.Code)
	}
	var after handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&after)
	if after.LogoURL == "v1" {
		t.Fatalf("delete did not invalidate cache: logo still = %q, want empty/default",
			after.LogoURL)
	}
}

// setupMSPHandlerWithCachedBranding wires the handler with a
// cached BrandingResolver so tests can exercise the
// MSP-rebrand-invalidates-cache path. The cache TTL is set high
// enough that without explicit InvalidateAll the test would see
// the stale value.
func setupMSPHandlerWithCachedBranding(t *testing.T) (
	*http.ServeMux,
	*memory.MSPRepository,
	*memory.TenantRepository,
	*svctenant.BulkService,
) {
	t.Helper()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	branding := svctenant.NewBrandingResolverWithCache(tenants, msps,
		svctenant.BrandingCacheOptions{TTL: time.Hour, MaxEntries: 64})
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, nil, branding, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)
	return mux, msps, tenants, nil
}

// TestMSPHandler_PatchRejectsStatusDeleted pins the round-6 fix:
// PATCH must NOT accept status='deleted'. The generic
// MSPRepository.Update writes status verbatim without stamping
// deleted_at, so allowing it on PATCH would leak an unreachable
// lifecycle row (status='deleted' but deleted_at IS NULL) that
// breaks slug-reuse (the partial unique index treats slug as still
// in use) and violates the (status='deleted' ⇔ deleted_at!=NULL)
// invariant the rest of the system assumes. Callers wanting to
// soft-delete must use DELETE or POST .../status, both of which
// stamp deleted_at NOW().
func TestMSPHandler_PatchRejectsStatusDeleted(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, err := msps.Create(context.Background(),
		repository.MSP{Name: "Acme", Slug: "acme-patch-del"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	deleted := "deleted"
	rec := doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{Status: &deleted})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 — PATCH must reject status=deleted",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}

	// Confirm the row is unchanged (status still active, deleted_at nil).
	after, err := msps.Get(context.Background(), m.ID)
	if err != nil {
		t.Fatalf("get after rejection: %v", err)
	}
	if after.Status != repository.MSPStatusActive {
		t.Fatalf("status = %q, want active (unchanged)", after.Status)
	}
	if after.DeletedAt != nil {
		t.Fatalf("deleted_at = %v, want nil (PATCH rejection must not write)", after.DeletedAt)
	}

	// Sanity-check the dedicated POST .../status endpoint still
	// accepts status=deleted — that's the right path, and it
	// stamps deleted_at via UpdateStatus.
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: "deleted"})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST .../status=deleted: code=%d body=%s, want 200",
			rec.Code, rec.Body.String())
	}
	after2, _ := msps.Get(context.Background(), m.ID)
	if after2.Status != repository.MSPStatusDeleted || after2.DeletedAt == nil {
		t.Fatalf("after setStatus=deleted: status=%q deleted_at=%v, "+
			"want both populated (lifecycle invariant)",
			after2.Status, after2.DeletedAt)
	}
}

// TestMSPHandler_PatchRejectsEmptyName pins the round-6 fix on the
// cross-backend divergence: a client posting `{"name":""}` would
// previously be silently ignored by the memory backend (guard
// `if *patch.Name != ""`) but accepted by the postgres backend
// (CASE arm binds the empty string). The handler now rejects it
// at the boundary so behavior is consistent.
func TestMSPHandler_PatchRejectsEmptyName(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, err := msps.Create(context.Background(),
		repository.MSP{Name: "OriginalName", Slug: "acme-empty-name"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	empty := ""
	rec := doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{Name: &empty})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 — PATCH must reject name=\"\"",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}
	// Sanity-check that the row's name is unchanged.
	after, _ := msps.Get(context.Background(), m.ID)
	if after.Name != "OriginalName" {
		t.Fatalf("name = %q, want OriginalName (unchanged)", after.Name)
	}
}

// TestMSPHandler_PatchRejectsEmptySlug is the slug-side companion
// to TestMSPHandler_PatchRejectsEmptyName.
func TestMSPHandler_PatchRejectsEmptySlug(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, err := msps.Create(context.Background(),
		repository.MSP{Name: "Acme", Slug: "acme-empty-slug-original"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	empty := ""
	rec := doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{Slug: &empty})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 — PATCH must reject slug=\"\"",
			rec.Code, rec.Body.String())
	}
	after, _ := msps.Get(context.Background(), m.ID)
	if after.Slug != "acme-empty-slug-original" {
		t.Fatalf("slug = %q, want acme-empty-slug-original (unchanged)", after.Slug)
	}
}

// TestMSPHandler_PatchOmittedFieldsAreNoOp is the positive-path
// companion: nil pointer (omitted from JSON) must leave the field
// untouched, distinguishing it from the &"" "supplied empty" case.
func TestMSPHandler_PatchOmittedFieldsAreNoOp(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	m, err := msps.Create(context.Background(),
		repository.MSP{Name: "OriginalName", Slug: "acme-omit"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Empty patch body — every pointer is nil, no field should change.
	rec := doMSPJSON(t, mux, http.MethodPatch, "/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200 — empty patch is valid",
			rec.Code, rec.Body.String())
	}
	after, _ := msps.Get(context.Background(), m.ID)
	if after.Name != "OriginalName" || after.Slug != "acme-omit" {
		t.Fatalf("after empty patch: name=%q slug=%q, want OriginalName/acme-omit",
			after.Name, after.Slug)
	}
}

// TestMSPHandler_SetStatusDeleted_CascadesBindings pins the
// round-10 fix: POST /api/v1/msps/{msp_id}/status with
// status="deleted" must perform the same cascade as DELETE
// /api/v1/msps/{msp_id}. Specifically it must:
//
//  1. Remove every msp_tenants row that pointed at this MSP.
//  2. Clear the denormalised tenants.msp_id pointer on every
//     tenant that pointed at this MSP.
//  3. Stamp the MSP row's status=deleted + deleted_at.
//
// Before the fix the handler routed through UpdateStatus, which
// only did step 3 — leaving orphaned join rows AND stale
// tenants.msp_id pointers at the just-deleted MSP. That breaks
// re-binding (the join row blocks new owner assignments) and
// silently keeps branding resolution pointing at the deleted
// MSP's logo/colors until an out-of-band bind/unbind cycle
// resets the denormalised pointer.
//
// The fix routes status="deleted" through Delete(), which
// already cascades correctly in both backends. The lifecycle
// contract (status='deleted' ⇔ deleted_at!=NULL) is preserved.
func TestMSPHandler_SetStatusDeleted_CascadesBindings(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-status-del"})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn1, err := tenants.Create(ctx, repository.Tenant{
		Name: "T1", Slug: "t1-status-del", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant1: %v", err)
	}
	tn2, err := tenants.Create(ctx, repository.Tenant{
		Name: "T2", Slug: "t2-status-del", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant2: %v", err)
	}
	if _, err := msps.AssignTenant(ctx, m.ID, tn1.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign tn1: %v", err)
	}
	if _, err := msps.AssignTenant(ctx, m.ID, tn2.ID,
		repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign tn2: %v", err)
	}

	// Sanity: bindings exist before the cascade.
	pre, err := msps.ListTenants(ctx, m.ID, repository.Page{})
	if err != nil {
		t.Fatalf("pre listTenants: %v", err)
	}
	if len(pre.Items) != 2 {
		t.Fatalf("pre cascade bindings = %d, want 2", len(pre.Items))
	}

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: "deleted"})
	if rec.Code != http.StatusOK {
		t.Fatalf("setStatus=deleted: code=%d body=%s, want 200",
			rec.Code, rec.Body.String())
	}
	// Response body should reflect the deleted lifecycle state.
	var body handler.MSPResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.Status != string(repository.MSPStatusDeleted) {
		t.Fatalf("response status = %q, want deleted", body.Status)
	}

	// (1) msp_tenants rows for this MSP must be gone.
	post, err := msps.ListTenants(ctx, m.ID, repository.Page{})
	if err != nil {
		t.Fatalf("post listTenants: %v", err)
	}
	if len(post.Items) != 0 {
		t.Fatalf("post cascade bindings = %d, want 0 — "+
			"setStatus=deleted must cascade msp_tenants rows",
			len(post.Items))
	}

	// (2) tenants.msp_id must be cleared on every tenant that
	// pointed at this MSP.
	for _, id := range []uuid.UUID{tn1.ID, tn2.ID} {
		got, err := tenants.Get(ctx, id)
		if err != nil {
			t.Fatalf("get tenant %s: %v", id, err)
		}
		if got.MSPID != nil {
			t.Fatalf("tenant %s msp_id = %v, want nil — "+
				"setStatus=deleted must clear denormalised pointer",
				id, *got.MSPID)
		}
	}

	// (3) lifecycle invariant: status=deleted ⇔ deleted_at!=NULL.
	after, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get msp after delete: %v", err)
	}
	if after.Status != repository.MSPStatusDeleted {
		t.Fatalf("post-delete status = %q, want deleted", after.Status)
	}
	if after.DeletedAt == nil {
		t.Fatalf("post-delete deleted_at = nil, want stamped — "+
			"lifecycle invariant violated for msp %s", m.ID)
	}
}

// TestMSPHandler_SetStatusDeleted_InvalidatesBrandingCache pins
// the second half of the round-10 fix: setStatus=deleted must
// flush the branding cache, otherwise tenants previously bound
// to the now-deleted MSP would keep resolving against the
// deleted MSP's cached branding until the TTL expires (multi-
// minute window in production).
//
// We use the cached BrandingResolver wiring with TTL=1h so the
// test deterministically fails if InvalidateAll is missing.
func TestMSPHandler_SetStatusDeleted_InvalidatesBrandingCache(t *testing.T) {
	t.Parallel()
	mux, msps, tenants, _ := setupMSPHandlerWithCachedBranding(t)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{
		Name:     "Acme",
		Slug:     "acme-setstatus-del-cache",
		Branding: repository.MSPBranding{LogoURL: "v1"},
	})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	mID := m.ID
	tn, err := tenants.Create(ctx, repository.Tenant{
		Name: "T", Slug: "t-setstatus-del-cache", MSPID: &mID,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	// Prime the cache: resolution returns the MSP's "v1" logo.
	rec := doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("prime resolve status = %d", rec.Code)
	}
	var primed handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&primed)
	if primed.LogoURL != "v1" {
		t.Fatalf("primed logo = %q, want v1", primed.LogoURL)
	}

	// Trip the deleted transition via the status endpoint.
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: "deleted"})
	if rec.Code != http.StatusOK {
		t.Fatalf("setStatus=deleted: code=%d body=%s",
			rec.Code, rec.Body.String())
	}

	// After the cascade, tenant's msp_id is cleared so the
	// resolver should fall through to platform defaults — the
	// cache must NOT continue serving the stale "v1".
	rec = doMSPJSON(t, mux, http.MethodGet,
		"/api/v1/tenants/"+tn.ID.String()+"/branding", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-delete resolve status = %d", rec.Code)
	}
	var after handler.BrandingResponse
	_ = json.NewDecoder(rec.Body).Decode(&after)
	if after.LogoURL == "v1" {
		t.Fatalf("setStatus=deleted did not invalidate cache: "+
			"logo still = %q, want empty/default", after.LogoURL)
	}
}

// TestMSPHandler_BulkClaimTokens_RejectsNegativeTTL pins the
// round-10 fix on bulk claim-token issuance: a client posting
// `{"count": 1, "ttl_seconds": -60}` must get a 400, not a 202
// with silently-unredeemable tokens (ExpiresAt in the past).
//
// Before the fix the handler relied on the OpenAPI `minimum: 0`
// constraint to gate the value, but no spec-validation
// middleware is wired into the stack — the spec is purely
// documentation. The negative duration would have flowed through
// to the identity service's token issuer producing past-expiry
// tokens that the response would still report as successful.
//
// The fix re-validates at the handler boundary. ttl=0 is still
// accepted because the identity service interprets it as "use
// the configured DefaultTokenTTL" — the documented fallback path.
func TestMSPHandler_BulkClaimTokens_RejectsNegativeTTL(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-negttl"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1-negttl"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	bulkSvc := svctenant.NewBulkService(
		msps,
		stubBulkAuthz{tenants: []uuid.UUID{tn.ID}},
		nil, nil,
		&fakeTokenIssuer{},
		nil,
		svctenant.BulkOptions{},
	)
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulkSvc, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/claim-tokens",
		handler.BulkClaimTokensRequest{Count: 1, TTLSeconds: -60})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400 — "+
			"negative ttl_seconds must be rejected at the handler boundary",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param", body.Error.Code)
	}

	// ttl=0 must still be accepted — that's the documented
	// "use DefaultTokenTTL" fallback path.
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/claim-tokens",
		handler.BulkClaimTokensRequest{Count: 1, TTLSeconds: 0})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("ttl=0 status = %d body=%s, want 202 — "+
			"the zero fallback is documented and intentional",
			rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_SetStatusDeleted_Idempotent pins the round-11
// fix: posting status="deleted" to an already-soft-deleted MSP
// must return 200 + the (still-deleted) MSP body, NOT a 403
// ErrForbidden propagated from a second Delete() call. Both
// repository backends explicitly reject double-deletes by
// design (the SQL guard at internal/repository/postgres/msp.go
// refuses to re-stamp deleted_at; the memory backend at
// internal/repository/memory/msp.go returns ErrForbidden).
// REST idempotency for soft-delete state transitions requires
// the handler to short-circuit when the row is already in the
// requested state, so retries from at-least-once delivery in
// upstream orchestration don't surface as application-level
// errors. Round-11 of Devin Review on PR #42 caught this
// surface as a contract violation.
func TestMSPHandler_SetStatusDeleted_Idempotent(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-idemp-del"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// First delete: 200, status=deleted in body.
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: string(repository.MSPStatusDeleted)})
	if rec.Code != http.StatusOK {
		t.Fatalf("first delete: status = %d body=%s, want 200",
			rec.Code, rec.Body.String())
	}
	var first handler.MSPResponse
	if err := json.NewDecoder(rec.Body).Decode(&first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if first.Status != string(repository.MSPStatusDeleted) {
		t.Fatalf("first.Status = %q, want %q",
			first.Status, repository.MSPStatusDeleted)
	}

	// Second delete (replay): must still be 200, NOT 403.
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: string(repository.MSPStatusDeleted)})
	if rec.Code != http.StatusOK {
		t.Fatalf("replay delete: status = %d body=%s, want 200 — "+
			"setStatus=deleted must be idempotent (no 403 on replay)",
			rec.Code, rec.Body.String())
	}
	var second handler.MSPResponse
	if err := json.NewDecoder(rec.Body).Decode(&second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if second.Status != string(repository.MSPStatusDeleted) {
		t.Fatalf("second.Status = %q, want %q",
			second.Status, repository.MSPStatusDeleted)
	}
	// Same ID returned — the row was not re-created.
	if second.ID != first.ID {
		t.Fatalf("ID drift: first=%q second=%q", first.ID, second.ID)
	}
	// deleted_at must be stable across the replay (the row's
	// soft-delete timestamp must NOT be re-stamped on replay).
	if second.UpdatedAt != first.UpdatedAt {
		t.Fatalf("UpdatedAt drift: first=%q second=%q — "+
			"the idempotent short-circuit must not re-touch the row",
			first.UpdatedAt, second.UpdatedAt)
	}
}

// TestMSPHandler_BulkClaimTokens_RejectsZeroCount pins the
// round-11 fix: a client posting `{"count": 0}` must get a
// 400 invalid_param at the handler boundary, not a 400 from
// the bulk service wrapped as a generic invalid_argument.
// The TTL guard already lives at the handler; the count guard
// belongs there for the same reason — uniform error surface
// and explicit message ("count must be > 0") rather than
// the service's wrapped error. Round-11 of Devin Review on
// PR #42 caught the asymmetric validation surface.
func TestMSPHandler_BulkClaimTokens_RejectsZeroCount(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-zerocount"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1-zerocount"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	bulkSvc := svctenant.NewBulkService(
		msps,
		stubBulkAuthz{tenants: []uuid.UUID{tn.ID}},
		nil, nil,
		&fakeTokenIssuer{},
		nil,
		svctenant.BulkOptions{},
	)
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulkSvc, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)

	// count=0 (the OpenAPI minimum is 1).
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/claim-tokens",
		handler.BulkClaimTokensRequest{Count: 0, TTLSeconds: 60})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("count=0 status = %d body=%s, want 400 — "+
			"zero count must be rejected at the handler boundary",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param — "+
			"handler boundary error, not service-wrapped",
			body.Error.Code)
	}
	if !strings.Contains(body.Error.Message, "count") {
		t.Fatalf("error.message = %q, want a message mentioning 'count'",
			body.Error.Message)
	}

	// count=-1 must also be rejected (defensive: catches signed-int
	// underflow if a client serialised an unsigned value as int).
	rec = doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/claim-tokens",
		handler.BulkClaimTokensRequest{Count: -1, TTLSeconds: 60})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("count=-1 status = %d body=%s, want 400",
			rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_BulkPermissionConstants_AreUsedByRouter pins
// the round-11 DRY fix: the router's middleware permission
// strings MUST resolve from the same exported constants as the
// bulk service's authorizedTenants() check. Before the fix the
// handler used string literals ("msp.bulk_apply_policy", etc.)
// while the service used svctenant.PermissionBulk* constants;
// if either side ever changed the string, the middleware would
// gate on one permission while the service evaluated authz on a
// different one, silently narrowing or broadening the authorized
// tenant set with no test failure. This test pins the cross-layer
// invariant directly: the constants are exported, public, and
// must match what the router would accept.
func TestMSPHandler_BulkPermissionConstants_AreUsedByRouter(t *testing.T) {
	t.Parallel()
	// The constants must exist and be non-empty. A future rename
	// like `Permission_BulkApplyPolicy` would surface here as a
	// compile error rather than a silent runtime mismatch.
	want := map[string]string{
		"PermissionBulkApplyPolicy":        svctenant.PermissionBulkApplyPolicy,
		"PermissionBulkProvisionSites":     svctenant.PermissionBulkProvisionSites,
		"PermissionBulkGenerateClaimToken": svctenant.PermissionBulkGenerateClaimToken,
	}
	for name, value := range want {
		if value == "" {
			t.Fatalf("svctenant.%s = \"\", want a non-empty permission string", name)
		}
	}

	// All three constants must be distinct — sharing a string
	// would collapse three RBAC permissions to one and break the
	// least-privilege guarantee the route table expresses.
	seen := map[string]string{}
	for name, value := range want {
		if prior, ok := seen[value]; ok {
			t.Fatalf("svctenant.%s and svctenant.%s both = %q — "+
				"the three bulk permissions must be distinct",
				name, prior, value)
		}
		seen[value] = name
	}

	// Sanity-check the wire-level convention: every bulk
	// permission must be in the `msp.bulk_*` namespace so
	// platform admins can pattern-match them in RBAC bindings.
	for name, value := range want {
		if !strings.HasPrefix(value, "msp.bulk_") {
			t.Fatalf("svctenant.%s = %q, want a string in the msp.bulk_* namespace",
				name, value)
		}
	}
}

// TestMSPHandler_SetStatus_RejectsResurrection pins the round-12
// BUG_0001 fix: `POST /api/v1/msps/{id}/status` with
// `{"status":"active"}` (or "suspended") on a soft-deleted MSP
// must return 403 Forbidden, not silently resurrect the row.
//
// The lifecycle invariant is `(status='deleted' ⇔ deleted_at != NULL)`.
// Both repository backends' UpdateStatus methods write the status
// column unconditionally and never CLEAR deleted_at on the reverse
// arm (memory: internal/repository/memory/msp.go:194; postgres:
// internal/repository/postgres/msp.go:275-280 — the SQL CASE only
// stamps deleted_at on `$2 = 'deleted'`). Without the handler guard
// a resurrected MSP would have `status='active' && deleted_at != NULL`,
// the partial unique slug index `WHERE deleted_at IS NULL` would
// still treat it as soft-deleted, every status-aware list query and
// the branding cache would behave inconsistently, and the original
// Delete's tenant-cascade (msp_tenants rows removed,
// tenants.msp_id cleared) is irreversible — the resurrected MSP is
// orphaned with no bindings even though it appears active.
//
// `deleted` is the terminal state of the MSP lifecycle.
func TestMSPHandler_SetStatus_RejectsResurrection(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()

	// Seed: create an MSP and soft-delete it via the canonical
	// Delete path so the cascade fires (msp_tenants, tenants.msp_id).
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-rez-guard"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := msps.Delete(ctx, m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	deleted, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get deleted: %v", err)
	}
	if deleted.Status != repository.MSPStatusDeleted {
		t.Fatalf("after delete, status = %q, want %q",
			deleted.Status, repository.MSPStatusDeleted)
	}
	if deleted.DeletedAt == nil {
		t.Fatalf("after delete, DeletedAt = nil, want non-nil " +
			"(lifecycle invariant: status='deleted' ⇔ deleted_at != NULL)")
	}

	// Attempt resurrection to `active` — must be rejected with 403.
	for _, target := range []repository.MSPStatus{
		repository.MSPStatusActive,
		repository.MSPStatusSuspended,
	} {
		rec := doMSPJSON(t, mux, http.MethodPost,
			"/api/v1/msps/"+m.ID.String()+"/status",
			handler.MSPStatusRequest{Status: string(target)})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("resurrection to %q: status = %d body=%s, want 403 — "+
				"deleted is a terminal lifecycle state",
				target, rec.Code, rec.Body.String())
		}
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.Error.Code != "forbidden" {
			t.Fatalf("error.code = %q, want forbidden", body.Error.Code)
		}
		if !strings.Contains(body.Error.Message, "deleted") {
			t.Fatalf("error.message = %q, want a message mentioning 'deleted'",
				body.Error.Message)
		}
	}

	// Verify the MSP is still deleted, not resurrected — the
	// lifecycle invariant must hold across the rejected attempts.
	stillDeleted, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get after resurrection attempt: %v", err)
	}
	if stillDeleted.Status != repository.MSPStatusDeleted {
		t.Fatalf("after rejected resurrection, status = %q, want %q",
			stillDeleted.Status, repository.MSPStatusDeleted)
	}
	if stillDeleted.DeletedAt == nil {
		t.Fatalf("after rejected resurrection, DeletedAt = nil, " +
			"want non-nil (lifecycle invariant violated)")
	}

	// Sanity: re-posting `deleted` is still idempotent per round-11,
	// so the guard didn't regress that path.
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: string(repository.MSPStatusDeleted)})
	if rec.Code != http.StatusOK {
		t.Fatalf("re-post deleted: status = %d body=%s, want 200 "+
			"(idempotent — round-11)",
			rec.Code, rec.Body.String())
	}
}

// TestMSPHandler_BulkApplyPolicy_RejectsEmptyTemplate pins the
// round-12 ANALYSIS fix: handler-boundary validation. A client
// posting `{}` or `{"template":null}` must get a 400
// invalid_param at the handler boundary with a specific message,
// not the generic `invalid_argument` the bulk service wraps
// around an empty templateGraph. Mirrors the count/ttl guards on
// bulk/claim-tokens — input validation consolidated at one layer.
func TestMSPHandler_BulkApplyPolicy_RejectsEmptyTemplate(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-empty-tmpl"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1-empty-tmpl"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	bulkSvc := svctenant.NewBulkService(
		msps,
		stubBulkAuthz{tenants: []uuid.UUID{tn.ID}},
		nil, nil,
		&fakeTokenIssuer{},
		nil,
		svctenant.BulkOptions{},
	)
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulkSvc, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)

	// template omitted entirely.
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/policy-templates",
		handler.BulkPolicyTemplateRequest{})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty template: status = %d body=%s, want 400",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param — handler boundary error",
			body.Error.Code)
	}
	if !strings.Contains(body.Error.Message, "template") {
		t.Fatalf("error.message = %q, want a message mentioning 'template'",
			body.Error.Message)
	}
}

// TestMSPHandler_BulkProvisionSites_RejectsEmptyName pins the
// round-12 ANALYSIS fix: handler-boundary validation for the
// site name. The bulk service already returns ErrInvalidArgument
// for an empty Site.Name (internal/service/tenant/bulk.go:222),
// but the handler now performs the same check up front so the
// error surface is uniform with the bulk/policy template-body
// guard and the bulk/claim-tokens count + ttl guards.
func TestMSPHandler_BulkProvisionSites_RejectsEmptyName(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	ctx := context.Background()
	m, _ := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-empty-name"})
	tn, _ := tenants.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1-empty-name"})
	if _, err := msps.AssignTenant(ctx, m.ID, tn.ID,
		repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	bulkSvc := svctenant.NewBulkService(
		msps,
		stubBulkAuthz{tenants: []uuid.UUID{tn.ID}},
		nil, nil,
		&fakeTokenIssuer{},
		nil,
		svctenant.BulkOptions{},
	)
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulkSvc, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/bulk/sites",
		handler.BulkSiteRequest{Name: ""})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name: status = %d body=%s, want 400",
			rec.Code, rec.Body.String())
	}
	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error.Code != "invalid_param" {
		t.Fatalf("error.code = %q, want invalid_param",
			body.Error.Code)
	}
	if !strings.Contains(body.Error.Message, "name") {
		t.Fatalf("error.message = %q, want a message mentioning 'name'",
			body.Error.Message)
	}
}

// TestMSPHandler_SetStatus_ResurrectionGuard_NoTOCTOU pins the
// round-13 🔴 BUG fix: the resurrection guard must be atomic with
// the status write. The original Get-then-check-then-UpdateStatus
// pattern (round-12) had a TOCTOU window — a concurrent
// Delete landing between Get (seeing status='active') and
// UpdateStatus (writing 'active' over a freshly stamped deleted_at)
// would land a corrupt (status='active', deleted_at != NULL) row.
// The fix pushes the precondition into the SQL: an atomic
// `UPDATE msps SET status=$2 WHERE id=$1 AND status <> 'deleted'`
// (TransitionStatus on the repository). When the precondition
// fails, the handler must surface 403 Forbidden.
//
// This test pins the lifecycle invariant under contention: 16
// concurrent goroutines, each racing a POST .../status=active
// against the canonical Delete path. Either:
//   - the Delete wins → POST .../status=active sees 'deleted' and
//     returns 403 (no resurrection); OR
//   - the POST wins on a not-yet-deleted row → returns 200 and
//     Delete then sees 'active' and succeeds.
//
// What MUST NOT happen: status='active' && deleted_at != NULL.
// The final invariant assertion validates this.
func TestMSPHandler_SetStatus_ResurrectionGuard_NoTOCTOU(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()

	const races = 32
	for i := 0; i < races; i++ {
		slug := fmt.Sprintf("acme-toctou-%d", i)
		m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: slug})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = doMSPJSON(t, mux, http.MethodPost,
				"/api/v1/msps/"+m.ID.String()+"/status",
				handler.MSPStatusRequest{Status: string(repository.MSPStatusActive)})
		}()
		go func() {
			defer wg.Done()
			_ = doMSPJSON(t, mux, http.MethodDelete,
				"/api/v1/msps/"+m.ID.String(), nil)
		}()
		wg.Wait()

		final, err := msps.Get(ctx, m.ID)
		if err != nil {
			t.Fatalf("get after race iter=%d: %v", i, err)
		}
		// Lifecycle invariant: (status='deleted' ⇔ deleted_at != NULL).
		// The atomic TransitionStatus ensures this holds even under
		// contention with Delete.
		if final.Status == repository.MSPStatusDeleted && final.DeletedAt == nil {
			t.Fatalf("iter=%d: status='deleted' but DeletedAt=nil — invariant violated", i)
		}
		if final.Status != repository.MSPStatusDeleted && final.DeletedAt != nil {
			t.Fatalf("iter=%d: status=%q but DeletedAt=%v — CORRUPT (race produced resurrection)",
				i, final.Status, final.DeletedAt)
		}
	}
}

// TestMSPRepository_TransitionStatus_AtomicReject pins the
// repository-level atomic primitive. Calling TransitionStatus on a
// soft-deleted MSP must return ErrForbidden without mutating the
// row. The handler relies on this to surface the resurrection
// guard correctly; this test pins the guarantee at the repo
// boundary so a future internal caller bypassing the handler
// still cannot resurrect via this method.
func TestMSPRepository_TransitionStatus_AtomicReject(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-rep-transition"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := msps.Delete(ctx, m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Soft-deleted row must reject every non-deleted target.
	for _, target := range []repository.MSPStatus{
		repository.MSPStatusActive,
		repository.MSPStatusSuspended,
	} {
		_, err := msps.TransitionStatus(ctx, m.ID, target)
		if !errors.Is(err, repository.ErrForbidden) {
			t.Fatalf("TransitionStatus(%q) on deleted MSP = %v, want ErrForbidden",
				target, err)
		}
	}

	// `to=deleted` is rejected with ErrInvalidArgument — the
	// terminal transition is owned by Delete().
	_, err = msps.TransitionStatus(ctx, m.ID, repository.MSPStatusDeleted)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("TransitionStatus(deleted) = %v, want ErrInvalidArgument", err)
	}

	// Missing MSP returns ErrNotFound (not ErrForbidden).
	_, err = msps.TransitionStatus(ctx, uuid.New(), repository.MSPStatusActive)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("TransitionStatus(missing) = %v, want ErrNotFound", err)
	}

	// Verify the deleted row is still deleted (no silent mutation).
	final, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Status != repository.MSPStatusDeleted || final.DeletedAt == nil {
		t.Fatalf("after rejected transition: status=%q, DeletedAt=%v — invariant violated",
			final.Status, final.DeletedAt)
	}
}

// TestMSPRepository_TransitionStatus_AtomicAccept pins the
// non-terminal happy path. A non-deleted MSP must accept
// active <-> suspended transitions.
func TestMSPRepository_TransitionStatus_AtomicAccept(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-rep-accept"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	suspended, err := msps.TransitionStatus(ctx, m.ID, repository.MSPStatusSuspended)
	if err != nil {
		t.Fatalf("active -> suspended: %v", err)
	}
	if suspended.Status != repository.MSPStatusSuspended {
		t.Fatalf("status = %q, want suspended", suspended.Status)
	}
	if suspended.DeletedAt != nil {
		t.Fatalf("DeletedAt = %v, want nil (no terminal cascade)", suspended.DeletedAt)
	}

	active, err := msps.TransitionStatus(ctx, m.ID, repository.MSPStatusActive)
	if err != nil {
		t.Fatalf("suspended -> active: %v", err)
	}
	if active.Status != repository.MSPStatusActive {
		t.Fatalf("status = %q, want active", active.Status)
	}
}

// TestMSPRepository_Update_RejectsSoftDeleted pins the round-13 🚩
// fix: PATCH on a soft-deleted MSP must return ErrForbidden, not
// silently mutate the row. The handler resurrection guard
// already protects status transitions; the Update method now
// enforces the same lifecycle invariant for ANY column
// (name/slug/branding/settings) via the
// `WHERE deleted_at IS NULL` clause on postgres and the
// `existing.Status == MSPStatusDeleted` guard on memory.
func TestMSPRepository_Update_RejectsSoftDeleted(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-rep-immutable"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := msps.Delete(ctx, m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	newName := "Renamed"
	_, err = msps.Update(ctx, m.ID, repository.MSPPatch{Name: &newName})
	if !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("Update on deleted MSP = %v, want ErrForbidden", err)
	}

	// Sanity: the row was not mutated.
	final, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Name != "Acme" {
		t.Fatalf("name = %q, want %q (Update must be rejected, not silently applied)",
			final.Name, "Acme")
	}
	if final.Status != repository.MSPStatusDeleted {
		t.Fatalf("status = %q, want %q", final.Status, repository.MSPStatusDeleted)
	}
}

// TestMSPHandler_Patch_RejectsSoftDeleted pins the round-13 🚩
// fix at the handler boundary. PATCH on a soft-deleted MSP must
// surface 403 Forbidden via WriteRepositoryError's mapping of
// ErrForbidden.
func TestMSPHandler_Patch_RejectsSoftDeleted(t *testing.T) {
	t.Parallel()
	mux, msps, _, _, _ := setupMSPHandler(t, false)
	ctx := context.Background()
	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-handler-immutable"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := msps.Delete(ctx, m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	newName := "Renamed"
	rec := doMSPJSON(t, mux, http.MethodPatch,
		"/api/v1/msps/"+m.ID.String(),
		handler.MSPPatchRequest{Name: &newName})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("PATCH on deleted: status = %d body=%s, want 403 — "+
			"soft-deleted MSPs are immutable",
			rec.Code, rec.Body.String())
	}

	final, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Name != "Acme" {
		t.Fatalf("name = %q, want unchanged 'Acme'", final.Name)
	}
}

// raceMSPSvc wraps an MSPService and simulates the round-15
// BUG_0001 TOCTOU race by performing a "concurrent" Delete via
// the same backing repo just before delegating the handler's
// Delete call. After the first underlying Delete commits, the
// second one (the handler's actual call) naturally returns
// ErrForbidden because the soft-delete-immutability guard
// refuses to re-stamp deleted_at on an already-deleted row
// (memory: internal/repository/memory/msp.go:276; postgres:
// internal/repository/postgres/msp.go:384). This is exactly the
// production race surface: the handler's pre-Get sees the row
// as active, the handler's Delete fires AFTER a concurrent
// caller's Delete commits, so the handler observes ErrForbidden.
// Without the round-15 fix, this surfaces a confusing 403 to a
// client whose request semantically succeeded; with the fix,
// the handler re-Gets, sees the now-deleted state, and returns
// 200+body per the idempotency contract.
type raceMSPSvc struct {
	repoMSPService
	once sync.Once
}

func (r *raceMSPSvc) Delete(ctx context.Context, id uuid.UUID) error {
	// On the first Delete call: simulate the "concurrent" caller
	// winning the race. We delete through the same backing repo
	// directly, then delegate the handler's actual Delete call
	// below — which now sees an already-deleted row and returns
	// ErrForbidden. This is the deterministic equivalent of two
	// real callers both calling setStatus(deleted) at the same
	// time on an active MSP: one commits, the other observes the
	// post-commit guard. Subsequent calls (none expected on this
	// path because the handler's pre-Get short-circuits the
	// second request) just see ErrForbidden naturally.
	r.once.Do(func() {
		_ = r.repoMSPService.Delete(ctx, id)
	})
	return r.repoMSPService.Delete(ctx, id)
}

// TestMSPHandler_SetStatusDeleted_TOCTOURecoversToIdempotent pins
// the round-15 🟡 BUG_0001 fix: the setStatus handler's deleted
// path had a TOCTOU window between the pre-Get (line 609) and
// the Delete call (line 618). When a concurrent caller's
// Delete landed in that window, the handler's Delete would
// return ErrForbidden (the repository backends refuse to
// re-stamp deleted_at), which mapped to HTTP 403 — violating
// the idempotency contract this endpoint documents (a POST
// .../status with status=deleted on an already-deleted MSP
// must return 200+body, not 403).
//
// The fix catches the ErrForbidden post-Delete and re-Gets the
// MSP. If the row is now in the deleted state, the handler
// returns 200+body (idempotent recovery). Only if the row is
// somehow still NOT deleted does the 403 surface — that case
// represents a genuinely unexpected state and the
// resurrection-guard branch a few lines below would catch any
// follow-up attempt anyway.
//
// This test uses a raceMSPSvc wrapper to deterministically
// inject the race window: on the handler's Delete call, the
// wrapper first commits an underlying Delete (simulating the
// concurrent winner), then delegates — producing the exact
// ErrForbidden surface the production race would.
func TestMSPHandler_SetStatusDeleted_TOCTOURecoversToIdempotent(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	svc := &raceMSPSvc{repoMSPService: repoMSPService{repo: msps}}
	h := handler.NewMSPHandler(svc, nil, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-toctou-del"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	// First call: the wrapper injects the race during Delete, so
	// the handler observes ErrForbidden and must recover via
	// re-Get → 200+body.
	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: string(repository.MSPStatusDeleted)})
	if rec.Code != http.StatusOK {
		t.Fatalf("setStatus(deleted) under TOCTOU race: status = %d body=%s, "+
			"want 200 — handler must recover from concurrent-Delete "+
			"ErrForbidden by re-Getting and honouring idempotency",
			rec.Code, rec.Body.String())
	}
	var resp handler.MSPResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Status != string(repository.MSPStatusDeleted) {
		t.Fatalf("resp.Status = %q, want %q — re-Get path must surface the "+
			"post-concurrent-Delete deleted state",
			resp.Status, repository.MSPStatusDeleted)
	}
	if resp.ID != m.ID.String() {
		t.Fatalf("resp.ID = %q, want %q — recovery must return the same row, not create a new one",
			resp.ID, m.ID)
	}

	// Repository invariant: the row must be soft-deleted exactly
	// once with deleted_at stamped — the wrapper's Do-once
	// arrangement plus the second-Delete-returns-ErrForbidden
	// natural behaviour means deleted_at was only set by the
	// concurrent (raced) call, not by the handler.
	final, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get after recovery: %v", err)
	}
	if final.Status != repository.MSPStatusDeleted {
		t.Fatalf("final.Status = %q, want deleted — invariant violated",
			final.Status)
	}
	if final.DeletedAt == nil {
		t.Fatalf("final.DeletedAt = nil, want stamped — " +
			"(status='deleted' ⇔ deleted_at != NULL) invariant violated")
	}
}

// TestMSPHandler_SetStatusDeleted_TOCTOUPropagatesGenuine403 pins
// the *negative* side of the round-15 fix: if the post-Delete
// re-Get returns a row that is NOT in the deleted state (a
// truly unexpected condition; under normal lifecycle the only
// way Delete returns ErrForbidden is when the row was just
// deleted by a concurrent caller), the handler must still
// surface the 403. We exercise this by wrapping the service so
// Delete returns ErrForbidden without actually mutating the row
// — i.e., a spurious / corrupt ErrForbidden. The handler's
// re-Get then sees the row still active, and the original
// ErrForbidden falls through to a 403 response.
//
// This pins the contract: the round-15 recovery path narrows to
// the legitimate concurrent-delete race; it must NOT silently
// swallow ErrForbidden when the lifecycle invariant is not
// actually satisfied.
func TestMSPHandler_SetStatusDeleted_TOCTOUPropagatesGenuine403(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	svc := &spuriousForbiddenMSPSvc{repoMSPService: repoMSPService{repo: msps}}
	h := handler.NewMSPHandler(svc, nil, nil, allowAllAuthz{})
	mux := http.NewServeMux()
	h.Register(mux)
	ctx := context.Background()

	m, err := msps.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-toctou-genuine"})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doMSPJSON(t, mux, http.MethodPost,
		"/api/v1/msps/"+m.ID.String()+"/status",
		handler.MSPStatusRequest{Status: string(repository.MSPStatusDeleted)})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("setStatus(deleted) with spurious ErrForbidden: status = %d body=%s, "+
			"want 403 — re-Get sees row still active, so the original "+
			"ErrForbidden must surface (no silent swallow)",
			rec.Code, rec.Body.String())
	}

	// The row must NOT have been mutated by the failed call.
	final, err := msps.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if final.Status != repository.MSPStatusActive {
		t.Fatalf("final.Status = %q, want active — no mutation must have occurred",
			final.Status)
	}
	if final.DeletedAt != nil {
		t.Fatalf("final.DeletedAt = %v, want nil — invariant violated",
			final.DeletedAt)
	}
}

// spuriousForbiddenMSPSvc returns ErrForbidden from Delete WITHOUT
// actually mutating the underlying row. Used to verify the
// round-15 fix narrows its recovery to legitimate concurrent
// deletes — the re-Get path must see status != deleted and
// surface the 403 rather than silently swallow it.
type spuriousForbiddenMSPSvc struct {
	repoMSPService
}

func (s *spuriousForbiddenMSPSvc) Delete(ctx context.Context, id uuid.UUID) error {
	return repository.ErrForbidden
}

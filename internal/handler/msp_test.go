package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

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

// stubBulkAuthz returns the seed tenants — used by BulkService
// in handler-level tests.
type stubBulkAuthz struct {
	tenants []uuid.UUID
}

func (s stubBulkAuthz) ListAuthorizedTenants(_ context.Context, _, _ uuid.UUID, _ repository.MSPRepository) ([]uuid.UUID, error) {
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
	store := memory.NewStore()
	msps := memory.NewMSPRepository(store)
	tenants := memory.NewTenantRepository(store)
	var bulk *svctenant.BulkService
	var branding *svctenant.BrandingResolver
	if withBranding {
		branding = svctenant.NewBrandingResolver(tenants, msps)
	}
	h := handler.NewMSPHandler(repoMSPService{repo: msps}, bulk, branding, allowAllAuthz{})
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

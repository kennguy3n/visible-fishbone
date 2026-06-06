// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

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
	"github.com/kennguy3n/visible-fishbone/internal/service/pop"
)

// stubPoPService is a hand-rolled handler.PoPService double. Each
// method returns a canned value or a pre-set error so the handler's
// status-code mapping and request/response shaping can be exercised
// without the real service or Postgres.
type stubPoPService struct {
	available []pop.PoP

	registerErr error
	registered  pop.PoP

	healthView pop.PoPHealthView
	healthErr  error

	assignment    pop.Assignment
	assignmentErr error

	capacityPlans []pop.RegionCapacityPlan
	capacityErr   error

	gotRegister   pop.PoP
	gotAssignTen  uuid.UUID
	gotAssignPoP  uuid.UUID
	gotAssignOver bool
}

func (s *stubPoPService) RegisterPoP(_ context.Context, p pop.PoP) (pop.PoP, error) {
	s.gotRegister = p
	if s.registerErr != nil {
		return pop.PoP{}, s.registerErr
	}
	out := s.registered
	if out.ID == uuid.Nil {
		out = p
		out.ID = uuid.New()
	}
	return out, nil
}

func (s *stubPoPService) ListAvailable() []pop.PoP { return s.available }

func (s *stubPoPService) PlanRegionCapacity(_ context.Context) ([]pop.RegionCapacityPlan, error) {
	if s.capacityErr != nil {
		return nil, s.capacityErr
	}
	return s.capacityPlans, nil
}

func (s *stubPoPService) HealthView(_ context.Context, _ uuid.UUID) (pop.PoPHealthView, error) {
	if s.healthErr != nil {
		return pop.PoPHealthView{}, s.healthErr
	}
	return s.healthView, nil
}

func (s *stubPoPService) SetAssignment(_ context.Context, tenantID, popID uuid.UUID, override bool) (pop.Assignment, error) {
	s.gotAssignTen, s.gotAssignPoP, s.gotAssignOver = tenantID, popID, override
	if s.assignmentErr != nil {
		return pop.Assignment{}, s.assignmentErr
	}
	return s.assignment, nil
}

// platformAuthz is a PlatformAuthorizer test double.
type platformAuthz struct{ allow bool }

func (p platformAuthz) AuthorizePlatform(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return p.allow, nil
}

func popMux(svc handler.PoPService, authz handler.PlatformAuthorizer) *http.ServeMux {
	h := handler.NewPoPHandler(svc, authz)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)
	h.Register(mux)
	return mux
}

// authedReq stamps an authenticated user UUID onto the request so the
// platform gate sees an identity.
func authedReq(req *http.Request) *http.Request {
	return req.WithContext(middleware.WithUserIDForTest(req.Context(), uuid.New()))
}

func TestPoPHandler_ListAvailable_Public(t *testing.T) {
	t.Parallel()
	svc := &stubPoPService{available: []pop.PoP{
		{ID: uuid.New(), Region: "us-east", Provider: pop.ProviderAWS, AnycastIP: "203.0.113.1", DNSName: "edge", CapacityTier: pop.CapacityMedium, Enabled: true},
	}}
	mux := popMux(svc, platformAuthz{allow: true})

	rec := httptest.NewRecorder()
	// No auth context at all — the public list must still serve.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/pops", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Items []handler.PoPResponse `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 1 || body.Items[0].Region != "us-east" {
		t.Fatalf("items = %+v", body.Items)
	}
}

func TestPoPHandler_Register_Unauthenticated(t *testing.T) {
	t.Parallel()
	mux := popMux(&stubPoPService{}, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"region":"us-east","provider":"aws","anycast_ip":"203.0.113.1","dns_name":"edge","capacity_tier":"medium"}`)
	// No WithUserIDForTest -> uuid.Nil identity -> 401.
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/pops", body))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestPoPHandler_Register_Forbidden(t *testing.T) {
	t.Parallel()
	mux := popMux(&stubPoPService{}, platformAuthz{allow: false})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"region":"us-east","provider":"aws","anycast_ip":"203.0.113.1","dns_name":"edge","capacity_tier":"medium"}`)
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/pops", body))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestPoPHandler_Register_Created(t *testing.T) {
	t.Parallel()
	svc := &stubPoPService{}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"region":"us-east","provider":"aws","anycast_ip":"203.0.113.1","dns_name":"edge","capacity_tier":"medium"}`)
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/pops", body))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if svc.gotRegister.Region != "us-east" || svc.gotRegister.Provider != pop.ProviderAWS {
		t.Fatalf("service saw %+v", svc.gotRegister)
	}
	// Enabled defaults to true when omitted.
	if !svc.gotRegister.Enabled {
		t.Fatal("Enabled should default to true when omitted")
	}
}

func TestPoPHandler_Register_InvalidArgument(t *testing.T) {
	t.Parallel()
	svc := &stubPoPService{registerErr: repository.ErrInvalidArgument}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"region":"us-east","provider":"ibm","anycast_ip":"203.0.113.1","dns_name":"edge","capacity_tier":"medium"}`)
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/pops", body))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPoPHandler_Health_OK(t *testing.T) {
	t.Parallel()
	id := uuid.New()
	svc := &stubPoPService{healthView: pop.PoPHealthView{
		PoP:        pop.PoP{ID: id, Region: "us-east", Provider: pop.ProviderAWS, AnycastIP: "203.0.113.1", DNSName: "edge", CapacityTier: pop.CapacityMedium, Enabled: true},
		Health:     &pop.Health{PoPID: id, ReportedAt: time.Unix(1000, 0).UTC(), ActiveConnections: 42, CPUPct: 12.5},
		Healthy:    true,
		Overloaded: false,
	}}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/pops/"+id.String()+"/health", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp handler.PoPHealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Healthy || resp.Health == nil || resp.Health.ActiveConnections != 42 {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestPoPHandler_Health_NotFound(t *testing.T) {
	t.Parallel()
	svc := &stubPoPService{healthErr: repository.ErrNotFound}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/pops/"+uuid.New().String()+"/health", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestPoPHandler_SetAssignment_OK(t *testing.T) {
	t.Parallel()
	tenant := uuid.New()
	popID := uuid.New()
	svc := &stubPoPService{assignment: pop.Assignment{TenantID: tenant, PoPID: popID, AssignedAt: time.Unix(1000, 0).UTC(), Override: true}}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"pop_id":"` + popID.String() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.String()+"/pop-assignment", body)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	if svc.gotAssignTen != tenant || svc.gotAssignPoP != popID || !svc.gotAssignOver {
		t.Fatalf("service saw tenant=%s pop=%s override=%v", svc.gotAssignTen, svc.gotAssignPoP, svc.gotAssignOver)
	}
}

func TestPoPHandler_SetAssignment_BadPoPID(t *testing.T) {
	t.Parallel()
	tenant := uuid.New()
	mux := popMux(&stubPoPService{}, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"pop_id":"not-a-uuid"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenant.String()+"/pop-assignment", body)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestPoPHandler_SetAssignment_WrappedByRequireTenant(t *testing.T) {
	t.Parallel()
	// The override route must be mounted via MountTenantScoped so
	// RequireTenant guards it (cross-tenant forgery protection). We
	// prove the wrapping is active by sending a non-UUID tenant_id:
	// RequireTenant rejects it with 400/invalid_tenant *before* the
	// handler body runs, so the stub service is never called.
	svc := &stubPoPService{}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"pop_id":"` + uuid.New().String() + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/not-a-uuid/pop-assignment", body)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (RequireTenant rejects bad tenant_id)", rec.Code)
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "invalid_tenant" {
		t.Fatalf("error.code = %q, want invalid_tenant (proves RequireTenant wrapping)", env.Error.Code)
	}
	if svc.gotAssignPoP != uuid.Nil {
		t.Fatal("handler body ran despite RequireTenant rejection")
	}
}

func TestPoPHandler_NilAuthz_DisablesAdminRoutes(t *testing.T) {
	t.Parallel()
	// With a nil authorizer the admin register route is never
	// registered. POST /api/v1/pops therefore never reaches the
	// handler: on this single mux only "GET /api/v1/pops" exists, so
	// the POST gets a method-not-allowed/not-found from the router
	// rather than a 201/401/403 from the handler body.
	svc := &stubPoPService{}
	mux := popMux(svc, nil)
	rec := httptest.NewRecorder()
	body := bytes.NewBufferString(`{"region":"us-east"}`)
	req := authedReq(httptest.NewRequest(http.MethodPost, "/api/v1/pops", body))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 404/405 (admin route not registered)", rec.Code)
	}
	if svc.gotRegister.Region != "" {
		t.Fatal("register handler ran despite nil authorizer")
	}
}

func TestPoPHandler_CapacityPlan_OK(t *testing.T) {
	t.Parallel()
	svc := &stubPoPService{capacityPlans: []pop.RegionCapacityPlan{
		{Region: "ap-southeast-1", ConnectedTenants: 700, CurrentPoPs: 2, RecommendedPoPs: 4, AvgTenantsPerPoP: 350, Direction: pop.ScaleUp},
		{Region: "eu-central-1", ConnectedTenants: 10, CurrentPoPs: 1, RecommendedPoPs: 1, AvgTenantsPerPoP: 10, Direction: pop.ScaleHold},
	}}
	mux := popMux(svc, platformAuthz{allow: true})
	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/pops/capacity-plan", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body struct {
		Items []handler.RegionCapacityPlanResponse `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 2 || body.Items[0].Region != "ap-southeast-1" ||
		body.Items[0].RecommendedPoPs != 4 || body.Items[0].Direction != "up" {
		t.Fatalf("items = %+v", body.Items)
	}
}

func TestPoPHandler_CapacityPlan_Forbidden(t *testing.T) {
	t.Parallel()
	mux := popMux(&stubPoPService{}, platformAuthz{allow: false})
	rec := httptest.NewRecorder()
	req := authedReq(httptest.NewRequest(http.MethodGet, "/api/v1/pops/capacity-plan", nil))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

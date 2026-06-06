package handler

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/pop"
)

// PoP admin permission strings. These are platform-scoped (a PoP is
// global infrastructure, not tenant-owned), so the gate is
// AuthorizePlatform — an MSP-scoped or tenant-scoped grant does NOT
// satisfy it. platform_admin (wildcard) does.
const (
	permPoPsRead  = "pops:read"
	permPoPsWrite = "pops:write"
)

// PoPService is the narrow control-plane surface the handler needs.
// Implemented by *pop.Service; kept as an interface so tests can
// stub it without standing up Postgres.
type PoPService interface {
	RegisterPoP(ctx context.Context, p pop.PoP) (pop.PoP, error)
	ListAvailable() []pop.PoP
	HealthView(ctx context.Context, popID uuid.UUID) (pop.PoPHealthView, error)
	SetAssignment(ctx context.Context, tenantID, popID uuid.UUID, override bool) (pop.Assignment, error)
	PlanRegionCapacity(ctx context.Context) ([]pop.RegionCapacityPlan, error)
}

// PlatformAuthorizer gates the platform-scoped PoP admin routes.
// Implemented by *rbac.Service (AuthorizePlatform). A nil authorizer
// disables the admin routes entirely (they 404 by not being
// registered) — see Register.
type PlatformAuthorizer interface {
	AuthorizePlatform(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

// PoPHandler exposes the Cloud PoP endpoints. The bootstrap list is
// public; the register/health/assignment routes are protected.
type PoPHandler struct {
	svc   PoPService
	authz PlatformAuthorizer
}

// NewPoPHandler wires the handler. authz may be nil, in which case
// the platform-admin routes (POST /pops, GET /pops/{id}/health) are
// not registered — the public bootstrap list still works.
func NewPoPHandler(svc PoPService, authz PlatformAuthorizer) *PoPHandler {
	return &PoPHandler{svc: svc, authz: authz}
}

// RegisterPublic attaches the unauthenticated bootstrap endpoint.
// GET /api/v1/pops lets a not-yet-enrolled client discover the PoP
// fleet so it can resolve the steering hostname and connect.
func (h *PoPHandler) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/pops", h.listAvailable)
}

// Register attaches the authenticated PoP routes. The platform-admin
// routes are gated by AuthorizePlatform; the per-tenant override is
// tenant-scoped via MountTenantScoped (RequireTenant).
func (h *PoPHandler) Register(mux *http.ServeMux) {
	if h.authz != nil {
		mux.HandleFunc("POST /api/v1/pops", h.register)
		mux.HandleFunc("GET /api/v1/pops/{pop_id}/health", h.health)
		mux.HandleFunc("GET /api/v1/pops/capacity-plan", h.capacityPlan)
	}
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/pop-assignment", h.setAssignment)
}

// requirePlatform gates a platform-scoped PoP route. Returns true
// when the request may proceed, false (after writing the response)
// otherwise. Mirrors MSPHandler.requirePlatformPermission.
func (h *PoPHandler) requirePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped pop routes require an authenticated user identity")
		return false
	}
	allowed, err := h.authz.AuthorizePlatform(r.Context(), userID, permission)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "authorization_failed",
			"failed to evaluate platform authorization")
		return false
	}
	if !allowed {
		WriteError(w, http.StatusForbidden, "platform_forbidden",
			"credentials do not authorise platform-scoped pop operations")
		return false
	}
	return true
}

// --- request / response shapes ---

// PoPResponse is the JSON projection of a pop.PoP.
type PoPResponse struct {
	ID           string `json:"id"`
	Region       string `json:"region"`
	Provider     string `json:"provider"`
	AnycastIP    string `json:"anycast_ip"`
	DNSName      string `json:"dns_name"`
	CapacityTier string `json:"capacity_tier"`
	Enabled      bool   `json:"enabled"`
	CreatedAt    string `json:"created_at,omitempty"`
	UpdatedAt    string `json:"updated_at,omitempty"`
}

const rfc3339Nano = "2006-01-02T15:04:05.000000000Z07:00"

func toPoPResponse(p pop.PoP) PoPResponse {
	resp := PoPResponse{
		ID:           p.ID.String(),
		Region:       p.Region,
		Provider:     string(p.Provider),
		AnycastIP:    p.AnycastIP,
		DNSName:      p.DNSName,
		CapacityTier: string(p.CapacityTier),
		Enabled:      p.Enabled,
	}
	if !p.CreatedAt.IsZero() {
		resp.CreatedAt = p.CreatedAt.Format(rfc3339Nano)
	}
	if !p.UpdatedAt.IsZero() {
		resp.UpdatedAt = p.UpdatedAt.Format(rfc3339Nano)
	}
	return resp
}

// PoPCreateRequest is the body for POST /api/v1/pops.
type PoPCreateRequest struct {
	Region       string `json:"region"`
	Provider     string `json:"provider"`
	AnycastIP    string `json:"anycast_ip"`
	DNSName      string `json:"dns_name"`
	CapacityTier string `json:"capacity_tier"`
	// Enabled defaults to true when omitted so a freshly-registered
	// PoP is immediately assignable; send false to stage a PoP.
	Enabled *bool `json:"enabled,omitempty"`
}

// PoPHealthResponse is the admin health view for a PoP.
type PoPHealthResponse struct {
	PoP        PoPResponse        `json:"pop"`
	Healthy    bool               `json:"healthy"`
	Overloaded bool               `json:"overloaded"`
	Health     *PoPHealthSnapshot `json:"health,omitempty"`
}

// PoPHealthSnapshot is the latest beacon projection.
type PoPHealthSnapshot struct {
	ReportedAt        string  `json:"reported_at"`
	CPUPct            float64 `json:"cpu_pct"`
	MemoryPct         float64 `json:"memory_pct"`
	ActiveConnections int     `json:"active_connections"`
	BandwidthMbps     float64 `json:"bandwidth_mbps"`
}

// RegionCapacityPlanResponse is the JSON projection of one region's
// autoscale recommendation.
type RegionCapacityPlanResponse struct {
	Region           string  `json:"region"`
	ConnectedTenants int     `json:"connected_tenants"`
	CurrentPoPs      int     `json:"current_pops"`
	RecommendedPoPs  int     `json:"recommended_pops"`
	AvgTenantsPerPoP float64 `json:"avg_tenants_per_pop"`
	Direction        string  `json:"direction"`
}

// PoPAssignmentRequest is the body for the override endpoint.
type PoPAssignmentRequest struct {
	PoPID string `json:"pop_id"`
}

// PoPAssignmentResponse is the JSON projection of an assignment.
type PoPAssignmentResponse struct {
	TenantID   string `json:"tenant_id"`
	PoPID      string `json:"pop_id"`
	AssignedAt string `json:"assigned_at"`
	Override   bool   `json:"override"`
}

// --- handlers ---

func (h *PoPHandler) listAvailable(w http.ResponseWriter, _ *http.Request) {
	pops := h.svc.ListAvailable()
	items := make([]PoPResponse, 0, len(pops))
	for _, p := range pops {
		items = append(items, toPoPResponse(p))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *PoPHandler) register(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permPoPsWrite) {
		return
	}
	var req PoPCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	created, err := h.svc.RegisterPoP(r.Context(), pop.PoP{
		Region:       req.Region,
		Provider:     pop.Provider(req.Provider),
		AnycastIP:    req.AnycastIP,
		DNSName:      req.DNSName,
		CapacityTier: pop.CapacityTier(req.CapacityTier),
		Enabled:      enabled,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toPoPResponse(created))
}

func (h *PoPHandler) health(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permPoPsRead) {
		return
	}
	popID, ok := PathUUID(w, r, "pop_id")
	if !ok {
		return
	}
	view, err := h.svc.HealthView(r.Context(), popID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	resp := PoPHealthResponse{
		PoP:        toPoPResponse(view.PoP),
		Healthy:    view.Healthy,
		Overloaded: view.Overloaded,
	}
	if view.Health != nil {
		resp.Health = &PoPHealthSnapshot{
			ReportedAt:        view.Health.ReportedAt.Format(rfc3339Nano),
			CPUPct:            view.Health.CPUPct,
			MemoryPct:         view.Health.MemoryPct,
			ActiveConnections: view.Health.ActiveConnections,
			BandwidthMbps:     view.Health.BandwidthMbps,
		}
	}
	WriteJSON(w, http.StatusOK, resp)
}

// capacityPlan returns the per-region autoscale recommendation derived
// from the current connected-tenant distribution. Platform-scoped: a
// PoP fleet is global infrastructure, and the plan reads assignments
// cross-tenant, so it requires pops:read at the platform level.
func (h *PoPHandler) capacityPlan(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permPoPsRead) {
		return
	}
	plans, err := h.svc.PlanRegionCapacity(r.Context())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]RegionCapacityPlanResponse, 0, len(plans))
	for _, p := range plans {
		items = append(items, RegionCapacityPlanResponse{
			Region:           p.Region,
			ConnectedTenants: p.ConnectedTenants,
			CurrentPoPs:      p.CurrentPoPs,
			RecommendedPoPs:  p.RecommendedPoPs,
			AvgTenantsPerPoP: p.AvgTenantsPerPoP,
			Direction:        string(p.Direction),
		})
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *PoPHandler) setAssignment(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req PoPAssignmentRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	popID, err := uuid.Parse(req.PoPID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "pop_id is not a valid UUID")
		return
	}
	// This endpoint is an operator override: it pins the tenant to a
	// specific PoP so the auto-rebalancer never moves it.
	assignment, err := h.svc.SetAssignment(r.Context(), tenantID, popID, true)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, PoPAssignmentResponse{
		TenantID:   assignment.TenantID.String(),
		PoPID:      assignment.PoPID.String(),
		AssignedAt: assignment.AssignedAt.Format(rfc3339Nano),
		Override:   assignment.Override,
	})
}

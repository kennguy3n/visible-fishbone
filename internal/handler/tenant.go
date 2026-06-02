package handler

import (
	"encoding/json"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// TenantHandler exposes the tenant CRUD endpoints.
type TenantHandler struct {
	svc *tenant.Service
}

// NewTenantHandler wires the handler.
func NewTenantHandler(svc *tenant.Service) *TenantHandler {
	return &TenantHandler{svc: svc}
}

// Register attaches the handler routes to a mux. Path parameters
// are deliberately spelled `tenant_id` (not `id`) so the
// router-level TenantScope middleware applies uniformly to every
// route under /api/v1/tenants/{tenant_id}/...
func (h *TenantHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants", h.create)
	MountTenantScoped(mux, "GET /api/v1/tenants", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}", h.get)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}", h.update)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/suspend", h.suspend)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}", h.delete)
}

// TenantCreateRequest is the JSON body for POST /tenants.
type TenantCreateRequest struct {
	Name     string          `json:"name"`
	Slug     string          `json:"slug,omitempty"`
	Region   string          `json:"region,omitempty"`
	Tier     string          `json:"tier"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

// TenantResponse is the JSON projection of repository.Tenant.
//
// `msp_id` reflects the denormalised `tenants.msp_id` column kept
// in sync with the `msp_tenants` join row whose relationship is
// `owner`. It is the answer to "which MSP owns this tenant?" and
// can be observed alongside the rest of the tenant's identity
// without a separate `/msps/{msp_id}/tenants` round-trip. Omitted
// from the JSON payload when nil (unmanaged tenant — direct
// platform customer with no MSP owner). Round-27 of Devin Review
// on PR #42 (ANALYSIS_0007) flagged that the field was readable
// on the repository.Tenant struct but invisible to HTTP clients.
type TenantResponse struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Status    string          `json:"status"`
	Region    string          `json:"region,omitempty"`
	Tier      string          `json:"tier"`
	Settings  json.RawMessage `json:"settings"`
	MSPID     *string         `json:"msp_id,omitempty"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

func toTenantResponse(t repository.Tenant) TenantResponse {
	settings := t.Settings
	if len(settings) == 0 {
		settings = json.RawMessage(`{}`)
	}
	var mspID *string
	if t.MSPID != nil {
		// Stringify into a pointer so omitempty drops the field
		// for unmanaged tenants. We don't emit `null` because the
		// OpenAPI schema marks `msp_id` as an optional uuid; a
		// `null` value would be valid JSON but the SDK code-gen
		// would surface it as a populated optional, which is the
		// opposite of "no MSP".
		s := t.MSPID.String()
		mspID = &s
	}
	return TenantResponse{
		ID: t.ID.String(), Name: t.Name, Slug: t.Slug,
		Status: string(t.Status), Region: t.Region, Tier: string(t.Tier),
		Settings:  settings,
		MSPID:     mspID,
		CreatedAt: t.CreatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
		UpdatedAt: t.UpdatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
}

func (h *TenantHandler) create(w http.ResponseWriter, r *http.Request) {
	var req TenantCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "missing_name", "name is required")
		return
	}
	if req.Tier == "" {
		WriteError(w, http.StatusBadRequest, "missing_tier", "tier is required")
		return
	}
	t := repository.Tenant{
		Name:     req.Name,
		Slug:     req.Slug,
		Region:   req.Region,
		Tier:     repository.TenantTier(req.Tier),
		Settings: req.Settings,
	}
	created, err := h.svc.Create(r.Context(), t)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toTenantResponse(created))
}

func (h *TenantHandler) list(w http.ResponseWriter, r *http.Request) {
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.List(r.Context(), page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]TenantResponse, 0, len(res.Items))
	for _, t := range res.Items {
		items = append(items, toTenantResponse(t))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *TenantHandler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	t, err := h.svc.Get(r.Context(), id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toTenantResponse(t))
}

// TenantUpdateRequest is the JSON body for PATCH /tenants/{tenant_id}.
//
// Region is a *string (not string) on purpose: it is the only
// optional, operator-settable text field on a tenant, and using a
// pointer is the only way to distinguish "field absent — leave
// alone" (nil) from "field set to empty — clear the value"
// (non-nil pointing at ""). Without this distinction an operator
// who set a Region by mistake during onboarding could never
// remove it again through the API; the only recourse would be a
// manual DB UPDATE, which defeats the point of having a PATCH
// endpoint.
//
// Name and Tier deliberately stay as plain strings because the
// service-layer Create rejects empty values for both, so the
// "clear to empty" interpretation is not a valid state for those
// fields — the zero-value "" can therefore be safely repurposed
// as the "field absent" sentinel without losing expressivity.
type TenantUpdateRequest struct {
	Name     string          `json:"name,omitempty"`
	Region   *string         `json:"region,omitempty"`
	Tier     string          `json:"tier,omitempty"`
	Settings json.RawMessage `json:"settings,omitempty"`
}

func (h *TenantHandler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req TenantUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Translate the wire-format request into a repository
	// TenantPatch: every non-zero / non-nil field becomes a
	// non-nil patch pointer, and the *string Region passes
	// through verbatim so a caller that sent `"region": ""` can
	// clear the column. The previous code populated a full
	// repository.Tenant by merging the request onto the
	// stored row and called svc.Update with it; that pattern
	// (a) silently dropped Region clears at the repo layer, and
	// (b) required an extra Get round-trip even when nothing
	// non-trivial was being changed.
	patch := repository.TenantPatch{}
	if req.Name != "" {
		n := req.Name
		patch.Name = &n
	}
	patch.Region = req.Region
	if req.Tier != "" {
		t := repository.TenantTier(req.Tier)
		patch.Tier = &t
	}
	if len(req.Settings) > 0 {
		s := req.Settings
		patch.Settings = &s
	}
	updated, err := h.svc.Update(r.Context(), id, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toTenantResponse(updated))
}

func (h *TenantHandler) suspend(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	t, err := h.svc.Suspend(r.Context(), id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toTenantResponse(t))
}

func (h *TenantHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

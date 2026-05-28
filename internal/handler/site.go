package handler

import (
	"encoding/json"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/site"
)

// SiteHandler exposes the site CRUD endpoints. All endpoints are
// mounted under /api/v1/tenants/{tenant_id}/sites and scoped to
// that tenant.
type SiteHandler struct {
	svc *site.Service
}

// NewSiteHandler wires the handler.
func NewSiteHandler(svc *site.Service) *SiteHandler {
	return &SiteHandler{svc: svc}
}

// Register attaches routes; routes inherit RequireTenant from the
// router-level chain.
func (h *SiteHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/sites", h.create)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/sites", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/sites/{id}", h.get)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/sites/{id}", h.update)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/sites/{id}", h.delete)
}

// SiteCreateRequest is the JSON body for POST /sites.
type SiteCreateRequest struct {
	Name     string          `json:"name"`
	Slug     string          `json:"slug,omitempty"`
	Template string          `json:"template"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// SiteUpdateRequest is the JSON body for PATCH /sites/{id}.
type SiteUpdateRequest struct {
	Name     string          `json:"name,omitempty"`
	Template string          `json:"template,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// SiteResponse is the JSON projection of repository.Site.
type SiteResponse struct {
	ID        string          `json:"id"`
	TenantID  string          `json:"tenant_id"`
	Name      string          `json:"name"`
	Slug      string          `json:"slug"`
	Template  string          `json:"template"`
	Config    json.RawMessage `json:"config"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

func toSiteResponse(s repository.Site) SiteResponse {
	cfg := s.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	return SiteResponse{
		ID: s.ID.String(), TenantID: s.TenantID.String(), Name: s.Name,
		Slug: s.Slug, Template: string(s.Template), Config: cfg,
		CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
		UpdatedAt: s.UpdatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
}

func (h *SiteHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req SiteCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "missing_name", "name is required")
		return
	}
	actorID := actorFromCtx(r)
	created, err := h.svc.Create(r.Context(), tenantID, actorID, repository.Site{
		Name:     req.Name,
		Slug:     req.Slug,
		Template: repository.SiteTemplate(req.Template),
		Config:   req.Config,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toSiteResponse(created))
}

func (h *SiteHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.List(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]SiteResponse, 0, len(res.Items))
	for _, s := range res.Items {
		items = append(items, toSiteResponse(s))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *SiteHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	s, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSiteResponse(s))
}

func (h *SiteHandler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	existing, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	var req SiteUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Template != "" {
		existing.Template = repository.SiteTemplate(req.Template)
	}
	if len(req.Config) > 0 {
		existing.Config = req.Config
	}
	actorID := actorFromCtx(r)
	updated, err := h.svc.Update(r.Context(), tenantID, actorID, existing)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSiteResponse(updated))
}

func (h *SiteHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	actorID := actorFromCtx(r)
	if err := h.svc.Delete(r.Context(), tenantID, id, actorID); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

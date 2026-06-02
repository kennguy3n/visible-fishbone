package handler

import (
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/browser"
)

// BrowserHandler exposes browser protection policy CRUD endpoints.
type BrowserHandler struct {
	svc *browser.Service
}

// NewBrowserHandler wires the handler.
func NewBrowserHandler(svc *browser.Service) *BrowserHandler {
	return &BrowserHandler{svc: svc}
}

// Register attaches routes.
func (h *BrowserHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/browser-policies", h.create)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/browser-policies", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/browser-policies/{id}", h.get)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/browser-policies/{id}", h.update)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/browser-policies/{id}", h.delete)
}

// BrowserPolicyCreateRequest is the JSON body for POST.
type BrowserPolicyCreateRequest struct {
	Name    string                   `json:"name"`
	Rules   []repository.BrowserRule `json:"rules"`
	Action  string                   `json:"action"`
	Scope   string                   `json:"scope"`
	Enabled *bool                    `json:"enabled,omitempty"`
}

// BrowserPolicyUpdateRequest is the JSON body for PATCH.
type BrowserPolicyUpdateRequest struct {
	Name    *string                  `json:"name,omitempty"`
	Rules   []repository.BrowserRule `json:"rules,omitempty"`
	Action  *string                  `json:"action,omitempty"`
	Scope   *string                  `json:"scope,omitempty"`
	Enabled *bool                    `json:"enabled,omitempty"`
}

// BrowserPolicyResponse is the JSON projection.
type BrowserPolicyResponse struct {
	ID        string                   `json:"id"`
	TenantID  string                   `json:"tenant_id"`
	Name      string                   `json:"name"`
	Rules     []repository.BrowserRule `json:"rules"`
	Action    string                   `json:"action"`
	Scope     string                   `json:"scope"`
	Enabled   bool                     `json:"enabled"`
	CreatedAt string                   `json:"created_at"`
	UpdatedAt string                   `json:"updated_at"`
}

func toBrowserPolicyResponse(p repository.BrowserPolicy) BrowserPolicyResponse {
	rules := p.Rules
	if rules == nil {
		rules = []repository.BrowserRule{}
	}
	return BrowserPolicyResponse{
		ID: p.ID.String(), TenantID: p.TenantID.String(),
		Name: p.Name, Rules: rules,
		Action: string(p.Action), Scope: string(p.Scope),
		Enabled:   p.Enabled,
		CreatedAt: p.CreatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
		UpdatedAt: p.UpdatedAt.Format("2006-01-02T15:04:05.000000000Z07:00"),
	}
}

func (h *BrowserHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req BrowserPolicyCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "missing_name", "name is required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	actorID := actorFromCtx(r)
	created, err := h.svc.CreatePolicy(r.Context(), tenantID, actorID, repository.BrowserPolicy{
		Name:    req.Name,
		Rules:   req.Rules,
		Action:  repository.BrowserPolicyAction(req.Action),
		Scope:   repository.BrowserPolicyScope(req.Scope),
		Enabled: enabled,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toBrowserPolicyResponse(created))
}

func (h *BrowserHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.ListPolicies(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]BrowserPolicyResponse, 0, len(res.Items))
	for _, p := range res.Items {
		items = append(items, toBrowserPolicyResponse(p))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *BrowserHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	p, err := h.svc.GetPolicy(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toBrowserPolicyResponse(p))
}

func (h *BrowserHandler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req BrowserPolicyUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	patch := repository.BrowserPolicyPatch{
		Name:  req.Name,
		Rules: req.Rules,
	}
	if req.Action != nil {
		a := repository.BrowserPolicyAction(*req.Action)
		patch.Action = &a
	}
	if req.Scope != nil {
		s := repository.BrowserPolicyScope(*req.Scope)
		patch.Scope = &s
	}
	patch.Enabled = req.Enabled
	actorID := actorFromCtx(r)
	updated, err := h.svc.UpdatePolicy(r.Context(), tenantID, id, actorID, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toBrowserPolicyResponse(updated))
}

func (h *BrowserHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	actorID := actorFromCtx(r)
	if err := h.svc.DeletePolicy(r.Context(), tenantID, id, actorID); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

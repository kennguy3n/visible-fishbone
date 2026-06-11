package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/policytemplates"
)

// PolicyTemplateHandler exposes the smart-default security baseline
// surface: browse the immutable template catalog, preview the rendered
// Policy-Graph intent for an industry+country selection, and
// idempotently apply that baseline to a tenant.
//
// The catalog routes are global (authenticated but not tenant-scoped)
// because the catalog is the same fleet-wide; the resolve/apply/read
// routes are tenant-scoped via the standard {tenant_id} path segment.
type PolicyTemplateHandler struct {
	svc *policytemplates.Service
}

// NewPolicyTemplateHandler wires the handler over the service.
func NewPolicyTemplateHandler(svc *policytemplates.Service) *PolicyTemplateHandler {
	return &PolicyTemplateHandler{svc: svc}
}

// Register attaches the policy-template routes.
func (h *PolicyTemplateHandler) Register(mux *http.ServeMux) {
	// Global catalog (authenticated, not tenant-scoped). Template IDs
	// contain a slash (e.g. "industry/finance"), so the catch-all
	// {id...} wildcard is used to capture the full id.
	mux.HandleFunc("GET /api/v1/policy-templates", h.listCatalog)
	mux.HandleFunc("GET /api/v1/policy-templates/{id...}", h.getTemplate)

	// Per-tenant resolve / apply / read.
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy-templates/preview", h.preview)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy-templates/apply", h.apply)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy-templates/applied", h.getApplied)
}

// --- wire types -----------------------------------------------------------

// selectionRequest is the body for preview/apply: the two coordinates
// an SME picks.
type selectionRequest struct {
	Industry string `json:"industry"`
	Country  string `json:"country"`
}

func (req selectionRequest) toSelection() policytemplates.Selection {
	return policytemplates.Selection{
		Industry: policytemplates.Industry(req.Industry),
		Country:  policytemplates.Country(req.Country),
	}
}

// previewResponse is the rendered baseline for a selection, including
// the full Policy-Graph intent (which Resolved omits from its own JSON
// so it can stay an opaque value); useful as a dry-run before apply.
type previewResponse struct {
	Selection   policytemplates.Selection `json:"selection"`
	Regime      string                    `json:"regime"`
	TemplateIDs []string                  `json:"template_ids"`
	GraphHash   string                    `json:"graph_hash"`
	Graph       json.RawMessage           `json:"graph"`
}

// appliedResponse is the wire shape of a tenant's persisted baseline.
type appliedResponse struct {
	TenantID    string          `json:"tenant_id"`
	Industry    string          `json:"industry"`
	Country     string          `json:"country"`
	Regime      string          `json:"regime"`
	TemplateIDs []string        `json:"template_ids"`
	GraphHash   string          `json:"graph_hash"`
	Graph       json.RawMessage `json:"graph"`
	Version     int             `json:"version"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

func toAppliedResponse(a policytemplates.AppliedTemplate) appliedResponse {
	return appliedResponse{
		TenantID:    a.TenantID.String(),
		Industry:    a.Industry,
		Country:     a.Country,
		Regime:      a.Regime,
		TemplateIDs: a.TemplateIDs,
		GraphHash:   a.GraphHash,
		Graph:       a.Graph,
		Version:     a.Version,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
	}
}

// --- handlers -------------------------------------------------------------

// listCatalog returns the full immutable template catalog.
func (h *PolicyTemplateHandler) listCatalog(w http.ResponseWriter, _ *http.Request) {
	templates := h.svc.ListTemplates()
	WriteJSON(w, http.StatusOK, map[string]any{"items": templates})
}

// getTemplate returns a single catalog template by id.
func (h *PolicyTemplateHandler) getTemplate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "template id is required")
		return
	}
	tmpl, err := h.svc.GetTemplate(id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, tmpl)
}

// preview renders (without persisting) the composed Policy-Graph intent
// for an industry+country selection.
func (h *PolicyTemplateHandler) preview(w http.ResponseWriter, r *http.Request) {
	if _, ok := PathUUID(w, r, "tenant_id"); !ok {
		return
	}
	var req selectionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	resolved, err := h.svc.Resolve(req.toSelection())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, previewResponse{
		Selection:   resolved.Selection,
		Regime:      string(resolved.Regime),
		TemplateIDs: resolved.TemplateIDs,
		GraphHash:   resolved.GraphHash,
		Graph:       resolved.GraphJSON,
	})
}

// apply idempotently persists and returns the rendered baseline for a
// tenant. Re-applying the same selection is a no-op that returns the
// stored row.
func (h *PolicyTemplateHandler) apply(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req selectionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	applied, err := h.svc.Apply(r.Context(), tenantID, req.toSelection())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAppliedResponse(applied))
}

// getApplied returns the tenant's current applied baseline (404 when
// none has been applied).
func (h *PolicyTemplateHandler) getApplied(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	applied, err := h.svc.GetApplied(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAppliedResponse(applied))
}

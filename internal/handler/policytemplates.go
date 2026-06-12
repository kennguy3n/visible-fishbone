package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/policytemplates"
)

// Permissions gating the cross-tenant roll-out surface. They follow the
// rbac "resource:action" grammar (a platform/tenant admin's wildcard
// grant satisfies them); a roll-out writes policy baselines across many
// tenants at once, so it reuses the policy read/write permissions.
// Defined here (not in the rbac package) so this change does not edit
// shared rbac code.
const (
	permPolicyTemplateRead  = "policy:read"
	permPolicyTemplateWrite = "policy:write"
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
	svc   *policytemplates.Service
	authz PolicyTemplateAuthorizer
}

// PolicyTemplateAuthorizer is the narrow RBAC seam the cross-tenant
// roll-out routes gate on. It is satisfied by *rbac.Service.HasPermission.
// Optional: a nil authorizer leaves the routes ungated (minimum-wiring/
// tests); production wires it so only operators holding the policy
// permissions can preview or execute a fleet-wide roll-out.
type PolicyTemplateAuthorizer interface {
	HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

// PolicyTemplateOption customises a PolicyTemplateHandler.
type PolicyTemplateOption func(*PolicyTemplateHandler)

// WithPolicyTemplateAuthorizer gates the cross-tenant roll-out routes
// behind an RBAC permission check: policy:read for the preview and
// policy:write for the execute. Without it the routes are authenticated
// but not role-gated. Production wiring always supplies one.
func WithPolicyTemplateAuthorizer(authz PolicyTemplateAuthorizer) PolicyTemplateOption {
	return func(h *PolicyTemplateHandler) {
		if authz != nil {
			h.authz = authz
		}
	}
}

// NewPolicyTemplateHandler wires the handler over the service.
func NewPolicyTemplateHandler(svc *policytemplates.Service, opts ...PolicyTemplateOption) *PolicyTemplateHandler {
	h := &PolicyTemplateHandler{svc: svc}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// authorize enforces the RBAC permission for a cross-tenant roll-out
// route. It returns true (proceed) when no authorizer is wired. With one
// wired it requires an authenticated user identity (401) holding the
// permission (403), mirroring the rollout/MSP permission gates.
func (h *PolicyTemplateHandler) authorize(w http.ResponseWriter, r *http.Request, permission string) bool {
	if h.authz == nil {
		return true
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"policy-template roll-out requires an authenticated user identity")
		return false
	}
	allowed, err := h.authz.HasPermission(r.Context(), userID, permission)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "authorization_failed",
			"failed to evaluate roll-out authorization")
		return false
	}
	if !allowed {
		WriteError(w, http.StatusForbidden, "forbidden",
			"credentials do not authorise this roll-out operation")
		return false
	}
	return true
}

// Register attaches the policy-template routes.
func (h *PolicyTemplateHandler) Register(mux *http.ServeMux) {
	// Global catalog (authenticated, not tenant-scoped). Template IDs
	// contain a slash (e.g. "industry/finance"), so the catch-all
	// {id...} wildcard is used to capture the full id.
	mux.HandleFunc("GET /api/v1/policy-templates", h.listCatalog)
	// The selection vocabulary the console picks from. Registered
	// before the {id...} catch-all; ServeMux prefers the more specific
	// static segment so "options" never resolves as a template id.
	mux.HandleFunc("GET /api/v1/policy-templates/options", h.options)
	mux.HandleFunc("GET /api/v1/policy-templates/{id...}", h.getTemplate)

	// Cross-tenant roll-out (authenticated, not tenant-scoped — the
	// operator pushes one baseline to N tenants at once). The repository
	// scopes each write to the per-tenant id in the body, so this fans
	// out over the existing per-tenant apply path.
	mux.HandleFunc("POST /api/v1/policy-templates/rollout/preview", h.rolloutPreview)
	mux.HandleFunc("POST /api/v1/policy-templates/rollout", h.rollout)

	// Per-tenant resolve / apply / read.
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy-templates/preview", h.preview)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy-templates/apply", h.apply)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy-templates/applied", h.getApplied)
}

// --- cross-tenant roll-out wire types -------------------------------------

// templateRolloutRequest is the body for the roll-out preview/execute
// routes: the selection to render plus the tenants to push it to.
type templateRolloutRequest struct {
	Industry  string   `json:"industry"`
	Country   string   `json:"country"`
	TenantIDs []string `json:"tenant_ids"`
}

func (req templateRolloutRequest) toSelection() policytemplates.Selection {
	return policytemplates.Selection{
		Industry: policytemplates.Industry(req.Industry),
		Country:  policytemplates.Country(req.Country),
	}
}

// parseTenantIDs maps the request's string tenant ids to UUIDs,
// writing a 400 and returning ok=false on the first malformed id.
func parseTenantIDs(w http.ResponseWriter, raw []string) ([]uuid.UUID, bool) {
	if len(raw) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "tenant_ids must contain at least one tenant")
		return nil, false
	}
	ids := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "tenant_ids contains an invalid uuid: "+s)
			return nil, false
		}
		ids = append(ids, id)
	}
	return ids, true
}

// rolloutPreview returns the target baseline plus the per-tenant diff
// for every selected tenant, without writing anything.
func (h *PolicyTemplateHandler) rolloutPreview(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, permPolicyTemplateRead) {
		return
	}
	var req templateRolloutRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	ids, ok := parseTenantIDs(w, req.TenantIDs)
	if !ok {
		return
	}
	preview, err := h.svc.PreviewRollout(r.Context(), ids, req.toSelection())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, preview)
}

// rollout applies the target baseline to every selected tenant and
// returns the per-tenant result. A roll-out always returns 200 with a
// per-tenant breakdown — a tenant-level apply failure is reported in
// the body (status=failed), not surfaced as a request-level error;
// only a bad selection or malformed request is a 4xx.
func (h *PolicyTemplateHandler) rollout(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, permPolicyTemplateWrite) {
		return
	}
	var req templateRolloutRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	ids, ok := parseTenantIDs(w, req.TenantIDs)
	if !ok {
		return
	}
	result, err := h.svc.ExecuteRollout(r.Context(), ids, req.toSelection())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// options returns the closed selection vocabulary (industries +
// supported countries with their compliance regime) the console builds
// its roll-out picker and onboarding wizard from.
func (h *PolicyTemplateHandler) options(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, h.svc.SelectionOptions())
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

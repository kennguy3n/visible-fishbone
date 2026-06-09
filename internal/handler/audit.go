package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
)

// permAuditReadPlatform is the platform-scoped permission the admin
// audit-log endpoint requires. The platform-scoped (tenant_id IS
// NULL) audit rows span the whole control plane and carry operator
// identities, so — exactly like the metering platform cost-report —
// an MSP- or tenant-scoped grant does NOT satisfy it; only a
// platform-scoped role with this permission (or the platform
// wildcard "*"). The PlatformAuthorizer interface is shared with the
// PoP / metering admin surfaces (see pop.go).
const permAuditReadPlatform = "audit:read_platform"

// AuditHandler exposes the (read-only) audit-log endpoint.
type AuditHandler struct {
	svc   *audit.Service
	authz PlatformAuthorizer
}

// NewAuditHandler wires the handler. authz gates the platform-scoped
// admin audit-log route; a nil authorizer leaves that route
// unregistered (it 404s) rather than serving cross-tenant audit data
// behind authentication alone — mirroring NewMeteringHandler /
// NewPoPHandler. The tenant-scoped route is unaffected.
func NewAuditHandler(svc *audit.Service, authz PlatformAuthorizer) *AuditHandler {
	return &AuditHandler{svc: svc, authz: authz}
}

// Register attaches routes.
func (h *AuditHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/audit-log", h.list)
	// Admin — platform-scoped (tenant-less) audit rows for SNG
	// operators. No path tenant binding; gated on an explicit
	// platform-scoped RBAC grant (audit:read_platform) via
	// AuthorizePlatform, mirroring the metering cost-report surface.
	// A nil authorizer leaves it unregistered (404).
	if h.authz != nil {
		mux.HandleFunc("GET /api/v1/admin/audit-log", h.listGlobal)
	}
}

// requirePlatform gates a platform-scoped audit route on an explicit
// RBAC grant. Returns true when the request may proceed, false (after
// writing the response) otherwise. Mirrors
// MeteringHandler.requirePlatform / PoPHandler.requirePlatform: a
// tenant-bound credential is refused outright (defense in depth),
// an authenticated user identity is required, and AuthorizePlatform
// must grant the permission against a platform-scoped role.
func (h *AuditHandler) requirePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	if middleware.TenantIDFromContext(r.Context()) != uuid.Nil {
		WriteError(w, http.StatusForbidden, "platform_forbidden",
			"platform-scoped audit routes are not accessible to tenant-bound credentials")
		return false
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped audit routes require an authenticated user identity")
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
			"credentials do not authorise platform-scoped audit operations")
		return false
	}
	return true
}

// AuditEntryResponse is the JSON projection of repository.AuditEntry.
// TenantID is a pointer so platform-scoped rows (tenant_id IS NULL,
// surfaced by the admin endpoint) render as `"tenant_id": null`
// rather than the misleading all-zero UUID; tenant-scoped rows still
// always carry their owning tenant.
type AuditEntryResponse struct {
	ID           string          `json:"id"`
	TenantID     *string         `json:"tenant_id"`
	ActorID      *string         `json:"actor_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	CreatedAt    string          `json:"created_at"`
}

func toAuditResponse(e repository.AuditEntry) AuditEntryResponse {
	resp := AuditEntryResponse{
		ID:     e.ID.String(),
		Action: e.Action, ResourceType: e.ResourceType,
		Details:   e.Details,
		CreatedAt: e.CreatedAt.Format(time.RFC3339Nano),
	}
	if e.TenantID != uuid.Nil {
		s := e.TenantID.String()
		resp.TenantID = &s
	}
	if e.ActorID != nil {
		s := e.ActorID.String()
		resp.ActorID = &s
	}
	if e.ResourceID != nil {
		s := e.ResourceID.String()
		resp.ResourceID = &s
	}
	return resp
}

// parseAuditQuery extracts the shared audit list filter + page from
// the request query string. It returns ok=false (after writing a 400)
// when a param is malformed, so callers can simply return.
func parseAuditQuery(w http.ResponseWriter, r *http.Request) (audit.ListFilter, repository.Page, bool) {
	q := r.URL.Query()
	filter := audit.ListFilter{
		ResourceType: q.Get("resource_type"),
		Action:       q.Get("action"),
	}
	if a := q.Get("actor_id"); a != "" {
		u, err := uuid.Parse(a)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "actor_id must be a UUID")
			return audit.ListFilter{}, repository.Page{}, false
		}
		filter.ActorID = &u
	}
	if f := q.Get("from"); f != "" {
		t, err := time.Parse(time.RFC3339Nano, f)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "from must be RFC3339")
			return audit.ListFilter{}, repository.Page{}, false
		}
		filter.From = &t
	}
	if to := q.Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339Nano, to)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "to must be RFC3339")
			return audit.ListFilter{}, repository.Page{}, false
		}
		filter.To = &t
	}
	page := repository.Page{
		After: q.Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(q.Get("order")),
	}
	return filter, page, true
}

func writeAuditPage(w http.ResponseWriter, res repository.PageResult[repository.AuditEntry]) {
	items := make([]AuditEntryResponse, 0, len(res.Items))
	for _, e := range res.Items {
		items = append(items, toAuditResponse(e))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *AuditHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	filter, page, ok := parseAuditQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.List(r.Context(), tenantID, filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	writeAuditPage(w, res)
}

// listGlobal serves the platform-scoped (tenant_id IS NULL) audit
// rows — global app_registry catalog mutations and vendor syncs that
// the tenant-scoped list can never see.
func (h *AuditHandler) listGlobal(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permAuditReadPlatform) {
		return
	}
	filter, page, ok := parseAuditQuery(w, r)
	if !ok {
		return
	}
	res, err := h.svc.ListGlobal(r.Context(), filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	writeAuditPage(w, res)
}

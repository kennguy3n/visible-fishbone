package handler

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/appid"
)

// Application-ID catalog permissions. The catalog is platform-global
// (one signed signature set shared by every tenant), so management is
// platform-scoped: an MSP- or tenant-scoped grant does NOT satisfy
// these; platform_admin (wildcard "*") does. Defined locally — they are
// plain RBAC tokens, not a central registry.
const (
	permAppIDCatalogRead    = "appid:read"
	permAppIDCatalogPublish = "appid:publish"
)

// AppIDCatalogService is the narrow surface the handler needs from the
// App-ID catalog service. Kept as an interface so tests can stub it
// without standing up a signer + repository.
type AppIDCatalogService interface {
	CurrentVersion(ctx context.Context) (repository.AppIDCatalogVersion, error)
	CurrentBundle(ctx context.Context) (appid.SignedBundle, repository.AppIDCatalogVersion, error)
	ListVersions(ctx context.Context, limit int) ([]repository.AppIDCatalogVersion, error)
	Republish(ctx context.Context, note string) (repository.AppIDCatalogVersion, error)
}

// AppIDHandler serves the Application-ID catalog: a tenant-scoped pull
// surface for the current signed bundle (edges fetch and verify it),
// and a platform-scoped management surface to publish new versions and
// inspect history.
type AppIDHandler struct {
	svc   AppIDCatalogService
	authz PlatformAuthorizer
}

// NewAppIDHandler wires the handler. Either dependency may be nil: a
// nil service or a nil authorizer leaves every route unregistered, so a
// deployment without the catalog service (or without RBAC) never
// exposes an unguarded or always-erroring endpoint.
func NewAppIDHandler(svc AppIDCatalogService, authz PlatformAuthorizer) *AppIDHandler {
	return &AppIDHandler{svc: svc, authz: authz}
}

// Register attaches the catalog routes. Registered only when both the
// service and authorizer are wired.
func (h *AppIDHandler) Register(mux *http.ServeMux) {
	if h == nil || h.svc == nil || h.authz == nil {
		return
	}
	// Tenant-scoped reads — RequireTenant applied by MountTenantScoped.
	// Content is global, but binding the route to the authenticated
	// tenant keeps the pull path on the same isolation rails as every
	// other tenant API.
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/appid/catalog/current", h.tenantCurrent)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/appid/catalog/bundle", h.tenantBundle)

	// Platform-scoped management. No path tenant binding; gated by
	// AuthorizePlatform inside each handler.
	mux.HandleFunc("GET /api/v1/admin/appid/catalog/versions", h.adminListVersions)
	mux.HandleFunc("POST /api/v1/admin/appid/catalog/versions", h.adminPublish)
}

// requirePlatform gates a platform-scoped route. Mirrors
// ThreatFeedHandler.requirePlatform.
func (h *AppIDHandler) requirePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped App-ID catalog routes require an authenticated user identity")
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
			"credentials do not authorise platform-scoped App-ID catalog operations")
		return false
	}
	return true
}

// --- response shapes ---

// CatalogVersionResponse is the JSON projection of a catalog version's
// metadata — everything an edge needs to decide whether its cached
// bundle is current without downloading the full payload.
type CatalogVersionResponse struct {
	Serial        int64  `json:"serial"`
	SchemaVersion int    `json:"schema_version"`
	AppCount      int    `json:"app_count"`
	Checksum      string `json:"checksum"`
	Note          string `json:"note,omitempty"`
	GeneratedAt   string `json:"generated_at,omitempty"`
}

func toCatalogVersionResponse(v repository.AppIDCatalogVersion) CatalogVersionResponse {
	resp := CatalogVersionResponse{
		Serial:        v.Serial,
		SchemaVersion: v.SchemaVersion,
		AppCount:      v.AppCount,
		Checksum:      v.Checksum,
		Note:          v.Note,
	}
	if !v.CreatedAt.IsZero() {
		resp.GeneratedAt = v.CreatedAt.Format(rfc3339Nano)
	}
	return resp
}

// CatalogBundleResponse is the tenant pull payload: the current version
// metadata plus the signed envelope the edge verifies and loads.
type CatalogBundleResponse struct {
	Version CatalogVersionResponse `json:"version"`
	Bundle  appid.SignedBundle     `json:"bundle"`
}

// CatalogVersionsResponse is the admin version-history projection.
type CatalogVersionsResponse struct {
	Versions []CatalogVersionResponse `json:"versions"`
}

// PublishCatalogRequest is the optional body for a publish request.
type PublishCatalogRequest struct {
	Note string `json:"note,omitempty"`
}

// --- handlers ---

// tenantCurrent returns the current catalog version metadata.
func (h *AppIDHandler) tenantCurrent(w http.ResponseWriter, r *http.Request) {
	ver, err := h.svc.CurrentVersion(r.Context())
	if err != nil {
		h.writeReadError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toCatalogVersionResponse(ver))
}

// tenantBundle returns the current signed bundle for the edge to verify
// and load.
func (h *AppIDHandler) tenantBundle(w http.ResponseWriter, r *http.Request) {
	env, ver, err := h.svc.CurrentBundle(r.Context())
	if err != nil {
		h.writeReadError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, CatalogBundleResponse{
		Version: toCatalogVersionResponse(ver),
		Bundle:  env,
	})
}

// adminListVersions returns version history newest-first.
func (h *AppIDHandler) adminListVersions(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permAppIDCatalogRead) {
		return
	}
	vers, err := h.svc.ListVersions(r.Context(), QueryLimit(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := make([]CatalogVersionResponse, len(vers))
	for i, v := range vers {
		out[i] = toCatalogVersionResponse(v)
	}
	WriteJSON(w, http.StatusOK, CatalogVersionsResponse{Versions: out})
}

// adminPublish signs and stores the current catalog as a new version
// (operator-triggered redistribution / key rotation). An empty body is
// accepted; an optional {"note": "..."} annotates the version.
func (h *AppIDHandler) adminPublish(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatform(w, r, permAppIDCatalogPublish) {
		return
	}
	var req PublishCatalogRequest
	if r.ContentLength != 0 {
		if !DecodeJSON(w, r, &req) {
			return
		}
	}
	ver, err := h.svc.Republish(r.Context(), req.Note)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toCatalogVersionResponse(ver))
}

// writeReadError maps a catalog read failure. A not-yet-seeded catalog
// is a transient boot condition, so it degrades to 503 with Retry-After
// rather than 404 — the resource will exist shortly and the edge should
// retry, keeping its last-good bundle in the meantime.
func (h *AppIDHandler) writeReadError(w http.ResponseWriter, err error) {
	if errors.Is(err, repository.ErrNotFound) {
		w.Header().Set("Retry-After", "10")
		WriteError(w, http.StatusServiceUnavailable, "catalog_unavailable",
			"the application-id catalog has not been published yet; retry shortly")
		return
	}
	WriteRepositoryError(w, err)
}

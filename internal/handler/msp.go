// Package handler — msp.go owns the REST surface for the MSP
// hierarchy: CRUD on the msps table, tenant binding management
// (assign / unassign / list), MSP-fan-out bulk operations
// (policy template / sites / claim tokens), and the per-tenant
// branding resolution + override path.
//
// Route shape mirrors the integration handler in spirit — every
// route is registered through a single Register entry point so
// the router has one wire-up to read. Permission gating uses
// RequireMSPScope (from middleware/msp.go) so a missing or
// insufficient grant 401/403s before the handler runs.
//
// Wire-format invariants:
//   - MSP responses never expose internal sequence numbers or
//     soft-delete timestamps. DeletedAt is observable only via
//     the absence of the row.
//   - Bulk endpoints return 202 Accepted + the partial-completion
//     BulkResult body. They do NOT pretend partial failure is a
//     success: HTTP 207-Multi-Status was considered but rejected
//     because Devin Review's prior round flagged it as
//     under-specified for non-WebDAV consumers.
//   - The plaintext claim tokens issued by bulk are returned
//     ONCE in the response body and never persisted in plaintext;
//     operators must capture them at request time.
//   - The branding response always has every field populated —
//     the resolver guarantees a fully-populated MSPBranding.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	svctenant "github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// MSPService is the narrow interface the handler needs from the
// production wiring. Implemented by a concrete *msp.Service that
// just delegates to repository.MSPRepository — we keep the
// interface here so tests can stub without dragging the full
// service surface.
type MSPService interface {
	Create(ctx context.Context, m repository.MSP) (repository.MSP, error)
	Get(ctx context.Context, id uuid.UUID) (repository.MSP, error)
	List(ctx context.Context, page repository.Page) (repository.PageResult[repository.MSP], error)
	Update(ctx context.Context, id uuid.UUID, patch repository.MSPPatch) (repository.MSP, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status repository.MSPStatus) (repository.MSP, error)
	Delete(ctx context.Context, id uuid.UUID) error
	AssignTenant(ctx context.Context, mspID, tenantID uuid.UUID, relationship repository.MSPRelationship, actor *uuid.UUID) (repository.MSPTenantBinding, error)
	UnassignTenant(ctx context.Context, mspID, tenantID uuid.UUID) error
	ListTenants(ctx context.Context, mspID uuid.UUID, page repository.Page) (repository.PageResult[repository.MSPTenantBinding], error)
}

// MSPAuthorizer is the same narrow gate used by RequireMSPScope.
// Re-declared here so callers can inject a stub in tests without
// importing the middleware package.
type MSPAuthorizer = middleware.MSPAuthorizer

// MSPHandler exposes the MSP CRUD + binding + bulk + branding
// REST endpoints. Construction wires the MSP service, the bulk
// service, the branding resolver, and the per-route authorizer.
type MSPHandler struct {
	msps     MSPService
	bulk     *svctenant.BulkService
	branding *svctenant.BrandingResolver
	authz    MSPAuthorizer
}

// NewMSPHandler wires the handler. Pass nil for `bulk` /
// `branding` to disable those routes — used only for
// minimum-wiring integration tests.
func NewMSPHandler(
	msps MSPService,
	bulk *svctenant.BulkService,
	branding *svctenant.BrandingResolver,
	authz MSPAuthorizer,
) *MSPHandler {
	return &MSPHandler{msps: msps, bulk: bulk, branding: branding, authz: authz}
}

// Register attaches every MSP route. RequireMSPScope wraps each
// MSP-scoped route with the matching permission so the handler
// body only runs for authorized callers. The permission grammar
// matches the rbac package conventions (`msp.read`, `msp.write`,
// `msp.bind_tenants`, `msp.bulk_apply_policy`, etc.).
func (h *MSPHandler) Register(mux *http.ServeMux) {
	// CRUD. List + Create are platform-scoped (RequireMSPScope
	// would need an msp_id; instead the route uses a
	// thin platform-permission gate via direct authorizer call
	// inside the handler body for List/Create).
	mux.HandleFunc("GET /api/v1/msps", h.list)
	mux.HandleFunc("POST /api/v1/msps", h.create)
	mux.Handle("GET /api/v1/msps/{msp_id}",
		middleware.RequireMSPScope(h.authz, "msp.read", "msp_id")(http.HandlerFunc(h.get)))
	mux.Handle("PATCH /api/v1/msps/{msp_id}",
		middleware.RequireMSPScope(h.authz, "msp.write", "msp_id")(http.HandlerFunc(h.update)))
	mux.Handle("POST /api/v1/msps/{msp_id}/status",
		middleware.RequireMSPScope(h.authz, "msp.write", "msp_id")(http.HandlerFunc(h.setStatus)))
	mux.Handle("DELETE /api/v1/msps/{msp_id}",
		middleware.RequireMSPScope(h.authz, "msp.delete", "msp_id")(http.HandlerFunc(h.delete)))

	// Tenant binding.
	mux.Handle("GET /api/v1/msps/{msp_id}/tenants",
		middleware.RequireMSPScope(h.authz, "msp.read", "msp_id")(http.HandlerFunc(h.listTenants)))
	mux.Handle("POST /api/v1/msps/{msp_id}/tenants/{tenant_id}",
		middleware.RequireMSPScope(h.authz, "msp.bind_tenants", "msp_id")(http.HandlerFunc(h.assignTenant)))
	mux.Handle("DELETE /api/v1/msps/{msp_id}/tenants/{tenant_id}",
		middleware.RequireMSPScope(h.authz, "msp.bind_tenants", "msp_id")(http.HandlerFunc(h.unassignTenant)))

	// Bulk operations (only registered when bulk service wired).
	if h.bulk != nil {
		mux.Handle("POST /api/v1/msps/{msp_id}/bulk/policy-templates",
			middleware.RequireMSPScope(h.authz, "msp.bulk_apply_policy", "msp_id")(http.HandlerFunc(h.bulkApplyPolicyTemplate)))
		mux.Handle("POST /api/v1/msps/{msp_id}/bulk/sites",
			middleware.RequireMSPScope(h.authz, "msp.bulk_provision_sites", "msp_id")(http.HandlerFunc(h.bulkProvisionSites)))
		mux.Handle("POST /api/v1/msps/{msp_id}/bulk/claim-tokens",
			middleware.RequireMSPScope(h.authz, "msp.bulk_generate_claim_tokens", "msp_id")(http.HandlerFunc(h.bulkGenerateClaimTokens)))
	}

	// Branding (only registered when resolver wired). Branding
	// reads are tenant-scoped (the resolver enforces tenant
	// membership) so they reuse MountTenantScoped.
	if h.branding != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/branding", h.getBranding)
		MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/branding", h.setBranding)
		MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/branding", h.clearBranding)
	}
}

// MSPRequest is the JSON body for POST /api/v1/msps and the
// generic field set for PATCH. Branding can be supplied in full
// at create time; PATCH delegates to MSPPatch's nil-vs-set
// semantics via the pointer-shaped patchRequest below.
type MSPRequest struct {
	Name     string                  `json:"name,omitempty"`
	Slug     string                  `json:"slug,omitempty"`
	Status   string                  `json:"status,omitempty"`
	Branding *repository.MSPBranding `json:"branding,omitempty"`
	Settings json.RawMessage         `json:"settings,omitempty"`
}

// MSPPatchRequest mirrors MSPPatch's "nil = leave untouched"
// semantics. Pointer-typed primitives differentiate "absent
// from JSON" from "supplied as zero value", matching how the
// tenant patch path works elsewhere.
type MSPPatchRequest struct {
	Name     *string                 `json:"name,omitempty"`
	Slug     *string                 `json:"slug,omitempty"`
	Status   *string                 `json:"status,omitempty"`
	Branding *repository.MSPBranding `json:"branding,omitempty"`
	Settings *json.RawMessage        `json:"settings,omitempty"`
}

// MSPStatusRequest is the JSON body for POST
// /api/v1/msps/{msp_id}/status.
type MSPStatusRequest struct {
	Status string `json:"status"`
}

// MSPResponse is the JSON projection of an MSP. Settings is
// passed through as a typed JSON value when valid, otherwise
// surfaced as raw bytes — same pattern as integration.go.
type MSPResponse struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Slug      string                 `json:"slug"`
	Status    string                 `json:"status"`
	Branding  repository.MSPBranding `json:"branding"`
	Settings  any                    `json:"settings,omitempty"`
	CreatedAt string                 `json:"created_at"`
	UpdatedAt string                 `json:"updated_at"`
}

func toMSPResponse(m repository.MSP) MSPResponse {
	resp := MSPResponse{
		ID:        m.ID.String(),
		Name:      m.Name,
		Slug:      m.Slug,
		Status:    string(m.Status),
		Branding:  m.Branding,
		CreatedAt: m.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt: m.UpdatedAt.Format(time.RFC3339Nano),
	}
	if len(m.Settings) > 0 {
		var v any
		if err := json.Unmarshal(m.Settings, &v); err == nil {
			resp.Settings = v
		} else {
			resp.Settings = json.RawMessage(m.Settings)
		}
	}
	return resp
}

// MSPTenantBindingResponse is the JSON projection of a binding
// row.
type MSPTenantBindingResponse struct {
	MSPID        string `json:"msp_id"`
	TenantID     string `json:"tenant_id"`
	Relationship string `json:"relationship"`
	CreatedAt    string `json:"created_at"`
}

func toBindingResponse(b repository.MSPTenantBinding) MSPTenantBindingResponse {
	return MSPTenantBindingResponse{
		MSPID:        b.MSPID.String(),
		TenantID:     b.TenantID.String(),
		Relationship: string(b.Relationship),
		CreatedAt:    b.CreatedAt.Format(time.RFC3339Nano),
	}
}

// ---- CRUD ----------------------------------------------------------------

// requirePlatformPermission gates the platform-scoped MSP routes
// (GET and POST /api/v1/msps) which have no msp_id in their URL
// and therefore cannot be wrapped with RequireMSPScope. Direct
// call inside the handler body, as the Register doc-comment
// already promises. The previous implementation registered these
// routes without any auth at all — round-2 of Devin Review on
// PR #42 caught the privilege-escalation surface (any
// authenticated user, including a tenant-scoped operator, could
// list every MSP in the platform or create a new one).
//
// Returns true when the handler should proceed and false (after
// writing the 401/403/500) when it must return.
func (h *MSPHandler) requirePlatformPermission(w http.ResponseWriter, r *http.Request, permission string) bool {
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped msp routes require an authenticated user identity")
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
			"credentials do not authorise platform-scoped msp operations")
		return false
	}
	return true
}

// validMSPStatus filters request-supplied status strings against
// the repository's enum on the dedicated `POST .../status`
// endpoint where `deleted` is a valid value: `UpdateStatus` and
// `Delete` both maintain the (status='deleted' ⇔ deleted_at!=NULL)
// invariant via the database-side `deleted_at = CASE WHEN status
// = 'deleted' THEN COALESCE(deleted_at, NOW()) ELSE deleted_at
// END` arm, and the memory backend mirrors that behaviour.
//
// PATCH and Create do NOT use this helper anymore: round-6 of
// Devin Review caught that the generic `MSPRepository.Update`
// does not stamp `deleted_at` when the patch sets status to
// 'deleted', so allowing `deleted` on PATCH leaked an
// unreachable lifecycle row (status='deleted' but deleted_at
// IS NULL). Both PATCH and Create now use `validMSPCreateStatus`
// which rejects `deleted`; callers wanting to soft-delete must
// use `DELETE /api/v1/msps/{msp_id}` or `POST .../status`.
func validMSPStatus(s string) bool {
	switch repository.MSPStatus(s) {
	case "",
		repository.MSPStatusActive,
		repository.MSPStatusSuspended,
		repository.MSPStatusDeleted:
		return true
	}
	return false
}

// validMSPCreateStatus is the stricter create-time variant. A
// POST with status=deleted would land an inconsistent row
// (status='deleted' but deleted_at IS NULL) that is invisible to
// status-aware queries yet blocks slug reuse via the partial
// unique index, producing an unreachable lifecycle state. The
// only legal path into deleted is the UpdateStatus + Delete
// soft-delete machinery, which always stamps deleted_at NOW().
// On create we only accept empty (→ defaults to active in the
// repo), active, or suspended.
func validMSPCreateStatus(s string) bool {
	switch repository.MSPStatus(s) {
	case "",
		repository.MSPStatusActive,
		repository.MSPStatusSuspended:
		return true
	}
	return false
}

func (h *MSPHandler) list(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformPermission(w, r, "msp.read") {
		return
	}
	// OpenAPI publishes the cursor parameter as `?after=`. The
	// shared QueryLimit/Page helpers, the tenant handler, and the
	// integration handler all use the same name. A copy-paste of
	// `?cursor=` slipped in here originally — spec-compliant
	// clients would have silently fetched the first page on
	// every request.
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("after"),
	}
	res, err := h.msps.List(r.Context(), page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Typed envelope with `omitempty` on next_cursor so the field
	// is OMITTED (rather than emitted as `""`) on the last page.
	// The map[string]any pattern used earlier serialised `"":` for
	// terminal pages, which is technically distinct from the
	// OpenAPI `nullable: true` declaration and can trip
	// spec-strict SDK validators that distinguish between absent,
	// null, and empty-string. Matches the alert/baseline handlers.
	out := struct {
		Items      []MSPResponse `json:"items"`
		NextCursor string        `json:"next_cursor,omitempty"`
	}{
		Items:      make([]MSPResponse, 0, len(res.Items)),
		NextCursor: res.NextCursor,
	}
	for _, m := range res.Items {
		out.Items = append(out.Items, toMSPResponse(m))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *MSPHandler) create(w http.ResponseWriter, r *http.Request) {
	if !h.requirePlatformPermission(w, r, "msp.write") {
		return
	}
	var req MSPRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param", "name is required")
		return
	}
	// Slug is required by the repo layer (memory: explicit guard;
	// postgres: NOT NULL column). Surface a precise 400 here so
	// the client gets `slug is required` rather than the generic
	// `invalid_argument` that bubbles up from the repo.
	if req.Slug == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param", "slug is required")
		return
	}
	// Status, when supplied, must match the create-time subset of
	// the repository enum. The memory repo writes the verbatim
	// string (no CHECK constraint), so without this guard a
	// client could POST `"status": "corrupt-state"` and have it
	// persist. Postgres would reject via CHECK at write time but
	// only when the postgres backend is wired; we want consistent
	// boundary validation across both backends. `deleted` is
	// additionally rejected because Create has no soft-delete
	// bookkeeping (would store status='deleted' with deleted_at
	// IS NULL — an unreachable lifecycle state); use
	// `DELETE /api/v1/msps/{msp_id}` or `PUT .../status` to
	// transition an existing MSP into the deleted state.
	if !validMSPCreateStatus(req.Status) {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"status on create must be one of active, suspended (or omitted to default to active); use DELETE or PUT .../status to delete")
		return
	}
	m := repository.MSP{
		Name:     req.Name,
		Slug:     req.Slug,
		Status:   repository.MSPStatus(req.Status),
		Settings: req.Settings,
	}
	if req.Branding != nil {
		m.Branding = *req.Branding
	}
	created, err := h.msps.Create(r.Context(), m)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toMSPResponse(created))
}

func (h *MSPHandler) get(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	m, err := h.msps.Get(r.Context(), id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toMSPResponse(m))
}

func (h *MSPHandler) update(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	var req MSPPatchRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Reject empty Name/Slug on PATCH. The MSPPatchRequest
	// pointer type lets us distinguish absent (nil → no change)
	// from supplied empty (&""). A client posting `{"name": ""}`
	// or `{"slug": ""}` would otherwise reach the repository
	// with `patch.Name = &""` / `patch.Slug = &""`, where the
	// two backends DISAGREE:
	//
	//   - memory backend (internal/repository/memory/msp.go) guards
	//     `if *patch.Name != ""` and silently ignores the empty
	//     value (no-op);
	//   - postgres backend (internal/repository/postgres/msp.go) uses
	//     a `CASE WHEN $X IS NOT NULL THEN $X ELSE name END` arm
	//     that binds the empty string, so the column is set to ''.
	//
	// Either is wrong — both Name and Slug are required on Create
	// (the create handler rejects empty for both), so PATCH should
	// not be a back door to nulling them out. Reject 400 here at
	// the handler boundary so both backends produce the same
	// error consistently. Tested by
	// TestMSPHandler_PatchRejectsEmptyName / _PatchRejectsEmptySlug.
	if req.Name != nil && *req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"name cannot be cleared via PATCH; omit the field to leave unchanged")
		return
	}
	if req.Slug != nil && *req.Slug == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"slug cannot be cleared via PATCH; omit the field to leave unchanged")
		return
	}
	patch := repository.MSPPatch{
		Name:     req.Name,
		Slug:     req.Slug,
		Branding: req.Branding,
		Settings: req.Settings,
	}
	// Skip patch.Status entirely when the client supplied an
	// empty string. The MSPPatchRequest pointer type already
	// differentiates "absent" (nil) from "supplied" (non-nil),
	// but a client posting `{"status": ""}` would otherwise reach
	// the repo with patch.Status = &""; the postgres backend
	// would then violate `CHECK (status IN ('active', 'suspended',
	// 'deleted'))` (the SQL CASE arm binds "" not NULL) while the
	// memory backend silently skips. Treating "" as "no change"
	// (matching the doc-comment on MSPPatchRequest's pointer
	// semantics) eliminates the cross-backend divergence and the
	// hidden 400 path.
	//
	// Note: round-6 of Devin Review caught a subtle BUG with the
	// previous `validMSPStatus` allow-list on PATCH — it accepted
	// "deleted", but the generic `MSPRepository.Update()` only
	// writes the status column without touching `deleted_at`. The
	// result was an inconsistent row (status='deleted' but
	// deleted_at IS NULL) that broke slug reuse via the partial
	// unique index (the index considers the slug still "in use"
	// because deleted_at is NULL) and violated the lifecycle
	// invariant the rest of the system assumes. We now use the
	// stricter `validMSPCreateStatus` here, which rejects
	// "deleted": callers wanting to soft-delete an MSP must use
	// the dedicated `DELETE /api/v1/msps/{msp_id}` or
	// `POST .../status` endpoints, both of which correctly stamp
	// `deleted_at NOW()` alongside the status change. Tested by
	// TestMSPHandler_PatchRejectsStatusDeleted.
	if req.Status != nil && *req.Status != "" {
		if !validMSPCreateStatus(*req.Status) {
			WriteError(w, http.StatusBadRequest, "invalid_param",
				"status on PATCH must be one of active, suspended; use DELETE or POST .../status to delete")
			return
		}
		s := repository.MSPStatus(*req.Status)
		patch.Status = &s
	}
	updated, err := h.msps.Update(r.Context(), id, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Branding may have changed. Tenants under this MSP inherit
	// per-field overrides, so a Branding mutation here invalidates
	// every cached entry — the cache keys on tenantID, not mspID,
	// so we cannot selectively flush.
	//
	// We invalidate ONLY when the patch actually touched Branding.
	// Round-7 of Devin Review caught the previous unconditional
	// flush: Name/Slug/Status/Settings changes do not affect the
	// resolved MSPBranding record (which only contains LogoURL,
	// PrimaryColor, SecondaryColor, CustomDomain, PortalSupportTo
	// — none of which derive from MSP top-level fields), so
	// flushing on every UpdateMSP caused a thundering-herd of
	// branding-resolve re-fetches against the tenant + msp repos
	// after any unrelated MSP metadata change. Conditional flush
	// preserves correctness (branding edits remain immediately
	// visible) while avoiding the unnecessary cache wipe on the
	// common case where operators rename an MSP or rotate its
	// status. InvalidateAll is a no-op on the uncached resolver so
	// this is safe regardless of construction path. See
	// BrandingResolver doc-comment for the rationale.
	if h.branding != nil && patch.Branding != nil {
		h.branding.InvalidateAll()
	}
	WriteJSON(w, http.StatusOK, toMSPResponse(updated))
}

func (h *MSPHandler) setStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	var req MSPStatusRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Status is required on this endpoint (not the partial-update
	// PATCH), so reject empty along with bogus enum strings.
	if req.Status == "" || !validMSPStatus(req.Status) {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"status must be one of active, suspended, deleted")
		return
	}
	updated, err := h.msps.UpdateStatus(r.Context(), id, repository.MSPStatus(req.Status))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toMSPResponse(updated))
}

func (h *MSPHandler) delete(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	if err := h.msps.Delete(r.Context(), id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Soft-deleting an MSP cascades by clearing tenants.msp_id for
	// every tenant the MSP owned (memory backend:
	// internal/repository/memory/msp.go:210-221; postgres backend:
	// internal/repository/postgres/msp.go:304-308). The resolver keys
	// the branding cache on tenantID, so any tenant that was bound to
	// this MSP would otherwise keep serving the now-deleted MSP's
	// branding fields until the cache TTL expired. We can't selectively
	// flush (the cache is keyed on tenantID and we don't enumerate the
	// owned tenant set here on purpose — that's the repo's concern), so
	// we invalidate the whole cache. InvalidateAll is a documented
	// no-op on uncached resolvers (internal/service/tenant/branding.go
	// :180-188), so this is free on the current production wiring (which
	// constructs the uncached variant via NewBrandingResolver) and only
	// pays a cost the moment caching is turned on. Round-8 of Devin
	// Review caught this gap. Symmetric with the Update path's
	// conditional flush — the Update path uses patch.Branding != nil as
	// a precise predicate; Delete cannot be that selective because it
	// has no per-field signal, so we always invalidate.
	if h.branding != nil {
		h.branding.InvalidateAll()
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Tenant binding ------------------------------------------------------

func (h *MSPHandler) listTenants(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	// `?after=` per OpenAPI; see list() above for the same fix.
	page := repository.Page{Limit: QueryLimit(r), After: r.URL.Query().Get("after")}
	res, err := h.msps.ListTenants(r.Context(), id, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Typed envelope; see list() above for the rationale.
	out := struct {
		Items      []MSPTenantBindingResponse `json:"items"`
		NextCursor string                     `json:"next_cursor,omitempty"`
	}{
		Items:      make([]MSPTenantBindingResponse, 0, len(res.Items)),
		NextCursor: res.NextCursor,
	}
	for _, b := range res.Items {
		out.Items = append(out.Items, toBindingResponse(b))
	}
	WriteJSON(w, http.StatusOK, out)
}

// AssignTenantRequest is the optional body for POST
// /api/v1/msps/{msp_id}/tenants/{tenant_id}. The relationship
// defaults to "owner" when omitted.
type AssignTenantRequest struct {
	Relationship string `json:"relationship,omitempty"`
}

func (h *MSPHandler) assignTenant(w http.ResponseWriter, r *http.Request) {
	mspID, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	rel := repository.MSPRelationshipOwner
	// Body is optional — assignTenant defaults to `owner` when
	// no body is supplied. r.ContentLength is:
	//   *  > 0 for fixed-length bodies (Content-Length header set)
	//   *  0   when the client explicitly sent no body
	//   * -1   when the body is sent with Transfer-Encoding: chunked
	//          (Content-Length unknown until the chunk stream ends)
	// The previous guard `r.ContentLength > 0` silently ignored
	// the chunked case — a client streaming `{"relationship":
	// "co_manager"}` over chunked encoding would get the
	// compiled-in default `owner` applied silently, with NO error
	// and no log line. Mirrors the fix on device.go:84.
	if r.ContentLength != 0 {
		var req AssignTenantRequest
		dec := json.NewDecoder(r.Body)
		// DisallowUnknownFields makes a typo like
		// `{"relasionship":"co_manager"}` surface as a 400
		// rather than silently falling through to the default
		// `owner` because `Relationship` parsed as the
		// zero-value. Same shape as the integration handler's
		// PATCH decoder.
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				// chunked transfer with zero bytes — treat as
				// "no body", apply default `owner` relationship.
			} else {
				WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
				return
			}
		}
		if req.Relationship != "" {
			rel = repository.MSPRelationship(req.Relationship)
		}
	}
	// Validate the enum at the handler boundary. The repository
	// rejects unknown relationships with ErrInvalidArgument, but
	// that surfaces as the generic `invalid_argument` body with
	// no field-level guidance. Producing a precise 400 here
	// matches the validMSPStatus + slug pattern earlier in this
	// file and gives clients an actionable error message.
	if !rel.IsValid() {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"relationship must be one of owner, co_manager (or omitted to default to owner)")
		return
	}
	binding, err := h.msps.AssignTenant(r.Context(), mspID, tenantID, rel, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Owner-relationship assignments cascade by setting
	// tenants.msp_id to the new MSP (memory backend:
	// internal/repository/memory/msp.go:301-307; postgres backend
	// mirrors this via the AssignTenant SQL). That changes the
	// branding resolution chain for this tenant: a cached branding
	// entry resolved before the binding would have used the old
	// msp_id (or platform defaults if previously unbound) and would
	// keep serving stale fields until TTL. Co-manager bindings do
	// NOT touch tenants.msp_id (only the join row is inserted), so
	// branding resolution is unaffected and we skip the invalidation
	// for those — keeps the cache hit-rate high for the common case
	// of attaching audit/read-only relationships. Round-9 of Devin
	// Review caught this gap. We use Invalidate(tenantID) instead
	// of InvalidateAll because we have the precise tenantID here
	// (unlike the delete path which cascades across the unknown
	// owned-tenant set); per-tenant flush is O(1) and minimises
	// blast radius. InvalidateAll/Invalidate are both no-ops on
	// the uncached production resolver.
	if h.branding != nil && rel == repository.MSPRelationshipOwner {
		h.branding.Invalidate(tenantID)
	}
	WriteJSON(w, http.StatusCreated, toBindingResponse(binding))
}

func (h *MSPHandler) unassignTenant(w http.ResponseWriter, r *http.Request) {
	mspID, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	if err := h.msps.UnassignTenant(r.Context(), mspID, tenantID); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Unassigning an owner binding cascades by clearing
	// tenants.msp_id back to NULL (memory backend:
	// internal/repository/memory/msp.go:330-337; postgres mirrors).
	// That changes the branding resolution chain: cached entries
	// keyed on tenantID would otherwise keep serving the
	// just-detached MSP's branding fields until TTL.
	//
	// The handler cannot tell whether the removed binding was owner
	// or co-manager without a pre-lookup (AssignTenant has `rel` in
	// scope; UnassignTenant identifies the binding by composite key
	// only). Pre-fetching the binding first would add a roundtrip
	// solely to gate a per-tenant invalidation that is itself O(1)
	// on the cache and a no-op on the production uncached resolver.
	// Use the always-invalidate strategy here — the cost is bounded
	// to one cache eviction per call, and the correctness is
	// strictly tighter than the pre-fetch alternative (the
	// pre-fetched binding could race with a concurrent assign).
	// Round-9 of Devin Review caught this gap. Symmetric with the
	// delete handler's full flush, but narrower: we know exactly
	// which tenant is affected here, so we use Invalidate(tenantID)
	// rather than InvalidateAll.
	if h.branding != nil {
		h.branding.Invalidate(tenantID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- Bulk operations -----------------------------------------------------

// BulkPolicyTemplateRequest carries the policy graph (same shape
// policy.PutGraph accepts).
type BulkPolicyTemplateRequest struct {
	Template json.RawMessage `json:"template"`
}

// BulkSiteRequest carries the per-tenant site template.
type BulkSiteRequest struct {
	Name     string          `json:"name"`
	Template string          `json:"template,omitempty"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// BulkClaimTokensRequest carries the count + TTL.
//
// TTLSeconds semantics:
//
//   - >0 → the issued tokens expire that many seconds after
//     issuance (typical operator value).
//   - 0 or omitted → the identity service falls back to its
//     configured DefaultTokenTTL (see internal/service/identity
//     and `cfg.Auth.ClaimTokenTTL`). This is INTENTIONAL: it
//     lets operator UIs default to "use platform setting"
//     without having to read the config first. The OpenAPI spec
//     documents this fallback explicitly so SDK clients are not
//     surprised by the silent default substitution.
//   - negative values are rejected at the OpenAPI layer
//     (`minimum: 0`); the handler does NOT need to re-check.
type BulkClaimTokensRequest struct {
	Count      int `json:"count"`
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// BulkOutcomeResponse is the per-tenant JSON projection of a
// BulkTenantOutcome.
type BulkOutcomeResponse struct {
	TenantID      string   `json:"tenant_id"`
	Error         string   `json:"error,omitempty"`
	PolicyVersion int      `json:"policy_version,omitempty"`
	SiteID        string   `json:"site_id,omitempty"`
	ClaimTokens   []string `json:"claim_tokens,omitempty"`
}

// BulkResultResponse wraps the per-tenant outcomes + run-level
// counts.
type BulkResultResponse struct {
	Successes []BulkOutcomeResponse `json:"successes"`
	Failures  []BulkOutcomeResponse `json:"failures"`
	StartedAt string                `json:"started_at"`
	EndedAt   string                `json:"ended_at"`
}

func toBulkOutcome(o svctenant.BulkTenantOutcome) BulkOutcomeResponse {
	r := BulkOutcomeResponse{
		TenantID:      o.TenantID.String(),
		PolicyVersion: o.PolicyVersion,
		ClaimTokens:   o.ClaimTokens,
	}
	if o.SiteID != uuid.Nil {
		r.SiteID = o.SiteID.String()
	}
	if o.Error != nil {
		r.Error = o.Error.Error()
	}
	return r
}

func toBulkResultResponse(res svctenant.BulkResult) BulkResultResponse {
	out := BulkResultResponse{
		StartedAt: res.StartedAt.Format(time.RFC3339Nano),
		EndedAt:   res.EndedAt.Format(time.RFC3339Nano),
		Successes: make([]BulkOutcomeResponse, 0, len(res.Successes)),
		Failures:  make([]BulkOutcomeResponse, 0, len(res.Failures)),
	}
	for _, o := range res.Successes {
		out.Successes = append(out.Successes, toBulkOutcome(o))
	}
	for _, o := range res.Failures {
		out.Failures = append(out.Failures, toBulkOutcome(o))
	}
	return out
}

func (h *MSPHandler) bulkApplyPolicyTemplate(w http.ResponseWriter, r *http.Request) {
	mspID, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated", "user identity required")
		return
	}
	var req BulkPolicyTemplateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	res, err := h.bulk.ApplyPolicyTemplateToTenants(r.Context(), mspID, userID, actorFromCtx(r), req.Template)
	if err != nil {
		writeBulkError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toBulkResultResponse(res))
}

func (h *MSPHandler) bulkProvisionSites(w http.ResponseWriter, r *http.Request) {
	mspID, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated", "user identity required")
		return
	}
	var req BulkSiteRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	site := repository.Site{
		Name:     req.Name,
		Template: repository.SiteTemplate(req.Template),
		Config:   req.Config,
	}
	res, err := h.bulk.BulkProvisionSites(r.Context(), mspID, userID, actorFromCtx(r), site)
	if err != nil {
		writeBulkError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toBulkResultResponse(res))
}

func (h *MSPHandler) bulkGenerateClaimTokens(w http.ResponseWriter, r *http.Request) {
	mspID, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated", "user identity required")
		return
	}
	var req BulkClaimTokensRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// req.TTLSeconds == 0 (omitted or explicit) flows through as
	// ttl=0, which the identity service interprets as "use
	// DefaultTokenTTL". See BulkClaimTokensRequest doc-comment for
	// the contract, and api/openapi.yaml for the spec.
	ttl := time.Duration(req.TTLSeconds) * time.Second
	res, err := h.bulk.BulkGenerateClaimTokens(r.Context(), mspID, userID, actorFromCtx(r), req.Count, ttl)
	if err != nil {
		writeBulkError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toBulkResultResponse(res))
}

// writeBulkError maps service-level bulk errors. Today the
// RequireMSPScope middleware validates the msp_id UUID and the
// authz layer rejects unauthorized callers BEFORE the bulk
// service runs, so ErrNotFound/ErrForbidden from the
// `authorizedTenants` step is unreachable in the happy-path call
// flow. But the bulk service is a public function with its own
// error contract; defence-in-depth mapping here ensures the HTTP
// surface stays correct if a future caller wires the bulk path
// without the middleware (e.g. an internal admin tool or a
// follow-up endpoint surface). Never leak `err.Error()` — the
// bulk path can wrap pgx / errgroup errors that surface internal
// implementation details (table names, internal tenant IDs); the
// repository-error helpers already use generic messages.
// Mirrors policy_simulation.go:299-306 and WriteRepositoryError.
func writeBulkError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrInvalidArgument),
		errors.Is(err, repository.ErrNotFound),
		errors.Is(err, repository.ErrForbidden),
		errors.Is(err, repository.ErrConflict),
		errors.Is(err, repository.ErrResourceExhausted):
		WriteRepositoryError(w, err)
	default:
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

// ---- Branding ------------------------------------------------------------

// BrandingResponse is the JSON projection of MSPBranding. Every
// field is populated by the resolver.
type BrandingResponse struct {
	LogoURL         string `json:"logo_url"`
	PrimaryColor    string `json:"primary_color"`
	SecondaryColor  string `json:"secondary_color"`
	CustomDomain    string `json:"custom_domain"`
	PortalSupportTo string `json:"portal_support_to"`
}

func toBrandingResponse(b repository.MSPBranding) BrandingResponse {
	return BrandingResponse{
		LogoURL:         b.LogoURL,
		PrimaryColor:    b.PrimaryColor,
		SecondaryColor:  b.SecondaryColor,
		CustomDomain:    b.CustomDomain,
		PortalSupportTo: b.PortalSupportTo,
	}
}

func (h *MSPHandler) getBranding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	b, err := h.branding.Resolve(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toBrandingResponse(b))
}

func (h *MSPHandler) setBranding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req repository.MSPBranding
	if !DecodeJSON(w, r, &req) {
		return
	}
	// SetTenantBranding returns the updated tenant row, so the
	// follow-up resolution can skip an otherwise-redundant
	// Get(tenant): branding.Resolve would re-fetch the same row
	// we already have in hand. ResolveForTenant operates on the
	// supplied tenant + at most one MSP fetch, saving one DB
	// roundtrip per setBranding call (called out by round-2
	// review on msp.go:644-655).
	updated, err := h.branding.SetTenantBranding(r.Context(), tenantID, req)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	b, err := h.branding.ResolveForTenant(r.Context(), updated)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toBrandingResponse(b))
}

func (h *MSPHandler) clearBranding(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	if _, err := h.branding.ClearTenantBranding(r.Context(), tenantID); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

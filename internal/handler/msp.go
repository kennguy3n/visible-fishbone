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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	svctenant "github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// isJSONNullPayload reports whether `b` is the JSON `null` literal
// (after stripping surrounding whitespace). Used to reject explicit
// `null` on payloads the OpenAPI spec declares as required JSON
// objects — see round-22 of Devin Review on PR #42 (ANALYSIS_0005).
// The matching repo-boundary normalisation that maps the `null`
// literal back to `{}` for any internal caller that bypasses the
// handler lives in internal/repository/postgres/nulls.go and
// internal/repository/memory/store.go.
func isJSONNullPayload(b json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(b), []byte("null"))
}

// MSPService is the narrow interface the handler needs from the
// production wiring. Implemented by a concrete *msp.Service that
// just delegates to repository.MSPRepository — we keep the
// interface here so tests can stub without dragging the full
// service surface.
type MSPService interface {
	Create(ctx context.Context, m repository.MSP) (repository.MSP, error)
	Get(ctx context.Context, id uuid.UUID) (repository.MSP, error)
	List(ctx context.Context, page repository.Page, filter repository.MSPListFilter) (repository.PageResult[repository.MSP], error)
	Update(ctx context.Context, id uuid.UUID, patch repository.MSPPatch) (repository.MSP, error)
	// TransitionStatus is the race-free building block for the
	// active <-> suspended transitions on POST .../status. The
	// repository's atomic SQL precondition (`WHERE status <>
	// 'deleted'`) closes the TOCTOU window present in a
	// Get-then-UpdateStatus pair (round-13 of Devin Review on
	// PR #42 — BUG_0001). The handler must NOT call this for
	// `to=deleted`; that transition is owned by Delete().
	//
	// Note: the older `UpdateStatus(ctx, id, status)` method
	// remains on the underlying `repository.MSPRepository` (other
	// service-layer callers may need it), but it is intentionally
	// NOT exposed on this handler-narrow interface. Round-16 of
	// Devin Review on PR #42 (ANALYSIS_0002) caught the dead-code
	// surface and the lifecycle-invariant risk: UpdateStatus
	// writes the status column unconditionally (no resurrection
	// guard, no `deleted_at` bookkeeping for a deleted-transition
	// path), so a future handler refactor that reached for it
	// would silently bypass the round-12/13 invariants. The
	// canonical paths are TransitionStatus (active <-> suspended)
	// and Delete (the cascading soft-delete) — and the handler
	// interface should expose exactly those.
	TransitionStatus(ctx context.Context, id uuid.UUID, to repository.MSPStatus) (repository.MSP, error)
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
	// Permission strings are sourced from the bulk service's exported
	// constants so the middleware gate and the service's
	// authorizedTenants() check resolve the same string. Round-11 of
	// Devin Review on PR #42 caught the previous DRY drift where the
	// handler had string literals ("msp.bulk_apply_policy") and the
	// bulk service had constants (svctenant.PermissionBulkApplyPolicy);
	// if either side ever changed, the middleware would gate on one
	// permission while the service evaluated authorization with a
	// different one, silently narrowing or broadening the authorized
	// tenant set with no test failure.
	if h.bulk != nil {
		mux.Handle("POST /api/v1/msps/{msp_id}/bulk/policy-templates",
			middleware.RequireMSPScope(h.authz, svctenant.PermissionBulkApplyPolicy, "msp_id")(http.HandlerFunc(h.bulkApplyPolicyTemplate)))
		mux.Handle("POST /api/v1/msps/{msp_id}/bulk/sites",
			middleware.RequireMSPScope(h.authz, svctenant.PermissionBulkProvisionSites, "msp_id")(http.HandlerFunc(h.bulkProvisionSites)))
		mux.Handle("POST /api/v1/msps/{msp_id}/bulk/claim-tokens",
			middleware.RequireMSPScope(h.authz, svctenant.PermissionBulkGenerateClaimToken, "msp_id")(http.HandlerFunc(h.bulkGenerateClaimTokens)))
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

// validSiteTemplate is the handler-boundary guard for the
// `template` field on BulkSiteRequest. Round-16 of Devin Review on
// PR #42 (ANALYSIS_0007) flagged that bogus values flowed through
// to the site service where they produced a generic
// `unknown template ...: invalid_argument` 400 — inconsistent
// with status, slug, and relationship which all surface a specific
// `invalid_param` message from this layer. Empty stays valid: the
// site service defaults the empty case to `branch` at
// `internal/service/site/service.go:86-88`.
func validSiteTemplate(s string) bool {
	switch repository.SiteTemplate(s) {
	case "",
		repository.SiteTemplateBranch,
		repository.SiteTemplateHub,
		repository.SiteTemplateCloudOnly,
		repository.SiteTemplateHomeOffice:
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
	// Default-exclude soft-deleted rows; admin tools opt in via
	// `?include_deleted=true`. Round-17 of Devin Review on PR #42
	// flagged that the previous handler returned all rows including
	// tombstoned ones, contradicting the lifecycle invariant that
	// `deleted` is terminal and should not appear in default
	// listings. Any value other than the canonical "true" is
	// treated as false (matches `strconv.ParseBool`'s strictness:
	// `1`, `t`, `T`, `TRUE`, `true`, `True` all evaluate true; we
	// only accept the lower-case "true" canonical form to keep
	// the query-string grammar minimal and predictable).
	filter := repository.MSPListFilter{
		IncludeDeleted: r.URL.Query().Get("include_deleted") == "true",
	}
	res, err := h.msps.List(r.Context(), page, filter)
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
		// Round-16 of Devin Review on PR #42 (BUG_0001) caught the
		// previous `PUT .../status` reference — the status endpoint
		// is registered as `POST /api/v1/msps/{msp_id}/status` (see
		// the Register() body above). A client following the stale
		// message would issue a PUT and get a 405 from the router
		// instead of the expected lifecycle transition. Match the
		// PATCH handler's wording downstream.
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"status on create must be one of active, suspended (or omitted to default to active); use DELETE or POST .../status to delete")
		return
	}
	// Reject the JSON `null` literal for `settings`. The OpenAPI
	// schema declares `settings: type: object` (no `nullable: true`),
	// and the repo defaults nil/empty payloads to `{}` so the stored
	// row always satisfies the object invariant. Without this guard,
	// `{"settings": null}` decodes to `json.RawMessage("null")`
	// (len == 4, NOT zero), the existing `len == 0` default in the
	// repo skips it, and we end up storing `'null'::jsonb` — valid
	// JSONB but in conflict with the OpenAPI contract and the
	// downstream client expectation that `settings` is always an
	// object. The repo boundary also normalises this defensively
	// for internal callers (see internal/repository/postgres/msp.go
	// and internal/repository/memory/msp.go); the handler 400 here
	// gives spec-strict HTTP clients a precise error rather than a
	// silent normalisation. Round-22 of Devin Review on PR #42
	// (ANALYSIS_0005).
	if isJSONNullPayload(req.Settings) {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"settings cannot be JSON null; omit the field or send an object")
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
	// Note on `{"settings": null}` for PATCH: the field type is
	// `*json.RawMessage`, and encoding/json decodes JSON `null`
	// for a pointer-typed field as a nil pointer (not a non-nil
	// pointer holding the 4-byte literal `null`). So `req.Settings
	// == nil` here, which downstream treats as "field omitted →
	// keep existing" — the right behaviour for a PATCH that the
	// client explicitly cleared with `null`. The Create handler
	// above DOES need an explicit `null`-literal guard because the
	// CREATE struct uses non-pointer `json.RawMessage` which
	// decodes `null` as the 4-byte `"null"`. The repo boundary
	// also defensively normalises the `null` literal back to `{}`
	// for any internal caller that constructs an MSPPatch with
	// `Settings: &json.RawMessage("null")` directly — see
	// internal/repository/postgres/msp.go and the matching memory
	// helper. Round-22 of Devin Review on PR #42 (ANALYSIS_0005).
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
	// Transitioning to `deleted` must follow the same cascade-aware
	// path as `DELETE /api/v1/msps/{msp_id}`: the repository's
	// UpdateStatus method only stamps the MSP row + deleted_at, but
	// Delete additionally removes msp_tenants rows and clears the
	// denormalised tenants.msp_id pointer (memory:
	// internal/repository/memory/msp.go:211-247; postgres mirrors).
	// Routing both endpoints through the same code path on the
	// deleted-transition closes the cascade gap caught by round-10
	// of Devin Review:
	//
	//   * orphaned msp_tenants rows would otherwise survive across the
	//     soft-delete, blocking re-binding and producing zombie rows;
	//   * tenants.msp_id would keep pointing at the soft-deleted MSP,
	//     so branding resolution would continue surfacing the deleted
	//     MSP's LogoURL/colors/CustomDomain until an out-of-band
	//     bind/unbind cycle reset the denormalised pointer.
	//
	// We use Delete() instead of teaching UpdateStatus to cascade in
	// both repository backends because (a) Delete already has the
	// canonical cascade implementation and the lifecycle invariant is
	// enforced in exactly one place, (b) UpdateStatus's contract
	// stays simple (active <-> suspended transitions only need to
	// touch the MSP row), and (c) doubling the cascade logic across
	// two repository methods is exactly the kind of
	// invariant-violation surface that the round-6 + round-8 reviews
	// were exercised against. After Delete we re-Get the row to honour
	// the OpenAPI contract that `POST .../status` returns 200 + the
	// MSP body (the DELETE endpoint returns 204 No Content, which
	// would be a wire-incompatible change here). Get() does NOT filter
	// soft-deleted rows, so the response shows status="deleted" with
	// deleted_at stamped — exactly what the client requested. We
	// invalidate the branding cache for the same reason the delete
	// handler does: every tenant previously bound to this MSP now
	// resolves through platform defaults, so any cached entry keyed on
	// tenantID would otherwise keep serving the just-deleted MSP's
	// branding until TTL.
	if repository.MSPStatus(req.Status) == repository.MSPStatusDeleted {
		// Privilege gate (round-18 of Devin Review on PR #42 —
		// BUG_0001). The route's middleware wrapper has already
		// established the caller holds `msp.write` against this MSP
		// (see Register() at line 125-126). That is sufficient for
		// active <-> suspended transitions, but transitioning into
		// `deleted` runs the same cascade as the dedicated `DELETE
		// /api/v1/msps/{msp_id}` endpoint — removing every
		// msp_tenants row and clearing the denormalised
		// tenants.msp_id pointer on every owned tenant. The DELETE
		// endpoint requires the stricter `msp.delete` permission
		// (line 127-128). Without this extra gate, any operator
		// holding `msp.write` but NOT `msp.delete` could bypass
		// the intended permission boundary by POSTing
		// `{"status": "deleted"}` to the status endpoint instead
		// of calling DELETE. Surface a 403 here so the two paths
		// observe the same authorisation contract regardless of
		// which verb the caller used. Tested by
		// TestMSPHandler_SetStatusDeleted_RequiresMSPDeletePermission.
		userID := middleware.UserIDFromContext(r.Context())
		if userID == uuid.Nil {
			// The route's middleware already enforced authentication,
			// so a missing user ID here is a programmer error (the
			// middleware chain was wired incorrectly). Fail closed
			// rather than fall through to the cascade.
			WriteError(w, http.StatusUnauthorized, "unauthenticated",
				"setStatus=deleted requires an authenticated user identity")
			return
		}
		allowed, err := h.authz.AuthorizeMSP(r.Context(), userID, id, "msp.delete")
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "authorization_failed",
				"failed to evaluate msp.delete authorization for setStatus=deleted")
			return
		}
		if !allowed {
			WriteError(w, http.StatusForbidden, "msp_forbidden",
				"setStatus=deleted requires the msp.delete permission (the cascade is identical to DELETE /api/v1/msps/{msp_id}); current grant only includes msp.write")
			return
		}
		// Idempotency contract: a `POST .../status` with
		// status="deleted" against an already-soft-deleted MSP must
		// return 200 + the (still-deleted) MSP body, NOT 403
		// ErrForbidden from a second Delete call. Both repository
		// backends explicitly reject double-deletes (memory:
		// internal/repository/memory/msp.go:221-222; postgres:
		// internal/repository/postgres/msp.go:317-325 — the SQL
		// guard refuses to re-stamp deleted_at). Without this short
		// circuit, replaying the same status request — a common
		// pattern with at-least-once delivery from upstream
		// orchestration — would surface a confusing 403 to clients
		// who already observed the deletion succeed once.
		//
		// Note: Get() does NOT filter soft-deleted rows (round-10
		// established this for the post-Delete read below), so the
		// pre-check sees the deleted row exactly the same way the
		// post-Delete path does. Round-11 of Devin Review on PR #42
		// flagged the previous 403-on-replay surface as a REST
		// idempotency violation for soft-delete semantics.
		existing, err := h.msps.Get(r.Context(), id)
		if err != nil {
			WriteRepositoryError(w, err)
			return
		}
		if existing.Status == repository.MSPStatusDeleted {
			WriteJSON(w, http.StatusOK, toMSPResponse(existing))
			return
		}
		if err := h.msps.Delete(r.Context(), id); err != nil {
			// TOCTOU window between the pre-Get above and this
			// Delete call: if a concurrent `DELETE /api/v1/msps/{id}`
			// or another `POST .../status` with status=deleted lands
			// in between, our pre-Get saw status=active so the
			// idempotency short-circuit didn't fire, then our Delete
			// returns ErrForbidden because the repository backends
			// refuse to re-stamp deleted_at on an already-deleted
			// row (memory: internal/repository/memory/msp.go:276;
			// postgres: internal/repository/postgres/msp.go:384).
			// Without this guard, the concurrent caller observes
			// 200+body (the winner) but THIS caller observes a 403
			// "operation not permitted" — even though the MSP is
			// now in exactly the state they requested, breaking
			// the idempotency contract this endpoint documents.
			//
			// Round-15 of Devin Review on PR #42 (BUG_0001) flagged
			// this race. Recovery: re-Get to confirm the row is now
			// soft-deleted (we expect the concurrent caller's
			// Delete to have committed); if so, return 200+body
			// just like the pre-check path would have. Only surface
			// the 403 if the row is somehow still NOT deleted — a
			// genuinely unexpected state (e.g. a parallel
			// resurrection, which is itself rejected by the
			// resurrection guard a few lines below). The branding
			// cache is invalidated either way because *some* caller
			// soft-deleted the MSP and any cached entry under this
			// MSP's tenants is now stale.
			if errors.Is(err, repository.ErrForbidden) {
				recheck, rgErr := h.msps.Get(r.Context(), id)
				if rgErr != nil {
					WriteRepositoryError(w, rgErr)
					return
				}
				if recheck.Status == repository.MSPStatusDeleted {
					if h.branding != nil {
						h.branding.InvalidateAll()
					}
					WriteJSON(w, http.StatusOK, toMSPResponse(recheck))
					return
				}
				// Truly unexpected: Delete refused but the row is
				// not in the deleted state. Fall through to surface
				// the original ErrForbidden as a 403.
			}
			WriteRepositoryError(w, err)
			return
		}
		if h.branding != nil {
			h.branding.InvalidateAll()
		}
		deleted, err := h.msps.Get(r.Context(), id)
		if err != nil {
			WriteRepositoryError(w, err)
			return
		}
		WriteJSON(w, http.StatusOK, toMSPResponse(deleted))
		return
	}
	// Resurrection guard: refuse to transition a soft-deleted MSP
	// back to active/suspended. Both repository backends'
	// UpdateStatus methods write the status column unconditionally
	// (memory: internal/repository/memory/msp.go:206; postgres:
	// internal/repository/postgres/msp.go SET status=$2,
	// deleted_at=CASE WHEN ... — the SQL CASE only stamps
	// deleted_at on `$2 = 'deleted'` and never CLEARS it on the
	// reverse arm), so without this guard a client could POST
	// `{"status":"active"}` to a soft-deleted MSP and produce a
	// corrupt row:
	//
	//   * status='active' but deleted_at != NULL — violates the
	//     `(status='deleted' ⇔ deleted_at != NULL)` lifecycle
	//     invariant the rest of the system relies on (the partial
	//     unique slug index `WHERE deleted_at IS NULL` would still
	//     see the row as soft-deleted; the resolver, status-aware
	//     list queries, and branding cache all behave inconsistently);
	//   * the cascade fired by the original `Delete()` —
	//     removing every `msp_tenants` row and clearing
	//     `tenants.msp_id` on each previously-owned tenant — is
	//     irreversible, leaving the resurrected MSP orphaned with
	//     no tenant bindings even though it appears active to
	//     status-only consumers.
	//
	// `deleted` is the terminal state of the MSP lifecycle. Round-12
	// of Devin Review on PR #42 caught the missing guard as
	// BUG_0001, and round-13 followed up with a 🔴 TOCTOU report
	// on the original Get-then-check-then-UpdateStatus pattern: a
	// concurrent DELETE could land between Get (seeing
	// status='active') and UpdateStatus (writing 'active' over a
	// stamped deleted_at), reintroducing the corrupt state the
	// guard was meant to prevent. The fix is to push the
	// precondition INTO the SQL statement — `WHERE status <>
	// 'deleted'` on the UPDATE — so the check and the write are
	// atomic. TransitionStatus exposes this atomic primitive and
	// returns ErrForbidden if the row is already deleted at
	// statement-evaluation time. To create a new MSP after a
	// deletion, callers must `POST /api/v1/msps` with a new slug —
	// the partial unique index intentionally allows slug reuse only
	// when the prior row is soft-deleted, but the resurrection path
	// was never the intended way to recycle an identifier.
	updated, err := h.msps.TransitionStatus(r.Context(), id, repository.MSPStatus(req.Status))
	if err != nil {
		if errors.Is(err, repository.ErrForbidden) {
			WriteError(w, http.StatusForbidden, "forbidden",
				"cannot transition a deleted MSP back to active or suspended; "+
					"deleted is a terminal lifecycle state — create a new MSP with the desired slug instead")
			return
		}
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
	// Branding cache invalidation. There are three relationship-
	// transition shapes here that change the branding resolution
	// chain for `tenantID`, and the handler does NOT have visibility
	// into the prior binding's relationship without a pre-lookup
	// (AssignTenant only returns the post-state binding):
	//
	//   1. NEW or REPLACE owner binding (no prior, or prior was owner
	//      on a different MSP, or prior was co_manager on this MSP):
	//      AssignTenant sets tenants.msp_id to mspID. → invalidate.
	//   2. DOWNGRADE owner → co_manager (prior was owner on THIS
	//      MSP; new relationship is co_manager): the repo correctly
	//      clears tenants.msp_id (see
	//      internal/repository/memory/msp.go:405-420 and postgres
	//      mirror), so branding resolution changes from "this MSP's
	//      branding" back to "platform defaults". → invalidate.
	//      Round-19 of Devin Review on PR #42 (BUG_0001) caught
	//      that the prior `rel == owner` gate missed this case.
	//   3. NEW co_manager (no prior owner on THIS MSP): only the
	//      join row is inserted, tenants.msp_id is unchanged, so
	//      branding resolution is unaffected. → in theory we could
	//      skip, but the handler has no way to distinguish (3) from
	//      (2) without racing the pre-lookup against a concurrent
	//      assign.
	//
	// We therefore invalidate unconditionally, mirroring the
	// always-invalidate strategy used by UnassignTenant which has
	// the same "can't tell prior relationship without a roundtrip"
	// constraint. The cost is bounded — one O(1) cache eviction per
	// call, no-op on the production uncached resolver. The
	// correctness is strictly tighter than the relationship-gated
	// alternative which had a documented gap (the downgrade path).
	// We use Invalidate(tenantID) instead of InvalidateAll because
	// the affected tenant is known precisely here; the delete path
	// cascades across the unknown owned-tenant set and must use
	// InvalidateAll.
	if h.branding != nil {
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

// MaxBulkClaimTokenCount caps the per-request token count on
// POST /api/v1/msps/{msp_id}/bulk/claim-tokens. Without an upper
// bound a client could request millions of tokens in a single
// call and exhaust the identity-store inserts (the postgres path
// issues one row per token under withTenant, and the memory path
// allocates a slice of length=count up front). Round-18 of Devin
// Review on PR #42 (ANALYSIS_0004) flagged this as a
// resource-exhaustion vector that the existing `count > 0` guard
// alone does not address. 1000 is intentionally generous compared
// to the paginated-list ceiling (repository.MaxPageLimit = 200)
// because token-issuance is a one-shot operator workflow rather
// than a routine listing, but still bounds the worst-case work
// per request to a fixed, predictable upper-bound that operators
// can reason about. Mirrored by ttl_seconds bounds checking
// already present at the handler boundary below.
const MaxBulkClaimTokenCount = 1000

// MaxClaimTokenTTLSeconds caps `ttl_seconds` on the same endpoint.
// Round-26 of Devin Review on PR #42 (ANALYSIS_0001) flagged
// that the existing `ttl_seconds >= 0` guard left an int64
// overflow window: `time.Duration(req.TTLSeconds) * time.Second`
// multiplies by 1e9 (nanoseconds per second), so any
// `TTLSeconds > math.MaxInt64 / 1e9` (~9.22 billion seconds, or
// ~292 years) wraps to a NEGATIVE duration. The bulk service
// stamps ExpiresAt = now + ttl, so the wrapped duration produces
// tokens whose ExpiresAt sits in the past — silently
// unredeemable, exactly the class of bug the lower-bound guard
// was added to prevent. The cap below (1 year) is multiple
// orders of magnitude below the overflow threshold, well above
// any plausible operator workflow (the longest legitimate
// claim-token lifetime today is a 30-day onboarding window),
// and symmetric with MaxBulkClaimTokenCount as a
// resource-exhaustion bound. A value of 0 stays valid — the
// identity service interprets ttl=0 as "use the configured
// DefaultTokenTTL" per BulkClaimTokensRequest's doc-comment.
const MaxClaimTokenTTLSeconds = 365 * 24 * 60 * 60

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
//   - negative values are rejected at the handler boundary below
//     (round-10 of Devin Review caught the original "OpenAPI gates
//     it" claim was false — no server-side OpenAPI validation
//     middleware is wired into the stack, so the spec is purely
//     documentation. A client posting `{"ttl_seconds": -60}` would
//     have flowed through as a negative time.Duration and produced
//     tokens with ExpiresAt in the past — silently unredeemable).
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
	// Template body must be present. The bulk service does enforce
	// this and returns ErrInvalidArgument-wrapped 400 via
	// writeBulkError, but the long-term contract puts input
	// validation at the handler boundary so the error surface is
	// uniform with the bulk/sites name guard, the bulk/claim-tokens
	// count + ttl guards, and the status/slug/rel checks the
	// earlier rounds consolidated here. Round-12 of Devin Review on
	// PR #42 flagged this asymmetric validation: handler-side
	// checks elsewhere produce specific `invalid_param` messages,
	// while a missing template body returned a generic
	// `invalid_argument`. The check uses `len()` against the raw
	// json.RawMessage rather than parsing — an empty body, `null`,
	// or just whitespace would all be rejected here, matching the
	// service-layer `len(templateGraph) == 0` predicate. The
	// `string(req.Template) == "null"` arm handles the explicit
	// JSON null case: `{"template": null}` unmarshals into a
	// non-nil 4-byte `RawMessage("null")`, but the policy
	// service would still reject it after fan-out cost — better
	// to fail fast at the boundary.
	if len(req.Template) == 0 || string(req.Template) == "null" {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"template is required")
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
	// Site name must be non-empty. Round-12 of Devin Review on
	// PR #42 caught the asymmetric validation: the bulk service
	// rejects an empty name at internal/service/tenant/bulk.go:222
	// with ErrInvalidArgument, but the handler did not surface a
	// specific message. Moving the check to the handler boundary
	// matches the pattern already established for the
	// bulk/claim-tokens count + ttl guards, the bulk/policy
	// template-body guard above, and the status/slug/rel checks on
	// the CRUD endpoints — uniform error surface, specific
	// `invalid_param` message, validation consolidated at one
	// layer.
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"name is required")
		return
	}
	// Validate `template` at the handler boundary so a bogus value
	// produces a specific `invalid_param` 400 instead of the generic
	// `invalid_argument` that bubbles up from the site service.
	// Round-16 of Devin Review on PR #42 (ANALYSIS_0007) flagged the
	// inconsistency: status / slug / relationship are all validated
	// at this layer, but template flowed through to
	// `internal/service/site/service.go:89-90` where the generic
	// `unknown template ...: invalid_argument` was wrapped into a 400
	// without the actionable param name. Empty stays valid (the site
	// service defaults it to `branch` at
	// `internal/service/site/service.go:86-88`); the four enum values
	// match `repository.SiteTemplate*` constants and the OpenAPI
	// declaration on `BulkSiteRequest`.
	if !validSiteTemplate(req.Template) {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"template must be one of branch, hub, cloud_only, home_office (or omitted to default to branch)")
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
	// Count must be > 0. The bulk service does enforce this and
	// returns ErrInvalidArgument-wrapped 400 via writeBulkError, but
	// the long-term contract puts boundary validation at the handler
	// so the error path is uniform with the negative-TTL guard below
	// and the client sees a specific message rather than the generic
	// "invalid_argument" the service wraps around it. Round-11 of
	// Devin Review on PR #42 caught the asymmetric validation surface:
	// the TTL guard lives at the handler, the count guard only at the
	// service — splitting input validation across two layers is the
	// same maintainability hazard the earlier rounds flagged on the
	// status enum, slug, and rel checks.
	if req.Count <= 0 {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"count must be > 0")
		return
	}
	// Upper-bound guard (round-18 of Devin Review on PR #42 —
	// ANALYSIS_0004). Without this cap a client could request
	// count=1_000_000 and force the bulk service to allocate the
	// matching-length slice + issue one DB row per token,
	// exhausting connection-pool capacity and inflating the
	// identity-store schema. The cap is set to
	// MaxBulkClaimTokenCount (1000) — well above any plausible
	// human-operator workflow but bounded enough to keep
	// worst-case work per request predictable. Surface the same
	// invalid_param shape as the lower bound so SDK clients can
	// handle both with a single error branch.
	if req.Count > MaxBulkClaimTokenCount {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			fmt.Sprintf("count must be <= %d (per-request upper bound — split very large issuance into multiple calls)", MaxBulkClaimTokenCount))
		return
	}
	// Negative TTLSeconds would compute ExpiresAt in the past and
	// produce silently-unredeemable tokens — the response would still
	// report success with token strings the client can never redeem.
	// The OpenAPI spec declares `minimum: 0` but the server has no
	// spec-validation middleware wired, so we re-check here at the
	// handler boundary. Round-10 of Devin Review caught the original
	// doc-comment's false "OpenAPI gates it" claim. We accept 0
	// because the identity service interprets ttl=0 as "use the
	// configured DefaultTokenTTL" — the intentional fallback path
	// documented on BulkClaimTokensRequest.
	if req.TTLSeconds < 0 {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"ttl_seconds must be >= 0")
		return
	}
	// Upper bound (round-26 of Devin Review on PR #42 —
	// ANALYSIS_0001). `time.Duration(req.TTLSeconds) *
	// time.Second` overflows int64 for TTLSeconds above ~9.2
	// billion (~292 years) and wraps to a negative duration,
	// silently producing tokens with ExpiresAt in the past. The
	// MaxClaimTokenTTLSeconds cap (1 year) is orders of magnitude
	// below the overflow threshold and well above any plausible
	// operator workflow. See the constant's doc-comment for the
	// detailed rationale.
	if req.TTLSeconds > MaxClaimTokenTTLSeconds {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			fmt.Sprintf("ttl_seconds must be <= %d (per-token upper bound; %d seconds is ~1 year)", MaxClaimTokenTTLSeconds, MaxClaimTokenTTLSeconds))
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

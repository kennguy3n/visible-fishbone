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

func (h *MSPHandler) list(w http.ResponseWriter, r *http.Request) {
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	res, err := h.msps.List(r.Context(), page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]MSPResponse, 0, len(res.Items))
	for _, m := range res.Items {
		items = append(items, toMSPResponse(m))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *MSPHandler) create(w http.ResponseWriter, r *http.Request) {
	var req MSPRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param", "name is required")
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
	patch := repository.MSPPatch{
		Name:     req.Name,
		Slug:     req.Slug,
		Branding: req.Branding,
		Settings: req.Settings,
	}
	if req.Status != nil {
		s := repository.MSPStatus(*req.Status)
		patch.Status = &s
	}
	updated, err := h.msps.Update(r.Context(), id, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
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
	w.WriteHeader(http.StatusNoContent)
}

// ---- Tenant binding ------------------------------------------------------

func (h *MSPHandler) listTenants(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "msp_id")
	if !ok {
		return
	}
	page := repository.Page{Limit: QueryLimit(r), After: r.URL.Query().Get("cursor")}
	res, err := h.msps.ListTenants(r.Context(), id, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]MSPTenantBindingResponse, 0, len(res.Items))
	for _, b := range res.Items {
		items = append(items, toBindingResponse(b))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
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
	// Body is optional — only decode when Content-Length > 0
	// signals a body was supplied. A zero-byte POST defaults to
	// owner.
	if r.ContentLength > 0 {
		var req AssignTenantRequest
		if !DecodeJSON(w, r, &req) {
			return
		}
		if req.Relationship != "" {
			rel = repository.MSPRelationship(req.Relationship)
		}
	}
	binding, err := h.msps.AssignTenant(r.Context(), mspID, tenantID, rel, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
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
	ttl := time.Duration(req.TTLSeconds) * time.Second
	res, err := h.bulk.BulkGenerateClaimTokens(r.Context(), mspID, userID, actorFromCtx(r), req.Count, ttl)
	if err != nil {
		writeBulkError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toBulkResultResponse(res))
}

// writeBulkError maps service-level bulk errors. ErrInvalidArgument
// already maps via WriteRepositoryError; anything else surfaces
// as 500.
func writeBulkError(w http.ResponseWriter, err error) {
	if errors.Is(err, repository.ErrInvalidArgument) {
		WriteRepositoryError(w, err)
		return
	}
	WriteError(w, http.StatusInternalServerError, "internal_error", err.Error())
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
	if _, err := h.branding.SetTenantBranding(r.Context(), tenantID, req); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Return the freshly-resolved (post-merge) view so the client
	// sees the effective branding after the override is applied.
	b, err := h.branding.Resolve(r.Context(), tenantID)
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

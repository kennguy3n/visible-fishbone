package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// SCIMHandler implements the SCIM 2.0 REST endpoints.
type SCIMHandler struct {
	scim *identity.SCIMService
}

// NewSCIMHandler returns a ready-to-use SCIM handler.
func NewSCIMHandler(scim *identity.SCIMService) *SCIMHandler {
	return &SCIMHandler{scim: scim}
}

// Register attaches SCIM routes. The SCIM bearer token carries a
// tenant binding so tenant_id is resolved from the auth context
// (not a path param). All SCIM routes require authentication.
func (h *SCIMHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /scim/v2/Users", h.createUser)
	mux.HandleFunc("GET /scim/v2/Users/{id}", h.getUser)
	mux.HandleFunc("GET /scim/v2/Users", h.listUsers)
	mux.HandleFunc("PUT /scim/v2/Users/{id}", h.updateUser)
	mux.HandleFunc("PATCH /scim/v2/Users/{id}", h.patchUser)
	mux.HandleFunc("DELETE /scim/v2/Users/{id}", h.deleteUser)

	mux.HandleFunc("POST /scim/v2/Groups", h.createGroup)
	mux.HandleFunc("GET /scim/v2/Groups/{id}", h.getGroup)
	mux.HandleFunc("GET /scim/v2/Groups", h.listGroups)
	mux.HandleFunc("PUT /scim/v2/Groups/{id}", h.updateGroup)
	mux.HandleFunc("PATCH /scim/v2/Groups/{id}", h.patchGroup)
	mux.HandleFunc("DELETE /scim/v2/Groups/{id}", h.deleteGroup)

	mux.HandleFunc("POST /scim/v2/Bulk", h.bulk)

	mux.HandleFunc("GET /scim/v2/ServiceProviderConfig", h.serviceProviderConfig)
	mux.HandleFunc("GET /scim/v2/Schemas", h.schemas)
	mux.HandleFunc("GET /scim/v2/ResourceTypes", h.resourceTypes)
}

func (h *SCIMHandler) tenantFromCtx(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	tid := middleware.TenantIDFromContext(r.Context())
	if tid == uuid.Nil {
		writeSCIMError(w, http.StatusUnauthorized, "missing tenant binding in SCIM bearer token")
		return uuid.Nil, false
	}
	return tid, true
}

// --- User endpoints -------------------------------------------------------

func (h *SCIMHandler) createUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	var su identity.SCIMUser
	if !decodeSCIM(w, r, &su) {
		return
	}
	result, err := h.scim.CreateUser(r.Context(), tid, su)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusCreated, result)
}

func (h *SCIMHandler) getUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	result, err := h.scim.GetUser(r.Context(), tid, id)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusOK, result)
}

func (h *SCIMHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	filter := r.URL.Query().Get("filter")
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	result, err := h.scim.ListUsers(r.Context(), tid, filter, startIndex, count)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMList(w, r, result)
}

func (h *SCIMHandler) updateUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	var su identity.SCIMUser
	if !decodeSCIM(w, r, &su) {
		return
	}
	if !h.checkIfMatch(w, r, func() (any, error) { return h.scim.GetUser(r.Context(), tid, id) }) {
		return
	}
	result, err := h.scim.UpdateUser(r.Context(), tid, id, su)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusOK, result)
}

func (h *SCIMHandler) patchUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	var patch identity.SCIMPatchRequest
	if !decodeSCIM(w, r, &patch) {
		return
	}
	if !h.checkIfMatch(w, r, func() (any, error) { return h.scim.GetUser(r.Context(), tid, id) }) {
		return
	}
	result, err := h.scim.PatchUser(r.Context(), tid, id, patch.Operations)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusOK, result)
}

func (h *SCIMHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.scim.DeleteUser(r.Context(), tid, id); err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Group endpoints ------------------------------------------------------

func (h *SCIMHandler) createGroup(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	var sg identity.SCIMGroup
	if !decodeSCIM(w, r, &sg) {
		return
	}
	result, err := h.scim.CreateGroup(r.Context(), tid, sg)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusCreated, result)
}

func (h *SCIMHandler) getGroup(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	result, err := h.scim.GetGroup(r.Context(), tid, id)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusOK, result)
}

func (h *SCIMHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	filter := r.URL.Query().Get("filter")
	startIndex, _ := strconv.Atoi(r.URL.Query().Get("startIndex"))
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	result, err := h.scim.ListGroups(r.Context(), tid, filter, startIndex, count)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMList(w, r, result)
}

func (h *SCIMHandler) updateGroup(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	var sg identity.SCIMGroup
	if !decodeSCIM(w, r, &sg) {
		return
	}
	if !h.checkIfMatch(w, r, func() (any, error) { return h.scim.GetGroup(r.Context(), tid, id) }) {
		return
	}
	result, err := h.scim.UpdateGroup(r.Context(), tid, id, sg)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusOK, result)
}

func (h *SCIMHandler) patchGroup(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	var patch identity.SCIMPatchRequest
	if !decodeSCIM(w, r, &patch) {
		return
	}
	if !h.checkIfMatch(w, r, func() (any, error) { return h.scim.GetGroup(r.Context(), tid, id) }) {
		return
	}
	result, err := h.scim.PatchGroup(r.Context(), tid, id, patch.Operations)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMResource(w, r, http.StatusOK, result)
}

func (h *SCIMHandler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	id, ok := scimPathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.scim.DeleteGroup(r.Context(), tid, id); err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Bulk endpoint --------------------------------------------------------

func (h *SCIMHandler) bulk(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenantFromCtx(w, r)
	if !ok {
		return
	}
	// Bound the decoded payload so a single bulk request cannot pin
	// unbounded memory (RFC 7644 §3.7.4 maxPayloadSize).
	r.Body = http.MaxBytesReader(w, r.Body, identity.SCIMBulkMaxPayloadBytes)
	var req identity.SCIMBulkRequest
	if !decodeSCIM(w, r, &req) {
		return
	}
	result, err := h.scim.Bulk(r.Context(), tid, req)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, result)
}

// --- Discovery endpoints --------------------------------------------------

func (h *SCIMHandler) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	config := map[string]any{
		"schemas":          []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://docs.shieldnet.io/scim",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": true, "maxOperations": identity.SCIMBulkMaxOperations, "maxPayloadSize": identity.SCIMBulkMaxPayloadBytes},
		"filter":           map[string]any{"supported": true, "maxResults": repository.MaxPageLimit},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": true},
		"authenticationSchemes": []map[string]any{
			{
				"type":        "oauthbearertoken",
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token Standard",
			},
		},
	}
	writeSCIMJSON(w, http.StatusOK, config)
}

func (h *SCIMHandler) schemas(w http.ResponseWriter, _ *http.Request) {
	schemas := identity.SCIMListResponse{
		Schemas:      []string{identity.SCIMSchemaList},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources: []any{
			map[string]any{
				"id":          identity.SCIMSchemaUser,
				"name":        "User",
				"description": "User Account",
			},
			map[string]any{
				"id":          identity.SCIMSchemaGroup,
				"name":        "Group",
				"description": "Group",
			},
		},
	}
	writeSCIMJSON(w, http.StatusOK, schemas)
}

func (h *SCIMHandler) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	types := identity.SCIMListResponse{
		Schemas:      []string{identity.SCIMSchemaList},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources: []any{
			map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "User",
				"name":     "User",
				"endpoint": "/scim/v2/Users",
				"schema":   identity.SCIMSchemaUser,
			},
			map[string]any{
				"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":       "Group",
				"name":     "Group",
				"endpoint": "/scim/v2/Groups",
				"schema":   identity.SCIMSchemaGroup,
			},
		},
	}
	writeSCIMJSON(w, http.StatusOK, types)
}

// --- SCIM-specific helpers ------------------------------------------------

// writeSCIMResource encodes a single SCIM resource, first applying the
// attributes / excludedAttributes projection, setting the ETag response
// header from meta.version, and honouring an If-None-Match precondition
// (returns 304 Not Modified on a match for a GET).
func writeSCIMResource(w http.ResponseWriter, r *http.Request, status int, resource any) {
	version := identity.ResourceVersion(resource)
	if version != "" {
		w.Header().Set("ETag", version)
		if r.Method == http.MethodGet {
			if inm := r.Header.Get("If-None-Match"); inm != "" && identity.ETagMatches(inm, version) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	attrs, excluded := scimAttrParams(r)
	body := identity.ProjectResource(resource, attrs, excluded)
	writeSCIMJSON(w, status, body)
}

// writeSCIMList encodes a SCIM list response, applying the attributes /
// excludedAttributes projection to every returned resource.
func writeSCIMList(w http.ResponseWriter, r *http.Request, list identity.SCIMListResponse) {
	attrs, excluded := scimAttrParams(r)
	if len(attrs) > 0 || len(excluded) > 0 {
		projected := make([]any, 0, len(list.Resources))
		for _, res := range list.Resources {
			projected = append(projected, identity.ProjectResource(res, attrs, excluded))
		}
		list.Resources = projected
	}
	writeSCIMJSON(w, http.StatusOK, list)
}

// scimAttrParams reads the attributes / excludedAttributes query
// parameters (RFC 7644 §3.9).
func scimAttrParams(r *http.Request) (attributes, excluded []string) {
	return identity.ParseAttributeList(r.URL.Query().Get("attributes")),
		identity.ParseAttributeList(r.URL.Query().Get("excludedAttributes"))
}

// checkIfMatch enforces an If-Match precondition on a mutating request
// (RFC 7644 §3.14). When the header is present it loads the current
// resource and compares versions, writing 412 Precondition Failed on a
// mismatch and 404 if the resource is gone. Returns true when the
// caller may proceed (no header, or the version matched).
func (h *SCIMHandler) checkIfMatch(w http.ResponseWriter, r *http.Request, load func() (any, error)) bool {
	ifMatch := r.Header.Get("If-Match")
	if ifMatch == "" {
		return true
	}
	current, err := load()
	if err != nil {
		writeSCIMRepoError(w, err)
		return false
	}
	if !identity.ETagMatches(ifMatch, identity.ResourceVersion(current)) {
		writeSCIMError(w, http.StatusPreconditionFailed, "resource version does not match If-Match precondition")
		return false
	}
	return true
}

func writeSCIMJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	_ = json.NewEncoder(w).Encode(body)
}

func writeSCIMError(w http.ResponseWriter, status int, detail string) {
	writeSCIMJSON(w, status, identity.SCIMError{
		Schemas: []string{identity.SCIMSchemaError},
		Status:  strconv.Itoa(status),
		Detail:  detail,
	})
}

func writeSCIMRepoError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		writeSCIMError(w, http.StatusNotFound, "resource not found")
	case errors.Is(err, repository.ErrConflict):
		writeSCIMError(w, http.StatusConflict, "uniqueness constraint violated")
	case errors.Is(err, repository.ErrForbidden):
		writeSCIMError(w, http.StatusForbidden, "operation not permitted")
	case errors.Is(err, repository.ErrInvalidArgument):
		writeSCIMError(w, http.StatusBadRequest, err.Error())
	default:
		writeSCIMError(w, http.StatusInternalServerError, "internal server error")
	}
}

func decodeSCIM(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeSCIMError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func scimPathUUID(w http.ResponseWriter, r *http.Request, name string) (uuid.UUID, bool) {
	raw := r.PathValue(name)
	if raw == "" {
		writeSCIMError(w, http.StatusBadRequest, name+" is required")
		return uuid.Nil, false
	}
	u, err := uuid.Parse(raw)
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, name+" is not a valid UUID")
		return uuid.Nil, false
	}
	return u, true
}

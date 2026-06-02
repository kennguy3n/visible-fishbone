package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
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
	writeSCIMJSON(w, http.StatusCreated, result)
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
	writeSCIMJSON(w, http.StatusOK, result)
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
	writeSCIMJSON(w, http.StatusOK, result)
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
	result, err := h.scim.UpdateUser(r.Context(), tid, id, su)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, result)
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
	result, err := h.scim.PatchUser(r.Context(), tid, id, patch.Operations)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, result)
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
	writeSCIMJSON(w, http.StatusCreated, result)
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
	writeSCIMJSON(w, http.StatusOK, result)
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
	writeSCIMJSON(w, http.StatusOK, result)
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
	result, err := h.scim.UpdateGroup(r.Context(), tid, id, sg)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, result)
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
	result, err := h.scim.PatchGroup(r.Context(), tid, id, patch.Operations)
	if err != nil {
		writeSCIMRepoError(w, err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, result)
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

// --- Discovery endpoints --------------------------------------------------

func (h *SCIMHandler) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	config := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"documentationUri": "https://docs.shieldnet.io/scim",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
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
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":          "User",
				"name":        "User",
				"endpoint":    "/scim/v2/Users",
				"schema":      identity.SCIMSchemaUser,
			},
			map[string]any{
				"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
				"id":          "Group",
				"name":        "Group",
				"endpoint":    "/scim/v2/Groups",
				"schema":      identity.SCIMSchemaGroup,
			},
		},
	}
	writeSCIMJSON(w, http.StatusOK, types)
}

// --- SCIM-specific helpers ------------------------------------------------

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
	WriteRepositoryError(w, err)
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

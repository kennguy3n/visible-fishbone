package handler

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/rbac"
)

// RBACHandler exposes the role/permission endpoints.
type RBACHandler struct {
	svc *rbac.Service
}

// NewRBACHandler wires the handler.
func NewRBACHandler(svc *rbac.Service) *RBACHandler {
	return &RBACHandler{svc: svc}
}

// Register attaches routes.
func (h *RBACHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/roles", h.listRoles)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/roles", h.createRole)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/users/{user_id}/roles", h.assignRole)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/users/{user_id}/roles/{role_id}", h.revokeRole)
}

// RoleResponse is the JSON projection of repository.Role.
type RoleResponse struct {
	ID          string   `json:"id"`
	TenantID    *string  `json:"tenant_id,omitempty"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	Scope       string   `json:"scope"`
}

func toRoleResponse(r repository.Role) RoleResponse {
	resp := RoleResponse{
		ID: r.ID.String(), Name: r.Name, Scope: string(r.Scope),
		Permissions: r.Permissions,
	}
	if r.TenantID != nil {
		s := r.TenantID.String()
		resp.TenantID = &s
	}
	if resp.Permissions == nil {
		resp.Permissions = []string{}
	}
	return resp
}

func (h *RBACHandler) listRoles(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	roles, err := h.svc.ListRoles(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := make([]RoleResponse, 0, len(roles))
	for _, role := range roles {
		out = append(out, toRoleResponse(role))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// RoleCreateRequest is the JSON body for POST /roles.
type RoleCreateRequest struct {
	Name        string   `json:"name"`
	Scope       string   `json:"scope"`
	Permissions []string `json:"permissions"`
}

func (h *RBACHandler) createRole(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req RoleCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	role, err := h.svc.CreateCustomRole(r.Context(), tenantID, actorFromCtx(r), req.Name, repository.RoleScope(req.Scope), req.Permissions)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toRoleResponse(role))
}

// RoleAssignRequest is the JSON body for POST /users/{user_id}/roles.
type RoleAssignRequest struct {
	RoleID  string  `json:"role_id"`
	ScopeID *string `json:"scope_id,omitempty"`
}

func (h *RBACHandler) assignRole(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	userID, ok := PathUUID(w, r, "user_id")
	if !ok {
		return
	}
	var req RoleAssignRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_role_id", "role_id must be a UUID")
		return
	}
	var scopePtr *uuid.UUID
	if req.ScopeID != nil && *req.ScopeID != "" {
		s, err := uuid.Parse(*req.ScopeID)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_scope_id", "scope_id must be a UUID")
			return
		}
		scopePtr = &s
	}
	if err := h.svc.AssignRole(r.Context(), tenantID, userID, roleID, scopePtr, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *RBACHandler) revokeRole(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	userID, ok := PathUUID(w, r, "user_id")
	if !ok {
		return
	}
	roleID, ok := PathUUID(w, r, "role_id")
	if !ok {
		return
	}
	var scopePtr *uuid.UUID
	if sid := r.URL.Query().Get("scope_id"); sid != "" {
		u, err := uuid.Parse(sid)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_scope_id", "scope_id must be a UUID")
			return
		}
		scopePtr = &u
	}
	if err := h.svc.RevokeRole(r.Context(), tenantID, userID, roleID, scopePtr, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

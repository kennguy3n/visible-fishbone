package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/apikey"
)

// APIKeyHandler exposes the tenant API-key CRUD endpoints.
//
// Routes are mounted under /api/v1/tenants/{tenant_id}/api-keys so
// the tenant-scope middleware applies — only an operator with a
// JWT or another API key for the same tenant can manage that
// tenant's keys.
type APIKeyHandler struct {
	svc *apikey.Service
}

// NewAPIKeyHandler wires the handler.
func NewAPIKeyHandler(svc *apikey.Service) *APIKeyHandler {
	return &APIKeyHandler{svc: svc}
}

// Register attaches routes.
func (h *APIKeyHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/api-keys", h.create)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/api-keys", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/api-keys/{id}", h.get)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/api-keys/{id}", h.revoke)
}

// APIKeyCreateRequest is the JSON body for POST.
//
// `expires_at` is RFC3339; omit it for a non-expiring key. We
// deliberately don't accept ttl-as-seconds — the absolute deadline
// is what gets persisted and an operator who wants "30 days" is
// expected to compute the RFC3339 timestamp client-side rather
// than rely on server-clock-relative TTL math.
type APIKeyCreateRequest struct {
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// APIKeyResponse is the JSON projection of repository.TenantAPIKey.
// Plaintext is included exactly on the Create response and never
// on Get / List.
type APIKeyResponse struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	Name       string `json:"name"`
	Subject    string `json:"subject"`
	Status     string `json:"status"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	LastUsedAt string `json:"last_used_at,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	CreatedAt  string `json:"created_at"`
	RevokedAt  string `json:"revoked_at,omitempty"`
	Plaintext  string `json:"plaintext,omitempty"`
}

func toAPIKeyResponse(k repository.TenantAPIKey, plaintext string) APIKeyResponse {
	resp := APIKeyResponse{
		ID:        k.ID.String(),
		TenantID:  k.TenantID.String(),
		Name:      k.Name,
		Subject:   k.Subject,
		Status:    string(k.Status),
		CreatedAt: k.CreatedAt.Format(time.RFC3339Nano),
		Plaintext: plaintext,
	}
	if k.ExpiresAt != nil {
		resp.ExpiresAt = k.ExpiresAt.Format(time.RFC3339Nano)
	}
	if k.LastUsedAt != nil {
		resp.LastUsedAt = k.LastUsedAt.Format(time.RFC3339Nano)
	}
	if k.CreatedBy != nil {
		resp.CreatedBy = k.CreatedBy.String()
	}
	if k.RevokedAt != nil {
		resp.RevokedAt = k.RevokedAt.Format(time.RFC3339Nano)
	}
	return resp
}

func (h *APIKeyHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req APIKeyCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	in := apikey.CreateInput{
		Name:    req.Name,
		Subject: req.Subject,
	}
	if req.ExpiresAt != "" {
		// time.RFC3339Nano accepts both fractional and non-fractional
		// RFC3339 timestamps — the `.999999999` is an optional
		// fractional indicator in Go's format syntax, so a plain
		// `2026-01-01T00:00:00Z` parses fine.
		t, err := time.Parse(time.RFC3339Nano, req.ExpiresAt)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be RFC3339")
			return
		}
		in.ExpiresAt = &t
	}
	res, err := h.svc.Create(r.Context(), tenantID, actorFromCtx(r), in)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toAPIKeyResponse(res.Record, res.Plaintext))
}

func (h *APIKeyHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	keys, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]APIKeyResponse, 0, len(keys))
	for _, k := range keys {
		items = append(items, toAPIKeyResponse(k, ""))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *APIKeyHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	k, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAPIKeyResponse(k, ""))
}

func (h *APIKeyHandler) revoke(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if _, err := h.svc.Revoke(r.Context(), tenantID, id, actorFromCtx(r)); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "api key not found")
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
)

// AuditHandler exposes the (read-only) audit-log endpoint.
type AuditHandler struct {
	svc *audit.Service
}

// NewAuditHandler wires the handler.
func NewAuditHandler(svc *audit.Service) *AuditHandler {
	return &AuditHandler{svc: svc}
}

// Register attaches routes.
func (h *AuditHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/audit-log", h.list)
}

// AuditEntryResponse is the JSON projection of repository.AuditEntry.
type AuditEntryResponse struct {
	ID           string          `json:"id"`
	TenantID     string          `json:"tenant_id"`
	ActorID      *string         `json:"actor_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	CreatedAt    string          `json:"created_at"`
}

func toAuditResponse(e repository.AuditEntry) AuditEntryResponse {
	resp := AuditEntryResponse{
		ID: e.ID.String(), TenantID: e.TenantID.String(),
		Action: e.Action, ResourceType: e.ResourceType,
		Details:   e.Details,
		CreatedAt: e.CreatedAt.Format(time.RFC3339Nano),
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

func (h *AuditHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := audit.ListFilter{
		ResourceType: q.Get("resource_type"),
		Action:       q.Get("action"),
	}
	if a := q.Get("actor_id"); a != "" {
		u, err := uuid.Parse(a)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "actor_id must be a UUID")
			return
		}
		filter.ActorID = &u
	}
	if f := q.Get("from"); f != "" {
		t, err := time.Parse(time.RFC3339Nano, f)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "from must be RFC3339")
			return
		}
		filter.From = &t
	}
	if to := q.Get("to"); to != "" {
		t, err := time.Parse(time.RFC3339Nano, to)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "to must be RFC3339")
			return
		}
		filter.To = &t
	}
	page := repository.Page{
		After: q.Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(q.Get("order")),
	}
	res, err := h.svc.List(r.Context(), tenantID, filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]AuditEntryResponse, 0, len(res.Items))
	for _, e := range res.Items {
		items = append(items, toAuditResponse(e))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/rbi"
)

// RBIHandler exposes the Remote Browser Isolation REST surface:
// session creation (called by the SWG when a URL triggers RBI),
// session lookup/listing for the operator console, session close,
// and a policy/config probe.
type RBIHandler struct {
	svc *rbi.Service
}

// NewRBIHandler wires the handler.
func NewRBIHandler(svc *rbi.Service) *RBIHandler {
	return &RBIHandler{svc: svc}
}

// Register attaches routes.
func (h *RBIHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/rbi/sessions", h.listSessions)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/rbi/sessions", h.createSession)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/rbi/sessions/{id}", h.getSession)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/rbi/sessions/{id}", h.closeSession)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/rbi/policy", h.getPolicy)
}

type rbiCreateRequest struct {
	TargetURL string `json:"target_url"`
	// UserID is optional; the SWG passes the authenticated user so
	// the session is attributable. Empty / omitted is allowed.
	UserID string `json:"user_id,omitempty"`
}

type rbiSessionResponse struct {
	ID        string `json:"id"`
	TargetURL string `json:"target_url"`
	Status    string `json:"status"`
	ProxyURL  string `json:"proxy_url,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

func toRBISessionResponse(s rbi.Session) rbiSessionResponse {
	out := rbiSessionResponse{
		ID:        s.ID.String(),
		TargetURL: s.TargetURL,
		Status:    s.Status,
		ProxyURL:  s.ProxyURL,
		ExpiresAt: s.ExpiresAt.Format(time.RFC3339),
		CreatedAt: s.CreatedAt.Format(time.RFC3339),
	}
	if s.UserID != uuid.Nil {
		out.UserID = s.UserID.String()
	}
	return out
}

func (h *RBIHandler) listSessions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	sessions, err := h.svc.ListSessions(r.Context(), tenantID, QueryLimit(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]rbiSessionResponse, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, toRBISessionResponse(s))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *RBIHandler) createSession(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req rbiCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	input := rbi.CreateSessionInput{TargetURL: req.TargetURL}
	if req.UserID != "" {
		uid, err := uuid.Parse(req.UserID)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_body", "user_id is not a valid UUID")
			return
		}
		input.UserID = uid
	}
	sess, err := h.svc.CreateSession(r.Context(), tenantID, input, actorFromCtx(r))
	if err != nil {
		if errors.Is(err, rbi.ErrNotConfigured) {
			WriteError(w, http.StatusServiceUnavailable, "rbi_not_configured", "RBI proxy is not configured")
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toRBISessionResponse(sess))
}

func (h *RBIHandler) getSession(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	sess, err := h.svc.GetSession(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRBISessionResponse(sess))
}

func (h *RBIHandler) closeSession(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.CloseSession(r.Context(), tenantID, id, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusNoContent, nil)
}

func (h *RBIHandler) getPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := PathUUID(w, r, "tenant_id"); !ok {
		return
	}
	pc := h.svc.PolicyConfig()
	WriteJSON(w, http.StatusOK, map[string]any{
		"configured":            h.svc.ProxyConfigured(),
		"categories":            pc.Categories,
		"risk_score_threshold":  pc.RiskScoreThreshold,
		"isolate_uncategorised": pc.IsolateUncategorised,
	})
}

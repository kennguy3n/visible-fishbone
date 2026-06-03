package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
)

// TroubleshootHandler exposes the troubleshooting REST surface.
type TroubleshootHandler struct {
	sessions   *troubleshoot.SessionService
	kb         *troubleshoot.KBService
	diagnostic *troubleshoot.DiagnosticEngine
}

// NewTroubleshootHandler wires dependencies.
func NewTroubleshootHandler(
	sessions *troubleshoot.SessionService,
	kb *troubleshoot.KBService,
	diagnostic *troubleshoot.DiagnosticEngine,
) *TroubleshootHandler {
	return &TroubleshootHandler{
		sessions:   sessions,
		kb:         kb,
		diagnostic: diagnostic,
	}
}

// Register attaches routes.
func (h *TroubleshootHandler) Register(mux *http.ServeMux) {
	// Session endpoints
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/troubleshoot/sessions", h.startSession)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/troubleshoot/sessions/{id}/messages", h.sendMessage)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/troubleshoot/sessions/{id}", h.getSession)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/troubleshoot/sessions/{id}/resolve", h.resolveSession)

	// Diagnostic endpoints
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/troubleshoot/diagnostics/run", h.runDiagnostics)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/troubleshoot/diagnostics/{check}", h.runSingleDiagnostic)

	// KB endpoints
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/troubleshoot/kb", h.listKB)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/troubleshoot/kb", h.createKB)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/troubleshoot/kb/{id}", h.getKB)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/troubleshoot/kb/{id}", h.updateKB)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/troubleshoot/kb/{id}", h.deleteKB)
}

// --- Session handlers ---

type startSessionRequest struct {
	Issue string `json:"issue"`
}

type sessionResponse struct {
	ID                uuid.UUID                  `json:"id"`
	TenantID          uuid.UUID                  `json:"tenant_id"`
	OperatorID        uuid.UUID                  `json:"operator_id"`
	Issue             string                     `json:"issue"`
	Status            string                     `json:"status"`
	Messages          []sessionMessageResponse   `json:"messages"`
	DiagnosticResults []diagnosticResultResponse `json:"diagnostic_results"`
	CreatedAt         string                     `json:"created_at"`
	UpdatedAt         string                     `json:"updated_at"`
}

type sessionMessageResponse struct {
	Role        string `json:"role"`
	Content     string `json:"content"`
	Timestamp   string `json:"timestamp"`
	AIGenerated bool   `json:"ai_generated"`
}

type diagnosticResultResponse struct {
	CheckName  string          `json:"check_name"`
	Status     string          `json:"status"`
	Message    string          `json:"message"`
	Details    json.RawMessage `json:"details,omitempty"`
	ExecutedAt string          `json:"executed_at"`
}

func toSessionResponse(s troubleshoot.TroubleshootSession) sessionResponse {
	msgs := make([]sessionMessageResponse, len(s.Messages))
	for i, m := range s.Messages {
		msgs[i] = sessionMessageResponse{
			Role:        m.Role,
			Content:     m.Content,
			Timestamp:   m.Timestamp.Format(time.RFC3339),
			AIGenerated: m.AIGenerated,
		}
	}
	diags := make([]diagnosticResultResponse, len(s.DiagnosticResults))
	for i, d := range s.DiagnosticResults {
		diags[i] = diagnosticResultResponse{
			CheckName:  d.CheckName,
			Status:     string(d.Status),
			Message:    d.Message,
			Details:    d.Details,
			ExecutedAt: d.ExecutedAt.Format(time.RFC3339),
		}
	}
	return sessionResponse{
		ID:                s.ID,
		TenantID:          s.TenantID,
		OperatorID:        s.OperatorID,
		Issue:             s.Issue,
		Status:            string(s.Status),
		Messages:          msgs,
		DiagnosticResults: diags,
		CreatedAt:         s.CreatedAt.Format(time.RFC3339),
		UpdatedAt:         s.UpdatedAt.Format(time.RFC3339),
	}
}

func (h *TroubleshootHandler) startSession(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req startSessionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Issue == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "issue is required")
		return
	}

	operatorID := uuid.Nil
	if actor := actorFromCtx(r); actor != nil {
		operatorID = *actor
	}

	sess, err := h.sessions.StartSession(r.Context(), tenantID, operatorID, req.Issue)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toSessionResponse(sess))
}

type sendMessageRequest struct {
	Content string `json:"content"`
}

func (h *TroubleshootHandler) sendMessage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	sessionID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req sendMessageRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Content == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "content is required")
		return
	}

	sess, err := h.sessions.SendMessage(r.Context(), tenantID, sessionID, req.Content)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSessionResponse(sess))
}

func (h *TroubleshootHandler) getSession(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	sessionID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	sess, err := h.sessions.GetSession(r.Context(), tenantID, sessionID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSessionResponse(sess))
}

func (h *TroubleshootHandler) resolveSession(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	sessionID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	sess, err := h.sessions.ResolveSession(r.Context(), tenantID, sessionID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSessionResponse(sess))
}

// --- Diagnostic handlers ---

func (h *TroubleshootHandler) runDiagnostics(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}

	results := h.diagnostic.RunAll(r.Context(), tenantID)
	resp := make([]diagnosticResultResponse, len(results))
	for i, d := range results {
		resp[i] = diagnosticResultResponse{
			CheckName:  d.CheckName,
			Status:     string(d.Status),
			Message:    d.Message,
			Details:    d.Details,
			ExecutedAt: d.ExecutedAt.Format(time.RFC3339),
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"results": resp})
}

func (h *TroubleshootHandler) runSingleDiagnostic(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	checkName := r.PathValue("check")
	if checkName == "" {
		WriteError(w, http.StatusBadRequest, "missing_param", "check name is required")
		return
	}

	result, err := h.diagnostic.RunCheck(r.Context(), tenantID, checkName)
	if err != nil {
		WriteError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, diagnosticResultResponse{
		CheckName:  result.CheckName,
		Status:     string(result.Status),
		Message:    result.Message,
		Details:    result.Details,
		ExecutedAt: result.ExecutedAt.Format(time.RFC3339),
	})
}

// --- KB handlers ---

type kbEntryRequest struct {
	Category string   `json:"category"`
	Title    string   `json:"title"`
	Content  string   `json:"content"`
	Tags     []string `json:"tags,omitempty"`
}

type kbEntryResponse struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Category  string     `json:"category"`
	Title     string     `json:"title"`
	Content   string     `json:"content"`
	Tags      []string   `json:"tags"`
	CreatedAt string     `json:"created_at"`
	UpdatedAt string     `json:"updated_at"`
}

func toKBEntryResponse(e troubleshoot.KBEntry) kbEntryResponse {
	return kbEntryResponse{
		ID:        e.ID,
		TenantID:  e.TenantID,
		Category:  string(e.Category),
		Title:     e.Title,
		Content:   e.Content,
		Tags:      e.Tags,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
		UpdatedAt: e.UpdatedAt.Format(time.RFC3339),
	}
}

func (h *TroubleshootHandler) listKB(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}

	var category *string
	if c := r.URL.Query().Get("category"); c != "" {
		category = &c
	}

	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
	}

	result, err := h.kb.List(r.Context(), &tenantID, category, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}

	items := make([]kbEntryResponse, len(result.Items))
	for i, e := range result.Items {
		items[i] = toKBEntryResponse(e)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *TroubleshootHandler) createKB(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req kbEntryRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	entry, err := h.kb.Create(r.Context(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategory(req.Category),
		Title:    req.Title,
		Content:  req.Content,
		Tags:     req.Tags,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toKBEntryResponse(entry))
}

func (h *TroubleshootHandler) getKB(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	entry, err := h.kb.Get(r.Context(), &tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toKBEntryResponse(entry))
}

func (h *TroubleshootHandler) updateKB(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req kbEntryRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	cat := repository.KBCategory(req.Category)
	patch := repository.KBEntryPatch{}
	if req.Category != "" {
		patch.Category = &cat
	}
	if req.Title != "" {
		patch.Title = &req.Title
	}
	if req.Content != "" {
		patch.Content = &req.Content
	}
	if req.Tags != nil {
		patch.Tags = &req.Tags
	}

	entry, err := h.kb.Update(r.Context(), &tenantID, id, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toKBEntryResponse(entry))
}

func (h *TroubleshootHandler) deleteKB(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	if err := h.kb.Delete(r.Context(), &tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

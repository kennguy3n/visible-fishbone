package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// AIHandler exposes the AI assistant REST surface.
// When the AI service is nil or not configured, all endpoints
// return 503 (matching the PolicySimulationHandler pattern).
type AIHandler struct {
	svc    *ai.Service
	logger *slog.Logger
}

// NewAIHandler constructs an AIHandler. svc may be nil (endpoints
// return 503).
func NewAIHandler(svc *ai.Service, logger *slog.Logger) *AIHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AIHandler{svc: svc, logger: logger}
}

// Register wires AI endpoints onto mux.
func (h *AIHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/summarize", h.summarize)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/suggest-policy", h.suggestPolicy)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/troubleshoot", h.troubleshoot)
}

func (h *AIHandler) summarize(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.SummarizerConfigured() {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Start string `json:"start"`
		End   string `json:"end"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	tr, err := parseTimeRange(req.Start, req.End)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_time_range", err.Error())
		return
	}
	summary, err := h.svc.Summarize(r.Context(), tenantID, tr)
	if err != nil {
		h.logger.Error("ai: summarize failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "summarization failed")
		return
	}
	WriteJSON(w, http.StatusOK, summary)
}

func (h *AIHandler) suggestPolicy(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Configured() {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Prompt string `json:"prompt"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Prompt == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "prompt is required")
		return
	}
	var actorID *uuid.UUID
	if uid := middleware.UserIDFromContext(r.Context()); uid != uuid.Nil {
		actorID = &uid
	}
	verified, err := h.svc.SuggestPolicy(r.Context(), tenantID, actorID, req.Prompt)
	if err != nil {
		h.logger.Error("ai: suggest-policy failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "policy suggestion failed")
		return
	}
	WriteJSON(w, http.StatusOK, verified)
}

func (h *AIHandler) troubleshoot(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil || !h.svc.Configured() {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Query string `json:"query"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Query == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "query is required")
		return
	}
	result, err := h.svc.Troubleshoot(r.Context(), tenantID, req.Query)
	if err != nil {
		h.logger.Error("ai: troubleshoot failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "troubleshooting failed")
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func parseTimeRange(start, end string) (ai.TimeRange, error) {
	var tr ai.TimeRange
	var err error
	if start != "" {
		tr.Start, err = time.Parse(time.RFC3339, start)
		if err != nil {
			return tr, fmt.Errorf("invalid start time: %w", err)
		}
	}
	if end != "" {
		tr.End, err = time.Parse(time.RFC3339, end)
		if err != nil {
			return tr, fmt.Errorf("invalid end time: %w", err)
		}
	}
	if tr.End.IsZero() {
		tr.End = time.Now().UTC()
	}
	if tr.Start.IsZero() {
		tr.Start = tr.End.Add(-24 * time.Hour)
	}
	if !tr.Start.Before(tr.End) {
		return tr, fmt.Errorf("start must be before end")
	}
	return tr, nil
}

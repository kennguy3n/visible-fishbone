package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// AIHandler exposes the AI assistant REST surface.
// When the AI service is nil or not configured, all endpoints
// return 503 (matching the PolicySimulationHandler pattern).
type AIHandler struct {
	svc    *ai.Service
	logger *slog.Logger

	// Enhanced AI capabilities (Tasks 67-71).
	correlation     *ai.CorrelationEngine
	nlQuery         *ai.NLQueryEngine
	reports         *ai.ReportEngine
	threatIntel     *ai.ThreatIntelEngine
	guardrails      *ai.GuardrailedProvider
	correlationRepo repository.AICorrelationRepository
	postureData     PostureDataSource

	// AI policy-tightening suggestions (Tasks 55-60).
	reviewSvc     *ai.ReviewService
	tighteningSvc *ai.TighteningService
}

// PostureDataSource supplies real per-tenant alert counts for a
// reporting period. It backs the read-only GET posture report so the
// response reflects actual alert volume rather than an empty (and
// therefore misleadingly "healthy") baseline. The POST .../generate
// endpoint continues to accept caller-supplied data and does not
// depend on this source.
type PostureDataSource interface {
	AlertCountsBySeverity(ctx context.Context, tenantID uuid.UUID, start, end time.Time) (map[string]int, error)
}

// NewAIHandler constructs an AIHandler. svc may be nil (endpoints
// return 503).
func NewAIHandler(svc *ai.Service, logger *slog.Logger) *AIHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AIHandler{svc: svc, logger: logger}
}

// SetEnhancedAI wires up the enhanced AI capabilities (Tasks 67-71)
// after construction. This pattern matches Service.SetSummarizer.
func (h *AIHandler) SetEnhancedAI(
	correlation *ai.CorrelationEngine,
	nlQuery *ai.NLQueryEngine,
	reports *ai.ReportEngine,
	threatIntel *ai.ThreatIntelEngine,
	guardrails *ai.GuardrailedProvider,
	correlationRepo repository.AICorrelationRepository,
) {
	h.correlation = correlation
	h.nlQuery = nlQuery
	h.reports = reports
	h.threatIntel = threatIntel
	h.guardrails = guardrails
	h.correlationRepo = correlationRepo
}

// SetPostureDataSource wires the optional real-alert data source used
// by the read-only GET posture report. When unset, GET returns 503
// (callers can still POST .../generate with explicit data). Kept as a
// separate setter so the source can be wired independently of the
// other enhanced-AI dependencies.
func (h *AIHandler) SetPostureDataSource(src PostureDataSource) {
	h.postureData = src
}

// SetReviewService attaches the suggestion review service.
func (h *AIHandler) SetReviewService(svc *ai.ReviewService) { h.reviewSvc = svc }

// SetTighteningService attaches the policy tightening analysis service.
func (h *AIHandler) SetTighteningService(svc *ai.TighteningService) { h.tighteningSvc = svc }

// Register wires AI endpoints onto mux.
func (h *AIHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/summarize", h.summarize)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/suggest-policy", h.suggestPolicy)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/troubleshoot", h.troubleshoot)

	// Enhanced AI endpoints (Tasks 67-71).
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/correlations", h.listCorrelations)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/correlations/{id}", h.getCorrelation)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/correlations/analyze", h.analyzeCorrelations)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/query", h.nlPolicyQuery)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/reports/posture", h.getPostureReport)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/reports/posture/generate", h.generatePostureReport)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/enrich", h.enrichAlert)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/guardrails/status", h.guardrailsStatus)

	// AI suggestion review workflow (Tasks 55-60).
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/suggestions", h.listSuggestions)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/suggestions/{id}", h.getSuggestion)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/suggestions/{id}/approve", h.approveSuggestion)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/suggestions/{id}/reject", h.rejectSuggestion)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ai/tightening/analyze", h.analyzeTightening)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ai/tightening/report", h.getTighteningReport)
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
	// Tag the context with the tenant ID so the guardrailed LLM
	// provider (when configured) attributes rate limiting, token
	// budgets, and audit records to the correct tenant rather than
	// uuid.Nil. The middleware tenant key is package-private to
	// middleware, so the ai package cannot read it directly.
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	summary, err := h.svc.Summarize(ctx, tenantID, tr)
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
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	verified, err := h.svc.SuggestPolicy(ctx, tenantID, actorID, req.Prompt)
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
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	result, err := h.svc.Troubleshoot(ctx, tenantID, req.Query)
	if err != nil {
		h.logger.Error("ai: troubleshoot failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "troubleshooting failed")
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

// --- Enhanced AI endpoints (Tasks 67-71) ---------------------------------

func (h *AIHandler) listCorrelations(w http.ResponseWriter, r *http.Request) {
	if h.correlationRepo == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI correlation service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{Limit: QueryLimit(r), After: r.URL.Query().Get("after")}
	result, err := h.correlationRepo.List(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (h *AIHandler) getCorrelation(w http.ResponseWriter, r *http.Request) {
	if h.correlationRepo == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI correlation service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.correlationRepo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, c)
}

func (h *AIHandler) analyzeCorrelations(w http.ResponseWriter, r *http.Request) {
	if h.correlation == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI correlation service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Alerts []ai.AlertInput `json:"alerts"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Enforce tenant scope on every alert.
	for i := range req.Alerts {
		req.Alerts[i].TenantID = tenantID
	}
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	result, err := h.correlation.Analyze(ctx, req.Alerts)
	if err != nil {
		h.logger.Error("ai: correlate failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "correlation analysis failed")
		return
	}
	// Persist clusters (fire-and-forget; log errors for diagnostics).
	// The repository assigns the canonical ID (the postgres backend
	// always generates its own), so we write the persisted ID back
	// onto the response cluster — otherwise a later
	// GET /ai/correlations/{id} would have no ID to resolve.
	//
	// The response contract is: a cluster's id is non-null iff that
	// cluster was persisted and is retrievable via GET. The engine
	// leaves id nil; on success we set it to the persisted ID, and on
	// failure (or when no repository is wired) it stays nil so the
	// caller sees JSON null — a clear "ephemeral" signal — rather than a
	// plausible id that would 404.
	if h.correlationRepo != nil {
		for i := range result.Clusters {
			cluster := result.Clusters[i]
			persisted, err := h.correlationRepo.Create(r.Context(), tenantID, repository.AICorrelation{
				AlertIDs: cluster.AlertIDs,
				Summary:  cluster.Summary,
				Severity: cluster.Severity,
				Status:   cluster.Status,
			})
			if err != nil {
				h.logger.Warn("ai: failed to persist correlation cluster",
					slog.String("tenant_id", tenantID.String()),
					slog.String("error", err.Error()))
				continue
			}
			pid := persisted.ID
			result.Clusters[i].ID = &pid
		}
	}
	WriteJSON(w, http.StatusOK, result)
}

func (h *AIHandler) nlPolicyQuery(w http.ResponseWriter, r *http.Request) {
	if h.nlQuery == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI query service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Question string `json:"question"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Question == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "question is required")
		return
	}
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	resp, err := h.nlQuery.Query(ctx, ai.NLQueryRequest{
		Question: req.Question,
		TenantID: tenantID,
	})
	if err != nil {
		h.logger.Error("ai: nl query failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "query failed")
		return
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (h *AIHandler) getPostureReport(w http.ResponseWriter, r *http.Request) {
	if h.reports == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI reports service is not configured")
		return
	}
	// The read-only GET reflects real, current posture. Without a
	// data source we must not fabricate an empty (and misleadingly
	// "healthy") report — return 503 and steer callers to the POST
	// .../generate endpoint, which accepts explicit alert data.
	if h.postureData == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"posture report data source is not configured; POST .../reports/posture/generate with explicit data")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	now := time.Now().UTC()
	const window = 7 * 24 * time.Hour
	start := now.Add(-window)
	counts, err := h.postureData.AlertCountsBySeverity(ctx, tenantID, start, now)
	if err != nil {
		h.logger.Error("ai: posture report alert counts failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "report generation failed")
		return
	}
	// Query the immediately preceding window so the report's trend is a
	// real period-over-period comparison. Without a baseline,
	// computeTrend treats any current alerts as a jump from zero and
	// always reports "degrading".
	prevCounts, err := h.postureData.AlertCountsBySeverity(ctx, tenantID, start.Add(-window), start)
	if err != nil {
		h.logger.Error("ai: posture report previous-period alert counts failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "report generation failed")
		return
	}
	var prevTotal int
	for _, v := range prevCounts {
		prevTotal += v
	}
	report, err := h.reports.Generate(ctx, ai.PostureInput{
		TenantID: tenantID,
		Period: ai.ReportPeriod{
			Start: start,
			End:   now,
			Label: "weekly",
		},
		AlertsBySeverity: counts,
		PrevPeriodAlerts: &prevTotal,
	})
	if err != nil {
		h.logger.Error("ai: posture report failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "report generation failed")
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

func (h *AIHandler) generatePostureReport(w http.ResponseWriter, r *http.Request) {
	if h.reports == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI reports service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Period string         `json:"period"` // weekly, monthly
		Alerts map[string]int `json:"alerts_by_severity"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Period == "" {
		req.Period = "weekly"
	}
	if req.Period != "weekly" && req.Period != "monthly" {
		WriteError(w, http.StatusBadRequest, "invalid_body",
			"period must be one of: weekly, monthly")
		return
	}
	if req.Alerts == nil {
		req.Alerts = map[string]int{}
	}
	now := time.Now().UTC()
	var start time.Time
	if req.Period == "monthly" {
		start = now.Add(-30 * 24 * time.Hour)
	} else {
		start = now.Add(-7 * 24 * time.Hour)
	}
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	report, err := h.reports.Generate(ctx, ai.PostureInput{
		TenantID:         tenantID,
		Period:           ai.ReportPeriod{Start: start, End: now, Label: req.Period},
		AlertsBySeverity: req.Alerts,
	})
	if err != nil {
		h.logger.Error("ai: generate posture report failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "report generation failed")
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

func (h *AIHandler) enrichAlert(w http.ResponseWriter, r *http.Request) {
	if h.threatIntel == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI threat intelligence service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		AlertID    uuid.UUID `json:"alert_id"`
		Indicators []string  `json:"indicators"`
		Severity   string    `json:"severity"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.AlertID == uuid.Nil {
		WriteError(w, http.StatusBadRequest, "invalid_body", "alert_id is required")
		return
	}
	if len(req.Indicators) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_body", "indicators is required")
		return
	}
	if req.Severity == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "severity is required")
		return
	}
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	tc, err := h.threatIntel.Enrich(ctx, ai.EnrichRequest{
		AlertID:    req.AlertID,
		TenantID:   tenantID,
		Indicators: req.Indicators,
		Severity:   req.Severity,
	})
	if err != nil {
		h.logger.Error("ai: enrich failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "enrichment failed")
		return
	}
	WriteJSON(w, http.StatusOK, tc)
}

func (h *AIHandler) guardrailsStatus(w http.ResponseWriter, r *http.Request) {
	if h.guardrails == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI guardrails service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	status := h.guardrails.Status(tenantID)
	WriteJSON(w, http.StatusOK, status)
}

// --- AI suggestion review handlers ----------------------------------------

// aiSuggestionResponse is the wire representation of an AI policy
// suggestion. The repository struct repository.AISuggestion has no
// JSON tags, so serialising it directly would emit PascalCase field
// names; this type pins the snake_case contract declared by the
// AISuggestion OpenAPI schema. Optional fields use pointers with
// omitempty so they are absent (not null/empty) when unset.
type aiSuggestionResponse struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	RuleID         string          `json:"rule_id"`
	Category       string          `json:"category"`
	SuggestionJSON json.RawMessage `json:"suggestion_json"`
	Confidence     float64         `json:"confidence"`
	Status         string          `json:"status"`
	CreatedAt      time.Time       `json:"created_at"`
	ReviewedAt     *time.Time      `json:"reviewed_at,omitempty"`
	ReviewerID     *uuid.UUID      `json:"reviewer_id,omitempty"`
	Feedback       *string         `json:"feedback,omitempty"`
}

func toAISuggestionResponse(s repository.AISuggestion) aiSuggestionResponse {
	return aiSuggestionResponse{
		ID:             s.ID,
		TenantID:       s.TenantID,
		RuleID:         s.RuleID,
		Category:       s.Category,
		SuggestionJSON: s.SuggestionJSON,
		Confidence:     s.Confidence,
		Status:         string(s.Status),
		CreatedAt:      s.CreatedAt,
		ReviewedAt:     s.ReviewedAt,
		ReviewerID:     s.ReviewerID,
		Feedback:       s.Feedback,
	}
}

func (h *AIHandler) listSuggestions(w http.ResponseWriter, r *http.Request) {
	if h.reviewSvc == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI suggestion service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var statusFilter *string
	if s := r.URL.Query().Get("status"); s != "" {
		if !ai.SuggestionStatus(s).Valid() {
			WriteError(w, http.StatusBadRequest, "invalid_status",
				"status must be one of: pending, approved, rejected, applied, rolled_back")
			return
		}
		statusFilter = &s
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
	}
	result, err := h.reviewSvc.ListSuggestions(r.Context(), tenantID, statusFilter, page)
	if err != nil {
		// A malformed/tampered cursor surfaces as ErrInvalidArgument
		// from the repository; that is a client error (400), not a
		// server fault, matching how getSuggestion maps repository
		// errors via WriteRepositoryError.
		if errors.Is(err, repository.ErrInvalidArgument) {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "invalid cursor")
			return
		}
		h.logger.Error("ai: list suggestions failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "failed to list suggestions")
		return
	}
	items := make([]aiSuggestionResponse, 0, len(result.Items))
	for _, s := range result.Items {
		items = append(items, toAISuggestionResponse(s))
	}
	// next_cursor is a required field in the AISuggestionPage schema,
	// so it is always emitted (no omitempty) even when empty.
	WriteJSON(w, http.StatusOK, struct {
		Items      []aiSuggestionResponse `json:"items"`
		NextCursor string                 `json:"next_cursor"`
	}{Items: items, NextCursor: result.NextCursor})
}

func (h *AIHandler) getSuggestion(w http.ResponseWriter, r *http.Request) {
	if h.reviewSvc == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI suggestion service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	suggestion, err := h.reviewSvc.GetSuggestion(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAISuggestionResponse(suggestion))
}

// decodeOptionalReviewBody decodes an optional JSON request body into
// dst. A missing body is allowed: a zero Content-Length or an empty
// chunked body (Content-Length == -1, decoder returns io.EOF) is
// treated as "no body" rather than a 400, mirroring the pattern used
// by device.go and msp.go. Any other decode error writes a 400 and
// returns false.
func decodeOptionalReviewBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.ContentLength == 0 {
		return true
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			return true
		}
		WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return false
	}
	return true
}

func (h *AIHandler) approveSuggestion(w http.ResponseWriter, r *http.Request) {
	if h.reviewSvc == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI suggestion service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Feedback string `json:"feedback"`
	}
	if !decodeOptionalReviewBody(w, r, &req) {
		return
	}
	reviewerID := actorFromCtx(r)
	if reviewerID == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized",
			"authenticated user required for approval")
		return
	}
	updated, err := h.reviewSvc.ApproveSuggestion(r.Context(), tenantID, id, *reviewerID, req.Feedback)
	if err != nil {
		writeReviewError(w, h.logger, "approve", err)
		return
	}
	WriteJSON(w, http.StatusOK, toAISuggestionResponse(updated))
}

func (h *AIHandler) rejectSuggestion(w http.ResponseWriter, r *http.Request) {
	if h.reviewSvc == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI suggestion service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req struct {
		Feedback string `json:"feedback"`
	}
	if !decodeOptionalReviewBody(w, r, &req) {
		return
	}
	reviewerID := actorFromCtx(r)
	if reviewerID == nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized",
			"authenticated user required for rejection")
		return
	}
	updated, err := h.reviewSvc.RejectSuggestion(r.Context(), tenantID, id, *reviewerID, req.Feedback)
	if err != nil {
		writeReviewError(w, h.logger, "reject", err)
		return
	}
	WriteJSON(w, http.StatusOK, toAISuggestionResponse(updated))
}

func (h *AIHandler) analyzeTightening(w http.ResponseWriter, r *http.Request) {
	if h.tighteningSvc == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI tightening service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req struct {
		Rules      []json.RawMessage `json:"rules"`
		HitCounts  map[string]int64  `json:"hit_counts"`
		WindowDays int               `json:"window_days"`
	}
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Tag the context with the tenant so that any LLM-backed work the
	// tightening service performs (today its rationales are deterministic,
	// but the service holds the guardrailed provider) is rate-limited and
	// audited under the right tenant rather than uuid.Nil. Mirrors every
	// other AI handler.
	ctx := ai.ContextWithTenantID(r.Context(), tenantID)
	report, err := h.tighteningSvc.Analyze(ctx, ai.AnalyzeInput{
		TenantID:   tenantID,
		Rules:      req.Rules,
		HitCounts:  req.HitCounts,
		WindowDays: req.WindowDays,
	})
	if err != nil {
		h.logger.Error("ai: tightening analysis failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "ai_error", "tightening analysis failed")
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

func (h *AIHandler) getTighteningReport(w http.ResponseWriter, r *http.Request) {
	if h.tighteningSvc == nil {
		WriteError(w, http.StatusServiceUnavailable, "ai_not_configured",
			"AI tightening service is not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	report, ok := h.tighteningSvc.LastReport(tenantID)
	if !ok {
		WriteError(w, http.StatusNotFound, "not_found",
			"no tightening report available; run an analysis first")
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

func writeReviewError(w http.ResponseWriter, logger *slog.Logger, action string, err error) {
	switch {
	case errors.Is(err, repository.ErrNotFound):
		WriteError(w, http.StatusNotFound, "not_found", "suggestion not found")
	case errors.Is(err, repository.ErrConflict):
		WriteError(w, http.StatusConflict, "conflict", "concurrent status change")
	case errors.Is(err, ai.ErrInvalidTransition):
		WriteError(w, http.StatusBadRequest, "invalid_transition", err.Error())
	default:
		logger.Error("ai: "+action+" suggestion failed", slog.String("error", err.Error()))
		WriteError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
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

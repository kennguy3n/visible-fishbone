// Package handler — policy_recommendation.go exposes the
// traffic-derived Policy Recommendation Engine REST surface.
//
// Endpoints (all tenant-scoped, JWT / API-key authenticated):
//
//	POST /api/v1/tenants/{tenant_id}/policy/recommendations
//	    Observes recent telemetry, synthesizes a least-privilege
//	    candidate policy graph, proves coverage + prev-vs-next impact,
//	    and persists the result as a pending recommendation. Body is
//	    optional (window + synthesis tuning); defaults to the last 24h.
//
//	GET  /api/v1/tenants/{tenant_id}/policy/recommendations
//	    Lists recommendations newest-first, optional ?status= filter,
//	    cursor-paginated (?after=, ?limit=).
//
//	GET  /api/v1/tenants/{tenant_id}/policy/recommendations/{recommendation_id}
//	    Returns a single recommendation (candidate graph + evidence).
//
//	POST .../recommendations/{recommendation_id}/apply
//	    Stages the candidate graph as a policy draft (feeding the
//	    existing canary-rollout path) and marks the recommendation
//	    applied. Idempotency: a non-pending recommendation returns 409.
//
//	POST .../recommendations/{recommendation_id}/dismiss
//	    Marks a pending recommendation dismissed.
//
// The engine depends on the telemetry hot tier (ClickHouse), built
// after the HTTP handlers in cmd/sng-control, so it is patched in via
// SetEngine once telemetry is ready — mirroring PolicySimulationHandler.
// Until then every route returns 503.

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policyrec"
)

// PolicyRecommendationHandler exposes the recommendation REST surface.
// engine is stored atomically so SetEngine can run from the startup
// goroutine without racing in-flight requests (same rationale as
// PolicySimulationHandler.sim).
type PolicyRecommendationHandler struct {
	engine atomic.Pointer[policyrec.Service]
	logger *slog.Logger
}

// NewPolicyRecommendationHandler constructs the handler. A nil engine
// is valid — routes 503 until SetEngine wires one. A nil logger falls
// back to slog.Default().
func NewPolicyRecommendationHandler(engine *policyrec.Service, logger *slog.Logger) *PolicyRecommendationHandler {
	if logger == nil {
		logger = slog.Default()
	}
	h := &PolicyRecommendationHandler{logger: logger}
	if engine != nil {
		h.engine.Store(engine)
	}
	return h
}

// SetEngine wires the engine after construction. Passing nil is a no-op
// so callers don't have to gate on whether telemetry is configured.
func (h *PolicyRecommendationHandler) SetEngine(e *policyrec.Service) {
	if h == nil || e == nil {
		return
	}
	h.engine.Store(e)
}

// Register wires every endpoint onto mux.
func (h *PolicyRecommendationHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/recommendations", h.generate)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/recommendations", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/recommendations/{recommendation_id}", h.get)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/recommendations/{recommendation_id}/apply", h.apply)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/recommendations/{recommendation_id}/dismiss", h.dismiss)
}

func (h *PolicyRecommendationHandler) loadEngine(w http.ResponseWriter) (*policyrec.Service, bool) {
	e := h.engine.Load()
	if e == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "policy recommendation engine not configured on this deployment")
		return nil, false
	}
	return e, true
}

// generateRequest is the POST /recommendations body. Every field is
// optional; the zero value generates a recommendation over the last 24h
// with default synthesis tuning.
type generateRequest struct {
	Since     *time.Time              `json:"since,omitempty"`
	Until     *time.Time              `json:"until,omitempty"`
	MaxEvents int                     `json:"max_events,omitempty"`
	Options   *synthesisOptionsParams `json:"options,omitempty"`
}

type synthesisOptionsParams struct {
	IPv4PrefixLen   int `json:"ipv4_prefix_len,omitempty"`
	IPv6PrefixLen   int `json:"ipv6_prefix_len,omitempty"`
	MaxRules        int `json:"max_rules,omitempty"`
	MinObservations int `json:"min_observations,omitempty"`
}

// recommendationResponse is the canonical wire shape of a
// PolicyRecommendation. Hand-rolled so the API contract is independent
// of the repository struct's evolution (matches simulationResponse).
type recommendationResponse struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	Status         string          `json:"status"`
	WindowStart    time.Time       `json:"window_start"`
	WindowEnd      time.Time       `json:"window_end"`
	Coverage       float64         `json:"coverage"`
	RuleCount      int             `json:"rule_count"`
	CandidateGraph json.RawMessage `json:"candidate_graph"`
	Summary        json.RawMessage `json:"summary"`
	AppliedGraphID *uuid.UUID      `json:"applied_graph_id"`
	CreatedAt      time.Time       `json:"created_at"`
	AppliedAt      *time.Time      `json:"applied_at"`
}

func toRecommendationResponse(r repository.PolicyRecommendation) recommendationResponse {
	return recommendationResponse{
		ID:             r.ID,
		TenantID:       r.TenantID,
		Status:         string(r.Status),
		WindowStart:    r.WindowStart,
		WindowEnd:      r.WindowEnd,
		Coverage:       r.Coverage,
		RuleCount:      r.RuleCount,
		CandidateGraph: r.CandidateGraph,
		Summary:        r.Summary,
		AppliedGraphID: r.AppliedGraphID,
		CreatedAt:      r.CreatedAt,
		AppliedAt:      r.AppliedAt,
	}
}

type recommendationListResponse struct {
	Items      []recommendationResponse `json:"items"`
	NextCursor string                   `json:"next_cursor"`
}

type applyResponse struct {
	Recommendation recommendationResponse `json:"recommendation"`
	DraftGraphID   uuid.UUID              `json:"draft_graph_id"`
}

func (h *PolicyRecommendationHandler) generate(w http.ResponseWriter, r *http.Request) {
	engine, ok := h.loadEngine(w)
	if !ok {
		return
	}
	if !engine.Ready() {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "policy recommendation engine requires the telemetry hot tier, which is not configured on this deployment")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	// The body is optional: an empty request generates over the default
	// window. Only decode when one was supplied.
	var req generateRequest
	if r.ContentLength != 0 {
		if !DecodeJSON(w, r, &req) {
			return
		}
	}

	until := time.Now().UTC()
	if req.Until != nil {
		until = req.Until.UTC()
	}
	since := until.Add(-24 * time.Hour)
	if req.Since != nil {
		since = req.Since.UTC()
	}

	genReq := policyrec.GenerateRequest{Since: since, Until: until, MaxEvents: req.MaxEvents}
	if req.Options != nil {
		genReq.Options = policyrec.SynthesisOptions{
			IPv4PrefixLen:   req.Options.IPv4PrefixLen,
			IPv6PrefixLen:   req.Options.IPv6PrefixLen,
			MaxRules:        req.Options.MaxRules,
			MinObservations: req.Options.MinObservations,
		}
	}

	rec, err := engine.Generate(r.Context(), tenantID, actorFromCtx(r), genReq)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toRecommendationResponse(rec))
}

func (h *PolicyRecommendationHandler) list(w http.ResponseWriter, r *http.Request) {
	engine, ok := h.loadEngine(w)
	if !ok {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var status *string
	if s := r.URL.Query().Get("status"); s != "" {
		status = &s
	}
	page := repository.Page{Limit: QueryLimit(r), After: r.URL.Query().Get("after")}
	result, err := engine.List(r.Context(), tenantID, status, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	resp := recommendationListResponse{
		Items:      make([]recommendationResponse, 0, len(result.Items)),
		NextCursor: result.NextCursor,
	}
	for _, rec := range result.Items {
		resp.Items = append(resp.Items, toRecommendationResponse(rec))
	}
	WriteJSON(w, http.StatusOK, resp)
}

func (h *PolicyRecommendationHandler) get(w http.ResponseWriter, r *http.Request) {
	engine, ok := h.loadEngine(w)
	if !ok {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "recommendation_id")
	if !ok {
		return
	}
	rec, err := engine.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRecommendationResponse(rec))
}

func (h *PolicyRecommendationHandler) apply(w http.ResponseWriter, r *http.Request) {
	engine, ok := h.loadEngine(w)
	if !ok {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "recommendation_id")
	if !ok {
		return
	}
	rec, draft, err := engine.Apply(r.Context(), tenantID, actorFromCtx(r), id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, applyResponse{
		Recommendation: toRecommendationResponse(rec),
		DraftGraphID:   draft.ID,
	})
}

func (h *PolicyRecommendationHandler) dismiss(w http.ResponseWriter, r *http.Request) {
	engine, ok := h.loadEngine(w)
	if !ok {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "recommendation_id")
	if !ok {
		return
	}
	rec, err := engine.Dismiss(r.Context(), tenantID, actorFromCtx(r), id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRecommendationResponse(rec))
}

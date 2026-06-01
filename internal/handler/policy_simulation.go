// Package handler — policy_simulation.go exposes the
// policy-change simulator + canary-rollout REST surface
// (Phase 3 Block 2, Task 10).
//
// Endpoints (all tenant-scoped, JWT/API-key authenticated):
//
//   POST /api/v1/tenants/{tenant_id}/policy/simulations
//       Triggers a deterministic replay of recent telemetry
//       against (current_graph, proposed_graph) and returns the
//       ImpactReport. The body is the proposed graph JSON; the
//       optional `since`/`until` query params bound the replay
//       window (defaults: last 24h ending now).
//
//   GET  /api/v1/tenants/{tenant_id}/policy/simulations/{simulation_id}
//       NOT IMPLEMENTED in this PR — simulator runs are
//       transient (response-only). Returns 404 with a stable
//       error code so future clients can be written today. A
//       follow-up PR (tracked alongside the persisted-baseline
//       work in PR C) will introduce a simulations table and
//       wire this path through.
//
//   POST /api/v1/tenants/{tenant_id}/policy/rollouts
//       Promotes a proposed graph to a dry-run rollout: compiles
//       the shadow bundle, registers a row in policy_rollouts,
//       and returns the rollout + the dry-run bundle metadata.
//       The actual bundle bytes are exposed via the existing
//       /policy/bundles/{target} endpoint (which is unchanged) —
//       this endpoint returns metadata + signing-key references.
//
//   GET  /api/v1/tenants/{tenant_id}/policy/rollouts
//       Lists rollouts in created_at DESC order.
//
//   GET  /api/v1/tenants/{tenant_id}/policy/rollouts/{rollout_id}
//       Returns a single rollout row.
//
//   POST /api/v1/tenants/{tenant_id}/policy/rollouts/{rollout_id}/advance
//       Advances the rollout to the next stage. Body:
//       {"stage": "canary"|"full"|"completed", "canary_percent":
//       N, "notes": ...}.
//
//   POST /api/v1/tenants/{tenant_id}/policy/rollouts/{rollout_id}/rollback
//       Aborts the rollout into the rolled_back terminal stage.
//
// The handler is wired in router.go via deps.PolicySimulation. A
// nil dep skips registration (the binary still serves the
// rest of the API).

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// PolicySimulationHandler exposes the simulator + rollout API
// surface. Construct via NewPolicySimulationHandler.
//
// sim is an atomic pointer so SetSimulator can be called from
// outside the HTTP server goroutine without a data race against
// in-flight /simulations requests. The startup path in
// cmd/sng-control already orders SetSimulator before the
// listener accept loop, but storing the pointer atomically
// makes the safety explicit and makes a future hot-reload of
// the ClickHouse reader trivially correct (see PR #39
// Devin Review ANALYSIS_0005).
type PolicySimulationHandler struct {
	policy  *policy.Service
	canary  *policy.CanaryService
	sim     atomic.Pointer[policy.Simulator]
	policyR repository.PolicyRepository
}

// NewPolicySimulationHandler bundles the dependencies the
// handler needs.
func NewPolicySimulationHandler(
	p *policy.Service,
	canary *policy.CanaryService,
	sim *policy.Simulator,
	policyR repository.PolicyRepository,
) *PolicySimulationHandler {
	h := &PolicySimulationHandler{
		policy:  p,
		canary:  canary,
		policyR: policyR,
	}
	if sim != nil {
		h.sim.Store(sim)
	}
	return h
}

// SetSimulator wires the simulator after construction. The
// simulator depends on the ClickHouse hot tier (built later by
// startTelemetry in cmd/sng-control), so the handler is
// constructed without one and the simulator is patched in once
// the telemetry stack is ready. Passing nil is a no-op so callers
// don't have to gate on whether ClickHouse is configured.
func (h *PolicySimulationHandler) SetSimulator(s *policy.Simulator) {
	if h == nil || s == nil {
		return
	}
	h.sim.Store(s)
}

// Register wires every endpoint onto mux.
func (h *PolicySimulationHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/simulations", h.simulate)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/simulations/{simulation_id}", h.getSimulation)

	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/rollouts", h.startRollout)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/rollouts", h.listRollouts)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/rollouts/{rollout_id}", h.getRollout)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/rollouts/{rollout_id}/advance", h.advanceRollout)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/rollouts/{rollout_id}/rollback", h.rollbackRollout)
}

// simulationRequest is the POST /simulations body.
type simulationRequest struct {
	// Proposed is the candidate policy graph JSON; passed
	// through to the simulator unchanged. Required.
	Proposed json.RawMessage `json:"proposed"`

	// Since / Until bound the replay window. RFC3339; both
	// optional. Defaults: since = now - 24h, until = now.
	Since *time.Time `json:"since,omitempty"`
	Until *time.Time `json:"until,omitempty"`

	// MaxEvents caps the per-run envelope budget. Optional;
	// zero -> policy.DefaultSimulationMaxEvents.
	MaxEvents int `json:"max_events,omitempty"`
}

// simulationResponse is the canonical wire shape of
// policy.ImpactReport. Hand-rolled (rather than embedding the
// service struct directly) so the API contract is independent
// of internal struct evolution.
type simulationResponse struct {
	SimulationID    uuid.UUID                   `json:"simulation_id"`
	TenantID        uuid.UUID                   `json:"tenant_id"`
	Since           time.Time                   `json:"since"`
	Until           time.Time                   `json:"until"`
	PrevGraphID     uuid.UUID                   `json:"prev_graph_id"`
	NextGraphID     uuid.UUID                   `json:"next_graph_id"`
	PrevGraphVer    int                         `json:"prev_graph_version"`
	NextGraphVer    int                         `json:"next_graph_version"`
	Total           int                         `json:"total"`
	Changed         int                         `json:"changed"`
	Transitions     []verdictTransitionResponse `json:"transitions"`
	AffectedDevices []uuid.UUID                 `json:"affected_devices"`
	AffectedSites   []uuid.UUID                 `json:"affected_sites"`
	PrevErrors      int                         `json:"prev_errors"`
	NextErrors      int                         `json:"next_errors"`
	StartedAt       time.Time                   `json:"started_at"`
	FinishedAt      time.Time                   `json:"finished_at"`
}

type verdictTransitionResponse struct {
	PrevVerdict string `json:"prev_verdict"`
	NextVerdict string `json:"next_verdict"`
	Count       int    `json:"count"`
}

func toSimulationResponse(r policy.ImpactReport) simulationResponse {
	// All array fields are initialized to non-nil empty slices so the
	// JSON response always renders [], not null. Clients (the operator
	// portal, downstream graphs) iterate these fields unconditionally
	// and would NPE on a null. Allocate with exact-fit capacity since
	// the input sizes are known.
	affectedDevices := r.AffectedDevices
	if affectedDevices == nil {
		affectedDevices = make([]uuid.UUID, 0)
	}
	affectedSites := r.AffectedSites
	if affectedSites == nil {
		affectedSites = make([]uuid.UUID, 0)
	}
	out := simulationResponse{
		SimulationID:    r.SimulationID,
		TenantID:        r.TenantID,
		Since:           r.Since,
		Until:           r.Until,
		PrevGraphID:     r.PrevGraphID,
		NextGraphID:     r.NextGraphID,
		PrevGraphVer:    r.PrevGraphVer,
		NextGraphVer:    r.NextGraphVer,
		Total:           r.Total,
		Changed:         r.Changed,
		AffectedDevices: affectedDevices,
		AffectedSites:   affectedSites,
		PrevErrors:      r.PrevErrors,
		NextErrors:      r.NextErrors,
		StartedAt:       r.StartedAt,
		FinishedAt:      r.FinishedAt,
		Transitions:     make([]verdictTransitionResponse, 0, len(r.Transitions)),
	}
	for _, t := range r.Transitions {
		out.Transitions = append(out.Transitions, verdictTransitionResponse{
			PrevVerdict: string(t.PrevVerdict),
			NextVerdict: string(t.NextVerdict),
			Count:       t.Count,
		})
	}
	return out
}

func (h *PolicySimulationHandler) simulate(w http.ResponseWriter, r *http.Request) {
	sim := h.sim.Load()
	if sim == nil || h.policyR == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "policy simulator not configured on this deployment")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req simulationRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if len(req.Proposed) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "proposed graph is required")
		return
	}
	// Pre-validate the proposed graph before handing it to the
	// simulator. Without this, ParseGraph failures inside the
	// simulator surface as a deny-all impact report (which is the
	// correct evaluation-fallback for production telemetry but is
	// misleading for an operator asking "is my proposed graph going
	// to do what I think?"). A 400 with the parser's error message
	// is the right answer on the API path.
	if _, err := policy.ParseGraph(req.Proposed); err != nil {
		WriteRepositoryError(w, err)
		return
	}

	until := time.Now().UTC()
	if req.Until != nil {
		until = req.Until.UTC()
	}
	since := until.Add(-24 * time.Hour)
	if req.Since != nil {
		since = req.Since.UTC()
	}
	if !until.After(since) {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "until must be after since")
		return
	}

	// The current canonical graph is the "prev" side. Missing
	// (404 from the repo) is non-fatal — the simulator treats
	// a zero PolicyGraph as deny-all so a fresh tenant can
	// still see the proposed graph's impact in isolation.
	prev, err := h.policyR.GetCurrentGraph(r.Context(), tenantID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		WriteRepositoryError(w, err)
		return
	}

	// Compose a transient PolicyGraph for the proposed side.
	// We deliberately do NOT call PutGraph here — the simulation
	// runs against the operator-supplied bytes without touching
	// the canonical graph state.
	proposed := repository.PolicyGraph{
		ID:      uuid.New(),
		TenantID: tenantID,
		Version: prev.Version + 1,
		Graph:   req.Proposed,
	}

	report, err := sim.Simulate(r.Context(), tenantID, prev, proposed, since, until, policy.SimulationOptions{
		MaxEvents: req.MaxEvents,
	})
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrSimulatorBusy):
			WriteError(w, http.StatusServiceUnavailable, "busy", err.Error())
		case errors.Is(err, policy.ErrSimulationTenant),
			errors.Is(err, policy.ErrSimulationWindow):
			WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		case errors.Is(err, policy.ErrNoEvaluator):
			WriteError(w, http.StatusUnprocessableEntity, "no_evaluator", err.Error())
		default:
			WriteError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	WriteJSON(w, http.StatusOK, toSimulationResponse(report))
}

// getSimulation is the read-by-ID endpoint. This PR runs the
// simulator transiently (no persistence) so by-ID retrieval is
// not yet possible — return 404 with a stable code so clients
// written against this path today still parse the response.
func (h *PolicySimulationHandler) getSimulation(w http.ResponseWriter, r *http.Request) {
	WriteError(w, http.StatusNotFound, "not_found",
		"simulation runs are not persisted in this build; re-run the simulation to inspect the report")
}

// rolloutRequest is the POST /rollouts body.
type rolloutRequest struct {
	// Proposed is the candidate policy graph JSON. Required.
	Proposed json.RawMessage `json:"proposed"`

	// SimulationID binds the rollout to a prior simulator
	// run for audit. Optional; the dry-run compiler will
	// allocate one if unset.
	SimulationID *uuid.UUID `json:"simulation_id,omitempty"`

	Notes string `json:"notes,omitempty"`
}

// rolloutResponse is the canonical wire shape of
// repository.PolicyRollout, plus the optional dry-run subject
// (returned on creation only, not on subsequent reads).
type rolloutResponse struct {
	ID              uuid.UUID                     `json:"id"`
	TenantID        uuid.UUID                     `json:"tenant_id"`
	GraphID         uuid.UUID                     `json:"graph_id"`
	PreviousGraphID uuid.UUID                     `json:"previous_graph_id,omitempty"`
	Stage           repository.PolicyRolloutStage `json:"stage"`
	CanaryPercent   int                           `json:"canary_percent"`
	SimulationID    uuid.UUID                     `json:"simulation_id,omitempty"`
	CreatedBy       *uuid.UUID                    `json:"created_by,omitempty"`
	CreatedAt       time.Time                     `json:"created_at"`
	UpdatedAt       time.Time                     `json:"updated_at"`
	Notes           string                        `json:"notes,omitempty"`

	// DryRunSubject is populated only on POST /rollouts (the
	// dry-run-stage creation path); list / get omit it.
	DryRunSubject string `json:"dry_run_subject,omitempty"`
}

func toRolloutResponse(r repository.PolicyRollout, subject string) rolloutResponse {
	return rolloutResponse{
		ID:              r.ID,
		TenantID:        r.TenantID,
		GraphID:         r.GraphID,
		PreviousGraphID: r.PreviousGraphID,
		Stage:           r.Stage,
		CanaryPercent:   r.CanaryPercent,
		SimulationID:    r.SimulationID,
		CreatedBy:       r.CreatedBy,
		CreatedAt:       r.CreatedAt,
		UpdatedAt:       r.UpdatedAt,
		Notes:           r.Notes,
		DryRunSubject:   subject,
	}
}

func (h *PolicySimulationHandler) startRollout(w http.ResponseWriter, r *http.Request) {
	if h.canary == nil || h.policyR == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "canary controller not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req rolloutRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if len(req.Proposed) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "proposed graph is required")
		return
	}
	// Same rationale as simulate: CompileDryRun degrades to the
	// legacy verbatim-rules path on ParseGraph failure, which
	// means a malformed graph would silently produce a shadow
	// bundle that denies everything. Reject it up front so the
	// operator sees a precise parser error instead of a deny-all
	// dry-run after the fact.
	if _, err := policy.ParseGraph(req.Proposed); err != nil {
		WriteRepositoryError(w, err)
		return
	}

	// Snapshot the current graph ID before we mint a new
	// candidate so the rollout audit row records what's being
	// replaced. ErrNotFound is non-fatal — a brand-new tenant
	// has no previous graph.
	var previousGraphID uuid.UUID
	prev, err := h.policyR.GetCurrentGraph(r.Context(), tenantID)
	if err == nil {
		previousGraphID = prev.ID
	} else if !errors.Is(err, repository.ErrNotFound) {
		WriteRepositoryError(w, err)
		return
	}

	// StartDryRun owns the draft-graph persistence: it runs
	// the "one active rollout per tenant" pre-check BEFORE
	// writing anything, so a 409 conflict response no longer
	// leaks an orphaned draft row into policy_graphs (see
	// PR #39 Devin Review ANALYSIS_0004).
	var simID uuid.UUID
	if req.SimulationID != nil {
		simID = *req.SimulationID
	}
	rollout, dryRun, err := h.canary.StartDryRun(r.Context(), tenantID, policy.StartDryRunInput{
		ProposedGraph:   req.Proposed,
		PreviousGraphID: previousGraphID,
		SimulationID:    simID,
		ActorID:         actorFromCtx(r),
		Notes:           req.Notes,
	})
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrCanaryRolloutActive):
			WriteError(w, http.StatusConflict, "rollout_active", err.Error())
		case errors.Is(err, repository.ErrInvalidArgument):
			WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		default:
			WriteRepositoryError(w, err)
		}
		return
	}
	WriteJSON(w, http.StatusCreated, toRolloutResponse(rollout, dryRun.Subject))
}

func (h *PolicySimulationHandler) listRollouts(w http.ResponseWriter, r *http.Request) {
	if h.canary == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "canary controller not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{Limit: QueryLimit(r), After: r.URL.Query().Get("cursor")}
	res, err := h.canary.List(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]rolloutResponse, 0, len(res.Items))
	for _, item := range res.Items {
		items = append(items, toRolloutResponse(item, ""))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *PolicySimulationHandler) getRollout(w http.ResponseWriter, r *http.Request) {
	if h.canary == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "canary controller not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	rolloutID, ok := PathUUID(w, r, "rollout_id")
	if !ok {
		return
	}
	rollout, err := h.canary.Get(r.Context(), tenantID, rolloutID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRolloutResponse(rollout, ""))
}

// advanceRolloutRequest body.
type advanceRolloutRequest struct {
	Stage         repository.PolicyRolloutStage `json:"stage"`
	CanaryPercent int                           `json:"canary_percent,omitempty"`
	Notes         string                        `json:"notes,omitempty"`
}

func (h *PolicySimulationHandler) advanceRollout(w http.ResponseWriter, r *http.Request) {
	if h.canary == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "canary controller not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	rolloutID, ok := PathUUID(w, r, "rollout_id")
	if !ok {
		return
	}
	var req advanceRolloutRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	updated, err := h.canary.Advance(r.Context(), tenantID, rolloutID, policy.AdvanceInput{
		NextStage:     req.Stage,
		CanaryPercent: req.CanaryPercent,
		Notes:         req.Notes,
		ActorID:       actorFromCtx(r),
	})
	if err != nil {
		switch {
		case errors.Is(err, policy.ErrCanaryPercent):
			WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		case errors.Is(err, repository.ErrInvalidArgument):
			WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		default:
			WriteRepositoryError(w, err)
		}
		return
	}
	WriteJSON(w, http.StatusOK, toRolloutResponse(updated, ""))
}

// rollbackRolloutRequest body.
type rollbackRolloutRequest struct {
	Notes string `json:"notes,omitempty"`
}

func (h *PolicySimulationHandler) rollbackRollout(w http.ResponseWriter, r *http.Request) {
	if h.canary == nil {
		WriteError(w, http.StatusServiceUnavailable, "unavailable", "canary controller not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	rolloutID, ok := PathUUID(w, r, "rollout_id")
	if !ok {
		return
	}
	var req rollbackRolloutRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	updated, err := h.canary.Rollback(r.Context(), tenantID, rolloutID, actorFromCtx(r), req.Notes)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRolloutResponse(updated, ""))
}

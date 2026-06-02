package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

type simHandlerFixture struct {
	handler  *PolicySimulationHandler
	tenant   repository.Tenant
	graph    repository.PolicyGraph
	policy   *policy.Service
	canary   *policy.CanaryService
	rollouts repository.PolicyRolloutRepository
	policyR  repository.PolicyRepository
}

func newSimHandlerFixture(t *testing.T) *simHandlerFixture {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	keys := policy.NewKeyService(keyRepo, auditRepo)
	svc := policy.New(policyRepo, auditRepo, keys)

	raw, _ := json.Marshal(map[string]any{
		"default_action": "deny",
		"rules": []map[string]any{
			{"id": "ngfw-1", "domain": "ngfw", "verb": "deny"},
		},
	})
	graph, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw)
	if err != nil {
		t.Fatalf("seed graph: %v", err)
	}
	rollouts := memory.NewPolicyRolloutRepository(store)
	canary, err := policy.NewCanaryService(svc, rollouts)
	if err != nil {
		t.Fatalf("new canary: %v", err)
	}
	// Simulator left nil — exercises the 503 path for /simulations.
	h := NewPolicySimulationHandler(svc, canary, nil, policyRepo, nil)
	return &simHandlerFixture{
		handler:  h,
		tenant:   tnt,
		graph:    graph,
		policy:   svc,
		canary:   canary,
		rollouts: rollouts,
		policyR:  policyRepo,
	}
}

func makeRequest(t *testing.T, method, path string, body any, pathVals map[string]string) *http.Request {
	t.Helper()
	var br *bytes.Buffer
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		br = bytes.NewBuffer(raw)
	} else {
		br = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, br)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range pathVals {
		req.SetPathValue(k, v)
	}
	return req
}

func decodeBody(t *testing.T, r *httptest.ResponseRecorder, out any) {
	t.Helper()
	if r.Body.Len() == 0 {
		return
	}
	if err := json.Unmarshal(r.Body.Bytes(), out); err != nil {
		t.Fatalf("decode body: %v\nbody=%s", err, r.Body.String())
	}
}

func TestSimulationHandler_Simulate_ReturnsServiceUnavailable_WhenSimulatorMissing(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	req := makeRequest(t, http.MethodPost, "/api/v1/tenants/"+f.tenant.ID.String()+"/policy/simulations",
		map[string]any{"proposed": map[string]any{"default_action": "deny"}},
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.simulate(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimulationHandler_StartRollout_CreatesAndReturns201(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts",
		map[string]any{
			"proposed": map[string]any{
				"default_action": "deny",
				"rules":          []map[string]any{{"id": "x", "domain": "ngfw", "verb": "deny"}},
			},
			"notes": "first attempt",
		},
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.startRollout(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", rec.Code, rec.Body.String())
	}
	var resp rolloutResponse
	decodeBody(t, rec, &resp)
	if resp.Stage != repository.PolicyRolloutStageDryRun {
		t.Fatalf("stage = %s, want dry_run", resp.Stage)
	}
	if resp.TenantID != f.tenant.ID {
		t.Fatalf("tenant id mismatch")
	}
	if resp.DryRunSubject == "" {
		t.Fatalf("dry-run subject not echoed back")
	}
	if resp.ID == uuid.Nil {
		t.Fatalf("rollout id missing")
	}
}

func TestSimulationHandler_StartRollout_RejectsActive(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	body := map[string]any{"proposed": map[string]any{"default_action": "deny"}}
	first := makeRequest(t, http.MethodPost, "/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts",
		body, map[string]string{"tenant_id": f.tenant.ID.String()})
	rec := httptest.NewRecorder()
	f.handler.startRollout(rec, first)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first start: %d; body=%s", rec.Code, rec.Body.String())
	}
	second := makeRequest(t, http.MethodPost, "/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts",
		body, map[string]string{"tenant_id": f.tenant.ID.String()})
	rec = httptest.NewRecorder()
	f.handler.startRollout(rec, second)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimulationHandler_StartRollout_400_OnMissingGraph(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts",
		map[string]any{"notes": "no proposal"},
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.startRollout(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimulationHandler_AdvanceRollout_StateMachine(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	// seed a rollout via the service directly to skip handler boilerplate.
	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenant.ID, policy.StartDryRunInput{
		ProposedGraph: f.graph.Graph,
	})
	if err != nil {
		t.Fatalf("seed rollout: %v", err)
	}

	// dry_run -> canary @ 25%
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts/"+rollout.ID.String()+"/advance",
		map[string]any{"stage": "canary", "canary_percent": 25, "notes": "to 25%"},
		map[string]string{"tenant_id": f.tenant.ID.String(), "rollout_id": rollout.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.advanceRollout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp rolloutResponse
	decodeBody(t, rec, &resp)
	if resp.Stage != repository.PolicyRolloutStageCanary || resp.CanaryPercent != 25 {
		t.Fatalf("stage/percent = %s/%d", resp.Stage, resp.CanaryPercent)
	}

	// dry_run -> canary at 0% triggers 400 (already-canary now,
	// but verify the dedicated guard via a fresh rollout).
	freshFixture := newSimHandlerFixture(t)
	freshRollout, _, _ := freshFixture.canary.StartDryRun(context.Background(), freshFixture.tenant.ID, policy.StartDryRunInput{
		ProposedGraph: freshFixture.graph.Graph,
	})
	req = makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+freshFixture.tenant.ID.String()+"/policy/rollouts/"+freshRollout.ID.String()+"/advance",
		map[string]any{"stage": "canary"},
		map[string]string{"tenant_id": freshFixture.tenant.ID.String(), "rollout_id": freshRollout.ID.String()},
	)
	rec = httptest.NewRecorder()
	freshFixture.handler.advanceRollout(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("zero-percent canary: status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimulationHandler_RollbackRollout_TerminatesRollout(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	rollout, _, err := f.canary.StartDryRun(context.Background(), f.tenant.ID, policy.StartDryRunInput{
		ProposedGraph: f.graph.Graph,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts/"+rollout.ID.String()+"/rollback",
		map[string]any{"notes": "abort"},
		map[string]string{"tenant_id": f.tenant.ID.String(), "rollout_id": rollout.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.rollbackRollout(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var resp rolloutResponse
	decodeBody(t, rec, &resp)
	if resp.Stage != repository.PolicyRolloutStageRolledBack {
		t.Fatalf("stage = %s, want rolled_back", resp.Stage)
	}
}

func TestSimulationHandler_ListRollouts_PaginatesAndSerialises(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	// Create + roll back several rollouts so they're all in
	// the terminal set and list returns them in CreatedAt
	// descending order.
	for i := 0; i < 3; i++ {
		rl, _, err := f.canary.StartDryRun(context.Background(), f.tenant.ID, policy.StartDryRunInput{
			ProposedGraph: f.graph.Graph,
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
		if _, err := f.canary.Rollback(context.Background(), f.tenant.ID, rl.ID, nil, ""); err != nil {
			t.Fatalf("rollback %d: %v", i, err)
		}
	}

	req := makeRequest(t, http.MethodGet,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts",
		nil,
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.listRollouts(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var page struct {
		Items      []rolloutResponse `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	decodeBody(t, rec, &page)
	if len(page.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(page.Items))
	}
}

// TestSimulationHandler_ListRollouts_OmitsEmptyNextCursor pins the
// round-5 fix: the typed envelope with `omitempty` MUST omit the
// `next_cursor` JSON key when there is no further page, rather
// than serialising it as `"next_cursor": ""`. Matches the
// alert/baseline/integration handlers; preserves the OpenAPI
// `nullable: true` contract for spec-strict SDK validators.
func TestSimulationHandler_ListRollouts_OmitsEmptyNextCursor(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	rl, _, err := f.canary.StartDryRun(context.Background(), f.tenant.ID, policy.StartDryRunInput{
		ProposedGraph: f.graph.Graph,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := f.canary.Rollback(context.Background(), f.tenant.ID, rl.ID, nil, ""); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	req := makeRequest(t, http.MethodGet,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts?limit=10",
		nil,
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.listRollouts(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	var raw map[string]json.RawMessage
	decodeBody(t, rec, &raw)
	if _, ok := raw["next_cursor"]; ok {
		t.Fatalf("next_cursor key present on terminal page; expected omitted: body=%s",
			rec.Body.String())
	}
	if _, ok := raw["items"]; !ok {
		t.Fatalf("items key missing: body=%s", rec.Body.String())
	}
}

func TestSimulationHandler_GetRollout_404OnUnknown(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	unknown := uuid.New()
	req := makeRequest(t, http.MethodGet,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts/"+unknown.String(),
		nil,
		map[string]string{"tenant_id": f.tenant.ID.String(), "rollout_id": unknown.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.getRollout(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSimulationHandler_GetSimulation_ReturnsNotFound(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	req := makeRequest(t, http.MethodGet,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/simulations/"+uuid.New().String(),
		nil,
		map[string]string{"tenant_id": f.tenant.ID.String(), "simulation_id": uuid.New().String()},
	)
	rec := httptest.NewRecorder()
	f.handler.getSimulation(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestNewPolicySimulationHandler_NilSimulator_Permitted(t *testing.T) {
	t.Parallel()
	// Construct with nil sim → no panic; SetSimulator(nil) is a no-op.
	h := NewPolicySimulationHandler(nil, nil, nil, nil, nil)
	if h == nil {
		t.Fatalf("nil handler returned")
	}
	h.SetSimulator(nil) // must not panic
}

// TestSimulationHandler_Simulate_RejectsInvalidProposedGraph
// pins the post-PR-39-round-2 contract that simulate validates
// the proposed graph BEFORE handing it to the simulator. Without
// this guard a malformed graph would surface as a deny-all
// impact report (correct-by-degradation for production telemetry
// but misleading for an operator iterating on a draft).
func TestSimulationHandler_Simulate_RejectsInvalidProposedGraph(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	// Wire a non-nil simulator so we exercise the pre-validation
	// branch instead of the 503 short-circuit. Re-use the default
	// graph evaluator factory since we only care that the request
	// is rejected before the simulator runs.
	store := memory.NewStore()
	srcStub := &stubTelemetrySource{} // implements ListEvents/ListFlowEvents
	sim, err := policy.NewSimulator(srcStub, policy.GraphEvaluatorFactory{})
	if err != nil {
		t.Fatalf("new simulator: %v", err)
	}
	f.handler.SetSimulator(sim)
	_ = store

	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/simulations",
		map[string]any{
			"proposed": map[string]any{
				// Unknown verb — Validate() rejects this.
				"default_action": "explode",
			},
		},
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.simulate(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	if srcStub.calls != 0 {
		t.Fatalf("simulator pulled events for an invalid graph — pre-validation didn't fire (calls=%d)", srcStub.calls)
	}
}

// TestSimulationHandler_StartRollout_RejectsInvalidProposedGraph
// pins the equivalent guard on the rollout path. CompileDryRun
// otherwise degrades to a deny-all shadow bundle on ParseGraph
// failure.
func TestSimulationHandler_StartRollout_RejectsInvalidProposedGraph(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/rollouts",
		map[string]any{
			"proposed": map[string]any{
				"default_action": "garbage",
			},
		},
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.startRollout(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// stubTelemetrySource is a minimal TelemetrySource that counts
// calls — used to assert that pre-validation rejects requests
// without invoking the simulator.
type stubTelemetrySource struct {
	calls int
}

func (s *stubTelemetrySource) ListFlowEvents(_ context.Context, _ uuid.UUID, _, _ time.Time, _ int) ([]schema.Envelope, error) {
	s.calls++
	return nil, nil
}

func (s *stubTelemetrySource) ListEvents(_ context.Context, _ uuid.UUID, _ []schema.EventClass, _, _ time.Time, _ int) ([]schema.Envelope, error) {
	s.calls++
	return nil, nil
}

var _ policy.TelemetrySource = (*stubTelemetrySource)(nil)

// TestSimulationHandler_Simulate_500_OpaqueErrorBody pins the
// round-3 BUG_0002 fix: when the simulator returns an internal
// failure (anything not in the typed errors-as values list), the
// HTTP response body MUST NOT carry the raw err.Error() string.
// The previous default branch did `WriteError(..., err.Error())`,
// leaking pgx / ClickHouse driver wording (and potentially
// tenant-isolated identifiers) to the caller.
func TestSimulationHandler_Simulate_500_OpaqueErrorBody(t *testing.T) {
	t.Parallel()
	f := newSimHandlerFixture(t)
	// Wire a simulator backed by a source that returns a
	// sentinel error so the simulator surfaces a non-typed
	// failure — the only path that lands on the `default`
	// arm of the err switch.
	sentinel := errors.New("clickhouse: query exec: 14:09 syntax: secret_table_name=baseline_models_tenant_xyz")
	srcStub := &errorTelemetrySource{err: sentinel}
	sim, err := policy.NewSimulator(srcStub, policy.GraphEvaluatorFactory{})
	if err != nil {
		t.Fatalf("new simulator: %v", err)
	}
	f.handler.SetSimulator(sim)

	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/simulations",
		map[string]any{
			"proposed": map[string]any{
				"default_action": "deny",
				"rules":          []map[string]any{{"id": "x", "domain": "ngfw", "verb": "deny"}},
			},
		},
		map[string]string{"tenant_id": f.tenant.ID.String()},
	)
	rec := httptest.NewRecorder()
	f.handler.simulate(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	// The body must not contain any substring of the
	// sentinel — that's exactly what the bug was.
	for _, leak := range []string{
		"clickhouse",
		"query exec",
		"baseline_models_tenant_xyz",
		"secret_table_name",
		sentinel.Error(),
	} {
		if bytes.Contains([]byte(body), []byte(leak)) {
			t.Fatalf("response body leaks internal error %q; body=%s", leak, body)
		}
	}
}

// errorTelemetrySource returns a fixed error from every fetch
// so the simulator's Simulate path surfaces a non-typed error
// (i.e. lands on the default arm of the handler's err switch).
type errorTelemetrySource struct{ err error }

func (s *errorTelemetrySource) ListFlowEvents(_ context.Context, _ uuid.UUID, _, _ time.Time, _ int) ([]schema.Envelope, error) {
	return nil, s.err
}
func (s *errorTelemetrySource) ListEvents(_ context.Context, _ uuid.UUID, _ []schema.EventClass, _, _ time.Time, _ int) ([]schema.Envelope, error) {
	return nil, s.err
}

var _ policy.TelemetrySource = (*errorTelemetrySource)(nil)

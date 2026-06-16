package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
	"github.com/kennguy3n/visible-fishbone/internal/service/policyrec"
)

// recHandlerSource is a fixed-envelope policy.TelemetrySource so the
// recommendation engine synthesizes a deterministic candidate without a
// live ClickHouse tier.
type recHandlerSource struct{ envs []schema.Envelope }

func (s *recHandlerSource) ListFlowEvents(ctx context.Context, tid uuid.UUID, since, until time.Time, limit int) ([]schema.Envelope, error) {
	return s.ListEvents(ctx, tid, []schema.EventClass{schema.EventClassFlow}, since, until, limit)
}

func (s *recHandlerSource) ListEvents(_ context.Context, _ uuid.UUID, classes []schema.EventClass, _, _ time.Time, _ int) ([]schema.Envelope, error) {
	wanted := map[schema.EventClass]struct{}{}
	for _, c := range classes {
		wanted[c] = struct{}{}
	}
	out := make([]schema.Envelope, 0, len(s.envs))
	for _, e := range s.envs {
		if _, ok := wanted[e.EventClass]; ok || len(wanted) == 0 {
			out = append(out, e)
		}
	}
	return out, nil
}

func recFlowEnv(t *testing.T, dstIP, proto string, dstPort uint16, verdict schema.Verdict) schema.Envelope {
	t.Helper()
	payload, err := schema.PackPayload(schema.FlowEvent{
		SrcIP: "10.1.1.1", DstIP: dstIP, SrcPort: 12345, DstPort: dstPort,
		Protocol: proto, Verdict: verdict,
	})
	if err != nil {
		t.Fatalf("pack flow: %v", err)
	}
	return schema.Envelope{
		SchemaVersion: 1, EventID: uuid.New(), TenantID: uuid.New(), DeviceID: uuid.New(),
		Timestamp: time.Unix(100, 0), EventClass: schema.EventClassFlow, Platform: "linux", Payload: payload,
	}
}

type recHandlerFixture struct {
	handler *PolicyRecommendationHandler
	engine  *policyrec.Service
	tenant  repository.Tenant
}

// newRecHandlerFixture builds a fully-wired engine (memory repo + real
// policy.Service as the graph provider + a fixed telemetry source) so
// the HTTP surface exercises the full generate -> persist -> apply path.
func newRecHandlerFixture(t *testing.T, wireSource bool) *recHandlerFixture {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	policySvc := policy.New(policyRepo, auditRepo, policy.NewKeyService(keyRepo, auditRepo))

	src := &recHandlerSource{envs: []schema.Envelope{
		recFlowEnv(t, "10.0.0.5", "tcp", 443, schema.VerdictAllow),
		recFlowEnv(t, "10.0.0.9", "tcp", 443, schema.VerdictAllow),
	}}
	var initialSrc policy.TelemetrySource
	if wireSource {
		initialSrc = src
	}
	engine := policyrec.New(memory.NewPolicyRecommendationRepository(store), initialSrc, policySvc, nil, nil)
	h := NewPolicyRecommendationHandler(engine, nil)
	return &recHandlerFixture{handler: h, engine: engine, tenant: tnt}
}

func TestRecHandler_Generate_503_WhenEngineMissing(t *testing.T) {
	t.Parallel()
	h := NewPolicyRecommendationHandler(nil, nil)
	f := newRecHandlerFixture(t, false)
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/recommendations", nil,
		map[string]string{"tenant_id": f.tenant.ID.String()})
	rec := httptest.NewRecorder()
	h.generate(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRecHandler_Generate_503_WhenTelemetryNotReady(t *testing.T) {
	t.Parallel()
	f := newRecHandlerFixture(t, false) // engine present, source not wired
	req := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+f.tenant.ID.String()+"/policy/recommendations", nil,
		map[string]string{"tenant_id": f.tenant.ID.String()})
	rec := httptest.NewRecorder()
	f.handler.generate(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRecHandler_GenerateListGetApply(t *testing.T) {
	t.Parallel()
	f := newRecHandlerFixture(t, true)
	tid := f.tenant.ID.String()

	// Generate.
	genReq := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/recommendations", nil,
		map[string]string{"tenant_id": tid})
	genRec := httptest.NewRecorder()
	f.handler.generate(genRec, genReq)
	if genRec.Code != http.StatusCreated {
		t.Fatalf("generate status = %d, want 201; body=%s", genRec.Code, genRec.Body.String())
	}
	var created recommendationResponse
	decodeBody(t, genRec, &created)
	if created.Status != "pending" {
		t.Fatalf("status = %q, want pending", created.Status)
	}
	// 2 flows in the same /24 on tcp/443 -> exactly one synthesized rule.
	if created.RuleCount != 1 {
		t.Fatalf("rule_count = %d, want 1", created.RuleCount)
	}
	if len(created.CandidateGraph) == 0 {
		t.Fatalf("candidate graph not echoed back")
	}

	// List (newest-first).
	listReq := makeRequest(t, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/recommendations", nil,
		map[string]string{"tenant_id": tid})
	listRec := httptest.NewRecorder()
	f.handler.list(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200; body=%s", listRec.Code, listRec.Body.String())
	}
	var page recommendationListResponse
	decodeBody(t, listRec, &page)
	if len(page.Items) != 1 || page.Items[0].ID != created.ID {
		t.Fatalf("list items = %+v, want exactly the created recommendation", page.Items)
	}

	// Get.
	getReq := makeRequest(t, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/recommendations/"+created.ID.String(), nil,
		map[string]string{"tenant_id": tid, "recommendation_id": created.ID.String()})
	getRec := httptest.NewRecorder()
	f.handler.get(getRec, getReq)
	if getRec.Code != http.StatusOK {
		t.Fatalf("get status = %d, want 200; body=%s", getRec.Code, getRec.Body.String())
	}

	// Apply -> stages a draft + marks applied.
	applyReq := makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/recommendations/"+created.ID.String()+"/apply", nil,
		map[string]string{"tenant_id": tid, "recommendation_id": created.ID.String()})
	applyRec := httptest.NewRecorder()
	f.handler.apply(applyRec, applyReq)
	if applyRec.Code != http.StatusOK {
		t.Fatalf("apply status = %d, want 200; body=%s", applyRec.Code, applyRec.Body.String())
	}
	var applied applyResponse
	decodeBody(t, applyRec, &applied)
	if applied.Recommendation.Status != "applied" {
		t.Fatalf("status = %q, want applied", applied.Recommendation.Status)
	}
	if applied.DraftGraphID == uuid.Nil {
		t.Fatalf("draft graph id missing")
	}

	// Re-applying a non-pending recommendation is a 409 conflict.
	conflictRec := httptest.NewRecorder()
	f.handler.apply(conflictRec, makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/recommendations/"+created.ID.String()+"/apply", nil,
		map[string]string{"tenant_id": tid, "recommendation_id": created.ID.String()}))
	if conflictRec.Code != http.StatusConflict {
		t.Fatalf("re-apply status = %d, want 409; body=%s", conflictRec.Code, conflictRec.Body.String())
	}
}

func TestRecHandler_Dismiss(t *testing.T) {
	t.Parallel()
	f := newRecHandlerFixture(t, true)
	tid := f.tenant.ID.String()

	genRec := httptest.NewRecorder()
	f.handler.generate(genRec, makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/recommendations", nil,
		map[string]string{"tenant_id": tid}))
	if genRec.Code != http.StatusCreated {
		t.Fatalf("generate status = %d, want 201; body=%s", genRec.Code, genRec.Body.String())
	}
	var created recommendationResponse
	decodeBody(t, genRec, &created)

	dismissRec := httptest.NewRecorder()
	f.handler.dismiss(dismissRec, makeRequest(t, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/recommendations/"+created.ID.String()+"/dismiss", nil,
		map[string]string{"tenant_id": tid, "recommendation_id": created.ID.String()}))
	if dismissRec.Code != http.StatusOK {
		t.Fatalf("dismiss status = %d, want 200; body=%s", dismissRec.Code, dismissRec.Body.String())
	}
	var dismissed recommendationResponse
	decodeBody(t, dismissRec, &dismissed)
	if dismissed.Status != "dismissed" {
		t.Fatalf("status = %q, want dismissed", dismissed.Status)
	}
	// A dismissal leaves applied_at unset.
	if dismissed.AppliedAt != nil {
		t.Fatalf("applied_at = %v, want nil for a dismissal", dismissed.AppliedAt)
	}
}

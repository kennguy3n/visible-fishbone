package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

func TestAIHandler_Summarize_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{
		"start": "2024-01-01T00:00:00Z",
		"end":   "2024-01-02T00:00:00Z",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/summarize",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)

	rec := httptest.NewRecorder()
	h.summarize(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_SuggestPolicy_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{"prompt": "block all traffic"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/suggest-policy",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)

	rec := httptest.NewRecorder()
	h.suggestPolicy(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_Troubleshoot_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{"query": "why is traffic blocked?"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/troubleshoot",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)

	rec := httptest.NewRecorder()
	h.troubleshoot(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_Summarize_200WithConfiguredService(t *testing.T) {
	t.Parallel()
	evidence := &stubHandlerEvidence{data: ai.TemplateData{
		AlertCount:    2,
		TopAlertKinds: []string{"anomaly"},
	}}
	summarizer := ai.NewSummarizer(nil, evidence)
	svc := ai.New(nil, nil, summarizer)
	h := NewAIHandler(svc, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{
		"start": "2024-01-01T00:00:00Z",
		"end":   "2024-01-02T00:00:00Z",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/summarize",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)

	rec := httptest.NewRecorder()
	h.summarize(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var summary ai.Summary
	if err := json.Unmarshal(rec.Body.Bytes(), &summary); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if summary.AIGenerated {
		t.Fatal("template-only mode: ai_generated must be false")
	}
	if summary.Text == "" {
		t.Fatal("expected non-empty summary text")
	}
}

func TestAIHandler_SuggestPolicy_400MissingPrompt(t *testing.T) {
	t.Parallel()
	svc := ai.New(&stubHandlerLLM{}, nil, nil)
	h := NewAIHandler(svc, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/suggest-policy",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)

	rec := httptest.NewRecorder()
	h.suggestPolicy(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_Troubleshoot_400MissingQuery(t *testing.T) {
	t.Parallel()
	svc := ai.New(&stubHandlerLLM{}, nil, nil)
	h := NewAIHandler(svc, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/troubleshoot",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)

	rec := httptest.NewRecorder()
	h.troubleshoot(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// --- Enhanced AI endpoint tests (Tasks 67-71) ----

func TestAIHandler_ListCorrelations_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/correlations", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.listCorrelations(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_ListCorrelations_200(t *testing.T) {
	t.Parallel()
	store := newTestMemoryStore()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, nil, nil, nil, store.aiCorrelationRepo)
	tenantID := uuid.New()
	// Seed one correlation.
	store.aiCorrelationRepo.Create(context.Background(), tenantID, repository.AICorrelation{
		AlertIDs: []uuid.UUID{uuid.New()},
		Severity: "high",
		Summary:  "test cluster",
	})
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/ai/correlations", nil)
	req.SetPathValue("tenant_id", tenantID.String())
	rec := httptest.NewRecorder()
	h.listCorrelations(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_GetCorrelation_404(t *testing.T) {
	t.Parallel()
	store := newTestMemoryStore()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, nil, nil, nil, store.aiCorrelationRepo)
	tenantID := uuid.New().String()
	corrID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/correlations/"+corrID, nil)
	req.SetPathValue("tenant_id", tenantID)
	req.SetPathValue("id", corrID)
	rec := httptest.NewRecorder()
	h.getCorrelation(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_AnalyzeCorrelations_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{"alerts": []any{}})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/correlations/analyze",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.analyzeCorrelations(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_NLPolicyQuery_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{"question": "can user X access app Y?"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/query",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.nlPolicyQuery(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_NLPolicyQuery_400MissingQuestion(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, ai.NewNLQueryEngine(nil), nil, nil, nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/query",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.nlPolicyQuery(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_NLPolicyQuery_200(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, ai.NewNLQueryEngine(nil), nil, nil, nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]string{"question": "Can user alice access app salesforce?"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/query",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.nlPolicyQuery(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_PostureReport_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getPostureReport(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_PostureReport_200(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, ai.NewReportEngine(nil), nil, nil, nil)
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getPostureReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_EnrichAlert_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{
		"alert_id":   uuid.New().String(),
		"indicators": []string{"1.2.3.4"},
		"severity":   "medium",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/enrich",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.enrichAlert(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_EnrichAlert_200(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, nil, ai.NewThreatIntelEngine(nil), nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{
		"alert_id":   uuid.New().String(),
		"indicators": []string{"1.2.3.4"},
		"severity":   "medium",
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/enrich",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.enrichAlert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_GuardrailsStatus_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/guardrails/status", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.guardrailsStatus(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
}

// --- test helpers ---

type testMemoryStore struct {
	aiCorrelationRepo *memory.AICorrelationRepository
}

func newTestMemoryStore() testMemoryStore {
	s := memory.NewStore()
	return testMemoryStore{
		aiCorrelationRepo: memory.NewAICorrelationRepository(s),
	}
}

// --- test stubs ---

type stubHandlerLLM struct{}

func (s *stubHandlerLLM) Complete(_ context.Context, _ ai.LLMRequest) (ai.LLMResponse, error) {
	return ai.LLMResponse{Text: "{}", ModelID: "test"}, nil
}

type stubHandlerEvidence struct {
	data ai.TemplateData
}

func (s *stubHandlerEvidence) QueryEvidence(_ context.Context, _ uuid.UUID, _ ai.TimeRange) (ai.TemplateData, error) {
	return s.data, nil
}

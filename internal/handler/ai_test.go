package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
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

func TestAIHandler_AnalyzeCorrelations_PersistedIDIsRetrievable(t *testing.T) {
	t.Parallel()
	store := newTestMemoryStore()
	h := NewAIHandler(nil, nil)
	engine := ai.NewCorrelationEngine(nil, ai.CorrelationConfig{})
	h.SetEnhancedAI(engine, nil, nil, nil, nil, store.aiCorrelationRepo)

	tenantID := uuid.New()
	now := time.Now().UTC()
	// Two alerts sharing a device within the time window correlate
	// into one cluster.
	alerts := []ai.AlertInput{
		{Kind: "malware", Severity: "high", DeviceID: "dev-1", CreatedAt: now},
		{Kind: "malware", Severity: "critical", DeviceID: "dev-1", CreatedAt: now.Add(time.Minute)},
	}
	body, _ := json.Marshal(map[string]any{"alerts": alerts})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/ai/correlations/analyze",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID.String())
	rec := httptest.NewRecorder()
	h.analyzeCorrelations(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("analyze status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var result ai.CorrelationResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode analyze response: %v", err)
	}
	if len(result.Clusters) == 0 {
		t.Fatal("expected at least one correlation cluster")
	}
	// Every returned cluster ID must resolve via GET — i.e. the
	// response carries the persisted ID, not a divergent engine ID.
	for _, cluster := range result.Clusters {
		if cluster.ID == uuid.Nil {
			t.Fatal("cluster ID must not be nil")
		}
		getReq := httptest.NewRequest(http.MethodGet,
			"/api/v1/tenants/"+tenantID.String()+"/ai/correlations/"+cluster.ID.String(), nil)
		getReq.SetPathValue("tenant_id", tenantID.String())
		getReq.SetPathValue("id", cluster.ID.String())
		getRec := httptest.NewRecorder()
		h.getCorrelation(getRec, getReq)
		if getRec.Code != http.StatusOK {
			t.Fatalf("GET correlation %s = %d, want 200; body=%s",
				cluster.ID, getRec.Code, getRec.Body.String())
		}
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

func TestAIHandler_PostureReport_503WhenNoDataSource(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	// Reports engine configured, but no posture data source: GET must
	// not fabricate an empty (misleadingly healthy) report.
	h.SetEnhancedAI(nil, nil, ai.NewReportEngine(nil), nil, nil, nil)
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
	// Wire a real-data source so GET reflects actual alert counts.
	h.SetPostureDataSource(stubPostureData{counts: map[string]int{"critical": 2, "warning": 1}})
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getPostureReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var report ai.PostureReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	// The report must reflect the real counts from the data source,
	// not an empty baseline.
	if report.Overview.TotalAlerts != 3 {
		t.Fatalf("total_alerts = %d, want 3; body=%s", report.Overview.TotalAlerts, rec.Body.String())
	}
	if report.Overview.AlertsBySeverity["critical"] != 2 {
		t.Fatalf("critical = %d, want 2", report.Overview.AlertsBySeverity["critical"])
	}
}

func TestAIHandler_PostureReport_TrendUsesPreviousPeriod(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, ai.NewReportEngine(nil), nil, nil, nil)
	// Previous window had far more alerts than the current window, so a
	// real period-over-period comparison must report "improving" — not
	// the "degrading" that results when the previous period is ignored
	// (treated as zero) and any current alert looks like a jump.
	h.SetPostureDataSource(trendPostureData{
		current: map[string]int{"critical": 2},
		prev:    map[string]int{"critical": 10},
	})
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getPostureReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var report ai.PostureReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	if report.Overview.Trend == "degrading" {
		t.Fatalf("trend = %q, want non-degrading (previous period had more alerts)", report.Overview.Trend)
	}
	if report.Overview.Trend != "improving" {
		t.Fatalf("trend = %q, want improving", report.Overview.Trend)
	}
}

func TestAIHandler_PostureReport_DataSourceError500(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, ai.NewReportEngine(nil), nil, nil, nil)
	h.SetPostureDataSource(stubPostureData{err: errStubPostureData})
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getPostureReport(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", rec.Code, rec.Body.String())
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

func TestAIHandler_EnrichAlert_400MissingFields(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body map[string]any
	}{
		{"missing alert_id", map[string]any{"indicators": []string{"1.2.3.4"}, "severity": "medium"}},
		{"missing indicators", map[string]any{"alert_id": uuid.New().String(), "severity": "medium"}},
		{"missing severity", map[string]any{"alert_id": uuid.New().String(), "indicators": []string{"1.2.3.4"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := NewAIHandler(nil, nil)
			h.SetEnhancedAI(nil, nil, nil, ai.NewThreatIntelEngine(nil), nil, nil)
			tenantID := uuid.New().String()
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost,
				"/api/v1/tenants/"+tenantID+"/ai/enrich",
				bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("tenant_id", tenantID)
			rec := httptest.NewRecorder()
			h.enrichAlert(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestAIHandler_GeneratePostureReport_400InvalidPeriod(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, ai.NewReportEngine(nil), nil, nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{"period": "daily"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture/generate",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.generatePostureReport(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_GeneratePostureReport_NoBaselineNotDegrading(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetEnhancedAI(nil, nil, ai.NewReportEngine(nil), nil, nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{
		"period":             "weekly",
		"alerts_by_severity": map[string]int{"critical": 3, "high": 4},
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/reports/posture/generate",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.generatePostureReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var report ai.PostureReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	// The POST handler supplies no previous-period baseline, so the
	// trend must be "stable" — not "degrading" fabricated from an
	// assumed-zero baseline.
	if report.Overview.Trend != "stable" {
		t.Fatalf("trend = %q, want stable (no baseline supplied)", report.Overview.Trend)
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

// --- AI suggestion handler tests ---

func TestAIHandler_ListSuggestions_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/suggestions", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.listSuggestions(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestAIHandler_ListSuggestions_200(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	reviewSvc := ai.NewReviewService(repo, nil)

	h := NewAIHandler(nil, nil)
	h.SetReviewService(reviewSvc)

	tenantID := uuid.New()
	repo.Create(context.Background(), tenantID, repository.AISuggestion{
		RuleID:         "r1",
		Category:       "unused",
		SuggestionJSON: json.RawMessage(`{}`),
		Confidence:     0.9,
	})

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/ai/suggestions", nil)
	req.SetPathValue("tenant_id", tenantID.String())
	rec := httptest.NewRecorder()
	h.listSuggestions(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_GetSuggestion_404(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	reviewSvc := ai.NewReviewService(repo, nil)

	h := NewAIHandler(nil, nil)
	h.SetReviewService(reviewSvc)

	tenantID := uuid.New().String()
	fakeID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/suggestions/"+fakeID, nil)
	req.SetPathValue("tenant_id", tenantID)
	req.SetPathValue("id", fakeID)
	rec := httptest.NewRecorder()
	h.getSuggestion(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_ApproveSuggestion(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	reviewSvc := ai.NewReviewService(repo, nil)

	h := NewAIHandler(nil, nil)
	h.SetReviewService(reviewSvc)

	tenantID := uuid.New()
	s, _ := repo.Create(context.Background(), tenantID, repository.AISuggestion{
		RuleID:         "r1",
		Category:       "unused",
		SuggestionJSON: json.RawMessage(`{}`),
		Confidence:     0.9,
	})

	userID := uuid.New()
	body, _ := json.Marshal(map[string]string{"feedback": "lgtm"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/ai/suggestions/"+s.ID.String()+"/approve",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID.String())
	req.SetPathValue("id", s.ID.String())
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), userID))
	rec := httptest.NewRecorder()
	h.approveSuggestion(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_RejectSuggestion(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	reviewSvc := ai.NewReviewService(repo, nil)

	h := NewAIHandler(nil, nil)
	h.SetReviewService(reviewSvc)

	tenantID := uuid.New()
	s, _ := repo.Create(context.Background(), tenantID, repository.AISuggestion{
		RuleID:         "r1",
		Category:       "unused",
		SuggestionJSON: json.RawMessage(`{}`),
		Confidence:     0.9,
	})

	userID := uuid.New()
	body, _ := json.Marshal(map[string]string{"feedback": "nope"})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/ai/suggestions/"+s.ID.String()+"/reject",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID.String())
	req.SetPathValue("id", s.ID.String())
	req = req.WithContext(middleware.WithUserIDForTest(req.Context(), userID))
	rec := httptest.NewRecorder()
	h.rejectSuggestion(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_AnalyzeTightening_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{"rules": []any{}})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/tightening/analyze",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.analyzeTightening(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestAIHandler_AnalyzeTightening_200(t *testing.T) {
	t.Parallel()
	tighteningSvc := ai.NewTighteningService(nil, nil)
	h := NewAIHandler(nil, nil)
	h.SetTighteningService(tighteningSvc)

	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{
		"rules":       []json.RawMessage{json.RawMessage(`{"id":"r1","verb":"allow","domain":"ngfw"}`)},
		"hit_counts":  map[string]int64{"r1": 0},
		"window_days": 30,
	})
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/tightening/analyze",
		bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.analyzeTightening(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_GetTighteningReport_503WhenNotConfigured(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/tightening/report", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getTighteningReport(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

func TestAIHandler_GetTighteningReport_404WhenNoRun(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetTighteningService(ai.NewTighteningService(nil, nil))

	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/tightening/report", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getTighteningReport(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_GetTighteningReport_200AfterAnalyze(t *testing.T) {
	t.Parallel()
	tighteningSvc := ai.NewTighteningService(nil, nil)
	h := NewAIHandler(nil, nil)
	h.SetTighteningService(tighteningSvc)

	tenantID := uuid.New().String()
	body, _ := json.Marshal(map[string]any{
		"rules":       []json.RawMessage{json.RawMessage(`{"id":"r1","verb":"allow","domain":"ngfw"}`)},
		"hit_counts":  map[string]int64{"r1": 0},
		"window_days": 30,
	})
	areq := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID+"/ai/tightening/analyze",
		bytes.NewReader(body))
	areq.Header.Set("Content-Type", "application/json")
	areq.SetPathValue("tenant_id", tenantID)
	h.analyzeTightening(httptest.NewRecorder(), areq)

	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/tightening/report", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.getTighteningReport(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Recommendations must serialise as a JSON array, never null.
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"recommendations":[`)) {
		t.Fatalf("expected recommendations array in body, got %s", rec.Body.String())
	}
}

func TestAIHandler_ListSuggestions_400OnInvalidStatus(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetReviewService(ai.NewReviewService(memory.NewAISuggestionRepository(memory.NewStore()), nil))

	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/suggestions?status=bogus", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.listSuggestions(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

// invalidArgListRepo is an AISuggestionRepository whose List always
// returns repository.ErrInvalidArgument, mimicking the postgres backend's
// behaviour for a malformed/tampered pagination cursor. The memory
// backend deliberately treats bad cursors as "start over", so a stub is
// needed to exercise the handler's 400 mapping.
type invalidArgListRepo struct {
	repository.AISuggestionRepository
}

func (invalidArgListRepo) List(context.Context, uuid.UUID, *string, repository.Page) (repository.PageResult[repository.AISuggestion], error) {
	return repository.PageResult[repository.AISuggestion]{}, repository.ErrInvalidArgument
}

func TestAIHandler_ListSuggestions_400OnInvalidCursor(t *testing.T) {
	t.Parallel()
	h := NewAIHandler(nil, nil)
	h.SetReviewService(ai.NewReviewService(invalidArgListRepo{}, nil))

	tenantID := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID+"/ai/suggestions?after=not-a-valid-cursor", nil)
	req.SetPathValue("tenant_id", tenantID)
	rec := httptest.NewRecorder()
	h.listSuggestions(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAIHandler_SuggestionResponses_SnakeCase(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	repo := memory.NewAISuggestionRepository(store)
	tenantID := uuid.New()
	created, err := repo.Create(context.Background(), tenantID, repository.AISuggestion{
		RuleID:         "r1",
		Category:       "unused",
		SuggestionJSON: json.RawMessage(`{"action":"remove_rule"}`),
		Confidence:     0.9,
	})
	if err != nil {
		t.Fatalf("seed create: %v", err)
	}

	h := NewAIHandler(nil, nil)
	h.SetReviewService(ai.NewReviewService(repo, nil))

	// list
	lreq := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/ai/suggestions", nil)
	lreq.SetPathValue("tenant_id", tenantID.String())
	lrec := httptest.NewRecorder()
	h.listSuggestions(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("list status = %d; body=%s", lrec.Code, lrec.Body.String())
	}
	body := lrec.Body.String()
	for _, want := range []string{`"items":[`, `"next_cursor"`, `"id":`, `"tenant_id":`, `"rule_id":`, `"suggestion_json":`, `"created_at":`} {
		if !strings.Contains(body, want) {
			t.Fatalf("list body missing %s: %s", want, body)
		}
	}
	for _, bad := range []string{`"ID"`, `"TenantID"`, `"RuleID"`, `"SuggestionJSON"`, `"NextCursor"`, `"Items"`} {
		if strings.Contains(body, bad) {
			t.Fatalf("list body has PascalCase %s: %s", bad, body)
		}
	}

	// get
	greq := httptest.NewRequest(http.MethodGet,
		"/api/v1/tenants/"+tenantID.String()+"/ai/suggestions/"+created.ID.String(), nil)
	greq.SetPathValue("tenant_id", tenantID.String())
	greq.SetPathValue("id", created.ID.String())
	grec := httptest.NewRecorder()
	h.getSuggestion(grec, greq)
	if grec.Code != http.StatusOK {
		t.Fatalf("get status = %d; body=%s", grec.Code, grec.Body.String())
	}
	if !strings.Contains(grec.Body.String(), `"tenant_id":`) || strings.Contains(grec.Body.String(), `"TenantID"`) {
		t.Fatalf("get body not snake_case: %s", grec.Body.String())
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

var errStubPostureData = errors.New("stub posture data failure")

// stubPostureData is a test double for the PostureDataSource.
type stubPostureData struct {
	counts map[string]int
	err    error
}

func (s stubPostureData) AlertCountsBySeverity(_ context.Context, _ uuid.UUID, _, _ time.Time) (map[string]int, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.counts, nil
}

// trendPostureData returns distinct counts for the current vs previous
// window (distinguished by the query's end time) so a handler's
// period-over-period trend computation can be exercised.
type trendPostureData struct {
	current map[string]int
	prev    map[string]int
}

func (s trendPostureData) AlertCountsBySeverity(_ context.Context, _ uuid.UUID, _, end time.Time) (map[string]int, error) {
	// The current-window query ends at ~now; the previous-window query
	// ends at the current window's start (~7d ago).
	if time.Since(end) < time.Hour {
		return s.current, nil
	}
	return s.prev, nil
}

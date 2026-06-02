package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

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

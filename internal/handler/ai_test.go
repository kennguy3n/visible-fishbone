package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

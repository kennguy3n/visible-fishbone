package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

// stubLLM is a deterministic LLM stub for testing.
type stubLLM struct {
	text    string
	err     error
	modelID string
}

func (s *stubLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	if s.err != nil {
		return LLMResponse{}, s.err
	}
	return LLMResponse{
		Text:       s.text,
		ModelID:    s.modelID,
		TokenCount: 42,
	}, nil
}

// stubEvidence is a deterministic EvidenceReader for testing.
type stubEvidence struct {
	data TemplateData
	err  error
}

func (s *stubEvidence) QueryEvidence(_ context.Context, _ uuid.UUID, _ TimeRange) (TemplateData, error) {
	if s.err != nil {
		return TemplateData{}, s.err
	}
	return s.data, nil
}

func TestSummarizer_TemplateOnly(t *testing.T) {
	t.Parallel()
	evidence := &stubEvidence{data: TemplateData{
		AlertCount:    3,
		TopAlertKinds: []string{"brute_force"},
	}}
	s := NewSummarizer(nil, evidence)
	tr := TimeRange{
		Start: time.Now().Add(-24 * time.Hour),
		End:   time.Now(),
	}
	summary, err := s.Generate(context.Background(), uuid.New(), tr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.AIGenerated {
		t.Fatal("template-only mode must set ai_generated=false")
	}
	if summary.Text == "" {
		t.Fatal("expected non-empty summary text")
	}
}

func TestSummarizer_LLMPolishes(t *testing.T) {
	t.Parallel()
	evidence := &stubEvidence{data: TemplateData{AlertCount: 1}}
	llm := &stubLLM{text: "polished summary text", modelID: "test-model"}
	s := NewSummarizer(llm, evidence)
	tr := TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now(),
	}
	summary, err := s.Generate(context.Background(), uuid.New(), tr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !summary.AIGenerated {
		t.Fatal("LLM-polished output must set ai_generated=true")
	}
	if summary.ModelID != "test-model" {
		t.Fatalf("expected model_id=test-model, got: %s", summary.ModelID)
	}
	if summary.Text != "polished summary text" {
		t.Fatalf("expected polished text, got: %s", summary.Text)
	}
}

func TestSummarizer_LLMFallback(t *testing.T) {
	t.Parallel()
	evidence := &stubEvidence{data: TemplateData{
		AlertCount:    2,
		TopAlertKinds: []string{"anomaly"},
	}}
	llm := &stubLLM{err: errors.New("LLM timeout")}
	s := NewSummarizer(llm, evidence)
	tr := TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now(),
	}
	summary, err := s.Generate(context.Background(), uuid.New(), tr)
	if err != nil {
		t.Fatalf("expected graceful fallback, got error: %v", err)
	}
	if summary.AIGenerated {
		t.Fatal("fallback to template must set ai_generated=false")
	}
	if summary.Text == "" {
		t.Fatal("expected non-empty template text on fallback")
	}
}

func TestSummarizer_EvidenceError(t *testing.T) {
	t.Parallel()
	evidence := &stubEvidence{err: errors.New("clickhouse down")}
	s := NewSummarizer(nil, evidence)
	tr := TimeRange{
		Start: time.Now().Add(-1 * time.Hour),
		End:   time.Now(),
	}
	_, err := s.Generate(context.Background(), uuid.New(), tr)
	if err == nil {
		t.Fatal("expected error when evidence reader fails")
	}
}

func TestSummarizer_AIGeneratedFlagConsistency(t *testing.T) {
	t.Parallel()
	evidence := &stubEvidence{data: TemplateData{}}

	// Template-only mode.
	s1 := NewSummarizer(nil, evidence)
	tr := TimeRange{Start: time.Now().Add(-time.Hour), End: time.Now()}
	sum1, _ := s1.Generate(context.Background(), uuid.New(), tr)
	if sum1.AIGenerated {
		t.Fatal("template-only: ai_generated must be false")
	}

	// LLM success.
	s2 := NewSummarizer(&stubLLM{text: "ok", modelID: "m"}, evidence)
	sum2, _ := s2.Generate(context.Background(), uuid.New(), tr)
	if !sum2.AIGenerated {
		t.Fatal("LLM success: ai_generated must be true")
	}

	// LLM failure.
	s3 := NewSummarizer(&stubLLM{err: errors.New("fail")}, evidence)
	sum3, _ := s3.Generate(context.Background(), uuid.New(), tr)
	if sum3.AIGenerated {
		t.Fatal("LLM failure: ai_generated must be false (fallback to template)")
	}
}

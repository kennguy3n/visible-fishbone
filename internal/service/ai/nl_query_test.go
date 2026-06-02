package ai

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestNLQueryEngine_EmptyQuestion(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	_, err := engine.Query(context.Background(), NLQueryRequest{
		TenantID: uuid.New(),
	})
	if err == nil {
		t.Fatal("expected error for empty question")
	}
}

func TestNLQueryEngine_StructuredParsing(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow verdict, got %s", resp.Verdict)
	}
	if resp.AIGenerated {
		t.Fatal("no LLM: ai_generated must be false")
	}
	if len(resp.MatchedRules) == 0 {
		t.Fatal("expected matched rules")
	}
}

func TestNLQueryEngine_StructuredParsingBlock(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "block user admin from app internal",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "deny" {
		t.Fatalf("expected deny verdict, got %s", resp.Verdict)
	}
}

func TestNLQueryEngine_NoEntities(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "what is the weather?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "unknown" {
		t.Fatalf("expected unknown verdict, got %s", resp.Verdict)
	}
	if resp.Confidence >= 0.5 {
		t.Fatalf("expected low confidence, got %f", resp.Confidence)
	}
}

func TestNLQueryEngine_WithLLM(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{
		text:    `{"user_ref": "alice", "app_ref": "salesforce", "device_ref": "laptop1", "action": "access"}`,
		modelID: "test-model",
	}
	engine := NewNLQueryEngine(llm)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can alice access salesforce from laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow, got %s", resp.Verdict)
	}
	if !resp.AIGenerated {
		t.Fatal("expected ai_generated=true with LLM")
	}
	if resp.ModelID != "test-model" {
		t.Fatalf("expected model_id=test-model, got %s", resp.ModelID)
	}
	if resp.Confidence < 0.7 {
		t.Fatalf("expected high confidence with LLM, got %f", resp.Confidence)
	}
}

func TestNLQueryEngine_LLMFallback(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{
		err: context.DeadlineExceeded,
	}
	engine := NewNLQueryEngine(llm)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user bob access app github?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to structured parsing.
	if resp.AIGenerated {
		t.Fatal("LLM failed: ai_generated should be false")
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow from structured fallback, got %s", resp.Verdict)
	}
}

// --- test stubs ---

type nlQueryStubLLM struct {
	text    string
	modelID string
	err     error
}

func (s *nlQueryStubLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	if s.err != nil {
		return LLMResponse{}, s.err
	}
	return LLMResponse{Text: s.text, ModelID: s.modelID, TokenCount: 30}, nil
}

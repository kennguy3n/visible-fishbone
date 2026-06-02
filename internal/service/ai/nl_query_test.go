package ai

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
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

func TestNLQueryEngine_DefaultHeuristicModeWhenNoSource(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.EvaluationMode != evalModeDefaultHeuristic {
		t.Fatalf("expected mode %q, got %q", evalModeDefaultHeuristic, resp.EvaluationMode)
	}
	if resp.MatchedRules[0] != "default-policy" {
		t.Fatalf("expected default-policy matched rule, got %v", resp.MatchedRules)
	}
}

func TestNLQueryEngine_CompiledBundleAllow(t *testing.T) {
	t.Parallel()
	// SWG rule that allows the salesforce.com host; default deny.
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	src := &fakeGraphSource{graph: repository.PolicyGraph{ID: uuid.New(), Version: 3, Graph: json.RawMessage(graph)}}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow from compiled bundle, got %q", resp.Verdict)
	}
	if resp.EvaluationMode != evalModeCompiledBundle {
		t.Fatalf("expected mode %q, got %q", evalModeCompiledBundle, resp.EvaluationMode)
	}
	if len(resp.MatchedRules) == 0 || resp.MatchedRules[0] == "default-policy" {
		t.Fatalf("expected a policy-graph matched rule reference, got %v", resp.MatchedRules)
	}
	if resp.Confidence < 0.9 {
		t.Fatalf("expected high confidence for authoritative verdict, got %f", resp.Confidence)
	}
}

func TestNLQueryEngine_CompiledBundleDefaultDeny(t *testing.T) {
	t.Parallel()
	// Same graph, but the queried app doesn't match the allow rule,
	// so the graph's default action (deny) governs.
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	src := &fakeGraphSource{graph: repository.PolicyGraph{ID: uuid.New(), Version: 1, Graph: json.RawMessage(graph)}}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user bob access app evil.com from device laptop2?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "deny" {
		t.Fatalf("expected deny from default action, got %q", resp.Verdict)
	}
	if resp.EvaluationMode != evalModeCompiledBundle {
		t.Fatalf("expected mode %q, got %q", evalModeCompiledBundle, resp.EvaluationMode)
	}
}

func TestNLQueryEngine_NoLivePolicyFallsBack(t *testing.T) {
	t.Parallel()
	src := &fakeGraphSource{err: repository.ErrNotFound}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.EvaluationMode != evalModeNoPolicy {
		t.Fatalf("expected mode %q, got %q", evalModeNoPolicy, resp.EvaluationMode)
	}
	// Heuristic default applies (allow unless explicit block).
	if resp.Verdict != "allow" {
		t.Fatalf("expected heuristic allow, got %q", resp.Verdict)
	}
}

// --- test stubs ---

type fakeGraphSource struct {
	graph repository.PolicyGraph
	err   error
}

func (f *fakeGraphSource) GetCurrentGraph(_ context.Context, _ uuid.UUID) (repository.PolicyGraph, error) {
	if f.err != nil {
		return repository.PolicyGraph{}, f.err
	}
	return f.graph, nil
}

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

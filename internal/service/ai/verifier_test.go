package ai

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// fakeCompiler is a minimal PolicyCompiler for verifier tests.
type fakeCompiler struct {
	err error
}

func (f *fakeCompiler) PutGraph(_ context.Context, _ uuid.UUID, _ *uuid.UUID, _ json.RawMessage) (repository.PolicyGraph, error) {
	if f.err != nil {
		return repository.PolicyGraph{}, f.err
	}
	return repository.PolicyGraph{ID: uuid.New()}, nil
}

func TestVerifier_AcceptValidGraph(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&fakeCompiler{})
	suggestion := PolicySuggestion{
		Graph:       json.RawMessage(`{"rules":[]}`),
		Rationale:   "test",
		Confidence:  0.8,
		AIGenerated: true,
	}
	result, err := v.Verify(context.Background(), uuid.New(), suggestion)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if !result.DryRun.Compiled {
		t.Fatal("expected compiled=true")
	}
	if result.DryRun.GraphID == "" {
		t.Fatal("expected non-empty graph_id")
	}
	if !result.Suggestion.AIGenerated {
		t.Fatal("expected ai_generated=true preserved")
	}
}

func TestVerifier_RejectInvalidGraph(t *testing.T) {
	t.Parallel()
	compileErr := errors.New("compile error: invalid rule")
	v := NewVerifier(&fakeCompiler{err: compileErr})
	suggestion := PolicySuggestion{
		Graph:       json.RawMessage(`{"bad":"graph"}`),
		Rationale:   "test",
		AIGenerated: true,
	}
	_, err := v.Verify(context.Background(), uuid.New(), suggestion)
	if err == nil {
		t.Fatal("expected error for invalid graph")
	}
	if !errors.Is(err, compileErr) {
		t.Fatalf("expected compile error wrapped, got: %v", err)
	}
}

func TestVerifier_EmptyGraph(t *testing.T) {
	t.Parallel()
	v := NewVerifier(&fakeCompiler{})
	_, err := v.Verify(context.Background(), uuid.New(), PolicySuggestion{})
	if err == nil {
		t.Fatal("expected error for empty graph")
	}
}

func TestVerifier_NilCompiler(t *testing.T) {
	t.Parallel()
	v := NewVerifier(nil)
	_, err := v.Verify(context.Background(), uuid.New(), PolicySuggestion{
		Graph: json.RawMessage(`{}`),
	})
	if err == nil {
		t.Fatal("expected error for nil compiler")
	}
}

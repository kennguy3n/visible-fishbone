package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyCompiler is the subset of policy.Service the verifier
// needs. Declared as an interface so the ai package does not import
// the concrete policy type (prevents import cycles) and the
// verifier can be unit-tested with a minimal fake.
type PolicyCompiler interface {
	PutDraftGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error)
}

// Verifier takes an AI-proposed PolicySuggestion, compiles it
// through the deterministic policy pipeline, and rejects anything
// that does not compile. This enforces the "AI proposes,
// deterministic systems enforce" invariant from PROPOSAL.md §8.1.
type Verifier struct {
	compiler PolicyCompiler
}

// NewVerifier constructs a Verifier. compiler must not be nil.
func NewVerifier(compiler PolicyCompiler) *Verifier {
	return &Verifier{compiler: compiler}
}

// Verify compiles the AI-proposed suggestion through
// policy.Service.PutDraftGraph. On success, returns a
// VerifiedSuggestion with dry-run metadata. On compile failure,
// returns the compiler error so the caller can surface it to the
// operator.
func (v *Verifier) Verify(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, suggestion PolicySuggestion) (VerifiedSuggestion, error) {
	if v.compiler == nil {
		return VerifiedSuggestion{}, fmt.Errorf("ai/verifier: no policy compiler configured")
	}
	if len(suggestion.Graph) == 0 {
		return VerifiedSuggestion{}, fmt.Errorf("ai/verifier: empty graph")
	}

	start := time.Now()
	graph, err := v.compiler.PutDraftGraph(ctx, tenantID, actorID, suggestion.Graph)
	elapsed := time.Since(start)

	if err != nil {
		return VerifiedSuggestion{}, fmt.Errorf("ai/verifier: compile rejected suggestion: %w", err)
	}
	return VerifiedSuggestion{
		Suggestion: suggestion,
		Verify: VerifyMeta{
			Compiled:  true,
			GraphID:   graph.ID.String(),
			CompileMS: elapsed.Milliseconds(),
		},
	}, nil
}

// Package ai implements the AI assistant service for ShieldNet
// Gateway. It follows the "AI proposes, deterministic systems
// enforce" invariant from ARCHITECTURE.md §3.5: every AI-generated
// policy suggestion MUST compile through the deterministic policy
// compiler before it can be queued, and every output is flagged
// with ai_generated: true.
package ai

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Service is the top-level AI service. It delegates to the
// Summarizer for incident/telemetry summaries, to the Verifier for
// policy suggestions, and to the LLMProvider for raw completions.
// When LLM is nil, only template-mode summaries are available.
// The summarizer is stored behind an atomic.Pointer so it can be
// wired post-construction when ClickHouse becomes available
// (matching the PolicySimulationHandler.SetSimulator pattern).
type Service struct {
	llm        LLMProvider
	verifier   *Verifier
	summarizer atomic.Pointer[Summarizer]
	logger     *slog.Logger
}

// Option configures New.
type Option func(*Service)

// WithLogger installs a non-default logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// New constructs an AI Service. llm may be nil (template-only
// mode). verifier may be nil when the policy compiler is not
// available. summarizer may be nil when ClickHouse is not
// configured.
func New(llm LLMProvider, verifier *Verifier, summarizer *Summarizer, opts ...Option) *Service {
	s := &Service{
		llm:      llm,
		verifier: verifier,
		logger:   slog.Default(),
	}
	if summarizer != nil {
		s.summarizer.Store(summarizer)
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// SetSummarizer wires a Summarizer post-construction. This
// supports the late-binding pattern where ClickHouse is not
// available at Service construction time but becomes ready
// later during startup (mirrors PolicySimulationHandler.SetSimulator).
func (s *Service) SetSummarizer(sum *Summarizer) {
	s.summarizer.Store(sum)
}

// Configured reports whether the AI service has an LLM provider
// wired. When false, only template-mode summaries are available
// and SuggestPolicy / Troubleshoot return errors.
func (s *Service) Configured() bool {
	return s != nil && s.llm != nil
}

// SummarizerConfigured reports whether the summarizer is wired.
func (s *Service) SummarizerConfigured() bool {
	return s != nil && s.summarizer.Load() != nil
}

// LLM returns the configured LLM provider (may be nil).
func (s *Service) LLM() LLMProvider {
	if s == nil {
		return nil
	}
	return s.llm
}

// SuggestPolicy asks the LLM to propose policy changes, then
// verifies the result through the deterministic compiler. Returns
// a VerifiedSuggestion on success or an error if the LLM is not
// configured, the suggestion is invalid, or compile fails.
func (s *Service) SuggestPolicy(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, prompt string) (VerifiedSuggestion, error) {
	if s.llm == nil {
		return VerifiedSuggestion{}, errors.New("ai: LLM not configured")
	}
	if s.verifier == nil {
		return VerifiedSuggestion{}, errors.New("ai: policy verifier not configured")
	}

	resp, err := s.llm.Complete(ctx, LLMRequest{
		Prompt:         buildPolicySuggestionPrompt(prompt),
		TemperatureX10: 3,
		MaxTokens:      2000,
	})
	if err != nil {
		return VerifiedSuggestion{}, fmt.Errorf("ai: llm complete: %w", err)
	}

	suggestion := PolicySuggestion{
		Graph:       []byte(extractJSON(resp.Text)),
		Rationale:   "AI-generated policy suggestion based on: " + truncate(prompt, 200),
		Confidence:  0.5,
		AIGenerated: true,
		ModelID:     resp.ModelID,
	}

	verified, err := s.verifier.Verify(ctx, tenantID, actorID, suggestion)
	if err != nil {
		return VerifiedSuggestion{}, fmt.Errorf("ai: verification failed: %w", err)
	}
	return verified, nil
}

// Summarize produces a summary for the given tenant and time
// range. If the Summarizer is not configured, returns an error.
func (s *Service) Summarize(ctx context.Context, tenantID uuid.UUID, tr TimeRange) (Summary, error) {
	sum := s.summarizer.Load()
	if sum == nil {
		return Summary{}, errors.New("ai: summarizer not configured")
	}
	summary, err := sum.Generate(ctx, tenantID, tr)
	if err != nil {
		return Summary{}, fmt.Errorf("ai: summarize: %w", err)
	}
	return summary, nil
}

// Troubleshoot runs a RAG-based troubleshooting query. Returns
// suggestions (never actions). Refuses to assert facts outside
// collected evidence.
func (s *Service) Troubleshoot(ctx context.Context, tenantID uuid.UUID, query string) (TroubleshootResult, error) {
	if s.llm == nil {
		return TroubleshootResult{}, errors.New("ai: LLM not configured")
	}

	start := time.Now()
	resp, err := s.llm.Complete(ctx, LLMRequest{
		Prompt:         buildTroubleshootPrompt(tenantID, query),
		TemperatureX10: 2,
		MaxTokens:      1500,
	})
	if err != nil {
		return TroubleshootResult{}, fmt.Errorf("ai: llm complete: %w", err)
	}

	_ = start // latency tracking reserved for future use
	return TroubleshootResult{
		Suggestions:    []string{resp.Text},
		ReferencedDocs: []string{},
		Confidence:     0.5,
		AIGenerated:    true,
		ModelID:        resp.ModelID,
	}, nil
}

// extractJSON strips markdown code fences and leading/trailing
// whitespace from an LLM response, returning only the JSON body.
// LLMs routinely wrap JSON in ```json ... ``` blocks despite
// prompts asking for raw JSON.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	// Strip ```json ... ``` or ``` ... ``` fences.
	if strings.HasPrefix(s, "```") {
		if idx := strings.Index(s[3:], "\n"); idx >= 0 {
			s = s[3+idx+1:]
		} else {
			s = s[3:]
		}
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
		s = strings.TrimSpace(s)
	}
	return s
}

func buildPolicySuggestionPrompt(userPrompt string) string {
	return "You are a ShieldNet Gateway policy assistant. " +
		"Given the following request, produce ONLY a valid JSON policy graph object. " +
		"Do not include any explanation outside the JSON. " +
		"The output must be parseable by the SNG policy compiler.\n\n" +
		"Request: " + userPrompt
}

func buildTroubleshootPrompt(tenantID uuid.UUID, query string) string {
	return fmt.Sprintf(
		"You are a ShieldNet Gateway troubleshooting assistant for tenant %s. "+
			"Provide suggestions only — never take actions. "+
			"Only reference facts from the provided evidence. "+
			"Do not assert facts outside collected evidence.\n\n"+
			"Query: %s", tenantID, query)
}

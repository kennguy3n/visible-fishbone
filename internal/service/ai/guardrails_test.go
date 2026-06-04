package ai

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGuardrailedProvider_PassThrough(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "response", modelID: "test"}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 10,
		MaxTokensPerDay:      1000,
	}, nil)

	ctx := ContextWithTenantID(context.Background(), uuid.New())
	resp, err := gp.Complete(ctx, LLMRequest{Prompt: "hello", MaxTokens: 100})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Text != "response" {
		t.Fatalf("expected 'response', got %q", resp.Text)
	}
	if resp.ModelID != "test" {
		t.Fatalf("expected model_id 'test', got %q", resp.ModelID)
	}
}

func TestGuardrailedProvider_RateLimiting(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test"}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 2,
		MaxTokensPerDay:      100000,
	}, nil)

	tenantID := uuid.New()
	ctx := ContextWithTenantID(context.Background(), tenantID)

	// First two should succeed.
	for i := 0; i < 2; i++ {
		_, err := gp.Complete(ctx, LLMRequest{Prompt: "test"})
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
	}

	// Third should be rate limited.
	_, err := gp.Complete(ctx, LLMRequest{Prompt: "test"})
	if err == nil {
		t.Fatal("expected rate limit error")
	}
}

func TestGuardrailedProvider_ContentFiltering(t *testing.T) {
	t.Parallel()
	var capturedPrompt string
	inner := &capturingLLM{
		resp: LLMResponse{Text: "safe response", ModelID: "test", TokenCount: 10},
		capture: func(req LLMRequest) {
			capturedPrompt = req.Prompt
		},
	}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 100,
		MaxTokensPerDay:      100000,
	}, nil)

	ctx := ContextWithTenantID(context.Background(), uuid.New())
	_, err := gp.Complete(ctx, LLMRequest{
		Prompt: "User email is admin@example.com and SSN is 123-45-6789",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify PII was redacted.
	if capturedPrompt == "" {
		t.Fatal("prompt was not captured")
	}
	if contains(capturedPrompt, "admin@example.com") {
		t.Fatal("email was not redacted")
	}
	if contains(capturedPrompt, "123-45-6789") {
		t.Fatal("SSN was not redacted")
	}
}

func TestGuardrailedProvider_AuditLogging(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test"}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 100,
		MaxTokensPerDay:      100000,
	}, nil)

	tenantID := uuid.New()
	ctx := ContextWithTenantID(context.Background(), tenantID)
	_, _ = gp.Complete(ctx, LLMRequest{Prompt: "hello"})

	log := gp.AuditLog()
	if len(log) != 1 {
		t.Fatalf("expected 1 audit record, got %d", len(log))
	}
	if log[0].TenantID != tenantID {
		t.Fatal("tenant_id mismatch in audit log")
	}
	if log[0].Action != "complete" {
		t.Fatalf("expected action 'complete', got %q", log[0].Action)
	}
}

func TestGuardrailedProvider_DurableAuditSink(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test"}
	sink := &stubAuditSink{}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 100,
		MaxTokensPerDay:      100000,
	}, nil, WithAuditSink(sink))

	tenantID := uuid.New()
	ctx := ContextWithTenantID(context.Background(), tenantID)
	if _, err := gp.Complete(ctx, LLMRequest{Prompt: "hello"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The durable sink must receive the same record that lands in the
	// in-memory ring buffer.
	got := sink.records()
	if len(got) != 1 {
		t.Fatalf("expected 1 durable audit record, got %d", len(got))
	}
	if got[0].TenantID != tenantID {
		t.Fatalf("durable sink tenant_id mismatch: got %s want %s", got[0].TenantID, tenantID)
	}
	if got[0].Action != "complete" {
		t.Fatalf("expected durable action 'complete', got %q", got[0].Action)
	}
	if got[0].Model != "test" {
		t.Fatalf("expected durable model 'test', got %q", got[0].Model)
	}
}

func TestGuardrailedProvider_DurableAuditSinkFailureDoesNotBreakCall(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test"}
	sink := &stubAuditSink{err: errStubSink}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 100,
		MaxTokensPerDay:      100000,
	}, nil, WithAuditSink(sink))

	ctx := ContextWithTenantID(context.Background(), uuid.New())
	// A failing durable sink must not surface as an error on the LLM
	// path: the completion itself succeeded.
	resp, err := gp.Complete(ctx, LLMRequest{Prompt: "hello"})
	if err != nil {
		t.Fatalf("sink failure must not break Complete: %v", err)
	}
	if resp.Text != "ok" {
		t.Fatalf("expected passthrough response, got %q", resp.Text)
	}
}

func TestGuardrailedProvider_Status(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test"}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 60,
		MaxTokensPerDay:      100000,
	}, nil)

	tenantID := uuid.New()
	ctx := ContextWithTenantID(context.Background(), tenantID)
	_, _ = gp.Complete(ctx, LLMRequest{Prompt: "test"})

	status := gp.Status(tenantID)
	if status.TenantID != tenantID {
		t.Fatal("tenant_id mismatch")
	}
	if status.RequestsThisMinute != 1 {
		t.Fatalf("expected 1 request, got %d", status.RequestsThisMinute)
	}
	if status.MaxRequestsPerMinute != 60 {
		t.Fatalf("expected max 60, got %d", status.MaxRequestsPerMinute)
	}
}

func TestGuardrailedProvider_TokenLimit(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test", tokenCount: 100}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 1000,
		MaxTokensPerDay:      100,
	}, nil)

	tenantID := uuid.New()
	ctx := ContextWithTenantID(context.Background(), tenantID)

	// First request uses 100 tokens.
	_, err := gp.Complete(ctx, LLMRequest{Prompt: "test"})
	if err != nil {
		t.Fatalf("first request: %v", err)
	}

	// Second request should exceed daily limit.
	_, err = gp.Complete(ctx, LLMRequest{Prompt: "test"})
	if err == nil {
		t.Fatal("expected token limit error")
	}
}

func TestGuardrailedProvider_EvictsStaleUsage(t *testing.T) {
	t.Parallel()
	inner := &guardrailStubLLM{text: "ok", modelID: "test"}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 60,
		MaxTokensPerDay:      100000,
	}, nil)

	// Seed an idle tenant whose last activity is well beyond usageTTL,
	// plus a recently-active tenant that must be retained.
	old := time.Now().Add(-2 * usageTTL)
	staleTenant := uuid.New()
	activeTenant := uuid.New()
	gp.mu.Lock()
	gp.usage[staleTenant] = &tenantUsage{minuteStart: old, dayStart: old}
	gp.usage[activeTenant] = &tenantUsage{minuteStart: time.Now(), dayStart: time.Now()}
	// Force the sweep to run on the next checkRateLimit call.
	gp.lastSweep = old
	gp.mu.Unlock()

	// A live request triggers the (rate-limited) eviction sweep.
	ctx := ContextWithTenantID(context.Background(), uuid.New())
	if _, err := gp.Complete(ctx, LLMRequest{Prompt: "hello"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gp.mu.Lock()
	_, staleExists := gp.usage[staleTenant]
	_, activeExists := gp.usage[activeTenant]
	gp.mu.Unlock()

	if staleExists {
		t.Fatal("stale tenant usage entry should have been evicted")
	}
	if !activeExists {
		t.Fatal("recently-active tenant usage entry must be retained")
	}
}

func TestValidateOutput(t *testing.T) {
	t.Parallel()
	if err := ValidateOutput(""); err == nil {
		t.Fatal("expected error for empty output")
	}
	if err := ValidateOutput("valid response"); err != nil {
		t.Fatalf("unexpected error for valid output: %v", err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// --- test stubs ---

type guardrailStubLLM struct {
	text       string
	modelID    string
	err        error
	tokenCount int
}

func (s *guardrailStubLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	if s.err != nil {
		return LLMResponse{}, s.err
	}
	tc := s.tokenCount
	if tc == 0 {
		tc = 42
	}
	return LLMResponse{Text: s.text, ModelID: s.modelID, TokenCount: tc}, nil
}

type capturingLLM struct {
	resp    LLMResponse
	capture func(LLMRequest)
}

func (c *capturingLLM) Complete(_ context.Context, req LLMRequest) (LLMResponse, error) {
	if c.capture != nil {
		c.capture(req)
	}
	return c.resp, nil
}

var errStubSink = errors.New("stub sink failure")

// stubAuditSink is a test double for the durable AuditSink.
type stubAuditSink struct {
	err error

	mu   sync.Mutex
	recs []AuditRecord
}

func (s *stubAuditSink) RecordAIAudit(_ context.Context, rec AuditRecord) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	s.recs = append(s.recs, rec)
	s.mu.Unlock()
	return nil
}

func (s *stubAuditSink) records() []AuditRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AuditRecord, len(s.recs))
	copy(out, s.recs)
	return out
}

// --- cost-metering budget gate / usage recorder (Session K) -------------

var errBudgetExceededStub = errors.New("budget_exceeded: llm_tokens_used hard limit reached")

// stubBudgetGate fails the budget check when blocked is true.
type stubBudgetGate struct {
	blocked bool
	calls   int
}

func (g *stubBudgetGate) CheckLLMTokenBudget(_ context.Context, _ uuid.UUID, _ int64) error {
	g.calls++
	if g.blocked {
		return errBudgetExceededStub
	}
	return nil
}

// stubUsageRecorder records the metered tokens/calls of each completion.
type stubUsageRecorder struct {
	mu     sync.Mutex
	tokens int64
	calls  int64
}

func (r *stubUsageRecorder) RecordLLMUsage(_ context.Context, _ uuid.UUID, tokens, calls int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokens += tokens
	r.calls += calls
	return nil
}

// countingLLM records how many times Complete is invoked.
type countingLLM struct {
	calls int
}

func (c *countingLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	c.calls++
	return LLMResponse{Text: "model output", ModelID: "test", TokenCount: 100}, nil
}

func TestGuardrailedProvider_BudgetExceededReturnsTemplateFallback(t *testing.T) {
	t.Parallel()
	inner := &countingLLM{}
	gate := &stubBudgetGate{blocked: true}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 10,
		MaxTokensPerDay:      100000,
	}, nil, WithBudgetGate(gate))

	ctx := ContextWithTenantID(context.Background(), uuid.New())
	resp, err := gp.Complete(ctx, LLMRequest{Prompt: "summarise this alert", MaxTokens: 200})
	if err != nil {
		t.Fatalf("budget fallback must not be an error: %v", err)
	}
	if inner.calls != 0 {
		t.Fatalf("upstream LLM must NOT be called when budget is exceeded; got %d calls", inner.calls)
	}
	if resp.ModelID != budgetFallbackModelID {
		t.Fatalf("model_id = %q, want %q", resp.ModelID, budgetFallbackModelID)
	}
	if resp.TokenCount != 0 {
		t.Fatalf("fallback must spend 0 tokens, got %d", resp.TokenCount)
	}
	if resp.Text == "" {
		t.Fatal("fallback must carry a user-visible note")
	}
}

func TestGuardrailedProvider_BudgetWithinLimitCallsModelAndMeters(t *testing.T) {
	t.Parallel()
	inner := &countingLLM{}
	gate := &stubBudgetGate{blocked: false}
	rec := &stubUsageRecorder{}
	gp := NewGuardrailedProvider(inner, GuardrailConfig{
		MaxRequestsPerMinute: 10,
		MaxTokensPerDay:      100000,
	}, nil, WithBudgetGate(gate), WithUsageRecorder(rec))

	ctx := ContextWithTenantID(context.Background(), uuid.New())
	resp, err := gp.Complete(ctx, LLMRequest{Prompt: "hello", MaxTokens: 50})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("upstream LLM call count = %d, want 1", inner.calls)
	}
	if resp.ModelID != "test" {
		t.Fatalf("model_id = %q, want real model", resp.ModelID)
	}
	if gate.calls != 1 {
		t.Fatalf("budget gate call count = %d, want 1", gate.calls)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.tokens != 100 || rec.calls != 1 {
		t.Fatalf("metered usage = (tokens %d, calls %d), want (100, 1)", rec.tokens, rec.calls)
	}
}

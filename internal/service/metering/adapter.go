package metering

import (
	"context"
	"errors"

	"github.com/google/uuid"
)

// GuardrailBudgetGate adapts a *BudgetEnforcer onto the narrow
// BudgetGate interface the AI guardrails declare (see
// internal/service/ai/guardrails.go). It is the single seam where the
// generic per-meter budget check is specialised to the LLM-token meter
// the guardrails gate on before every completion. Kept here (rather
// than in cmd/sng-control) so it is unit-tested alongside the enforcer
// and reused by any future caller.
type GuardrailBudgetGate struct {
	enforcer *BudgetEnforcer
}

// NewGuardrailBudgetGate wraps an enforcer for use as an AI BudgetGate.
func NewGuardrailBudgetGate(enforcer *BudgetEnforcer) *GuardrailBudgetGate {
	return &GuardrailBudgetGate{enforcer: enforcer}
}

// CheckLLMTokenBudget returns a non-nil error (wrapping
// ErrBudgetExceeded) only when spending estimatedTokens would breach
// the tenant's hard LLM-token budget; a soft-limit crossing is allowed
// (and alerted inside the enforcer). A nil enforcer is treated as "no
// budgeting configured" and always allows.
func (g *GuardrailBudgetGate) CheckLLMTokenBudget(ctx context.Context, tenantID uuid.UUID, estimatedTokens int64) error {
	if g == nil || g.enforcer == nil {
		return nil
	}
	_, err := g.enforcer.CheckBudget(ctx, MeterLLMTokensUsed, tenantID, estimatedTokens)
	return err
}

// GuardrailUsageRecorder adapts a *MeteringService onto the AI
// UsageRecorder interface, metering a completed LLM call's token count
// and the call itself. Both meter writes are attempted; a combined
// error is returned (the guardrails log it and never surface it to the
// caller, so metering can never break the live LLM path).
type GuardrailUsageRecorder struct {
	svc *MeteringService
}

// NewGuardrailUsageRecorder wraps a MeteringService for use as an AI
// UsageRecorder.
func NewGuardrailUsageRecorder(svc *MeteringService) *GuardrailUsageRecorder {
	return &GuardrailUsageRecorder{svc: svc}
}

// RecordLLMUsage meters `tokens` against llm_tokens_used and `calls`
// against llm_calls. A nil service is a no-op.
func (r *GuardrailUsageRecorder) RecordLLMUsage(ctx context.Context, tenantID uuid.UUID, tokens, calls int64) error {
	if r == nil || r.svc == nil {
		return nil
	}
	tokenErr := r.svc.Record(ctx, tenantID, MeterLLMTokensUsed, tokens)
	callErr := r.svc.Record(ctx, tenantID, MeterLLMCalls, calls)
	return errors.Join(tokenErr, callErr)
}

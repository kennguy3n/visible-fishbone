package metering

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestGuardrailBudgetGateBlocksOnHardLimit(t *testing.T) {
	tid := uuid.New()
	cur := staticCurrent{values: map[Meter]int64{MeterLLMTokensUsed: 1_000_000}}
	enf := mustEnforcer(t, cur, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})
	gate := NewGuardrailBudgetGate(enf)

	// Starter token budget is 1,000,000/month; already at the cap, so
	// any additional spend is a hard breach.
	err := gate.CheckLLMTokenBudget(context.Background(), tid, 1)
	if err == nil || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
}

func TestGuardrailBudgetGateAllowsWithinBudget(t *testing.T) {
	tid := uuid.New()
	cur := staticCurrent{values: map[Meter]int64{MeterLLMTokensUsed: 10}}
	enf := mustEnforcer(t, cur, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})
	gate := NewGuardrailBudgetGate(enf)

	if err := gate.CheckLLMTokenBudget(context.Background(), tid, 100); err != nil {
		t.Fatalf("within budget should allow, got %v", err)
	}
}

func TestGuardrailBudgetGateNilIsNoop(t *testing.T) {
	var gate *GuardrailBudgetGate
	if err := gate.CheckLLMTokenBudget(context.Background(), uuid.New(), 100); err != nil {
		t.Fatalf("nil gate should allow, got %v", err)
	}
	if err := NewGuardrailBudgetGate(nil).CheckLLMTokenBudget(context.Background(), uuid.New(), 100); err != nil {
		t.Fatalf("gate over nil enforcer should allow, got %v", err)
	}
}

func TestGuardrailUsageRecorderMetersTokensAndCalls(t *testing.T) {
	store := newFakeStore()
	svc := mustService(t, store)
	rec := NewGuardrailUsageRecorder(svc)
	ctx := context.Background()
	tid := uuid.New()

	if err := rec.RecordLLMUsage(ctx, tid, 1500, 1); err != nil {
		t.Fatalf("RecordLLMUsage: %v", err)
	}
	if got := svc.Current(ctx, tid, MeterLLMTokensUsed); got != 1500 {
		t.Fatalf("tokens = %d, want 1500", got)
	}
	if got := svc.Current(ctx, tid, MeterLLMCalls); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
}

func TestGuardrailUsageRecorderNilIsNoop(t *testing.T) {
	var rec *GuardrailUsageRecorder
	if err := rec.RecordLLMUsage(context.Background(), uuid.New(), 1, 1); err != nil {
		t.Fatalf("nil recorder should be a no-op, got %v", err)
	}
}

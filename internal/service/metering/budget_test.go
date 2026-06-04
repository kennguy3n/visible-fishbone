package metering

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func mustEnforcer(t *testing.T, usage CurrentReader, store BudgetStore, tiers TierResolver, opts ...BudgetOption) *BudgetEnforcer {
	t.Helper()
	e, err := NewBudgetEnforcer(usage, store, tiers, nil, opts...)
	if err != nil {
		t.Fatalf("NewBudgetEnforcer: %v", err)
	}
	return e
}

func TestNewBudgetEnforcerValidatesDeps(t *testing.T) {
	store := newFakeStore()
	tiers := fakeTiers{tier: repository.TenantTierStarter}
	cur := staticCurrent{}
	if _, err := NewBudgetEnforcer(nil, store, tiers, nil); err == nil {
		t.Fatal("expected error for nil usage")
	}
	if _, err := NewBudgetEnforcer(cur, nil, tiers, nil); err == nil {
		t.Fatal("expected error for nil store")
	}
	if _, err := NewBudgetEnforcer(cur, store, nil, nil); err == nil {
		t.Fatal("expected error for nil tiers")
	}
}

func TestCheckBudgetTierDefaultHardLimit(t *testing.T) {
	tid := uuid.New()
	// Starter tier: 1000 LLM calls/month hard limit.
	cur := staticCurrent{values: map[Meter]int64{MeterLLMCalls: 999}}
	e := mustEnforcer(t, cur, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})
	ctx := context.Background()

	// 999 + 1 = 1000, exactly at the limit → allowed.
	dec, err := e.CheckBudget(ctx, MeterLLMCalls, tid, 1)
	if err != nil {
		t.Fatalf("at-limit check: %v", err)
	}
	if !dec.Allowed || dec.HardExceeded {
		t.Fatalf("at limit should be allowed: %+v", dec)
	}
	// 999 + 2 = 1001 > 1000 → hard exceeded, wrapped sentinel.
	dec, err = e.CheckBudget(ctx, MeterLLMCalls, tid, 2)
	if err == nil || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("expected ErrBudgetExceeded, got %v", err)
	}
	if dec.Allowed || !dec.HardExceeded {
		t.Fatalf("over limit should be rejected: %+v", dec)
	}
}

func TestCheckBudgetSoftLimitAllowsButFlags(t *testing.T) {
	tid := uuid.New()
	// Starter url_cat: hard 100000/day → derived soft = 80000.
	cur := staticCurrent{values: map[Meter]int64{MeterURLCatLookups: 80_000}}
	e := mustEnforcer(t, cur, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})

	dec, err := e.CheckBudget(context.Background(), MeterURLCatLookups, tid, 1)
	if err != nil {
		t.Fatalf("soft-exceed must not error: %v", err)
	}
	if !dec.Allowed {
		t.Fatal("soft exceed must remain allowed")
	}
	if !dec.SoftExceeded {
		t.Fatal("expected SoftExceeded")
	}
	if e.Stats().SoftAlerts != 1 {
		t.Fatalf("SoftAlerts = %d, want 1", e.Stats().SoftAlerts)
	}
}

func TestCheckBudgetUnknownMeterUnbounded(t *testing.T) {
	tid := uuid.New()
	// s3_bytes_archived has no tier default and no override → unbounded.
	cur := staticCurrent{values: map[Meter]int64{MeterS3BytesArchived: 1 << 40}}
	e := mustEnforcer(t, cur, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})

	dec, err := e.CheckBudget(context.Background(), MeterS3BytesArchived, tid, 1<<30)
	if err != nil {
		t.Fatalf("unbounded meter must not error: %v", err)
	}
	if !dec.Allowed {
		t.Fatal("unbounded meter must be allowed")
	}
}

func TestCheckBudgetRejectsBadInput(t *testing.T) {
	e := mustEnforcer(t, staticCurrent{}, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})
	if _, err := e.CheckBudget(context.Background(), MeterLLMCalls, uuid.Nil, 1); err == nil {
		t.Fatal("expected error for nil tenant")
	}
	if _, err := e.CheckBudget(context.Background(), Meter("bogus"), uuid.New(), 1); err == nil {
		t.Fatal("expected error for unknown meter")
	}
}

func TestTenantOverrideTakesPrecedenceOverTier(t *testing.T) {
	tid := uuid.New()
	store := newFakeStore()
	// Override the starter 1000-call limit down to 10.
	_ = store.UpsertTenantBudget(context.Background(), tid, BudgetLimit{
		Meter: MeterLLMCalls, HardLimit: 10, Period: PeriodMonthly,
	})
	cur := staticCurrent{values: map[Meter]int64{MeterLLMCalls: 10}}
	e := mustEnforcer(t, cur, store, fakeTiers{tier: repository.TenantTierStarter})

	_, err := e.CheckBudget(context.Background(), MeterLLMCalls, tid, 1)
	if err == nil || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("override of 10 should reject the 11th call, got %v", err)
	}
}

func TestGlobalDefaultsFallback(t *testing.T) {
	tid := uuid.New()
	// No tier default for malware_scans; supply a global default.
	cur := staticCurrent{values: map[Meter]int64{MeterMalwareScans: 5}}
	e := mustEnforcer(t, cur, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter},
		WithGlobalDefaults(map[string]int64{string(MeterMalwareScans): 5}))

	_, err := e.CheckBudget(context.Background(), MeterMalwareScans, tid, 1)
	if err == nil || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("global default of 5 should reject the 6th scan, got %v", err)
	}
}

func TestSetTenantBudgetValidation(t *testing.T) {
	e := mustEnforcer(t, staticCurrent{}, newFakeStore(), fakeTiers{tier: repository.TenantTierStarter})
	ctx := context.Background()
	tid := uuid.New()

	if err := e.SetTenantBudget(ctx, uuid.Nil, BudgetLimit{Meter: MeterLLMCalls, HardLimit: 1}); err == nil {
		t.Fatal("expected error for nil tenant")
	}
	if err := e.SetTenantBudget(ctx, tid, BudgetLimit{Meter: Meter("nope"), HardLimit: 1}); err == nil {
		t.Fatal("expected error for unknown meter")
	}
	if err := e.SetTenantBudget(ctx, tid, BudgetLimit{Meter: MeterLLMCalls, HardLimit: -1}); err == nil {
		t.Fatal("expected error for negative limit")
	}
	if err := e.SetTenantBudget(ctx, tid, BudgetLimit{Meter: MeterLLMCalls, SoftLimit: 10, HardLimit: 5}); err == nil {
		t.Fatal("expected error for soft > hard")
	}
}

func TestSetTenantBudgetInvalidatesCache(t *testing.T) {
	tid := uuid.New()
	store := newFakeStore()
	cur := staticCurrent{values: map[Meter]int64{MeterLLMCalls: 50}}
	e := mustEnforcer(t, cur, store, fakeTiers{tier: repository.TenantTierStarter})
	ctx := context.Background()

	// Prime the cache (starter allows 1000 calls).
	if _, err := e.CheckBudget(ctx, MeterLLMCalls, tid, 1); err != nil {
		t.Fatalf("initial check: %v", err)
	}
	// Tighten to 50 — must take effect immediately, not after TTL.
	if err := e.SetTenantBudget(ctx, tid, BudgetLimit{Meter: MeterLLMCalls, HardLimit: 50, Period: PeriodMonthly}); err != nil {
		t.Fatalf("SetTenantBudget: %v", err)
	}
	_, err := e.CheckBudget(ctx, MeterLLMCalls, tid, 1)
	if err == nil || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("tightened limit should reject immediately, got %v", err)
	}
}

func TestResolveLimitsCacheTTLExpiry(t *testing.T) {
	tid := uuid.New()
	store := newFakeStore()
	cur := staticCurrent{values: map[Meter]int64{MeterLLMCalls: 0}}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tiers := fakeTiers{byTenant: map[uuid.UUID]repository.TenantTier{tid: repository.TenantTierStarter}}
	e := mustEnforcer(t, cur, store, tiers, withBudgetClock(func() time.Time { return clock }))
	ctx := context.Background()

	budgets, err := e.TenantBudgets(ctx, tid)
	if err != nil {
		t.Fatalf("TenantBudgets: %v", err)
	}
	if budgets[MeterLLMCalls].HardLimit != 1000 {
		t.Fatalf("starter llm_calls hard = %d, want 1000", budgets[MeterLLMCalls].HardLimit)
	}
	// Change tier out-of-band (the resolver's byTenant map is shared by
	// reference with the enforcer's copy) and advance past the TTL so the
	// next resolve reloads and reflects the new enterprise limits.
	tiers.byTenant[tid] = repository.TenantTierEnterprise
	clock = clock.Add(cacheTTL + time.Minute)
	budgets, err = e.TenantBudgets(ctx, tid)
	if err != nil {
		t.Fatalf("TenantBudgets reload: %v", err)
	}
	if budgets[MeterLLMCalls].HardLimit != 20000 {
		t.Fatalf("enterprise llm_calls hard = %d, want 20000", budgets[MeterLLMCalls].HardLimit)
	}
}

func TestResolveLimitsFallsBackToStaleCacheOnError(t *testing.T) {
	tid := uuid.New()
	store := newFakeStore()
	cur := staticCurrent{values: map[Meter]int64{MeterLLMCalls: 1500}}
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := mustEnforcer(t, cur, store, fakeTiers{tier: repository.TenantTierStarter},
		withBudgetClock(func() time.Time { return clock }))
	ctx := context.Background()

	// Prime the cache with the starter limit (1000). The check itself
	// reports over-limit (used 1500 > 1000); we only care that it
	// populated the cache as a side effect.
	_, _ = e.CheckBudget(ctx, MeterLLMCalls, tid, 1)
	// Now make the store fail and expire the cache.
	store.failTenantBudgets = errors.New("db down")
	clock = clock.Add(cacheTTL + time.Minute)
	// Reload fails → falls back to the stale cached limit (still 1000),
	// so the over-limit usage is still correctly rejected rather than
	// the check fataling or going unbounded.
	_, err := e.CheckBudget(ctx, MeterLLMCalls, tid, 1)
	if err == nil || !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("stale-cache fallback should still enforce, got %v", err)
	}
}

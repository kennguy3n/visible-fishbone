package telemetry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

func TestNewTenantLimit_Rejects(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		rate  rate.Limit
		burst int
	}{
		{"zero rate", 0, 10},
		{"negative rate", -1, 10},
		{"zero burst", 1, 0},
		{"negative burst", 1, -1},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewTenantLimit(tc.rate, tc.burst); err == nil {
				t.Fatalf("expected error for rate=%v burst=%d", tc.rate, tc.burst)
			}
		})
	}
}

func TestNewTenantLimit_Ok(t *testing.T) {
	t.Parallel()
	lim, err := NewTenantLimit(10, 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lim.Rate != 10 || lim.Burst != 5 {
		t.Fatalf("got %+v", lim)
	}
}

func TestStaticLimitResolver_AlwaysReturnsConfigured(t *testing.T) {
	t.Parallel()
	want := TenantLimit{Rate: 1, Burst: 1}
	r := StaticLimitResolver{Limit: want}
	for i := 0; i < 5; i++ {
		got := r.Resolve(context.Background(), uuid.New())
		if got != want {
			t.Fatalf("call %d: got %+v want %+v", i, got, want)
		}
	}
}

func TestMapLimitResolver_FallbackAndOverride(t *testing.T) {
	t.Parallel()
	fallback := TenantLimit{Rate: 10, Burst: 5}
	r := NewMapLimitResolver(fallback)

	tenantA := uuid.New()
	if got := r.Resolve(context.Background(), tenantA); got != fallback {
		t.Fatalf("pre-override: got %+v want %+v", got, fallback)
	}

	override := TenantLimit{Rate: 100, Burst: 50}
	r.SetTenant(tenantA, override)
	if got := r.Resolve(context.Background(), tenantA); got != override {
		t.Fatalf("post-override: got %+v want %+v", got, override)
	}

	tenantB := uuid.New()
	if got := r.Resolve(context.Background(), tenantB); got != fallback {
		t.Fatalf("untouched tenant: got %+v want %+v", got, fallback)
	}

	// uuid.Nil updates the fallback.
	newFallback := TenantLimit{Rate: 20, Burst: 10}
	r.SetTenant(uuid.Nil, newFallback)
	if got := r.Resolve(context.Background(), tenantB); got != newFallback {
		t.Fatalf("after fallback update: got %+v want %+v", got, newFallback)
	}
}

func TestPerTenantLimiter_AllowsBurst(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		Limit: TenantLimit{Rate: 1, Burst: 5},
	})
	tenant := uuid.New()
	for i := 0; i < 5; i++ {
		if !l.Allow(context.Background(), tenant) {
			t.Fatalf("burst[%d] should be allowed", i)
		}
	}
	if l.Allow(context.Background(), tenant) {
		t.Fatalf("post-burst Allow should be false (bucket empty)")
	}
}

func TestPerTenantLimiter_WaitBlocksUntilTokenAvailable(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		// One token per 20ms; burst=1 so the second Wait blocks.
		Limit: TenantLimit{Rate: rate.Every(20 * time.Millisecond), Burst: 1},
	})
	tenant := uuid.New()
	// First Wait consumes the burst immediately.
	if err := l.WaitWithBudget(context.Background(), tenant, 200*time.Millisecond); err != nil {
		t.Fatalf("first wait: %v", err)
	}
	start := time.Now()
	if err := l.WaitWithBudget(context.Background(), tenant, 200*time.Millisecond); err != nil {
		t.Fatalf("second wait: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 10*time.Millisecond {
		t.Fatalf("second wait returned too fast (%s) — expected ≥10ms", elapsed)
	}
}

func TestPerTenantLimiter_WaitTimesOut(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		// One token per second; burst=1 so the second Wait
		// blocks for ~1s. We give it 10ms — should reject.
		Limit: TenantLimit{Rate: 1, Burst: 1},
	})
	tenant := uuid.New()
	if err := l.WaitWithBudget(context.Background(), tenant, 10*time.Millisecond); err != nil {
		t.Fatalf("priming wait: %v", err)
	}
	err := l.WaitWithBudget(context.Background(), tenant, 10*time.Millisecond)
	if !errors.Is(err, ErrTenantBlocked) {
		t.Fatalf("expected ErrTenantBlocked, got %v", err)
	}
}

func TestPerTenantLimiter_NilTenantRejected(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(nil)
	if l.Allow(context.Background(), uuid.Nil) {
		t.Fatalf("Allow(nil) must reject")
	}
	if err := l.Wait(context.Background(), uuid.Nil); !errors.Is(err, ErrTenantBlocked) {
		t.Fatalf("Wait(nil) must return ErrTenantBlocked, got %v", err)
	}
}

func TestPerTenantLimiter_InfiniteRateBypasses(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		Limit: TenantLimit{Rate: rate.Inf, Burst: 1},
	})
	tenant := uuid.New()
	for i := 0; i < 100; i++ {
		if !l.Allow(context.Background(), tenant) {
			t.Fatalf("rate.Inf should permit unbounded Allow calls (failed at %d)", i)
		}
		if err := l.Wait(context.Background(), tenant); err != nil {
			t.Fatalf("rate.Inf Wait should not block (failed at %d): %v", i, err)
		}
	}
}

func TestPerTenantLimiter_PerTenantIsolation(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		Limit: TenantLimit{Rate: 1, Burst: 2},
	})
	tenantA := uuid.New()
	tenantB := uuid.New()
	for i := 0; i < 2; i++ {
		if !l.Allow(context.Background(), tenantA) {
			t.Fatalf("tenantA burst[%d] should be allowed", i)
		}
	}
	if l.Allow(context.Background(), tenantA) {
		t.Fatalf("tenantA should be exhausted")
	}
	// tenantB has its own bucket, still has full burst.
	for i := 0; i < 2; i++ {
		if !l.Allow(context.Background(), tenantB) {
			t.Fatalf("tenantB burst[%d] should be allowed (independent bucket)", i)
		}
	}
}

func TestPerTenantLimiter_BudgetRefreshedFromResolver(t *testing.T) {
	t.Parallel()
	r := NewMapLimitResolver(TenantLimit{Rate: 1, Burst: 1})
	l := NewPerTenantLimiter(r)
	tenant := uuid.New()
	if !l.Allow(context.Background(), tenant) {
		t.Fatalf("initial burst should pass")
	}
	if l.Allow(context.Background(), tenant) {
		t.Fatalf("post-burst should fail")
	}
	// Raise the per-tenant budget; the next Allow should
	// observe the larger burst.
	r.SetTenant(tenant, TenantLimit{Rate: 10, Burst: 100})
	// The token bucket retained the previous reservations but
	// SetBurst raises the cap so further Allows succeed once
	// the bucket refills. With Rate=10 and Burst=100, the
	// bucket fills to 100 over ~10s, but Allow is non-blocking
	// — accept whichever side of the refill we land on.
	// Calling WaitWithBudget with a generous budget proves the
	// new limit took effect.
	if err := l.WaitWithBudget(context.Background(), tenant, time.Second); err != nil {
		t.Fatalf("wait after budget bump: %v", err)
	}
	snap := l.Snapshot()
	got, ok := snap[tenant]
	if !ok {
		t.Fatalf("tenant missing from snapshot")
	}
	if got.Burst != 100 {
		t.Fatalf("Snapshot did not reflect bumped burst: got %d", got.Burst)
	}
}

func TestPerTenantLimiter_ConcurrentTenants(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		Limit: TenantLimit{Rate: 1000, Burst: 1000},
	})
	const tenants = 50
	const callsPer = 50
	ids := make([]uuid.UUID, tenants)
	for i := range ids {
		ids[i] = uuid.New()
	}
	var wg sync.WaitGroup
	var ok int64
	for _, id := range ids {
		id := id
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < callsPer; j++ {
				if l.Allow(context.Background(), id) {
					atomic.AddInt64(&ok, 1)
				}
			}
		}()
	}
	wg.Wait()
	// Every (tenant, call) pair should fit within the per-
	// tenant 1000-burst.
	if got := atomic.LoadInt64(&ok); got != int64(tenants*callsPer) {
		t.Fatalf("expected %d allows, got %d", tenants*callsPer, got)
	}
}

func TestPerTenantLimiter_ContextCancellation(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(StaticLimitResolver{
		Limit: TenantLimit{Rate: 1, Burst: 1},
	})
	tenant := uuid.New()
	if err := l.WaitWithBudget(context.Background(), tenant, 100*time.Millisecond); err != nil {
		t.Fatalf("priming wait: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	err := l.WaitWithBudget(ctx, tenant, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestNewPerTenantLimiter_NilResolverInstallsDefault(t *testing.T) {
	t.Parallel()
	l := NewPerTenantLimiter(nil)
	tenant := uuid.New()
	if !l.Allow(context.Background(), tenant) {
		t.Fatalf("default resolver should permit the first event")
	}
}

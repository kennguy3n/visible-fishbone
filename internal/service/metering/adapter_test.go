package metering

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

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

// --- ClickHouseRowLimiter -------------------------------------------------

// rowTestClock is a manually-advanced clock so the token-bucket math is
// fully deterministic under test (AllowN takes an explicit time).
type rowTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func newRowTestClock() *rowTestClock {
	return &rowTestClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *rowTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *rowTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestNewRowLimitValidation(t *testing.T) {
	if _, err := NewRowLimit(0, 10); err == nil {
		t.Error("zero rate must be rejected")
	}
	if _, err := NewRowLimit(100, 0); err == nil {
		t.Error("zero burst must be rejected")
	}
	if rl, err := NewRowLimit(100, 10); err != nil || rl.Rate != 100 || rl.Burst != 10 {
		t.Fatalf("valid limit: got %+v err=%v", rl, err)
	}
}

func TestRowLimitFromConfig(t *testing.T) {
	def := defaultRowLimit()
	// Non-positive fields fall back to the package default, so an
	// operator who leaves the knobs unset gets exactly the default.
	if got := RowLimitFromConfig(0, 0); got != def {
		t.Errorf("RowLimitFromConfig(0,0) = %+v, want default %+v", got, def)
	}
	if got := RowLimitFromConfig(-1, -1); got != def {
		t.Errorf("RowLimitFromConfig(neg) = %+v, want default %+v", got, def)
	}
	// Each field is overridden independently.
	if got := RowLimitFromConfig(5000, 0); got.Rate != 5000 || got.Burst != def.Burst {
		t.Errorf("rate override = %+v, want rate=5000 burst=%d", got, def.Burst)
	}
	if got := RowLimitFromConfig(0, 60000); got.Rate != def.Rate || got.Burst != 60000 {
		t.Errorf("burst override = %+v, want rate=%v burst=60000", got, def.Rate)
	}
	if got := RowLimitFromConfig(5000, 60000); got.Rate != 5000 || got.Burst != 60000 {
		t.Errorf("both override = %+v, want rate=5000 burst=60000", got)
	}
}

func TestRowLimiterAllowNBurstThenRefill(t *testing.T) {
	clk := newRowTestClock()
	tid := uuid.New()
	// 100 rows/sec sustained, 1000-row burst.
	limit, _ := NewRowLimit(100, 1000)
	l := NewClickHouseRowLimiter(StaticRowLimitResolver{Limit: limit}, withRowLimiterClock(clk.now))
	ctx := context.Background()

	// Drain the full burst in one shot.
	if !l.AllowN(ctx, tid, 1000) {
		t.Fatal("first burst-sized write should be admitted")
	}
	// Bucket now empty: another row is refused, and nothing is consumed.
	if l.AllowN(ctx, tid, 1) {
		t.Fatal("write past an empty bucket must be refused")
	}
	// After 1 second, 100 tokens have refilled.
	clk.advance(time.Second)
	if !l.AllowN(ctx, tid, 100) {
		t.Fatal("100 tokens should have refilled after 1s")
	}
	if l.AllowN(ctx, tid, 1) {
		t.Fatal("bucket should be empty again after consuming the refill")
	}
}

func TestRowLimiterRejectsBatchLargerThanBurst(t *testing.T) {
	tid := uuid.New()
	limit, _ := NewRowLimit(100, 500)
	l := NewClickHouseRowLimiter(StaticRowLimitResolver{Limit: limit})
	ctx := context.Background()

	// A batch larger than the burst can never be admitted in one shot;
	// it must be refused (not panic) and consume nothing.
	if l.AllowN(ctx, tid, 501) {
		t.Fatal("batch larger than burst must be refused")
	}
	// A within-burst batch right after is still fully available.
	if !l.AllowN(ctx, tid, 500) {
		t.Fatal("within-burst batch must be admitted (oversized reject consumed nothing)")
	}
	err := l.WaitN(ctx, tid, 501)
	if !errors.Is(err, ErrRowLimitExceeded) {
		t.Fatalf("WaitN oversized batch err = %v, want ErrRowLimitExceeded", err)
	}
}

func TestRowLimiterNonPositiveAndNilTenant(t *testing.T) {
	l := NewClickHouseRowLimiter(nil) // default budget
	ctx := context.Background()

	// Non-positive row counts are no-ops that always allow.
	if !l.AllowN(ctx, uuid.New(), 0) || !l.AllowN(ctx, uuid.New(), -5) {
		t.Fatal("non-positive row counts must always allow")
	}
	// A nil tenant is rejected.
	if l.AllowN(ctx, uuid.Nil, 1) {
		t.Fatal("nil tenant must be refused")
	}
	if err := l.WaitN(ctx, uuid.Nil, 1); !errors.Is(err, ErrRowLimitExceeded) {
		t.Fatalf("WaitN nil tenant err = %v, want ErrRowLimitExceeded", err)
	}
	// A nil limiter is an always-allow no-op.
	var nilLimiter *ClickHouseRowLimiter
	if !nilLimiter.AllowN(ctx, uuid.New(), 100) {
		t.Fatal("nil limiter must always allow")
	}
	if err := nilLimiter.WaitN(ctx, uuid.New(), 100); err != nil {
		t.Fatalf("nil limiter WaitN err = %v, want nil", err)
	}
	if nilLimiter.Snapshot() != nil {
		t.Fatal("nil limiter Snapshot must be nil")
	}
}

func TestRowLimiterUnlimitedTenant(t *testing.T) {
	tid := uuid.New()
	l := NewClickHouseRowLimiter(StaticRowLimitResolver{Limit: RowLimit{Rate: rate.Inf, Burst: 1}})
	ctx := context.Background()
	// A rate.Inf tenant is never limited, even for huge batches.
	if !l.AllowN(ctx, tid, 1_000_000) {
		t.Fatal("rate.Inf tenant must always be allowed")
	}
	if err := l.WaitN(ctx, tid, 1_000_000); err != nil {
		t.Fatalf("rate.Inf WaitN err = %v, want nil", err)
	}
}

func TestRowLimiterRebuildsBucketOnBudgetChange(t *testing.T) {
	clk := newRowTestClock()
	tid := uuid.New()
	res := &mutableRowResolver{limit: RowLimit{Rate: 100, Burst: 100}}
	l := NewClickHouseRowLimiter(res, withRowLimiterClock(clk.now))
	ctx := context.Background()

	if !l.AllowN(ctx, tid, 100) {
		t.Fatal("initial burst should be admitted")
	}
	// Operator raises the budget. The in-place rebuild is applied lazily
	// on the next AllowN/WaitN for the tenant (the seam that resolves the
	// budget), so issue a probe write to trigger it.
	res.set(RowLimit{Rate: 1000, Burst: 1000})
	clk.advance(time.Second)
	if !l.AllowN(ctx, tid, 1) {
		t.Fatal("probe write should be admitted (100 tokens refilled at old rate)")
	}
	if snap := l.Snapshot()[tid]; snap.Rate != 1000 || snap.Burst != 1000 {
		t.Fatalf("snapshot did not reflect new budget after rebuild: %+v", snap)
	}
	// Raising the burst does not mint free tokens (correct token-bucket
	// semantics) — they accrue at the new rate, so after 1s the bucket
	// holds the new 1000-row burst.
	clk.advance(time.Second)
	if !l.AllowN(ctx, tid, 1000) {
		t.Fatal("raised burst should be admittable after refilling at the new rate")
	}
}

// TestRowLimiterConcurrentAllowNDuringBudgetChange hammers AllowN from
// many goroutines while an operator repeatedly changes the budget. With
// -race this exercises the atomic refresh-then-consume path (allowN /
// refreshLocked under b.mu): the two SetXAt calls and the AllowN that
// follows must be serialised so no caller observes a half-applied
// limiter. The assertion is liveness/safety (no race, no panic, every
// call returns a bool) rather than an exact admit count, since the
// admitted volume legitimately depends on the interleaving.
func TestRowLimiterConcurrentAllowNDuringBudgetChange(t *testing.T) {
	tid := uuid.New()
	res := &mutableRowResolver{limit: RowLimit{Rate: 1000, Burst: 1000}}
	l := NewClickHouseRowLimiter(res)
	ctx := context.Background()

	const readers = 16
	const iters = 2000

	// Writer: flip the budget between two finite values continuously
	// until the readers are done.
	stop := make(chan struct{})
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		hi := true
		for {
			select {
			case <-stop:
				return
			default:
				if hi {
					res.set(RowLimit{Rate: 2000, Burst: 5000})
				} else {
					res.set(RowLimit{Rate: 500, Burst: 800})
				}
				hi = !hi
			}
		}
	}()

	var readersWG sync.WaitGroup
	for r := 0; r < readers; r++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for i := 0; i < iters; i++ {
				// Mix single-row and small-batch writes; both must
				// return without racing the concurrent reconfigure.
				_ = l.AllowN(ctx, tid, 1)
				_ = l.AllowN(ctx, tid, 64)
			}
		}()
	}

	readersWG.Wait()
	close(stop)
	writer.Wait()

	// The bucket must be in one of the two configured states — never a
	// half-applied (new rate, old burst) hybrid.
	snap := l.Snapshot()[tid]
	okHi := snap.Rate == 2000 && snap.Burst == 5000
	okLo := snap.Rate == 500 && snap.Burst == 800
	if !okHi && !okLo {
		t.Fatalf("bucket left half-applied after concurrent reconfigure: %+v", snap)
	}
}

func TestRowLimiterWaitNRespectsContextCancellation(t *testing.T) {
	tid := uuid.New()
	limit, _ := NewRowLimit(1, 1) // 1 row/sec, burst 1 — very slow refill
	l := NewClickHouseRowLimiter(StaticRowLimitResolver{Limit: limit})

	// Drain the single burst token.
	if !l.AllowN(context.Background(), tid, 1) {
		t.Fatal("first token should be admitted")
	}
	// Next WaitN would block ~1s for a refill; cancel first so it returns
	// the context error instead of blocking the writer indefinitely.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.WaitN(ctx, tid, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitN err = %v, want context.Canceled", err)
	}
}

// mutableRowResolver is a resolver whose limit an operator can change
// at runtime, to exercise the in-place bucket rebuild.
type mutableRowResolver struct {
	mu    sync.Mutex
	limit RowLimit
}

func (r *mutableRowResolver) set(l RowLimit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.limit = l
}

func (r *mutableRowResolver) ResolveRowLimit(context.Context, uuid.UUID) RowLimit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limit
}

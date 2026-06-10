package metering

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// arlClock is a test clock advanced explicitly by the test.
type arlClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *arlClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *arlClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// feedRates pushes one estimation window per entry in rates (rows/sec),
// leaving every window rolled into a median sample. A window's sample is
// closed by the next positive observe, so a trailing observe flushes the
// final window.
func feedRates(tr *medianRateTracker, id uuid.UUID, clk *arlClock, window time.Duration, rates []float64) {
	secs := window.Seconds()
	for _, r := range rates {
		rows := int64(r * secs)
		if rows < 1 {
			rows = 1
		}
		tr.observe(id, rows, clk.Now())
		clk.Advance(window)
	}
	tr.observe(id, 1, clk.Now())
}

func TestAdaptiveRowColdStartUsesInitialRate(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	tr := newMedianRateTracker(AdaptiveRowLimitConfig{NowFunc: clk.Now}.withDefaults())
	id := uuid.New()

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Rate != DefaultAdaptiveRowInitialRate {
		t.Fatalf("cold-start rate = %v, want initial %v", got.Rate, DefaultAdaptiveRowInitialRate)
	}
}

func TestAdaptiveRowCapIsTwiceTrailingMedian(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	cfg := AdaptiveRowLimitConfig{NowFunc: clk.Now}.withDefaults()
	tr := newMedianRateTracker(cfg)
	id := uuid.New()

	// 12 windows at a steady 1000 rows/sec ⇒ median 1000 ⇒ cap 2000.
	rates := make([]float64, cfg.SampleWindows)
	for i := range rates {
		rates[i] = 1000
	}
	feedRates(tr, id, clk, cfg.Window, rates)

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Rate != rate.Limit(2000) {
		t.Fatalf("cap = %v, want 2× median = 2000", got.Rate)
	}
}

func TestAdaptiveRowMedianIgnoresTransientSpike(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	cfg := AdaptiveRowLimitConfig{NowFunc: clk.Now}.withDefaults()
	tr := newMedianRateTracker(cfg)
	id := uuid.New()

	// 11 windows at 1000 rows/sec, then a single 50,000 rows/sec spike.
	// The median of {1000×11, 50000} is still 1000, so the cap holds at
	// 2000 — the spike does not widen the tenant's budget.
	rates := make([]float64, 0, cfg.SampleWindows)
	for i := 0; i < cfg.SampleWindows-1; i++ {
		rates = append(rates, 1000)
	}
	rates = append(rates, 50000)
	feedRates(tr, id, clk, cfg.Window, rates)

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Rate != rate.Limit(2000) {
		t.Fatalf("cap = %v after transient spike, want held at 2000", got.Rate)
	}
}

func TestAdaptiveRowSustainedIncreaseRaisesCap(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	cfg := AdaptiveRowLimitConfig{NowFunc: clk.Now}.withDefaults()
	tr := newMedianRateTracker(cfg)
	id := uuid.New()

	// Establish a 1000 rows/sec baseline, then sustain 5000 rows/sec for
	// a full horizon. Once the higher rate fills the ring, the median —
	// and therefore the cap — tracks it: median 5000 ⇒ cap 10000.
	base := make([]float64, cfg.SampleWindows)
	for i := range base {
		base[i] = 1000
	}
	feedRates(tr, id, clk, cfg.Window, base)

	sustained := make([]float64, cfg.SampleWindows)
	for i := range sustained {
		sustained[i] = 5000
	}
	feedRates(tr, id, clk, cfg.Window, sustained)

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Rate != rate.Limit(10000) {
		t.Fatalf("cap = %v after sustained increase, want 2× 5000 = 10000", got.Rate)
	}
}

func TestAdaptiveRowQuietTenantKeepsFloor(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	cfg := AdaptiveRowLimitConfig{NowFunc: clk.Now}.withDefaults()
	tr := newMedianRateTracker(cfg)
	id := uuid.New()

	// A near-silent tenant: ~1 row/sec. 2× median would be ~2 rows/sec,
	// far below the floor, so the cap clamps to MinRate.
	rates := make([]float64, cfg.SampleWindows)
	for i := range rates {
		rates[i] = 1
	}
	feedRates(tr, id, clk, cfg.Window, rates)

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Rate != cfg.MinRate {
		t.Fatalf("quiet-tenant cap = %v, want floor %v", got.Rate, cfg.MinRate)
	}
}

func TestAdaptiveRowCapClampsToMaxRate(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	cfg := AdaptiveRowLimitConfig{NowFunc: clk.Now, MaxRate: 5000}.withDefaults()
	tr := newMedianRateTracker(cfg)
	id := uuid.New()

	// Median 10000 ⇒ 2× = 20000, but MaxRate caps it at 5000.
	rates := make([]float64, cfg.SampleWindows)
	for i := range rates {
		rates[i] = 10000
	}
	feedRates(tr, id, clk, cfg.Window, rates)

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Rate != rate.Limit(5000) {
		t.Fatalf("cap = %v, want clamped to MaxRate 5000", got.Rate)
	}
}

func TestAdaptiveRowBurstScalesWithRate(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	cfg := AdaptiveRowLimitConfig{NowFunc: clk.Now}.withDefaults()
	tr := newMedianRateTracker(cfg)
	id := uuid.New()

	// Median 5000 ⇒ cap 10000 rows/sec ⇒ burst = 10s × 10000 = 100000.
	rates := make([]float64, cfg.SampleWindows)
	for i := range rates {
		rates[i] = 5000
	}
	feedRates(tr, id, clk, cfg.Window, rates)

	got := tr.ResolveRowLimit(context.Background(), id)
	if got.Burst != 100000 {
		t.Fatalf("burst = %d, want 100000 (BurstSeconds × rate)", got.Burst)
	}
}

func TestAdaptiveRowLimiterAllowNShedsAboveBurst(t *testing.T) {
	clk := &arlClock{now: time.Unix(0, 0)}
	l := NewAdaptiveRowLimiter(AdaptiveRowLimitConfig{NowFunc: clk.Now})
	id := uuid.New()
	ctx := context.Background()

	// Cold start: cap = InitialRate (2000/s), burst = DefaultAdaptiveRowMinBurst
	// (20000). Offer rows=1 in a tight loop at a frozen clock: the first
	// `burst` are admitted from the bucket, the next is shed.
	admitted := 0
	for i := 0; i < DefaultAdaptiveRowMinBurst+100; i++ {
		if l.AllowN(ctx, id, 1) {
			admitted++
		}
	}
	if admitted != DefaultAdaptiveRowMinBurst {
		t.Fatalf("admitted %d rows at frozen clock, want exactly burst = %d", admitted, DefaultAdaptiveRowMinBurst)
	}
}

func TestAdaptiveRowLimiterNilSafe(t *testing.T) {
	var l *AdaptiveRowLimiter
	if !l.AllowN(context.Background(), uuid.New(), 5) {
		t.Fatal("nil limiter AllowN should always allow")
	}
	if err := l.WaitN(context.Background(), uuid.New(), 5); err != nil {
		t.Fatalf("nil limiter WaitN should be a no-op, got %v", err)
	}
	if l.Snapshot() != nil {
		t.Fatal("nil limiter Snapshot should be nil")
	}
}

func TestAdaptiveRowLimiterNilTenantRejected(t *testing.T) {
	l := NewAdaptiveRowLimiter(AdaptiveRowLimitConfig{})
	if l.AllowN(context.Background(), uuid.Nil, 1) {
		t.Fatal("nil tenant should be rejected")
	}
}

package telemetry

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// testClock is a manually-advanced clock so the sampler's windowing
// is fully deterministic under test (no wall-clock flakiness).
type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func newTestClock() *testClock {
	return &testClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// newRandUUID draws a reproducible random UUID from r so statistical
// assertions don't flake across runs.
func newRandUUID(r *rand.Rand) uuid.UUID {
	var id uuid.UUID
	r.Read(id[:])
	return id
}

// budgetResolver is a single-budget resolver used to drive a known
// per-tenant events/sec budget in tests.
func budgetResolver(eventsPerSec rate.Limit) LimitResolver {
	return StaticLimitResolver{Limit: TenantLimit{Rate: eventsPerSec, Burst: int(eventsPerSec)}}
}

// primeKeepProb feeds `arrivals` events into a fresh tenant's first
// window (all kept, keepProb 1.0), then advances exactly one window
// so the NEXT Decide recomputes the keep probability from that
// observed arrival rate. With a 1s window, observed == arrivals, so
// the resulting keepProb == budget/arrivals.
func primeKeepProb(t *testing.T, s *AdaptiveSampler, clk *testClock, r *rand.Rand, tid uuid.UUID, arrivals int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < arrivals; i++ {
		s.Decide(ctx, tid, newRandUUID(r))
	}
	clk.advance(s.window)
}

func TestHashFractionDeterministicAndUniform(t *testing.T) {
	id := uuid.New()
	if hashFraction(id) != hashFraction(id) {
		t.Fatal("hashFraction is not deterministic for the same UUID")
	}

	r := rand.New(rand.NewSource(1))
	const n = 100_000
	var sum float64
	buckets := make([]int, 10)
	for i := 0; i < n; i++ {
		f := hashFraction(newRandUUID(r))
		if f < 0 || f >= 1 {
			t.Fatalf("hashFraction out of [0,1): %v", f)
		}
		sum += f
		buckets[int(f*10)]++
	}
	if mean := sum / n; math.Abs(mean-0.5) > 0.01 {
		t.Errorf("mean fraction = %v, want ~0.5 (non-uniform hash)", mean)
	}
	// Every decile bucket should hold ~10% of the mass.
	for d, c := range buckets {
		if frac := float64(c) / n; math.Abs(frac-0.1) > 0.02 {
			t.Errorf("decile %d holds %.3f of mass, want ~0.1", d, frac)
		}
	}
}

func TestAdaptiveSamplerNilIsNoop(t *testing.T) {
	var s *AdaptiveSampler // nil
	keep, rateApplied := s.Decide(context.Background(), uuid.New(), uuid.New())
	if !keep || rateApplied != 1.0 {
		t.Fatalf("nil sampler: keep=%v rate=%v, want true/1.0", keep, rateApplied)
	}
	if s.Snapshot() != nil {
		t.Error("nil sampler Snapshot should be nil")
	}
	if s.ForPartition() != nil {
		t.Error("nil sampler ForPartition should be nil")
	}
}

func TestDecideClassTrustedClassesFixedRate(t *testing.T) {
	clk := newTestClock()
	r := rand.New(rand.NewSource(7))
	// A generous budget so the adaptive path would keep everything —
	// proving the trusted-class shedding comes from the fixed policy,
	// not from adaptive load shedding.
	s := NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(1_000_000),
		Window:   time.Second,
		NowFunc:  clk.now,
	})
	ctx := context.Background()
	tid := uuid.New()

	for _, tc := range []string{"trusted_direct", "trusted_media_bypass"} {
		const n = 200_000
		kept := 0
		for i := 0; i < n; i++ {
			keep, sampleRate := s.DecideClass(ctx, tid, newRandUUID(r), tc)
			if sampleRate != TrustedClassSampleRate {
				t.Fatalf("%s: sampleRate = %v, want %v", tc, sampleRate, TrustedClassSampleRate)
			}
			if keep {
				kept++
			}
		}
		// Kept fraction must hover around the fixed 1:100 rate.
		if frac := float64(kept) / n; math.Abs(frac-TrustedClassSampleRate) > 0.002 {
			t.Errorf("%s: kept fraction = %.4f, want ~%.4f", tc, frac, TrustedClassSampleRate)
		}
	}
	// The fixed-rate classes must not have touched the adaptive
	// per-tenant window (no arrival recorded), so the tenant has no
	// adaptive state at all.
	if snap := s.Snapshot(); len(snap) != 0 {
		t.Errorf("trusted-class sampling must not create adaptive tenant state, got %d entries", len(snap))
	}
}

func TestDecideClassDeterministicAndRedeliveryStable(t *testing.T) {
	s := NewAdaptiveSampler(SamplerConfig{Resolver: budgetResolver(1_000_000)})
	ctx := context.Background()
	tid := uuid.New()
	eid := uuid.New()

	keep1, rate1 := s.DecideClass(ctx, tid, eid, "trusted_direct")
	keep2, rate2 := s.DecideClass(ctx, tid, eid, "trusted_direct")
	if keep1 != keep2 || rate1 != rate2 {
		t.Fatalf("non-deterministic verdict for same event: (%v,%v) vs (%v,%v)", keep1, rate1, keep2, rate2)
	}
	// The redelivery rate-recovery path must report the same fixed rate
	// without consulting per-tenant adaptive state.
	if sr := s.SampleRateForClass(tid, "trusted_direct"); sr != TrustedClassSampleRate {
		t.Fatalf("SampleRateForClass(trusted_direct) = %v, want %v", sr, TrustedClassSampleRate)
	}
}

func TestDecideClassNonTrustedFallsThroughToAdaptive(t *testing.T) {
	clk := newTestClock()
	r := rand.New(rand.NewSource(11))
	s := NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(100),
		Window:   time.Second,
		NowFunc:  clk.now,
	})
	ctx := context.Background()
	tid := uuid.New()

	// inspect_full must use adaptive sampling: under budget it keeps
	// everything, and unlike a trusted class it DOES record arrivals.
	keep, sampleRate := s.DecideClass(ctx, tid, newRandUUID(r), "inspect_full")
	if !keep || sampleRate != 1.0 {
		t.Fatalf("inspect_full under budget: keep=%v rate=%v, want true/1.0", keep, sampleRate)
	}
	if snap := s.Snapshot(); len(snap) != 1 {
		t.Fatalf("adaptive class must create per-tenant state, got %d entries", len(snap))
	}
	// An empty class (unknown) also falls through to adaptive.
	if _, ok := fixedClassSampleRate(""); ok {
		t.Fatal("empty traffic class must not be treated as fixed-rate")
	}
}

func TestAdaptiveSamplerUnderBudgetKeepsAll(t *testing.T) {
	clk := newTestClock()
	r := rand.New(rand.NewSource(2))
	s := NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(1000),
		Window:   time.Second,
		NowFunc:  clk.now,
	})
	tid := uuid.New()
	ctx := context.Background()

	// Window 1 sees only 100 events (well under the 1000/s budget).
	for i := 0; i < 100; i++ {
		if keep, rt := s.Decide(ctx, tid, newRandUUID(r)); !keep || rt != 1.0 {
			t.Fatalf("window1 event %d dropped/sampled: keep=%v rate=%v", i, keep, rt)
		}
	}
	clk.advance(time.Second)
	// Window 2 must still keep everything: observed (100/s) <= budget.
	for i := 0; i < 100; i++ {
		if keep, rt := s.Decide(ctx, tid, newRandUUID(r)); !keep || rt != 1.0 {
			t.Fatalf("window2 event %d dropped/sampled: keep=%v rate=%v", i, keep, rt)
		}
	}
}

func TestAdaptiveSamplerDeterministicDecision(t *testing.T) {
	clk := newTestClock()
	r := rand.New(rand.NewSource(3))
	s := NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(1000),
		Window:   time.Second,
		NowFunc:  clk.now,
	})
	tid := uuid.New()
	// Drive keepProb to 0.5 (2000 arrivals over a 1s window vs 1000/s).
	primeKeepProb(t, s, clk, r, tid, 2000)
	ctx := context.Background()

	// The same event must always reach the same verdict at a fixed
	// keep probability — essential for redelivery stability.
	id := newRandUUID(r)
	keep0, rate0 := s.Decide(ctx, tid, id)
	for i := 0; i < 50; i++ {
		keep, rt := s.Decide(ctx, tid, id)
		if keep != keep0 || rt != rate0 {
			t.Fatalf("non-deterministic decision: (%v,%v) != (%v,%v)", keep, rt, keep0, rate0)
		}
	}
	if math.Abs(rate0-0.5) > 1e-9 {
		t.Errorf("keepProb = %v, want 0.5", rate0)
	}
}

// TestAdaptiveSamplerRepresentativeAtRates is the statistical
// integration test required by the spec: at several sampling rates,
// the kept fraction must match the keep probability and de-biasing
// (scaling by 1/rate) must recover the true volume, including across
// independent dimensions.
func TestAdaptiveSamplerRepresentativeAtRates(t *testing.T) {
	const (
		budget    = rate.Limit(1000)
		measure   = 200_000
		numBucket = 4
	)
	for _, tc := range []struct {
		name     string
		arrivals int // window-1 arrivals → keepProb = budget/arrivals
		wantProb float64
	}{
		{"rate_0.50", 2000, 0.50},
		{"rate_0.25", 4000, 0.25},
		{"rate_0.10", 10000, 0.10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clk := newTestClock()
			r := rand.New(rand.NewSource(int64(len(tc.name))))
			s := NewAdaptiveSampler(SamplerConfig{
				Resolver: budgetResolver(budget),
				Window:   time.Second,
				NowFunc:  clk.now,
			})
			tid := uuid.New()
			primeKeepProb(t, s, clk, r, tid, tc.arrivals)
			ctx := context.Background()

			var kept int
			perBucketTotal := make([]int, numBucket)
			perBucketKept := make([]int, numBucket)
			var appliedRate float64
			for i := 0; i < measure; i++ {
				b := i % numBucket
				perBucketTotal[b]++
				keep, rt := s.Decide(ctx, tid, newRandUUID(r))
				appliedRate = rt
				if keep {
					kept++
					perBucketKept[b]++
				}
			}

			// The applied keep probability matches the target.
			if math.Abs(appliedRate-tc.wantProb) > 1e-9 {
				t.Fatalf("applied rate = %v, want %v", appliedRate, tc.wantProb)
			}

			// Observed kept fraction is within 5% (relative) of p.
			keptFrac := float64(kept) / measure
			if rel := math.Abs(keptFrac-tc.wantProb) / tc.wantProb; rel > 0.05 {
				t.Errorf("kept fraction = %v, want ~%v (rel err %.3f)", keptFrac, tc.wantProb, rel)
			}

			// De-biasing recovers the true volume within 5%.
			debiased := float64(kept) / appliedRate
			if rel := math.Abs(debiased-measure) / measure; rel > 0.05 {
				t.Errorf("de-biased estimate = %.0f, want ~%d (rel err %.3f)", debiased, measure, rel)
			}

			// Representative across independent dimensions: each bucket
			// keeps ~p of its events (de-bias recovers per-bucket totals).
			for b := 0; b < numBucket; b++ {
				bf := float64(perBucketKept[b]) / float64(perBucketTotal[b])
				if rel := math.Abs(bf-tc.wantProb) / tc.wantProb; rel > 0.08 {
					t.Errorf("bucket %d kept fraction = %v, want ~%v (rel err %.3f)", b, bf, tc.wantProb, rel)
				}
			}

			// Volume actually shed (the 30-50%+ ClickHouse reduction
			// the workstream targets).
			if reduction := 1 - keptFrac; reduction < 0.30 {
				t.Errorf("write-volume reduction = %.2f, want >= 0.30", reduction)
			}
		})
	}
}

func TestAdaptiveSamplerMinRateFloor(t *testing.T) {
	clk := newTestClock()
	r := rand.New(rand.NewSource(7))
	s := NewAdaptiveSampler(SamplerConfig{
		Resolver:      budgetResolver(10),
		Window:        time.Second,
		MinSampleRate: 0.05,
		NowFunc:       clk.now,
	})
	tid := uuid.New()
	// 100k arrivals/s against a 10/s budget → raw ratio 0.0001, but
	// the floor clamps the keep probability to 0.05 so visibility is
	// never fully lost.
	primeKeepProb(t, s, clk, r, tid, 100_000)
	_, rt := s.Decide(context.Background(), tid, newRandUUID(r))
	if math.Abs(rt-0.05) > 1e-9 {
		t.Fatalf("keepProb = %v, want clamped to 0.05", rt)
	}
}

// TestAdaptiveSamplerMonotoneSuperset verifies the consistent-sampling
// property: the set kept at a lower rate is a subset of the set kept
// at a higher rate, so adapting the rate never reshuffles which
// events survive.
func TestAdaptiveSamplerMonotoneSuperset(t *testing.T) {
	ctx := context.Background()
	ids := make([]uuid.UUID, 5000)
	r := rand.New(rand.NewSource(11))
	for i := range ids {
		ids[i] = newRandUUID(r)
	}

	keptAt := func(arrivals int) map[uuid.UUID]bool {
		clk := newTestClock()
		pr := rand.New(rand.NewSource(11)) // identical UUID stream for priming
		s := NewAdaptiveSampler(SamplerConfig{
			Resolver: budgetResolver(1000),
			Window:   time.Second,
			NowFunc:  clk.now,
		})
		tid := uuid.New()
		primeKeepProb(t, s, clk, pr, tid, arrivals)
		out := make(map[uuid.UUID]bool)
		for _, id := range ids {
			if keep, _ := s.Decide(ctx, tid, id); keep {
				out[id] = true
			}
		}
		return out
	}

	low := keptAt(10000) // keepProb 0.10
	high := keptAt(2000) // keepProb 0.50
	if len(low) == 0 || len(high) <= len(low) {
		t.Fatalf("expected high-rate set to strictly contain more: low=%d high=%d", len(low), len(high))
	}
	for id := range low {
		if !high[id] {
			t.Fatalf("event %s kept at p=0.10 but dropped at p=0.50 — not monotone", id)
		}
	}
}

func TestAdaptiveSamplerForPartitionIndependent(t *testing.T) {
	clk := newTestClock()
	parent := NewAdaptiveSampler(SamplerConfig{
		Resolver: budgetResolver(1000),
		Window:   time.Second,
		NowFunc:  clk.now,
	})
	child := parent.ForPartition()
	if child == nil {
		t.Fatal("ForPartition returned nil")
	}
	// Independent state maps: a tenant seen by the child is not
	// recorded in the parent.
	tid := uuid.New()
	child.Decide(context.Background(), tid, uuid.New())
	if _, ok := child.tenants[tid]; !ok {
		t.Error("child should track the tenant it served")
	}
	if _, ok := parent.tenants[tid]; ok {
		t.Error("parent must not share the child's per-tenant state")
	}
	// Shared budget resolver: both resolve the same budget.
	if parent.resolver != child.resolver {
		t.Error("ForPartition must share the budget resolver")
	}
}

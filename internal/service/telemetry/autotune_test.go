package telemetry

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

// fakeTunable is an in-memory BatchTunable for driving the controller
// deterministically. rows/inserts are advanced by the test (directly
// or via simulateInterval) and SetBatchSize records the latest value.
type fakeTunable struct {
	mu      sync.Mutex
	batch   int
	rows    uint64
	inserts uint64
}

func newFakeTunable(batch int) *fakeTunable { return &fakeTunable{batch: batch} }

func (f *fakeTunable) BatchSize() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.batch
}

func (f *fakeTunable) SetBatchSize(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if n >= 1 {
		f.batch = n
	}
}

func (f *fakeTunable) RowsWritten() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rows
}

func (f *fakeTunable) InsertCount() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.inserts
}

// simulateInterval advances the writer's counters as if `secs` seconds
// of traffic at `rowsPerSec` had flowed through it at the current batch
// size, modelling size-triggered inserts (dInserts ≈ dRows/batch). The
// fractional carry keeps the insert count faithful across intervals so
// the closed-loop simulation converges the way the real writer would.
func (f *fakeTunable) simulateInterval(rowsPerSec, secs float64, carry *float64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	dRows := rowsPerSec * secs
	f.rows += uint64(dRows)
	insertsF := dRows/float64(f.batch) + *carry
	whole := math.Floor(insertsF)
	*carry = insertsF - whole
	f.inserts += uint64(whole)
}

// manualClock is a test clock advanced explicitly by the test.
type manualClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *manualClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *manualClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func TestAutoTuneGrowsBatchWhenInsertRateTooHigh(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	w := newFakeTunable(1024)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		TargetInsertsPerSec: 2.0,
		Interval:            10 * time.Second,
		Smoothing:           1.0, // no damping: jump straight to desired
		NowFunc:             clk.Now,
	}, w)

	// Prime baseline.
	tuner.tuneOnce()

	// One interval: 20k rows/s with a 1024 batch ⇒ ~19.5 inserts/s,
	// far over the 2/s target. Desired batch = 20000/2 = 10000.
	clk.Advance(10 * time.Second)
	w.mu.Lock()
	w.rows += 200000
	w.inserts += 195
	w.mu.Unlock()
	tuner.tuneOnce()

	if got := w.BatchSize(); got != 10000 {
		t.Fatalf("batch = %d, want 10000 (rows/s ÷ target)", got)
	}
}

func TestAutoTuneShrinksBatchWhenRowRateFalls(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	w := newFakeTunable(10000)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		TargetInsertsPerSec: 2.0,
		Interval:            10 * time.Second,
		Smoothing:           1.0,
		NowFunc:             clk.Now,
	}, w)
	tuner.tuneOnce()

	// Row rate drops to 2000/s. Desired batch = 2000/2 = 1000.
	clk.Advance(10 * time.Second)
	w.mu.Lock()
	w.rows += 20000
	w.inserts += 2
	w.mu.Unlock()
	tuner.tuneOnce()

	if got := w.BatchSize(); got != 1000 {
		t.Fatalf("batch = %d, want 1000", got)
	}
}

func TestAutoTuneConvergesToTargetInsertRate(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	w := newFakeTunable(1024)
	const (
		target     = 2.0
		rowsPerSec = 26500.0 // 5K-tenant tier total (docs/scaling.md §3.3)
		interval   = 10 * time.Second
	)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		TargetInsertsPerSec: target,
		Interval:            interval,
		MaxBatchSize:        100000, // above the converged ~13250 so it isn't clamped
		Smoothing:           DefaultAutoTuneSmoothing,
		NowFunc:             clk.Now,
	}, w)
	tuner.tuneOnce() // prime

	var carry float64
	for i := 0; i < 40; i++ {
		clk.Advance(interval)
		w.simulateInterval(rowsPerSec, interval.Seconds(), &carry)
		tuner.tuneOnce()
	}

	// Converged batch should be ≈ rowsPerSec/target = 13250, which
	// yields an insert rate of ≈ target.
	wantBatch := rowsPerSec / target
	gotBatch := float64(w.BatchSize())
	if math.Abs(gotBatch-wantBatch)/wantBatch > 0.05 {
		t.Fatalf("converged batch = %.0f, want ≈ %.0f (±5%%)", gotBatch, wantBatch)
	}
	gotInsertRate := rowsPerSec / gotBatch
	if math.Abs(gotInsertRate-target) > 0.2 {
		t.Fatalf("converged insert rate = %.2f/s, want ≈ %.2f/s", gotInsertRate, target)
	}
}

func TestAutoTuneIdleLeavesBatchUnchanged(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	w := newFakeTunable(4096)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		Interval:  10 * time.Second,
		Smoothing: 1.0,
		NowFunc:   clk.Now,
	}, w)
	tuner.tuneOnce()

	// No rows flushed across the interval ⇒ batch must not move.
	clk.Advance(10 * time.Second)
	tuner.tuneOnce()

	if got := w.BatchSize(); got != 4096 {
		t.Fatalf("idle batch = %d, want 4096 (unchanged)", got)
	}
}

func TestAutoTuneClampsToMaxAndRecommendsSharding(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	w := newFakeTunable(1024)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		TargetInsertsPerSec: 2.0,
		Interval:            10 * time.Second,
		MaxBatchSize:        65536,
		Smoothing:           1.0,
		NowFunc:             clk.Now,
	}, w)
	tuner.tuneOnce()

	// Row rate so high desired batch (≫ 65536) exceeds the cap and the
	// insert rate is still over target ⇒ clamp at max.
	clk.Advance(10 * time.Second)
	w.mu.Lock()
	w.rows += 5000000 // 500k rows/s ⇒ desired 250k batch
	w.inserts += 1000 // 100 inserts/s, well over target
	w.mu.Unlock()
	tuner.tuneOnce()

	if got := w.BatchSize(); got != 65536 {
		t.Fatalf("batch = %d, want clamped to 65536", got)
	}
}

func TestAutoTuneReBaselinesOnCounterReset(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	w := newFakeTunable(2048)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		TargetInsertsPerSec: 2.0,
		Interval:            10 * time.Second,
		Smoothing:           1.0,
		NowFunc:             clk.Now,
	}, w)
	tuner.tuneOnce()

	// Advance with real load so a baseline exists.
	clk.Advance(10 * time.Second)
	w.mu.Lock()
	w.rows += 40000
	w.inserts += 20
	w.mu.Unlock()
	tuner.tuneOnce()
	tuned := w.BatchSize()

	// Simulate a writer restart: counters reset to zero. The tuner must
	// re-baseline and not move the batch on a negative delta.
	w.mu.Lock()
	w.rows = 0
	w.inserts = 0
	w.mu.Unlock()
	clk.Advance(10 * time.Second)
	tuner.tuneOnce()

	if got := w.BatchSize(); got != tuned {
		t.Fatalf("batch = %d after counter reset, want unchanged %d", got, tuned)
	}
}

func TestAutoTunePerShardIndependent(t *testing.T) {
	clk := &manualClock{now: time.Unix(0, 0)}
	hot := newFakeTunable(1024)
	cold := newFakeTunable(1024)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		TargetInsertsPerSec: 2.0,
		Interval:            10 * time.Second,
		Smoothing:           1.0,
		NowFunc:             clk.Now,
	}, hot, cold)
	tuner.tuneOnce()

	clk.Advance(10 * time.Second)
	// hot shard sees 10x the rows of the cold shard.
	hot.mu.Lock()
	hot.rows += 200000
	hot.inserts += 195
	hot.mu.Unlock()
	cold.mu.Lock()
	cold.rows += 20000
	cold.inserts += 19
	cold.mu.Unlock()
	tuner.tuneOnce()

	if hot.BatchSize() != 10000 {
		t.Fatalf("hot shard batch = %d, want 10000", hot.BatchSize())
	}
	if cold.BatchSize() != 1000 {
		t.Fatalf("cold shard batch = %d, want 1000", cold.BatchSize())
	}
}

func TestNewBatchAutoTunerNilWhenNoWriters(t *testing.T) {
	if tuner := NewBatchAutoTuner(AutoTuneConfig{}); tuner != nil {
		t.Fatal("expected nil tuner with no writers")
	}
	if tuner := NewBatchAutoTuner(AutoTuneConfig{}, nil, nil); tuner != nil {
		t.Fatal("expected nil tuner when all writers are nil")
	}
	// A nil tuner's lifecycle calls must be safe no-ops.
	var nilTuner *BatchAutoTuner
	nilTuner.Start(context.Background())
	nilTuner.Stop()
}

func TestAutoTuneStartStop(t *testing.T) {
	w := newFakeTunable(1024)
	tuner := NewBatchAutoTuner(AutoTuneConfig{
		Interval: time.Millisecond,
	}, w)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	tuner.Start(ctx)
	tuner.Start(ctx) // idempotent
	time.Sleep(20 * time.Millisecond)
	tuner.Stop()
	tuner.Stop() // idempotent
}

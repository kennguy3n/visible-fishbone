package ai

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

type stubTenantLister struct {
	tenants []uuid.UUID
}

func (s *stubTenantLister) ListActiveTenants(_ context.Context) ([]uuid.UUID, error) {
	return s.tenants, nil
}

type stubOptInChecker struct {
	optedIn map[uuid.UUID]bool
}

func (s *stubOptInChecker) IsOptedIn(_ context.Context, id uuid.UUID) bool {
	return s.optedIn[id]
}

type stubAnalysisRunner struct {
	runCount    atomic.Int64
	suggestions int
	err         error
}

func (s *stubAnalysisRunner) RunAnalysis(_ context.Context, _ uuid.UUID) (int, error) {
	s.runCount.Add(1)
	return s.suggestions, s.err
}

func TestScheduler_RunOnce(t *testing.T) {
	t.Parallel()
	t1 := uuid.New()
	t2 := uuid.New()
	t3 := uuid.New()

	runner := &stubAnalysisRunner{suggestions: 3}
	sched := NewScheduler(
		SchedulerConfig{
			Interval:       time.Hour,
			TenantCooldown: 0,
			MaxConcurrent:  2,
		},
		&stubTenantLister{tenants: []uuid.UUID{t1, t2, t3}},
		&stubOptInChecker{optedIn: map[uuid.UUID]bool{t1: true, t2: true, t3: false}},
		runner,
		nil,
	)

	err := sched.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runner.runCount.Load() != 2 {
		t.Fatalf("expected 2 runs (opted-in tenants), got %d", runner.runCount.Load())
	}

	m := sched.Metrics()
	if m.TotalRuns != 2 {
		t.Fatalf("expected 2 total runs, got %d", m.TotalRuns)
	}
}

func TestScheduler_RunOnceWithError(t *testing.T) {
	t.Parallel()
	t1 := uuid.New()

	runner := &stubAnalysisRunner{err: errors.New("analysis failed")}
	sched := NewScheduler(
		SchedulerConfig{
			Interval:       time.Hour,
			TenantCooldown: 0,
			MaxConcurrent:  1,
		},
		&stubTenantLister{tenants: []uuid.UUID{t1}},
		&stubOptInChecker{optedIn: map[uuid.UUID]bool{t1: true}},
		runner,
		nil,
	)

	err := sched.RunOnce(context.Background())
	if err == nil {
		t.Fatal("expected error from runner")
	}

	m := sched.Metrics()
	if m.TotalErrors != 1 {
		t.Fatalf("expected 1 error, got %d", m.TotalErrors)
	}
}

func TestScheduler_StartStop(t *testing.T) {
	t.Parallel()
	runner := &stubAnalysisRunner{}
	sched := NewScheduler(
		SchedulerConfig{
			Interval:       100 * time.Millisecond,
			TenantCooldown: 0,
			MaxConcurrent:  1,
		},
		&stubTenantLister{tenants: nil},
		&stubOptInChecker{optedIn: map[uuid.UUID]bool{}},
		runner,
		nil,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sched.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	sched.Stop()
}

func TestScheduler_NoTenantsOptedIn(t *testing.T) {
	t.Parallel()
	t1 := uuid.New()

	runner := &stubAnalysisRunner{suggestions: 1}
	sched := NewScheduler(
		SchedulerConfig{
			Interval:       time.Hour,
			TenantCooldown: 0,
			MaxConcurrent:  1,
		},
		&stubTenantLister{tenants: []uuid.UUID{t1}},
		&stubOptInChecker{optedIn: map[uuid.UUID]bool{t1: false}},
		runner,
		nil,
	)

	err := sched.RunOnce(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if runner.runCount.Load() != 0 {
		t.Fatalf("expected 0 runs, got %d", runner.runCount.Load())
	}
}

func TestSchedulerMetrics_Snapshot(t *testing.T) {
	t.Parallel()
	m := &SchedulerMetrics{}
	m.Record(5, nil, 100*time.Millisecond)
	m.Record(3, errors.New("fail"), 200*time.Millisecond)

	snap := m.Snapshot()
	if snap.TotalRuns != 2 {
		t.Fatalf("expected 2 runs, got %d", snap.TotalRuns)
	}
	if snap.TotalSuggestions != 8 {
		t.Fatalf("expected 8 suggestions, got %d", snap.TotalSuggestions)
	}
	if snap.TotalErrors != 1 {
		t.Fatalf("expected 1 error, got %d", snap.TotalErrors)
	}
}

// recordingRunner captures the wall-clock start time of each analysis so a
// test can assert how starts are paced relative to one another.
type recordingRunner struct {
	mu     sync.Mutex
	starts []time.Time
}

func (r *recordingRunner) RunAnalysis(_ context.Context, _ uuid.UUID) (int, error) {
	r.mu.Lock()
	r.starts = append(r.starts, time.Now())
	r.mu.Unlock()
	return 0, nil
}

// TenantCooldown must pace the rate of new analysis starts: with a single
// concurrency slot, the second tenant's analysis cannot begin until the
// first tenant's cooldown has elapsed (the slot is held through cooldown).
func TestScheduler_CooldownPacesStarts(t *testing.T) {
	t.Parallel()
	t1 := uuid.New()
	t2 := uuid.New()

	const cooldown = 120 * time.Millisecond
	runner := &recordingRunner{}
	sched := NewScheduler(
		SchedulerConfig{
			Interval:       time.Hour,
			TenantCooldown: cooldown,
			MaxConcurrent:  1,
		},
		&stubTenantLister{tenants: []uuid.UUID{t1, t2}},
		&stubOptInChecker{optedIn: map[uuid.UUID]bool{t1: true, t2: true}},
		runner,
		nil,
	)

	if err := sched.RunOnce(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	runner.mu.Lock()
	defer runner.mu.Unlock()
	if len(runner.starts) != 2 {
		t.Fatalf("expected 2 analysis starts, got %d", len(runner.starts))
	}
	// Allow a little slack below the full cooldown for timer/scheduling
	// jitter, but the gap must clearly reflect the cooldown rather than
	// near-zero (which is what an immediate slot release would produce).
	gap := runner.starts[1].Sub(runner.starts[0])
	if gap < cooldown/2 {
		t.Fatalf("second analysis started too soon (gap %v < %v); cooldown is not pacing starts", gap, cooldown/2)
	}
}

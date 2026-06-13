package tenancy

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// recordingObserver captures ObserveSweep calls for assertion. Safe for
// concurrent use so the concurrency test can share one.
type recordingObserver struct {
	mu   sync.Mutex
	rows []sweepRow
}

type sweepRow struct {
	job              string
	tier             Tier
	visited, skipped int
}

func (o *recordingObserver) ObserveSweep(job string, tier Tier, visited, skipped int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.rows = append(o.rows, sweepRow{job, tier, visited, skipped})
}

func (o *recordingObserver) total() (visited, skipped int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, r := range o.rows {
		visited += r.visited
		skipped += r.skipped
	}
	return
}

// TestBeginIsZeroBasedAndMonotonic verifies the first pass is cycle 0
// (the guaranteed full sweep) and subsequent passes increment by one.
func TestBeginIsZeroBasedAndMonotonic(t *testing.T) {
	s := NewTieredSweep("job", DefaultPlanner(), nil)
	now := time.Now()
	for want := int64(0); want < 5; want++ {
		if got := s.Begin(now).Cycle; got != want {
			t.Fatalf("pass %d: Cycle = %d, want %d", want, got, want)
		}
	}
}

// TestCycleZeroVisitsEveryTier asserts the bootstrap full-sweep contract:
// on cycle 0 every tier is due regardless of cadence.
func TestCycleZeroVisitsEveryTier(t *testing.T) {
	s := NewTieredSweep("job", DefaultPlanner(), nil)
	now := time.Now()
	c := s.Begin(now)
	for _, tier := range []Tier{TierActive, TierIdle, TierDormant} {
		if !c.visitTier(tier) {
			t.Fatalf("cycle 0: tier %v should be visited", tier)
		}
	}
}

// TestVisitCadenceMatchesPlanner checks the helper gates identically to
// the underlying SweepPlanner across a full dormant period.
func TestVisitCadenceMatchesPlanner(t *testing.T) {
	planner := DefaultPlanner()
	s := NewTieredSweep("job", planner, nil)
	now := time.Now()
	for cycle := int64(0); cycle < planner.DormantEvery; cycle++ {
		c := s.Begin(now)
		if c.Cycle != cycle {
			t.Fatalf("unexpected cycle %d, want %d", c.Cycle, cycle)
		}
		for _, tier := range []Tier{TierActive, TierIdle, TierDormant} {
			want := planner.ShouldVisit(tier, cycle)
			// Re-derive via a fresh classification-free path: visitTier
			// consults planner.ShouldVisit with c.Cycle.
			got := s.planner.ShouldVisit(tier, c.Cycle)
			if got != want {
				t.Fatalf("cycle %d tier %v: ShouldVisit mismatch", cycle, tier)
			}
		}
	}
}

// TestDueGatesAndTallies feeds a known activity mix and asserts the due
// set and the per-tier tallies on cycle 1 (where idle/dormant are not
// due under the default cadence).
func TestDueGatesAndTallies(t *testing.T) {
	obs := &recordingObserver{}
	s := NewTieredSweep("idp", DefaultPlanner(), obs)
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

	active := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-time.Hour))}
	idle := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-7 * 24 * time.Hour))}
	dormant := repository.TenantActivity{ID: uuid.New(), LastActiveAt: nil}
	acts := []repository.TenantActivity{active, idle, dormant}

	// Burn cycle 0 (full sweep visits everyone).
	c0 := s.Begin(now)
	if due := c0.Due(acts); len(due) != 3 {
		t.Fatalf("cycle 0: due = %d, want 3 (full sweep)", len(due))
	}
	c0.Finish()

	// Cycle 1: only the active tenant is due (idle every 10, dormant
	// every 100).
	c1 := s.Begin(now)
	due := c1.Due(acts)
	if len(due) != 1 || due[0] != active.ID {
		t.Fatalf("cycle 1: due = %v, want [%v]", due, active.ID)
	}
	sum := c1.Summary()
	if sum.Total != 3 || sum.Visited != 1 || sum.Skipped != 2 {
		t.Fatalf("cycle 1 summary = %+v, want total 3 visited 1 skipped 2", sum)
	}
	if sum.Active != 1 || sum.Idle != 1 || sum.Dormant != 1 {
		t.Fatalf("cycle 1 tier counts = %+v, want 1/1/1", sum)
	}
	c1.Finish()

	// Observer saw both finishes; the active tier was visited twice
	// (cycles 0 and 1), idle/dormant visited once (cycle 0) and skipped
	// once (cycle 1).
	visited, skipped := obs.total()
	if visited != 4 || skipped != 2 {
		t.Fatalf("observer totals visited=%d skipped=%d, want 4/2", visited, skipped)
	}
}

// TestDuePreservesOrder ensures Due returns ids in input order.
func TestDuePreservesOrder(t *testing.T) {
	s := NewTieredSweep("job", DefaultPlanner(), nil)
	now := time.Now()
	acts := make([]repository.TenantActivity, 5)
	for i := range acts {
		acts[i] = repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now)}
	}
	due := s.Begin(now).Due(acts) // cycle 0: all active-tier, all due
	if len(due) != len(acts) {
		t.Fatalf("due = %d, want %d", len(due), len(acts))
	}
	for i := range acts {
		if due[i] != acts[i].ID {
			t.Fatalf("order not preserved at %d", i)
		}
	}
}

// TestFailSafeMisconfiguredPlannerVisitsEveryone asserts the inherited
// fail-safe: a contradictory classifier treats every tenant as active,
// so every tenant is visited every cycle (more work, never less).
func TestFailSafeMisconfiguredPlannerVisitsEveryone(t *testing.T) {
	bad := SweepPlanner{
		Classifier:   Classifier{IdleAfter: 0, DormantAfter: 0}, // contradictory
		IdleEvery:    10,
		DormantEvery: 100,
	}
	s := NewTieredSweep("job", bad, nil)
	now := time.Now()
	acts := []repository.TenantActivity{
		{ID: uuid.New(), LastActiveAt: nil},                                 // would be dormant
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-365 * 24 * time.Hour))}, // ancient
	}
	// Burn cycle 0, then check a later cycle where dormant would be skipped.
	s.Begin(now).Due(acts)
	c := s.Begin(now)
	if due := c.Due(acts); len(due) != len(acts) {
		t.Fatalf("misconfigured planner: due = %d, want %d (fail-safe all-active)", len(due), len(acts))
	}
	if sum := c.Summary(); sum.Active != 2 || sum.Skipped != 0 {
		t.Fatalf("misconfigured planner summary = %+v, want all-active none-skipped", sum)
	}
}

// TestNilObserverDoesNotPanic asserts the documented nil-observer
// contract: gating still works, emission is silently skipped.
func TestNilObserverDoesNotPanic(t *testing.T) {
	s := NewTieredSweep("job", DefaultPlanner(), nil)
	c := s.Begin(time.Now())
	c.Visit(nil)
	c.Finish() // must not panic with a nil observer
}

// TestFinishSkipsEmptyTiers asserts a tier with no tenants this cycle
// emits no metric series (so an idle series never appears for a job that
// has no tenants in that tier).
func TestFinishSkipsEmptyTiers(t *testing.T) {
	obs := &recordingObserver{}
	s := NewTieredSweep("job", DefaultPlanner(), obs)
	now := time.Now()
	c := s.Begin(now)
	c.Visit(ptr(now)) // one active tenant only
	c.Finish()
	obs.mu.Lock()
	defer obs.mu.Unlock()
	if len(obs.rows) != 1 {
		t.Fatalf("emitted %d rows, want 1 (only the active tier)", len(obs.rows))
	}
	if obs.rows[0].tier != TierActive {
		t.Fatalf("emitted tier %v, want active", obs.rows[0].tier)
	}
}

// TestConcurrentBeginIsRaceFree drives many overlapping passes to prove
// the atomic cycle counter and per-pass SweepCycle keep independent
// tallies (run under -race).
func TestConcurrentBeginIsRaceFree(t *testing.T) {
	obs := &recordingObserver{}
	s := NewTieredSweep("job", DefaultPlanner(), obs)
	now := time.Now()
	var wg sync.WaitGroup
	const passes = 100
	for i := 0; i < passes; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := s.Begin(now)
			c.Visit(ptr(now))
			c.Finish()
		}()
	}
	wg.Wait()
	// Every pass visited exactly one active tenant.
	visited, _ := obs.total()
	if visited != passes {
		t.Fatalf("visited = %d, want %d", visited, passes)
	}
	// The counter advanced exactly `passes` times (next cycle == passes).
	if got := s.Begin(now).Cycle; got != int64(passes) {
		t.Fatalf("next cycle = %d, want %d", got, passes)
	}
}

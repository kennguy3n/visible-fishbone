package compliance_test

import (
	"context"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

func newScheduler(t *testing.T, now func() time.Time, opts ...compliance.SchedulerOption) (*compliance.Scheduler, *compliance.EvidenceService) {
	t.Helper()
	svc, _, _ := newEvidenceService(t)
	src := compliance.Sources{
		RBACPolicy: func(context.Context) (any, error) { return map[string]string{"role": "admin"}, nil },
		HAConfig:   func(context.Context) (any, error) { return map[string]string{"model": "active-active"}, nil },
	}
	collectorOpts := []compliance.CollectorOption{}
	if now != nil {
		collectorOpts = append(collectorOpts, compliance.WithCollectorClock(now))
	}
	collector := compliance.NewSOC2Collector(src, nil, collectorOpts...)
	if now != nil {
		opts = append(opts, compliance.WithSchedulerClock(now))
	}
	sched, err := compliance.NewScheduler(collector, svc, nil, opts...)
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}
	return sched, svc
}

func TestScheduler_NewRejectsNilDeps(t *testing.T) {
	if _, err := compliance.NewScheduler(nil, nil, nil); err == nil {
		t.Fatal("expected error for nil collector/evidence")
	}
}

func TestScheduler_CollectWeekly(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC) }
	sched, _ := newScheduler(t, clock)

	row, err := sched.CollectWeekly(context.Background())
	if err != nil {
		t.Fatalf("CollectWeekly: %v", err)
	}
	if row.CollectionType != compliance.CollectionWeekly {
		t.Fatalf("type = %q, want weekly", row.CollectionType)
	}
	if row.Status != compliance.StatusCollected {
		t.Fatalf("status = %q, want collected", row.Status)
	}
}

func TestScheduler_AggregateMonthly(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC) }
	sched, svc := newScheduler(t, clock)
	ctx := context.Background()

	// Two weekly bundles within the aggregation window.
	w1, err := sched.CollectWeekly(ctx)
	if err != nil {
		t.Fatalf("CollectWeekly 1: %v", err)
	}
	w2, err := sched.CollectWeekly(ctx)
	if err != nil {
		t.Fatalf("CollectWeekly 2: %v", err)
	}

	monthly, err := sched.AggregateMonthly(ctx)
	if err != nil {
		t.Fatalf("AggregateMonthly: %v", err)
	}
	if monthly.CollectionType != compliance.CollectionMonthly {
		t.Fatalf("type = %q, want monthly", monthly.CollectionType)
	}

	// Constituent weeklies are transitioned to 'aggregated'.
	for _, id := range []repository.ComplianceEvidence{w1, w2} {
		got, err := svc.Get(ctx, id.ID)
		if err != nil {
			t.Fatalf("Get weekly: %v", err)
		}
		if got.Status != compliance.StatusAggregated {
			t.Fatalf("weekly %s status = %q, want aggregated", got.ID, got.Status)
		}
	}
}

func TestScheduler_AggregateMonthly_NoEvidence(t *testing.T) {
	sched, _ := newScheduler(t, func() time.Time { return time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC) })
	if _, err := sched.AggregateMonthly(context.Background()); err == nil {
		t.Fatal("expected ErrNoEvidence when no weeklies exist")
	}
}

func TestScheduler_DetectGaps(t *testing.T) {
	ctx := context.Background()

	// 1) No weekly at all → MissingWeekly.
	sched, _ := newScheduler(t, func() time.Time { return time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC) })
	rep, err := sched.DetectGaps(ctx)
	if err != nil {
		t.Fatalf("DetectGaps (missing): %v", err)
	}
	if !rep.MissingWeekly || !rep.HasGap() {
		t.Fatalf("expected MissingWeekly gap, got %+v", rep)
	}

	// 2) Fresh weekly → no gap. Collect at the same instant the gap
	// check evaluates.
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	sched2, _ := newScheduler(t, func() time.Time { return fixed })
	if _, err := sched2.CollectWeekly(ctx); err != nil {
		t.Fatalf("CollectWeekly: %v", err)
	}
	rep, err = sched2.DetectGaps(ctx)
	if err != nil {
		t.Fatalf("DetectGaps (fresh): %v", err)
	}
	if rep.HasGap() {
		t.Fatalf("expected no gap for fresh weekly, got %+v", rep)
	}

	// 3) Stale weekly → StaleWeekly. Collect in the past relative to a
	// later "now" beyond the max-age window.
	collectAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	checkAt := collectAt.Add(compliance.DefaultWeeklyMaxAge + 24*time.Hour)
	clk := &mutableClock{t: collectAt}
	sched3, _ := newScheduler(t, clk.now)
	if _, err := sched3.CollectWeekly(ctx); err != nil {
		t.Fatalf("CollectWeekly: %v", err)
	}
	clk.t = checkAt
	rep, err = sched3.DetectGaps(ctx)
	if err != nil {
		t.Fatalf("DetectGaps (stale): %v", err)
	}
	if !rep.StaleWeekly || !rep.HasGap() {
		t.Fatalf("expected StaleWeekly gap, got %+v", rep)
	}
}

// mutableClock is a test clock whose value can be advanced between
// calls so a single scheduler observes a collection in the past and a
// gap check in the present.
type mutableClock struct{ t time.Time }

func (c *mutableClock) now() time.Time { return c.t }

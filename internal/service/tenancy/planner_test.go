package tenancy

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func ptr(t time.Time) *time.Time { return &t }

func TestClassify(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	c := Classifier{IdleAfter: 24 * time.Hour, DormantAfter: 14 * 24 * time.Hour}

	cases := []struct {
		name       string
		lastActive *time.Time
		want       Tier
	}{
		{"never seen is dormant", nil, TierDormant},
		{"seen now is active", ptr(now), TierActive},
		{"seen 1h ago is active", ptr(now.Add(-time.Hour)), TierActive},
		{"just under idle threshold is active", ptr(now.Add(-24*time.Hour + time.Minute)), TierActive},
		{"exactly idle threshold is idle", ptr(now.Add(-24 * time.Hour)), TierIdle},
		{"7d ago is idle", ptr(now.Add(-7 * 24 * time.Hour)), TierIdle},
		{"just under dormant threshold is idle", ptr(now.Add(-14*24*time.Hour + time.Minute)), TierIdle},
		{"exactly dormant threshold is dormant", ptr(now.Add(-14 * 24 * time.Hour)), TierDormant},
		{"30d ago is dormant", ptr(now.Add(-30 * 24 * time.Hour)), TierDormant},
		{"future timestamp (clock skew) is active", ptr(now.Add(time.Hour)), TierActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := c.Classify(now, tc.lastActive); got != tc.want {
				t.Fatalf("Classify(%v) = %v, want %v", tc.lastActive, got, tc.want)
			}
		})
	}
}

func TestClassifyFailSafe(t *testing.T) {
	now := time.Now().UTC()
	// Unconfigured / contradictory classifiers must never bucket a live
	// tenant as dormant — they fail toward "active" (do more work).
	for _, c := range []Classifier{
		{},                                      // zero value
		{IdleAfter: 0, DormantAfter: time.Hour}, // no idle threshold
		{IdleAfter: time.Hour, DormantAfter: time.Hour},         // dormant <= idle
		{IdleAfter: 2 * time.Hour, DormantAfter: 1 * time.Hour}, // inverted
	} {
		if got := c.Classify(now, nil); got != TierActive {
			t.Fatalf("invalid classifier %+v should fail safe to active, got %v", c, got)
		}
		if got := c.Classify(now, ptr(now.Add(-365*24*time.Hour))); got != TierActive {
			t.Fatalf("invalid classifier %+v should fail safe to active even for ancient tenant, got %v", c, got)
		}
	}
}

func TestShouldVisitCadence(t *testing.T) {
	p := SweepPlanner{
		Classifier:   Classifier{IdleAfter: 24 * time.Hour, DormantAfter: 14 * 24 * time.Hour},
		IdleEvery:    10,
		DormantEvery: 100,
	}

	// Active is always visited.
	for _, cycle := range []int64{0, 1, 7, 99, 1000} {
		if !p.ShouldVisit(TierActive, cycle) {
			t.Fatalf("active tenant must be visited on cycle %d", cycle)
		}
	}

	// Cycle 0 visits every tier (full startup sweep).
	if !p.ShouldVisit(TierIdle, 0) || !p.ShouldVisit(TierDormant, 0) {
		t.Fatal("cycle 0 must visit all tiers")
	}

	// Idle: every 10th cycle.
	idleVisited := map[int64]bool{10: true, 20: true, 100: true}
	for _, cycle := range []int64{1, 5, 9, 11, 19} {
		if p.ShouldVisit(TierIdle, cycle) {
			t.Fatalf("idle tenant should be skipped on cycle %d", cycle)
		}
	}
	for cycle := range idleVisited {
		if !p.ShouldVisit(TierIdle, cycle) {
			t.Fatalf("idle tenant should be visited on cycle %d", cycle)
		}
	}

	// Dormant: every 100th cycle.
	for _, cycle := range []int64{1, 10, 50, 99, 101, 150} {
		if p.ShouldVisit(TierDormant, cycle) {
			t.Fatalf("dormant tenant should be skipped on cycle %d", cycle)
		}
	}
	for _, cycle := range []int64{100, 200, 1000} {
		if !p.ShouldVisit(TierDormant, cycle) {
			t.Fatalf("dormant tenant should be visited on cycle %d", cycle)
		}
	}
}

func TestShouldVisitEveryLessOrEqualOne(t *testing.T) {
	// A planner with cadence <= 1 degrades to "visit every cycle",
	// i.e. the legacy behaviour (no skipping).
	p := SweepPlanner{
		Classifier:   Classifier{IdleAfter: time.Hour, DormantAfter: 2 * time.Hour},
		IdleEvery:    1,
		DormantEvery: 0,
	}
	for _, cycle := range []int64{1, 2, 3, 17} {
		if !p.ShouldVisit(TierIdle, cycle) || !p.ShouldVisit(TierDormant, cycle) {
			t.Fatalf("cadence<=1 must visit every cycle (cycle %d)", cycle)
		}
	}
}

func TestPlanFiltersAndPreservesOrder(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	p := DefaultPlanner()

	active := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-time.Hour))}
	idle := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-3 * 24 * time.Hour))}
	dormant := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-30 * 24 * time.Hour))}
	never := repository.TenantActivity{ID: uuid.New(), LastActiveAt: nil}
	acts := []repository.TenantActivity{active, idle, dormant, never}

	// Cycle 1: only the active tenant is due (idle every 10, dormant every 100).
	got := p.Plan(now, 1, acts)
	if len(got) != 1 || got[0] != active.ID {
		t.Fatalf("cycle 1 should visit only the active tenant, got %v", got)
	}

	// Cycle 10: active + idle (10%10==0, 10%100!=0).
	got = p.Plan(now, 10, acts)
	if len(got) != 2 || got[0] != active.ID || got[1] != idle.ID {
		t.Fatalf("cycle 10 should visit active+idle in order, got %v", got)
	}

	// Cycle 100: everyone (active always, idle 100%10==0, dormant+never 100%100==0).
	got = p.Plan(now, 100, acts)
	if len(got) != 4 {
		t.Fatalf("cycle 100 should visit all 4 tenants, got %v", got)
	}
	// Order preserved from input.
	want := []uuid.UUID{active.ID, idle.ID, dormant.ID, never.ID}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("cycle 100 order mismatch at %d: got %v want %v", i, got, want)
		}
	}

	// Cycle 0: full startup sweep visits all.
	if len(p.Plan(now, 0, acts)) != 4 {
		t.Fatal("cycle 0 should visit all tenants")
	}
}

func TestSummarize(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	p := DefaultPlanner()
	acts := []repository.TenantActivity{
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-time.Hour))},           // active
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-time.Hour))},           // active
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-3 * 24 * time.Hour))},  // idle
		{ID: uuid.New(), LastActiveAt: nil},                                // dormant
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-90 * 24 * time.Hour))}, // dormant
	}

	s := p.Summarize(now, 1, acts)
	if s.Active != 2 || s.Idle != 1 || s.Dormant != 2 || s.Total != 5 {
		t.Fatalf("tier tallies wrong: %+v", s)
	}
	// Cycle 1: only the 2 active tenants are visited; 3 skipped.
	if s.Visited != 2 || s.Skipped != 3 {
		t.Fatalf("cycle 1 visited/skipped wrong: %+v", s)
	}

	// Cycle 100: all visited.
	s = p.Summarize(now, 100, acts)
	if s.Visited != 5 || s.Skipped != 0 {
		t.Fatalf("cycle 100 should visit all: %+v", s)
	}
}

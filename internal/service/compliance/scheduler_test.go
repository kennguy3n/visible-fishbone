package compliance_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
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

// TestScheduler_AggregateMonthly_ExcludesAndPreservesFailed is a
// regression test: monthly aggregation must roll up only successfully
// 'collected' weeklies. A 'failed' weekly (e.g. an S3 upload error)
// must be excluded from the manifest and must KEEP its 'failed' status
// so operators and gap detection can still see it — it must never be
// silently masked as 'aggregated'.
func TestScheduler_AggregateMonthly_ExcludesAndPreservesFailed(t *testing.T) {
	clock := func() time.Time { return time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC) }
	ctx := context.Background()

	// Build the scheduler over a repo we keep a handle to, so we can
	// seed a 'failed' weekly directly.
	store := memory.NewStore()
	repo := memory.NewComplianceEvidenceRepository(store)
	objStore := compliance.NewMemoryObjectStore()
	signer, err := compliance.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	svc, err := compliance.NewEvidenceService(repo, objStore, signer, nil)
	if err != nil {
		t.Fatalf("NewEvidenceService: %v", err)
	}
	src := compliance.Sources{
		RBACPolicy: func(context.Context) (any, error) { return map[string]string{"role": "admin"}, nil },
	}
	collector := compliance.NewSOC2Collector(src, nil, compliance.WithCollectorClock(clock))
	sched, err := compliance.NewScheduler(collector, svc, nil, compliance.WithSchedulerClock(clock))
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	// One genuinely collected weekly (within the window).
	collected, err := sched.CollectWeekly(ctx)
	if err != nil {
		t.Fatalf("CollectWeekly: %v", err)
	}

	// A failed weekly within the window, seeded directly.
	failed, err := repo.Create(ctx, repository.ComplianceEvidence{
		ID:             uuid.New(),
		CollectionType: compliance.CollectionWeekly,
		CollectedAt:    clock().Add(-24 * time.Hour),
		S3Key:          "compliance-evidence/type=weekly/date=2026-07-09/failed.json",
		Signature:      "deadbeef",
		Status:         compliance.StatusFailed,
	})
	if err != nil {
		t.Fatalf("seed failed weekly: %v", err)
	}

	monthly, err := sched.AggregateMonthly(ctx)
	if err != nil {
		t.Fatalf("AggregateMonthly: %v", err)
	}

	// The failed weekly KEEPS its status.
	gotFailed, err := svc.Get(ctx, failed.ID)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if gotFailed.Status != compliance.StatusFailed {
		t.Fatalf("failed weekly status = %q, want failed (must not be masked)", gotFailed.Status)
	}

	// The collected weekly becomes aggregated.
	gotCollected, err := svc.Get(ctx, collected.ID)
	if err != nil {
		t.Fatalf("Get collected: %v", err)
	}
	if gotCollected.Status != compliance.StatusAggregated {
		t.Fatalf("collected weekly status = %q, want aggregated", gotCollected.Status)
	}

	// The manifest references only the collected weekly.
	_, body, err := svc.Download(ctx, monthly.ID)
	if err != nil {
		t.Fatalf("Download monthly: %v", err)
	}
	var bundle struct {
		Artifacts []struct {
			Name string          `json:"name"`
			Data json.RawMessage `json:"data"`
		} `json:"artifacts"`
	}
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatalf("unmarshal bundle: %v", err)
	}
	var manifest struct {
		WeeklyCount   int `json:"weekly_count"`
		WeeklyBundles []struct {
			ID string `json:"id"`
		} `json:"weekly_bundles"`
	}
	if len(bundle.Artifacts) != 1 {
		t.Fatalf("monthly bundle artifacts = %d, want 1", len(bundle.Artifacts))
	}
	if err := json.Unmarshal(bundle.Artifacts[0].Data, &manifest); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if manifest.WeeklyCount != 1 {
		t.Fatalf("manifest weekly_count = %d, want 1 (failed excluded)", manifest.WeeklyCount)
	}
	if len(manifest.WeeklyBundles) != 1 || manifest.WeeklyBundles[0].ID != collected.ID.String() {
		t.Fatalf("manifest should reference only the collected weekly, got %+v", manifest.WeeklyBundles)
	}
}

// mutableClock is a test clock whose value can be advanced between
// calls so a single scheduler observes a collection in the past and a
// gap check in the present.
type mutableClock struct{ t time.Time }

func (c *mutableClock) now() time.Time { return c.t }

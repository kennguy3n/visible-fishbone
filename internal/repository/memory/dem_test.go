package memory_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func f64(v float64) *float64 { return &v }

func makeDEMTarget(key string) repository.DEMTarget {
	return repository.DEMTarget{
		TargetKey:       key,
		Name:            "Target " + key,
		ProbeKind:       "https",
		Address:         "https://example.test/health",
		Enabled:         true,
		IntervalSeconds: 60,
		TimeoutMs:       5000,
	}
}

func successResult(targetKey string, totalMs float64, observedAt time.Time) repository.DEMProbeResult {
	return repository.DEMProbeResult{
		TargetKey:  targetKey,
		TargetName: "Target " + targetKey,
		ProbeKind:  "https",
		Success:    true,
		TotalMs:    f64(totalMs),
		HTTPStatus: func() *int { v := 200; return &v }(),
		ObservedAt: observedAt,
	}
}

func failResult(targetKey string, observedAt time.Time) repository.DEMProbeResult {
	return repository.DEMProbeResult{
		TargetKey:  targetKey,
		TargetName: "Target " + targetKey,
		ProbeKind:  "https",
		Success:    false,
		ErrorKind:  "timeout",
		ObservedAt: observedAt,
	}
}

// --- Targets ------------------------------------------------------------

func TestDEM_Target_CRUD(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()

	created, err := repo.CreateTarget(ctx(), tenant, makeDEMTarget("salesforce"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.ID == uuid.Nil || created.TenantID != tenant {
		t.Fatalf("create did not stamp id/tenant: %+v", created)
	}

	// Duplicate (tenant, target_key) -> conflict.
	if _, err := repo.CreateTarget(ctx(), tenant, makeDEMTarget("salesforce")); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("duplicate create err = %v, want ErrConflict", err)
	}

	got, err := repo.GetTarget(ctx(), tenant, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.TargetKey != "salesforce" {
		t.Fatalf("get key = %q", got.TargetKey)
	}

	// Tenant isolation.
	if _, err := repo.GetTarget(ctx(), uuid.New(), created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant get err = %v, want ErrNotFound", err)
	}

	upd := got
	upd.Enabled = false
	upd.Name = "Renamed"
	updated, err := repo.UpdateTarget(ctx(), tenant, upd)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Enabled || updated.Name != "Renamed" {
		t.Fatalf("update not applied: %+v", updated)
	}

	if err := repo.DeleteTarget(ctx(), tenant, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetTarget(ctx(), tenant, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("get after delete err = %v, want ErrNotFound", err)
	}
	if err := repo.DeleteTarget(ctx(), tenant, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("double delete err = %v, want ErrNotFound", err)
	}
}

func TestDEM_Target_ListPagination(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()
	for i := 0; i < 5; i++ {
		if _, err := repo.CreateTarget(ctx(), tenant, makeDEMTarget(string(rune('a'+i)))); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	page1, err := repo.ListTargets(ctx(), tenant, repository.Page{Limit: 2})
	if err != nil {
		t.Fatalf("list page1: %v", err)
	}
	if len(page1.Items) != 2 || page1.NextCursor == "" {
		t.Fatalf("page1 = %d items, cursor=%q", len(page1.Items), page1.NextCursor)
	}
	seen := map[uuid.UUID]bool{}
	cursor := page1.NextCursor
	for _, it := range page1.Items {
		seen[it.ID] = true
	}
	for cursor != "" {
		pg, err := repo.ListTargets(ctx(), tenant, repository.Page{Limit: 2, After: cursor})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		for _, it := range pg.Items {
			if seen[it.ID] {
				t.Fatalf("duplicate item across pages: %s", it.ID)
			}
			seen[it.ID] = true
		}
		cursor = pg.NextCursor
	}
	if len(seen) != 5 {
		t.Fatalf("paged %d distinct items, want 5", len(seen))
	}
}

// --- Probe results + window aggregate -----------------------------------

func TestDEM_WindowAggregate_Percentiles(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()
	base := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	results := []repository.DEMProbeResult{
		successResult("zoom", 10, base.Add(1*time.Second)),
		successResult("zoom", 20, base.Add(2*time.Second)),
		successResult("zoom", 30, base.Add(3*time.Second)),
		successResult("zoom", 40, base.Add(4*time.Second)),
		successResult("zoom", 50, base.Add(5*time.Second)),
		failResult("zoom", base.Add(6*time.Second)),
		// Different target — must not leak into the zoom aggregate.
		successResult("slack", 999, base.Add(2*time.Second)),
	}
	if err := repo.InsertProbeResults(ctx(), tenant, results); err != nil {
		t.Fatalf("insert: %v", err)
	}

	agg, err := repo.WindowAggregate(ctx(), tenant, "zoom", base)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.SampleCount != 6 || agg.SuccessCount != 5 {
		t.Fatalf("counts = %d/%d, want 6/5", agg.SuccessCount, agg.SampleCount)
	}
	if agg.LatencyP50Ms == nil || *agg.LatencyP50Ms != 30 {
		t.Fatalf("p50 = %v, want 30", agg.LatencyP50Ms)
	}
	if agg.LatencyP95Ms == nil || *agg.LatencyP95Ms != 48 {
		t.Fatalf("p95 = %v, want 48", agg.LatencyP95Ms)
	}
	if !agg.WindowStart.Equal(base.Add(1*time.Second)) || !agg.WindowEnd.Equal(base.Add(6*time.Second)) {
		t.Fatalf("window = [%s, %s]", agg.WindowStart, agg.WindowEnd)
	}

	// `since` bound excludes the early samples.
	agg2, err := repo.WindowAggregate(ctx(), tenant, "zoom", base.Add(4*time.Second))
	if err != nil {
		t.Fatalf("aggregate2: %v", err)
	}
	if agg2.SampleCount != 3 || agg2.SuccessCount != 2 {
		t.Fatalf("bounded counts = %d/%d, want 2/3", agg2.SuccessCount, agg2.SampleCount)
	}
}

func TestDEM_WindowAggregate_AllFailed(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()
	base := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := repo.InsertProbeResults(ctx(), tenant, []repository.DEMProbeResult{
		failResult("ghost", base.Add(time.Second)),
		failResult("ghost", base.Add(2*time.Second)),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	agg, err := repo.WindowAggregate(ctx(), tenant, "ghost", base)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.SampleCount != 2 || agg.SuccessCount != 0 {
		t.Fatalf("counts = %d/%d, want 0/2", agg.SuccessCount, agg.SampleCount)
	}
	if agg.LatencyP50Ms != nil || agg.LatencyP95Ms != nil {
		t.Fatalf("expected nil percentiles when all failed")
	}
}

func TestDEM_PruneProbeResults(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()
	base := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	if err := repo.InsertProbeResults(ctx(), tenant, []repository.DEMProbeResult{
		successResult("a", 10, base),
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	// CreatedAt is stamped from the fixed clock (year 2025), so a
	// far-future cutoff prunes everything.
	removed, err := repo.PruneProbeResults(ctx(), time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1", removed)
	}
	agg, err := repo.WindowAggregate(ctx(), tenant, "a", base)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if agg.SampleCount != 0 {
		t.Fatalf("sample_count = %d after prune, want 0", agg.SampleCount)
	}
}

// --- Scores -------------------------------------------------------------

func TestDEM_Scores_ListAndLatest(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()
	base := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)

	mk := func(key string, score float64) repository.DEMExperienceScore {
		return repository.DEMExperienceScore{
			TargetKey:     key,
			TargetName:    "Target " + key,
			Score:         score,
			Availability:  1,
			LatencyP50Ms:  f64(20),
			SampleCount:   10,
			WindowSeconds: 300,
			WindowStart:   base,
			WindowEnd:     base.Add(5 * time.Minute),
		}
	}
	for _, sc := range []repository.DEMExperienceScore{
		mk("zoom", 90), mk("zoom", 80), mk("slack", 70),
	} {
		if _, err := repo.InsertScore(ctx(), tenant, sc); err != nil {
			t.Fatalf("insert score: %v", err)
		}
	}

	// Filter by target_key.
	zoomOnly, err := repo.ListScores(ctx(), tenant, repository.DEMScoreFilter{TargetKeys: []string{"zoom"}}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list zoom: %v", err)
	}
	if len(zoomOnly.Items) != 2 {
		t.Fatalf("zoom scores = %d, want 2", len(zoomOnly.Items))
	}

	latest, err := repo.LatestScores(ctx(), tenant)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if len(latest) != 2 {
		t.Fatalf("latest = %d targets, want 2", len(latest))
	}
	for _, sc := range latest {
		if sc.TargetKey == "zoom" && sc.Score != 80 {
			t.Fatalf("latest zoom score = %v, want 80 (newest)", sc.Score)
		}
	}
}

// --- Target state -------------------------------------------------------

func TestDEM_TargetState_Upsert(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()

	if _, found, err := repo.GetTargetState(ctx(), tenant, "zoom"); err != nil || found {
		t.Fatalf("initial get: found=%v err=%v, want false/nil", found, err)
	}

	first, err := repo.UpsertTargetState(ctx(), tenant, repository.DEMTargetState{
		TargetKey:   "zoom",
		TargetName:  "Zoom",
		EWMAScore:   f64(90),
		SampleCount: 1,
	})
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if first.ID == uuid.Nil {
		t.Fatalf("upsert did not stamp id")
	}

	second, err := repo.UpsertTargetState(ctx(), tenant, repository.DEMTargetState{
		TargetKey:   "zoom",
		TargetName:  "Zoom",
		EWMAScore:   f64(85),
		SampleCount: 2,
		Degraded:    true,
	})
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if second.ID != first.ID {
		t.Fatalf("upsert changed id: %s != %s", second.ID, first.ID)
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("upsert changed created_at")
	}
	if second.SampleCount != 2 || !second.Degraded || second.EWMAScore == nil || *second.EWMAScore != 85 {
		t.Fatalf("upsert update not applied: %+v", second)
	}

	got, found, err := repo.GetTargetState(ctx(), tenant, "zoom")
	if err != nil || !found {
		t.Fatalf("get after upsert: found=%v err=%v", found, err)
	}
	if got.SampleCount != 2 {
		t.Fatalf("persisted sample_count = %d, want 2", got.SampleCount)
	}
}

// TestDEM_MutateTargetState_FirstObservation verifies that the very
// first mutate sees a zero-valued baseline (no row yet) and that the
// returned state is persisted with a stamped id and timestamps.
func TestDEM_MutateTargetState_FirstObservation(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()

	var sawPrev repository.DEMTargetState
	out, err := repo.MutateTargetState(ctx(), tenant, "zoom", "Zoom",
		func(prev repository.DEMTargetState) (repository.DEMTargetState, error) {
			sawPrev = prev
			prev.EWMAScore = f64(90)
			prev.SampleCount++
			return prev, nil
		})
	if err != nil {
		t.Fatalf("mutate: %v", err)
	}
	if sawPrev.SampleCount != 0 || sawPrev.EWMAScore != nil {
		t.Fatalf("first mutate saw non-zero prev: %+v", sawPrev)
	}
	if out.ID == uuid.Nil || out.CreatedAt.IsZero() || out.SampleCount != 1 {
		t.Fatalf("first mutate persisted wrong row: %+v", out)
	}
}

// TestDEM_MutateTargetState_Concurrent is the regression test for the
// non-atomic read-modify-write race (Devin Review BUG_0001). N
// goroutines concurrently fold a sample into the same target's
// baseline; because MutateTargetState serializes the read-compute
// -write, every increment must land — the final sample_count equals N
// with no lost updates. Run under -race.
func TestDEM_MutateTargetState_Concurrent(t *testing.T) {
	s := newStore(t)
	repo := memory.NewDEMRepository(s)
	tenant := uuid.New()

	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := repo.MutateTargetState(ctx(), tenant, "zoom", "Zoom",
				func(prev repository.DEMTargetState) (repository.DEMTargetState, error) {
					prev.SampleCount++
					sum := float64(0)
					if prev.EWMAScore != nil {
						sum = *prev.EWMAScore
					}
					sum++
					prev.EWMAScore = &sum
					return prev, nil
				})
			if err != nil {
				t.Errorf("mutate: %v", err)
			}
		}()
	}
	wg.Wait()

	got, found, err := repo.GetTargetState(ctx(), tenant, "zoom")
	if err != nil || !found {
		t.Fatalf("get after concurrent mutate: found=%v err=%v", found, err)
	}
	if got.SampleCount != goroutines {
		t.Fatalf("lost updates: sample_count = %d, want %d", got.SampleCount, goroutines)
	}
	if got.EWMAScore == nil || *got.EWMAScore != float64(goroutines) {
		t.Fatalf("lost updates: ewma accumulator = %v, want %d", got.EWMAScore, goroutines)
	}
}

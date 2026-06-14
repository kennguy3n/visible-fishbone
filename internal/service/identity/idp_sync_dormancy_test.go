package identity

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

type fakeActivity struct {
	acts []repository.TenantActivity
	hits int
}

func (f *fakeActivity) ListTenantActivity(_ context.Context) ([]repository.TenantActivity, error) {
	f.hits++
	return f.acts, nil
}

// fullTenantSource is a TenantSource that must NOT be consulted once a
// dormancy planner is wired — calling it fails the test.
type fullTenantSource struct {
	t   *testing.T
	ids []uuid.UUID
}

func (s fullTenantSource) ListTenants(_ context.Context) ([]uuid.UUID, error) {
	s.t.Fatal("ListTenants should not be called when a dormancy planner is configured")
	return s.ids, nil
}

func newPlannerService(t *testing.T, act *fakeActivity, now time.Time) *SyncService {
	t.Helper()
	svc := NewSyncService(nil, nil, nil, nil, fullTenantSource{t: t}, nil, nil, nil, nil)
	svc.nowFunc = func() time.Time { return now }
	sweep := tenancy.NewTieredSweep("idp_directory_sync", tenancy.DefaultPlanner(), nil)
	return svc.WithDormancyPlanner(sweep, act)
}

func ptr(ts time.Time) *time.Time { return &ts }

func TestDueTenantsTieredCadence(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	active := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-time.Hour))}
	idle := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-3 * 24 * time.Hour))}
	dormant := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-30 * 24 * time.Hour))}
	never := repository.TenantActivity{ID: uuid.New(), LastActiveAt: nil}
	act := &fakeActivity{acts: []repository.TenantActivity{active, idle, dormant, never}}
	svc := newPlannerService(t, act, now)

	// dueTenants advances the sweep's internal 0-based cycle counter on
	// each call, so drive it sequentially and capture the due set at the
	// cadence-significant cycles (0 full, 1 active-only, 10 +idle, 100
	// +dormant). The first call is cycle 0.
	byCycle := map[int64][]uuid.UUID{}
	for cycle := int64(0); cycle <= 100; cycle++ {
		due, err := svc.dueTenants(context.Background())
		if err != nil {
			t.Fatalf("dueTenants cycle %d: %v", cycle, err)
		}
		byCycle[cycle] = due
	}

	if got := byCycle[0]; len(got) != 4 {
		t.Fatalf("cycle 0 should reconcile all 4 tenants, got %d", len(got))
	}
	if got := byCycle[1]; len(got) != 1 || got[0] != active.ID {
		t.Fatalf("cycle 1 should reconcile only active tenant, got %v", got)
	}
	if got := byCycle[10]; len(got) != 2 || got[0] != active.ID || got[1] != idle.ID {
		t.Fatalf("cycle 10 should reconcile active+idle, got %v", got)
	}
	if got := byCycle[100]; len(got) != 4 {
		t.Fatalf("cycle 100 should reconcile all 4 tenants, got %d", len(got))
	}
}

func TestSyncAllAdvancesCycleAndUsesPlanner(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	// Empty activity set: no tenant is due, so syncAll does no per-tenant
	// work (the repos are nil) — we are only asserting the planner path
	// is taken (activity source queried, cycle advanced, legacy fan-out
	// never used).
	act := &fakeActivity{acts: nil}
	svc := newPlannerService(t, act, now)

	// Two passes: cycle 0 (full) then cycle 1. The planner source must
	// be consulted each pass and the legacy full fan-out never used.
	svc.syncAll(context.Background())
	svc.syncAll(context.Background())
	if act.hits != 2 {
		t.Fatalf("activity source should be queried once per pass, got %d", act.hits)
	}
	// After two passes the next cycle the sweep hands out is 2 (it ran
	// cycles 0 and 1). Begin advances the counter, so this also asserts
	// monotonicity.
	if got := svc.sweep.Begin(now).Cycle; got != 2 {
		t.Fatalf("cycle counter should be 2 after two passes, got %d", got)
	}
}

func TestDueTenantsFallsBackWithoutPlanner(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	svc := NewSyncService(nil, nil, nil, nil, staticTenants{ids: ids}, nil, nil, nil, nil)
	due, err := svc.dueTenants(context.Background())
	if err != nil {
		t.Fatalf("dueTenants: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("legacy fan-out should return all tenants, got %d", len(due))
	}
}

type staticTenants struct{ ids []uuid.UUID }

func (s staticTenants) ListTenants(_ context.Context) ([]uuid.UUID, error) { return s.ids, nil }

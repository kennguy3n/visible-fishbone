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
	planner := tenancy.DefaultPlanner()
	return svc.WithDormancyPlanner(&planner, act)
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

	// Cycle 0 (startup): full reconcile of all tiers.
	due, err := svc.dueTenants(context.Background(), 0)
	if err != nil {
		t.Fatalf("dueTenants cycle 0: %v", err)
	}
	if len(due) != 4 {
		t.Fatalf("cycle 0 should reconcile all 4 tenants, got %d", len(due))
	}

	// Cycle 1: only the active tenant is due.
	due, _ = svc.dueTenants(context.Background(), 1)
	if len(due) != 1 || due[0] != active.ID {
		t.Fatalf("cycle 1 should reconcile only active tenant, got %v", due)
	}

	// Cycle 10: active + idle.
	due, _ = svc.dueTenants(context.Background(), 10)
	if len(due) != 2 || due[0] != active.ID || due[1] != idle.ID {
		t.Fatalf("cycle 10 should reconcile active+idle, got %v", due)
	}

	// Cycle 100: everyone (dormant + never-seen included).
	due, _ = svc.dueTenants(context.Background(), 100)
	if len(due) != 4 {
		t.Fatalf("cycle 100 should reconcile all 4 tenants, got %d", len(due))
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
	if got := svc.cycle.Load(); got != 2 {
		t.Fatalf("cycle counter should be 2 after two passes, got %d", got)
	}
}

func TestDueTenantsFallsBackWithoutPlanner(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	svc := NewSyncService(nil, nil, nil, nil, staticTenants{ids: ids}, nil, nil, nil, nil)
	due, err := svc.dueTenants(context.Background(), 5)
	if err != nil {
		t.Fatalf("dueTenants: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("legacy fan-out should return all tenants, got %d", len(due))
	}
}

type staticTenants struct{ ids []uuid.UUID }

func (s staticTenants) ListTenants(_ context.Context) ([]uuid.UUID, error) { return s.ids, nil }

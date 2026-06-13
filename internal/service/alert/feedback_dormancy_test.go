package alert

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

type fakeActivitySource struct {
	acts []repository.TenantActivity
	hits int
}

func (f *fakeActivitySource) ListTenantActivity(context.Context) ([]repository.TenantActivity, error) {
	f.hits++
	return f.acts, nil
}

func ptr(ts time.Time) *time.Time { return &ts }

// TestFeedbackDueTenantsTieredCadence pins the dormancy gating on the
// tuning loop: with a sweep configured the legacy tenantsFn is never
// consulted and the due set follows the activity-tiered cadence.
func TestFeedbackDueTenantsTieredCadence(t *testing.T) {
	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	active := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-time.Hour))}
	idle := repository.TenantActivity{ID: uuid.New(), LastActiveAt: ptr(now.Add(-3 * 24 * time.Hour))}
	dormant := repository.TenantActivity{ID: uuid.New(), LastActiveAt: nil}
	act := &fakeActivitySource{acts: []repository.TenantActivity{active, idle, dormant}}

	fb := NewFeedback(stubFeedback{}, nil, &trackingBaseline{release: make(chan struct{})}, FeedbackTuningOptions{})
	fb.now = func() time.Time { return now }
	sweep := tenancy.NewTieredSweep("alert_feedback_tuning", tenancy.DefaultPlanner(), nil)
	fb.WithDormancySweep(sweep, act)

	// tenantsFn fails the test if consulted — the sweep must own enumeration.
	tenantsFn := func(context.Context) ([]uuid.UUID, error) {
		t.Fatal("legacy tenantsFn must not be called when a dormancy sweep is configured")
		return nil, nil
	}

	byCycle := map[int64][]uuid.UUID{}
	for cycle := int64(0); cycle <= 100; cycle++ {
		due, err := fb.dueTenants(context.Background(), tenantsFn)
		if err != nil {
			t.Fatalf("dueTenants cycle %d: %v", cycle, err)
		}
		byCycle[cycle] = due
	}

	if got := byCycle[0]; len(got) != 3 {
		t.Fatalf("cycle 0 (full sweep) should tune all 3 tenants, got %d", len(got))
	}
	if got := byCycle[1]; len(got) != 1 || got[0] != active.ID {
		t.Fatalf("cycle 1 should tune only the active tenant, got %v", got)
	}
	if got := byCycle[10]; len(got) != 2 || got[0] != active.ID || got[1] != idle.ID {
		t.Fatalf("cycle 10 should tune active+idle, got %v", got)
	}
	if got := byCycle[100]; len(got) != 3 {
		t.Fatalf("cycle 100 should tune all 3 tenants, got %d", len(got))
	}
	if act.hits != 101 {
		t.Fatalf("activity source should be queried once per cycle, got %d", act.hits)
	}
}

// TestFeedbackDueTenantsFallsBackWithoutSweep asserts the default
// (no sweep) path delegates to the legacy full-fanout enumerator.
func TestFeedbackDueTenantsFallsBackWithoutSweep(t *testing.T) {
	ids := []uuid.UUID{uuid.New(), uuid.New()}
	fb := NewFeedback(stubFeedback{}, nil, &trackingBaseline{release: make(chan struct{})}, FeedbackTuningOptions{})
	due, err := fb.dueTenants(context.Background(), func(context.Context) ([]uuid.UUID, error) {
		return ids, nil
	})
	if err != nil {
		t.Fatalf("dueTenants: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("legacy fan-out should return all tenants, got %d", len(due))
	}
}

package capacity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

type fakeLister struct {
	acts []repository.TenantActivity
	err  error
}

func (f fakeLister) ListTenantActivity(context.Context) ([]repository.TenantActivity, error) {
	return f.acts, f.err
}

func ptr(t time.Time) *time.Time { return &t }

func TestRepoFleetObserverCounts(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	acts := []repository.TenantActivity{
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-1 * time.Hour))},  // active
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-30 * time.Hour))}, // idle (>24h)
		{ID: uuid.New(), LastActiveAt: nil},                           // never active
		{ID: uuid.New(), LastActiveAt: ptr(now.Add(-2 * time.Hour))},  // active
	}
	o := &RepoFleetObserver{
		tenants:      fakeLister{acts: acts},
		activeWindow: DefaultActiveWindow,
		now:          func() time.Time { return now },
	}

	obs, err := o.Observe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if obs.TenantCount != 4 {
		t.Errorf("TenantCount = %d, want 4", obs.TenantCount)
	}
	if obs.ActiveTenantCount != 2 {
		t.Errorf("ActiveTenantCount = %d, want 2", obs.ActiveTenantCount)
	}
	if !obs.ObservedAt.Equal(now) {
		t.Errorf("ObservedAt = %v, want %v", obs.ObservedAt, now)
	}
}

func TestRepoFleetObserverPropagatesError(t *testing.T) {
	o := &RepoFleetObserver{
		tenants:      fakeLister{err: errors.New("db down")},
		activeWindow: DefaultActiveWindow,
		now:          time.Now,
	}
	if _, err := o.Observe(context.Background()); err == nil {
		t.Fatal("expected error to propagate")
	}
}

func TestNewRepoFleetObserverDefaults(t *testing.T) {
	o := NewRepoFleetObserver(nil, 0, nil)
	if o.activeWindow != DefaultActiveWindow {
		t.Errorf("activeWindow = %v, want default %v", o.activeWindow, DefaultActiveWindow)
	}
	if o.now == nil {
		t.Error("now should default to time.Now")
	}
}

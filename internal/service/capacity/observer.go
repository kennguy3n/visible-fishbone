package capacity

import (
	"context"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultActiveWindow is the recency window RepoFleetObserver uses to
// classify a tenant as "active" for the reported ActiveTenantCount. It
// mirrors the dormancy planner's default IdleAfter (24h) so the active
// count the autopilot reports lines up with the tier the sweep planner
// treats as active. It is context only — the sizing model grades the
// total tenant count.
const DefaultActiveWindow = 24 * time.Hour

// tenantActivityLister is the slice of the tenant repository the
// observer needs: the single cheap (id, last_active_at) enumeration the
// dormancy planner already relies on. Declared as an interface so tests
// can drive the observer with a fake instead of a live database.
type tenantActivityLister interface {
	ListTenantActivity(ctx context.Context) ([]repository.TenantActivity, error)
}

// RepoFleetObserver reads the live fleet size from the tenant
// repository. It counts the non-deleted tenant rows (the model's
// primary scaling input) and, as operator context, how many were active
// within ActiveWindow.
type RepoFleetObserver struct {
	tenants tenantActivityLister
	// ActiveWindow is the recency cutoff for ActiveTenantCount.
	// <= 0 uses DefaultActiveWindow.
	activeWindow time.Duration
	now          func() time.Time
}

// NewRepoFleetObserver builds an observer over the tenant repository.
// A nil now uses time.Now; a non-positive window uses DefaultActiveWindow.
func NewRepoFleetObserver(tenants repository.TenantRepository, activeWindow time.Duration, now func() time.Time) *RepoFleetObserver {
	if activeWindow <= 0 {
		activeWindow = DefaultActiveWindow
	}
	if now == nil {
		now = time.Now
	}
	return &RepoFleetObserver{tenants: tenants, activeWindow: activeWindow, now: now}
}

// Observe enumerates live tenants once and returns the fleet
// observation. It does not populate EventsPerSec: the production
// reconciler sizes against the per-class model rates (matching the
// offline bench), and wiring a live telemetry-rate source is left as a
// future refinement (see the package doc and PR limitations).
func (o *RepoFleetObserver) Observe(ctx context.Context) (FleetObservation, error) {
	acts, err := o.tenants.ListTenantActivity(ctx)
	if err != nil {
		return FleetObservation{}, err
	}
	now := o.now()
	cutoff := now.Add(-o.activeWindow)
	active := 0
	for _, a := range acts {
		if a.LastActiveAt != nil && a.LastActiveAt.After(cutoff) {
			active++
		}
	}
	return FleetObservation{
		TenantCount:       len(acts),
		ActiveTenantCount: active,
		ObservedAt:        now,
	}, nil
}

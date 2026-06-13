package hibernation

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Registry is the per-replica in-memory snapshot of which tenants are
// hibernated. It is the shared, lock-free-read surface that the
// telemetry [SampleResolver] and [RetentionResolver] consult on the hot
// path and that the metering fleet view reads to mark a parked trial's
// projected cost near-zero.
//
// The durable source of truth is the [Store]; the leader-only
// [Controller] writes transitions there, a per-replica [Syncer]
// refreshes the registry from it, and the [Coordinator] clears an entry
// inline on wake so full telemetry resumes without waiting for the next
// sync. A nil *Registry is safe: IsHibernated reports false, so callers
// (e.g. a resolver wired only when the feature gate is on) need not
// branch on optional wiring.
type Registry struct {
	mu  sync.RWMutex
	hib map[uuid.UUID]struct{}
}

// NewRegistry returns an empty registry (every tenant active).
func NewRegistry() *Registry {
	return &Registry{hib: make(map[uuid.UUID]struct{})}
}

// IsHibernated reports whether the tenant is currently parked. A nil
// registry or nil tenant reports false (fail-safe toward more work).
func (r *Registry) IsHibernated(tenantID uuid.UUID) bool {
	if r == nil || tenantID == uuid.Nil {
		return false
	}
	r.mu.RLock()
	_, ok := r.hib[tenantID]
	r.mu.RUnlock()
	return ok
}

// Replace atomically swaps the hibernated set for the given ids. It is
// how the [Syncer] reconciles the registry to the store each cycle:
// tenants no longer in the set become active, new ones become parked.
func (r *Registry) Replace(ids []uuid.UUID) {
	next := make(map[uuid.UUID]struct{}, len(ids))
	for _, id := range ids {
		if id != uuid.Nil {
			next[id] = struct{}{}
		}
	}
	r.mu.Lock()
	r.hib = next
	r.mu.Unlock()
}

// Clear removes a single tenant from the hibernated set. Used by the
// [Coordinator] to resume full telemetry the instant a parked tenant
// shows activity, ahead of the next store sync. A no-op for a tenant
// that is not parked.
func (r *Registry) Clear(tenantID uuid.UUID) {
	if r == nil || tenantID == uuid.Nil {
		return
	}
	r.mu.Lock()
	delete(r.hib, tenantID)
	r.mu.Unlock()
}

// Len returns the number of currently-hibernated tenants. Used for the
// fleet gauge and tests.
func (r *Registry) Len() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	n := len(r.hib)
	r.mu.RUnlock()
	return n
}

// Syncer reconciles a [Registry] to the [Store] on a fixed cadence. It
// runs on EVERY replica (not just the leader): the leader-only
// controller writes transitions to the store, and each replica's syncer
// pulls them into its local registry so the telemetry sampler and
// retention resolver on every replica honor the current parked set.
type Syncer struct {
	store  Store
	reg    *Registry
	logger *slog.Logger
}

// NewSyncer wires a Syncer. store and reg must be non-nil. A nil logger
// is replaced with a discard logger.
func NewSyncer(store Store, reg *Registry, logger *slog.Logger) *Syncer {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(noopWriter{}, nil))
	}
	return &Syncer{store: store, reg: reg, logger: logger}
}

// Refresh performs a single store→registry reconcile.
func (s *Syncer) Refresh(ctx context.Context) error {
	recs, err := s.store.List(ctx)
	if err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(recs))
	for _, rec := range recs {
		if rec.State.Hibernated() {
			ids = append(ids, rec.TenantID)
		}
	}
	s.reg.Replace(ids)
	return nil
}

// Run refreshes immediately, then on every tick until ctx is cancelled.
// A refresh failure is logged and retried on the next tick — a stale
// registry fails safe toward more work (a tenant whose hibernation row
// is missed stays active, i.e. fully sampled), so a transient store
// error never silently parks a live tenant.
func (s *Syncer) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
		s.logger.Warn("hibernation: registry refresh failed", slog.Any("error", err))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Refresh(ctx); err != nil && ctx.Err() == nil {
				s.logger.Warn("hibernation: registry refresh failed", slog.Any("error", err))
			}
		}
	}
}

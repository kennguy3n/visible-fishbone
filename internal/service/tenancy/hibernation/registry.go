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
//
// Wake/sync race: [Coordinator.Wake] clears an entry inline and then
// persists the active state, but a [Syncer] refresh whose store snapshot
// predates that write would re-add the tenant on its next [Replace],
// briefly re-parking a tenant the user just woke. To close that window
// Clear records a wake timestamp and Replace skips any tenant woken
// within wakeGrace, trusting the recent local wake over a possibly-stale
// store read. This fails safe toward MORE telemetry; once the wake has
// propagated to the store the tenant simply stays out of the parked set.
type Registry struct {
	mu        sync.RWMutex
	hib       map[uuid.UUID]struct{}
	wokeAt    map[uuid.UUID]time.Time
	wakeGrace time.Duration
	now       func() time.Time
}

// DefaultWakeGrace is how long Replace suppresses re-hibernating a
// tenant after an inline wake. It must comfortably exceed the registry
// sync interval so a store write from the wake is visible to the next
// refresh before the grace lapses.
const DefaultWakeGrace = 5 * time.Minute

// RegistryOption customises a Registry at construction.
type RegistryOption func(*Registry)

// WithWakeGrace overrides the post-wake re-hibernation suppression
// window. Values <= 0 are ignored.
func WithWakeGrace(d time.Duration) RegistryOption {
	return func(r *Registry) {
		if d > 0 {
			r.wakeGrace = d
		}
	}
}

// WithRegistryClock overrides the time source (tests). A nil clock is
// ignored.
func WithRegistryClock(now func() time.Time) RegistryOption {
	return func(r *Registry) {
		if now != nil {
			r.now = now
		}
	}
}

// NewRegistry returns an empty registry (every tenant active).
func NewRegistry(opts ...RegistryOption) *Registry {
	r := &Registry{
		hib:       make(map[uuid.UUID]struct{}),
		wokeAt:    make(map[uuid.UUID]time.Time),
		wakeGrace: DefaultWakeGrace,
		now:       time.Now,
	}
	for _, o := range opts {
		o(r)
	}
	return r
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
// tenants no longer in the set become active, new ones become parked. A
// tenant woken within wakeGrace is skipped so a store snapshot that
// predates the wake's persisted active state cannot transiently re-park
// it (see the Registry doc comment).
func (r *Registry) Replace(ids []uuid.UUID) {
	if r == nil {
		return
	}
	next := make(map[uuid.UUID]struct{}, len(ids))
	r.mu.Lock()
	now := r.now()
	for _, id := range ids {
		if id == uuid.Nil {
			continue
		}
		if t, ok := r.wokeAt[id]; ok && now.Sub(t) < r.wakeGrace {
			continue
		}
		next[id] = struct{}{}
	}
	for id, t := range r.wokeAt {
		if now.Sub(t) >= r.wakeGrace {
			delete(r.wokeAt, id)
		}
	}
	r.hib = next
	r.mu.Unlock()
}

// Clear removes a single tenant from the hibernated set. Used by the
// [Coordinator] to resume full telemetry the instant a parked tenant
// shows activity, ahead of the next store sync. It also stamps a wake
// time so a racing [Replace] (from a syncer snapshot taken before the
// wake was persisted) does not re-park the tenant within wakeGrace. A
// no-op for a tenant that is not parked, but the wake stamp is recorded
// regardless so the suppression holds even if Clear lands first.
func (r *Registry) Clear(tenantID uuid.UUID) {
	if r == nil || tenantID == uuid.Nil {
		return
	}
	r.mu.Lock()
	delete(r.hib, tenantID)
	r.wokeAt[tenantID] = r.now()
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

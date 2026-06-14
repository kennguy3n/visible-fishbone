package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy/hibernation"
)

// TenantHibernationRepository is the memory-backed implementation of
// hibernation.Store. It is cross-tenant (system-scoped) by design — the
// leader-only controller and per-replica registry sync read/write the
// whole set — mirroring the Postgres system policy in migration 068.
//
// Like the capability-rollout store, this is a self-contained feature
// whose table is introduced by a single migration, so its state is kept
// local rather than hanging off the shared Store. Construct one with
// [NewTenantHibernationRepository] and share it like any other repo in a
// test.
type TenantHibernationRepository struct {
	mu   sync.RWMutex
	now  func() time.Time
	rows map[uuid.UUID]hibernation.Record
}

// NewTenantHibernationRepository returns an empty in-memory hibernation
// store.
func NewTenantHibernationRepository() *TenantHibernationRepository {
	return &TenantHibernationRepository{
		now:  func() time.Time { return time.Now().UTC() },
		rows: make(map[uuid.UUID]hibernation.Record),
	}
}

var _ hibernation.Store = (*TenantHibernationRepository)(nil)

// SetClock overrides the time source for deterministic tests.
func (r *TenantHibernationRepository) SetClock(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// List returns every stored record in tenant_id order.
func (r *TenantHibernationRepository) List(ctx context.Context) ([]hibernation.Record, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.mu.RLock()
	out := make([]hibernation.Record, 0, len(r.rows))
	for _, rec := range r.rows {
		out = append(out, rec)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].TenantID.String() < out[j].TenantID.String()
	})
	return out, nil
}

// SetHibernated upserts the tenant to the hibernated state.
func (r *TenantHibernationRepository) SetHibernated(ctx context.Context, tenantID uuid.UUID, reason string, at time.Time) (hibernation.Record, error) {
	return r.upsert(ctx, tenantID, hibernation.StateHibernated, reason, at)
}

// SetActive upserts the tenant to the active state.
func (r *TenantHibernationRepository) SetActive(ctx context.Context, tenantID uuid.UUID, reason string, at time.Time) (hibernation.Record, error) {
	return r.upsert(ctx, tenantID, hibernation.StateActive, reason, at)
}

func (r *TenantHibernationRepository) upsert(ctx context.Context, tenantID uuid.UUID, state hibernation.State, reason string, at time.Time) (hibernation.Record, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return hibernation.Record{}, err
	}
	if tenantID == uuid.Nil || !state.Valid() {
		return hibernation.Record{}, repository.ErrInvalidArgument
	}
	if at.IsZero() {
		at = r.now()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stored := hibernation.Record{
		TenantID:  tenantID,
		State:     state,
		Reason:    reason,
		UpdatedAt: r.now(),
	}
	if existing, ok := r.rows[tenantID]; ok {
		stored.HibernatedAt = existing.HibernatedAt
		stored.WokeAt = existing.WokeAt
	}
	if state.Hibernated() {
		t := at
		stored.HibernatedAt = &t
	} else {
		t := at
		stored.WokeAt = &t
	}
	r.rows[tenantID] = stored
	return stored, nil
}

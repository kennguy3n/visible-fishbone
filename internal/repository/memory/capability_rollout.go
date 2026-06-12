package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// CapabilityRolloutRepository is the memory-backed implementation of
// rollout.Repository. Tenant isolation is enforced by filtering on
// tenant_id, mirroring the Postgres RLS policy in migration 066.
//
// Like the DLP review queue, this is a self-contained feature whose
// table is introduced by a single migration, so its state is kept local
// rather than hanging off the shared Store. Construct one with
// [NewCapabilityRolloutRepository] and share it like any other repo in a
// test.
type CapabilityRolloutRepository struct {
	mu  sync.RWMutex
	now func() time.Time
	// rows is keyed by (tenant_id, capability), the table's composite PK.
	rows map[capabilityRolloutKey]rollout.Record
}

type capabilityRolloutKey struct {
	tenant     uuid.UUID
	capability rollout.Capability
}

// NewCapabilityRolloutRepository returns an empty in-memory rollout
// store. now may be nil (defaults to time.Now UTC).
func NewCapabilityRolloutRepository() *CapabilityRolloutRepository {
	return &CapabilityRolloutRepository{
		now:  func() time.Time { return time.Now().UTC() },
		rows: make(map[capabilityRolloutKey]rollout.Record),
	}
}

var _ rollout.Repository = (*CapabilityRolloutRepository)(nil)

// SetClock overrides the time source for deterministic tests.
func (r *CapabilityRolloutRepository) SetClock(now func() time.Time) {
	if now != nil {
		r.now = now
	}
}

// Get returns the record for (tenant, capability), or ErrNotFound.
func (r *CapabilityRolloutRepository) Get(ctx context.Context, tenantID uuid.UUID, c rollout.Capability) (rollout.Record, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return rollout.Record{}, err
	}
	if tenantID == uuid.Nil || !c.Valid() {
		return rollout.Record{}, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.rows[capabilityRolloutKey{tenant: tenantID, capability: c}]
	if !ok {
		return rollout.Record{}, repository.ErrNotFound
	}
	return rec, nil
}

// List returns every stored record for the tenant, in capability order.
func (r *CapabilityRolloutRepository) List(ctx context.Context, tenantID uuid.UUID) ([]rollout.Record, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	r.mu.RLock()
	out := make([]rollout.Record, 0)
	for k, rec := range r.rows {
		if k.tenant != tenantID {
			continue
		}
		out = append(out, rec)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		return out[i].Capability < out[j].Capability
	})
	return out, nil
}

// Upsert inserts or updates the (tenant, capability) row. created_at is
// preserved across updates; updated_at advances on every write,
// mirroring the Postgres set_updated_at trigger.
func (r *CapabilityRolloutRepository) Upsert(ctx context.Context, tenantID uuid.UUID, rec rollout.Record) (rollout.Record, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return rollout.Record{}, err
	}
	if tenantID == uuid.Nil || !rec.Capability.Valid() || !rec.State.Valid() {
		return rollout.Record{}, repository.ErrInvalidArgument
	}
	if rec.TenantID != uuid.Nil && rec.TenantID != tenantID {
		return rollout.Record{}, repository.ErrInvalidArgument
	}

	now := r.now()
	key := capabilityRolloutKey{tenant: tenantID, capability: rec.Capability}

	r.mu.Lock()
	defer r.mu.Unlock()
	stored := rollout.Record{
		TenantID:   tenantID,
		Capability: rec.Capability,
		State:      rec.State,
		Reason:     rec.Reason,
		UpdatedBy:  rec.UpdatedBy,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if existing, ok := r.rows[key]; ok {
		stored.CreatedAt = existing.CreatedAt
	}
	r.rows[key] = stored
	return stored, nil
}

package memory

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TenantMigrationRepository is the memory-backed implementation of
// repository.TenantMigrationRepository (migration 059). Tenant
// isolation is enforced by filtering on tenant_id, mirroring the
// Postgres RLS policy; the single-in-flight invariant mirrors the
// partial unique index uq_tenant_migrations_active.
type TenantMigrationRepository struct{ s *Store }

// NewTenantMigrationRepository binds the Store to the interface.
func NewTenantMigrationRepository(s *Store) *TenantMigrationRepository {
	return &TenantMigrationRepository{s: s}
}

var _ repository.TenantMigrationRepository = (*TenantMigrationRepository)(nil)

// cloneTenantMigration deep-copies the value so callers can never
// mutate stored state through a returned slice/pointer alias (the
// Postgres driver returns fresh values per row, and the memory store
// must match that to be a faithful test double).
func cloneTenantMigration(m repository.TenantMigration) repository.TenantMigration {
	out := m
	if len(m.Checkpoint) > 0 {
		out.Checkpoint = append(json.RawMessage(nil), m.Checkpoint...)
	} else {
		out.Checkpoint = nil
	}
	if m.StartedAt != nil {
		t := *m.StartedAt
		out.StartedAt = &t
	}
	if m.CompletedAt != nil {
		t := *m.CompletedAt
		out.CompletedAt = &t
	}
	return out
}

func (r *TenantMigrationRepository) Create(ctx context.Context, tenantID uuid.UUID, m repository.TenantMigration) (repository.TenantMigration, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantMigration{}, err
	}
	if tenantID == uuid.Nil || m.SourceRegion == "" || m.TargetRegion == "" || m.SourceRegion == m.TargetRegion {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	// Single in-flight migration per tenant (partial unique index).
	for _, existing := range r.s.tenantMigrations {
		if existing.TenantID == tenantID && !repository.IsTerminalMigrationState(existing.State) {
			return repository.TenantMigration{}, repository.ErrConflict
		}
	}
	m.TenantID = tenantID
	if m.ID == uuid.Nil {
		m.ID = uuid.New()
	}
	if m.State == "" {
		m.State = repository.MigrationStatePending
	}
	if len(m.Checkpoint) == 0 {
		m.Checkpoint = json.RawMessage(`{}`)
	}
	now := r.s.clock()
	m.CreatedAt = now
	m.UpdatedAt = now
	r.s.tenantMigrations[m.ID] = cloneTenantMigration(m)
	return cloneTenantMigration(m), nil
}

func (r *TenantMigrationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.TenantMigration, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantMigration{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	m, ok := r.s.tenantMigrations[id]
	if !ok || m.TenantID != tenantID {
		return repository.TenantMigration{}, repository.ErrNotFound
	}
	return cloneTenantMigration(m), nil
}

func (r *TenantMigrationRepository) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.TenantMigration, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantMigration{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, m := range r.s.tenantMigrations {
		if m.TenantID == tenantID && !repository.IsTerminalMigrationState(m.State) {
			return cloneTenantMigration(m), nil
		}
	}
	return repository.TenantMigration{}, repository.ErrNotFound
}

func (r *TenantMigrationRepository) Latest(ctx context.Context, tenantID uuid.UUID) (repository.TenantMigration, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantMigration{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []repository.TenantMigration
	for _, m := range r.s.tenantMigrations {
		if m.TenantID == tenantID {
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return repository.TenantMigration{}, repository.ErrNotFound
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return cloneTenantMigration(out[0]), nil
}

func (r *TenantMigrationRepository) Update(ctx context.Context, tenantID uuid.UUID, m repository.TenantMigration) (repository.TenantMigration, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantMigration{}, err
	}
	if tenantID == uuid.Nil || m.ID == uuid.Nil {
		return repository.TenantMigration{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	cur, ok := r.s.tenantMigrations[m.ID]
	if !ok || cur.TenantID != tenantID {
		return repository.TenantMigration{}, repository.ErrNotFound
	}
	// Re-activating a terminal row would violate the single-in-flight
	// invariant if another in-flight migration already exists. Mirror
	// the partial unique index rather than silently allowing two.
	if !repository.IsTerminalMigrationState(m.State) {
		for id, other := range r.s.tenantMigrations {
			if id != m.ID && other.TenantID == tenantID && !repository.IsTerminalMigrationState(other.State) {
				return repository.TenantMigration{}, repository.ErrConflict
			}
		}
	}
	// Persist only the mutable transition fields; identity + creation
	// metadata are immutable.
	cur.State = m.State
	cur.DualRead = m.DualRead
	cur.Detail = m.Detail
	cur.Attempts = m.Attempts
	cur.StartedAt = m.StartedAt
	cur.CompletedAt = m.CompletedAt
	if len(m.Checkpoint) == 0 {
		cur.Checkpoint = json.RawMessage(`{}`)
	} else {
		cur.Checkpoint = m.Checkpoint
	}
	cur.UpdatedAt = r.s.clock()
	r.s.tenantMigrations[cur.ID] = cloneTenantMigration(cur)
	return cloneTenantMigration(cur), nil
}

func (r *TenantMigrationRepository) ListResumable(ctx context.Context) ([]repository.TenantMigration, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var out []repository.TenantMigration
	for _, m := range r.s.tenantMigrations {
		if !repository.IsTerminalMigrationState(m.State) {
			out = append(out, cloneTenantMigration(m))
		}
	}
	// Oldest-updated first: the runner drains the longest-waiting
	// migration first.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].UpdatedAt.Before(out[j].UpdatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

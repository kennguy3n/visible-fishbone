package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policytemplates/ptmodel"
)

// PolicyTemplateRepository is the in-memory implementation of
// policytemplates.Repository. It is self-contained (its own lock,
// maps, and clock) rather than embedding the shared Store, so it can
// live entirely in this new file without touching the existing store
// definition.
//
// Tenant isolation is enforced exactly as the Postgres RLS policy
// does: the per-tenant applied state is keyed on tenant_id and every
// read/write filters on it, so one tenant can never observe another's
// baseline.
type PolicyTemplateRepository struct {
	mu      sync.RWMutex
	clock   func() time.Time
	catalog map[string]ptmodel.CatalogRow
	applied map[uuid.UUID]ptmodel.AppliedTemplate
}

// NewPolicyTemplateRepository returns an empty in-memory repository.
func NewPolicyTemplateRepository() *PolicyTemplateRepository {
	return &PolicyTemplateRepository{
		clock:   time.Now,
		catalog: make(map[string]ptmodel.CatalogRow),
		applied: make(map[uuid.UUID]ptmodel.AppliedTemplate),
	}
}

// SetClock overrides the wall-clock source for deterministic tests.
func (r *PolicyTemplateRepository) SetClock(fn func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clock = fn
}

// UpsertCatalog idempotently writes catalog rows. A row whose
// ContentHash is unchanged keeps its CreatedAt/UpdatedAt untouched.
func (r *PolicyTemplateRepository) UpsertCatalog(_ context.Context, rows []ptmodel.CatalogRow) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock()
	for _, row := range rows {
		if existing, ok := r.catalog[row.ID]; ok {
			if existing.ContentHash == row.ContentHash {
				continue // unchanged — preserve timestamps
			}
			row.CreatedAt = existing.CreatedAt
			row.UpdatedAt = now
		} else {
			row.CreatedAt = now
			row.UpdatedAt = now
		}
		row.Spec = cloneJSON(row.Spec)
		r.catalog[row.ID] = row
	}
	return nil
}

// ListCatalog returns every catalog row, sorted by id.
func (r *PolicyTemplateRepository) ListCatalog(_ context.Context) ([]ptmodel.CatalogRow, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]ptmodel.CatalogRow, 0, len(r.catalog))
	for _, row := range r.catalog {
		row.Spec = cloneJSON(row.Spec)
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// GetApplied returns a tenant's applied baseline, or ErrNotFound.
func (r *PolicyTemplateRepository) GetApplied(_ context.Context, tenantID uuid.UUID) (ptmodel.AppliedTemplate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	row, ok := r.applied[tenantID]
	if !ok {
		return ptmodel.AppliedTemplate{}, repository.ErrNotFound
	}
	return cloneApplied(row), nil
}

// UpsertApplied inserts or replaces a tenant's applied baseline.
func (r *PolicyTemplateRepository) UpsertApplied(_ context.Context, applied ptmodel.AppliedTemplate) (ptmodel.AppliedTemplate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.clock()
	if existing, ok := r.applied[applied.TenantID]; ok {
		applied.CreatedAt = existing.CreatedAt
	} else {
		applied.CreatedAt = now
	}
	applied.UpdatedAt = now

	stored := cloneApplied(applied)
	r.applied[applied.TenantID] = stored
	return cloneApplied(stored), nil
}

// cloneApplied deep-copies an AppliedTemplate so callers cannot mutate
// stored state through shared slices/buffers.
func cloneApplied(in ptmodel.AppliedTemplate) ptmodel.AppliedTemplate {
	out := in
	out.Graph = cloneJSON(in.Graph)
	if in.TemplateIDs != nil {
		out.TemplateIDs = append([]string(nil), in.TemplateIDs...)
	}
	return out
}

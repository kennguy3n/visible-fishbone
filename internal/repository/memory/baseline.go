// Package memory — baseline.go is the in-memory
// implementation of repository.BaselineModelRepository.
//
// The Welford / EWMA state is held by value in the BaselineModel
// struct; this driver just persists the struct and arbitrates
// optimistic locking via the Version field. The arithmetic
// itself lives in baseline.Engine — keeping it in the service
// layer means the memory and postgres drivers stay byte-for-byte
// equivalent on the read/write path.
package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// BaselineModelRepository binds the memory Store to
// repository.BaselineModelRepository.
type BaselineModelRepository struct{ s *Store }

// NewBaselineModelRepository wires a fresh repo over the shared
// Store.
func NewBaselineModelRepository(s *Store) *BaselineModelRepository {
	return &BaselineModelRepository{s: s}
}

// baselineKey is the composite (tenant, dimension,
// window_seconds) key that uniquely identifies a baseline model.
// The UNIQUE (tenant_id, dimension, window_seconds) constraint
// on the postgres table is enforced here by hashing into this
// key and rejecting duplicate inserts.
type baselineKey struct {
	TenantID      uuid.UUID
	Dimension     string
	WindowSeconds int
}

func (r *BaselineModelRepository) findByKey(k baselineKey) (repository.BaselineModel, bool) {
	for _, m := range r.s.baselineModels {
		if m.TenantID == k.TenantID &&
			m.Dimension == k.Dimension &&
			m.WindowSeconds == k.WindowSeconds {
			return m, true
		}
	}
	return repository.BaselineModel{}, false
}

// GetForDimension returns the model for the supplied
// (tenant, dimension, windowSeconds). Returns ErrNotFound when
// no such row exists.
func (r *BaselineModelRepository) GetForDimension(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	if dimension == "" {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	m, ok := r.findByKey(baselineKey{TenantID: tenantID, Dimension: dimension, WindowSeconds: windowSeconds})
	if !ok {
		return repository.BaselineModel{}, repository.ErrNotFound
	}
	return m, nil
}

// Upsert inserts the model when none exists for the (tenant,
// dim, window) tuple, otherwise UPDATEs the existing row under
// optimistic concurrency keyed off m.Version. INSERT always
// stamps Version=1; UPDATE rejects when m.Version does not
// match the persisted Version with ErrConflict so the caller
// can retry the load+fold+write cycle.
func (r *BaselineModelRepository) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	m repository.BaselineModel,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil || m.Dimension == "" || m.WindowSeconds <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	if m.Alpha <= 0 || m.Alpha > 1 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	if m.ZThreshold <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	now := r.s.clock()
	existing, ok := r.findByKey(baselineKey{TenantID: tenantID, Dimension: m.Dimension, WindowSeconds: m.WindowSeconds})
	if !ok {
		// INSERT path.
		if m.ID == uuid.Nil {
			m.ID = uuid.New()
		}
		m.TenantID = tenantID
		m.CreatedAt = now
		m.LastUpdatedAt = now
		m.Version = 1
		r.s.baselineModels[m.ID] = m
		return m, nil
	}
	// UPDATE path — enforce optimistic lock.
	if m.Version != existing.Version {
		return repository.BaselineModel{}, repository.ErrConflict
	}
	// Preserve immutable fields from the existing row; the
	// service layer only owns the Welford / EWMA / threshold
	// fields plus LastObservedAt.
	merged := existing
	merged.Samples = m.Samples
	merged.Mean = m.Mean
	merged.M2 = m.M2
	merged.EWMA = m.EWMA
	merged.EWMAVar = m.EWMAVar
	merged.Alpha = m.Alpha
	merged.ZThreshold = m.ZThreshold
	if !m.LastObservedAt.IsZero() {
		merged.LastObservedAt = m.LastObservedAt
	}
	merged.LastUpdatedAt = now
	merged.Version = existing.Version + 1
	r.s.baselineModels[merged.ID] = merged
	return merged, nil
}

// List enumerates models for a tenant in LastUpdatedAt DESC
// order. Pagination follows the same cursor scheme as the rest
// of the memory store.
func (r *BaselineModelRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.BaselineModel], error) {
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.BaselineModel]{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.BaselineModel, 0, len(r.s.baselineModels))
	for _, m := range r.s.baselineModels {
		if m.TenantID != tenantID {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastUpdatedAt.Equal(out[j].LastUpdatedAt) {
			return out[i].LastUpdatedAt.After(out[j].LastUpdatedAt)
		}
		return out[i].ID.String() > out[j].ID.String()
	})
	limit := page.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	if limit > len(out) {
		limit = len(out)
	}
	return repository.PageResult[repository.BaselineModel]{Items: out[:limit]}, nil
}

// UpdateThreshold updates the ZThreshold on a model in-place
// without touching the Welford / EWMA state. Returns
// ErrNotFound when no model exists for the tuple.
func (r *BaselineModelRepository) UpdateThreshold(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
	zThreshold float64,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil || dimension == "" {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	if zThreshold <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.findByKey(baselineKey{TenantID: tenantID, Dimension: dimension, WindowSeconds: windowSeconds})
	if !ok {
		return repository.BaselineModel{}, repository.ErrNotFound
	}
	existing.ZThreshold = zThreshold
	existing.LastUpdatedAt = r.s.clock()
	existing.Version++
	r.s.baselineModels[existing.ID] = existing
	return existing, nil
}

// Compile-time interface satisfaction asserted in repos.go.
var _ repository.BaselineModelRepository = (*BaselineModelRepository)(nil)

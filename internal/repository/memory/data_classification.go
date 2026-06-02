package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DataClassificationRepository is the in-memory implementation of
// repository.DataClassificationRepository.
type DataClassificationRepository struct{ s *Store }

// NewDataClassificationRepository returns a DataClassificationRepository
// backed by the given Store.
func NewDataClassificationRepository(s *Store) *DataClassificationRepository {
	return &DataClassificationRepository{s: s}
}

func (r *DataClassificationRepository) Create(_ context.Context, tenantID uuid.UUID, dc repository.DataClassification) (repository.DataClassification, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	// Enforce unique (tenant_id, level).
	for _, existing := range r.s.dataClassifications {
		if existing.TenantID == tenantID && existing.Level == dc.Level {
			return repository.DataClassification{}, repository.ErrConflict
		}
	}

	now := r.s.clock()
	dc.ID = uuid.New()
	dc.TenantID = tenantID
	dc.CreatedAt = now
	dc.UpdatedAt = now
	if dc.HandlingRules == nil {
		dc.HandlingRules = []byte(`{}`)
	}

	r.s.dataClassifications[dc.ID] = dc
	return cloneDataClassification(dc), nil
}

func (r *DataClassificationRepository) Get(_ context.Context, tenantID, id uuid.UUID) (repository.DataClassification, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	dc, ok := r.s.dataClassifications[id]
	if !ok || dc.TenantID != tenantID {
		return repository.DataClassification{}, repository.ErrNotFound
	}
	return cloneDataClassification(dc), nil
}

func (r *DataClassificationRepository) GetByLevel(_ context.Context, tenantID uuid.UUID, level repository.ClassificationLevel) (repository.DataClassification, error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	for _, dc := range r.s.dataClassifications {
		if dc.TenantID == tenantID && dc.Level == level {
			return cloneDataClassification(dc), nil
		}
	}
	return repository.DataClassification{}, repository.ErrNotFound
}

func (r *DataClassificationRepository) List(_ context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DataClassification], error) {
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var items []repository.DataClassification
	for _, dc := range r.s.dataClassifications {
		if dc.TenantID == tenantID {
			items = append(items, cloneDataClassification(dc))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].CreatedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].CreatedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(dc repository.DataClassification) cursor {
		return cursor{CreatedAt: dc.CreatedAt, ID: dc.ID}
	}), nil
}

func (r *DataClassificationRepository) Update(_ context.Context, tenantID, id uuid.UUID, patch repository.DataClassificationPatch) (repository.DataClassification, error) {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	dc, ok := r.s.dataClassifications[id]
	if !ok || dc.TenantID != tenantID {
		return repository.DataClassification{}, repository.ErrNotFound
	}
	if patch.Label != nil {
		dc.Label = *patch.Label
	}
	if patch.Level != nil {
		// Enforce unique (tenant_id, level) on update.
		for _, existing := range r.s.dataClassifications {
			if existing.TenantID == tenantID && existing.Level == *patch.Level && existing.ID != id {
				return repository.DataClassification{}, repository.ErrConflict
			}
		}
		dc.Level = *patch.Level
	}
	if patch.Description != nil {
		dc.Description = *patch.Description
	}
	if patch.HandlingRules != nil {
		dc.HandlingRules = cloneJSON(*patch.HandlingRules)
	}
	dc.UpdatedAt = r.s.clock()
	r.s.dataClassifications[id] = dc
	return cloneDataClassification(dc), nil
}

func (r *DataClassificationRepository) Delete(_ context.Context, tenantID, id uuid.UUID) error {
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	dc, ok := r.s.dataClassifications[id]
	if !ok || dc.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.dataClassifications, id)
	return nil
}

func cloneDataClassification(dc repository.DataClassification) repository.DataClassification {
	dc.HandlingRules = cloneJSON(dc.HandlingRules)
	return dc
}

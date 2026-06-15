package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DLPIDMRepository is the in-memory implementation of
// repository.DLPIDMRepository (WP4 OCR/IDM control-plane state).
//
// Unlike the older memory repositories, this one keeps its state on
// its own struct (guarded by its own mutex) rather than on the shared
// Store, because the Store definition is owned by another work package
// and must not be co-edited. It still borrows the Store's injected
// clock so deterministic-timestamp tests behave identically.
type DLPIDMRepository struct {
	s *Store

	mu      sync.RWMutex
	sets    map[uuid.UUID]repository.IDMFingerprintSet
	configs map[uuid.UUID]repository.DLPOCRIDMConfig
}

// NewDLPIDMRepository returns a DLPIDMRepository backed by the given
// Store (used only for its clock).
func NewDLPIDMRepository(s *Store) *DLPIDMRepository {
	return &DLPIDMRepository{
		s:       s,
		sets:    map[uuid.UUID]repository.IDMFingerprintSet{},
		configs: map[uuid.UUID]repository.DLPOCRIDMConfig{},
	}
}

var _ repository.DLPIDMRepository = (*DLPIDMRepository)(nil)

func cloneIDMFingerprintSet(set repository.IDMFingerprintSet) repository.IDMFingerprintSet {
	if set.Fingerprints != nil {
		fps := make([]uint64, len(set.Fingerprints))
		copy(fps, set.Fingerprints)
		set.Fingerprints = fps
	}
	return set
}

func (r *DLPIDMRepository) CreateFingerprintSet(_ context.Context, tenantID uuid.UUID, set repository.IDMFingerprintSet) (repository.IDMFingerprintSet, error) {
	if tenantID == uuid.Nil {
		return repository.IDMFingerprintSet{}, repository.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.sets {
		if existing.TenantID == tenantID && existing.Name == set.Name {
			return repository.IDMFingerprintSet{}, repository.ErrConflict
		}
	}

	now := r.s.clock()
	set.ID = uuid.New()
	set.TenantID = tenantID
	set.CreatedAt = now
	set.UpdatedAt = now
	set = cloneIDMFingerprintSet(set)
	r.sets[set.ID] = set
	return cloneIDMFingerprintSet(set), nil
}

func (r *DLPIDMRepository) GetFingerprintSet(_ context.Context, tenantID, id uuid.UUID) (repository.IDMFingerprintSet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	set, ok := r.sets[id]
	if !ok || set.TenantID != tenantID {
		return repository.IDMFingerprintSet{}, repository.ErrNotFound
	}
	return cloneIDMFingerprintSet(set), nil
}

func (r *DLPIDMRepository) ListFingerprintSets(_ context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.IDMFingerprintSet], error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var items []repository.IDMFingerprintSet
	for _, set := range r.sets {
		if set.TenantID == tenantID {
			items = append(items, cloneIDMFingerprintSet(set))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].CreatedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].CreatedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(set repository.IDMFingerprintSet) cursor {
		return cursor{CreatedAt: set.CreatedAt, ID: set.ID}
	}), nil
}

func (r *DLPIDMRepository) UpdateFingerprintSet(_ context.Context, tenantID, id uuid.UUID, patch repository.IDMFingerprintSetPatch) (repository.IDMFingerprintSet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	set, ok := r.sets[id]
	if !ok || set.TenantID != tenantID {
		return repository.IDMFingerprintSet{}, repository.ErrNotFound
	}
	if patch.Name != nil {
		for _, existing := range r.sets {
			if existing.TenantID == tenantID && existing.Name == *patch.Name && existing.ID != id {
				return repository.IDMFingerprintSet{}, repository.ErrConflict
			}
		}
		set.Name = *patch.Name
	}
	if patch.Description != nil {
		set.Description = *patch.Description
	}
	set.UpdatedAt = r.s.clock()
	r.sets[id] = cloneIDMFingerprintSet(set)
	return cloneIDMFingerprintSet(set), nil
}

func (r *DLPIDMRepository) DeleteFingerprintSet(_ context.Context, tenantID, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	set, ok := r.sets[id]
	if !ok || set.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.sets, id)
	return nil
}

func (r *DLPIDMRepository) FingerprintSetStats(_ context.Context, tenantID uuid.UUID) (repository.IDMFingerprintSetStats, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var stats repository.IDMFingerprintSetStats
	for _, set := range r.sets {
		if set.TenantID != tenantID {
			continue
		}
		stats.SetCount++
		stats.TotalFingerprints += int64(len(set.Fingerprints))
		stats.TotalSourceBytes += set.SourceBytes
	}
	return stats, nil
}

func (r *DLPIDMRepository) GetConfig(_ context.Context, tenantID uuid.UUID) (repository.DLPOCRIDMConfig, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	cfg, ok := r.configs[tenantID]
	if !ok {
		return repository.DLPOCRIDMConfig{}, repository.ErrNotFound
	}
	return cfg, nil
}

func (r *DLPIDMRepository) UpsertConfig(_ context.Context, tenantID uuid.UUID, cfg repository.DLPOCRIDMConfig) (repository.DLPOCRIDMConfig, error) {
	if tenantID == uuid.Nil {
		return repository.DLPOCRIDMConfig{}, repository.ErrInvalidArgument
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.s.clock()
	cfg.TenantID = tenantID
	cfg.UpdatedAt = now
	if existing, ok := r.configs[tenantID]; ok {
		cfg.CreatedAt = existing.CreatedAt
	} else {
		cfg.CreatedAt = now
	}
	r.configs[tenantID] = cfg
	return cfg, nil
}

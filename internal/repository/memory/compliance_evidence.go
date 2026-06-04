package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ComplianceEvidenceRepository is the memory-backed
// ComplianceEvidenceRepository. Platform-level (not tenant-scoped):
// rows have no tenant binding and List/Get see every row.
type ComplianceEvidenceRepository struct{ s *Store }

// NewComplianceEvidenceRepository wires a fresh repo over the shared Store.
func NewComplianceEvidenceRepository(s *Store) *ComplianceEvidenceRepository {
	return &ComplianceEvidenceRepository{s: s}
}

var _ repository.ComplianceEvidenceRepository = (*ComplianceEvidenceRepository)(nil)

func (r *ComplianceEvidenceRepository) Create(ctx context.Context, e repository.ComplianceEvidence) (repository.ComplianceEvidence, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ComplianceEvidence{}, err
	}
	if e.CollectionType == "" || e.S3Key == "" || e.Signature == "" || e.Status == "" {
		return repository.ComplianceEvidence{}, repository.ErrInvalidArgument
	}

	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	// Enforce the s3_key UNIQUE constraint the Postgres schema declares.
	for _, existing := range r.s.complianceEvidence {
		if existing.S3Key == e.S3Key {
			return repository.ComplianceEvidence{}, repository.ErrConflict
		}
	}

	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	now := r.s.clock()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	if e.CollectedAt.IsZero() {
		e.CollectedAt = now
	}
	r.s.complianceEvidence[e.ID] = e
	return e, nil
}

func (r *ComplianceEvidenceRepository) Get(ctx context.Context, id uuid.UUID) (repository.ComplianceEvidence, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ComplianceEvidence{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	e, ok := r.s.complianceEvidence[id]
	if !ok {
		return repository.ComplianceEvidence{}, repository.ErrNotFound
	}
	return e, nil
}

func (r *ComplianceEvidenceRepository) List(ctx context.Context, filter repository.ComplianceEvidenceFilter, page repository.Page) (repository.PageResult[repository.ComplianceEvidence], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.ComplianceEvidence]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var all []repository.ComplianceEvidence
	for _, e := range r.s.complianceEvidence {
		if filter.CollectionType != "" && e.CollectionType != filter.CollectionType {
			continue
		}
		if filter.Status != "" && e.Status != filter.Status {
			continue
		}
		all = append(all, e)
	}

	sorted := sortByCreatedAtDesc(all,
		func(e repository.ComplianceEvidence) time.Time { return e.CollectedAt },
		func(e repository.ComplianceEvidence) uuid.UUID { return e.ID },
		page.Normalize().Order,
	)

	return paginate(sorted, page, func(e repository.ComplianceEvidence) cursor {
		return cursor{CreatedAt: e.CollectedAt, ID: e.ID}
	}), nil
}

func (r *ComplianceEvidenceRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status string) (repository.ComplianceEvidence, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ComplianceEvidence{}, err
	}
	if status == "" {
		return repository.ComplianceEvidence{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.complianceEvidence[id]
	if !ok {
		return repository.ComplianceEvidence{}, repository.ErrNotFound
	}
	e.Status = status
	r.s.complianceEvidence[id] = e
	return e, nil
}

func (r *ComplianceEvidenceRepository) LatestByType(ctx context.Context, collectionType string) (repository.ComplianceEvidence, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ComplianceEvidence{}, err
	}
	if collectionType == "" {
		return repository.ComplianceEvidence{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var (
		best  repository.ComplianceEvidence
		found bool
	)
	for _, e := range r.s.complianceEvidence {
		if e.CollectionType != collectionType {
			continue
		}
		if !found || e.CollectedAt.After(best.CollectedAt) {
			best = e
			found = true
		}
	}
	if !found {
		return repository.ComplianceEvidence{}, repository.ErrNotFound
	}
	return best, nil
}

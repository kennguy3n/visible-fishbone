package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AICorrelationRepository is the memory-backed AICorrelationRepository.
type AICorrelationRepository struct{ s *Store }

// NewAICorrelationRepository wires a fresh repo over the shared Store.
func NewAICorrelationRepository(s *Store) *AICorrelationRepository {
	return &AICorrelationRepository{s: s}
}

var _ repository.AICorrelationRepository = (*AICorrelationRepository)(nil)

func cloneAICorrelation(c repository.AICorrelation) repository.AICorrelation {
	out := c
	if c.AlertIDs != nil {
		out.AlertIDs = make([]uuid.UUID, len(c.AlertIDs))
		copy(out.AlertIDs, c.AlertIDs)
	}
	return out
}

// Create persists a new AI correlation cluster.
func (r *AICorrelationRepository) Create(ctx context.Context, tenantID uuid.UUID, c repository.AICorrelation) (repository.AICorrelation, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AICorrelation{}, err
	}
	if tenantID == uuid.Nil {
		return repository.AICorrelation{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if c.ID == uuid.Nil {
		c.ID = uuid.New()
	}
	c.TenantID = tenantID
	now := r.s.clock()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	c.UpdatedAt = now
	if c.Status == "" {
		c.Status = "open"
	}
	if err := repository.ValidateAICorrelationStatus(c.Status); err != nil {
		return repository.AICorrelation{}, err
	}
	r.s.aiCorrelations[c.ID] = c
	return cloneAICorrelation(c), nil
}

// Get returns one correlation by ID, scoped to tenant.
func (r *AICorrelationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.AICorrelation, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AICorrelation{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	c, ok := r.s.aiCorrelations[id]
	if !ok || c.TenantID != tenantID {
		return repository.AICorrelation{}, repository.ErrNotFound
	}
	return cloneAICorrelation(c), nil
}

// List enumerates correlations in CreatedAt-DESC order.
func (r *AICorrelationRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.AICorrelation], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.AICorrelation]{}, err
	}
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.AICorrelation]{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.AICorrelation, 0, len(r.s.aiCorrelations))
	for _, c := range r.s.aiCorrelations {
		if c.TenantID != tenantID {
			continue
		}
		all = append(all, cloneAICorrelation(c))
	}
	sorted := sortByCreatedAtDesc(all,
		func(c repository.AICorrelation) time.Time { return c.CreatedAt },
		func(c repository.AICorrelation) uuid.UUID { return c.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(c repository.AICorrelation) cursor {
		return cursor{CreatedAt: c.CreatedAt, ID: c.ID}
	}), nil
}

// UpdateStatus changes the status of a correlation.
func (r *AICorrelationRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if err := repository.ValidateAICorrelationStatus(status); err != nil {
		return err
	}
	c, ok := r.s.aiCorrelations[id]
	if !ok || c.TenantID != tenantID {
		return repository.ErrNotFound
	}
	c.Status = status
	c.UpdatedAt = r.s.clock()
	r.s.aiCorrelations[id] = c
	return nil
}

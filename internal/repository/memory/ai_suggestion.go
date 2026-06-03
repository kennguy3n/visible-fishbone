package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AISuggestionRepository is the memory-backed AISuggestionRepository.
type AISuggestionRepository struct{ s *Store }

// NewAISuggestionRepository wires a fresh repo over the shared Store.
func NewAISuggestionRepository(s *Store) *AISuggestionRepository {
	return &AISuggestionRepository{s: s}
}

var _ repository.AISuggestionRepository = (*AISuggestionRepository)(nil)

func cloneAISuggestion(s repository.AISuggestion) repository.AISuggestion {
	out := s
	out.SuggestionJSON = cloneJSON(s.SuggestionJSON)
	if s.ReviewerID != nil {
		v := *s.ReviewerID
		out.ReviewerID = &v
	}
	if s.ReviewedAt != nil {
		v := *s.ReviewedAt
		out.ReviewedAt = &v
	}
	if s.Feedback != nil {
		v := *s.Feedback
		out.Feedback = &v
	}
	return out
}

func (r *AISuggestionRepository) Create(ctx context.Context, tenantID uuid.UUID, s repository.AISuggestion) (repository.AISuggestion, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AISuggestion{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	if s.Status == "" {
		s.Status = repository.AISuggestionStatusPending
	}
	now := r.s.clock()
	s.CreatedAt = now

	if r.s.aiSuggestions == nil {
		r.s.aiSuggestions = map[uuid.UUID]repository.AISuggestion{}
	}
	r.s.aiSuggestions[s.ID] = s
	return cloneAISuggestion(s), nil
}

func (r *AISuggestionRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.AISuggestion, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AISuggestion{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	s, ok := r.s.aiSuggestions[id]
	if !ok || s.TenantID != tenantID {
		return repository.AISuggestion{}, repository.ErrNotFound
	}
	return cloneAISuggestion(s), nil
}

func (r *AISuggestionRepository) List(ctx context.Context, tenantID uuid.UUID, status *string, page repository.Page) (repository.PageResult[repository.AISuggestion], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.AISuggestion]{}, err
	}
	page = page.Normalize()
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var items []repository.AISuggestion
	for _, s := range r.s.aiSuggestions {
		if s.TenantID != tenantID {
			continue
		}
		if status != nil && string(s.Status) != *status {
			continue
		}
		items = append(items, cloneAISuggestion(s))
	}

	order := page.Order
	if order == "" {
		order = repository.SortDesc
	}
	items = sortByCreatedAtDesc(items,
		func(s repository.AISuggestion) time.Time { return s.CreatedAt },
		func(s repository.AISuggestion) uuid.UUID { return s.ID },
		order,
	)

	return paginate(items, page, func(s repository.AISuggestion) cursor {
		return cursor{CreatedAt: s.CreatedAt, ID: s.ID}
	}), nil
}

func (r *AISuggestionRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, expectedStatus, newStatus string, reviewerID *uuid.UUID, feedback *string) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	s, ok := r.s.aiSuggestions[id]
	if !ok || s.TenantID != tenantID {
		return repository.ErrNotFound
	}
	if string(s.Status) != expectedStatus {
		return repository.ErrConflict
	}
	s.Status = repository.AISuggestionStatus(newStatus)
	now := r.s.clock()
	s.ReviewedAt = &now
	if reviewerID != nil {
		v := *reviewerID
		s.ReviewerID = &v
	}
	if feedback != nil {
		v := *feedback
		s.Feedback = &v
	}
	r.s.aiSuggestions[id] = s
	return nil
}

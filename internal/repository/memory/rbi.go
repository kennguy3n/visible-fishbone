package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// RBISessionRepository is the in-memory implementation of
// repository.RBISessionRepository (rbi_sessions, migration 043).
type RBISessionRepository struct{ s *Store }

func NewRBISessionRepository(s *Store) *RBISessionRepository {
	return &RBISessionRepository{s: s}
}

var _ repository.RBISessionRepository = (*RBISessionRepository)(nil)

func cloneRBISession(s repository.RBISession) repository.RBISession {
	return s
}

func (r *RBISessionRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.RBISession,
) (repository.RBISession, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.RBISession{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.RBISession{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.RBISession{}, repository.ErrNotFound
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if _, exists := r.s.rbiSessions[s.ID]; exists {
		return repository.RBISession{}, repository.ErrConflict
	}
	s.TenantID = tenantID
	now := r.s.clock()
	s.CreatedAt = now
	s.UpdatedAt = now
	r.s.rbiSessions[s.ID] = s
	return cloneRBISession(s), nil
}

func (r *RBISessionRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.RBISession, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.RBISession{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.s.rbiSessions[id]
	if !ok || s.TenantID != tenantID {
		return repository.RBISession{}, repository.ErrNotFound
	}
	return cloneRBISession(s), nil
}

func (r *RBISessionRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	limit int,
) ([]repository.RBISession, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.RBISession, 0)
	for _, s := range r.s.rbiSessions {
		if s.TenantID != tenantID {
			continue
		}
		out = append(out, cloneRBISession(s))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *RBISessionRepository) Close(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.rbiSessions[id]
	if !ok || s.TenantID != tenantID || s.Status != "active" {
		return repository.ErrNotFound
	}
	s.Status = "closed"
	s.UpdatedAt = r.s.clock()
	r.s.rbiSessions[id] = s
	return nil
}

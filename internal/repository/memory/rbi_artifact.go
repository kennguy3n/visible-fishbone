package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// RBIArtifactRepository is the in-memory implementation of
// repository.RBIArtifactRepository (rbi_session_artifacts, migration
// 048).
type RBIArtifactRepository struct{ s *Store }

func NewRBIArtifactRepository(s *Store) *RBIArtifactRepository {
	return &RBIArtifactRepository{s: s}
}

var _ repository.RBIArtifactRepository = (*RBIArtifactRepository)(nil)

func (r *RBIArtifactRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	a repository.RBIArtifact,
) (repository.RBIArtifact, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.RBIArtifact{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.RBIArtifact{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.RBIArtifact{}, repository.ErrNotFound
	}
	// The artifact must reference a session owned by this tenant.
	sess, ok := r.s.rbiSessions[a.SessionID]
	if !ok || sess.TenantID != tenantID {
		return repository.RBIArtifact{}, repository.ErrNotFound
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if _, exists := r.s.rbiArtifacts[a.ID]; exists {
		return repository.RBIArtifact{}, repository.ErrConflict
	}
	a.TenantID = tenantID
	a.CreatedAt = r.s.clock()
	r.s.rbiArtifacts[a.ID] = a
	return a, nil
}

func (r *RBIArtifactRepository) ListBySession(
	ctx context.Context,
	tenantID, sessionID uuid.UUID,
	limit int,
) ([]repository.RBIArtifact, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.RBIArtifact, 0)
	for _, a := range r.s.rbiArtifacts {
		if a.TenantID != tenantID || a.SessionID != sessionID {
			continue
		}
		out = append(out, a)
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

package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyRecommendationRepository is the memory-backed
// repository.PolicyRecommendationRepository.
type PolicyRecommendationRepository struct{ s *Store }

// NewPolicyRecommendationRepository wires a fresh repo over the shared
// Store.
func NewPolicyRecommendationRepository(s *Store) *PolicyRecommendationRepository {
	return &PolicyRecommendationRepository{s: s}
}

var _ repository.PolicyRecommendationRepository = (*PolicyRecommendationRepository)(nil)

func clonePolicyRecommendation(r repository.PolicyRecommendation) repository.PolicyRecommendation {
	out := r
	out.CandidateGraph = cloneJSON(r.CandidateGraph)
	out.Summary = cloneJSON(r.Summary)
	if r.AppliedGraphID != nil {
		v := *r.AppliedGraphID
		out.AppliedGraphID = &v
	}
	if r.AppliedAt != nil {
		v := *r.AppliedAt
		out.AppliedAt = &v
	}
	if r.ActorID != nil {
		v := *r.ActorID
		out.ActorID = &v
	}
	return out
}

func (r *PolicyRecommendationRepository) Create(ctx context.Context, tenantID uuid.UUID, rec repository.PolicyRecommendation) (repository.PolicyRecommendation, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyRecommendation{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}
	rec.TenantID = tenantID
	if rec.Status == "" {
		rec.Status = repository.PolicyRecommendationStatusPending
	}
	rec.CreatedAt = r.s.clock()

	if r.s.policyRecommendations == nil {
		r.s.policyRecommendations = map[uuid.UUID]repository.PolicyRecommendation{}
	}
	r.s.policyRecommendations[rec.ID] = rec
	return clonePolicyRecommendation(rec), nil
}

func (r *PolicyRecommendationRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyRecommendation, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyRecommendation{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	rec, ok := r.s.policyRecommendations[id]
	if !ok || rec.TenantID != tenantID {
		return repository.PolicyRecommendation{}, repository.ErrNotFound
	}
	return clonePolicyRecommendation(rec), nil
}

func (r *PolicyRecommendationRepository) List(ctx context.Context, tenantID uuid.UUID, status *string, page repository.Page) (repository.PageResult[repository.PolicyRecommendation], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.PolicyRecommendation]{}, err
	}
	page = page.Normalize()
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()

	var items []repository.PolicyRecommendation
	for _, rec := range r.s.policyRecommendations {
		if rec.TenantID != tenantID {
			continue
		}
		if status != nil && string(rec.Status) != *status {
			continue
		}
		items = append(items, clonePolicyRecommendation(rec))
	}

	items = sortByCreatedAtDesc(items,
		func(rec repository.PolicyRecommendation) time.Time { return rec.CreatedAt },
		func(rec repository.PolicyRecommendation) uuid.UUID { return rec.ID },
		page.Order,
	)

	return paginate(items, page, func(rec repository.PolicyRecommendation) cursor {
		return cursor{CreatedAt: rec.CreatedAt, ID: rec.ID}
	}), nil
}

func (r *PolicyRecommendationRepository) MarkApplied(ctx context.Context, tenantID, id, appliedGraphID uuid.UUID, actorID *uuid.UUID) error {
	return r.transition(ctx, tenantID, id, repository.PolicyRecommendationStatusApplied, &appliedGraphID, actorID)
}

func (r *PolicyRecommendationRepository) MarkDismissed(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	return r.transition(ctx, tenantID, id, repository.PolicyRecommendationStatusDismissed, nil, actorID)
}

func (r *PolicyRecommendationRepository) transition(ctx context.Context, tenantID, id uuid.UUID, newStatus repository.PolicyRecommendationStatus, appliedGraphID *uuid.UUID, actorID *uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	rec, ok := r.s.policyRecommendations[id]
	if !ok || rec.TenantID != tenantID {
		return repository.ErrNotFound
	}
	if rec.Status != repository.PolicyRecommendationStatusPending {
		return repository.ErrConflict
	}
	rec.Status = newStatus
	// applied_at marks application only; a dismissal leaves it nil.
	if newStatus == repository.PolicyRecommendationStatusApplied {
		now := r.s.clock()
		rec.AppliedAt = &now
	}
	if appliedGraphID != nil {
		v := *appliedGraphID
		rec.AppliedGraphID = &v
	}
	if actorID != nil {
		v := *actorID
		rec.ActorID = &v
	}
	r.s.policyRecommendations[id] = rec
	return nil
}

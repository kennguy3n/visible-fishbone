package memory

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyReviewScheduleRepository is the memory-backed implementation.
type PolicyReviewScheduleRepository struct{ s *Store }

func NewPolicyReviewScheduleRepository(s *Store) *PolicyReviewScheduleRepository {
	return &PolicyReviewScheduleRepository{s: s}
}

var _ repository.PolicyReviewScheduleRepository = (*PolicyReviewScheduleRepository)(nil)

func (r *PolicyReviewScheduleRepository) Create(ctx context.Context, tenantID uuid.UUID, s repository.PolicyReviewSchedule) (repository.PolicyReviewSchedule, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyReviewSchedule{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil || s.PolicyID == uuid.Nil {
		return repository.PolicyReviewSchedule{}, repository.ErrInvalidArgument
	}
	// Check uniqueness on (tenant_id, policy_id).
	for _, existing := range r.s.policyReviewSchedules {
		if existing.TenantID == tenantID && existing.PolicyID == s.PolicyID {
			return repository.PolicyReviewSchedule{}, repository.ErrConflict
		}
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	if s.ReviewIntervalDays <= 0 {
		s.ReviewIntervalDays = 90
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = r.s.clock()
	}
	r.s.policyReviewSchedules[s.ID] = s
	return s, nil
}

func (r *PolicyReviewScheduleRepository) Get(ctx context.Context, tenantID, policyID uuid.UUID) (repository.PolicyReviewSchedule, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyReviewSchedule{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, s := range r.s.policyReviewSchedules {
		if s.TenantID == tenantID && s.PolicyID == policyID {
			return s, nil
		}
	}
	return repository.PolicyReviewSchedule{}, repository.ErrNotFound
}

func (r *PolicyReviewScheduleRepository) ListDue(ctx context.Context, before time.Time, limit int) ([]repository.PolicyReviewSchedule, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var result []repository.PolicyReviewSchedule
	for _, s := range r.s.policyReviewSchedules {
		if s.NextReviewAt != nil && !s.NextReviewAt.After(before) {
			result = append(result, s)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].NextReviewAt == nil {
			return false
		}
		if result[j].NextReviewAt == nil {
			return true
		}
		return result[i].NextReviewAt.Before(*result[j].NextReviewAt)
	})
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (r *PolicyReviewScheduleRepository) UpdateLastReviewed(ctx context.Context, tenantID, policyID uuid.UUID, at time.Time) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, s := range r.s.policyReviewSchedules {
		if s.TenantID == tenantID && s.PolicyID == policyID {
			at = at.UTC()
			s.LastReviewedAt = &at
			next := at.AddDate(0, 0, s.ReviewIntervalDays)
			s.NextReviewAt = &next
			r.s.policyReviewSchedules[id] = s
			return nil
		}
	}
	return repository.ErrNotFound
}

// OpsHealthSnapshotRepository is the memory-backed implementation.
type OpsHealthSnapshotRepository struct{ s *Store }

func NewOpsHealthSnapshotRepository(s *Store) *OpsHealthSnapshotRepository {
	return &OpsHealthSnapshotRepository{s: s}
}

var _ repository.OpsHealthSnapshotRepository = (*OpsHealthSnapshotRepository)(nil)

func (r *OpsHealthSnapshotRepository) Create(ctx context.Context, tenantID uuid.UUID, s repository.OpsHealthSnapshot) (repository.OpsHealthSnapshot, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.OpsHealthSnapshot{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.OpsHealthSnapshot{}, repository.ErrInvalidArgument
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	if s.CreatedAt.IsZero() {
		s.CreatedAt = r.s.clock()
	}
	s.ComponentScores = cloneJSON(s.ComponentScores)
	r.s.opsHealthSnapshots[s.ID] = s
	return s, nil
}

func (r *OpsHealthSnapshotRepository) GetLatest(ctx context.Context, tenantID uuid.UUID) (repository.OpsHealthSnapshot, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.OpsHealthSnapshot{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var latest repository.OpsHealthSnapshot
	found := false
	for _, s := range r.s.opsHealthSnapshots {
		if s.TenantID != tenantID {
			continue
		}
		if !found || s.CreatedAt.After(latest.CreatedAt) {
			latest = s
			found = true
		}
	}
	if !found {
		return repository.OpsHealthSnapshot{}, repository.ErrNotFound
	}
	latest.ComponentScores = cloneJSON(latest.ComponentScores)
	return latest, nil
}

func (r *OpsHealthSnapshotRepository) ListHistory(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]repository.OpsHealthSnapshot, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var result []repository.OpsHealthSnapshot
	for _, s := range r.s.opsHealthSnapshots {
		if s.TenantID == tenantID && !s.CreatedAt.Before(since) {
			cp := s
			cp.ComponentScores = cloneJSON(s.ComponentScores)
			result = append(result, cp)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})
	if len(result) > repository.MaxOpsHealthHistory {
		result = result[:repository.MaxOpsHealthHistory]
	}
	return result, nil
}

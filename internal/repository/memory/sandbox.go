package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SandboxVerdictRepository is the in-memory implementation of
// repository.SandboxVerdictRepository (sandbox_verdicts,
// migration 042). It mirrors the Postgres store's tenant scoping,
// (tenant, sha256) upsert semantics, and most-recent-first ordering
// so service/handler tests behave identically against either
// backend.
type SandboxVerdictRepository struct{ s *Store }

func NewSandboxVerdictRepository(s *Store) *SandboxVerdictRepository {
	return &SandboxVerdictRepository{s: s}
}

var _ repository.SandboxVerdictRepository = (*SandboxVerdictRepository)(nil)

func cloneSandboxVerdict(v repository.SandboxVerdict) repository.SandboxVerdict {
	// AnalyzedAt is a pointer; copy the pointee so a caller mutating
	// the returned value cannot reach back into the stored row.
	if v.AnalyzedAt != nil {
		t := *v.AnalyzedAt
		v.AnalyzedAt = &t
	}
	return v
}

// findBySHA256 returns the existing row for (tenant, sha256) if one
// exists. Caller must hold at least the read lock.
func (r *SandboxVerdictRepository) findBySHA256(tenantID uuid.UUID, sha256 string) (repository.SandboxVerdict, bool) {
	for _, v := range r.s.sandboxVerdicts {
		if v.TenantID == tenantID && v.SHA256 == sha256 {
			return v, true
		}
	}
	return repository.SandboxVerdict{}, false
}

func (r *SandboxVerdictRepository) Upsert(
	ctx context.Context,
	tenantID uuid.UUID,
	v repository.SandboxVerdict,
) (repository.SandboxVerdict, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.SandboxVerdict{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.SandboxVerdict{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.SandboxVerdict{}, repository.ErrNotFound
	}
	now := r.s.clock()
	if existing, ok := r.findBySHA256(tenantID, v.SHA256); ok {
		// Update in place: preserve id + created_at, bump updated_at.
		existing.Classification = v.Classification
		existing.Confidence = v.Confidence
		existing.Provider = v.Provider
		existing.SandboxID = v.SandboxID
		existing.Summary = v.Summary
		existing.Status = v.Status
		existing.AnalyzedAt = v.AnalyzedAt
		existing.UpdatedAt = now
		r.s.sandboxVerdicts[existing.ID] = existing
		return cloneSandboxVerdict(existing), nil
	}
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	v.TenantID = tenantID
	v.CreatedAt = now
	v.UpdatedAt = now
	r.s.sandboxVerdicts[v.ID] = cloneSandboxVerdict(v)
	return cloneSandboxVerdict(v), nil
}

func (r *SandboxVerdictRepository) GetBySHA256(
	ctx context.Context,
	tenantID uuid.UUID,
	sha256 string,
) (repository.SandboxVerdict, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.SandboxVerdict{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	v, ok := r.findBySHA256(tenantID, sha256)
	if !ok {
		return repository.SandboxVerdict{}, repository.ErrNotFound
	}
	return cloneSandboxVerdict(v), nil
}

func (r *SandboxVerdictRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	limit int,
) ([]repository.SandboxVerdict, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.SandboxVerdict, 0, len(r.s.sandboxVerdicts))
	for _, v := range r.s.sandboxVerdicts {
		if v.TenantID != tenantID {
			continue
		}
		out = append(out, cloneSandboxVerdict(v))
	}
	// Deterministic: newest first, then id — matching the Postgres
	// store's ORDER BY created_at DESC, id.
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

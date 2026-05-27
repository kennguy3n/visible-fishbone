package memory

import (
	"bytes"
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ClaimTokenRepository is the memory-backed ClaimTokenRepository
// implementation.
type ClaimTokenRepository struct{ s *Store }

func NewClaimTokenRepository(s *Store) *ClaimTokenRepository { return &ClaimTokenRepository{s: s} }

var _ repository.ClaimTokenRepository = (*ClaimTokenRepository)(nil)

func (r *ClaimTokenRepository) Create(ctx context.Context, tenantID uuid.UUID, t repository.ClaimToken) (repository.ClaimToken, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ClaimToken{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.ClaimToken{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.ClaimToken{}, repository.ErrNotFound
	}
	if len(t.TokenHash) == 0 {
		return repository.ClaimToken{}, repository.ErrInvalidArgument
	}
	for _, existing := range r.s.claimTokens {
		if bytes.Equal(existing.TokenHash, t.TokenHash) {
			return repository.ClaimToken{}, repository.ErrConflict
		}
	}
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	t.TenantID = tenantID
	if t.CreatedAt.IsZero() {
		t.CreatedAt = r.s.clock()
	}
	t.TokenHash = cloneBytes(t.TokenHash)
	r.s.claimTokens[t.ID] = t
	return t, nil
}

func (r *ClaimTokenRepository) Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, now time.Time) (repository.ClaimToken, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ClaimToken{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	now = now.UTC()
	for id, t := range r.s.claimTokens {
		if t.TenantID != tenantID || !bytes.Equal(t.TokenHash, hash) {
			continue
		}
		if t.RedeemedAt != nil {
			return repository.ClaimToken{}, repository.ErrForbidden
		}
		if !t.ExpiresAt.After(now) {
			return repository.ClaimToken{}, repository.ErrForbidden
		}
		t.RedeemedAt = &now
		r.s.claimTokens[id] = t
		out := t
		out.TokenHash = cloneBytes(t.TokenHash)
		return out, nil
	}
	return repository.ClaimToken{}, repository.ErrNotFound
}

func (r *ClaimTokenRepository) UnredeemByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, t := range r.s.claimTokens {
		if t.TenantID == tenantID && bytes.Equal(t.TokenHash, hash) {
			t.RedeemedAt = nil
			r.s.claimTokens[id] = t
			return nil
		}
	}
	return repository.ErrNotFound
}

func (r *ClaimTokenRepository) GetByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) (repository.ClaimToken, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.ClaimToken{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, t := range r.s.claimTokens {
		if t.TenantID == tenantID && bytes.Equal(t.TokenHash, hash) {
			out := t
			out.TokenHash = cloneBytes(t.TokenHash)
			return out, nil
		}
	}
	return repository.ClaimToken{}, repository.ErrNotFound
}

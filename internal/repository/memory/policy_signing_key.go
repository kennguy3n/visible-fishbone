package memory

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicySigningKeyRepository is the memory-backed implementation of
// repository.PolicySigningKeyRepository.  It mirrors the
// "at most one active key per tenant" invariant from the partial
// unique index on the Postgres side by rejecting Create when an
// active key already exists.
type PolicySigningKeyRepository struct{ s *Store }

func NewPolicySigningKeyRepository(s *Store) *PolicySigningKeyRepository {
	return &PolicySigningKeyRepository{s: s}
}

var _ repository.PolicySigningKeyRepository = (*PolicySigningKeyRepository)(nil)

func cloneSigningKey(in repository.PolicySigningKey) repository.PolicySigningKey {
	out := in
	out.PublicKey = cloneBytes(in.PublicKey)
	out.PrivateKey = cloneBytes(in.PrivateKey)
	if in.RotatedAt != nil {
		t := *in.RotatedAt
		out.RotatedAt = &t
	}
	if in.RevokedAt != nil {
		t := *in.RevokedAt
		out.RevokedAt = &t
	}
	return out
}

func (r *PolicySigningKeyRepository) Create(ctx context.Context, tenantID uuid.UUID, k repository.PolicySigningKey) (repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicySigningKey{}, err
	}
	if tenantID == uuid.Nil || k.KeyID == "" || k.Algorithm == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if len(k.PublicKey) == 0 || len(k.PrivateKey) == 0 {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.PolicySigningKey{}, repository.ErrNotFound
	}
	if k.Status == "" {
		k.Status = repository.PolicySigningKeyStatusActive
	}
	for _, existing := range r.s.policySigningKeys {
		if existing.TenantID != tenantID {
			continue
		}
		if existing.KeyID == k.KeyID {
			return repository.PolicySigningKey{}, repository.ErrConflict
		}
		if k.Status == repository.PolicySigningKeyStatusActive && existing.Status == repository.PolicySigningKeyStatusActive {
			return repository.PolicySigningKey{}, repository.ErrConflict
		}
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.ActivatedAt.IsZero() {
		k.ActivatedAt = r.s.clock()
	}
	k.TenantID = tenantID
	k.CreatedAt = r.s.clock()
	stored := cloneSigningKey(k)
	r.s.policySigningKeys[stored.ID] = stored
	return cloneSigningKey(stored), nil
}

func (r *PolicySigningKeyRepository) CreateIfNoHistory(ctx context.Context, tenantID uuid.UUID, k repository.PolicySigningKey) (repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicySigningKey{}, err
	}
	if tenantID == uuid.Nil || k.KeyID == "" || k.Algorithm == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if len(k.PublicKey) == 0 || len(k.PrivateKey) == 0 {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	// Hold the store write lock for both the existence probe and
	// the insert so a concurrent goroutine running Create / Rotate
	// / Revoke against the same tenant cannot race in between the
	// two phases. This is the memory-side analogue of the postgres
	// CTE that does the check + insert in one statement.
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.PolicySigningKey{}, repository.ErrNotFound
	}
	for _, existing := range r.s.policySigningKeys {
		if existing.TenantID == tenantID {
			return repository.PolicySigningKey{}, repository.ErrConflict
		}
	}
	if k.Status == "" {
		k.Status = repository.PolicySigningKeyStatusActive
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	if k.ActivatedAt.IsZero() {
		k.ActivatedAt = r.s.clock()
	}
	k.TenantID = tenantID
	k.CreatedAt = r.s.clock()
	stored := cloneSigningKey(k)
	r.s.policySigningKeys[stored.ID] = stored
	return cloneSigningKey(stored), nil
}

func (r *PolicySigningKeyRepository) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicySigningKey{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, k := range r.s.policySigningKeys {
		if k.TenantID == tenantID && k.Status == repository.PolicySigningKeyStatusActive {
			return cloneSigningKey(k), nil
		}
	}
	return repository.PolicySigningKey{}, repository.ErrNotFound
}

func (r *PolicySigningKeyRepository) GetByKeyID(ctx context.Context, tenantID uuid.UUID, keyID string) (repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicySigningKey{}, err
	}
	if keyID == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, k := range r.s.policySigningKeys {
		if k.TenantID == tenantID && k.KeyID == keyID {
			return cloneSigningKey(k), nil
		}
	}
	return repository.PolicySigningKey{}, repository.ErrNotFound
}

func (r *PolicySigningKeyRepository) List(ctx context.Context, tenantID uuid.UUID) ([]repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.PolicySigningKey, 0, len(r.s.policySigningKeys))
	for _, k := range r.s.policySigningKeys {
		if k.TenantID != tenantID {
			continue
		}
		out = append(out, cloneSigningKey(k))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].ActivatedAt.Equal(out[j].ActivatedAt) {
			return out[i].ActivatedAt.After(out[j].ActivatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

func (r *PolicySigningKeyRepository) Rotate(ctx context.Context, tenantID uuid.UUID, newKey repository.PolicySigningKey, at time.Time) (repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicySigningKey{}, err
	}
	if tenantID == uuid.Nil || newKey.KeyID == "" || newKey.Algorithm == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if len(newKey.PublicKey) == 0 || len(newKey.PrivateKey) == 0 {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if at.IsZero() {
		at = r.s.clock()
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	var (
		activeID uuid.UUID
		found    bool
	)
	for id, k := range r.s.policySigningKeys {
		if k.TenantID == tenantID && k.Status == repository.PolicySigningKeyStatusActive {
			activeID = id
			found = true
			break
		}
	}
	if !found {
		return repository.PolicySigningKey{}, repository.ErrNotFound
	}
	for _, existing := range r.s.policySigningKeys {
		if existing.TenantID == tenantID && existing.KeyID == newKey.KeyID {
			return repository.PolicySigningKey{}, repository.ErrConflict
		}
	}
	prev := r.s.policySigningKeys[activeID]
	prev.Status = repository.PolicySigningKeyStatusRotated
	rotatedAt := at
	prev.RotatedAt = &rotatedAt
	r.s.policySigningKeys[activeID] = prev

	if newKey.ID == uuid.Nil {
		newKey.ID = uuid.New()
	}
	newKey.TenantID = tenantID
	newKey.Status = repository.PolicySigningKeyStatusActive
	newKey.ActivatedAt = at
	newKey.CreatedAt = r.s.clock()
	stored := cloneSigningKey(newKey)
	r.s.policySigningKeys[stored.ID] = stored
	return cloneSigningKey(stored), nil
}

func (r *PolicySigningKeyRepository) Revoke(ctx context.Context, tenantID uuid.UUID, keyID string, at time.Time) (repository.PolicySigningKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicySigningKey{}, err
	}
	if keyID == "" {
		return repository.PolicySigningKey{}, repository.ErrInvalidArgument
	}
	if at.IsZero() {
		at = r.s.clock()
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, k := range r.s.policySigningKeys {
		if k.TenantID != tenantID || k.KeyID != keyID {
			continue
		}
		if k.Status == repository.PolicySigningKeyStatusRevoked {
			return repository.PolicySigningKey{}, repository.ErrNotFound
		}
		k.Status = repository.PolicySigningKeyStatusRevoked
		revokedAt := at
		k.RevokedAt = &revokedAt
		r.s.policySigningKeys[id] = k
		return cloneSigningKey(k), nil
	}
	return repository.PolicySigningKey{}, repository.ErrNotFound
}

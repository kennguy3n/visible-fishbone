package memory

import (
	"bytes"
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TenantAPIKeyRepository is the in-memory implementation of
// repository.TenantAPIKeyRepository. It mirrors the Postgres
// constraint set: unique hash globally, tenant-scoped reads/writes
// except LookupByHash which is cross-tenant (the Postgres analogue
// flips sng.system_role='true' for that one path).
type TenantAPIKeyRepository struct{ s *Store }

// NewTenantAPIKeyRepository binds the Store to the interface.
func NewTenantAPIKeyRepository(s *Store) *TenantAPIKeyRepository {
	return &TenantAPIKeyRepository{s: s}
}

var _ repository.TenantAPIKeyRepository = (*TenantAPIKeyRepository)(nil)

func cloneAPIKey(in repository.TenantAPIKey) repository.TenantAPIKey {
	out := in
	out.Hash = cloneBytes(in.Hash)
	if in.ExpiresAt != nil {
		t := *in.ExpiresAt
		out.ExpiresAt = &t
	}
	if in.LastUsedAt != nil {
		t := *in.LastUsedAt
		out.LastUsedAt = &t
	}
	if in.CreatedBy != nil {
		u := *in.CreatedBy
		out.CreatedBy = &u
	}
	if in.RevokedAt != nil {
		t := *in.RevokedAt
		out.RevokedAt = &t
	}
	return out
}

func (r *TenantAPIKeyRepository) Create(ctx context.Context, tenantID uuid.UUID, k repository.TenantAPIKey) (repository.TenantAPIKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantAPIKey{}, err
	}
	if tenantID == uuid.Nil || k.Name == "" || k.Subject == "" || len(k.Hash) == 0 {
		return repository.TenantAPIKey{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.TenantAPIKey{}, repository.ErrNotFound
	}
	for _, existing := range r.s.tenantAPIKeys {
		if bytes.Equal(existing.Hash, k.Hash) {
			return repository.TenantAPIKey{}, repository.ErrConflict
		}
	}
	if k.Status == "" {
		k.Status = repository.TenantAPIKeyStatusActive
	}
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	k.TenantID = tenantID
	k.CreatedAt = r.s.clock()
	stored := cloneAPIKey(k)
	r.s.tenantAPIKeys[stored.ID] = stored
	return cloneAPIKey(stored), nil
}

func (r *TenantAPIKeyRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.TenantAPIKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantAPIKey{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	k, ok := r.s.tenantAPIKeys[id]
	if !ok || k.TenantID != tenantID {
		return repository.TenantAPIKey{}, repository.ErrNotFound
	}
	return cloneAPIKey(k), nil
}

func (r *TenantAPIKeyRepository) List(ctx context.Context, tenantID uuid.UUID) ([]repository.TenantAPIKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.TenantAPIKey, 0)
	for _, k := range r.s.tenantAPIKeys {
		if k.TenantID == tenantID {
			out = append(out, cloneAPIKey(k))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() < out[j].ID.String()
	})
	return out, nil
}

func (r *TenantAPIKeyRepository) Revoke(ctx context.Context, tenantID, id uuid.UUID, at time.Time) (repository.TenantAPIKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantAPIKey{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k, ok := r.s.tenantAPIKeys[id]
	if !ok || k.TenantID != tenantID {
		return repository.TenantAPIKey{}, repository.ErrNotFound
	}
	if k.Status == repository.TenantAPIKeyStatusRevoked {
		// Idempotent — return the existing row unchanged so the
		// service layer can audit the no-op explicitly.
		return cloneAPIKey(k), nil
	}
	k.Status = repository.TenantAPIKeyStatusRevoked
	t := at.UTC()
	k.RevokedAt = &t
	r.s.tenantAPIKeys[id] = cloneAPIKey(k)
	return cloneAPIKey(k), nil
}

func (r *TenantAPIKeyRepository) LookupByHash(ctx context.Context, hash []byte) (repository.TenantAPIKey, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TenantAPIKey{}, err
	}
	if len(hash) == 0 {
		return repository.TenantAPIKey{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, k := range r.s.tenantAPIKeys {
		if bytes.Equal(k.Hash, hash) {
			return cloneAPIKey(k), nil
		}
	}
	return repository.TenantAPIKey{}, repository.ErrNotFound
}

func (r *TenantAPIKeyRepository) CountActive(ctx context.Context, tenantID uuid.UUID, now time.Time) (int, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return 0, err
	}
	if tenantID == uuid.Nil {
		return 0, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	n := 0
	for _, k := range r.s.tenantAPIKeys {
		if k.TenantID != tenantID {
			continue
		}
		if k.Status != repository.TenantAPIKeyStatusActive {
			continue
		}
		if k.ExpiresAt != nil && !k.ExpiresAt.After(now) {
			continue
		}
		n++
	}
	return n, nil
}

func (r *TenantAPIKeyRepository) TouchLastUsed(ctx context.Context, tenantID, id uuid.UUID, at time.Time) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	k, ok := r.s.tenantAPIKeys[id]
	if !ok || k.TenantID != tenantID {
		return repository.ErrNotFound
	}
	t := at.UTC()
	k.LastUsedAt = &t
	r.s.tenantAPIKeys[id] = cloneAPIKey(k)
	return nil
}

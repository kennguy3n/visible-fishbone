package memory

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TenantRepository is the memory-backed TenantRepository
// implementation. Constructed via NewTenantRepository so callers
// always go through a typed constructor (avoids hand-typing the
// Store reference everywhere).
type TenantRepository struct{ s *Store }

// NewTenantRepository binds a Store to the TenantRepository interface.
func NewTenantRepository(s *Store) *TenantRepository { return &TenantRepository{s: s} }

// Compile-time assertion the type satisfies the interface.
var _ repository.TenantRepository = (*TenantRepository)(nil)

func (r *TenantRepository) Create(ctx context.Context, t repository.Tenant) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()

	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Slug == "" {
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	for _, existing := range r.s.tenants {
		if existing.Slug == t.Slug && existing.DeletedAt == nil {
			return repository.Tenant{}, repository.ErrConflict
		}
	}
	now := r.s.clock()
	t.CreatedAt = now
	t.UpdatedAt = now
	if t.Status == "" {
		t.Status = repository.TenantStatusActive
	}
	t.Settings = cloneJSON(t.Settings)
	r.s.tenants[t.ID] = t
	return t, nil
}

func (r *TenantRepository) Get(ctx context.Context, id uuid.UUID) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	t, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	t.Settings = cloneJSON(t.Settings)
	return t, nil
}

func (r *TenantRepository) GetBySlug(ctx context.Context, slug string) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, t := range r.s.tenants {
		if t.Slug == slug {
			t.Settings = cloneJSON(t.Settings)
			return t, nil
		}
	}
	return repository.Tenant{}, repository.ErrNotFound
}

func (r *TenantRepository) List(ctx context.Context, page repository.Page) (repository.PageResult[repository.Tenant], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.Tenant]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.Tenant, 0, len(r.s.tenants))
	for _, t := range r.s.tenants {
		t.Settings = cloneJSON(t.Settings)
		all = append(all, t)
	}
	sorted := sortByCreatedAtDesc(all,
		func(t repository.Tenant) time.Time { return t.CreatedAt },
		func(t repository.Tenant) uuid.UUID { return t.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(t repository.Tenant) cursor {
		return cursor{CreatedAt: t.CreatedAt, ID: t.ID}
	}), nil
}

func (r *TenantRepository) Update(ctx context.Context, t repository.Tenant) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[t.ID]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	if t.Slug != "" && t.Slug != existing.Slug {
		for id, other := range r.s.tenants {
			if id == t.ID {
				continue
			}
			if other.Slug == t.Slug && other.DeletedAt == nil {
				return repository.Tenant{}, repository.ErrConflict
			}
		}
		existing.Slug = t.Slug
	}
	if t.Name != "" {
		existing.Name = t.Name
	}
	if t.Region != "" {
		existing.Region = t.Region
	}
	if t.Tier != "" {
		existing.Tier = t.Tier
	}
	if t.Settings != nil {
		existing.Settings = cloneJSON(t.Settings)
	}
	if t.Status != "" {
		existing.Status = t.Status
	}
	existing.UpdatedAt = r.s.clock()
	r.s.tenants[existing.ID] = existing
	out := existing
	out.Settings = cloneJSON(existing.Settings)
	return out, nil
}

func (r *TenantRepository) UpdateStatus(ctx context.Context, id uuid.UUID, status repository.TenantStatus) (repository.Tenant, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Tenant{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.tenants[id]
	if !ok {
		return repository.Tenant{}, repository.ErrNotFound
	}
	switch status {
	case repository.TenantStatusActive, repository.TenantStatusSuspended, repository.TenantStatusDeleted:
	default:
		return repository.Tenant{}, repository.ErrInvalidArgument
	}
	existing.Status = status
	existing.UpdatedAt = r.s.clock()
	if status == repository.TenantStatusDeleted && existing.DeletedAt == nil {
		t := r.s.clock()
		existing.DeletedAt = &t
	}
	r.s.tenants[id] = existing
	out := existing
	out.Settings = cloneJSON(existing.Settings)
	return out, nil
}

func (r *TenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	if _, err := r.UpdateStatus(ctx, id, repository.TenantStatusDeleted); err != nil {
		return err
	}
	return nil
}

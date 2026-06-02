package memory

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// UserRepository is the memory-backed UserRepository implementation.
type UserRepository struct{ s *Store }

func NewUserRepository(s *Store) *UserRepository { return &UserRepository{s: s} }

var _ repository.UserRepository = (*UserRepository)(nil)

func (r *UserRepository) Create(ctx context.Context, tenantID uuid.UUID, u repository.User) (repository.User, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.User{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.User{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.User{}, repository.ErrNotFound
	}
	if u.Email == "" {
		return repository.User{}, repository.ErrInvalidArgument
	}
	emailKey := strings.ToLower(u.Email)
	for _, existing := range r.s.users {
		if existing.TenantID == tenantID && strings.EqualFold(existing.Email, emailKey) {
			return repository.User{}, repository.ErrConflict
		}
	}
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	u.TenantID = tenantID
	if u.Status == "" {
		u.Status = repository.UserStatusActive
	}
	now := r.s.clock()
	u.CreatedAt = now
	u.UpdatedAt = now
	r.s.users[u.ID] = u
	return u, nil
}

func (r *UserRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.User, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.User{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	u, ok := r.s.users[id]
	if !ok || u.TenantID != tenantID {
		return repository.User{}, repository.ErrNotFound
	}
	return u, nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, tenantID uuid.UUID, email string) (repository.User, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.User{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, u := range r.s.users {
		if u.TenantID == tenantID && strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return repository.User{}, repository.ErrNotFound
}

func (r *UserRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.User], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.User]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.User, 0, len(r.s.users))
	for _, u := range r.s.users {
		if u.TenantID != tenantID {
			continue
		}
		all = append(all, u)
	}
	sorted := sortByCreatedAtDesc(all,
		func(u repository.User) time.Time { return u.CreatedAt },
		func(u repository.User) uuid.UUID { return u.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(u repository.User) cursor {
		return cursor{CreatedAt: u.CreatedAt, ID: u.ID}
	}), nil
}

func (r *UserRepository) Update(ctx context.Context, tenantID uuid.UUID, u repository.User) (repository.User, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.User{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.users[u.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.User{}, repository.ErrNotFound
	}
	if u.Email != "" && !strings.EqualFold(u.Email, existing.Email) {
		for id, other := range r.s.users {
			if id == existing.ID {
				continue
			}
			if other.TenantID == tenantID && strings.EqualFold(other.Email, u.Email) {
				return repository.User{}, repository.ErrConflict
			}
		}
		existing.Email = u.Email
	}
	if u.Name != "" {
		existing.Name = u.Name
	}
	if u.ExternalID != "" {
		existing.ExternalID = u.ExternalID
	}
	if u.IDPSubject != "" {
		existing.IDPSubject = u.IDPSubject
	}
	if u.Status != "" {
		existing.Status = u.Status
	}
	existing.UpdatedAt = r.s.clock()
	r.s.users[existing.ID] = existing
	return existing, nil
}

func (r *UserRepository) ClearExternalID(ctx context.Context, tenantID, userID uuid.UUID) (repository.User, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.User{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.users[userID]
	if !ok || existing.TenantID != tenantID {
		return repository.User{}, repository.ErrNotFound
	}
	existing.ExternalID = ""
	existing.UpdatedAt = r.s.clock()
	r.s.users[existing.ID] = existing
	return existing, nil
}

func (r *UserRepository) UpdateAndClearExternalID(ctx context.Context, tenantID uuid.UUID, u repository.User) (repository.User, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.User{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.users[u.ID]
	if !ok || existing.TenantID != tenantID {
		return repository.User{}, repository.ErrNotFound
	}
	if u.Email != "" {
		for uid, other := range r.s.users {
			if uid != u.ID && other.TenantID == tenantID && strings.EqualFold(other.Email, u.Email) {
				return repository.User{}, repository.ErrConflict
			}
		}
		existing.Email = u.Email
	}
	if u.Name != "" {
		existing.Name = u.Name
	}
	existing.ExternalID = ""
	if u.IDPSubject != "" {
		existing.IDPSubject = u.IDPSubject
	}
	if u.Status != "" {
		existing.Status = u.Status
	}
	existing.UpdatedAt = r.s.clock()
	r.s.users[existing.ID] = existing
	return existing, nil
}

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

func (r *UserRepository) SearchUsers(ctx context.Context, tenantID uuid.UUID, filter repository.UserSearchFilter, offset, limit int) ([]repository.User, int, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, 0, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	matching := make([]repository.User, 0)
	for _, u := range r.s.users {
		if u.TenantID != tenantID {
			continue
		}
		if !userMatchesFilter(u, filter) {
			continue
		}
		matching = append(matching, u)
	}
	// Match the postgres backend's deterministic ordering so the SCIM
	// pagination window is stable across both drivers.
	sorted := sortByCreatedAtDesc(matching,
		func(u repository.User) time.Time { return u.CreatedAt },
		func(u repository.User) uuid.UUID { return u.ID },
		repository.SortDesc,
	)
	total := len(sorted)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	if limit <= 0 {
		return []repository.User{}, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return sorted[offset:end], total, nil
}

// userMatchesFilter reports whether u satisfies filter. A zero filter
// (empty Field) matches every user. Matching is case-insensitive to
// mirror the postgres backend.
func userMatchesFilter(u repository.User, filter repository.UserSearchFilter) bool {
	if filter.Field == "" {
		return true
	}
	var field string
	switch filter.Field {
	case repository.UserSearchFieldEmail:
		field = u.Email
	case repository.UserSearchFieldName:
		field = u.Name
	case repository.UserSearchFieldExternalID:
		field = u.ExternalID
	default:
		return false
	}
	fl := strings.ToLower(field)
	vl := strings.ToLower(filter.Value)
	switch filter.Op {
	case repository.TextMatchEquals:
		return fl == vl
	case repository.TextMatchContains:
		return strings.Contains(fl, vl)
	case repository.TextMatchPrefix:
		return strings.HasPrefix(fl, vl)
	default:
		return false
	}
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

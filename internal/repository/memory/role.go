package memory

import (
	"context"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// RoleRepository is the memory-backed RoleRepository implementation.
type RoleRepository struct{ s *Store }

func NewRoleRepository(s *Store) *RoleRepository { return &RoleRepository{s: s} }

var _ repository.RoleRepository = (*RoleRepository)(nil)

func (r *RoleRepository) Create(ctx context.Context, role repository.Role) (repository.Role, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Role{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if role.Name == "" {
		return repository.Role{}, repository.ErrInvalidArgument
	}
	switch role.Scope {
	case repository.RoleScopePlatform, repository.RoleScopeMSP,
		repository.RoleScopeTenant, repository.RoleScopeSite:
	default:
		return repository.Role{}, repository.ErrInvalidArgument
	}
	if role.TenantID != nil {
		if _, ok := r.s.tenants[*role.TenantID]; !ok {
			return repository.Role{}, repository.ErrNotFound
		}
	}
	for _, existing := range r.s.roles {
		if existing.Name != role.Name {
			continue
		}
		// UNIQUE(tenant_id, name) — NULL tenant_ids form their
		// own implicit bucket of system roles.
		switch {
		case existing.TenantID == nil && role.TenantID == nil:
			return repository.Role{}, repository.ErrConflict
		case existing.TenantID != nil && role.TenantID != nil && *existing.TenantID == *role.TenantID:
			return repository.Role{}, repository.ErrConflict
		}
	}
	if role.ID == uuid.Nil {
		role.ID = uuid.New()
	}
	if role.Permissions == nil {
		role.Permissions = []string{}
	} else {
		role.Permissions = append([]string(nil), role.Permissions...)
	}
	role.CreatedAt = r.s.clock()
	r.s.roles[role.ID] = role
	return role, nil
}

func (r *RoleRepository) Get(ctx context.Context, id uuid.UUID) (repository.Role, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Role{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	role, ok := r.s.roles[id]
	if !ok {
		return repository.Role{}, repository.ErrNotFound
	}
	role.Permissions = append([]string(nil), role.Permissions...)
	return role, nil
}

func (r *RoleRepository) List(ctx context.Context, tenantID *uuid.UUID) ([]repository.Role, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.Role, 0, len(r.s.roles))
	for _, role := range r.s.roles {
		// Always include system roles (TenantID == nil) AND
		// the tenant's own roles when tenantID is supplied.
		// When tenantID is nil, callers see the full roles
		// table (administrative listing).
		if tenantID == nil ||
			role.TenantID == nil ||
			(role.TenantID != nil && *role.TenantID == *tenantID) {
			cp := role
			cp.Permissions = append([]string(nil), role.Permissions...)
			out = append(out, cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (r *RoleRepository) AssignRole(ctx context.Context, ur repository.UserRole) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if _, ok := r.s.users[ur.UserID]; !ok {
		return repository.ErrNotFound
	}
	if _, ok := r.s.roles[ur.RoleID]; !ok {
		return repository.ErrNotFound
	}
	key := userRoleKey{UserID: ur.UserID, RoleID: ur.RoleID, ScopeID: scopeIDOrZero(ur.ScopeID)}
	if _, dup := r.s.userRoles[key]; dup {
		return repository.ErrConflict
	}
	if ur.GrantedAt.IsZero() {
		ur.GrantedAt = r.s.clock()
	}
	r.s.userRoles[key] = ur
	return nil
}

func (r *RoleRepository) RevokeRole(ctx context.Context, userID, roleID uuid.UUID, scopeID *uuid.UUID) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	key := userRoleKey{UserID: userID, RoleID: roleID, ScopeID: scopeIDOrZero(scopeID)}
	if _, ok := r.s.userRoles[key]; !ok {
		return repository.ErrNotFound
	}
	delete(r.s.userRoles, key)
	return nil
}

func (r *RoleRepository) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]repository.UserRole, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.UserRole, 0)
	for _, ur := range r.s.userRoles {
		if ur.UserID == userID {
			out = append(out, ur)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantedAt.Before(out[j].GrantedAt) })
	return out, nil
}

func (r *RoleRepository) HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return false, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, ur := range r.s.userRoles {
		if ur.UserID != userID {
			continue
		}
		role, ok := r.s.roles[ur.RoleID]
		if !ok {
			continue
		}
		for _, p := range role.Permissions {
			if p == permission || p == "*" {
				return true, nil
			}
		}
	}
	return false, nil
}

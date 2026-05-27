// Package rbac implements role-based access control on top of the
// RoleRepository + UserRepository. Six system roles are seeded on
// tenant creation:
//
//   - platform_admin (scope: platform) — manage all tenants
//   - msp_admin      (scope: msp)      — manage child tenants
//   - tenant_admin   (scope: tenant)   — full tenant access
//   - site_admin     (scope: site)     — manage a single site
//   - operator       (scope: tenant)   — day-to-day operations
//   - viewer         (scope: tenant)   — read-only
//
// Permissions are simple string tokens (e.g. "devices:read"). A
// permission of "*" granted on a role acts as a wildcard match.
package rbac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Permission strings used across the platform. Co-located here so
// the canonical set is reviewable as a single block.
const (
	PermTenantsRead   = "tenants:read"
	PermTenantsWrite  = "tenants:write"
	PermTenantsDelete = "tenants:delete"

	PermSitesRead   = "sites:read"
	PermSitesWrite  = "sites:write"
	PermSitesDelete = "sites:delete"

	PermDevicesRead   = "devices:read"
	PermDevicesWrite  = "devices:write"
	PermDevicesDelete = "devices:delete"

	PermPolicyRead    = "policy:read"
	PermPolicyWrite   = "policy:write"
	PermPolicyCompile = "policy:compile"

	PermUsersRead   = "users:read"
	PermUsersWrite  = "users:write"
	PermUsersDelete = "users:delete"

	PermAuditRead = "audit:read"

	PermRolesRead   = "roles:read"
	PermRolesWrite  = "roles:write"
	PermRolesAssign = "roles:assign"

	PermWildcard = "*"
)

// SystemRole describes a built-in role. Names are stable identifiers
// and serve as the (tenant_id IS NULL, name) lookup key.
type SystemRole struct {
	Name        string
	Scope       repository.RoleScope
	Permissions []string
}

// SystemRoles is the canonical list of roles seeded on every tenant
// creation. Order is deterministic so the audit log + tests can
// rely on insertion order.
var SystemRoles = []SystemRole{
	{
		Name:        "platform_admin",
		Scope:       repository.RoleScopePlatform,
		Permissions: []string{PermWildcard},
	},
	{
		Name:  "msp_admin",
		Scope: repository.RoleScopeMSP,
		Permissions: []string{
			PermTenantsRead, PermTenantsWrite,
			PermSitesRead, PermSitesWrite,
			PermDevicesRead, PermDevicesWrite,
			PermPolicyRead, PermPolicyWrite,
			PermUsersRead, PermUsersWrite,
			PermRolesRead, PermRolesAssign,
			PermAuditRead,
		},
	},
	{
		Name:  "tenant_admin",
		Scope: repository.RoleScopeTenant,
		Permissions: []string{
			PermTenantsRead, PermTenantsWrite,
			PermSitesRead, PermSitesWrite, PermSitesDelete,
			PermDevicesRead, PermDevicesWrite, PermDevicesDelete,
			PermPolicyRead, PermPolicyWrite, PermPolicyCompile,
			PermUsersRead, PermUsersWrite, PermUsersDelete,
			PermRolesRead, PermRolesWrite, PermRolesAssign,
			PermAuditRead,
		},
	},
	{
		Name:  "site_admin",
		Scope: repository.RoleScopeSite,
		Permissions: []string{
			PermSitesRead, PermSitesWrite,
			PermDevicesRead, PermDevicesWrite,
			PermPolicyRead,
			PermUsersRead,
			PermAuditRead,
		},
	},
	{
		Name:  "operator",
		Scope: repository.RoleScopeTenant,
		Permissions: []string{
			PermSitesRead, PermDevicesRead, PermDevicesWrite,
			PermPolicyRead, PermUsersRead, PermAuditRead,
		},
	},
	{
		Name:  "viewer",
		Scope: repository.RoleScopeTenant,
		Permissions: []string{
			PermTenantsRead, PermSitesRead, PermDevicesRead,
			PermPolicyRead, PermUsersRead, PermAuditRead,
		},
	},
}

// Service implements RBAC operations.
type Service struct {
	roles repository.RoleRepository
	users repository.UserRepository
	audit repository.AuditLogRepository
}

// New returns a ready-to-use RBAC service.
func New(
	roles repository.RoleRepository,
	users repository.UserRepository,
	audit repository.AuditLogRepository,
) *Service {
	return &Service{roles: roles, users: users, audit: audit}
}

// SeedSystemRoles inserts every SystemRole as a tenant-scoped role.
// Idempotent: roles that already exist (same tenant+name) trigger
// ErrConflict and are skipped silently. Returns the freshly seeded
// roles plus any pre-existing ones, in deterministic order.
//
// Pass tenantID = uuid.Nil for the platform-wide singleton (system
// roles with tenant_id = NULL); pass a real UUID for a per-tenant
// snapshot.
func (svc *Service) SeedSystemRoles(ctx context.Context, tenantID uuid.UUID) ([]repository.Role, error) {
	out := make([]repository.Role, 0, len(SystemRoles))
	var scopedID *uuid.UUID
	if tenantID != uuid.Nil {
		scopedID = &tenantID
	}
	for _, sr := range SystemRoles {
		role := repository.Role{
			TenantID:    scopedID,
			Name:        sr.Name,
			Permissions: append([]string{}, sr.Permissions...),
			Scope:       sr.Scope,
		}
		created, err := svc.roles.Create(ctx, role)
		switch {
		case err == nil:
			out = append(out, created)
		case errors.Is(err, repository.ErrConflict):
			// Role already exists; we don't have a (tenant, name)
			// lookup so skip and let the caller refetch via List.
		default:
			return nil, fmt.Errorf("seed role %q: %w", sr.Name, err)
		}
	}
	return out, nil
}

// CreateCustomRole creates a tenant-scoped custom role.
func (svc *Service) CreateCustomRole(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	name string,
	scope repository.RoleScope,
	permissions []string,
) (repository.Role, error) {
	if name == "" {
		return repository.Role{}, fmt.Errorf("role name is required: %w", repository.ErrInvalidArgument)
	}
	if scope == "" {
		return repository.Role{}, fmt.Errorf("role scope is required: %w", repository.ErrInvalidArgument)
	}
	created, err := svc.roles.Create(ctx, repository.Role{
		TenantID:    &tenantID,
		Name:        name,
		Permissions: append([]string{}, permissions...),
		Scope:       scope,
	})
	if err != nil {
		return repository.Role{}, err
	}
	_ = svc.appendAudit(ctx, tenantID, actorID, "role.created", "role", &created.ID, nil)
	return created, nil
}

// ListRoles returns roles visible to a tenant: system roles
// (tenant_id IS NULL) plus the tenant's own roles.
func (svc *Service) ListRoles(ctx context.Context, tenantID uuid.UUID) ([]repository.Role, error) {
	return svc.roles.List(ctx, &tenantID)
}

// AssignRole grants a role to a user, optionally scoped to a
// specific resource (e.g. a site UUID for site-scoped roles).
func (svc *Service) AssignRole(
	ctx context.Context,
	tenantID, userID, roleID uuid.UUID,
	scopeID *uuid.UUID,
	grantedBy *uuid.UUID,
) error {
	if err := svc.roles.AssignRole(ctx, repository.UserRole{
		UserID:    userID,
		RoleID:    roleID,
		ScopeID:   scopeID,
		GrantedBy: grantedBy,
	}); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{
		"user_id":  userID,
		"role_id":  roleID,
		"scope_id": scopeID,
	})
	_ = svc.appendAudit(ctx, tenantID, grantedBy, "role.assigned", "user_role", &userID, details)
	return nil
}

// RevokeRole removes a role grant from a user.
func (svc *Service) RevokeRole(
	ctx context.Context,
	tenantID, userID, roleID uuid.UUID,
	scopeID *uuid.UUID,
	actorID *uuid.UUID,
) error {
	if err := svc.roles.RevokeRole(ctx, userID, roleID, scopeID); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{
		"user_id":  userID,
		"role_id":  roleID,
		"scope_id": scopeID,
	})
	_ = svc.appendAudit(ctx, tenantID, actorID, "role.revoked", "user_role", &userID, details)
	return nil
}

// GetUserRoles returns every role binding for a user.
func (svc *Service) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]repository.UserRole, error) {
	return svc.roles.GetUserRoles(ctx, userID)
}

// HasPermission reports whether the user holds a role granting the
// permission. Wildcards ("*") in a role's permissions match any
// requested permission.
func (svc *Service) HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error) {
	return svc.roles.HasPermission(ctx, userID, permission)
}

func (svc *Service) appendAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details json.RawMessage,
) error {
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	_, err := svc.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

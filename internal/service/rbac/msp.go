package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AuthorizeMSP reports whether the user holds a role granting
// `permission` on the given MSP.
//
// Decision rule, evaluated in order:
//  1. Any role with scope=platform and permission in the role's
//     set (or `"*"`) → allow. Platform_admin sees every MSP.
//  2. Any role with scope=msp, scope_id matching `mspID`, and the
//     permission in the role's set (or `"*"`) → allow.
//  3. Otherwise → deny.
//
// Note: scope=tenant grants are NOT considered here. The
// composition msp → tenant → site (i.e. "I can act on every
// tenant the MSP owns") is computed separately via
// ListAuthorizedTenants; per-tenant authorization is the
// existing rbac.HasPermission path.
//
// Returns (false, nil) on a clean deny. Returns a non-nil error
// only when the underlying storage call fails (e.g. db down).
func (svc *Service) AuthorizeMSP(
	ctx context.Context,
	userID, mspID uuid.UUID,
	permission string,
) (bool, error) {
	if userID == uuid.Nil || mspID == uuid.Nil || permission == "" {
		return false, fmt.Errorf("authorize msp: %w", repository.ErrInvalidArgument)
	}
	grants, err := svc.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("authorize msp: get user roles: %w", err)
	}
	for _, g := range grants {
		role, err := svc.roles.Get(ctx, g.RoleID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				// Stale grant (role was deleted) — skip; don't
				// fail the whole authorize call.
				continue
			}
			return false, fmt.Errorf("authorize msp: get role %s: %w", g.RoleID, err)
		}
		if !rolePermits(role, permission) {
			continue
		}
		switch role.Scope {
		case repository.RoleScopePlatform:
			// Platform-scoped grants ignore scope_id (one
			// global grant gates everything). Mirrors the
			// existing platform_admin escape hatch.
			return true, nil
		case repository.RoleScopeMSP:
			// MSP-scoped grants must match the requested MSP.
			// A nil ScopeID is treated as "no specific MSP" —
			// useful for the system-singleton msp_admin row
			// seeded with tenant_id NULL — and is rejected
			// here so msp_admin grants are explicit.
			if g.ScopeID != nil && *g.ScopeID == mspID {
				return true, nil
			}
		}
	}
	return false, nil
}

// ListAuthorizedTenants returns every tenant under `mspID` that the
// user is authorized to act on. Composition rule:
//
//   - If the user holds any platform-scoped grant with the
//     wildcard permission, they see every tenant the MSP owns or
//     co-manages.
//   - If the user holds an msp-scoped grant matching `mspID`,
//     they see every tenant the MSP owns or co-manages.
//   - Otherwise the set is restricted to tenants where the user
//     additionally holds a tenant-scoped grant matching that
//     tenant.
//
// This is the data side of the MSP bulk-operations surface
// (Task 24): callers fan out across the returned slice rather
// than iterating msp.AssignedTenants() with no authorization
// check.
func (svc *Service) ListAuthorizedTenants(
	ctx context.Context,
	userID, mspID uuid.UUID,
	msps repository.MSPRepository,
) ([]uuid.UUID, error) {
	if userID == uuid.Nil || mspID == uuid.Nil {
		return nil, fmt.Errorf("list authorized tenants: %w", repository.ErrInvalidArgument)
	}
	// Pull every binding for the MSP. ListTenants returns paginated
	// rows; for the platform's expected MSP sizes (<10k tenants)
	// the unbounded loop is acceptable and matches the bulk-op
	// fan-out limit.
	var bound []uuid.UUID
	var cursor string
	for {
		page, err := msps.ListTenants(ctx, mspID, repository.Page{
			Limit: 1000,
			After: cursor,
		})
		if err != nil {
			return nil, fmt.Errorf("list authorized tenants: msp binding: %w", err)
		}
		for _, b := range page.Items {
			bound = append(bound, b.TenantID)
		}
		if page.NextCursor == "" {
			break
		}
		cursor = page.NextCursor
	}

	// Decide the broad authorization (platform or msp scope).
	broad, err := svc.userHasBroadAuthority(ctx, userID, mspID)
	if err != nil {
		return nil, err
	}
	if broad {
		return bound, nil
	}

	// Fall back to per-tenant authorization. Read every grant once
	// and look up scope_ids matching bound tenants.
	grants, err := svc.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list authorized tenants: get user roles: %w", err)
	}
	tenantGrants := make(map[uuid.UUID]struct{}, len(grants))
	for _, g := range grants {
		role, err := svc.roles.Get(ctx, g.RoleID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				continue
			}
			return nil, fmt.Errorf("list authorized tenants: get role: %w", err)
		}
		if role.Scope != repository.RoleScopeTenant {
			continue
		}
		// Tenant-scoped roles encode the tenant via Role.TenantID
		// (system roles seeded per-tenant) or via UserRole.ScopeID
		// (custom roles with a tenant scope). We accept either.
		switch {
		case g.ScopeID != nil:
			tenantGrants[*g.ScopeID] = struct{}{}
		case role.TenantID != nil:
			tenantGrants[*role.TenantID] = struct{}{}
		}
	}
	out := make([]uuid.UUID, 0, len(bound))
	for _, tid := range bound {
		if _, ok := tenantGrants[tid]; ok {
			out = append(out, tid)
		}
	}
	return out, nil
}

// userHasBroadAuthority reports whether the user holds either a
// platform-wildcard grant or an msp-scoped grant for `mspID`. It
// is the precondition that lets ListAuthorizedTenants short-
// circuit the per-tenant grant scan.
func (svc *Service) userHasBroadAuthority(
	ctx context.Context,
	userID, mspID uuid.UUID,
) (bool, error) {
	grants, err := svc.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("broad authority: get user roles: %w", err)
	}
	for _, g := range grants {
		role, err := svc.roles.Get(ctx, g.RoleID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				continue
			}
			return false, fmt.Errorf("broad authority: get role: %w", err)
		}
		switch role.Scope {
		case repository.RoleScopePlatform:
			if containsString(role.Permissions, PermWildcard) {
				return true, nil
			}
		case repository.RoleScopeMSP:
			if g.ScopeID != nil && *g.ScopeID == mspID {
				return true, nil
			}
		}
	}
	return false, nil
}

// GrantMSPRole assigns `roleID` to `userID` scoped to `mspID`.
// The role must have scope=msp; otherwise ErrInvalidArgument.
//
// Wraps the lower-level AssignRole so the scope_id is set
// uniformly and the audit entry carries the MSP context.
func (svc *Service) GrantMSPRole(
	ctx context.Context,
	mspID, userID, roleID uuid.UUID,
	grantedBy *uuid.UUID,
) error {
	if mspID == uuid.Nil || userID == uuid.Nil || roleID == uuid.Nil {
		return fmt.Errorf("grant msp role: %w", repository.ErrInvalidArgument)
	}
	role, err := svc.roles.Get(ctx, roleID)
	if err != nil {
		return fmt.Errorf("grant msp role: get role: %w", err)
	}
	if role.Scope != repository.RoleScopeMSP {
		return fmt.Errorf("grant msp role: role scope is %q, want %q: %w",
			role.Scope, repository.RoleScopeMSP, repository.ErrInvalidArgument)
	}
	scope := mspID
	// The audit entry uses tenant_id = uuid.Nil because MSP grants
	// are platform-scoped (no owning tenant). The MSP id is in the
	// details payload via AssignRole's existing serialisation.
	return svc.AssignRole(ctx, uuid.Nil, userID, roleID, &scope, grantedBy)
}

// rolePermits reports whether the role's permission set includes
// the requested permission (literal or `"*"` wildcard).
func rolePermits(r repository.Role, permission string) bool {
	for _, p := range r.Permissions {
		if p == PermWildcard || p == permission {
			return true
		}
	}
	return false
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

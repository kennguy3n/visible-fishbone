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

// AuthorizePlatform reports whether the user holds a platform-scoped
// role granting `permission`. Used by the MSP CRUD list/create
// endpoints which operate above any specific MSP — there is no
// msp_id to gate against, so AuthorizeMSP (which rejects
// mspID=uuid.Nil) is unsuitable.
//
// Decision rule:
//  1. Any role with scope=platform and permission in the role's
//     set (or `"*"`) → allow.
//  2. Otherwise → deny.
//
// Note: MSP-scoped grants are NOT considered platform authority. An
// operator with msp_admin on a single MSP must not be able to list
// or create OTHER MSPs — round-2 plugged that privilege-escalation
// path on `GET/POST /api/v1/msps`.
//
// Returns (false, nil) on a clean deny. Returns a non-nil error
// only when the underlying storage call fails (e.g. db down).
func (svc *Service) AuthorizePlatform(
	ctx context.Context,
	userID uuid.UUID,
	permission string,
) (bool, error) {
	if userID == uuid.Nil || permission == "" {
		return false, fmt.Errorf("authorize platform: %w", repository.ErrInvalidArgument)
	}
	grants, err := svc.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("authorize platform: get user roles: %w", err)
	}
	for _, g := range grants {
		role, err := svc.roles.Get(ctx, g.RoleID)
		if err != nil {
			if errors.Is(err, repository.ErrNotFound) {
				// Stale grant (role was deleted) — skip; don't
				// fail the whole authorize call.
				continue
			}
			return false, fmt.Errorf("authorize platform: get role %s: %w", g.RoleID, err)
		}
		if role.Scope != repository.RoleScopePlatform {
			continue
		}
		if rolePermits(role, permission) {
			return true, nil
		}
	}
	return false, nil
}

// ListAuthorizedTenantsMaxPages caps the pagination loop in
// ListAuthorizedTenants as a safety net. At repository.MaxPageLimit
// (200) per page this allows up to ~1,000,000 tenant bindings per
// MSP — well above the documented platform target (<10k tenants per
// MSP) and large enough to avoid spurious failures on legitimate
// growth, while still guaranteeing the call cannot spin indefinitely
// if the repository ever returns a non-empty cursor that never
// advances (e.g. a misconfigured cursor-comparison predicate). When
// the cap is reached we return an explicit error rather than
// silently truncating the authorized set, because under-authorization
// is a security-sensitive bug.
//
// Round-20 of Devin Review on PR #42 (BUG_0001) caught that the
// prior `Limit: 1000` paired with a 1000-page cap claimed to
// support ~1M bindings — but both the memory and postgres backends
// silently clamp Limit via `Page.Normalize()` to
// repository.MaxPageLimit (200), so the real ceiling was only
// 200K. Worse, the same call did 5× the round-trips it claimed
// because each effective page returned 200 rows, not 1000. The
// fix here is two-fold: (1) the inner ListTenants call now passes
// repository.MaxPageLimit explicitly so the "rows per page"
// number is honest, and (2) this cap is raised to 5000 to keep
// the documented ~1M ceiling. The product of the two constants
// remains the supported binding count; making the per-page
// number match the backend clamp eliminates the silent half of
// the bug.
const ListAuthorizedTenantsMaxPages = 5000

// ErrTooManyMSPBindings is returned by ListAuthorizedTenants when
// the binding pagination loop exceeds ListAuthorizedTenantsMaxPages.
// Callers should treat this as a 500-class server error — the MSP
// has grown beyond the supported size and operator action is
// required (rather than silently returning a truncated authorized
// set, which would be a privilege-confused result).
var ErrTooManyMSPBindings = errors.New("rbac: msp tenant bindings exceed pagination cap; bulk authorization aborted")

// ListAuthorizedTenants returns every tenant under `mspID` that the
// user is authorized to act on for `permission`. Composition rule:
//
//   - If the user holds any platform-scoped grant whose permission
//     set contains `permission` (literal or `"*"` wildcard), they
//     see every tenant the MSP owns or co-manages.
//   - If the user holds an msp-scoped grant matching `mspID` whose
//     permission set contains `permission` (literal or wildcard),
//     they see every tenant the MSP owns or co-manages.
//   - Otherwise the set is restricted to tenants where the user
//     additionally holds a tenant-scoped grant matching that
//     tenant.
//
// Passing `permission == ""` rejects with ErrInvalidArgument; the
// caller is responsible for naming the bulk-op permission so the
// broad-authority short-circuit is correctly gated. Round-6 of
// Devin Review caught the previous signature (no permission arg)
// silently misbehaving for platform roles with a specific
// permission rather than wildcard — such roles fell through the
// broad branch, hit the per-tenant scan with no tenant-scoped
// grants, and returned an empty authorized set. Threading the
// permission through fixes that and also tightens the MSP-scope
// branch (previously broad for ANY msp-scope role, even ones that
// did not grant the requested permission).
//
// This is the data side of the MSP bulk-operations surface
// (Task 24): callers fan out across the returned slice rather
// than iterating msp.AssignedTenants() with no authorization
// check.
func (svc *Service) ListAuthorizedTenants(
	ctx context.Context,
	userID, mspID uuid.UUID,
	permission string,
	msps repository.MSPRepository,
) ([]uuid.UUID, error) {
	if userID == uuid.Nil || mspID == uuid.Nil || permission == "" {
		return nil, fmt.Errorf("list authorized tenants: %w", repository.ErrInvalidArgument)
	}
	// Pull every binding for the MSP. ListTenants returns paginated
	// rows; for the platform's expected MSP sizes (<10k tenants)
	// the loop terminates in 10 iterations, but we cap at
	// ListAuthorizedTenantsMaxPages as a defensive guard against
	// pathological repository behaviour (e.g. a misconfigured
	// cursor predicate that never advances).
	var bound []uuid.UUID
	var cursor string
	for i := 0; i < ListAuthorizedTenantsMaxPages; i++ {
		// Limit is repository.MaxPageLimit so the "rows per
		// page" actually matches the backend behaviour rather
		// than being silently clamped by Page.Normalize(). See
		// the round-20 BUG_0001 note on
		// ListAuthorizedTenantsMaxPages above for the full story.
		page, err := msps.ListTenants(ctx, mspID, repository.Page{
			Limit: repository.MaxPageLimit,
			After: cursor,
		})
		if err != nil {
			return nil, fmt.Errorf("list authorized tenants: msp binding: %w", err)
		}
		for _, b := range page.Items {
			bound = append(bound, b.TenantID)
		}
		if page.NextCursor == "" {
			// Decide the broad authorization (platform or msp scope).
			broad, err := svc.userHasBroadAuthority(ctx, userID, mspID, permission)
			if err != nil {
				return nil, err
			}
			if broad {
				return bound, nil
			}
			return svc.restrictToTenantGrants(ctx, userID, permission, bound)
		}
		cursor = page.NextCursor
	}
	return nil, fmt.Errorf("list authorized tenants: %w", ErrTooManyMSPBindings)
}

// restrictToTenantGrants resolves the per-tenant grant subset for
// a user without broad authority. Split out from
// ListAuthorizedTenants to keep the pagination loop
// readable now that the cap-bound for-loop forces early return on
// the final page.
//
// `permission` is the bulk-op permission the caller is asking
// for. We filter tenant-scoped roles to those that ACTUALLY grant
// that permission (literal or wildcard). Without this gate, a user
// with a tenant-scope `viewer` role (read-only) would be
// authorized to participate in a bulk write (e.g.
// `msp.bulk_apply_policy`) on that tenant — because the previous
// implementation only checked role.Scope==tenant + scope_id match,
// not the role's permission set. The handler path is currently
// protected by `RequireMSPScope` middleware which gates the same
// permission, so this was unreachable end-to-end via the HTTP
// surface. But `BulkService` is a public Go API: an internal
// caller (e.g. a future event-driven bulk pipeline) could invoke
// it directly, bypassing the middleware. Round-7 of Devin Review
// flagged this as a latent privilege-confusion surface; the fix
// closes it as defense-in-depth so the tenant-grant subset is
// always correctly gated regardless of how the bulk service is
// reached.
func (svc *Service) restrictToTenantGrants(
	ctx context.Context,
	userID uuid.UUID,
	permission string,
	bound []uuid.UUID,
) ([]uuid.UUID, error) {
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
		// Permission gate: the tenant-scope role must actually grant
		// the requested permission (literal or wildcard). A viewer
		// role with only `tenants.read` must not satisfy a bulk-write
		// authorization for that tenant.
		if !rolePermits(role, permission) {
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

// userHasBroadAuthority reports whether the user holds a
// platform-scoped or msp-scoped grant that BOTH (a) matches the
// scope target and (b) grants `permission` (literal or wildcard).
// When true, ListAuthorizedTenants short-circuits the per-tenant
// grant scan and returns every bound tenant.
//
// Round-6 of Devin Review: the previous implementation accepted
// any platform-scoped role iff it carried the wildcard
// permission, and accepted any msp-scoped role for the matching
// mspID regardless of permission. Both cases were inconsistent:
//
//   - A platform role with a specific permission (e.g.
//     `msp.bulk_apply_policy` but no `*`) silently produced an
//     empty authorized set rather than broadening — the
//     opposite of the operator's expectation.
//   - An msp-scoped role with a specific permission (e.g.
//     `tenants.read` only) broadened bulk-op authorization to
//     all tenants under the MSP without actually granting the
//     bulk-op permission, which the caller already required at
//     the middleware boundary.
//
// The fix is to gate BOTH branches on rolePermits(role,
// permission); the middleware contract (the caller has the
// bulk-op permission at MSP scope) plus this composition rule
// produces the consistent answer: every grant that names the
// bulk-op permission at platform or MSP scope broadens, every
// other grant restricts to tenant-scope subsets.
func (svc *Service) userHasBroadAuthority(
	ctx context.Context,
	userID, mspID uuid.UUID,
	permission string,
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
		if !rolePermits(role, permission) {
			continue
		}
		switch role.Scope {
		case repository.RoleScopePlatform:
			return true, nil
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

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
	// Fetch the user's grants and resolve every unique role ONCE
	// up front, then pass the resolved (grant, role) tuples to both
	// the broad-authority short-circuit and the tenant-restriction
	// path. The previous shape called GetUserRoles twice (once
	// inside userHasBroadAuthority, once inside
	// restrictToTenantGrants) and re-resolved each grant's role
	// independently on each call — N+1 across both the duplicate
	// GetUserRoles AND the per-call Role Get loop. Round-23 of
	// Devin Review on PR #42 (ANALYSIS_0005) flagged the duplicate
	// GetUserRoles; resolving roles once also closes the N+1 the
	// reviewer noted would compound with it.
	resolvedGrants, err := svc.resolveUserGrantsWithRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list authorized tenants: %w", err)
	}
	// Decide broad authority and (for the non-broad case) the
	// authorized tenant-grant set BEFORE pulling any binding
	// pages. Round-25 of Devin Review on PR #42 (ANALYSIS_0003)
	// flagged the previous shape: we eagerly accumulated every
	// msp_tenants binding (up to ~1M via the page cap) into a
	// flat slice and only decided authorization at the end. For
	// non-broad operators with a small tenant-grant set on a
	// large MSP that allocated O(total bindings) instead of
	// O(authorized), and for the no-authority-at-all case it
	// scanned every page just to return nil. The new shape:
	//
	//  1. If the user holds broad authority (platform-scope or
	//     msp-scope matching mspID with `permission`), every
	//     binding is authorized — we still page through them
	//     all because the contract returns the full set, but
	//     skip the per-row hash lookup.
	//  2. If not broad, we precompute the authorized tenant
	//     set from the resolved tenant-scope grants. If that
	//     set is empty, the answer is unambiguously empty and
	//     we short-circuit without fetching a single page.
	//  3. Otherwise we filter each page inline against the set
	//     and only retain matches, bounding the in-memory
	//     `bound` slice to authorized tenants regardless of
	//     MSP size.
	broad := hasBroadAuthorityIn(resolvedGrants, mspID, permission)
	var tenantGrantSet map[uuid.UUID]struct{}
	if !broad {
		tenantGrantSet = authorizedTenantSet(resolvedGrants, permission)
		if len(tenantGrantSet) == 0 {
			// No broad authority AND no tenant-scope grants —
			// the answer is empty without consulting the
			// MSP binding table at all. Saves up to ~5000
			// ListTenants round-trips on a pathologically
			// large MSP.
			return nil, nil
		}
	}
	// Pull bindings for the MSP. ListTenants returns paginated
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
			if broad {
				bound = append(bound, b.TenantID)
				continue
			}
			if _, ok := tenantGrantSet[b.TenantID]; ok {
				bound = append(bound, b.TenantID)
			}
		}
		if page.NextCursor == "" {
			return bound, nil
		}
		cursor = page.NextCursor
	}
	return nil, fmt.Errorf("list authorized tenants: %w", ErrTooManyMSPBindings)
}

// resolvedGrant pairs a UserRole assignment with the Role it
// resolves to. resolveUserGrantsWithRoles fetches user grants and
// every unique role exactly once so the downstream composition
// decisions iterate without further storage round-trips.
type resolvedGrant struct {
	grant repository.UserRole
	role  repository.Role
}

// resolveUserGrantsWithRoles loads every grant for `userID` plus the
// distinct Role rows those grants reference, returning the joined
// tuples. Stale grants (role row was deleted out from under the
// assignment) are silently dropped — they cannot grant anything.
// Round-23 of Devin Review on PR #42 (ANALYSIS_0005).
func (svc *Service) resolveUserGrantsWithRoles(
	ctx context.Context,
	userID uuid.UUID,
) ([]resolvedGrant, error) {
	grants, err := svc.roles.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get user roles: %w", err)
	}
	roleCache := make(map[uuid.UUID]repository.Role, len(grants))
	out := make([]resolvedGrant, 0, len(grants))
	for _, g := range grants {
		role, ok := roleCache[g.RoleID]
		if !ok {
			fetched, err := svc.roles.Get(ctx, g.RoleID)
			if err != nil {
				if errors.Is(err, repository.ErrNotFound) {
					// Stale grant — skip, matches the previous
					// per-helper continue-on-NotFound behaviour.
					continue
				}
				return nil, fmt.Errorf("get role %s: %w", g.RoleID, err)
			}
			role = fetched
			roleCache[g.RoleID] = role
		}
		out = append(out, resolvedGrant{grant: g, role: role})
	}
	return out, nil
}

// hasBroadAuthorityIn is the pure-function form of
// userHasBroadAuthority that operates on pre-resolved (grant, role)
// tuples. Returns true when ANY grant satisfies the broad-authority
// gate (platform-scope wildcard/named perm, or msp-scope grant
// matching mspID with the named perm). Round-23 of Devin Review on
// PR #42 (ANALYSIS_0005).
func hasBroadAuthorityIn(grants []resolvedGrant, mspID uuid.UUID, permission string) bool {
	for _, rg := range grants {
		if !rolePermits(rg.role, permission) {
			continue
		}
		switch rg.role.Scope {
		case repository.RoleScopePlatform:
			return true
		case repository.RoleScopeMSP:
			if rg.grant.ScopeID != nil && *rg.grant.ScopeID == mspID {
				return true
			}
		}
	}
	return false
}

// authorizedTenantSet returns the set of tenant IDs the user holds
// a tenant-scoped grant for, gated by the named permission. The
// returned map is suitable for O(1) lookup while streaming MSP
// bindings through ListAuthorizedTenants. Round-25 of Devin Review
// on PR #42 (ANALYSIS_0003) hoisted this computation out of the
// post-loop restrictToTenantGrantsIn so we can decide broad
// authority + the authorized set BEFORE fetching binding pages,
// short-circuit when both are empty, and stream-filter pages when
// the set is small but the MSP is large.
func authorizedTenantSet(grants []resolvedGrant, permission string) map[uuid.UUID]struct{} {
	tenantGrants := make(map[uuid.UUID]struct{}, len(grants))
	for _, rg := range grants {
		if rg.role.Scope != repository.RoleScopeTenant {
			continue
		}
		if !rolePermits(rg.role, permission) {
			continue
		}
		switch {
		case rg.grant.ScopeID != nil:
			tenantGrants[*rg.grant.ScopeID] = struct{}{}
		case rg.role.TenantID != nil:
			tenantGrants[*rg.role.TenantID] = struct{}{}
		}
	}
	return tenantGrants
}

// restrictToTenantGrantsIn is the pure-function form of
// restrictToTenantGrants. Returns the subset of `bound` tenants that
// the user holds a tenant-scoped grant for, gated by the named
// permission. Retained for any caller that still post-filters a
// fully accumulated slice; ListAuthorizedTenants now stream-filters
// inside the page loop instead. Round-23 of Devin Review on PR #42
// (ANALYSIS_0005); the inner set computation is shared with
// authorizedTenantSet from round-25.
func restrictToTenantGrantsIn(grants []resolvedGrant, permission string, bound []uuid.UUID) []uuid.UUID {
	tenantGrants := authorizedTenantSet(grants, permission)
	out := make([]uuid.UUID, 0, len(bound))
	for _, tid := range bound {
		if _, ok := tenantGrants[tid]; ok {
			out = append(out, tid)
		}
	}
	return out
}

// Composition rules for the tenant-scope subset and the
// broad-authority short-circuit are implemented as pure functions
// (restrictToTenantGrantsIn, hasBroadAuthorityIn) operating on the
// pre-resolved (grant, role) tuples returned by
// resolveUserGrantsWithRoles. Splitting along that boundary keeps
// each composition rule a one-pass scan and avoids the duplicate
// GetUserRoles/Role-Get pattern flagged by round-23 ANALYSIS_0005.
//
// Round-6 of Devin Review motivated the original split into
// userHasBroadAuthority / restrictToTenantGrants: a platform role
// with a specific permission (e.g. `msp.bulk_apply_policy` but no
// `*`) used to silently produce an empty authorized set rather
// than broadening, and an msp-scoped role with a specific
// permission like `tenants.read` would broaden bulk-op
// authorization to all tenants under the MSP without actually
// granting the bulk-op permission. Both branches now gate on
// rolePermits(role, permission) — see hasBroadAuthorityIn.
//
// Round-7 of Devin Review motivated the permission gate on the
// tenant-restriction path: a tenant-scope `viewer` role
// (read-only) would otherwise satisfy a bulk-write authorization
// for that tenant via Scope==tenant + scope_id match alone. The
// handler path is gated by `RequireMSPScope` middleware, so the
// HTTP surface was safe, but `BulkService` is a public Go API:
// internal callers (e.g. a future event-driven bulk pipeline)
// could invoke it directly. The permission gate in
// restrictToTenantGrantsIn closes this as defence-in-depth.

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

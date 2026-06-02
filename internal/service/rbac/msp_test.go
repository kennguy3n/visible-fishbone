package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rbac"
)

// mspRBACFixtures wires a Store + svc + repos + a fresh user
// without any pre-seeded roles. Tests opt in to whichever grant
// they need so each is read in isolation.
func mspRBACFixtures(t *testing.T) (
	*rbac.Service,
	*memory.Store,
	*memory.MSPRepository,
	*memory.RoleRepository,
	uuid.UUID, // userID
	uuid.UUID, // mspID
) {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	userRepo := memory.NewUserRepository(store)
	roleRepo := memory.NewRoleRepository(store)
	mspRepo := memory.NewMSPRepository(store)
	svc := rbac.New(roleRepo, memory.NewAuditLogRepository(store), nil)

	tn, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	user, err := userRepo.Create(context.Background(), tn.ID, repository.User{
		Email: "u@example.com", Status: repository.UserStatusActive,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	msp, err := mspRepo.Create(context.Background(), repository.MSP{Name: "Acme", Slug: "acme"})
	if err != nil {
		t.Fatalf("seed msp: %v", err)
	}
	return svc, store, mspRepo, roleRepo, user.ID, msp.ID
}

func mustSeedRole(t *testing.T, repo *memory.RoleRepository, r repository.Role) repository.Role {
	t.Helper()
	out, err := repo.Create(context.Background(), r)
	if err != nil {
		t.Fatalf("create role %s: %v", r.Name, err)
	}
	return out
}

func TestAuthorizeMSP_DeniesWithoutGrant(t *testing.T) {
	svc, _, _, _, userID, mspID := mspRBACFixtures(t)
	ok, err := svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsRead)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if ok {
		t.Fatal("expected deny without grant")
	}
}

func TestAuthorizeMSP_AllowsMSPScopedGrant(t *testing.T) {
	svc, _, _, roleRepo, userID, mspID := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "msp_ops",
		Scope:       repository.RoleScopeMSP,
		Permissions: []string{rbac.PermTenantsRead, rbac.PermSitesRead},
	})
	scope := mspID
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	ok, err := svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsRead)
	if err != nil || !ok {
		t.Fatalf("expected allow, got ok=%v err=%v", ok, err)
	}
	// Permission outside the role set → deny.
	ok, _ = svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsDelete)
	if ok {
		t.Fatal("expected deny for un-granted permission")
	}
}

func TestAuthorizeMSP_RejectsMSPGrantForDifferentMSP(t *testing.T) {
	svc, _, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	otherMSP, err := mspRepo.Create(context.Background(), repository.MSP{Name: "Other", Slug: "other"})
	if err != nil {
		t.Fatalf("create other msp: %v", err)
	}
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "msp_ops",
		Scope:       repository.RoleScopeMSP,
		Permissions: []string{rbac.PermTenantsRead},
	})
	scope := otherMSP.ID
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, err := svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsRead)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if ok {
		t.Fatal("expected deny for cross-MSP grant")
	}
}

func TestAuthorizeMSP_PlatformWildcardAllowsAnyMSP(t *testing.T) {
	svc, _, _, roleRepo, userID, mspID := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "platform_admin",
		Scope:       repository.RoleScopePlatform,
		Permissions: []string{rbac.PermWildcard},
	})
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, err := svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsDelete)
	if err != nil || !ok {
		t.Fatalf("expected platform wildcard allow, got ok=%v err=%v", ok, err)
	}
}

func TestAuthorizeMSP_RejectsTenantScopedGrant(t *testing.T) {
	// Tenant-scoped grants are NOT considered by AuthorizeMSP —
	// per-tenant authz is the existing HasPermission path. This
	// pins the composition rule documented in AuthorizeMSP's
	// doc comment.
	svc, _, _, roleRepo, userID, mspID := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "tenant_admin",
		Scope:       repository.RoleScopeTenant,
		Permissions: []string{rbac.PermWildcard},
	})
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, _ := svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsRead)
	if ok {
		t.Fatal("tenant-scoped grants must not satisfy MSP authz")
	}
}

func TestAuthorizeMSP_RejectsInvalidInputs(t *testing.T) {
	svc, _, _, _, userID, mspID := mspRBACFixtures(t)
	if _, err := svc.AuthorizeMSP(context.Background(), uuid.Nil, mspID, rbac.PermTenantsRead); err == nil {
		t.Fatal("nil user should error")
	}
	if _, err := svc.AuthorizeMSP(context.Background(), userID, uuid.Nil, rbac.PermTenantsRead); err == nil {
		t.Fatal("nil msp should error")
	}
	if _, err := svc.AuthorizeMSP(context.Background(), userID, mspID, ""); err == nil {
		t.Fatal("empty permission should error")
	}
}

func TestListAuthorizedTenants_BroadAuthorityReturnsEveryBoundTenant(t *testing.T) {
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	// Seed two tenants under the MSP.
	t1, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	t2, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t2", Slug: "t2"})
	if _, err := mspRepo.AssignTenant(ctx, mspID, t1.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign t1: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, mspID, t2.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign t2: %v", err)
	}

	// Grant the user msp-scope, then assert ListAuthorizedTenants
	// returns BOTH bound tenants.
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "msp_admin",
		Scope:       repository.RoleScopeMSP,
		Permissions: []string{rbac.PermTenantsRead},
	})
	scope := mspID
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, rbac.PermTenantsRead, mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d (%#v)", len(tenants), tenants)
	}
}

func TestListAuthorizedTenants_NoBroadAuthRestrictsToTenantGrants(t *testing.T) {
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	t1, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	t2, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t2", Slug: "t2"})
	if _, err := mspRepo.AssignTenant(ctx, mspID, t1.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign t1: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, mspID, t2.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign t2: %v", err)
	}

	// Tenant-scoped grant for t1 only.
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "tenant_admin",
		Scope:       repository.RoleScopeTenant,
		Permissions: []string{rbac.PermTenantsRead},
		TenantID:    &t1.ID,
	})
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, rbac.PermTenantsRead, mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tenants) != 1 || tenants[0] != t1.ID {
		t.Fatalf("expected only t1, got %#v", tenants)
	}
}

func TestGrantMSPRole_RejectsNonMSPScope(t *testing.T) {
	svc, _, _, roleRepo, userID, mspID := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "tenant_admin",
		Scope:       repository.RoleScopeTenant,
		Permissions: []string{rbac.PermWildcard},
	})
	err := svc.GrantMSPRole(context.Background(), mspID, userID, role.ID, nil)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestGrantMSPRole_StampsScopeAndAuthorizes(t *testing.T) {
	svc, _, _, roleRepo, userID, mspID := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "msp_ops",
		Scope:       repository.RoleScopeMSP,
		Permissions: []string{rbac.PermTenantsRead},
	})
	if err := svc.GrantMSPRole(context.Background(), mspID, userID, role.ID, nil); err != nil {
		t.Fatalf("grant: %v", err)
	}
	ok, err := svc.AuthorizeMSP(context.Background(), userID, mspID, rbac.PermTenantsRead)
	if err != nil || !ok {
		t.Fatalf("expected allow after grant, got ok=%v err=%v", ok, err)
	}
}

// TestAuthorizePlatform_DeniesWithoutGrant exercises the deny path
// of the round-2 fix on PR #42. With no platform-scoped grant, the
// caller must be rejected. This is the security floor — an MSP
// list/create attempt with no grant must never pass.
func TestAuthorizePlatform_DeniesWithoutGrant(t *testing.T) {
	svc, _, _, _, userID, _ := mspRBACFixtures(t)
	ok, err := svc.AuthorizePlatform(context.Background(), userID, "msp.read")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if ok {
		t.Fatal("expected deny without grant")
	}
}

// TestAuthorizePlatform_AllowsPlatformScopedGrant covers the happy
// path: a platform-scoped grant carrying the literal permission
// allows the caller.
func TestAuthorizePlatform_AllowsPlatformScopedGrant(t *testing.T) {
	svc, _, _, roleRepo, userID, _ := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name: "platform_msp_admin", Scope: repository.RoleScopePlatform,
		Permissions: []string{"msp.read", "msp.write"},
	})
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, err := svc.AuthorizePlatform(context.Background(), userID, "msp.read")
	if err != nil || !ok {
		t.Fatalf("expected allow with platform-scoped grant, got ok=%v err=%v", ok, err)
	}
}

// TestAuthorizePlatform_PlatformWildcardAllows verifies the `*`
// wildcard short-circuit so a platform_admin (`Permissions: ["*"]`)
// can manage MSPs without needing an explicit msp.read enumeration.
func TestAuthorizePlatform_PlatformWildcardAllows(t *testing.T) {
	svc, _, _, roleRepo, userID, _ := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name: "platform_admin", Scope: repository.RoleScopePlatform,
		Permissions: []string{rbac.PermWildcard},
	})
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, err := svc.AuthorizePlatform(context.Background(), userID, "msp.write")
	if err != nil || !ok {
		t.Fatalf("expected allow with platform wildcard, got ok=%v err=%v", ok, err)
	}
}

// TestAuthorizePlatform_RejectsMSPScopedGrant is the security
// invariant that motivated the round-2 fix: an msp_admin grant on
// ONE MSP must not satisfy a platform-scope check, otherwise that
// operator could enumerate or create OTHER MSPs.
func TestAuthorizePlatform_RejectsMSPScopedGrant(t *testing.T) {
	svc, _, _, roleRepo, userID, mspID := mspRBACFixtures(t)
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name: "msp_admin", Scope: repository.RoleScopeMSP,
		Permissions: []string{rbac.PermWildcard, "msp.read", "msp.write"},
	})
	scope := mspID
	if err := roleRepo.AssignRole(context.Background(), repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, err := svc.AuthorizePlatform(context.Background(), userID, "msp.read")
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	if ok {
		t.Fatal("MSP-scoped grant must NOT satisfy platform authz — privilege escalation surface")
	}
}

// TestAuthorizePlatform_RejectsInvalidInputs pins the input
// validation: nil user UUID or empty permission strings must error
// rather than silently denying (the latter would mask programmer
// bugs at call sites).
func TestAuthorizePlatform_RejectsInvalidInputs(t *testing.T) {
	svc, _, _, _, userID, _ := mspRBACFixtures(t)
	if _, err := svc.AuthorizePlatform(context.Background(), uuid.Nil, "msp.read"); err == nil {
		t.Fatal("nil user should error")
	}
	if _, err := svc.AuthorizePlatform(context.Background(), userID, ""); err == nil {
		t.Fatal("empty permission should error")
	}
	if !errors.Is(err1(svc.AuthorizePlatform(context.Background(), uuid.Nil, "msp.read")),
		repository.ErrInvalidArgument) {
		t.Fatal("invalid input error must wrap repository.ErrInvalidArgument")
	}
}

// err1 returns the error out of a (bool, error) tuple. Helper used
// only by the invalid-input test above.
func err1(_ bool, err error) error { return err }

// TestListAuthorizedTenants_PlatformSpecificPermissionBroadensSet
// pins the round-6 fix: a platform-scoped role with a SPECIFIC
// (non-wildcard) permission MUST now broaden ListAuthorizedTenants
// to all bound tenants. Previously the implementation required
// `*` on platform-scoped roles, silently returning empty for
// operators whose grant was narrower-but-still-applicable. The
// fix threads the permission through to userHasBroadAuthority,
// which now gates BOTH scopes (platform + msp) on rolePermits.
func TestListAuthorizedTenants_PlatformSpecificPermissionBroadensSet(t *testing.T) {
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	t1, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t1", Slug: "p-t1"})
	t2, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t2", Slug: "p-t2"})
	if _, err := mspRepo.AssignTenant(ctx, mspID, t1.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign t1: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, mspID, t2.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign t2: %v", err)
	}

	// Platform-scope role with the specific bulk-apply permission
	// (NOT wildcard).
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "platform_bulk_apply",
		Scope:       repository.RoleScopePlatform,
		Permissions: []string{"msp.bulk_apply_policy"},
	})
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, "msp.bulk_apply_policy", mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("expected 2 tenants from platform-specific-permission broadening, got %d (%#v)",
			len(tenants), tenants)
	}

	// Negative-case: ASKING for a different permission must NOT
	// broaden (the role does not grant `policy.write`).
	tenants, err = svc.ListAuthorizedTenants(ctx, userID, mspID, "policy.write", mspRepo)
	if err != nil {
		t.Fatalf("list narrow: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected empty when asking for permission the role lacks, got %d (%#v)",
			len(tenants), tenants)
	}
}

// TestListAuthorizedTenants_MSPScopeWithoutPermissionDoesNotBroaden
// pins the round-6 tightening on the msp-scope branch. Previously
// ANY msp-scope role granted broad authority; the fix requires
// the role to actually permit the requested permission.
func TestListAuthorizedTenants_MSPScopeWithoutPermissionDoesNotBroaden(t *testing.T) {
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	t1, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t1", Slug: "m-t1"})
	t2, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t2", Slug: "m-t2"})
	if _, err := mspRepo.AssignTenant(ctx, mspID, t1.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign t1: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, mspID, t2.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign t2: %v", err)
	}

	// MSP-scope role with ONLY tenants.read — not the bulk-op
	// permission.
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "msp_reader",
		Scope:       repository.RoleScopeMSP,
		Permissions: []string{rbac.PermTenantsRead},
	})
	scope := mspID
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	// Asking for a different permission: must NOT broaden, and
	// without any tenant-scoped grants, the result is empty.
	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, "msp.bulk_apply_policy", mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("msp-scope reader role must NOT broaden bulk_apply set, got %d (%#v)",
			len(tenants), tenants)
	}

	// Asking for the permission the role DOES grant: broadens.
	tenants, err = svc.ListAuthorizedTenants(ctx, userID, mspID, rbac.PermTenantsRead, mspRepo)
	if err != nil {
		t.Fatalf("list matching perm: %v", err)
	}
	if len(tenants) != 2 {
		t.Fatalf("msp-scope role with matching perm must broaden, got %d (%#v)",
			len(tenants), tenants)
	}
}

// TestListAuthorizedTenants_RejectsEmptyPermission pins the
// programmer-error guard: passing permission="" rejects with
// ErrInvalidArgument so callers cannot accidentally skip the
// authorization gate.
func TestListAuthorizedTenants_RejectsEmptyPermission(t *testing.T) {
	svc, _, mspRepo, _, userID, mspID := mspRBACFixtures(t)
	_, err := svc.ListAuthorizedTenants(context.Background(), userID, mspID, "", mspRepo)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty permission, got %v", err)
	}
}

// TestListAuthorizedTenants_TenantScopeWithoutPermissionExcluded pins
// the round-7 defense-in-depth fix: a tenant-scoped role that does
// NOT grant the requested permission must NOT contribute that tenant
// to the authorized set, even when the user has no broad authority.
//
// Scenario:
//   - User has tenant-scope role on t1 with ONLY `tenants.read`
//   - Caller asks for `msp.bulk_apply_policy` authorization
//   - Previous behaviour: t1 would be included in the authorized set
//     because the function only checked scope+scope_id match, not
//     the permission set. A latent privilege-confusion if any
//     internal caller invoked BulkService bypassing the
//     RequireMSPScope middleware.
//   - Fixed behaviour: t1 is excluded — tenant-scope roles must
//     actually grant the requested permission to satisfy the
//     authorization.
func TestListAuthorizedTenants_TenantScopeWithoutPermissionExcluded(t *testing.T) {
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	t1, _ := tenantRepo.Create(ctx, repository.Tenant{Name: "t1", Slug: "t1"})
	if _, err := mspRepo.AssignTenant(ctx, mspID, t1.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign t1: %v", err)
	}
	// Tenant-scoped role that grants ONLY tenants.read (not the
	// bulk_apply_policy permission the caller is asking for).
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "tenant_viewer",
		Scope:       repository.RoleScopeTenant,
		Permissions: []string{rbac.PermTenantsRead},
		TenantID:    &t1.ID,
	})
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// Ask for the bulk_apply_policy permission: tenant-viewer must
	// not be sufficient.
	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, "msp.bulk_apply_policy", mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected empty (tenant viewer must not satisfy bulk-write), got %d tenants %#v",
			len(tenants), tenants)
	}

	// Sanity check the positive path: a tenant-scoped role granting
	// the bulk_apply_policy permission DOES restrict-to that tenant.
	roleWrite := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "tenant_bulk_writer",
		Scope:       repository.RoleScopeTenant,
		Permissions: []string{"msp.bulk_apply_policy"},
		TenantID:    &t1.ID,
	})
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: roleWrite.ID,
	}); err != nil {
		t.Fatalf("assign write: %v", err)
	}
	tenants, err = svc.ListAuthorizedTenants(ctx, userID, mspID, "msp.bulk_apply_policy", mspRepo)
	if err != nil {
		t.Fatalf("list (with write role): %v", err)
	}
	if len(tenants) != 1 || tenants[0] != t1.ID {
		t.Fatalf("expected just t1 after adding write role, got %#v", tenants)
	}
}

// TestListAuthorizedTenants_PaginatesAcrossPageLimitClamp pins
// round-20 of Devin Review on PR #42 (BUG_0001). The prior code
// asked for `Limit: 1000` per page, but both backends silently
// clamp page sizes to `repository.MaxPageLimit` (200) via
// `Page.Normalize()`. The result: a documented "supports ~1M
// bindings" surface that actually capped at 200K because the
// outer loop counter (ListAuthorizedTenantsMaxPages=1000) was
// multiplied by 200, not 1000.
//
// The fix passes `repository.MaxPageLimit` explicitly and raises
// the outer cap to 5000 so the product (and therefore the
// documented binding ceiling) is restored to ~1M. This test
// pins the behaviour that matters for callers: a binding set
// larger than `MaxPageLimit` MUST be returned in full when the
// user has broad authority, and the cursor loop MUST advance
// across page boundaries rather than silently truncating at the
// first page.
//
// We seed `MaxPageLimit + 50` tenants (250) and assert every one
// is returned. Pre-fix, the inner page would still return 200
// rows (the backend clamps regardless of caller intent), so this
// would have passed by accident — but the precise pin is on the
// `Limit` value the service passes to the repo, which is now
// `repository.MaxPageLimit` rather than `1000`. We re-derive that
// assertion from the binding count: 250 rows demand TWO page
// reads, which requires NextCursor to advance after the first
// 200-row page. If a future refactor reintroduced a clamped
// `Limit > MaxPageLimit` value it would still pass the rows-back
// check (backend would still clamp), so the secondary assertion
// is that the per-page count never exceeds MaxPageLimit by
// inspecting the public constant directly. The full chain is
// belt-and-suspenders against future regressions.
func TestListAuthorizedTenants_PaginatesAcrossPageLimitClamp(t *testing.T) {
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	// Seed MaxPageLimit + 50 tenants under the MSP. Use co-manager
	// to avoid the partial-unique-owner index constraints and so
	// every tenant counts under the MSP binding scan.
	total := repository.MaxPageLimit + 50
	want := make(map[uuid.UUID]struct{}, total)
	for i := 0; i < total; i++ {
		tn, err := tenantRepo.Create(ctx, repository.Tenant{
			Name: fmt.Sprintf("t-%d", i),
			Slug: fmt.Sprintf("p20-t-%03d", i),
		})
		if err != nil {
			t.Fatalf("seed tenant %d: %v", i, err)
		}
		if _, err := mspRepo.AssignTenant(ctx, mspID, tn.ID, repository.MSPRelationshipCoManager, nil); err != nil {
			t.Fatalf("assign tenant %d: %v", i, err)
		}
		want[tn.ID] = struct{}{}
	}

	// Grant the user msp-scope so they hit the broad-authority
	// branch (no per-tenant scan; just the bulk MSP binding read).
	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "msp_bulk_writer",
		Scope:       repository.RoleScopeMSP,
		Permissions: []string{rbac.PermTenantsRead},
	})
	scope := mspID
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	got, err := svc.ListAuthorizedTenants(ctx, userID, mspID, rbac.PermTenantsRead, mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != total {
		t.Fatalf("expected all %d tenants returned by cursor pagination, got %d", total, len(got))
	}
	for _, id := range got {
		if _, ok := want[id]; !ok {
			t.Fatalf("unexpected tenant in result: %s", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("missing %d tenants from pagination loop — silent truncation regression?", len(want))
	}
}

// callCountingRoleRepo wraps a RoleRepository and counts
// GetUserRoles + Get(role) invocations. Used by
// TestListAuthorizedTenants_ResolvesUserRolesOnce to pin the
// round-23 ANALYSIS_0005 fix that consolidated the two duplicated
// GetUserRoles call sites (one in userHasBroadAuthority, one in
// restrictToTenantGrants) into a single up-front fetch in
// ListAuthorizedTenants.
type callCountingRoleRepo struct {
	repository.RoleRepository
	getUserRolesCalls int
	getRoleCalls      int
}

func (c *callCountingRoleRepo) GetUserRoles(ctx context.Context, userID uuid.UUID) ([]repository.UserRole, error) {
	c.getUserRolesCalls++
	return c.RoleRepository.GetUserRoles(ctx, userID)
}

func (c *callCountingRoleRepo) Get(ctx context.Context, id uuid.UUID) (repository.Role, error) {
	c.getRoleCalls++
	return c.RoleRepository.Get(ctx, id)
}

// TestListAuthorizedTenants_ResolvesUserRolesOnce pins the round-23
// ANALYSIS_0005 fix on PR #42. The old implementation called
// GetUserRoles twice for a non-broad-authority operator — once in
// userHasBroadAuthority, once in restrictToTenantGrants — and
// re-resolved every grant's role independently in each helper. The
// new shape fetches grants once and resolves the distinct role
// rows once before deciding broad vs tenant-restricted
// authorization.
//
// We verify two invariants:
//
//  1. GetUserRoles is invoked exactly ONCE per ListAuthorizedTenants
//     call. Both the broad-authority path (early return) and the
//     tenant-restriction path (no broad authority) must share the
//     single fetch.
//  2. Get(roleID) is invoked at most ONCE per distinct role ID
//     across the whole call. If a user has N grants pointing at the
//     same role, the repository should be hit once, not N times.
//
// Run in two scenarios so both code paths are exercised:
//
//   - Tenant-restriction path (no platform/msp broad grant).
//   - Broad-authority path (msp-scope grant matching mspID).
func TestListAuthorizedTenants_ResolvesUserRolesOnce(t *testing.T) {
	cases := []struct {
		name      string
		broad     bool
		roleScope repository.RoleScope
	}{
		{name: "TenantRestrictionPath", broad: false, roleScope: repository.RoleScopeTenant},
		{name: "BroadAuthorityPath", broad: true, roleScope: repository.RoleScopeMSP},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := memory.NewStore()
			tenantRepo := memory.NewTenantRepository(store)
			userRepo := memory.NewUserRepository(store)
			roleRepo := memory.NewRoleRepository(store)
			mspRepo := memory.NewMSPRepository(store)
			counting := &callCountingRoleRepo{RoleRepository: roleRepo}
			svc := rbac.New(counting, memory.NewAuditLogRepository(store), nil)

			ctx := context.Background()
			tn, err := tenantRepo.Create(ctx, repository.Tenant{Name: "T", Slug: "t-r23"})
			if err != nil {
				t.Fatalf("seed tenant: %v", err)
			}
			user, err := userRepo.Create(ctx, tn.ID, repository.User{
				Email: "u@example.com", Status: repository.UserStatusActive,
			})
			if err != nil {
				t.Fatalf("seed user: %v", err)
			}
			msp, err := mspRepo.Create(ctx, repository.MSP{Name: "A", Slug: "a-r23"})
			if err != nil {
				t.Fatalf("seed msp: %v", err)
			}
			if _, err := mspRepo.AssignTenant(ctx, msp.ID, tn.ID, repository.MSPRelationshipOwner, nil); err != nil {
				t.Fatalf("assign tenant: %v", err)
			}

			// Seed ONE role and assign it to the user TWICE on
			// different scope_ids. This exercises the "distinct
			// role lookup is cached" invariant: with two grants
			// pointing at the same role, the repository should
			// see exactly one Get(role) call.
			role := mustSeedRole(t, roleRepo, repository.Role{
				Name:        "r23_role",
				Scope:       tc.roleScope,
				TenantID:    nil,
				Permissions: []string{rbac.PermTenantsRead},
			})
			scopeTenant := tn.ID
			scopeMSP := msp.ID
			grants := []repository.UserRole{
				{UserID: user.ID, RoleID: role.ID, ScopeID: &scopeTenant},
				{UserID: user.ID, RoleID: role.ID, ScopeID: &scopeMSP},
			}
			for _, g := range grants {
				if err := roleRepo.AssignRole(ctx, g); err != nil {
					t.Fatalf("assign: %v", err)
				}
			}

			// Reset counts after seeding so we measure only the
			// ListAuthorizedTenants call itself.
			counting.getUserRolesCalls = 0
			counting.getRoleCalls = 0

			out, err := svc.ListAuthorizedTenants(ctx, user.ID, msp.ID, rbac.PermTenantsRead, mspRepo)
			if err != nil {
				t.Fatalf("list: %v", err)
			}

			if counting.getUserRolesCalls != 1 {
				t.Fatalf("GetUserRoles called %d times, want exactly 1 (round-23 ANALYSIS_0005 regression)",
					counting.getUserRolesCalls)
			}
			// Two grants both reference the same role row; the
			// resolver must dedupe the lookup. Permits 1; the old
			// shape would do 4 (2 grants × 2 helpers).
			if counting.getRoleCalls > 1 {
				t.Fatalf("Get(role) called %d times for a single distinct role; want <= 1 (round-23 ANALYSIS_0005 role-cache regression)",
					counting.getRoleCalls)
			}

			// Final shape: the broad path returns every bound
			// tenant, the tenant-restriction path returns only
			// tenants the user has tenant-scope grants on.
			switch {
			case tc.broad && len(out) != 1:
				t.Fatalf("broad-authority path: want 1 tenant, got %d", len(out))
			case !tc.broad && len(out) != 1:
				t.Fatalf("tenant-restriction path: want 1 tenant (user has tenant-scope grant on the bound tenant), got %d", len(out))
			}
		})
	}
}

// callCountingMSPRepo wraps an MSPRepository and counts ListTenants
// invocations. Used by TestListAuthorizedTenants_NoAuthorityShortCircuits
// to pin the round-25 ANALYSIS_0003 fix that decides broad authority +
// the authorized tenant-grant set BEFORE consulting the binding table
// — when both are empty, ListTenants must be called zero times.
type callCountingMSPRepo struct {
	repository.MSPRepository
	listTenantsCalls int
}

func (c *callCountingMSPRepo) ListTenants(
	ctx context.Context, mspID uuid.UUID, page repository.Page,
) (repository.PageResult[repository.MSPTenantBinding], error) {
	c.listTenantsCalls++
	return c.MSPRepository.ListTenants(ctx, mspID, page)
}

// TestListAuthorizedTenants_NoAuthorityShortCircuitsBindingFetch pins
// round-25 of Devin Review on PR #42 (ANALYSIS_0003). The previous
// shape fetched ALL msp_tenants bindings (up to ~1M via the page cap)
// even when the user had zero grants for the named permission —
// O(MSP size) DB work to return an empty slice. The new shape decides
// broad authority + the authorized tenant-grant set from the resolved
// (grant, role) tuples BEFORE the page loop; when both are empty, it
// short-circuits without touching ListTenants at all.
//
// We seed a non-trivial MSP (>1 page of bindings) and a user with NO
// role grants of any kind, then assert:
//
//  1. ListAuthorizedTenants returns nil, nil.
//  2. ListTenants was invoked exactly zero times.
//
// Invariant 2 is the key regression gate — if a future refactor
// reintroduces the eager-fetch shape, this test catches it
// immediately (no need to time the call or watch DB load).
func TestListAuthorizedTenants_NoAuthorityShortCircuitsBindingFetch(t *testing.T) {
	t.Parallel()
	svc, store, mspRepo, _, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	// Seed enough tenants to span multiple pages so the test
	// would visibly fail with O(MSP size) round-trips if the
	// short-circuit regressed.
	total := repository.MaxPageLimit + 5
	for i := 0; i < total; i++ {
		tn, err := tenantRepo.Create(ctx, repository.Tenant{
			Name: fmt.Sprintf("t-%d", i),
			Slug: fmt.Sprintf("r25-sc-%03d", i),
		})
		if err != nil {
			t.Fatalf("seed tenant %d: %v", i, err)
		}
		if _, err := mspRepo.AssignTenant(ctx, mspID, tn.ID, repository.MSPRelationshipCoManager, nil); err != nil {
			t.Fatalf("assign tenant %d: %v", i, err)
		}
	}

	counting := &callCountingMSPRepo{MSPRepository: mspRepo}
	got, err := svc.ListAuthorizedTenants(ctx, userID, mspID, rbac.PermTenantsRead, counting)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("user has no grants — expected empty result, got %d tenants", len(got))
	}
	if counting.listTenantsCalls != 0 {
		t.Fatalf("regression: ListTenants invoked %d times for a user with no authority; round-25 short-circuit broken (expected 0)", counting.listTenantsCalls)
	}
}

// TestListAuthorizedTenants_NonBroadStreamFiltersBindings pins the
// round-25 ANALYSIS_0003 stream-filter behaviour for the non-broad
// case. A user with a tenant-scope grant for exactly ONE tenant
// inside an MSP that spans multiple pages of bindings must:
//
//  1. Receive that single tenant back (and no others).
//  2. Hit the pagination loop the same number of times as the
//     broad case (the inner-loop filter is what changed, not the
//     outer page cadence).
func TestListAuthorizedTenants_NonBroadStreamFiltersBindings(t *testing.T) {
	t.Parallel()
	svc, store, mspRepo, roleRepo, userID, mspID := mspRBACFixtures(t)
	tenantRepo := memory.NewTenantRepository(store)
	ctx := context.Background()

	// Seed >1 page so we exercise the cursor loop, not the single-page
	// happy path.
	total := repository.MaxPageLimit + 25
	var targetTenant uuid.UUID
	for i := 0; i < total; i++ {
		tn, err := tenantRepo.Create(ctx, repository.Tenant{
			Name: fmt.Sprintf("t-%d", i),
			Slug: fmt.Sprintf("r25-sf-%03d", i),
		})
		if err != nil {
			t.Fatalf("seed tenant %d: %v", i, err)
		}
		if _, err := mspRepo.AssignTenant(ctx, mspID, tn.ID, repository.MSPRelationshipCoManager, nil); err != nil {
			t.Fatalf("assign tenant %d: %v", i, err)
		}
		// Pick a tenant in the SECOND page so the stream-filter
		// must outlast the first page boundary.
		if i == repository.MaxPageLimit+3 {
			targetTenant = tn.ID
		}
	}
	if targetTenant == uuid.Nil {
		t.Fatalf("test bug: target tenant not selected")
	}

	role := mustSeedRole(t, roleRepo, repository.Role{
		Name:        "tenant_scoped_reader",
		Scope:       repository.RoleScopeTenant,
		TenantID:    &targetTenant,
		Permissions: []string{rbac.PermTenantsRead},
	})
	scope := targetTenant
	if err := roleRepo.AssignRole(ctx, repository.UserRole{
		UserID: userID, RoleID: role.ID, ScopeID: &scope,
	}); err != nil {
		t.Fatalf("assign: %v", err)
	}

	got, err := svc.ListAuthorizedTenants(ctx, userID, mspID, rbac.PermTenantsRead, mspRepo)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 authorized tenant (round-25 stream-filter), got %d", len(got))
	}
	if got[0] != targetTenant {
		t.Fatalf("expected the tenant-scope-granted tenant, got %s want %s", got[0], targetTenant)
	}
}

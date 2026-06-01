package rbac_test

import (
	"context"
	"errors"
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
	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, mspRepo)
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
	tenants, err := svc.ListAuthorizedTenants(ctx, userID, mspID, mspRepo)
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

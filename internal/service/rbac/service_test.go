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

func newSvc(t *testing.T) (*rbac.Service, *memory.Store, uuid.UUID, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	user, err := memory.NewUserRepository(s).Create(context.Background(), tn.ID, repository.User{
		Email: "u@example.com", Status: repository.UserStatusActive,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	svc := rbac.New(memory.NewRoleRepository(s), memory.NewUserRepository(s), memory.NewAuditLogRepository(s))
	return svc, s, tn.ID, user.ID
}

func TestSeedSystemRoles(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, _ := newSvc(t)
	ctx := context.Background()
	roles, err := svc.SeedSystemRoles(ctx, tenantID)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(roles) != len(rbac.SystemRoles) {
		t.Errorf("len = %d, want %d", len(roles), len(rbac.SystemRoles))
	}
	// idempotent
	again, err := svc.SeedSystemRoles(ctx, tenantID)
	if err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("re-seed returned %d, want 0", len(again))
	}
}

func TestAssignAndRevoke(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, userID := newSvc(t)
	ctx := context.Background()
	roles, err := svc.SeedSystemRoles(ctx, tenantID)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	var tenantAdmin repository.Role
	for _, r := range roles {
		if r.Name == "tenant_admin" {
			tenantAdmin = r
			break
		}
	}
	if tenantAdmin.ID == uuid.Nil {
		t.Fatal("tenant_admin not seeded")
	}

	if err := svc.AssignRole(ctx, tenantID, userID, tenantAdmin.ID, nil, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	ok, err := svc.HasPermission(ctx, userID, rbac.PermDevicesRead)
	if err != nil {
		t.Fatalf("hasperm: %v", err)
	}
	if !ok {
		t.Error("expected devices:read")
	}

	if err := svc.RevokeRole(ctx, tenantID, userID, tenantAdmin.ID, nil, nil); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	ok, _ = svc.HasPermission(ctx, userID, rbac.PermDevicesRead)
	if ok {
		t.Error("expected no perm after revoke")
	}
}

func TestWildcardPermission(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, userID := newSvc(t)
	ctx := context.Background()
	roles, _ := svc.SeedSystemRoles(ctx, tenantID)
	var platform repository.Role
	for _, r := range roles {
		if r.Name == "platform_admin" {
			platform = r
			break
		}
	}
	if err := svc.AssignRole(ctx, tenantID, userID, platform.ID, nil, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	for _, p := range []string{rbac.PermTenantsDelete, rbac.PermPolicyCompile, rbac.PermAuditRead, "any:thing"} {
		ok, err := svc.HasPermission(ctx, userID, p)
		if err != nil || !ok {
			t.Errorf("wildcard should grant %s: ok=%v err=%v", p, ok, err)
		}
	}
}

func TestCreateCustomRole(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, _ := newSvc(t)
	ctx := context.Background()
	role, err := svc.CreateCustomRole(ctx, tenantID, nil, "custom-ro",
		repository.RoleScopeTenant, []string{rbac.PermDevicesRead})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if role.Name != "custom-ro" {
		t.Errorf("name = %q", role.Name)
	}

	_, err = svc.CreateCustomRole(ctx, tenantID, nil, "", repository.RoleScopeTenant, nil)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

func TestListRoles(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, _ := newSvc(t)
	ctx := context.Background()
	if _, err := svc.SeedSystemRoles(ctx, tenantID); err != nil {
		t.Fatalf("seed: %v", err)
	}
	roles, err := svc.ListRoles(ctx, tenantID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(roles) < len(rbac.SystemRoles) {
		t.Errorf("got %d, want >= %d", len(roles), len(rbac.SystemRoles))
	}
}

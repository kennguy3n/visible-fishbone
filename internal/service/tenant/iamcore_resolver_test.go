package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedTenant(t *testing.T, repo repository.TenantRepository, name, slug string, status repository.TenantStatus) repository.Tenant {
	t.Helper()
	tn, err := repo.Create(context.Background(), repository.Tenant{
		Name: name, Slug: slug, Status: status, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return tn
}

func TestIAMCoreResolver_BySlug(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantRepository(memory.NewStore())
	tn := seedTenant(t, repo, "Acme", "acme", repository.TenantStatusActive)
	r := NewIAMCoreTenantResolver(repo)

	got, err := r.ResolveTenant(context.Background(), "acme")
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if got != tn.ID {
		t.Errorf("got %v, want %v", got, tn.ID)
	}
}

func TestIAMCoreResolver_ByUUID(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantRepository(memory.NewStore())
	tn := seedTenant(t, repo, "Acme", "acme", repository.TenantStatusActive)
	r := NewIAMCoreTenantResolver(repo)

	got, err := r.ResolveTenant(context.Background(), tn.ID.String())
	if err != nil {
		t.Fatalf("ResolveTenant: %v", err)
	}
	if got != tn.ID {
		t.Errorf("got %v, want %v", got, tn.ID)
	}
}

func TestIAMCoreResolver_EmptyIsInvalid(t *testing.T) {
	t.Parallel()
	r := NewIAMCoreTenantResolver(memory.NewTenantRepository(memory.NewStore()))
	if _, err := r.ResolveTenant(context.Background(), "   "); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("empty tenant_id must be ErrInvalidArgument, got %v", err)
	}
}

func TestIAMCoreResolver_UnknownIsNotFound(t *testing.T) {
	t.Parallel()
	r := NewIAMCoreTenantResolver(memory.NewTenantRepository(memory.NewStore()))
	if _, err := r.ResolveTenant(context.Background(), "ghost-tenant"); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("unknown tenant must surface ErrNotFound, got %v", err)
	}
}

func TestIAMCoreResolver_ReverseMappingReturnsSlug(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantRepository(memory.NewStore())
	tn := seedTenant(t, repo, "Acme", "acme", repository.TenantStatusActive)
	r := NewIAMCoreTenantResolver(repo)

	got, err := r.IAMCoreTenantID(context.Background(), tn.ID)
	if err != nil {
		t.Fatalf("IAMCoreTenantID: %v", err)
	}
	if got != "acme" {
		t.Errorf("got %q, want acme", got)
	}
	// Round-trips: the iam-core id resolves back to the same tenant.
	back, err := r.ResolveTenant(context.Background(), got)
	if err != nil || back != tn.ID {
		t.Errorf("round-trip failed: back=%v err=%v", back, err)
	}
}

func TestIAMCoreResolver_SuspendedIsForbidden(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantRepository(memory.NewStore())
	seedTenant(t, repo, "Acme", "acme", repository.TenantStatusSuspended)
	r := NewIAMCoreTenantResolver(repo)

	if _, err := r.ResolveTenant(context.Background(), "acme"); !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("suspended tenant must be rejected fail-closed (ErrForbidden), got %v", err)
	}
}

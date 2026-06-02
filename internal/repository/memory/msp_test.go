package memory

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// mspFixtures spins up a Store + tenant repo + msp repo combo so
// each test starts from clean state.
func mspFixtures(t *testing.T) (*Store, *MSPRepository, *TenantRepository) {
	t.Helper()
	store := NewStore()
	mspRepo := NewMSPRepository(store)
	tenantRepo := NewTenantRepository(store)
	return store, mspRepo, tenantRepo
}

func mustCreateTenant(t *testing.T, repo *TenantRepository, slug string) repository.Tenant {
	t.Helper()
	out, err := repo.Create(context.Background(), repository.Tenant{
		Name: slug,
		Slug: slug,
	})
	if err != nil {
		t.Fatalf("create tenant %s: %v", slug, err)
	}
	return out
}

func mustCreateMSP(t *testing.T, repo *MSPRepository, slug string) repository.MSP {
	t.Helper()
	out, err := repo.Create(context.Background(), repository.MSP{
		Name: slug,
		Slug: slug,
	})
	if err != nil {
		t.Fatalf("create msp %s: %v", slug, err)
	}
	return out
}

func TestMSPRepository_CreateGetUpdateDelete(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()

	m, err := mspRepo.Create(ctx, repository.MSP{
		Name: "Acme Managed",
		Slug: "acme-managed",
		Branding: repository.MSPBranding{
			LogoURL:      "https://cdn.acme.example/logo.png",
			PrimaryColor: "#ff0033",
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if m.ID == uuid.Nil {
		t.Fatal("expected ID populated")
	}
	if m.Status != repository.MSPStatusActive {
		t.Fatalf("default status = %q want active", m.Status)
	}
	if m.Branding.LogoURL != "https://cdn.acme.example/logo.png" {
		t.Fatalf("branding lost: %#v", m.Branding)
	}

	// Slug must be unique while not soft-deleted.
	_, err = mspRepo.Create(ctx, repository.MSP{Name: "Dup", Slug: "acme-managed"})
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("dup slug should conflict, got %v", err)
	}

	got, err := mspRepo.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Branding.PrimaryColor != "#ff0033" {
		t.Fatalf("get returned wrong branding: %#v", got.Branding)
	}

	gotBySlug, err := mspRepo.GetBySlug(ctx, "acme-managed")
	if err != nil || gotBySlug.ID != m.ID {
		t.Fatalf("get by slug: %v, id=%v want %v", err, gotBySlug.ID, m.ID)
	}

	newName := "Acme MSP"
	newBranding := repository.MSPBranding{PrimaryColor: "#00ff00", CustomDomain: "portal.acme.example"}
	updated, err := mspRepo.Update(ctx, m.ID, repository.MSPPatch{
		Name:     &newName,
		Branding: &newBranding,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Acme MSP" || updated.Branding.CustomDomain != "portal.acme.example" {
		t.Fatalf("update lost fields: %#v", updated)
	}
	// LogoURL was not in the new Branding payload — the patch
	// replaces the entire MSPBranding value (it's a value type,
	// not sparse). This is documented in the MSPPatch contract.
	if updated.Branding.LogoURL != "" {
		t.Fatalf("expected branding replaced wholesale, kept logo: %q", updated.Branding.LogoURL)
	}

	if err := mspRepo.Delete(ctx, m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	deleted, err := mspRepo.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if deleted.Status != repository.MSPStatusDeleted || deleted.DeletedAt == nil {
		t.Fatalf("expected soft-deleted, got %+v", deleted)
	}
	// Second delete is forbidden (idempotency belongs to the caller).
	if err := mspRepo.Delete(ctx, m.ID); !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("second delete should be ErrForbidden, got %v", err)
	}
}

func TestMSPRepository_AssignTenant_OwnerUpdatesDenormalisedColumn(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	msp := mustCreateMSP(t, mspRepo, "msp-a")
	tenant := mustCreateTenant(t, tenantRepo, "tenant-a")

	binding, err := mspRepo.AssignTenant(ctx, msp.ID, tenant.ID, repository.MSPRelationshipOwner, nil)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if binding.Relationship != repository.MSPRelationshipOwner {
		t.Fatalf("got rel %q", binding.Relationship)
	}

	got, err := tenantRepo.Get(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.MSPID == nil || *got.MSPID != msp.ID {
		t.Fatalf("tenants.msp_id not updated: got %v want %v", got.MSPID, msp.ID)
	}
}

func TestMSPRepository_AssignTenant_OwnerEvictsPreviousOwner(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	mspA := mustCreateMSP(t, mspRepo, "msp-a")
	mspB := mustCreateMSP(t, mspRepo, "msp-b")
	tenant := mustCreateTenant(t, tenantRepo, "tenant-a")

	if _, err := mspRepo.AssignTenant(ctx, mspA.ID, tenant.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign A: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, mspB.ID, tenant.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign B: %v", err)
	}

	// mspA's owner binding must have been evicted (the partial
	// unique index in migration 015 only allows one owner per
	// tenant — the memory repo mirrors the semantic).
	bindings, err := mspRepo.ListBindings(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding, got %d: %#v", len(bindings), bindings)
	}
	if bindings[0].MSPID != mspB.ID {
		t.Fatalf("expected owner to be mspB, got %v", bindings[0].MSPID)
	}

	got, err := tenantRepo.Get(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.MSPID == nil || *got.MSPID != mspB.ID {
		t.Fatalf("denormalised pointer not updated to mspB: %v", got.MSPID)
	}
}

func TestMSPRepository_AssignTenant_CoManagerCoexistsWithOwner(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	mspOwner := mustCreateMSP(t, mspRepo, "msp-owner")
	mspCo := mustCreateMSP(t, mspRepo, "msp-co")
	tenant := mustCreateTenant(t, tenantRepo, "tenant-co")

	if _, err := mspRepo.AssignTenant(ctx, mspOwner.ID, tenant.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, mspCo.ID, tenant.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign co: %v", err)
	}

	bindings, err := mspRepo.ListBindings(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 2 {
		t.Fatalf("expected 2 bindings, got %d: %#v", len(bindings), bindings)
	}
	// Denormalised pointer still tracks the owner.
	got, _ := tenantRepo.Get(ctx, tenant.ID)
	if got.MSPID == nil || *got.MSPID != mspOwner.ID {
		t.Fatalf("denormalised pointer drifted, got %v want %v", got.MSPID, mspOwner.ID)
	}
}

func TestMSPRepository_UnassignTenant_OwnerClearsDenormalisedColumn(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	msp := mustCreateMSP(t, mspRepo, "msp")
	tenant := mustCreateTenant(t, tenantRepo, "tenant")

	if _, err := mspRepo.AssignTenant(ctx, msp.ID, tenant.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := mspRepo.UnassignTenant(ctx, msp.ID, tenant.ID); err != nil {
		t.Fatalf("unassign: %v", err)
	}
	got, _ := tenantRepo.Get(ctx, tenant.ID)
	if got.MSPID != nil {
		t.Fatalf("expected denormalised pointer cleared, got %v", got.MSPID)
	}
	if err := mspRepo.UnassignTenant(ctx, msp.ID, tenant.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("second unassign should ErrNotFound, got %v", err)
	}
}

func TestMSPRepository_Delete_CascadesBindingsAndTenantPointer(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	msp := mustCreateMSP(t, mspRepo, "msp")
	tenants := []repository.Tenant{
		mustCreateTenant(t, tenantRepo, "t1"),
		mustCreateTenant(t, tenantRepo, "t2"),
	}
	for _, ten := range tenants {
		if _, err := mspRepo.AssignTenant(ctx, msp.ID, ten.ID, repository.MSPRelationshipOwner, nil); err != nil {
			t.Fatalf("assign %s: %v", ten.Slug, err)
		}
	}

	if err := mspRepo.Delete(ctx, msp.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// All bindings gone.
	for _, ten := range tenants {
		bindings, _ := mspRepo.ListBindings(ctx, ten.ID)
		if len(bindings) != 0 {
			t.Fatalf("tenant %s still bound after MSP delete: %#v", ten.Slug, bindings)
		}
		got, _ := tenantRepo.Get(ctx, ten.ID)
		if got.MSPID != nil {
			t.Fatalf("tenant %s pointer not cleared: %v", ten.Slug, got.MSPID)
		}
	}
}

func TestMSPRepository_ListTenants_PaginatesNewestFirst(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	msp := mustCreateMSP(t, mspRepo, "msp")
	for i, slug := range []string{"a", "b", "c"} {
		ten := mustCreateTenant(t, tenantRepo, slug)
		rel := repository.MSPRelationshipOwner
		if i > 0 {
			rel = repository.MSPRelationshipCoManager
		}
		if _, err := mspRepo.AssignTenant(ctx, msp.ID, ten.ID, rel, nil); err != nil {
			t.Fatalf("assign: %v", err)
		}
	}

	first, err := mspRepo.ListTenants(ctx, msp.ID, repository.Page{Limit: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(first.Items) != 2 {
		t.Fatalf("page 1 size = %d want 2", len(first.Items))
	}
	if first.NextCursor == "" {
		t.Fatal("expected next cursor")
	}
	second, err := mspRepo.ListTenants(ctx, msp.ID, repository.Page{Limit: 2, After: first.NextCursor})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(second.Items) != 1 {
		t.Fatalf("page 2 size = %d want 1", len(second.Items))
	}
}

func TestMSPRepository_AssignTenant_RejectsUnknownIDs(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	msp := mustCreateMSP(t, mspRepo, "msp")
	tenant := mustCreateTenant(t, tenantRepo, "tenant")
	unknown := uuid.New()

	if _, err := mspRepo.AssignTenant(ctx, unknown, tenant.ID, repository.MSPRelationshipOwner, nil); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unknown msp: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, msp.ID, unknown, repository.MSPRelationshipOwner, nil); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unknown tenant: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, msp.ID, tenant.ID, repository.MSPRelationship("bogus"), nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("bogus relationship: %v", err)
	}
}

func TestMSPRepository_UpdateStatus_TransitionsLifecycle(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	msp := mustCreateMSP(t, mspRepo, "msp")

	suspended, err := mspRepo.UpdateStatus(ctx, msp.ID, repository.MSPStatusSuspended)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if suspended.Status != repository.MSPStatusSuspended {
		t.Fatalf("got status %q", suspended.Status)
	}
	if _, err := mspRepo.UpdateStatus(ctx, msp.ID, repository.MSPStatus("bogus")); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("bogus status: %v", err)
	}
}

// TestMSPRepository_GetBySlug_FiltersSoftDeleted pins the
// soft-delete filter on GetBySlug. After a soft-delete + slug
// reuse cycle, two rows can share the same slug (Create only
// enforces uniqueness among non-deleted rows, mirroring the
// postgres partial unique index `WHERE deleted_at IS NULL`).
// Without the filter, Go map iteration order is undefined and
// GetBySlug could return either the tombstone or the live row.
func TestMSPRepository_GetBySlug_FiltersSoftDeleted(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()

	original, err := mspRepo.Create(ctx, repository.MSP{
		Name: "Original Acme",
		Slug: "acme",
	})
	if err != nil {
		t.Fatalf("create original: %v", err)
	}
	if err := mspRepo.Delete(ctx, original.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	revived, err := mspRepo.Create(ctx, repository.MSP{
		Name: "Revived Acme",
		Slug: "acme",
	})
	if err != nil {
		t.Fatalf("create revived (slug reuse should be allowed post-soft-delete): %v", err)
	}
	got, err := mspRepo.GetBySlug(ctx, "acme")
	if err != nil {
		t.Fatalf("get by slug: %v", err)
	}
	if got.ID != revived.ID {
		t.Fatalf("GetBySlug returned wrong row: got %s want %s (tombstone leaked)", got.ID, revived.ID)
	}
	if got.DeletedAt != nil {
		t.Fatalf("GetBySlug returned soft-deleted row: deleted_at=%v", got.DeletedAt)
	}
}

// TestMSPRepository_GetBySlug_ReturnsErrNotFoundForOnlySoftDeleted
// confirms that when no active row exists for the slug, GetBySlug
// reports ErrNotFound rather than the tombstoned row.
func TestMSPRepository_GetBySlug_ReturnsErrNotFoundForOnlySoftDeleted(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()

	m, err := mspRepo.Create(ctx, repository.MSP{
		Name: "Gone",
		Slug: "gone",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := mspRepo.Delete(ctx, m.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, err := mspRepo.GetBySlug(ctx, "gone"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// TestMSPRepository_Update_RejectsEmptyName pins the round-8
// defense-in-depth guard at the repo boundary: even if an
// internal caller bypasses the HTTP handler (which already 400s
// on `{"name": ""}`), the memory repo must reject *patch.Name=""
// with ErrInvalidArgument so the two backends stay consistent.
// The previous behaviour silently dropped the empty value, while
// postgres would have written it into the NOT NULL column.
func TestMSPRepository_Update_RejectsEmptyName(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	m, err := mspRepo.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-empty-name"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	empty := ""
	_, err = mspRepo.Update(ctx, m.ID, repository.MSPPatch{Name: &empty})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty Name, got %v", err)
	}
	// And the row must NOT have been mutated.
	after, err := mspRepo.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Name != "Acme" {
		t.Fatalf("row mutated despite rejected update: name = %q, want Acme", after.Name)
	}
}

// TestMSPRepository_Update_RejectsEmptySlug is the slug-side
// twin of the empty-Name test above.
func TestMSPRepository_Update_RejectsEmptySlug(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	m, err := mspRepo.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-empty-slug"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	empty := ""
	_, err = mspRepo.Update(ctx, m.ID, repository.MSPPatch{Slug: &empty})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for empty Slug, got %v", err)
	}
	after, err := mspRepo.Get(ctx, m.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if after.Slug != "acme-empty-slug" {
		t.Fatalf("row mutated despite rejected update: slug = %q, want acme-empty-slug", after.Slug)
	}
}

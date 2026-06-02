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

// TestMSPRepository_UpdateStatus_ResurrectionRejected pins
// round-17 of Devin Review on PR #42 (ANALYSIS_0005). Before the
// guard, an UpdateStatus(deleted_row, 'active') call would
// silently flip the row's status while leaving deleted_at
// stamped, breaking the lifecycle invariant
// `(status='deleted' ⇔ deleted_at != NULL)` and producing a
// corrupt row that the partial unique slug index could not
// reconcile. The guard rejects every UpdateStatus call on a
// soft-deleted row with ErrForbidden — including idempotent
// `deleted → deleted` — because the legal cascading-delete path
// is Delete() (which clears msp_tenants + tenants.msp_id) and
// the legal transition out of deleted does not exist (deleted
// is terminal by design for MSPs).
func TestMSPRepository_UpdateStatus_ResurrectionRejected(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	msp := mustCreateMSP(t, mspRepo, "msp")
	if err := mspRepo.Delete(ctx, msp.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	for _, to := range []repository.MSPStatus{
		repository.MSPStatusActive,
		repository.MSPStatusSuspended,
		repository.MSPStatusDeleted,
	} {
		if _, err := mspRepo.UpdateStatus(ctx, msp.ID, to); !errors.Is(err, repository.ErrForbidden) {
			t.Fatalf("UpdateStatus(deleted -> %s): want ErrForbidden, got %v", to, err)
		}
	}
	// The row must remain in its tombstoned state — Status=deleted,
	// DeletedAt != nil — regardless of the rejected attempts.
	got, err := mspRepo.Get(ctx, msp.ID)
	if err != nil {
		t.Fatalf("Get post-resurrection-attempt: %v", err)
	}
	if got.Status != repository.MSPStatusDeleted || got.DeletedAt == nil {
		t.Fatalf("row mutated by rejected UpdateStatus calls: status=%q deleted_at=%v",
			got.Status, got.DeletedAt)
	}
}

// TestMSPRepository_TransitionStatus_RejectsCorruptDeletedAtRow
// pins round-19 of Devin Review on PR #42 (ANALYSIS_0002). The
// memory backend's TransitionStatus previously only checked
// `existing.Status == MSPStatusDeleted` to refuse mutations on
// a tombstoned row. Under the lifecycle invariant
// `(Status==Deleted ⇔ DeletedAt != nil)` the Status check is
// sufficient, but Update() defends against any hypothetical
// corrupt row (status='deleted' with DeletedAt nil, OR
// status='active' with DeletedAt stamped — produced e.g. by a
// partial migration or a buggy admin tool that touched one
// column without the other) by checking BOTH predicates.
// TransitionStatus now mirrors that belt-and-suspenders shape
// so it observes the same refusal regardless of which side of
// the invariant the corruption manifests on. Postgres
// TransitionStatus carries the matching SQL precondition `WHERE
// status <> 'deleted' AND deleted_at IS NULL`.
func TestMSPRepository_TransitionStatus_RejectsCorruptDeletedAtRow(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	msp := mustCreateMSP(t, mspRepo, "msp")

	// Stamp DeletedAt while leaving Status='active' — a corrupt
	// row violating the lifecycle invariant. There is no public
	// API that can produce this; we surgically mutate the
	// underlying store directly. This is the contract under
	// test: TransitionStatus must refuse to mutate such a row.
	mspRepo.s.mu.Lock()
	row := mspRepo.s.msps[msp.ID]
	stamped := mspRepo.s.clock()
	row.DeletedAt = &stamped
	mspRepo.s.msps[msp.ID] = row
	mspRepo.s.mu.Unlock()

	for _, to := range []repository.MSPStatus{
		repository.MSPStatusActive,
		repository.MSPStatusSuspended,
	} {
		if _, err := mspRepo.TransitionStatus(ctx, msp.ID, to); !errors.Is(err, repository.ErrForbidden) {
			t.Fatalf("TransitionStatus(corrupt-deleted_at -> %s): want ErrForbidden, got %v", to, err)
		}
	}

	// And the conventional path — Status=deleted with DeletedAt
	// stamped, the legal tombstoned state — must also refuse.
	mspRepo.s.mu.Lock()
	row = mspRepo.s.msps[msp.ID]
	row.Status = repository.MSPStatusDeleted
	mspRepo.s.msps[msp.ID] = row
	mspRepo.s.mu.Unlock()
	if _, err := mspRepo.TransitionStatus(ctx, msp.ID, repository.MSPStatusActive); !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("TransitionStatus(legal-deleted -> active): want ErrForbidden, got %v", err)
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

// TestMSPRepository_Update_RejectsSoftDeletedRowOnStatusGuard pins
// the round-14 defense-in-depth fix for ANALYSIS_0002: under the
// lifecycle invariant `(status='deleted' ⇔ deleted_at != NULL)`
// the two halves of the guard are equivalent, but the memory
// backend must still reject a PATCH against a row whose Status is
// already 'deleted'. This is the original round-13 half of the
// guard.
func TestMSPRepository_Update_RejectsSoftDeletedRowOnStatusGuard(t *testing.T) {
	_, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	m, err := mspRepo.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-soft-status"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := mspRepo.Delete(ctx, m.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	newName := "Renamed"
	_, err = mspRepo.Update(ctx, m.ID, repository.MSPPatch{Name: &newName})
	if !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("Update on soft-deleted MSP should ErrForbidden, got %v", err)
	}
}

// TestMSPRepository_Update_RejectsCorruptDeletedAtOnlyRow pins the
// round-14 ANALYSIS_0002 defense-in-depth: a corrupt row with
// `deleted_at != nil` but `Status != deleted` (lifecycle invariant
// violation, e.g. partial write) must still be rejected. Prior to
// round-14 the memory backend only checked `Status == deleted` so
// such a row would have been mutated; the postgres backend would
// have rejected it via the `deleted_at IS NULL` predicate. The
// fix mirrors postgres's predicate into memory so both backends
// fail the same way on corrupt data.
func TestMSPRepository_Update_RejectsCorruptDeletedAtOnlyRow(t *testing.T) {
	store, mspRepo, _ := mspFixtures(t)
	ctx := context.Background()
	m, err := mspRepo.Create(ctx, repository.MSP{Name: "Acme", Slug: "acme-corrupt-da"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Simulate corrupt data: deleted_at stamped but Status NOT
	// transitioned to 'deleted'. This violates the lifecycle
	// invariant the system is designed to maintain, but we
	// defend against it anyway.
	store.mu.Lock()
	row := store.msps[m.ID]
	ts := row.CreatedAt
	row.DeletedAt = &ts
	// row.Status remains MSPStatusActive
	store.msps[m.ID] = row
	store.mu.Unlock()

	newName := "Renamed"
	_, err = mspRepo.Update(ctx, m.ID, repository.MSPPatch{Name: &newName})
	if !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("Update on corrupt-deleted_at row should ErrForbidden, got %v", err)
	}
}

// TestMSPRepository_AssignTenant_DowngradeClearsMSPID pins the
// round-14 fix for ANALYSIS_0003: when AssignTenant is called for
// the same (msp, tenant) pair with relationship=co_manager after
// a prior relationship=owner assignment, the binding is upserted
// (memory direct write, postgres ON CONFLICT DO UPDATE) but the
// denormalised `tenants.msp_id` pointer must be cleared so the
// join table and the denormalised column stay consistent. Prior
// to round-14 the downgrade left the pointer stale, creating a
// cross-storage-site drift.
func TestMSPRepository_AssignTenant_DowngradeClearsMSPID(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	msp := mustCreateMSP(t, mspRepo, "downgrade-msp")
	tenant := mustCreateTenant(t, tenantRepo, "downgrade-tenant")

	// First make it an owner — pointer should be set.
	if _, err := mspRepo.AssignTenant(ctx, msp.ID, tenant.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	got, err := tenantRepo.Get(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("get tenant after owner: %v", err)
	}
	if got.MSPID == nil || *got.MSPID != msp.ID {
		t.Fatalf("after owner-assign expected pointer to %s, got %v", msp.ID, got.MSPID)
	}

	// Now downgrade to co_manager — pointer must be cleared.
	if _, err := mspRepo.AssignTenant(ctx, msp.ID, tenant.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("assign co_manager: %v", err)
	}
	got, err = tenantRepo.Get(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("get tenant after downgrade: %v", err)
	}
	if got.MSPID != nil {
		t.Fatalf("after downgrade expected pointer cleared, got %v", got.MSPID)
	}
	// But the binding itself must still exist and now be co_manager.
	bindings, err := mspRepo.ListBindings(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("list bindings: %v", err)
	}
	if len(bindings) != 1 {
		t.Fatalf("expected 1 binding after downgrade, got %d", len(bindings))
	}
	if bindings[0].Relationship != repository.MSPRelationshipCoManager {
		t.Fatalf("expected co_manager binding, got %s", bindings[0].Relationship)
	}
	if bindings[0].MSPID != msp.ID {
		t.Fatalf("binding MSP ID mismatch: got %s want %s", bindings[0].MSPID, msp.ID)
	}
}

// TestMSPRepository_AssignTenant_RepeatedCoManagerDoesNotClearOtherOwner
// pins that the round-14 downgrade fix does NOT stomp a pointer set
// by some other MSP: if MSP-A owns the tenant and MSP-B is bound as
// co_manager (no prior owner relationship on B), a repeat
// co_manager assign on B must not touch tenants.msp_id (still
// points at A).
func TestMSPRepository_AssignTenant_RepeatedCoManagerDoesNotClearOtherOwner(t *testing.T) {
	_, mspRepo, tenantRepo := mspFixtures(t)
	ctx := context.Background()

	owner := mustCreateMSP(t, mspRepo, "owner-msp")
	co := mustCreateMSP(t, mspRepo, "co-msp")
	tenant := mustCreateTenant(t, tenantRepo, "shared-tenant")

	if _, err := mspRepo.AssignTenant(ctx, owner.ID, tenant.ID, repository.MSPRelationshipOwner, nil); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	if _, err := mspRepo.AssignTenant(ctx, co.ID, tenant.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("first co_manager assign: %v", err)
	}
	// Repeat — idempotent upsert; must NOT clear owner's pointer.
	if _, err := mspRepo.AssignTenant(ctx, co.ID, tenant.ID, repository.MSPRelationshipCoManager, nil); err != nil {
		t.Fatalf("repeated co_manager assign: %v", err)
	}
	got, err := tenantRepo.Get(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if got.MSPID == nil || *got.MSPID != owner.ID {
		t.Fatalf("owner pointer mutated by repeated co_manager: got %v want %s", got.MSPID, owner.ID)
	}
}

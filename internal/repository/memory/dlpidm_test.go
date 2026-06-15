// Package memory_test — dlpidm_test exercises the in-memory
// DLPIDMRepository CRUD contract for WP4 (protected-document
// fingerprint sets + OCR/IDM config), mirroring the postgres behavior:
// tenant isolation, (tenant, name) uniqueness, cursor pagination,
// metadata-only update, stats aggregation, and config upsert.
package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newDLPIDMRepo(t *testing.T) *memory.DLPIDMRepository {
	t.Helper()
	store := memory.NewStore()
	// Deterministic, monotonically increasing clock so created_at
	// ordering in pagination is stable.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var tick int64
	store.SetClock(func() time.Time {
		tick++
		return base.Add(time.Duration(tick) * time.Second)
	})
	return memory.NewDLPIDMRepository(store)
}

func sampleSet(name string) repository.IDMFingerprintSet {
	return repository.IDMFingerprintSet{
		Name:            name,
		Description:     "desc " + name,
		ShingleSize:     5,
		WindowSize:      8,
		MaxFingerprints: 2048,
		Fingerprints:    []uint64{1, 2, 3, 4, 5},
		SourceBytes:     1024,
	}
}

func TestDLPIDMRepository_CreateAndGet(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	created, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("contracts"))
	if err != nil {
		t.Fatalf("CreateFingerprintSet: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("expected generated id")
	}
	if created.TenantID != tenantID {
		t.Fatalf("tenant = %v, want %v", created.TenantID, tenantID)
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Fatal("expected timestamps to be set")
	}

	got, err := repo.GetFingerprintSet(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("GetFingerprintSet: %v", err)
	}
	if len(got.Fingerprints) != 5 {
		t.Fatalf("fingerprints len = %d, want 5", len(got.Fingerprints))
	}
}

func TestDLPIDMRepository_CreateRejectsDuplicateName(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	if _, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("dup")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("dup"))
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestDLPIDMRepository_TenantIsolation(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantA, tenantB := uuid.New(), uuid.New()

	created, err := repo.CreateFingerprintSet(ctx, tenantA, sampleSet("a-only"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Same name under a different tenant must be allowed.
	if _, err := repo.CreateFingerprintSet(ctx, tenantB, sampleSet("a-only")); err != nil {
		t.Fatalf("create under tenant B: %v", err)
	}
	// Tenant B cannot read tenant A's set.
	if _, err := repo.GetFingerprintSet(ctx, tenantB, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant get err = %v, want ErrNotFound", err)
	}
}

func TestDLPIDMRepository_ListPagination(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	for _, name := range []string{"one", "two", "three"} {
		if _, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet(name)); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}

	first, err := repo.ListFingerprintSets(ctx, tenantID, repository.Page{Limit: 2})
	if err != nil {
		t.Fatalf("list page 1: %v", err)
	}
	if len(first.Items) != 2 {
		t.Fatalf("page 1 len = %d, want 2", len(first.Items))
	}
	if first.NextCursor == "" {
		t.Fatal("expected next cursor")
	}
	second, err := repo.ListFingerprintSets(ctx, tenantID, repository.Page{Limit: 2, After: first.NextCursor})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(second.Items) != 1 {
		t.Fatalf("page 2 len = %d, want 1", len(second.Items))
	}
}

func TestDLPIDMRepository_UpdateMetadata(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	created, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("orig"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	newName := "renamed"
	newDesc := "updated description"
	updated, err := repo.UpdateFingerprintSet(ctx, tenantID, created.ID, repository.IDMFingerprintSetPatch{
		Name:        &newName,
		Description: &newDesc,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != newName || updated.Description != newDesc {
		t.Fatalf("update = %+v, want name=%q desc=%q", updated, newName, newDesc)
	}
	// Fingerprints must be untouched by a metadata patch.
	if len(updated.Fingerprints) != 5 {
		t.Fatalf("fingerprints len = %d, want 5 (unchanged)", len(updated.Fingerprints))
	}
}

func TestDLPIDMRepository_UpdateRejectsNameCollision(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	if _, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("taken")); err != nil {
		t.Fatalf("create taken: %v", err)
	}
	other, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("other"))
	if err != nil {
		t.Fatalf("create other: %v", err)
	}
	collide := "taken"
	_, err = repo.UpdateFingerprintSet(ctx, tenantID, other.ID, repository.IDMFingerprintSetPatch{Name: &collide})
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestDLPIDMRepository_Delete(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	created, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet("gone"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := repo.DeleteFingerprintSet(ctx, tenantID, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.GetFingerprintSet(ctx, tenantID, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("get after delete err = %v, want ErrNotFound", err)
	}
	if err := repo.DeleteFingerprintSet(ctx, tenantID, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("double delete err = %v, want ErrNotFound", err)
	}
}

func TestDLPIDMRepository_Stats(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	for _, name := range []string{"s1", "s2"} {
		if _, err := repo.CreateFingerprintSet(ctx, tenantID, sampleSet(name)); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	stats, err := repo.FingerprintSetStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.SetCount != 2 {
		t.Fatalf("set count = %d, want 2", stats.SetCount)
	}
	if stats.TotalFingerprints != 10 {
		t.Fatalf("total fingerprints = %d, want 10", stats.TotalFingerprints)
	}
	if stats.TotalSourceBytes != 2048 {
		t.Fatalf("total source bytes = %d, want 2048", stats.TotalSourceBytes)
	}
}

func TestDLPIDMRepository_ConfigUpsert(t *testing.T) {
	t.Parallel()
	repo := newDLPIDMRepo(t)
	ctx := context.Background()
	tenantID := uuid.New()

	if _, err := repo.GetConfig(ctx, tenantID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("get missing config err = %v, want ErrNotFound", err)
	}

	cfg := repository.DLPOCRIDMConfig{
		OCREnabled:             true,
		OCRMaxInputBytes:       4 << 20,
		OCRMaxDimension:        4096,
		IDMEnabled:             true,
		IDMSimilarityThreshold: 0.8,
		IDMShingleSize:         5,
		IDMWindowSize:          8,
		IDMMaxFingerprints:     2048,
	}
	first, err := repo.UpsertConfig(ctx, tenantID, cfg)
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if first.CreatedAt.IsZero() {
		t.Fatal("expected created_at on insert")
	}

	cfg.OCREnabled = false
	cfg.IDMSimilarityThreshold = 0.9
	second, err := repo.UpsertConfig(ctx, tenantID, cfg)
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if second.OCREnabled {
		t.Fatal("expected ocr disabled after update")
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at changed on update: %v -> %v", first.CreatedAt, second.CreatedAt)
	}
	if !second.UpdatedAt.After(first.UpdatedAt) {
		t.Fatalf("updated_at not advanced: %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
}

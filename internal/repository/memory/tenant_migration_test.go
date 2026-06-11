// Package memory_test — tenant_migration_test pins the contract of the
// memory TenantMigrationRepository so it stays a faithful double for the
// Postgres implementation (migration 059): single in-flight migration
// per tenant, tenant-scoped reads, terminal-state semantics, and
// resumable ordering.
package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newMigRepo(t *testing.T) (*memory.TenantMigrationRepository, *memory.Store) {
	t.Helper()
	s := memory.NewStore()
	return memory.NewTenantMigrationRepository(s), s
}

func mkMig(tenantID uuid.UUID, state string) repository.TenantMigration {
	return repository.TenantMigration{
		TenantID:     tenantID,
		SourceRegion: "us-east-1",
		TargetRegion: "eu-central-1",
		State:        state,
		DualRead:     true,
	}
}

func TestTenantMigration_CreateValidates(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()

	// nil tenant id arg.
	if _, err := repo.Create(ctx, uuid.Nil, mkMig(tid, repository.MigrationStatePending)); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("nil tenant: err = %v, want ErrInvalidArgument", err)
	}
	bad := []repository.TenantMigration{
		{TenantID: tid, SourceRegion: "", TargetRegion: "eu-central-1"},       // empty source
		{TenantID: tid, SourceRegion: "us-east-1", TargetRegion: ""},          // empty target
		{TenantID: tid, SourceRegion: "us-east-1", TargetRegion: "us-east-1"}, // identical
	}
	for i, m := range bad {
		if _, err := repo.Create(ctx, tid, m); !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("bad[%d]: err = %v, want ErrInvalidArgument", i, err)
		}
	}
}

func TestTenantMigration_SingleInFlight(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()

	if _, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending)); err != nil {
		t.Fatalf("first create: %v", err)
	}
	// Second in-flight migration for the same tenant is rejected.
	if _, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending)); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second create: err = %v, want ErrConflict", err)
	}
	// A different tenant is unaffected.
	if _, err := repo.Create(ctx, uuid.New(), mkMig(uuid.New(), repository.MigrationStatePending)); err != nil {
		t.Fatalf("other tenant create: %v", err)
	}
}

func TestTenantMigration_TerminalAllowsNew(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()

	created, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Drive it to a terminal state.
	created.State = repository.MigrationStateCompleted
	if _, err := repo.Update(ctx, tid, created); err != nil {
		t.Fatalf("update->completed: %v", err)
	}
	// Now a new migration is allowed.
	if _, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending)); err != nil {
		t.Fatalf("create after terminal: %v", err)
	}
}

func TestTenantMigration_GetIsTenantScoped(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()
	created, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Wrong tenant cannot read it (RLS parity).
	if _, err := repo.Get(ctx, uuid.New(), created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant Get: err = %v, want ErrNotFound", err)
	}
	got, err := repo.Get(ctx, tid, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("Get returned wrong row")
	}
}

func TestTenantMigration_GetActiveAndLatest(t *testing.T) {
	t.Parallel()
	repo, s := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()
	clk := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return clk })

	first, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create first: %v", err)
	}
	// Terminalize the first.
	first.State = repository.MigrationStateRolledBack
	if _, err := repo.Update(ctx, tid, first); err != nil {
		t.Fatalf("update first: %v", err)
	}
	// No active now.
	if _, err := repo.GetActive(ctx, tid); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("GetActive after terminal: err = %v, want ErrNotFound", err)
	}
	// Create a second, later migration.
	clk = clk.Add(time.Hour)
	second, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create second: %v", err)
	}
	active, err := repo.GetActive(ctx, tid)
	if err != nil {
		t.Fatalf("GetActive: %v", err)
	}
	if active.ID != second.ID {
		t.Fatalf("GetActive = %v, want second %v", active.ID, second.ID)
	}
	latest, err := repo.Latest(ctx, tid)
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if latest.ID != second.ID {
		t.Fatalf("Latest = %v, want second %v", latest.ID, second.ID)
	}
}

func TestTenantMigration_UpdateImmutableIdentity(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()
	created, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Attempt to mutate identity/creation fields via Update — they must
	// be ignored.
	tamper := created
	tamper.SourceRegion = "ap-southeast-1"
	tamper.TargetRegion = "me-central-1"
	tamper.CreatedAt = created.CreatedAt.Add(-time.Hour)
	tamper.State = repository.MigrationStateRewrappingKeys
	tamper.Detail = "stepping"
	tamper.Checkpoint = json.RawMessage(`{"steps":{"rewrap_keys":{"status":"done"}}}`)
	updated, err := repo.Update(ctx, tid, tamper)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.SourceRegion != "us-east-1" || updated.TargetRegion != "eu-central-1" {
		t.Errorf("regions mutated: %q -> %q", updated.SourceRegion, updated.TargetRegion)
	}
	if !updated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("created_at mutated")
	}
	if updated.State != repository.MigrationStateRewrappingKeys || updated.Detail != "stepping" {
		t.Errorf("mutable fields not applied: state=%q detail=%q", updated.State, updated.Detail)
	}
}

func TestTenantMigration_ListResumableOrdering(t *testing.T) {
	t.Parallel()
	repo, s := newMigRepo(t)
	ctx := context.Background()
	clk := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return clk })

	// Three tenants with in-flight migrations created at increasing times.
	for i := 0; i < 3; i++ {
		tid := uuid.New()
		if _, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending)); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		clk = clk.Add(time.Minute)
	}
	// One terminal migration must be excluded.
	tidDone := uuid.New()
	done, err := repo.Create(ctx, tidDone, mkMig(tidDone, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create done: %v", err)
	}
	done.State = repository.MigrationStateCompleted
	if _, err := repo.Update(ctx, tidDone, done); err != nil {
		t.Fatalf("complete: %v", err)
	}

	list, err := repo.ListResumable(ctx)
	if err != nil {
		t.Fatalf("ListResumable: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("resumable count = %d, want 3", len(list))
	}
	// Oldest-updated first.
	for i := 0; i < len(list)-1; i++ {
		if list[i].UpdatedAt.After(list[i+1].UpdatedAt) {
			t.Errorf("not oldest-first at %d: %v after %v", i, list[i].UpdatedAt, list[i+1].UpdatedAt)
		}
	}
}

func TestTenantMigration_CheckpointDefaultsToEmptyObject(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()
	created, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if string(created.Checkpoint) != `{}` {
		t.Errorf("checkpoint default = %q, want {}", created.Checkpoint)
	}
}

// TestTenantMigration_OptimisticConcurrency pins the version-based
// optimistic lock: a fresh row starts at version 0, every Update bumps
// it, and a write that presents a stale version is rejected with
// ErrConcurrentUpdate without mutating the stored row (so a resume loop
// racing a Start over the same migration yields instead of clobbering).
func TestTenantMigration_OptimisticConcurrency(t *testing.T) {
	t.Parallel()
	repo, _ := newMigRepo(t)
	ctx := context.Background()
	tid := uuid.New()

	created, err := repo.Create(ctx, tid, mkMig(tid, repository.MigrationStatePending))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Version != 0 {
		t.Fatalf("fresh version = %d, want 0", created.Version)
	}

	// First writer (loaded version 0) wins and the counter advances.
	winner := created
	winner.State = repository.MigrationStateRewrappingKeys
	saved, err := repo.Update(ctx, tid, winner)
	if err != nil {
		t.Fatalf("winner update: %v", err)
	}
	if saved.Version != 1 {
		t.Fatalf("version after update = %d, want 1", saved.Version)
	}

	// A stale writer still holding version 0 is rejected and changes
	// nothing — it must yield to the winner.
	stale := created // still version 0
	stale.State = repository.MigrationStateCopyingObjects
	stale.Detail = "stale write"
	if _, err := repo.Update(ctx, tid, stale); !errors.Is(err, repository.ErrConcurrentUpdate) {
		t.Fatalf("stale update: err = %v, want ErrConcurrentUpdate", err)
	}
	got, err := repo.Get(ctx, tid, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.State != repository.MigrationStateRewrappingKeys || got.Version != 1 || got.Detail != "" {
		t.Fatalf("stale write leaked: state=%q version=%d detail=%q", got.State, got.Version, got.Detail)
	}

	// The winner, presenting the current version, continues to succeed.
	next := saved
	next.State = repository.MigrationStateCopyingTelemetry
	if _, err := repo.Update(ctx, tid, next); err != nil {
		t.Fatalf("winner second update: %v", err)
	}
}

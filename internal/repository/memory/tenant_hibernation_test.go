// Package memory_test — tenant_hibernation_test pins the upsert,
// audit-timestamp and listing contract for the in-memory
// TenantHibernationRepository so it stays a faithful double for the
// Postgres schema + system-scoped access in migration 068.
package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy/hibernation"
)

func TestTenantHibernationRepository_Validation(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantHibernationRepository()
	if _, err := repo.SetHibernated(context.Background(), uuid.Nil, "", time.Now()); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("nil tenant = %v, want ErrInvalidArgument", err)
	}
}

func TestTenantHibernationRepository_UpsertAuditTrail(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantHibernationRepository()
	ctx := context.Background()
	id := uuid.New()

	hAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rec, err := repo.SetHibernated(ctx, id, "reached dormant tier", hAt)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != hibernation.StateHibernated || rec.HibernatedAt == nil || !rec.HibernatedAt.Equal(hAt) {
		t.Fatalf("hibernate record wrong: %+v", rec)
	}
	if rec.WokeAt != nil {
		t.Fatal("woke_at should be nil before any wake")
	}

	// Waking advances woke_at but preserves hibernated_at (audit trail of
	// the most recent transition in each direction).
	wAt := hAt.Add(48 * time.Hour)
	rec, err = repo.SetActive(ctx, id, "woke on activity", wAt)
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != hibernation.StateActive {
		t.Fatalf("state after wake = %s, want active", rec.State)
	}
	if rec.WokeAt == nil || !rec.WokeAt.Equal(wAt) {
		t.Fatalf("woke_at not advanced: %+v", rec)
	}
	if rec.HibernatedAt == nil || !rec.HibernatedAt.Equal(hAt) {
		t.Fatalf("hibernated_at should be preserved across wake: %+v", rec)
	}
}

func TestTenantHibernationRepository_List(t *testing.T) {
	t.Parallel()
	repo := memory.NewTenantHibernationRepository()
	ctx := context.Background()
	a, b := uuid.New(), uuid.New()
	if _, err := repo.SetHibernated(ctx, a, "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.SetActive(ctx, b, "x", time.Now()); err != nil {
		t.Fatal(err)
	}
	recs, err := repo.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("List returned %d records, want 2", len(recs))
	}
	// Implements the service-side hibernation.Store interface.
	var _ hibernation.Store = repo
}

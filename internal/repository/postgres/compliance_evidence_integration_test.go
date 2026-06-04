//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TestComplianceEvidence_Integration exercises the platform-level
// compliance_evidence repository against a real Postgres (migration
// 039). The table has no tenant_id and no RLS, so every operation runs
// via onPrimary — there is no per-tenant isolation to assert, only the
// CRUD / ordering / uniqueness contract.
func TestComplianceEvidence_Integration(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	repo := store.NewComplianceEvidenceRepository()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	mk := func(collType, key string, collectedAt time.Time, status string) repository.ComplianceEvidence {
		return repository.ComplianceEvidence{
			CollectionType: collType,
			CollectedAt:    collectedAt,
			S3Key:          key,
			Signature:      "deadbeef",
			Status:         status,
		}
	}

	t.Run("Create_assigns_id_and_created_at", func(t *testing.T) {
		row, err := repo.Create(bgCtx(), mk("weekly", "k/weekly/"+uuid.NewString(), base, "collecting"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if row.ID == uuid.Nil {
			t.Fatal("expected server-assigned id")
		}
		if row.CreatedAt.IsZero() {
			t.Fatal("expected server-assigned created_at")
		}

		got, err := repo.Get(bgCtx(), row.ID)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.S3Key != row.S3Key || got.Status != "collecting" {
			t.Fatalf("get mismatch: %+v", got)
		}
	})

	t.Run("Create_preserves_caller_supplied_id", func(t *testing.T) {
		// EvidenceService embeds this id in the signed bundle and the S3
		// key, so the row id must equal the supplied id rather than a
		// DEFAULT gen_random_uuid() value.
		want := uuid.New()
		e := mk("weekly", "k/id/"+uuid.NewString(), base, "collected")
		e.ID = want
		row, err := repo.Create(bgCtx(), e)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if row.ID != want {
			t.Fatalf("row id = %s, want caller-supplied %s", row.ID, want)
		}
		got, err := repo.Get(bgCtx(), want)
		if err != nil {
			t.Fatalf("get by caller id: %v", err)
		}
		if got.ID != want {
			t.Fatalf("get id = %s, want %s", got.ID, want)
		}
	})

	t.Run("Get_unknown_is_not_found", func(t *testing.T) {
		if _, err := repo.Get(bgCtx(), uuid.New()); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("want ErrNotFound, got %v", err)
		}
	})

	t.Run("Duplicate_s3_key_conflicts", func(t *testing.T) {
		key := "k/dup/" + uuid.NewString()
		if _, err := repo.Create(bgCtx(), mk("weekly", key, base, "collected")); err != nil {
			t.Fatalf("first create: %v", err)
		}
		if _, err := repo.Create(bgCtx(), mk("weekly", key, base, "collected")); !errors.Is(err, repository.ErrConflict) {
			t.Fatalf("want ErrConflict on duplicate s3_key, got %v", err)
		}
	})

	t.Run("UpdateStatus_transitions", func(t *testing.T) {
		row, err := repo.Create(bgCtx(), mk("weekly", "k/upd/"+uuid.NewString(), base, "collecting"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		updated, err := repo.UpdateStatus(bgCtx(), row.ID, "collected")
		if err != nil {
			t.Fatalf("update status: %v", err)
		}
		if updated.Status != "collected" {
			t.Fatalf("status = %q, want collected", updated.Status)
		}
		if _, err := repo.UpdateStatus(bgCtx(), uuid.New(), "collected"); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("update unknown: want ErrNotFound, got %v", err)
		}
	})

	t.Run("List_orders_recent_first_and_filters", func(t *testing.T) {
		ct := "monthly"
		old := mk(ct, "k/list/old/"+uuid.NewString(), base, "collected")
		recent := mk(ct, "k/list/recent/"+uuid.NewString(), base.Add(48*time.Hour), "collected")
		if _, err := repo.Create(bgCtx(), old); err != nil {
			t.Fatalf("create old: %v", err)
		}
		if _, err := repo.Create(bgCtx(), recent); err != nil {
			t.Fatalf("create recent: %v", err)
		}

		page, err := repo.List(bgCtx(), repository.ComplianceEvidenceFilter{CollectionType: ct}, repository.Page{Limit: 50})
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(page.Items) < 2 {
			t.Fatalf("expected >=2 monthly rows, got %d", len(page.Items))
		}
		// Most-recent-first.
		for i := 1; i < len(page.Items); i++ {
			if page.Items[i-1].CollectedAt.Before(page.Items[i].CollectedAt) {
				t.Fatalf("list not ordered most-recent-first at %d", i)
			}
		}
		for _, it := range page.Items {
			if it.CollectionType != ct {
				t.Fatalf("filter leaked type %q", it.CollectionType)
			}
		}
	})

	t.Run("LatestByType", func(t *testing.T) {
		ct := "latest-" + uuid.NewString()[:8]
		_, err := repo.Create(bgCtx(), mk(ct, "k/lat/old/"+uuid.NewString(), base, "collected"))
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		newest := mk(ct, "k/lat/new/"+uuid.NewString(), base.Add(72*time.Hour), "collected")
		if _, err := repo.Create(bgCtx(), newest); err != nil {
			t.Fatalf("create newest: %v", err)
		}

		got, err := repo.LatestByType(bgCtx(), ct)
		if err != nil {
			t.Fatalf("latest by type: %v", err)
		}
		if !got.CollectedAt.Equal(newest.CollectedAt) {
			t.Fatalf("latest = %v, want %v", got.CollectedAt, newest.CollectedAt)
		}

		if _, err := repo.LatestByType(bgCtx(), "no-such-type"); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("want ErrNotFound for unknown type, got %v", err)
		}
	})
}

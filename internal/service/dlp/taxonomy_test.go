package dlp_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

func newTaxonomyService(t *testing.T) (*dlp.TaxonomyService, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	svc := dlp.NewTaxonomyService(
		memory.NewDataClassificationRepository(store),
		memory.NewAuditLogRepository(store),
		nil,
	)
	return svc, tenantID
}

func TestSeedDefaults(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	ctx := context.Background()

	if err := svc.SeedDefaults(ctx, tid); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := svc.List(ctx, tid, repository.Page{Limit: 100})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Items) != 5 {
		t.Fatalf("items = %d, want 5", len(res.Items))
	}
}

func TestSeedDefaults_Idempotent(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	ctx := context.Background()

	_ = svc.SeedDefaults(ctx, tid)
	_ = svc.SeedDefaults(ctx, tid)

	res, _ := svc.List(ctx, tid, repository.Page{Limit: 100})
	if len(res.Items) != 5 {
		t.Fatalf("items = %d, want 5 (idempotent)", len(res.Items))
	}
}

func TestClassify(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	ctx := context.Background()

	_ = svc.SeedDefaults(ctx, tid)

	dc, err := svc.Classify(ctx, tid, repository.ClassificationLevelConfidential)
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if dc.Level != repository.ClassificationLevelConfidential {
		t.Fatalf("level = %q, want confidential", dc.Level)
	}
}

func TestClassify_NotFound(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	ctx := context.Background()

	_, err := svc.Classify(ctx, tid, repository.ClassificationLevelTopSecret)
	if err == nil {
		t.Fatal("expected not found")
	}
}

func TestCreate_InvalidLevel(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	_, err := svc.Create(context.Background(), tid, repository.DataClassification{
		Label: "Bad", Level: "invalid",
	})
	if err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestUpdate(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	ctx := context.Background()

	created, _ := svc.Create(ctx, tid, repository.DataClassification{
		Label: "Custom", Level: repository.ClassificationLevelPublic,
	})
	newLabel := "Updated"
	updated, err := svc.Update(ctx, tid, created.ID, repository.DataClassificationPatch{
		Label: &newLabel,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Label != "Updated" {
		t.Fatalf("label = %q, want Updated", updated.Label)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	svc, tid := newTaxonomyService(t)
	ctx := context.Background()

	created, _ := svc.Create(ctx, tid, repository.DataClassification{
		Label: "ToDelete", Level: repository.ClassificationLevelInternal,
	})
	if err := svc.Delete(ctx, tid, created.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := svc.Get(ctx, tid, created.ID)
	if err == nil {
		t.Fatal("expected not found after delete")
	}
}

package policytemplates

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	memrepo "github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	pgrepo "github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

// Compile-time assertions that both repository implementations satisfy
// the package's Repository interface. The postgres assertion uses a
// typed nil so no database is required.
var (
	_ Repository = (*memrepo.PolicyTemplateRepository)(nil)
	_ Repository = (*pgrepo.PolicyTemplateRepository)(nil)
)

func newTestService(t *testing.T) (*Service, *memrepo.PolicyTemplateRepository) {
	t.Helper()
	repo := memrepo.NewPolicyTemplateRepository()
	return New(repo, nil), repo
}

func TestListTemplates_ReturnsImmutableCopies(t *testing.T) {
	svc, _ := newTestService(t)
	list := svc.ListTemplates()
	if len(list) == 0 {
		t.Fatal("empty catalog")
	}
	// Mutate the returned spec; the catalog must be unaffected.
	if len(list[0].Spec.Categories) > 0 {
		list[0].Spec.Categories[0].Action = "tampered"
	}
	again := svc.ListTemplates()
	for _, c := range again[0].Spec.Categories {
		if c.Action == "tampered" {
			t.Fatal("ListTemplates leaked a mutable reference to the catalog")
		}
	}
}

func TestGetTemplate(t *testing.T) {
	svc, _ := newTestService(t)
	tmpl, err := svc.GetTemplate(baselineTemplateID)
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if tmpl.Kind != KindBaseline {
		t.Errorf("kind = %q, want baseline", tmpl.Kind)
	}
	if _, err := svc.GetTemplate("does-not-exist"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing template err = %v, want ErrNotFound", err)
	}
}

func TestApply_Idempotent(t *testing.T) {
	svc, repo := newTestService(t)
	// Freeze then advance the clock so we can detect a write by an
	// updated_at change.
	now := time.Unix(1_700_000_000, 0).UTC()
	repo.SetClock(func() time.Time { return now })

	ctx := context.Background()
	tenant := uuid.New()
	sel := Selection{Industry: IndustryFinance, Country: "DE"}

	first, err := svc.Apply(ctx, tenant, sel)
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	if first.GraphHash == "" || len(first.Graph) == 0 {
		t.Fatal("first apply produced an empty graph")
	}

	// Advance the clock; a real write would stamp this newer time.
	now = now.Add(time.Hour)

	second, err := svc.Apply(ctx, tenant, sel)
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second.GraphHash != first.GraphHash {
		t.Errorf("idempotent apply changed hash: %q -> %q", first.GraphHash, second.GraphHash)
	}
	if !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Errorf("idempotent apply rewrote the row: updated_at %v -> %v", first.UpdatedAt, second.UpdatedAt)
	}
}

func TestApply_ChangingSelectionUpdates(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()

	first, err := svc.Apply(ctx, tenant, Selection{Industry: IndustryRetail, Country: "US"})
	if err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	second, err := svc.Apply(ctx, tenant, Selection{Industry: IndustryHealthcare, Country: "GB"})
	if err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if second.GraphHash == first.GraphHash {
		t.Error("changing selection did not change the rendered graph")
	}
	if second.Industry != string(IndustryHealthcare) || second.Country != "GB" {
		t.Errorf("applied selection not updated: %q/%q", second.Industry, second.Country)
	}

	// Only one row per tenant: GetApplied returns the latest.
	got, err := svc.GetApplied(ctx, tenant)
	if err != nil {
		t.Fatalf("GetApplied: %v", err)
	}
	if got.GraphHash != second.GraphHash {
		t.Errorf("GetApplied returned stale row")
	}
}

func TestApply_Errors(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.Apply(ctx, uuid.Nil, Selection{Industry: IndustryRetail, Country: "US"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("nil tenant err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.Apply(ctx, uuid.New(), Selection{Industry: "bogus", Country: "US"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("bad industry err = %v, want ErrInvalidArgument", err)
	}
}

func TestGetApplied_NotFound(t *testing.T) {
	svc, _ := newTestService(t)
	if _, err := svc.GetApplied(context.Background(), uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("unapplied tenant err = %v, want ErrNotFound", err)
	}
}

func TestSeedCatalog_Idempotent(t *testing.T) {
	svc, repo := newTestService(t)
	ctx := context.Background()

	if err := svc.SeedCatalog(ctx); err != nil {
		t.Fatalf("SeedCatalog: %v", err)
	}
	rows, err := repo.ListCatalog(ctx)
	if err != nil {
		t.Fatalf("ListCatalog: %v", err)
	}
	if len(rows) != len(svc.catalog) {
		t.Errorf("seeded %d rows, want %d", len(rows), len(svc.catalog))
	}
	// Re-seeding is a no-op.
	if err := svc.SeedCatalog(ctx); err != nil {
		t.Fatalf("re-SeedCatalog: %v", err)
	}
	rows2, err := repo.ListCatalog(ctx)
	if err != nil {
		t.Fatalf("ListCatalog (2nd): %v", err)
	}
	if len(rows2) != len(rows) {
		t.Errorf("re-seed changed row count: %d -> %d", len(rows), len(rows2))
	}
}

func TestNilRepository(t *testing.T) {
	svc := New(nil, nil)
	ctx := context.Background()
	if _, err := svc.Apply(ctx, uuid.New(), Selection{Industry: IndustryRetail, Country: "US"}); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Errorf("Apply err = %v, want ErrRepositoryUnavailable", err)
	}
	if err := svc.SeedCatalog(ctx); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Errorf("SeedCatalog err = %v, want ErrRepositoryUnavailable", err)
	}
	// Catalog-only methods still work.
	if len(svc.ListTemplates()) == 0 {
		t.Error("ListTemplates should work without a repository")
	}
}

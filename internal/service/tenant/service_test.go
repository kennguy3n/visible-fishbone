package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

func newSvc(t *testing.T) (*tenant.Service, *memory.Store) {
	t.Helper()
	s := memory.NewStore()
	return tenant.New(memory.NewTenantRepository(s), memory.NewAuditLogRepository(s), nil), s
}

func TestDeriveSlug(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Acme Corp":     "acme-corp",
		"  Café 99   ":  "caf-99",
		"hello@@@world": "hello-world",
		"---x---":       "x",
		"!!!":           "",
	}
	for in, want := range cases {
		if got := tenant.DeriveSlug(in); got != want {
			t.Errorf("DeriveSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsValidSlug(t *testing.T) {
	t.Parallel()
	good := []string{"a", "acme", "acme-corp", "a-b-c-1", "abc123"}
	bad := []string{"", "-a", "a-", "a--b", "AB", "a_b", string(make([]byte, 70))}
	for _, s := range good {
		if !tenant.IsValidSlug(s) {
			t.Errorf("expected %q valid", s)
		}
	}
	for _, s := range bad {
		if tenant.IsValidSlug(s) {
			t.Errorf("expected %q invalid", s)
		}
	}
}

func TestCreate_DerivesSlugAndAudits(t *testing.T) {
	t.Parallel()
	svc, store := newSvc(t)
	ctx := context.Background()

	got, err := svc.Create(ctx, repository.Tenant{Name: "Acme Corp"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.Slug != "acme-corp" {
		t.Errorf("slug = %q", got.Slug)
	}
	if got.Status != repository.TenantStatusActive {
		t.Errorf("status = %v", got.Status)
	}
	if got.Tier != repository.TenantTierStarter {
		t.Errorf("default tier = %v", got.Tier)
	}

	auditRepo := memory.NewAuditLogRepository(store)
	entries, err := auditRepo.List(ctx, got.ID, repository.AuditFilter{}, repository.Page{})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries.Items) != 1 || entries.Items[0].Action != "tenant.created" {
		t.Errorf("audit = %+v", entries.Items)
	}
}

func TestCreate_RejectsBadSlug(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	_, err := svc.Create(context.Background(), repository.Tenant{Name: "x", Slug: "-bad"})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestCreate_RequiresName(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	_, err := svc.Create(context.Background(), repository.Tenant{})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

func TestSuspendDelete(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	ctx := context.Background()
	tn, err := svc.Create(ctx, repository.Tenant{Name: "T"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	suspended, err := svc.Suspend(ctx, tn.ID)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if suspended.Status != repository.TenantStatusSuspended {
		t.Errorf("status = %v", suspended.Status)
	}

	if err := svc.Delete(ctx, tn.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err := svc.Get(ctx, tn.ID)
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got.Status != repository.TenantStatusDeleted || got.DeletedAt == nil {
		t.Errorf("expected deleted, got %+v", got)
	}
}

func TestSuspend_RejectsNonActive(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	ctx := context.Background()
	tn, err := svc.Create(ctx, repository.Tenant{Name: "SM"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// Suspend it first (valid: active → suspended).
	if _, err := svc.Suspend(ctx, tn.ID); err != nil {
		t.Fatalf("first suspend: %v", err)
	}
	// Second suspend should be rejected (suspended → suspended).
	if _, err := svc.Suspend(ctx, tn.ID); !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("expected ErrForbidden on double suspend, got %v", err)
	}
	// Delete (valid: suspended → deleted).
	if err := svc.Delete(ctx, tn.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// Suspend a deleted tenant should be rejected.
	if _, err := svc.Suspend(ctx, tn.ID); !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("expected ErrForbidden on suspend-after-delete, got %v", err)
	}
}

func TestDelete_RejectsAlreadyDeleted(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	ctx := context.Background()
	tn, err := svc.Create(ctx, repository.Tenant{Name: "DD"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.Delete(ctx, tn.ID); err != nil {
		t.Fatalf("first delete: %v", err)
	}
	if err := svc.Delete(ctx, tn.ID); !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("expected ErrForbidden on double delete, got %v", err)
	}
}

func TestUpdate_RequiresID(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	_, err := svc.Update(context.Background(), uuid.Nil, repository.TenantPatch{})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

func TestGetBySlug(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	ctx := context.Background()
	created, err := svc.Create(ctx, repository.Tenant{Name: "Foo"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.GetBySlug(ctx, created.Slug)
	if err != nil {
		t.Fatalf("get by slug: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("id mismatch: %v vs %v", got.ID, created.ID)
	}
}

func TestList(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := svc.Create(ctx, repository.Tenant{Name: "Tenant " + string(rune('A'+i))}); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	page, err := svc.List(ctx, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 3 {
		t.Errorf("len = %d", len(page.Items))
	}
}

func TestCreate_EmptyDerivedSlugFallback(t *testing.T) {
	t.Parallel()
	svc, _ := newSvc(t)
	tn, err := svc.Create(context.Background(), repository.Tenant{Name: "!!!"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if tn.Slug == "" {
		t.Errorf("expected fallback slug, got empty")
	}
	_ = uuid.Validate
}

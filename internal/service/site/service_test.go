package site_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/site"
)

func newSvc(t *testing.T) (*site.Service, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return site.New(memory.NewSiteRepository(s), memory.NewAuditLogRepository(s), nil), tn.ID
}

func TestCreate_TemplateDefaults(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	ctx := context.Background()
	for tpl := range site.TemplateConfig {
		got, err := svc.Create(ctx, tenantID, nil, repository.Site{
			Name: "S-" + string(tpl), Template: tpl,
		})
		if err != nil {
			t.Fatalf("create %s: %v", tpl, err)
		}
		if len(got.Config) == 0 {
			t.Errorf("template %s: empty config", tpl)
		}
		var m map[string]any
		if err := json.Unmarshal(got.Config, &m); err != nil {
			t.Errorf("template %s: invalid JSON config: %v", tpl, err)
		}
	}
}

func TestCreate_DefaultTemplateBranch(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	got, err := svc.Create(context.Background(), tenantID, nil, repository.Site{Name: "HQ"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.Template != repository.SiteTemplateBranch {
		t.Errorf("template = %v", got.Template)
	}
	if got.Slug != "hq" {
		t.Errorf("slug = %q", got.Slug)
	}
}

func TestCreate_UnknownTemplate(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	_, err := svc.Create(context.Background(), tenantID, nil, repository.Site{
		Name: "x", Template: "nope",
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

func TestCreate_RequiresName(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	_, err := svc.Create(context.Background(), tenantID, nil, repository.Site{})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

func TestCRUDLifecycle(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	ctx := context.Background()
	created, err := svc.Create(ctx, tenantID, nil, repository.Site{Name: "Branch 1"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.Get(ctx, tenantID, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("id mismatch")
	}
	got.Name = "Branch 1 (renamed)"
	updated, err := svc.Update(ctx, tenantID, nil, got)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Branch 1 (renamed)" {
		t.Errorf("name = %q", updated.Name)
	}
	page, err := svc.List(ctx, tenantID, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("len = %d", len(page.Items))
	}
	if err := svc.Delete(ctx, tenantID, created.ID, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.Get(ctx, tenantID, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdate_RequiresID(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	_, err := svc.Update(context.Background(), tenantID, nil, repository.Site{})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

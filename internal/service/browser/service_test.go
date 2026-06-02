package browser_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/browser"
)

func newTestService(t *testing.T) (*browser.Service, uuid.UUID) {
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
	svc := browser.New(
		memory.NewBrowserPolicyRepository(store),
		memory.NewAuditLogRepository(store),
		nil,
	)
	return svc, tenantID
}

func TestCreatePolicy(t *testing.T) {
	t.Parallel()
	svc, tid := newTestService(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, tid, nil, repository.BrowserPolicy{
		Name:   "block-downloads",
		Action: repository.BrowserPolicyActionBlock,
		Scope:  repository.BrowserPolicyScopeUser,
		Rules: []repository.BrowserRule{
			{Type: repository.BrowserRuleTypeDownload, Action: repository.BrowserPolicyActionBlock},
		},
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == uuid.Nil {
		t.Fatal("expected non-nil ID")
	}
	if p.Name != "block-downloads" {
		t.Fatalf("name = %q, want block-downloads", p.Name)
	}
	if len(p.Rules) != 1 {
		t.Fatalf("rules len = %d, want 1", len(p.Rules))
	}
}

func TestCreatePolicy_InvalidAction(t *testing.T) {
	t.Parallel()
	svc, tid := newTestService(t)
	_, err := svc.CreatePolicy(context.Background(), tid, nil, repository.BrowserPolicy{
		Name:   "bad",
		Action: "invalid",
		Scope:  repository.BrowserPolicyScopeUser,
	})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestCreatePolicy_EmptyName(t *testing.T) {
	t.Parallel()
	svc, tid := newTestService(t)
	_, err := svc.CreatePolicy(context.Background(), tid, nil, repository.BrowserPolicy{
		Action: repository.BrowserPolicyActionBlock,
		Scope:  repository.BrowserPolicyScopeUser,
	})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestListPolicies(t *testing.T) {
	t.Parallel()
	svc, tid := newTestService(t)
	ctx := context.Background()

	for i := range 3 {
		if _, err := svc.CreatePolicy(ctx, tid, nil, repository.BrowserPolicy{
			Name:   "policy-" + string(rune('a'+i)),
			Action: repository.BrowserPolicyActionBlock,
			Scope:  repository.BrowserPolicyScopeUser,
		}); err != nil {
			t.Fatalf("create[%d]: %v", i, err)
		}
	}
	res, err := svc.ListPolicies(ctx, tid, repository.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(res.Items) != 3 {
		t.Fatalf("items = %d, want 3", len(res.Items))
	}
}

func TestUpdatePolicy(t *testing.T) {
	t.Parallel()
	svc, tid := newTestService(t)
	ctx := context.Background()

	p, _ := svc.CreatePolicy(ctx, tid, nil, repository.BrowserPolicy{
		Name: "orig", Action: repository.BrowserPolicyActionBlock,
		Scope: repository.BrowserPolicyScopeUser, Enabled: true,
	})

	newName := "renamed"
	updated, err := svc.UpdatePolicy(ctx, tid, p.ID, nil, repository.BrowserPolicyPatch{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "renamed" {
		t.Fatalf("name = %q, want renamed", updated.Name)
	}
}

func TestDeletePolicy(t *testing.T) {
	t.Parallel()
	svc, tid := newTestService(t)
	ctx := context.Background()

	p, _ := svc.CreatePolicy(ctx, tid, nil, repository.BrowserPolicy{
		Name: "to-delete", Action: repository.BrowserPolicyActionBlock,
		Scope: repository.BrowserPolicyScopeUser,
	})

	if err := svc.DeletePolicy(ctx, tid, p.ID, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err := svc.GetPolicy(ctx, tid, p.ID)
	if err == nil {
		t.Fatal("expected not found after delete")
	}
}

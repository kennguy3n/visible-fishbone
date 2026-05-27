package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/audit"
)

func newSvc(t *testing.T) (*audit.Service, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "T", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	return audit.New(memory.NewAuditLogRepository(s)), tn.ID
}

func TestAppendValidation(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	ctx := context.Background()

	cases := []audit.Entry{
		{TenantID: uuid.Nil, Action: "x", ResourceType: "y"},
		{TenantID: tenantID, Action: "", ResourceType: "y"},
		{TenantID: tenantID, Action: "x", ResourceType: ""},
	}
	for i, e := range cases {
		_, err := svc.Append(ctx, e)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Errorf("case %d: err = %v, want ErrInvalidArgument", i, err)
		}
	}
}

func TestAppendAndList(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, err := svc.Append(ctx, audit.Entry{
			TenantID:     tenantID,
			Action:       "thing.done",
			ResourceType: "thing",
			Details:      json.RawMessage(`{"i":1}`),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	page, err := svc.List(ctx, tenantID, audit.ListFilter{}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 5 {
		t.Errorf("len = %d", len(page.Items))
	}
}

func TestListFilters(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	ctx := context.Background()
	actor := uuid.New()
	for _, action := range []string{"a", "b", "a"} {
		_, err := svc.Append(ctx, audit.Entry{
			TenantID: tenantID, ActorID: &actor, Action: action, ResourceType: "r",
		})
		if err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	page, err := svc.List(ctx, tenantID, audit.ListFilter{Action: "a"}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 2 {
		t.Errorf("action filter: len = %d", len(page.Items))
	}

	now := time.Now().UTC()
	future := now.Add(time.Hour)
	page, err = svc.List(ctx, tenantID, audit.ListFilter{From: &future}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 0 {
		t.Errorf("future filter: len = %d", len(page.Items))
	}
}

func TestEmptyDetailsDefaults(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSvc(t)
	got, err := svc.Append(context.Background(), audit.Entry{
		TenantID: tenantID, Action: "x", ResourceType: "y",
	})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if string(got.Details) != `{}` {
		t.Errorf("default details = %q", string(got.Details))
	}
}

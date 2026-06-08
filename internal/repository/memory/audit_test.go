package memory_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// TestAuditLog_GlobalRowsParity pins the cross-backend contract that
// the Postgres impl enforces via RLS: AppendGlobal rows (TenantID ==
// uuid.Nil) are reachable ONLY through ListGlobal, never through a
// tenant-scoped List — including List(uuid.Nil), which must return
// nothing (in Postgres `tenant_id = '0000…'::uuid` never matches a
// NULL row).
func TestAuditLog_GlobalRowsParity(t *testing.T) {
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "AU", Slug: "au",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	ar := memory.NewAuditLogRepository(s)

	g, err := ar.AppendGlobal(ctx(), repository.AuditEntry{
		Action: "app_registry.created", ResourceType: "app_registry",
		Details: json.RawMessage(`{"name":"office365"}`),
	})
	if err != nil {
		t.Fatalf("AppendGlobal: %v", err)
	}
	if g.TenantID != uuid.Nil {
		t.Fatalf("AppendGlobal TenantID = %s, want uuid.Nil", g.TenantID)
	}
	if _, err := ar.Append(ctx(), tnt.ID, repository.AuditEntry{
		Action: "app_registry.override_created", ResourceType: "app_registry",
	}); err != nil {
		t.Fatalf("Append (tenant-scoped): %v", err)
	}

	// ListGlobal sees ONLY the global row.
	gl, err := ar.ListGlobal(ctx(), repository.AuditFilter{ResourceType: "app_registry"}, repository.Page{Limit: 100})
	if err != nil {
		t.Fatalf("ListGlobal: %v", err)
	}
	if len(gl.Items) != 1 || gl.Items[0].ID != g.ID {
		t.Fatalf("ListGlobal = %+v, want exactly the global row %s", gl.Items, g.ID)
	}

	// A tenant's List sees ONLY its own row, never the global row.
	tl, err := ar.List(ctx(), tnt.ID, repository.AuditFilter{ResourceType: "app_registry"}, repository.Page{Limit: 100})
	if err != nil {
		t.Fatalf("List(tenant): %v", err)
	}
	for _, it := range tl.Items {
		if it.ID == g.ID || it.TenantID == uuid.Nil {
			t.Fatalf("tenant List leaked global row: %+v", it)
		}
	}

	// List(uuid.Nil) must return nothing — mirrors Postgres RLS, where
	// the global rows are reachable only via the system-role ListGlobal.
	nl, err := ar.List(ctx(), uuid.Nil, repository.AuditFilter{}, repository.Page{Limit: 100})
	if err != nil {
		t.Fatalf("List(uuid.Nil): %v", err)
	}
	if len(nl.Items) != 0 {
		t.Fatalf("List(uuid.Nil) = %d items, want 0 (global rows must not leak via tenant List)", len(nl.Items))
	}
}

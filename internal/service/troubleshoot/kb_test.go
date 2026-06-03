package troubleshoot_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
)

func seedTenant(t *testing.T, store *memory.Store) uuid.UUID {
	t.Helper()
	repo := memory.NewTenantRepository(store)
	tenant, err := repo.Create(context.Background(), repository.Tenant{
		Name: "test-tenant",
		Slug: "test-" + uuid.New().String()[:8],
	})
	if err != nil {
		t.Fatal(err)
	}
	return tenant.ID
}

func TestKBService_CreateAndGet(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	svc := troubleshoot.NewKBService(kbRepo)

	entry, err := svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategoryConnectivity,
		Title:    "VPN Connection Drops",
		Content:  "Steps to diagnose VPN connectivity issues.",
		Tags:     []string{"vpn", "connectivity"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID == uuid.Nil {
		t.Fatal("expected non-nil ID")
	}
	if entry.Title != "VPN Connection Drops" {
		t.Fatalf("expected title 'VPN Connection Drops', got %q", entry.Title)
	}

	got, err := svc.Get(context.Background(), &tenantID, entry.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != entry.ID {
		t.Fatalf("expected ID %s, got %s", entry.ID, got.ID)
	}
}

func TestKBService_List(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	svc := troubleshoot.NewKBService(kbRepo)

	for _, cat := range []troubleshoot.KBCategory{
		troubleshoot.KBCategoryConnectivity,
		troubleshoot.KBCategoryPolicy,
		troubleshoot.KBCategoryPerformance,
	} {
		_, err := svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
			Category: cat,
			Title:    "Entry for " + string(cat),
			Content:  "Content for " + string(cat),
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	result, err := svc.List(context.Background(), &tenantID, nil, repository.Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(result.Items))
	}

	cat := "connectivity"
	filtered, err := svc.List(context.Background(), &tenantID, &cat, repository.Page{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered.Items) != 1 {
		t.Fatalf("expected 1 filtered item, got %d", len(filtered.Items))
	}
}

func TestKBService_Update(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	svc := troubleshoot.NewKBService(kbRepo)

	entry, err := svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategoryPolicy,
		Title:    "Original Title",
		Content:  "Original content",
	})
	if err != nil {
		t.Fatal(err)
	}

	newTitle := "Updated Title"
	updated, err := svc.Update(context.Background(), &tenantID, entry.ID, repository.KBEntryPatch{
		Title: &newTitle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Title != "Updated Title" {
		t.Fatalf("expected updated title, got %q", updated.Title)
	}
}

func TestKBService_Delete(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	svc := troubleshoot.NewKBService(kbRepo)

	entry, err := svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategoryIdentity,
		Title:    "To Delete",
		Content:  "This will be deleted",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Delete(context.Background(), &tenantID, entry.ID); err != nil {
		t.Fatal(err)
	}

	_, err = svc.Get(context.Background(), &tenantID, entry.ID)
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestKBService_Search(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	svc := troubleshoot.NewKBService(kbRepo)

	_, err := svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategoryConnectivity,
		Title:    "VPN Troubleshooting Guide",
		Content:  "How to diagnose VPN issues",
		Tags:     []string{"vpn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: troubleshoot.KBCategoryPolicy,
		Title:    "Firewall Rules",
		Content:  "How to configure firewall rules",
		Tags:     []string{"firewall"},
	})
	if err != nil {
		t.Fatal(err)
	}

	results, err := svc.Search(context.Background(), &tenantID, "VPN", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(results))
	}
	if results[0].Title != "VPN Troubleshooting Guide" {
		t.Fatalf("expected VPN guide, got %q", results[0].Title)
	}
}

func TestKBService_InvalidCategory(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	svc := troubleshoot.NewKBService(kbRepo)

	_, err := svc.Create(context.Background(), &tenantID, troubleshoot.KBEntry{
		Category: "invalid",
		Title:    "Bad",
		Content:  "Bad content",
	})
	if err == nil {
		t.Fatal("expected error for invalid category")
	}
}

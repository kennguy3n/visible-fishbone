package terraform_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/terraform"
)

func newTestProvider(t *testing.T) (*terraform.Provider, *memory.Store, uuid.UUID) {
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
	provider := terraform.New(terraform.Deps{
		Sites:               memory.NewSiteRepository(store),
		BrowserPolicies:     memory.NewBrowserPolicyRepository(store),
		DataClassifications: memory.NewDataClassificationRepository(store),
		Audit:               memory.NewAuditLogRepository(store),
	}, nil)
	return provider, store, tenantID
}

func TestExportImport_RoundTrip(t *testing.T) {
	t.Parallel()
	provider, store, tenantID := newTestProvider(t)
	ctx := context.Background()

	// Seed some data.
	siteRepo := memory.NewSiteRepository(store)
	_, _ = siteRepo.Create(ctx, tenantID, repository.Site{
		Name: "HQ", Slug: "hq", Template: repository.SiteTemplateBranch,
	})

	bpRepo := memory.NewBrowserPolicyRepository(store)
	_, _ = bpRepo.Create(ctx, tenantID, repository.BrowserPolicy{
		Name: "block-dl", Action: repository.BrowserPolicyActionBlock,
		Scope: repository.BrowserPolicyScopeUser, Enabled: true,
	})

	// Export.
	exported, err := provider.ExportTenantConfig(ctx, tenantID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	var cfg terraform.ExportedConfig
	if err := json.Unmarshal(exported, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if cfg.Version != terraform.ConfigVersion {
		t.Fatalf("version = %d, want %d", cfg.Version, terraform.ConfigVersion)
	}
	if len(cfg.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(cfg.Sites))
	}
	if len(cfg.BrowserPolicies) != 1 {
		t.Fatalf("browser_policies = %d, want 1", len(cfg.BrowserPolicies))
	}

	// Import into a fresh tenant.
	newTenantID := uuid.New()
	_, _ = memory.NewTenantRepository(store).Create(ctx, repository.Tenant{
		ID: newTenantID, Name: "T2", Slug: "t2",
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err := provider.ImportTenantConfig(ctx, newTenantID, exported); err != nil {
		t.Fatalf("import: %v", err)
	}

	// Verify imported data.
	re, _ := provider.ExportTenantConfig(ctx, newTenantID)
	var imported terraform.ExportedConfig
	_ = json.Unmarshal(re, &imported)
	if len(imported.Sites) != 1 {
		t.Fatalf("imported sites = %d, want 1", len(imported.Sites))
	}
}

func TestImport_Upsert(t *testing.T) {
	t.Parallel()
	provider, store, tenantID := newTestProvider(t)
	ctx := context.Background()

	// Seed initial data.
	bpRepo := memory.NewBrowserPolicyRepository(store)
	_, _ = bpRepo.Create(ctx, tenantID, repository.BrowserPolicy{
		Name: "block-dl", Action: repository.BrowserPolicyActionBlock,
		Scope: repository.BrowserPolicyScopeUser, Enabled: true,
	})

	siteRepo := memory.NewSiteRepository(store)
	_, _ = siteRepo.Create(ctx, tenantID, repository.Site{
		Name: "HQ", Slug: "hq", Template: repository.SiteTemplateBranch,
	})

	// Import config that modifies existing resources.
	cfg := terraform.ExportedConfig{
		Version: terraform.ConfigVersion,
		Sites: []terraform.ExportedSite{
			{Name: "HQ-Updated", Slug: "hq", Template: "hub"},
		},
		BrowserPolicies: []terraform.ExportedBrowserPolicy{
			{Name: "block-dl", Action: "allow", Scope: "site", Enabled: false},
		},
	}
	raw, _ := json.Marshal(cfg)
	if err := provider.ImportTenantConfig(ctx, tenantID, raw); err != nil {
		t.Fatalf("import upsert: %v", err)
	}

	// Verify updated data via export.
	exported, _ := provider.ExportTenantConfig(ctx, tenantID)
	var result terraform.ExportedConfig
	_ = json.Unmarshal(exported, &result)

	if len(result.Sites) != 1 {
		t.Fatalf("sites = %d, want 1", len(result.Sites))
	}
	if result.Sites[0].Name != "HQ-Updated" {
		t.Fatalf("site name = %q, want HQ-Updated", result.Sites[0].Name)
	}
	if result.Sites[0].Template != "hub" {
		t.Fatalf("site template = %q, want hub", result.Sites[0].Template)
	}

	if len(result.BrowserPolicies) != 1 {
		t.Fatalf("browser policies = %d, want 1", len(result.BrowserPolicies))
	}
	if result.BrowserPolicies[0].Action != "allow" {
		t.Fatalf("bp action = %q, want allow", result.BrowserPolicies[0].Action)
	}
	if result.BrowserPolicies[0].Enabled {
		t.Fatal("bp enabled = true, want false")
	}
}

func TestImport_InvalidVersion(t *testing.T) {
	t.Parallel()
	provider, _, tenantID := newTestProvider(t)

	err := provider.ImportTenantConfig(context.Background(), tenantID, json.RawMessage(`{"version":999}`))
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestExport_EmptyTenant(t *testing.T) {
	t.Parallel()
	provider, _, tenantID := newTestProvider(t)

	exported, err := provider.ExportTenantConfig(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var cfg terraform.ExportedConfig
	_ = json.Unmarshal(exported, &cfg)
	if cfg.Version != terraform.ConfigVersion {
		t.Fatalf("version = %d, want %d", cfg.Version, terraform.ConfigVersion)
	}
}

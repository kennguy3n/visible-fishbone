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

func TestDetectDrift_NoDrift(t *testing.T) {
	t.Parallel()
	provider, store, tenantID := newTestProvider(t)
	ctx := context.Background()

	siteRepo := memory.NewSiteRepository(store)
	_, _ = siteRepo.Create(ctx, tenantID, repository.Site{
		Name: "HQ", Slug: "hq", Template: repository.SiteTemplateBranch,
	})

	exported, _ := provider.ExportTenantConfig(ctx, tenantID)
	report, err := provider.DetectDrift(ctx, tenantID, exported)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if report.HasDrift {
		t.Fatalf("expected no drift, got %d entries", len(report.Entries))
	}
}

func TestDetectDrift_AddedResource(t *testing.T) {
	t.Parallel()
	provider, store, tenantID := newTestProvider(t)
	ctx := context.Background()

	// Declared has nothing, actual has a site.
	siteRepo := memory.NewSiteRepository(store)
	_, _ = siteRepo.Create(ctx, tenantID, repository.Site{
		Name: "HQ", Slug: "hq", Template: repository.SiteTemplateBranch,
	})

	declared := terraform.ExportedConfig{Version: terraform.ConfigVersion, TenantID: tenantID.String()}
	declaredJSON, _ := json.Marshal(declared)

	report, err := provider.DetectDrift(ctx, tenantID, declaredJSON)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if !report.HasDrift {
		t.Fatal("expected drift")
	}
	found := false
	for _, e := range report.Entries {
		if e.ResourceType == "site" && e.DriftType == terraform.DriftTypeAdded {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected added site drift entry, got %+v", report.Entries)
	}
}

func TestDetectDrift_RemovedResource(t *testing.T) {
	t.Parallel()
	provider, _, tenantID := newTestProvider(t)
	ctx := context.Background()

	// Declared has a site, actual has nothing.
	declared := terraform.ExportedConfig{
		Version:  terraform.ConfigVersion,
		TenantID: tenantID.String(),
		Sites:    []terraform.ExportedSite{{Name: "Ghost", Slug: "ghost", Template: "office"}},
	}
	declaredJSON, _ := json.Marshal(declared)

	report, err := provider.DetectDrift(ctx, tenantID, declaredJSON)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if !report.HasDrift {
		t.Fatal("expected drift")
	}
	found := false
	for _, e := range report.Entries {
		if e.ResourceType == "site" && e.DriftType == terraform.DriftTypeRemoved {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected removed site drift entry, got %+v", report.Entries)
	}
}

func TestDetectDrift_MultipleResourceTypes(t *testing.T) {
	t.Parallel()
	provider, store, tenantID := newTestProvider(t)
	ctx := context.Background()

	// Actual has a browser policy.
	bpRepo := memory.NewBrowserPolicyRepository(store)
	_, _ = bpRepo.Create(ctx, tenantID, repository.BrowserPolicy{
		Name: "extra-bp", Action: repository.BrowserPolicyActionBlock,
		Scope: repository.BrowserPolicyScopeUser,
	})

	// Declared is empty.
	declared := terraform.ExportedConfig{Version: terraform.ConfigVersion, TenantID: tenantID.String()}
	declaredJSON, _ := json.Marshal(declared)

	report, _ := provider.DetectDrift(ctx, tenantID, declaredJSON)
	if !report.HasDrift {
		t.Fatal("expected drift")
	}

	typeMap := map[string]bool{}
	for _, e := range report.Entries {
		typeMap[e.ResourceType] = true
	}
	if !typeMap["browser_policy"] {
		t.Fatalf("expected browser_policy drift, got types: %v", typeMap)
	}
}

func TestDetectDrift_ModifiedResource(t *testing.T) {
	t.Parallel()
	provider, store, tenantID := newTestProvider(t)
	ctx := context.Background()

	siteRepo := memory.NewSiteRepository(store)
	_, _ = siteRepo.Create(ctx, tenantID, repository.Site{
		Name: "HQ", Slug: "hq", Template: repository.SiteTemplateBranch,
	})

	// Declared has same name but different template.
	declared := terraform.ExportedConfig{
		Version:  terraform.ConfigVersion,
		TenantID: tenantID.String(),
		Sites:    []terraform.ExportedSite{{Name: "HQ", Slug: "hq", Template: "hub"}},
	}
	declaredJSON, _ := json.Marshal(declared)

	report, err := provider.DetectDrift(ctx, tenantID, declaredJSON)
	if err != nil {
		t.Fatalf("drift: %v", err)
	}
	if !report.HasDrift {
		t.Fatal("expected drift for modified resource")
	}
	found := false
	for _, e := range report.Entries {
		if e.ResourceType == "site" && e.DriftType == terraform.DriftTypeModified {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected modified site drift entry, got %+v", report.Entries)
	}
}

func TestDetectDrift_InvalidJSON(t *testing.T) {
	t.Parallel()
	provider, _, tenantID := newTestProvider(t)
	_, err := provider.DetectDrift(context.Background(), tenantID, json.RawMessage(`{bad`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestDetectDrift_TenantIDPreserved(t *testing.T) {
	t.Parallel()
	provider, _, tenantID := newTestProvider(t)
	ctx := context.Background()

	declared := terraform.ExportedConfig{Version: terraform.ConfigVersion, TenantID: tenantID.String()}
	declaredJSON, _ := json.Marshal(declared)

	report, _ := provider.DetectDrift(ctx, tenantID, declaredJSON)
	if report.TenantID != tenantID {
		t.Fatalf("tenant_id = %s, want %s", report.TenantID, tenantID)
	}
}

// unused import guard
var _ = uuid.New

package dlp_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

func setup(t *testing.T) (*dlp.Service, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	store.SetClock(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) })

	tenantRepo := memory.NewTenantRepository(store)
	tenant, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "test-dlp", Tier: repository.TenantTierStarter,
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	svc := dlp.New(
		memory.NewDLPPolicyRepository(store),
		memory.NewDLPFingerprintRepository(store),
		memory.NewDLPMatchRepository(store),
		memory.NewDLPModelRepository(store),
		nil,
	)
	return svc, tenant.ID
}

// setupWithBlockedApps mirrors setup but wires a blocked-apps source so
// CompileEndpointBundle folds operator block overrides into the bundle.
func setupWithBlockedApps(t *testing.T, src dlp.BlockedAppsSource) (*dlp.Service, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	store.SetClock(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) })

	tenantRepo := memory.NewTenantRepository(store)
	tenant, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "test-dlp-blocked", Tier: repository.TenantTierStarter,
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	svc := dlp.New(
		memory.NewDLPPolicyRepository(store),
		memory.NewDLPFingerprintRepository(store),
		memory.NewDLPMatchRepository(store),
		memory.NewDLPModelRepository(store),
		nil,
		dlp.WithBlockedApps(src),
	)
	return svc, tenant.ID
}

func TestService_CreateAndListPolicies(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:   "PCI Test",
		Rules:  []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "credit_card"}},
		Action: repository.DLPActionBlock,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if p.ID == uuid.Nil {
		t.Fatal("expected non-nil policy ID")
	}

	result, err := svc.ListPolicies(ctx, tid, repository.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(result.Items))
	}
}

func TestService_CreatePolicy_Validation(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	// Missing name.
	_, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Rules:  []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "email"}},
		Action: repository.DLPActionLog,
	})
	if err == nil {
		t.Fatal("expected error for missing name")
	}

	// No rules.
	_, err = svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:   "Empty",
		Rules:  nil,
		Action: repository.DLPActionLog,
	})
	if err == nil {
		t.Fatal("expected error for empty rules")
	}

	// Invalid action.
	_, err = svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:   "Bad",
		Rules:  []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "email"}},
		Action: repository.DLPAction("invalid"),
	})
	if err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestService_UpdatePolicy(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:   "Update Me",
		Rules:  []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "email"}},
		Action: repository.DLPActionLog,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	newName := "Updated"
	updated, err := svc.UpdatePolicy(ctx, tid, p.ID, repository.DLPPolicyPatch{
		Name: &newName,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "Updated" {
		t.Errorf("expected name 'Updated', got %q", updated.Name)
	}
}

func TestService_DeletePolicy(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:   "Delete Me",
		Rules:  []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "email"}},
		Action: repository.DLPActionLog,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := svc.DeletePolicy(ctx, tid, p.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err = svc.GetPolicy(ctx, tid, p.ID)
	if err == nil {
		t.Fatal("expected error after deletion")
	}
}

func TestService_TestPolicy(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	p, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:   "SSN Detector",
		Rules:  []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "ssn_us"}},
		Action: repository.DLPActionBlock,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	result, err := svc.TestPolicy(ctx, tid, p.ID, []byte("My SSN is 123-45-6789"))
	if err != nil {
		t.Fatalf("test: %v", err)
	}
	if !result.Matched {
		t.Fatal("expected match")
	}
	if result.Action != repository.DLPActionBlock {
		t.Errorf("expected block action, got %q", result.Action)
	}
}

func TestService_Classify(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	_, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Email Policy",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "email"}},
		Action:  repository.DLPActionRedact,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	result, err := svc.Classify(ctx, tid, dlp.ClassificationInput{
		ContentType: "text/plain",
		Content:     []byte("Send to alice@example.com"),
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match")
	}
	if result.Action != repository.DLPActionRedact {
		t.Errorf("expected redact action, got %q", result.Action)
	}
}

func TestService_Classify_MultiplePolices(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	_, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Email Log",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "email"}},
		Action:  repository.DLPActionLog,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create email: %v", err)
	}
	_, err = svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "SSN Block",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: "ssn_us"}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create ssn: %v", err)
	}

	result, err := svc.Classify(ctx, tid, dlp.ClassificationInput{
		ContentType: "text/plain",
		Content:     []byte("Email: alice@test.com SSN: 123-45-6789"),
	})
	if err != nil {
		t.Fatalf("classify: %v", err)
	}
	if len(result.PolicyIDs) != 2 {
		t.Fatalf("expected 2 policy IDs, got %d", len(result.PolicyIDs))
	}
	// Highest action wins.
	if result.Action != repository.DLPActionBlock {
		t.Errorf("expected block (highest severity), got %q", result.Action)
	}
}

func TestService_Templates(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	templates := svc.ListTemplates()
	if len(templates) == 0 {
		t.Fatal("expected at least one template")
	}

	// Apply PCI-DSS template.
	p, err := svc.ApplyTemplate(ctx, tid, "pci-dss")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if p.Name != "PCI-DSS" {
		t.Errorf("expected name 'PCI-DSS', got %q", p.Name)
	}
	if !p.Enabled {
		t.Error("expected policy to be enabled by default")
	}

	// Unknown template.
	_, err = svc.ApplyTemplate(ctx, tid, "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown template")
	}
}

func TestService_Fingerprints(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	content := []byte("this is a sensitive financial document about quarterly earnings and revenue projections for fiscal year 2025")
	fp, err := svc.RegisterFingerprint(ctx, tid, "earnings-q1", "text/plain", content)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if fp.ID == uuid.Nil {
		t.Fatal("expected non-nil fingerprint ID")
	}

	result, err := svc.ListFingerprints(ctx, tid, repository.Page{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(result.Items) != 1 {
		t.Fatalf("expected 1 fingerprint, got %d", len(result.Items))
	}
}

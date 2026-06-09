package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newCountsService(t *testing.T) (*Service, repository.Tenant) {
	t.Helper()
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(s)
	keyRepo := memory.NewPolicySigningKeyRepository(s)
	auditRepo := memory.NewAuditLogRepository(s)
	keys := NewKeyService(keyRepo, auditRepo)
	return New(policyRepo, auditRepo, keys), tnt
}

func TestPolicyCounts_NoGraphIsZero(t *testing.T) {
	t.Parallel()
	svc, tnt := newCountsService(t)
	total, active, err := svc.PolicyCounts(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("PolicyCounts: %v", err)
	}
	if total != 0 || active != 0 {
		t.Fatalf("counts = %d/%d, want 0/0 with no published graph", total, active)
	}
}

func TestPolicyCounts_LegacyGraphFallsBackToVerbatimRules(t *testing.T) {
	t.Parallel()
	// A legacy graph that fails the typed-schema parse (here: an
	// invalid default_action that PutGraph would reject today) must
	// still produce coverage counts rather than a 500 — mirroring
	// Compile's verbatim-rules fallback. We insert it via the repo
	// directly, bypassing PutGraph's typed validation, exactly as a
	// graph written before that validation existed would be stored.
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(s)
	auditRepo := memory.NewAuditLogRepository(s)
	keys := NewKeyService(memory.NewPolicySigningKeyRepository(s), auditRepo)
	svc := New(policyRepo, auditRepo, keys)

	legacy := map[string]any{
		// "permit" is not a valid Verb, so ParseGraph rejects the
		// graph at the default_action check; the rules themselves
		// remain countable from the raw JSON.
		"default_action": "permit",
		"rules": []map[string]any{
			{"id": "ngfw-1", "domain": "ngfw", "verb": "deny"},
			{"id": "swg-1", "domain": "swg", "verb": "inspect"},
			{"id": "dlp-1", "domain": "dlp", "verb": "suggest_only"},
		},
	}
	raw, _ := json.Marshal(legacy)
	if _, err := ParseGraph(raw); err == nil {
		t.Fatal("precondition: legacy graph should fail ParseGraph")
	}
	if _, err := policyRepo.CreateGraph(context.Background(), tnt.ID, repository.PolicyGraph{
		Graph: raw, IsDraft: false,
	}); err != nil {
		t.Fatalf("create legacy graph: %v", err)
	}

	total, active, err := svc.PolicyCounts(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("PolicyCounts on legacy graph: %v", err)
	}
	if total != 3 || active != 2 {
		t.Fatalf("counts = %d/%d, want 3/2 (legacy verbatim fallback, suggest_only excluded)", total, active)
	}
}

func TestPolicyCounts_UnparseableGraphIsEmpty(t *testing.T) {
	t.Parallel()
	// A genuinely opaque stored graph (not even valid JSON with a
	// rules array) reports the honest 0/0 empty state, never a 500.
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(s)
	auditRepo := memory.NewAuditLogRepository(s)
	keys := NewKeyService(memory.NewPolicySigningKeyRepository(s), auditRepo)
	svc := New(policyRepo, auditRepo, keys)

	if _, err := policyRepo.CreateGraph(context.Background(), tnt.ID, repository.PolicyGraph{
		Graph: json.RawMessage(`not json at all`), IsDraft: false,
	}); err != nil {
		t.Fatalf("create opaque graph: %v", err)
	}
	total, active, err := svc.PolicyCounts(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("PolicyCounts on opaque graph: %v", err)
	}
	if total != 0 || active != 0 {
		t.Fatalf("counts = %d/%d, want 0/0 for an unparseable graph", total, active)
	}
}

func TestPolicyCounts_ActiveExcludesSuggestOnly(t *testing.T) {
	t.Parallel()
	svc, tnt := newCountsService(t)
	// 4 rules total; one is suggest_only (a proposed/"dormant" rule),
	// so 3 are actively enforcing.
	graph := map[string]any{
		"default_action": "deny",
		"rules": []map[string]any{
			{"id": "ngfw-1", "domain": "ngfw", "verb": "deny"},
			{"id": "ztna-1", "domain": "ztna", "verb": "allow"},
			{"id": "swg-1", "domain": "swg", "verb": "inspect"},
			{"id": "dlp-1", "domain": "dlp", "verb": "suggest_only"},
		},
	}
	raw, _ := json.Marshal(graph)
	if _, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}
	total, active, err := svc.PolicyCounts(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("PolicyCounts: %v", err)
	}
	if total != 4 || active != 3 {
		t.Fatalf("counts = %d/%d, want 4/3 (suggest_only excluded from active)", total, active)
	}
}

package policy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestCompile_PerTargetRuleSlicing(t *testing.T) {
	t.Parallel()
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
	svc := New(policyRepo, auditRepo, keys)

	graph := map[string]any{
		"default_action": "deny",
		"rules": []map[string]any{
			{"id": "ngfw-1", "domain": "ngfw", "verb": "deny"},
			{"id": "ztna-1", "domain": "ztna", "verb": "allow"},
			{"id": "dlp-1", "domain": "dlp", "verb": "log"},
		},
	}
	raw, _ := json.Marshal(graph)
	if _, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}

	res, err := svc.Compile(context.Background(), tnt.ID, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(res.Bundles) != 4 {
		t.Fatalf("expected 4 bundles, got %d", len(res.Bundles))
	}

	type decoded struct {
		Target string `msgpack:"t"`
		Rules  []struct {
			ID     string `json:"id"`
			Domain string `json:"domain"`
			Verb   string `json:"verb"`
		} `msgpack:"-"`
		RawRules json.RawMessage `msgpack:"r"`
		KeyID    string          `msgpack:"-"`
	}
	for _, b := range res.Bundles {
		var d decoded
		if err := msgpack.Unmarshal(b.Bundle, &d); err != nil {
			t.Fatalf("unmarshal %s: %v", b.TargetType, err)
		}
		var rules []struct {
			ID     string `json:"id"`
			Domain string `json:"domain"`
			Verb   string `json:"verb"`
		}
		if err := json.Unmarshal(d.RawRules, &rules); err != nil {
			t.Fatalf("unmarshal rules %s: %v", b.TargetType, err)
		}
		ids := map[string]bool{}
		for _, r := range rules {
			ids[r.ID] = true
		}
		switch b.TargetType {
		case repository.PolicyBundleTargetEdge:
			// Edge gets NGFW + ZTNA + DLP.
			if !ids["ngfw-1"] || !ids["ztna-1"] || !ids["dlp-1"] {
				t.Errorf("edge bundle missing rules: %v", ids)
			}
		case repository.PolicyBundleTargetEndpoint:
			// Endpoint gets ZTNA + DLP, not NGFW.
			if ids["ngfw-1"] {
				t.Errorf("endpoint bundle leaked ngfw rule")
			}
			if !ids["ztna-1"] || !ids["dlp-1"] {
				t.Errorf("endpoint missing expected rules: %v", ids)
			}
		case repository.PolicyBundleTargetCloud:
			// Cloud gets ZTNA + DLP, not NGFW.
			if ids["ngfw-1"] {
				t.Errorf("cloud bundle leaked ngfw rule")
			}
			if !ids["ztna-1"] || !ids["dlp-1"] {
				t.Errorf("cloud missing expected rules: %v", ids)
			}
		case repository.PolicyBundleTargetMobile:
			// Mobile gets ZTNA only — DLP not yet supported on mobile.
			if ids["ngfw-1"] || ids["dlp-1"] {
				t.Errorf("mobile bundle leaked non-mobile rules: %v", ids)
			}
			if !ids["ztna-1"] {
				t.Errorf("mobile missing ztna rule: %v", ids)
			}
		}
		if b.KeyID == "" {
			t.Errorf("%s bundle has empty key_id", b.TargetType)
		}
	}
}

func TestCompile_BundleSignatureVerifiesAgainstActiveKey(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(s)
	keyRepo := memory.NewPolicySigningKeyRepository(s)
	keys := NewKeyService(keyRepo, nil)
	svc := New(policyRepo, nil, keys)

	if _, err := svc.PutGraph(context.Background(), tnt.ID, nil, json.RawMessage(`{"default_action":"deny"}`)); err != nil {
		t.Fatalf("put: %v", err)
	}
	res, err := svc.Compile(context.Background(), tnt.ID, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	active, err := keys.GetActive(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("active key: %v", err)
	}
	for _, b := range res.Bundles {
		if b.KeyID != active.KeyID {
			t.Errorf("%s bundle key_id %q != active %q", b.TargetType, b.KeyID, active.KeyID)
		}
		if !ed25519.Verify(ed25519.PublicKey(active.PublicKey), b.Bundle, b.Signature) {
			t.Errorf("%s bundle signature did not verify against active public key", b.TargetType)
		}
	}
}

func TestCompile_Determinism(t *testing.T) {
	t.Parallel()
	// The bundle bytes (sans signature, which depends on the
	// per-tenant key generated at random) must be identical across
	// two compiles of the same graph. This is what makes ETag-based
	// caching at the agent boundary safe.
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, _ := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	policyRepo := memory.NewPolicyRepository(s)
	keyRepo := memory.NewPolicySigningKeyRepository(s)
	keys := NewKeyService(keyRepo, nil)
	svc := New(policyRepo, nil, keys)
	raw := json.RawMessage(`{"default_action":"deny","rules":[{"id":"r","domain":"ztna","verb":"allow"}]}`)
	if _, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw); err != nil {
		t.Fatalf("put: %v", err)
	}
	r1, err := svc.Compile(context.Background(), tnt.ID, nil)
	if err != nil {
		t.Fatalf("compile 1: %v", err)
	}
	// Re-encode the same graph (no new PutGraph — we want the same
	// graph_id / graph_version on both compilations).
	graph, err := policyRepo.GetCurrentGraph(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("get graph: %v", err)
	}
	for _, target := range []repository.PolicyBundleTarget{
		repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile,
	} {
		var existing []byte
		for _, b := range r1.Bundles {
			if b.TargetType == target {
				existing = b.Bundle
				break
			}
		}
		if existing == nil {
			t.Fatalf("missing bundle for %s", target)
		}
		fresh, err := encodeBundlePayload(target, graph, r1.Compiled)
		if err != nil {
			t.Fatalf("re-encode %s: %v", target, err)
		}
		if string(fresh) != string(existing) {
			t.Errorf("%s: non-deterministic encode\n  fresh:   %x\n  existing: %x", target, fresh, existing)
		}
	}
	_ = uuid.Nil // silence unused import on some toolchains
}

// TestService_PutGraph_RejectsInvalidTypedSchema verifies that
// PutGraph enforces the typed-graph contract at write time. Prior
// to PR7 Round 2, PutGraph accepted any syntactically-valid JSON
// and only surfaced schema violations implicitly at compile time
// (rules silently fell back to the PR6 broadcast-all-rules path
// when ParseGraph failed). That divergence was inconsistent with
// the documented contract in graph.go (~"operators get schema
// validation at PUT time rather than at compile time"). This test
// pins the corrected behaviour: invalid verbs, domains, targets,
// missing rule ids, duplicate ids, and unresolved subject/predicate
// references must all be rejected with ErrInvalidArgument.
func TestService_PutGraph_RejectsInvalidTypedSchema(t *testing.T) {
	t.Parallel()
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
	keys := NewKeyService(keyRepo, nil)
	svc := New(policyRepo, nil, keys)

	cases := []struct {
		name string
		raw  string
	}{
		{"invalid_default_action_verb", `{"default_action":"yeet"}`},
		{"invalid_rule_domain", `{"default_action":"deny","rules":[{"id":"r1","domain":"not-a-real-domain","verb":"allow"}]}`},
		{"invalid_rule_verb", `{"default_action":"deny","rules":[{"id":"r1","domain":"ztna","verb":"yeet"}]}`},
		{"missing_rule_id", `{"default_action":"deny","rules":[{"domain":"ztna","verb":"allow"}]}`},
		{"duplicate_rule_id", `{"default_action":"deny","rules":[{"id":"r1","domain":"ztna","verb":"allow"},{"id":"r1","domain":"dlp","verb":"log"}]}`},
		{"invalid_target", `{"default_action":"deny","rules":[{"id":"r1","domain":"ztna","verb":"allow","targets":["not-a-target"]}]}`},
		{"unresolved_subject_ref", `{"default_action":"deny","subjects":[{"name":"alice","kind":"user"}],"rules":[{"id":"r1","domain":"ztna","verb":"allow","subject_refs":["bob"]}]}`},
		{"duplicate_subject_name", `{"default_action":"deny","subjects":[{"name":"alice","kind":"user"},{"name":"alice","kind":"user"}]}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.PutGraph(context.Background(), tnt.ID, nil, json.RawMessage(tc.raw))
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("want ErrInvalidArgument, got %v", err)
			}
		})
	}
}

// TestService_PutGraph_AcceptsValidTypedSchema is the positive
// counterpart to ensure the new validator hasn't introduced
// false-positive rejections for legitimate graphs (empty doc,
// default-only, fully-populated typed graph with subjects /
// predicates / rules / targets).
func TestService_PutGraph_AcceptsValidTypedSchema(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, _ := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	policyRepo := memory.NewPolicyRepository(s)
	keyRepo := memory.NewPolicySigningKeyRepository(s)
	keys := NewKeyService(keyRepo, nil)
	svc := New(policyRepo, nil, keys)

	cases := []string{
		`{}`,
		`{"default_action":"deny"}`,
		`{"default_action":"allow","rules":[{"id":"r1","domain":"ngfw","verb":"deny"}]}`,
		`{"default_action":"deny","subjects":[{"name":"alice","kind":"user"}],"predicates":[{"name":"hours"}],"rules":[{"id":"r1","domain":"ztna","verb":"allow","subject_refs":["alice"],"predicate_refs":["hours"],"targets":["edge","cloud"]}]}`,
		// Unknown top-level fields ignored (PR8+ forward compat).
		`{"default_action":"deny","metadata":{"author":"ken","version":2}}`,
	}
	for i, raw := range cases {
		if _, err := svc.PutGraph(context.Background(), tnt.ID, nil, json.RawMessage(raw)); err != nil {
			t.Errorf("case %d (%q): unexpected error: %v", i, raw, err)
		}
	}
}

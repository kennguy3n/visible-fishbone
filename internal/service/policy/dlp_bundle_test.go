package policy

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// fakeDLPCompiler is a tiny DLPEndpointCompiler that returns a fixed
// JSON document, so the policy compile path can be exercised without
// importing the dlp service.
type fakeDLPCompiler struct {
	doc json.RawMessage
	err error
}

func (f fakeDLPCompiler) CompileEndpointBundle(_ context.Context, _ uuid.UUID) (json.RawMessage, error) {
	return f.doc, f.err
}

// dlpDecoded is the subset of the wire bundle these tests inspect.
type dlpDecoded struct {
	Target string          `msgpack:"t"`
	Dlp    json.RawMessage `msgpack:"dl"`
}

func compileBundles(t *testing.T, opts ...ServiceOption) []repository.PolicyBundle {
	t.Helper()
	ctx := context.Background()
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(ctx, repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(s)
	keyRepo := memory.NewPolicySigningKeyRepository(s)
	auditRepo := memory.NewAuditLogRepository(s)
	keys := NewKeyService(keyRepo, auditRepo)
	svc := New(policyRepo, auditRepo, keys, opts...)

	graph := map[string]any{"default_action": "deny", "rules": []map[string]any{}}
	raw, _ := json.Marshal(graph)
	if _, err := svc.PutGraph(ctx, tnt.ID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}
	res, err := svc.Compile(ctx, tnt.ID, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return res.Bundles
}

// TestCompile_DLPSectionRidesEndpointOnly locks in the
// DLPEndpointCompiler contract: the endpoint DLP document is embedded
// in the endpoint bundle's `dl` section verbatim and in no other
// target's bundle.
func TestCompile_DLPSectionRidesEndpointOnly(t *testing.T) {
	t.Parallel()
	doc := json.RawMessage(`{"schema_version":1,"target":"endpoint","domain":"dlp","rules":[],"ai_app":{"enabled":true,"block_opt_in":false,"block_confidence":0.9,"min_report_confidence":0.5,"coach_severity_floor":"high"}}`)

	bundles := compileBundles(t, WithDLPEndpointCompiler(fakeDLPCompiler{doc: doc}))

	var sawEndpoint bool
	for _, b := range bundles {
		var d dlpDecoded
		if err := msgpack.Unmarshal(b.Bundle, &d); err != nil {
			t.Fatalf("unmarshal %s bundle: %v", b.TargetType, err)
		}
		if b.TargetType == repository.PolicyBundleTargetEndpoint {
			sawEndpoint = true
			if len(d.Dlp) == 0 {
				t.Fatal("endpoint bundle missing dl section")
			}
			// The bytes must survive the round-trip unchanged so the
			// agent's sng-dlp decoder sees exactly what was compiled.
			if !json.Valid(d.Dlp) {
				t.Fatalf("dl section is not valid JSON: %s", d.Dlp)
			}
			var got map[string]any
			if err := json.Unmarshal(d.Dlp, &got); err != nil {
				t.Fatalf("decode dl section: %v", err)
			}
			if got["domain"] != "dlp" || got["target"] != "endpoint" {
				t.Errorf("dl section shape = %v", got)
			}
			if _, ok := got["ai_app"]; !ok {
				t.Error("dl section missing ai_app block (detector would stay disarmed)")
			}
		} else if len(d.Dlp) != 0 {
			t.Errorf("%s bundle should not carry a dl section, got %s", b.TargetType, d.Dlp)
		}
	}
	if !sawEndpoint {
		t.Fatal("no endpoint bundle produced")
	}
}

// TestCompile_NoDLPCompilerOmitsSection locks in the "When nil, the
// section is omitted" contract: without a wired DLP compiler, no
// bundle (endpoint included) carries a dl section.
func TestCompile_NoDLPCompilerOmitsSection(t *testing.T) {
	t.Parallel()
	bundles := compileBundles(t)
	for _, b := range bundles {
		var d dlpDecoded
		if err := msgpack.Unmarshal(b.Bundle, &d); err != nil {
			t.Fatalf("unmarshal %s bundle: %v", b.TargetType, err)
		}
		if len(d.Dlp) != 0 {
			t.Errorf("%s bundle carries a dl section despite nil DLP compiler: %s", b.TargetType, d.Dlp)
		}
	}
}

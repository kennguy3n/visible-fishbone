package policy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newDryRunFixture(t *testing.T) (*Service, repository.PolicyGraph, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	keys := NewKeyService(keyRepo, auditRepo)
	svc := New(policyRepo, auditRepo, keys)

	raw, _ := json.Marshal(map[string]any{
		"default_action": "deny",
		"rules": []map[string]any{
			{"id": "ngfw-1", "domain": "ngfw", "verb": "deny"},
		},
	})
	graph, err := svc.PutGraph(context.Background(), tnt.ID, nil, raw)
	if err != nil {
		t.Fatalf("put graph: %v", err)
	}
	return svc, graph, tnt.ID
}

func TestDryRunSubject_Format(t *testing.T) {
	t.Parallel()
	tenantID := uuid.New()
	simID := uuid.New()
	got := DryRunSubject(tenantID, simID)
	want := "sng." + tenantID.String() + ".telemetry.verdict.dryrun." + simID.String()
	if got != want {
		t.Fatalf("subject = %q, want %q", got, want)
	}
}

func TestCompileDryRun_SignerRequired(t *testing.T) {
	t.Parallel()
	// Construct a Service WITHOUT a signer to exercise the
	// guard. We can't use the fixture (which always wires a
	// KeyService) so we build the minimum directly.
	store := memory.NewStore()
	policyRepo := memory.NewPolicyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	svc := New(policyRepo, auditRepo, nil)
	_, err := svc.CompileDryRun(context.Background(), uuid.New(),
		repository.PolicyGraph{ID: uuid.New(), Graph: json.RawMessage(`{"default_action":"deny"}`)},
		DryRunOptions{})
	if !errors.Is(err, ErrDryRunSignerRequired) {
		t.Fatalf("err = %v, want ErrDryRunSignerRequired", err)
	}
}

func TestCompileDryRun_GeneratesSimulationID(t *testing.T) {
	t.Parallel()
	svc, graph, tenantID := newDryRunFixture(t)
	dr1, err := svc.CompileDryRun(context.Background(), tenantID, graph, DryRunOptions{})
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	dr2, err := svc.CompileDryRun(context.Background(), tenantID, graph, DryRunOptions{})
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if dr1.SimulationID == uuid.Nil || dr2.SimulationID == uuid.Nil {
		t.Fatalf("simulation id missing")
	}
	if dr1.SimulationID == dr2.SimulationID {
		t.Fatalf("two compiles produced identical simulation id; expected unique generation")
	}
}

func TestCompileDryRun_HonoursSuppliedSimulationID(t *testing.T) {
	t.Parallel()
	svc, graph, tenantID := newDryRunFixture(t)
	want := uuid.New()
	dr, err := svc.CompileDryRun(context.Background(), tenantID, graph, DryRunOptions{SimulationID: want})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if dr.SimulationID != want {
		t.Fatalf("simulation id = %s, want %s", dr.SimulationID, want)
	}
	wantSubject := DryRunSubject(tenantID, want)
	if dr.Subject != wantSubject {
		t.Fatalf("subject = %q, want %q", dr.Subject, wantSubject)
	}
}

func TestCompileDryRun_CompilesAllTargets(t *testing.T) {
	t.Parallel()
	svc, graph, tenantID := newDryRunFixture(t)
	dr, err := svc.CompileDryRun(context.Background(), tenantID, graph, DryRunOptions{})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(dr.Bundles) == 0 {
		t.Fatalf("no bundles")
	}
	// Each bundle's wire form must carry bundle_kind = "dry_run"
	// so an agent unpacking it diverts to log-only execution.
	for _, b := range dr.Bundles {
		// Wire tags match dryRunBundlePayload (msgpack tags
		// `k`, `sim`, `sub` — see encodeDryRunBundle).
		var p struct {
			Kind         string `msgpack:"k"`
			SimulationID string `msgpack:"sim"`
			Subject      string `msgpack:"sub"`
		}
		if err := msgpack.Unmarshal(b.Bundle, &p); err != nil {
			t.Fatalf("unmarshal %s: %v", b.TargetType, err)
		}
		if p.Kind != "dry_run" {
			t.Fatalf("bundle %s kind = %q, want dry_run", b.TargetType, p.Kind)
		}
		if p.SimulationID != dr.SimulationID.String() {
			t.Fatalf("bundle %s sim id = %q, want %s", b.TargetType, p.SimulationID, dr.SimulationID)
		}
		if !strings.HasPrefix(p.Subject, "sng.") || !strings.Contains(p.Subject, ".dryrun.") {
			t.Fatalf("bundle %s subject malformed: %q", b.TargetType, p.Subject)
		}
		if len(b.Signature) == 0 {
			t.Fatalf("bundle %s signature missing", b.TargetType)
		}
		if b.KeyID == "" {
			t.Fatalf("bundle %s key_id missing", b.TargetType)
		}
		if b.ID != uuid.Nil {
			t.Fatalf("bundle %s ID = %s, must be zero (in-memory only)", b.TargetType, b.ID)
		}
	}
}

func TestCompileDryRun_RestrictsToSuppliedTargets(t *testing.T) {
	t.Parallel()
	svc, graph, tenantID := newDryRunFixture(t)
	dr, err := svc.CompileDryRun(context.Background(), tenantID, graph, DryRunOptions{
		Targets: []repository.PolicyBundleTarget{repository.PolicyBundleTargetEdge},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(dr.Bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(dr.Bundles))
	}
	if dr.Bundles[0].TargetType != repository.PolicyBundleTargetEdge {
		t.Fatalf("target = %s, want edge", dr.Bundles[0].TargetType)
	}
}

func TestCompileDryRun_DoesNotPersist(t *testing.T) {
	t.Parallel()
	svc, graph, tenantID := newDryRunFixture(t)
	// Capture the current canonical bundle (which may be empty
	// because we haven't compiled the live path yet).
	before, _ := svc.GetLatestBundle(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if _, err := svc.CompileDryRun(context.Background(), tenantID, graph, DryRunOptions{}); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	after, _ := svc.GetLatestBundle(context.Background(), tenantID, repository.PolicyBundleTargetEdge)
	if !bundlesEqual(before, after) {
		t.Fatalf("dry-run compile must NOT mutate live bundle (before=%v after=%v)", before, after)
	}
}

func bundlesEqual(a, b repository.PolicyBundle) bool {
	if a.ID != b.ID {
		return false
	}
	if len(a.Bundle) != len(b.Bundle) {
		return false
	}
	for i := range a.Bundle {
		if a.Bundle[i] != b.Bundle[i] {
			return false
		}
	}
	return true
}

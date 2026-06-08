package policy_test

// This integration test proves the full WORKSTREAM 8 path the unit
// tests exercise in pieces: seed the threat-intel IOCStore, wire the
// ai.IOCEnforcementCompiler into policy.Service via WithIOCCompiler /
// WithMalwareHashCompiler, Compile a signed bundle, and assert that
//
//  1. the IP / domain / URL indicators land as deny rules in the
//     compiled bundle (and the file hash lands in the `mw` malware
//     section for the SWG-bearing targets), and
//  2. traffic matching those indicators is actually blocked, by
//     replaying flow / DNS / HTTP envelopes through the same
//     GraphEvaluator the policy simulator uses and checking the
//     verdict is "deny" while unrelated traffic is allowed.
//
// It lives in the external policy_test package so it can import both
// the policy service and the ai compiler without the ai->policy
// import cycle that an in-package test would create.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

const (
	iocIP     = "203.0.113.10"
	iocDomain = "evil.example.com"
	iocURL    = "http://bad.example/payload"
	iocHost   = "bad.example"
	iocHash   = "a1b2c3d4e5f6071829304a5b6c7d8e9f00112233445566778899aabbccddeeff"
)

// seedStore builds an IOCStore with one high-confidence indicator of
// each enforceable type.
func seedStore(t *testing.T) *ai.IOCStore {
	t.Helper()
	store := ai.NewIOCStore()
	mk := func(typ ai.IOCType, v string, conf float64) ai.IOC {
		ioc, ok := ai.NewIOC(typ, v, ai.IOCMeta{
			Source:     "taxii:test",
			Confidence: conf,
			LastSeen:   time.Now().UTC(),
		})
		if !ok {
			t.Fatalf("seed: invalid indicator %q", v)
		}
		return ioc
	}
	res := store.Upsert(
		mk(ai.IOCTypeIP, iocIP, 0.95),
		mk(ai.IOCTypeDomain, iocDomain, 0.92),
		mk(ai.IOCTypeURL, iocURL, 0.9),
		mk(ai.IOCTypeHash, iocHash, 0.97),
	)
	if res.Added != 4 {
		t.Fatalf("seed upsert added %d, want 4 (%#v)", res.Added, res)
	}
	return store
}

// decodedBundle is the subset of the wire bundle this test inspects.
type decodedBundle struct {
	Target   string          `msgpack:"t"`
	RawRules json.RawMessage `msgpack:"r"`
	Malware  json.RawMessage `msgpack:"mw"`
}

func TestIOCToBundleToBlock_Integration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := seedStore(t)
	compiler := ai.NewIOCEnforcementCompiler(store)

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
	keys := policy.NewKeyService(keyRepo, auditRepo)

	svc := policy.New(policyRepo, auditRepo, keys,
		policy.WithIOCCompiler(compiler),
		policy.WithMalwareHashCompiler(compiler),
	)

	// A minimal base graph that allows by default with no base
	// rules — every block in this test must come from the folded-in
	// IOC rules, and any unrelated traffic falls through to the
	// default allow.
	graph := map[string]any{
		"default_action": "allow",
		"rules":          []map[string]any{},
	}
	raw, _ := json.Marshal(graph)
	if _, err := svc.PutGraph(ctx, tnt.ID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}

	res, err := svc.Compile(ctx, tnt.ID, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// --- Assertion 1: indicators land in the compiled bundle. ---
	var edge decodedBundle
	for _, b := range res.Bundles {
		if b.TargetType == repository.PolicyBundleTargetEdge {
			if err := msgpack.Unmarshal(b.Bundle, &edge); err != nil {
				t.Fatalf("unmarshal edge bundle: %v", err)
			}
		}
	}
	if edge.Target != string(repository.PolicyBundleTargetEdge) {
		t.Fatalf("edge bundle not found in compile result")
	}

	ruleIDs, ruleByID := decodeRules(t, edge.RawRules)
	for _, want := range []string{
		"ti-ngfw-" + iocIP,
		"ti-dns-" + iocDomain,
		"ti-swg-" + iocHost,
	} {
		if !ruleIDs[want] {
			t.Errorf("compiled edge bundle missing IOC rule %q; have %v", want, ruleIDs)
		}
		if r, ok := ruleByID[want]; ok && r.Verb != "deny" {
			t.Errorf("IOC rule %q is not a deny: verb=%q", want, r.Verb)
		}
	}

	// The file hash rides the malware section, not the rule slice.
	if len(edge.Malware) == 0 {
		t.Fatal("edge bundle missing malware (mw) section")
	}
	var mw []policy.MalwareHashEntry
	if err := json.Unmarshal(edge.Malware, &mw); err != nil {
		t.Fatalf("decode malware section: %v", err)
	}
	foundHash := false
	for _, e := range mw {
		if e.Hash == iocHash {
			foundHash = true
			if e.Verdict != "malicious" {
				t.Errorf("hash verdict: got %q want malicious", e.Verdict)
			}
		}
	}
	if !foundHash {
		t.Errorf("malware section missing seeded hash %q: %#v", iocHash, mw)
	}

	// --- Assertion 2: matching traffic is blocked. ---
	// Replay envelopes through a GraphEvaluator built from exactly
	// the rules that shipped in the bundle — this is the simulator's
	// own block-prediction path, so a "deny" here means a real edge
	// would block the flow/query/request.
	eval := evaluatorFromBundleRules(t, edge.RawRules)

	assertVerdict(t, eval, flowEnvelope(t, tnt.ID, iocIP), schema.VerdictDeny, "flow to malicious IP")
	assertVerdict(t, eval, dnsEnvelope(t, tnt.ID, iocDomain), schema.VerdictDeny, "DNS query for sinkholed domain")
	assertVerdict(t, eval, httpEnvelope(t, tnt.ID, iocHost), schema.VerdictDeny, "HTTP request to SWG-denied host")

	// Unrelated traffic is unaffected (falls through to the default
	// allow). DNS and HTTP negative controls are used because their
	// matchers key on the query/host the IOC rules constrain; an
	// indicator that doesn't match leaves the request on the default
	// path.
	assertVerdict(t, eval, dnsEnvelope(t, tnt.ID, "good.example.org"), schema.VerdictAllow, "DNS query for clean domain")
	assertVerdict(t, eval, httpEnvelope(t, tnt.ID, "good.example"), schema.VerdictAllow, "HTTP request to clean host")
}

// --- helpers ---

type decodedRule struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	Verb   string `json:"verb"`
}

func decodeRules(t *testing.T, rawRules json.RawMessage) (map[string]bool, map[string]decodedRule) {
	t.Helper()
	var rules []decodedRule
	if err := json.Unmarshal(rawRules, &rules); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	ids := map[string]bool{}
	byID := map[string]decodedRule{}
	for _, r := range rules {
		ids[r.ID] = true
		byID[r.ID] = r
	}
	return ids, byID
}

// evaluatorFromBundleRules wraps the bundle's per-target rule slice
// in a graph and builds the same GraphEvaluator the policy simulator
// uses, so the test evaluates the exact rules that shipped.
func evaluatorFromBundleRules(t *testing.T, rawRules json.RawMessage) policy.Evaluator {
	t.Helper()
	graph := map[string]json.RawMessage{
		"default_action": json.RawMessage(`"allow"`),
		"rules":          rawRules,
	}
	graphJSON, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("marshal eval graph: %v", err)
	}
	eval, err := policy.GraphEvaluatorFactory{}.Build(context.Background(), repository.PolicyGraph{
		ID:    uuid.New(),
		Graph: graphJSON,
	})
	if err != nil {
		t.Fatalf("build evaluator: %v", err)
	}
	return eval
}

func assertVerdict(t *testing.T, eval policy.Evaluator, env schema.Envelope, want schema.Verdict, desc string) {
	t.Helper()
	got, err := eval.Evaluate(context.Background(), env)
	if err != nil {
		t.Fatalf("evaluate %s: %v", desc, err)
	}
	if got != want {
		t.Errorf("%s: verdict = %q, want %q", desc, got, want)
	}
}

func baseEnvelope(tenantID uuid.UUID, cls schema.EventClass) schema.Envelope {
	return schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      tenantID,
		DeviceID:      uuid.New(),
		Timestamp:     time.Now().UTC(),
		EventClass:    cls,
		Platform:      schema.PlatformLinux,
	}
}

func flowEnvelope(t *testing.T, tenantID uuid.UUID, dstIP string) schema.Envelope {
	t.Helper()
	env := baseEnvelope(tenantID, schema.EventClassFlow)
	payload, err := schema.PackPayload(schema.FlowEvent{
		SrcIP: "10.0.0.5", DstIP: dstIP, Protocol: "tcp", DstPort: 443,
		Verdict: schema.VerdictAllow,
	})
	if err != nil {
		t.Fatalf("pack flow: %v", err)
	}
	env.Payload = payload
	return env
}

func dnsEnvelope(t *testing.T, tenantID uuid.UUID, query string) schema.Envelope {
	t.Helper()
	env := baseEnvelope(tenantID, schema.EventClassDNS)
	payload, err := schema.PackPayload(schema.DNSEvent{
		Query: query, QType: "A", Verdict: schema.VerdictAllow,
	})
	if err != nil {
		t.Fatalf("pack dns: %v", err)
	}
	env.Payload = payload
	return env
}

func httpEnvelope(t *testing.T, tenantID uuid.UUID, host string) schema.Envelope {
	t.Helper()
	env := baseEnvelope(tenantID, schema.EventClassHTTP)
	payload, err := schema.PackPayload(schema.HTTPEvent{
		Method: "GET", Host: host, URL: "http://" + host + "/payload",
		Verdict: schema.VerdictAllow,
	})
	if err != nil {
		t.Fatalf("pack http: %v", err)
	}
	env.Payload = payload
	return env
}

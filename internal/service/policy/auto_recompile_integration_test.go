package policy_test

// This integration test proves the WORKSTREAM 8 follow-up auto-recompile
// path end to end: a feed refresh ingests a fresh indicator, the
// FeedManager's OnUpdate hook Triggers the Recompiler, and the
// Recompiler drives a policy Compile WITHOUT any operator-issued
// Compile call — so the freshly-ingested indicator lands in the
// enforcement bundle on its own.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func TestAutoRecompileOnFeedUpdate_Integration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Store starts EMPTY: the only way the indicator can reach a
	// bundle is via the feed refresh -> OnUpdate -> auto-recompile
	// path under test.
	store := ai.NewIOCStore()
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

	graph := map[string]any{"default_action": "allow", "rules": []map[string]any{}}
	raw, _ := json.Marshal(graph)
	if _, err := svc.PutGraph(ctx, tnt.ID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}

	// The recompile callback the Recompiler invokes. It performs the
	// only Compile in this test and captures the result for assertion.
	var (
		mu       sync.Mutex
		lastRes  policy.CompileResult
		compiled = make(chan struct{}, 4)
	)
	recompiler := ai.NewRecompiler(func(ctx context.Context) error {
		res, err := svc.Compile(ctx, tnt.ID, nil)
		mu.Lock()
		lastRes = res
		mu.Unlock()
		compiled <- struct{}{}
		return err
	})

	// Wire the feed manager so a successful refresh Triggers a
	// recompile. The store is the same instance the compiler reads.
	feed := ai.Feed{
		Name:    "ti-csv",
		Parser:  ai.CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.95},
		Fetcher: ai.StaticFetcher{Data: []byte("evil.example.com\n")},
	}
	mgr := ai.NewFeedManager(store, []ai.Feed{feed},
		ai.WithOnUpdate(func(context.Context, ai.IOCSnapshot) {
			recompiler.Trigger()
		}),
	)

	recompiler.Start(ctx)
	defer recompiler.Stop()
	mgr.Start(ctx) // warm-up refresh fires OnUpdate -> Trigger
	defer mgr.Stop()

	// Wait for the auto-recompile to run. No manual Compile is called
	// anywhere in the test body.
	select {
	case <-compiled:
	case <-time.After(5 * time.Second):
		t.Fatal("auto-recompile never ran after feed update")
	}

	mu.Lock()
	res := lastRes
	mu.Unlock()

	// The auto-compiled bundle must contain the IOC deny rule for the
	// indicator the feed just ingested.
	var edge struct {
		Target   string          `msgpack:"t"`
		RawRules json.RawMessage `msgpack:"r"`
	}
	for _, b := range res.Bundles {
		if b.TargetType == repository.PolicyBundleTargetEdge {
			if err := msgpack.Unmarshal(b.Bundle, &edge); err != nil {
				t.Fatalf("unmarshal edge bundle: %v", err)
			}
		}
	}
	if edge.Target != string(repository.PolicyBundleTargetEdge) {
		t.Fatalf("edge bundle not found in auto-compile result")
	}

	var rules []struct {
		ID   string `json:"id"`
		Verb string `json:"verb"`
	}
	if err := json.Unmarshal(edge.RawRules, &rules); err != nil {
		t.Fatalf("decode rules: %v", err)
	}
	want := "ti-dns-evil.example.com"
	found := false
	for _, r := range rules {
		if r.ID == want {
			found = true
			if r.Verb != "deny" {
				t.Errorf("auto-compiled IOC rule %q verb=%q, want deny", want, r.Verb)
			}
		}
	}
	if !found {
		t.Fatalf("auto-compiled bundle missing feed-ingested IOC rule %q; rules=%+v", want, rules)
	}
}

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func fixedSnapshot(s IOCSnapshot) func() IOCSnapshot {
	return func() IOCSnapshot { return s }
}

func TestIOCEnforcementCompiler_RulesByDomainAndConfidenceFloor(t *testing.T) {
	t.Parallel()
	snap := IOCSnapshot{
		IPs: []IOC{
			mkIOC(IOCTypeIP, "203.0.113.10", 0.9),
			mkIOC(IOCTypeIP, "203.0.113.11", 0.3), // below floor -> dropped
		},
		Domains: []IOC{mkIOC(IOCTypeDomain, "evil.example.com", 0.8)},
		URLs: []IOC{
			mkIOC(IOCTypeURL, "http://bad.example/a", 0.7),
			mkIOC(IOCTypeURL, "http://bad.example/b", 0.95), // same host -> collapses
		},
	}
	c := newIOCEnforcementCompilerFromSnapshot(fixedSnapshot(snap))
	rules, err := c.CompileIOCRules(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}

	byID := map[string]policy.Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	if _, ok := byID["ti-ngfw-203.0.113.10"]; !ok {
		t.Errorf("missing NGFW deny rule; rules=%v", byID)
	}
	if _, ok := byID["ti-ngfw-203.0.113.11"]; ok {
		t.Errorf("below-floor IP must not compile to a rule")
	}
	if r, ok := byID["ti-dns-evil.example.com"]; !ok || r.Domain != policy.DomainDNS || r.Verb != policy.VerbDeny {
		t.Errorf("DNS sinkhole rule wrong: %#v", r)
	}
	// Two URLs on the same host collapse into a single SWG rule.
	swgCount := 0
	for id := range byID {
		if id == "ti-swg-bad.example" {
			swgCount++
		}
	}
	if swgCount != 1 {
		t.Errorf("expected 1 collapsed SWG rule for shared host, got %d", swgCount)
	}

	// Predicate of the NGFW rule must carry the dst_ip match the
	// evaluator understands.
	ngfw := byID["ti-ngfw-203.0.113.10"]
	if len(ngfw.Predicates) != 1 {
		t.Fatalf("ngfw predicates: %#v", ngfw.Predicates)
	}
	var m map[string]string
	if err := json.Unmarshal(ngfw.Predicates[0].Match, &m); err != nil {
		t.Fatalf("predicate match decode: %v", err)
	}
	if m["dst_ip"] != "203.0.113.10" {
		t.Errorf("ngfw predicate dst_ip: %#v", m)
	}
}

func TestIOCEnforcementCompiler_MalwareVerdictThresholds(t *testing.T) {
	t.Parallel()
	snap := IOCSnapshot{
		Hashes: []IOC{
			mkIOC(IOCTypeHash, sampleSHA256, 0.9), // >= maliciousThreshold(0.8)
			mkIOC(IOCTypeHash, sampleMD5, 0.65),   // suspicious band
			mkIOC(IOCTypeHash, sampleSHA1, 0.2),   // below floor -> dropped
		},
	}
	c := newIOCEnforcementCompilerFromSnapshot(fixedSnapshot(snap))
	entries, err := c.CompileMalwareHashes(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("compile malware: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 malware entries, got %d (%#v)", len(entries), entries)
	}
	verdict := map[string]string{}
	for _, e := range entries {
		verdict[e.Hash] = e.Verdict
	}
	if verdict[sampleSHA256] != "malicious" {
		t.Errorf("high-confidence hash should be malicious: %q", verdict[sampleSHA256])
	}
	if verdict[sampleMD5] != "suspicious" {
		t.Errorf("mid-confidence hash should be suspicious: %q", verdict[sampleMD5])
	}
	if _, ok := verdict[sampleSHA1]; ok {
		t.Errorf("below-floor hash must be dropped")
	}
}

// stubEmitter records demotion calls for the bridge test.
type stubEmitter struct {
	domains []string
}

func (s *stubEmitter) EmitDomainDemotion(_ context.Context, domain, _ string, _ time.Time) error {
	s.domains = append(s.domains, domain)
	return nil
}

func TestDemotionBridge_EmitsAboveFloorDomains(t *testing.T) {
	t.Parallel()
	em := &stubEmitter{}
	bridge := NewDemotionBridge(em)
	snap := IOCSnapshot{
		Domains: []IOC{
			mkIOC(IOCTypeDomain, "evil.example.com", 0.9),
			mkIOC(IOCTypeDomain, "low.example.com", 0.1), // below floor
		},
	}
	if err := bridge.Sync(context.Background(), snap); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(em.domains) != 1 || em.domains[0] != "evil.example.com" {
		t.Fatalf("bridge emitted: %#v", em.domains)
	}
}

// TestDemotionBridge_SkipsUnchangedDomainsAcrossSyncs guards the
// delta behaviour: re-syncing the same snapshot (as happens when N
// feeds each fire the OnUpdate hook with the shared merged store)
// must not re-emit an already-demoted domain, but a domain whose
// LastSeen advanced (the feed re-observed it) is re-emitted so the
// override is re-established if it was cleared.
func TestDemotionBridge_SkipsUnchangedDomainsAcrossSyncs(t *testing.T) {
	t.Parallel()
	em := &stubEmitter{}
	bridge := NewDemotionBridge(em)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	snap := IOCSnapshot{Domains: []IOC{
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9, func(i *IOC) { i.LastSeen = t0 }),
	}}

	// First two syncs carry the same sighting → emit once only.
	for i := 0; i < 2; i++ {
		if err := bridge.Sync(context.Background(), snap); err != nil {
			t.Fatalf("sync %d: %v", i, err)
		}
	}
	if len(em.domains) != 1 {
		t.Fatalf("unchanged re-sync re-emitted: %#v", em.domains)
	}

	// LastSeen advances (feed re-observed the domain) → re-emit.
	snap2 := IOCSnapshot{Domains: []IOC{
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9, func(i *IOC) { i.LastSeen = t0.Add(time.Hour) }),
	}}
	if err := bridge.Sync(context.Background(), snap2); err != nil {
		t.Fatalf("advanced sync: %v", err)
	}
	if len(em.domains) != 2 {
		t.Fatalf("advanced LastSeen should re-emit, got: %#v", em.domains)
	}
}

// TestDemotionBridge_RetriesAfterEmitError confirms a domain whose
// emit fails is not recorded as synced, so the next refresh retries
// it rather than silently dropping it from enforcement.
func TestDemotionBridge_RetriesAfterEmitError(t *testing.T) {
	t.Parallel()
	em := &flakyEmitter{failFirst: true}
	bridge := NewDemotionBridge(em)
	snap := IOCSnapshot{Domains: []IOC{
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9, func(i *IOC) {
			i.LastSeen = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
		}),
	}}
	if err := bridge.Sync(context.Background(), snap); err == nil {
		t.Fatal("first sync should surface the emit error")
	}
	if err := bridge.Sync(context.Background(), snap); err != nil {
		t.Fatalf("retry sync: %v", err)
	}
	if em.calls != 2 {
		t.Fatalf("failed domain should be retried, calls = %d", em.calls)
	}
}

// TestDemotionBridge_PrunesDepartedDomains guards the unbounded-map
// concern: a domain that leaves the store (TTL sweep) is dropped
// from the bridge's tracking, and if it later returns it is
// re-emitted rather than silently skipped.
func TestDemotionBridge_PrunesDepartedDomains(t *testing.T) {
	t.Parallel()
	em := &stubEmitter{}
	bridge := NewDemotionBridge(em)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	with := IOCSnapshot{Domains: []IOC{
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9, func(i *IOC) { i.LastSeen = t0 }),
	}}

	if err := bridge.Sync(context.Background(), with); err != nil {
		t.Fatalf("seed sync: %v", err)
	}
	// Domain expired out of the store → empty snapshot prunes it.
	if err := bridge.Sync(context.Background(), IOCSnapshot{}); err != nil {
		t.Fatalf("empty sync: %v", err)
	}
	if len(bridge.emitted) != 0 {
		t.Fatalf("departed domain not pruned: %#v", bridge.emitted)
	}
	// Same domain, same LastSeen returns → must re-emit (override may
	// have been cleared while it was gone), not be skipped as stale.
	if err := bridge.Sync(context.Background(), with); err != nil {
		t.Fatalf("re-add sync: %v", err)
	}
	if len(em.domains) != 2 {
		t.Fatalf("returning domain should re-emit, got: %#v", em.domains)
	}
}

// TestDemotionBridge_PrunesDepartedDomainOnChurn covers the
// equal-size churn case: one domain expires as another arrives, so
// len(emitted) == len(present) yet a departed entry must still be
// pruned (a size-comparison guard would wrongly skip it).
func TestDemotionBridge_PrunesDepartedDomainOnChurn(t *testing.T) {
	t.Parallel()
	em := &stubEmitter{}
	bridge := NewDemotionBridge(em)
	t0 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(v string) IOC {
		return mkIOC(IOCTypeDomain, v, 0.9, func(i *IOC) { i.LastSeen = t0 })
	}

	// Seed A + B.
	if err := bridge.Sync(context.Background(), IOCSnapshot{Domains: []IOC{mk("a.example.com"), mk("b.example.com")}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A expires, C arrives → present={B,C}, emitted was {A,B}: equal size.
	if err := bridge.Sync(context.Background(), IOCSnapshot{Domains: []IOC{mk("b.example.com"), mk("c.example.com")}}); err != nil {
		t.Fatalf("churn: %v", err)
	}
	if _, stale := bridge.emitted["a.example.com"]; stale {
		t.Fatalf("departed domain A not pruned on equal-size churn: %#v", bridge.emitted)
	}
	// A returns with the same LastSeen → must re-emit (not blocked by a
	// stale entry).
	if err := bridge.Sync(context.Background(), IOCSnapshot{Domains: []IOC{mk("a.example.com")}}); err != nil {
		t.Fatalf("return: %v", err)
	}
	got := map[string]int{}
	for _, d := range em.domains {
		got[d]++
	}
	if got["a.example.com"] != 2 {
		t.Fatalf("returning domain A should re-emit, emits=%#v", em.domains)
	}
}

// flakyEmitter fails its first EmitDomainDemotion call, then
// succeeds, to exercise the retry path.
type flakyEmitter struct {
	failFirst bool
	calls     int
}

func (e *flakyEmitter) EmitDomainDemotion(_ context.Context, _, _ string, _ time.Time) error {
	e.calls++
	if e.failFirst && e.calls == 1 {
		return errors.New("emit failed")
	}
	return nil
}

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
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
		CIDRs: []IOC{
			mkIOC(IOCTypeCIDR, "198.51.100.0/24", 0.9),
			mkIOC(IOCTypeCIDR, "198.51.100.0/25", 0.3), // below floor -> dropped
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
	if r, ok := byID["ti-ngfw-198.51.100.0/24"]; !ok || r.Domain != policy.DomainNGFW || r.Verb != policy.VerbDeny {
		t.Errorf("missing NGFW CIDR deny rule: %#v", r)
	}
	if _, ok := byID["ti-ngfw-198.51.100.0/25"]; ok {
		t.Errorf("below-floor CIDR must not compile to a rule")
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

	// Predicate of the single-IP NGFW rule must carry the TAGGED
	// dst_cidr matcher the edge enforces, with the host folded to a
	// /32 (so a host IOC and a range IOC ride one matcher).
	ngfw := byID["ti-ngfw-203.0.113.10"]
	if len(ngfw.Predicates) != 1 {
		t.Fatalf("ngfw predicates: %#v", ngfw.Predicates)
	}
	var m map[string]string
	if err := json.Unmarshal(ngfw.Predicates[0].Match, &m); err != nil {
		t.Fatalf("predicate match decode: %v", err)
	}
	if m["kind"] != "dst_cidr" || m["cidr"] != "203.0.113.10/32" {
		t.Errorf("ngfw IP predicate should be a /32 dst_cidr: %#v", m)
	}
	// The CIDR rule carries the range verbatim.
	cidrRule := byID["ti-ngfw-198.51.100.0/24"]
	var cm map[string]string
	if err := json.Unmarshal(cidrRule.Predicates[0].Match, &cm); err != nil {
		t.Fatalf("cidr predicate match decode: %v", err)
	}
	if cm["kind"] != "dst_cidr" || cm["cidr"] != "198.51.100.0/24" {
		t.Errorf("ngfw CIDR predicate wrong: %#v", cm)
	}
}

func TestIOCEnforcementCompiler_HostIPAndExplicitSlash32Collapse(t *testing.T) {
	t.Parallel()
	// The same address arriving both as a bare IP and as an explicit
	// /32 CIDR (e.g. via different feed attribute labels) folds to one
	// dst_cidr matcher; only a single deny rule should be emitted. The
	// host-IP rule is emitted first and wins.
	snap := IOCSnapshot{
		IPs:   []IOC{mkIOC(IOCTypeIP, "203.0.113.10", 0.9)},
		CIDRs: []IOC{mkIOC(IOCTypeCIDR, "203.0.113.10/32", 0.9)},
	}
	c := newIOCEnforcementCompilerFromSnapshot(fixedSnapshot(snap))
	rules, err := c.CompileIOCRules(context.Background(), uuid.New())
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	var ngfw []policy.Rule
	for _, r := range rules {
		if r.Domain == policy.DomainNGFW {
			ngfw = append(ngfw, r)
		}
	}
	if len(ngfw) != 1 {
		t.Fatalf("expected 1 deduped NGFW rule, got %d: %#v", len(ngfw), ngfw)
	}
	if ngfw[0].ID != "ti-ngfw-203.0.113.10" {
		t.Errorf("host-IP rule should win the dedup, got ID %q", ngfw[0].ID)
	}
	var m map[string]string
	if err := json.Unmarshal(ngfw[0].Predicates[0].Match, &m); err != nil {
		t.Fatalf("predicate decode: %v", err)
	}
	if m["cidr"] != "203.0.113.10/32" {
		t.Errorf("folded predicate cidr wrong: %#v", m)
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

// countingEmitter is a thread-safe emitter that records how many
// times each domain was demoted. It is used by the concurrency test
// since the bridge now calls the emitter outside its own mutex.
type countingEmitter struct {
	mu     sync.Mutex
	counts map[string]int
}

func newCountingEmitter() *countingEmitter {
	return &countingEmitter{counts: make(map[string]int)}
}

func (e *countingEmitter) EmitDomainDemotion(_ context.Context, domain, _ string, _ time.Time) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counts[domain]++
	return nil
}

// TestDemotionBridge_ConcurrentSyncNoRace runs many feed goroutines
// calling Sync concurrently against the same bridge (mirroring the
// FeedManager fan-out). It guards the emit-outside-the-lock refactor:
// the run must be race-free (go test -race) and, because the sighting
// never advances after the first emit, every domain must be demoted
// at least once and the emitted map must converge to exactly the live
// domain set.
func TestDemotionBridge_ConcurrentSyncNoRace(t *testing.T) {
	t.Parallel()
	em := newCountingEmitter()
	bridge := NewDemotionBridge(em)

	seen := time.Now()
	domains := []IOC{
		mkIOC(IOCTypeDomain, "a.example.com", 0.9, func(i *IOC) { i.LastSeen = seen }),
		mkIOC(IOCTypeDomain, "b.example.com", 0.9, func(i *IOC) { i.LastSeen = seen }),
		mkIOC(IOCTypeDomain, "c.example.com", 0.9, func(i *IOC) { i.LastSeen = seen }),
	}
	snap := IOCSnapshot{Domains: domains}

	const goroutines = 16
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := bridge.Sync(context.Background(), snap); err != nil {
					t.Errorf("sync: %v", err)
				}
			}
		}()
	}
	wg.Wait()

	em.mu.Lock()
	defer em.mu.Unlock()
	for _, ioc := range domains {
		if em.counts[ioc.Value] < 1 {
			t.Errorf("domain %q never demoted under concurrency", ioc.Value)
		}
	}
	// The emitted map must hold exactly the three live domains: the
	// delta guard collapses repeats and the unconditional prune drops
	// nothing here (all three stay present).
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if len(bridge.emitted) != len(domains) {
		t.Fatalf("emitted map = %d entries, want %d (%#v)", len(bridge.emitted), len(domains), bridge.emitted)
	}
}

// TestIOCEnforcementCompiler_SnapshotIOCSharesOneSnapshot verifies
// that SnapshotIOC captures the store exactly once and that both
// CompileIOCRules and CompileMalwareHashes on the returned view
// derive from that single capture — the cross-plane consistency
// guarantee policy.Service.compileIOCEnforcement relies on. The
// snapshot func mutates its output after the first call, so a second
// capture would yield empty planes and fail the assertions.
func TestIOCEnforcementCompiler_SnapshotIOCSharesOneSnapshot(t *testing.T) {
	t.Parallel()
	var calls int
	snapFn := func() IOCSnapshot {
		calls++
		if calls == 1 {
			return IOCSnapshot{
				IPs:    []IOC{mkIOC(IOCTypeIP, "203.0.113.10", 0.9)},
				Hashes: []IOC{mkIOC(IOCTypeHash, "a1b2c3d4e5f6071829304a5b6c7d8e9f00112233445566778899aabbccddeeff", 0.97)},
			}
		}
		return IOCSnapshot{} // a second capture would surface as empty planes
	}
	c := newIOCEnforcementCompilerFromSnapshot(snapFn)

	view, err := c.SnapshotIOC(context.Background(), uuid.Nil)
	if err != nil {
		t.Fatalf("snapshot ioc: %v", err)
	}
	if calls != 1 {
		t.Fatalf("SnapshotIOC took %d snapshots, want 1", calls)
	}

	rules, err := view.CompileIOCRules()
	if err != nil {
		t.Fatalf("compile rules: %v", err)
	}
	hashes, err := view.CompileMalwareHashes()
	if err != nil {
		t.Fatalf("compile malware: %v", err)
	}
	if calls != 1 {
		t.Fatalf("compiling the two planes re-snapshotted the store: calls=%d, want 1", calls)
	}
	if len(rules) != 1 {
		t.Errorf("want 1 IP deny rule from the captured snapshot, got %d (%#v)", len(rules), rules)
	}
	if len(hashes) != 1 {
		t.Errorf("want 1 malware hash from the captured snapshot, got %d (%#v)", len(hashes), hashes)
	}
}

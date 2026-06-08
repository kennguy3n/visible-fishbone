package ai

import (
	"context"
	"encoding/json"
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

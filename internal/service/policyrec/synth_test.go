package policyrec

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func flowEnv(t *testing.T, dstIP, proto string, dstPort uint16, verdict schema.Verdict) schema.Envelope {
	t.Helper()
	payload, err := schema.PackPayload(schema.FlowEvent{
		SrcIP:    "10.1.1.1",
		DstIP:    dstIP,
		SrcPort:  12345,
		DstPort:  dstPort,
		Protocol: proto,
		Verdict:  verdict,
	})
	if err != nil {
		t.Fatalf("pack flow: %v", err)
	}
	return schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      uuid.New(),
		DeviceID:      uuid.New(),
		Timestamp:     time.Unix(100, 0),
		EventClass:    schema.EventClassFlow,
		Platform:      "linux",
		Payload:       payload,
	}
}

func dnsEnv(t *testing.T, query string, verdict schema.Verdict) schema.Envelope {
	t.Helper()
	payload, err := schema.PackPayload(schema.DNSEvent{Query: query, QType: "A", Verdict: verdict})
	if err != nil {
		t.Fatalf("pack dns: %v", err)
	}
	return schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      uuid.New(),
		DeviceID:      uuid.New(),
		Timestamp:     time.Unix(100, 0),
		EventClass:    schema.EventClassDNS,
		Platform:      "linux",
		Payload:       payload,
	}
}

func httpEnv(t *testing.T, host, method string, verdict schema.Verdict) schema.Envelope {
	t.Helper()
	payload, err := schema.PackPayload(schema.HTTPEvent{Method: method, URL: "https://" + host + "/", Host: host, StatusCode: 200, Verdict: verdict})
	if err != nil {
		t.Fatalf("pack http: %v", err)
	}
	return schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      uuid.New(),
		DeviceID:      uuid.New(),
		Timestamp:     time.Unix(100, 0),
		EventClass:    schema.EventClassHTTP,
		Platform:      "linux",
		Payload:       payload,
	}
}

func TestSynthesize_DefaultDenyAndCIDRAggregation(t *testing.T) {
	t.Parallel()
	events := []schema.Envelope{
		flowEnv(t, "10.0.0.5", "tcp", 443, schema.VerdictAllow),
		flowEnv(t, "10.0.0.9", "tcp", 443, schema.VerdictAllow), // same /24, same proto/port -> same rule
		flowEnv(t, "10.0.0.5", "tcp", 22, schema.VerdictAllow),  // different port -> distinct rule
	}
	graph, stats := Synthesize(events, SynthesisOptions{})

	if graph.DefaultAction != policy.VerbDeny {
		t.Fatalf("default_action = %q, want deny", graph.DefaultAction)
	}
	if len(graph.Rules) != 2 {
		t.Fatalf("rules = %d, want 2 (443 and 22 aggregated to /24)", len(graph.Rules))
	}
	if stats.ObservedPermitted != 3 {
		t.Fatalf("observed permitted = %d, want 3", stats.ObservedPermitted)
	}
	for _, r := range graph.Rules {
		if r.Verb != policy.VerbAllow || r.Domain != policy.DomainNGFW {
			t.Fatalf("rule %s: verb=%q domain=%q", r.ID, r.Verb, r.Domain)
		}
	}

	// The synthesized graph must pass the same validation the policy
	// compiler enforces.
	raw, err := json.Marshal(graph)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := policy.ParseGraph(raw); err != nil {
		t.Fatalf("synthesized graph failed policy validation: %v", err)
	}
}

func TestSynthesize_ExcludesDeniedTraffic(t *testing.T) {
	t.Parallel()
	events := []schema.Envelope{
		flowEnv(t, "10.0.0.5", "tcp", 443, schema.VerdictAllow),
		flowEnv(t, "203.0.113.7", "tcp", 23, schema.VerdictDeny), // telnet, blocked -> never re-allowed
	}
	graph, _ := Synthesize(events, SynthesisOptions{})
	if len(graph.Rules) != 1 {
		t.Fatalf("rules = %d, want 1 (denied traffic excluded)", len(graph.Rules))
	}
}

func TestSynthesize_DNSAndHTTP(t *testing.T) {
	t.Parallel()
	events := []schema.Envelope{
		dnsEnv(t, "api.example.com", schema.VerdictAllow),
		dnsEnv(t, "api.example.com", schema.VerdictAllow), // dedup
		dnsEnv(t, "bad.example.net", schema.VerdictDeny),  // excluded
		httpEnv(t, "portal.example.com", "GET", schema.VerdictAllow),
	}
	graph, stats := Synthesize(events, SynthesisOptions{})
	var dns, swg int
	for _, r := range graph.Rules {
		switch r.Domain {
		case policy.DomainDNS:
			dns++
		case policy.DomainSWG:
			swg++
		}
	}
	if dns != 1 || swg != 1 {
		t.Fatalf("dns=%d swg=%d, want 1 and 1", dns, swg)
	}
	if stats.PerClassObserved["dns"] != 2 || stats.PerClassObserved["http"] != 1 {
		t.Fatalf("per-class observed = %+v", stats.PerClassObserved)
	}
}

func TestSynthesize_NoiseFloor(t *testing.T) {
	t.Parallel()
	events := []schema.Envelope{
		dnsEnv(t, "frequent.example.com", schema.VerdictAllow),
		dnsEnv(t, "frequent.example.com", schema.VerdictAllow),
		dnsEnv(t, "oneoff.example.com", schema.VerdictAllow), // single observation -> dropped
	}
	graph, stats := Synthesize(events, SynthesisOptions{MinObservations: 2})
	if len(graph.Rules) != 1 {
		t.Fatalf("rules = %d, want 1 (noise floor drops single-observation group)", len(graph.Rules))
	}
	if stats.DroppedGroups != 1 {
		t.Fatalf("dropped groups = %d, want 1", stats.DroppedGroups)
	}
}

func TestSynthesize_MaxRulesTruncationKeepsHighestFrequency(t *testing.T) {
	t.Parallel()
	var events []schema.Envelope
	// "keep.example.com" observed 5x, three other domains once each.
	for i := 0; i < 5; i++ {
		events = append(events, dnsEnv(t, "keep.example.com", schema.VerdictAllow))
	}
	events = append(events,
		dnsEnv(t, "drop1.example.com", schema.VerdictAllow),
		dnsEnv(t, "drop2.example.com", schema.VerdictAllow),
	)
	graph, stats := Synthesize(events, SynthesisOptions{MaxRules: 1})
	if len(graph.Rules) != 1 {
		t.Fatalf("rules = %d, want 1 (MaxRules cap)", len(graph.Rules))
	}
	if !stats.Truncated || stats.DroppedGroups != 2 {
		t.Fatalf("truncated=%v dropped=%d, want true and 2", stats.Truncated, stats.DroppedGroups)
	}
	if got := graph.Rules[0].ID; got != "rec-dns-keep.example.com" {
		t.Fatalf("kept rule = %q, want the highest-frequency group", got)
	}
}

func TestSynthesize_DeterministicOutput(t *testing.T) {
	t.Parallel()
	events := []schema.Envelope{
		httpEnv(t, "b.example.com", "GET", schema.VerdictAllow),
		dnsEnv(t, "a.example.com", schema.VerdictAllow),
		flowEnv(t, "192.168.1.20", "udp", 53, schema.VerdictAllow),
	}
	g1, _ := Synthesize(events, SynthesisOptions{})
	g2, _ := Synthesize(events, SynthesisOptions{})
	b1, _ := json.Marshal(g1)
	b2, _ := json.Marshal(g2)
	if string(b1) != string(b2) {
		t.Fatalf("synthesis is not deterministic:\n%s\n%s", b1, b2)
	}
}

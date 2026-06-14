package ai

import (
	"strings"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// containsLineWith reports whether some line contains every substring.
func containsLineWith(lines []string, subs ...string) bool {
	for _, ln := range lines {
		all := true
		for _, s := range subs {
			if !strings.Contains(ln, s) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// TestClassifyRuleCategory_Parity exercises the Go port of the edge
// classifier across the precedence ladder (msg tactic > classtype >
// whole-line keyword). The same battery is asserted on the Rust side
// (crates/sng-ips classify parity test) so the producer's per-category
// counts match the edge's hit-stat grouping.
func TestClassifyRuleCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		line string
		want policy.IPSRuleCategory
	}{
		{`alert tls any any -> any any (msg:"SNG THREATINTEL C2 ja3 client fingerprint"; classtype:command-and-control; sid:1; rev:1;)`, policy.IPSCategoryC2},
		{`alert dns any any -> any any (msg:"SNG THREATINTEL MALWARE dns query"; classtype:trojan-activity; sid:2; rev:1;)`, policy.IPSCategoryMalware},
		{`alert ip any any -> any any (msg:"SNG THREATINTEL EXPLOIT destination address"; classtype:web-application-attack; sid:3; rev:1;)`, policy.IPSCategoryExploit},
		{`alert ip any any -> any any (msg:"SNG THREATINTEL DOS destination address"; classtype:denial-of-service; sid:4; rev:1;)`, policy.IPSCategoryDoS},
		{`alert dns any any -> any any (msg:"SNG THREATINTEL EXFIL dns query"; sid:5; rev:1;)`, policy.IPSCategoryExfiltration},
		{`alert dns any any -> any any (msg:"SNG THREATINTEL LATERAL dns query"; sid:6; rev:1;)`, policy.IPSCategoryLateralMovement},
		{`alert ip any any -> any any (msg:"SNG THREATINTEL GENERIC destination address"; classtype:misc-activity; sid:7; rev:1;)`, policy.IPSCategoryOther},
		// msg tactic beats classtype (exfil named in msg wins over a c2 classtype).
		{`alert dns any any -> any any (msg:"EXFIL beacon"; classtype:command-and-control; sid:8; rev:1;)`, policy.IPSCategoryExfiltration},
		// whole-line keyword fallback when neither msg nor classtype classify.
		{`alert tcp any any -> any any (msg:"generic"; content:"trojan-dropper"; sid:9; rev:1;)`, policy.IPSCategoryMalware},
		// boundary: "collateral" must NOT match the "lateral" token.
		{`alert ip any any -> any any (msg:"collateral note"; classtype:misc-activity; sid:10; rev:1;)`, policy.IPSCategoryOther},
	}
	for _, tc := range cases {
		if got := classifyRuleCategory(tc.line); got != tc.want {
			t.Errorf("classifyRuleCategory(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

// TestIPSRuleCompiler_EmitsCategorizedRules verifies each IOC type
// compiles to a syntactically-plausible Suricata rule that the edge
// classifier buckets into the producer's intended category.
func TestIPSRuleCompiler_EmitsCategorizedRules(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(
		mkIOC(IOCTypeJA3, sampleJA3, 0.9),
		mkIOC(IOCTypeDomain, "malware-drop.example", 0.9),
		mkIOC(IOCTypeIP, "203.0.113.10", 0.9, func(i *IOC) { i.Campaign = "Emotet botnet" }),
		mkIOC(IOCTypeCIDR, "198.51.100.0/24", 0.9, func(i *IOC) { i.Source = "exfil-tracker" }),
	)
	set := NewIPSRuleCompiler(store).Compile()

	if set.Total != 4 {
		t.Fatalf("Total = %d, want 4\n%s", set.Total, set.RulesText)
	}
	lines := strings.Split(strings.TrimRight(set.RulesText, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d rule lines:\n%s", len(lines), set.RulesText)
	}

	// JA3 -> tls ja3.hash content; C2 by default.
	if !containsLineWith(lines, "ja3.hash", `content:"`+sampleJA3+`"`) {
		t.Errorf("no ja3.hash rule for the fingerprint:\n%s", set.RulesText)
	}
	// Domain -> dns.query content.
	if !containsLineWith(lines, "dns.query", `content:"malware-drop.example"`) {
		t.Errorf("no dns.query rule for the domain:\n%s", set.RulesText)
	}
	// IP -> ip rule with the address as dst.
	if !containsLineWith(lines, "alert ip", "-> 203.0.113.10 any") {
		t.Errorf("no ip rule for the address:\n%s", set.RulesText)
	}
	// CIDR -> ip rule with the range as dst.
	if !containsLineWith(lines, "alert ip", "-> 198.51.100.0/24 any") {
		t.Errorf("no ip rule for the cidr:\n%s", set.RulesText)
	}

	// Every line must carry a unique sid >= the reserved base, rev:1,
	// and the provenance metadata.
	seenSID := map[string]bool{}
	for _, ln := range lines {
		if !strings.Contains(ln, "rev:1;") {
			t.Errorf("rule missing rev:1: %q", ln)
		}
		if !strings.Contains(ln, "metadata:sng_threatintel ") {
			t.Errorf("rule missing provenance metadata: %q", ln)
		}
		sid := extractRuleOption(strings.ToLower(ln), "sid")
		if sid == "" || seenSID[sid] {
			t.Errorf("missing/duplicate sid %q in %q", sid, ln)
		}
		seenSID[sid] = true
	}

	// Efficacy metric: JA3 -> C2, domain/ip -> Malware,
	// exfil-tracker CIDR -> Exfiltration. Every category present.
	if got := set.ByCategory[policy.IPSCategoryC2]; got != 1 {
		t.Errorf("C2 count = %d, want 1", got)
	}
	if got := set.ByCategory[policy.IPSCategoryMalware]; got != 2 {
		t.Errorf("Malware count = %d, want 2 (domain + ip)", got)
	}
	if got := set.ByCategory[policy.IPSCategoryExfiltration]; got != 1 {
		t.Errorf("Exfiltration count = %d, want 1 (exfil-tracker cidr)", got)
	}
	if _, ok := set.ByCategory[policy.IPSCategoryDoS]; !ok {
		t.Errorf("DoS category missing from the stable row set")
	}
	// Counts must reconcile with the total.
	var sum int
	for _, n := range set.ByCategory {
		sum += n
	}
	if sum != set.Total {
		t.Errorf("category sum %d != total %d", sum, set.Total)
	}
}

// TestIPSRuleCompiler_ConfidenceGate drops sub-threshold indicators.
func TestIPSRuleCompiler_ConfidenceGate(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(
		mkIOC(IOCTypeJA3, sampleJA3, 0.9),
		mkIOC(IOCTypeDomain, "low.example", 0.3),
	)
	set := NewIPSRuleCompiler(store, WithIPSMinConfidence(0.5)).Compile()
	if set.Total != 1 {
		t.Fatalf("Total = %d, want 1 (sub-threshold domain dropped)\n%s", set.Total, set.RulesText)
	}
	if strings.Contains(set.RulesText, "low.example") {
		t.Errorf("sub-threshold domain leaked into rules:\n%s", set.RulesText)
	}
}

// TestIPSRuleCompiler_Deterministic verifies stable ordering and sids
// across compiles of the same snapshot (so a republished bundle is
// byte-identical when the store is unchanged).
func TestIPSRuleCompiler_Deterministic(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(
		mkIOC(IOCTypeDomain, "b.example", 0.9),
		mkIOC(IOCTypeDomain, "a.example", 0.9),
		mkIOC(IOCTypeJA3, sampleJA3, 0.9),
	)
	c := NewIPSRuleCompiler(store)
	first := c.Compile().RulesText
	second := c.Compile().RulesText
	if first != second {
		t.Fatalf("non-deterministic output:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	// a.example must sort before b.example (sids ascending by sortKey).
	ai := strings.Index(first, "a.example")
	bi := strings.Index(first, "b.example")
	if ai < 0 || bi < 0 || ai > bi {
		t.Fatalf("domains not in deterministic order:\n%s", first)
	}
}

// TestIPSRuleCompiler_Empty yields an empty rule set and a full-zero
// category row set.
func TestIPSRuleCompiler_Empty(t *testing.T) {
	t.Parallel()
	set := NewIPSRuleCompiler(NewIOCStore()).Compile()
	if set.Total != 0 || set.RulesText != "" {
		t.Fatalf("empty store produced %d rules: %q", set.Total, set.RulesText)
	}
	if len(set.ByCategory) != len(policy.AllIPSRuleCategories()) {
		t.Fatalf("ByCategory should carry every category, got %d", len(set.ByCategory))
	}
}

// TestIPSRuleCompiler_AttributionDrivesCategory verifies feed
// attribution keywords steer the category and that the emitted rule
// classifies back to that same category on the edge.
func TestIPSRuleCompiler_AttributionDrivesCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mut  func(*IOC)
		want policy.IPSRuleCategory
	}{
		{func(i *IOC) { i.Source = "et-lateral" }, policy.IPSCategoryLateralMovement},
		{func(i *IOC) { i.Campaign = "DDoS booter" }, policy.IPSCategoryDoS},
		{func(i *IOC) { i.ThreatActor = "CVE-2024-1234 exploit kit" }, policy.IPSCategoryExploit},
		{func(i *IOC) { i.Source = "ransomware-tracker" }, policy.IPSCategoryMalware},
	}
	for i, tc := range cases {
		store := NewIOCStore()
		store.Upsert(mkIOC(IOCTypeDomain, "x.example", 0.9, tc.mut))
		set := NewIPSRuleCompiler(store).Compile()
		if set.ByCategory[tc.want] != 1 {
			t.Errorf("case %d: category %q count = %d, want 1\n%s", i, tc.want, set.ByCategory[tc.want], set.RulesText)
		}
	}
}

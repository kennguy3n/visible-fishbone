package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestParseGraph_Empty(t *testing.T) {
	t.Parallel()
	g, err := ParseGraph(nil)
	if err != nil {
		t.Fatalf("parse nil: %v", err)
	}
	if g.DefaultAction != VerbDeny {
		t.Errorf("default action: want deny, got %q", g.DefaultAction)
	}
	if len(g.Rules) != 0 {
		t.Errorf("rules: want empty, got %d", len(g.Rules))
	}
}

func TestParseGraph_Valid(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
		"default_action": "allow",
		"subjects": [
			{"name": "engineering", "kind": "user"}
		],
		"predicates": [
			{"name": "weekend"}
		],
		"rules": [
			{"id": "r-ngfw-deny-tor", "domain": "ngfw", "verb": "deny", "subject_refs": ["engineering"]},
			{"id": "r-ztna-allow-prod", "domain": "ztna", "verb": "allow", "predicate_refs": ["weekend"]}
		]
	}`)
	g, err := ParseGraph(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if g.DefaultAction != VerbAllow {
		t.Errorf("default: %q", g.DefaultAction)
	}
	if len(g.Rules) != 2 {
		t.Errorf("rules count: %d", len(g.Rules))
	}
}

func TestParseGraph_PreservesUnknownRuleFields(t *testing.T) {
	t.Parallel()
	// The contract advertised on Rule.Extra is that unknown
	// rule fields survive a parse/compile round-trip. Without
	// Rule.UnmarshalJSON, the json:"-" tag would drop them
	// silently. Compile the rule for its routing target and
	// confirm the unknown key reappears in the encoded output.
	// Use compact JSON so the Extra round-trip can be compared
	// byte-for-byte without normalising whitespace (Extra values
	// are stored as raw bytes from the input document).
	raw := json.RawMessage(`{"rules":[{"id":"r1","domain":"ngfw","verb":"deny","vendor_specific":{"acme":7}}]}`)
	g, err := ParseGraph(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(g.Rules) != 1 {
		t.Fatalf("rule count: %d", len(g.Rules))
	}
	extra, ok := g.Rules[0].Extra["vendor_specific"]
	if !ok {
		t.Fatalf("vendor_specific dropped from Extra: %+v", g.Rules[0].Extra)
	}
	if string(extra) != `{"acme":7}` {
		t.Errorf("Extra value mangled: %s", extra)
	}
	encoded, err := EncodeRules(g.Rules)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.Contains(string(encoded), `"vendor_specific":{"acme":7}`) {
		t.Errorf("vendor_specific not in encoded output: %s", encoded)
	}
}

func TestParseGraph_Invalid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{"bad default verb", `{"default_action": "nope"}`},
		{"bad domain", `{"rules": [{"id": "x", "domain": "made-up", "verb": "deny"}]}`},
		{"bad verb", `{"rules": [{"id": "x", "domain": "ngfw", "verb": "noooo"}]}`},
		{"duplicate rule id", `{"rules": [{"id": "r1", "domain": "ngfw", "verb": "deny"}, {"id": "r1", "domain": "ngfw", "verb": "deny"}]}`},
		{"unknown subject ref", `{"rules": [{"id": "r1", "domain": "ngfw", "verb": "deny", "subject_refs": ["ghost"]}]}`},
		{"unknown predicate ref", `{"rules": [{"id": "r1", "domain": "ngfw", "verb": "deny", "predicate_refs": ["ghost"]}]}`},
		{"duplicate subject name", `{"subjects": [{"name": "a", "kind": "user"}, {"name": "a", "kind": "device"}]}`},
		{"bad subject kind", `{"subjects": [{"name": "a", "kind": "alien"}]}`},
		{"bad target", `{"rules": [{"id": "r1", "domain": "ngfw", "verb": "deny", "targets": ["nope"]}]}`},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseGraph([]byte(c.body))
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Errorf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}
}

func TestCompileTarget_DomainRouting(t *testing.T) {
	t.Parallel()
	// Construct a graph that exercises every Domain → target
	// edge in domainTargets so the routing matrix is exercised
	// by a single source-of-truth test.
	g := Graph{
		DefaultAction: VerbDeny,
		Rules: []Rule{
			{ID: "ngfw-1", Domain: DomainNGFW, Verb: VerbDeny},
			{ID: "swg-1", Domain: DomainSWG, Verb: VerbInspect},
			{ID: "dns-1", Domain: DomainDNS, Verb: VerbDeny},
			{ID: "ztna-1", Domain: DomainZTNA, Verb: VerbAllow},
			{ID: "sdwan-1", Domain: DomainSDWAN, Verb: VerbSteer},
			{ID: "dlp-1", Domain: DomainDLP, Verb: VerbLog},
			{ID: "casb-1", Domain: DomainInlineCASB, Verb: VerbInspect},
		},
	}
	cases := []struct {
		target  repository.PolicyBundleTarget
		wantIDs []string
	}{
		{repository.PolicyBundleTargetEdge, []string{"ngfw-1", "swg-1", "dns-1", "ztna-1", "sdwan-1", "dlp-1", "casb-1"}},
		{repository.PolicyBundleTargetEndpoint, []string{"dns-1", "ztna-1", "sdwan-1", "dlp-1"}},
		{repository.PolicyBundleTargetCloud, []string{"swg-1", "dns-1", "ztna-1", "dlp-1", "casb-1"}},
		{repository.PolicyBundleTargetMobile, []string{"ztna-1"}},
	}
	for _, c := range cases {
		c := c
		t.Run(string(c.target), func(t *testing.T) {
			got := g.CompileTarget(c.target)
			gotIDs := make([]string, 0, len(got))
			for _, r := range got {
				gotIDs = append(gotIDs, r.ID)
			}
			if strings.Join(gotIDs, ",") != strings.Join(c.wantIDs, ",") {
				t.Errorf("target=%s: want %v, got %v", c.target, c.wantIDs, gotIDs)
			}
		})
	}
}

func TestCompileTarget_ExplicitTargetsOverrideDomainRouting(t *testing.T) {
	t.Parallel()
	g := Graph{
		DefaultAction: VerbDeny,
		Rules: []Rule{{
			// NGFW would normally only ship to edge; the explicit
			// Targets list flips it to mobile-only.
			ID: "explicit", Domain: DomainNGFW, Verb: VerbDeny,
			Targets: []repository.PolicyBundleTarget{repository.PolicyBundleTargetMobile},
		}},
	}
	mobile := g.CompileTarget(repository.PolicyBundleTargetMobile)
	if len(mobile) != 1 || mobile[0].ID != "explicit" {
		t.Errorf("mobile: want explicit rule, got %#v", mobile)
	}
	edge := g.CompileTarget(repository.PolicyBundleTargetEdge)
	if len(edge) != 0 {
		t.Errorf("edge: want zero rules, got %d (Targets whitelist should suppress domain-routing)", len(edge))
	}
}

func TestEncodeRules_Deterministic(t *testing.T) {
	t.Parallel()
	// Same rule set encoded twice must produce identical bytes
	// — the bundle signature relies on this for verifiability.
	rules := []Rule{
		{ID: "a", Domain: DomainNGFW, Verb: VerbDeny, Extra: map[string]json.RawMessage{
			"z": json.RawMessage(`{"k":1}`),
			"a": json.RawMessage(`true`),
		}},
		{ID: "b", Domain: DomainDNS, Verb: VerbAllow},
	}
	first, err := EncodeRules(rules)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := EncodeRules(rules)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if string(first) != string(second) {
		t.Errorf("non-deterministic encode:\n  first:  %s\n  second: %s", first, second)
	}
	// Extra keys must be sorted alphabetically in the output.
	if idx := strings.Index(string(first), `"a":`); idx == -1 {
		t.Errorf("missing 'a' Extra key: %s", first)
	}
	if !strings.Contains(string(first), `"a":true`) {
		t.Errorf("Extra key 'a' value not preserved: %s", first)
	}
}

func TestEncodeRules_Empty(t *testing.T) {
	t.Parallel()
	out, err := EncodeRules(nil)
	if err != nil {
		t.Fatalf("encode nil: %v", err)
	}
	if string(out) != "[]" {
		t.Errorf("nil → %s, want []", out)
	}
}

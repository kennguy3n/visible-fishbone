package policytemplates

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func TestResolve_Deterministic(t *testing.T) {
	sel := Selection{Industry: IndustryFinance, Country: "DE"}
	a, err := Resolve(sel)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	b, err := Resolve(sel)
	if err != nil {
		t.Fatalf("Resolve (2nd): %v", err)
	}
	if a.GraphHash != b.GraphHash {
		t.Errorf("non-deterministic hash: %q vs %q", a.GraphHash, b.GraphHash)
	}
	if !bytes.Equal(a.GraphJSON, b.GraphJSON) {
		t.Errorf("non-deterministic graph bytes")
	}
	if a.GraphHash == "" {
		t.Errorf("empty graph hash")
	}
}

func TestResolve_NormalizeCountryCase(t *testing.T) {
	lower, err := Resolve(Selection{Industry: IndustryRetail, Country: "gb"})
	if err != nil {
		t.Fatalf("Resolve lower: %v", err)
	}
	upper, err := Resolve(Selection{Industry: IndustryRetail, Country: "GB"})
	if err != nil {
		t.Fatalf("Resolve upper: %v", err)
	}
	if lower.GraphHash != upper.GraphHash {
		t.Errorf("country case changed hash: %q vs %q", lower.GraphHash, upper.GraphHash)
	}
	if lower.Regime != RegimeUKDPA {
		t.Errorf("regime = %q, want %q", lower.Regime, RegimeUKDPA)
	}
}

func TestResolve_Errors(t *testing.T) {
	if _, err := Resolve(Selection{Industry: "nope", Country: "US"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("unknown industry err = %v, want ErrInvalidArgument", err)
	}
	if _, err := Resolve(Selection{Industry: IndustryRetail, Country: "ZZ"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("unknown country err = %v, want ErrInvalidArgument", err)
	}
}

func TestResolve_GraphValidAndProvenance(t *testing.T) {
	res, err := Resolve(Selection{Industry: IndustryHealthcare, Country: "GB"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if err := res.Graph.Validate(); err != nil {
		t.Fatalf("rendered graph invalid: %v", err)
	}
	if res.Graph.DefaultAction != policy.VerbDeny {
		t.Errorf("default action = %q, want deny", res.Graph.DefaultAction)
	}
	if res.Graph.Version != GraphVersion {
		t.Errorf("graph version = %d, want %d", res.Graph.Version, GraphVersion)
	}
	wantIDs := []string{
		baselineTemplateID,
		industryTemplateID(IndustryHealthcare),
		complianceTemplateID(RegimeUKDPA),
	}
	if len(res.TemplateIDs) != 3 {
		t.Fatalf("template ids = %v, want 3", res.TemplateIDs)
	}
	for i, want := range wantIDs {
		if res.TemplateIDs[i] != want {
			t.Errorf("template id[%d] = %q, want %q", i, res.TemplateIDs[i], want)
		}
	}
}

// ruleIndex maps each rendered rule's predicate match shape so tests
// can assert on (domain, verb, category/detector/port) tuples.
func decodeMatch(t *testing.T, raw json.RawMessage) map[string]any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode predicate match: %v", err)
	}
	return m
}

func TestResolve_SecurityCategoriesBlockedOnDNSAndSWG(t *testing.T) {
	res, err := Resolve(Selection{Industry: IndustryGeneral, Country: "US"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	type key struct {
		domain policy.Domain
		cat    string
	}
	got := map[key]policy.Verb{}
	for _, r := range res.Graph.Rules {
		if r.Domain != policy.DomainDNS && r.Domain != policy.DomainSWG {
			continue
		}
		if len(r.Predicates) != 1 {
			continue
		}
		m := decodeMatch(t, r.Predicates[0].Match)
		if c, ok := m["category"].(string); ok {
			got[key{r.Domain, c}] = r.Verb
		}
	}
	for _, cat := range []string{"security.threat", "security.hacking", "anonymizer"} {
		if got[key{policy.DomainDNS, cat}] != policy.VerbDeny {
			t.Errorf("category %q not denied on DNS plane", cat)
		}
		if got[key{policy.DomainSWG, cat}] != policy.VerbDeny {
			t.Errorf("category %q not denied on SWG plane", cat)
		}
	}
}

func TestResolve_DLPVerbMapping(t *testing.T) {
	// EU GDPR: iban(high)->deny, eu_vat/phone(medium)->inspect, email(low)->log.
	res, err := Resolve(Selection{Industry: IndustryProfessional, Country: "FR"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	verbByDetector := map[string]policy.Verb{}
	for _, r := range res.Graph.Rules {
		if r.Domain != policy.DomainDLP || len(r.Predicates) != 1 {
			continue
		}
		m := decodeMatch(t, r.Predicates[0].Match)
		if d, ok := m["dlp_detector"].(string); ok {
			verbByDetector[d] = r.Verb
		}
	}
	checks := map[string]policy.Verb{
		"iban":   policy.VerbDeny,
		"eu_vat": policy.VerbInspect,
		"phone":  policy.VerbInspect,
		"email":  policy.VerbLog,
	}
	for det, want := range checks {
		if verbByDetector[det] != want {
			t.Errorf("detector %q verb = %q, want %q", det, verbByDetector[det], want)
		}
	}
}

func TestResolve_FirewallPosture(t *testing.T) {
	portHasVerb := func(res Resolved, want policy.Verb, proto string, port float64) bool {
		for _, r := range res.Graph.Rules {
			if r.Domain != policy.DomainNGFW || r.Verb != want || len(r.Predicates) != 1 {
				continue
			}
			m := decodeMatch(t, r.Predicates[0].Match)
			if m["protocol"] == proto && m["dst_port"] == port {
				return true
			}
		}
		return false
	}
	allowsPort := func(res Resolved, proto string, port float64) bool {
		return portHasVerb(res, policy.VerbAllow, proto, port)
	}
	deniesPort := func(res Resolved, proto string, port float64) bool {
		return portHasVerb(res, policy.VerbDeny, proto, port)
	}

	strict, err := Resolve(Selection{Industry: IndustryHealthcare, Country: "GB"}) // strict
	if err != nil {
		t.Fatalf("Resolve strict: %v", err)
	}
	standard, err := Resolve(Selection{Industry: IndustryRetail, Country: "GB"}) // standard
	if err != nil {
		t.Fatalf("Resolve standard: %v", err)
	}

	if !allowsPort(standard, "tcp", 80) {
		t.Errorf("standard posture must allow tcp/80")
	}
	if allowsPort(strict, "tcp", 80) {
		t.Errorf("strict posture must NOT allow tcp/80")
	}
	for _, res := range []Resolved{strict, standard} {
		if !allowsPort(res, "tcp", 443) {
			t.Errorf("posture must allow tcp/443 (HTTPS)")
		}
		if !deniesPort(res, "tcp", 445) {
			t.Errorf("posture must deny tcp/445 (SMB)")
		}
		if !deniesPort(res, "tcp", 3389) {
			t.Errorf("posture must deny tcp/3389 (RDP)")
		}
	}
	if !deniesPort(strict, "tcp", 21) {
		t.Errorf("strict posture must deny tcp/21 (FTP)")
	}
}

func TestComposeSpecs_BlockOverridesMonitorAndMaxSensitivity(t *testing.T) {
	baseline := Spec{Categories: []CategoryRule{{CategorySocialMedia, CategoryMonitor}}}
	industry := Spec{
		Categories: []CategoryRule{{CategorySocialMedia, CategoryBlock}},
		Detectors:  []DetectorRule{{"email", SensitivityLow}},
		Firewall:   PostureStrict,
	}
	compliance := Spec{Detectors: []DetectorRule{{"email", SensitivityHigh}}}

	c := composeSpecs(baseline, industry, compliance)
	if c.categories[CategorySocialMedia] != CategoryBlock {
		t.Errorf("block must override monitor, got %q", c.categories[CategorySocialMedia])
	}
	if c.detectors["email"] != SensitivityHigh {
		t.Errorf("max sensitivity must win, got %q", c.detectors["email"])
	}
	if c.posture != PostureStrict {
		t.Errorf("posture = %q, want strict", c.posture)
	}
}

func TestComposeSpecs_MonitorDoesNotDowngradeBlock(t *testing.T) {
	// Order independence: a later monitor must not override an earlier block.
	baseline := Spec{Categories: []CategoryRule{{CategoryGambling, CategoryBlock}}}
	industry := Spec{Categories: []CategoryRule{{CategoryGambling, CategoryMonitor}}, Firewall: PostureStandard}
	c := composeSpecs(baseline, industry, Spec{})
	if c.categories[CategoryGambling] != CategoryBlock {
		t.Errorf("block downgraded to %q by later monitor", c.categories[CategoryGambling])
	}
}

func TestRenderRules_WithinRuleSizeLimit(t *testing.T) {
	// Every rendered rule must satisfy the policy package's per-rule
	// byte cap; Resolve already calls Validate, but assert explicitly
	// so a regression points here.
	res, err := Resolve(Selection{Industry: IndustryFinance, Country: "US"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(res.Graph.Rules) == 0 {
		t.Fatalf("no rules rendered")
	}
	for _, r := range res.Graph.Rules {
		enc, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal rule %q: %v", r.ID, err)
		}
		if len(enc) > policy.MaxRuleBytes {
			t.Errorf("rule %q is %d bytes, exceeds %d", r.ID, len(enc), policy.MaxRuleBytes)
		}
	}
}

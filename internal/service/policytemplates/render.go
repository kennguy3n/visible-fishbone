package policytemplates

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// GraphVersion is the schema version stamped on every rendered graph.
// Bump it when the rendering changes in a way that should force a
// re-render of already-applied baselines (the content hash also
// changes, so Apply re-renders automatically — this is mostly for
// human-facing provenance).
const GraphVersion = 1

// Selection is an SME's two-coordinate choice. It resolves to a
// baseline + industry + compliance template triple.
type Selection struct {
	Industry Industry `json:"industry"`
	Country  Country  `json:"country"`
}

// Normalize upper-cases the country code so "gb" and "GB" resolve
// identically. Industry tokens are already lower-case constants.
func (s Selection) Normalize() Selection {
	return Selection{Industry: s.Industry, Country: Country(strings.ToUpper(string(s.Country)))}
}

// Resolved is the output of Resolve: the composed, validated
// Policy-Graph intent plus the provenance needed to persist and audit
// the decision.
type Resolved struct {
	Selection Selection        `json:"selection"`
	Regime    ComplianceRegime `json:"regime"`
	// TemplateIDs are the catalog templates that composed this graph,
	// sorted: [baseline, industry, compliance].
	TemplateIDs []string `json:"template_ids"`
	// Graph is the rendered, validated Policy-Graph intent.
	Graph policy.Graph `json:"-"`
	// GraphJSON is the canonical (deterministic) JSON encoding of
	// Graph. GraphHash is its SHA-256, used for idempotent Apply.
	GraphJSON json.RawMessage `json:"-"`
	GraphHash string          `json:"graph_hash"`
}

// Resolve composes the baseline + industry + compliance profiles for a
// Selection into a single validated policy.Graph. It is pure (no I/O)
// and deterministic: the same Selection always yields byte-identical
// GraphJSON and GraphHash.
func Resolve(sel Selection) (Resolved, error) {
	sel = sel.Normalize()

	industrySpec, ok := industryProfiles[sel.Industry]
	if !ok {
		return Resolved{}, fmt.Errorf("unknown industry %q: %w", sel.Industry, errInvalidArgument)
	}
	regime, ok := RegimeForCountry(sel.Country)
	if !ok {
		return Resolved{}, fmt.Errorf("unsupported country %q: %w", sel.Country, errInvalidArgument)
	}
	complianceSpec := complianceProfiles[regime]

	composed := composeSpecs(baselineProfile, industrySpec, complianceSpec)

	g := policy.Graph{
		Version:       GraphVersion,
		DefaultAction: policy.VerbDeny,
		Rules:         renderRules(composed),
	}
	if err := g.Validate(); err != nil {
		return Resolved{}, fmt.Errorf("rendered graph invalid: %w", err)
	}

	canonical, err := canonicalJSON(g)
	if err != nil {
		return Resolved{}, err
	}
	sum := sha256.Sum256(canonical)

	return Resolved{
		Selection:   sel,
		Regime:      regime,
		TemplateIDs: []string{baselineTemplateID, industryTemplateID(sel.Industry), complianceTemplateID(regime)},
		Graph:       g,
		GraphJSON:   canonical,
		GraphHash:   hex.EncodeToString(sum[:]),
	}, nil
}

// composedSpec is the merged intent after dedup. It is the single
// input to renderRules.
type composedSpec struct {
	// categories maps category -> effective action (block wins over
	// monitor).
	categories map[URLCategory]CategoryAction
	// detectors maps detector -> effective (highest) sensitivity.
	detectors map[PIIDetector]Sensitivity
	posture   FirewallPosture
}

func composeSpecs(baseline, industry, compliance Spec) composedSpec {
	out := composedSpec{
		categories: map[URLCategory]CategoryAction{},
		detectors:  map[PIIDetector]Sensitivity{},
		posture:    industry.Firewall,
	}
	if out.posture == "" {
		out.posture = PostureStandard
	}
	for _, s := range []Spec{baseline, industry, compliance} {
		for _, c := range s.Categories {
			// Block always wins; monitor only fills a not-yet-set slot.
			if cur, ok := out.categories[c.Category]; ok && cur == CategoryBlock {
				continue
			}
			out.categories[c.Category] = c.Action
		}
		for _, d := range s.Detectors {
			if cur, ok := out.detectors[d.Detector]; !ok || sensitivityRank(d.Sensitivity) > sensitivityRank(cur) {
				out.detectors[d.Detector] = d.Sensitivity
			}
		}
	}
	return out
}

func sensitivityRank(s Sensitivity) int {
	switch s {
	case SensitivityHigh:
		return 3
	case SensitivityMedium:
		return 2
	case SensitivityLow:
		return 1
	default:
		return 0
	}
}

// renderRules turns the composed intent into the full slice of
// policy.Rule, sorted by ID for deterministic output.
func renderRules(c composedSpec) []policy.Rule {
	var rules []policy.Rule

	// Safe-browsing: one DNS + one SWG rule per blocked category
	// (defence in depth), one SWG log rule per monitored category.
	for _, cat := range sortedCategories(c.categories) {
		switch c.categories[cat] {
		case CategoryBlock:
			rules = append(rules,
				categoryRule(policy.DomainDNS, policy.VerbDeny, cat, "dns-deny"),
				categoryRule(policy.DomainSWG, policy.VerbDeny, cat, "swg-deny"),
			)
		case CategoryMonitor:
			rules = append(rules, categoryRule(policy.DomainSWG, policy.VerbLog, cat, "swg-log"))
		}
	}

	// DLP: one rule per detector, verb fixed by sensitivity.
	for _, det := range sortedDetectors(c.detectors) {
		rules = append(rules, dlpRule(det, c.detectors[det]))
	}

	// Baseline firewall posture.
	rules = append(rules, firewallRules(c.posture)...)

	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

func categoryRule(domain policy.Domain, verb policy.Verb, cat URLCategory, idTag string) policy.Rule {
	return policy.Rule{
		ID:          "pt-" + idTag + "-" + string(cat),
		Domain:      domain,
		Verb:        verb,
		Predicates:  []policy.Predicate{categoryPredicate(cat)},
		Description: fmt.Sprintf("%s %q on the %s plane", verb, cat, domain),
	}
}

func categoryPredicate(cat URLCategory) policy.Predicate {
	// {"category":"<cat>"} — the dotted-category match the SWG verdict
	// layer and DNS resolver both interpret.
	match, _ := json.Marshal(struct {
		Category string `json:"category"`
	}{Category: string(cat)})
	return policy.Predicate{Name: "category:" + string(cat), Match: match}
}

func dlpRule(det PIIDetector, sens Sensitivity) policy.Rule {
	verb := dlpVerb(sens)
	match, _ := json.Marshal(struct {
		Detector    string `json:"dlp_detector"`
		Sensitivity string `json:"sensitivity"`
	}{Detector: string(det), Sensitivity: string(sens)})
	return policy.Rule{
		ID:          fmt.Sprintf("pt-dlp-%s-%s", verb, det),
		Domain:      policy.DomainDLP,
		Verb:        verb,
		Predicates:  []policy.Predicate{{Name: "dlp:" + string(det), Match: match}},
		Description: fmt.Sprintf("DLP %s on detector %q (%s sensitivity)", verb, det, sens),
	}
}

// dlpVerb maps a DLP sensitivity tier to a Policy-Graph verb:
//   - high   → deny    (block transmission of the most sensitive PII)
//   - medium → inspect (inspect/redact in-line)
//   - low    → log     (visibility only)
func dlpVerb(s Sensitivity) policy.Verb {
	switch s {
	case SensitivityHigh:
		return policy.VerbDeny
	case SensitivityMedium:
		return policy.VerbInspect
	default:
		return policy.VerbLog
	}
}

// firewallPort is one egress port decision in a posture ruleset.
type firewallPort struct {
	proto string
	port  uint16
	allow bool
	desc  string
}

// firewallRuleset returns the ordered port decisions for a posture.
// allow=true ports are the permitted egress services; allow=false
// ports are explicitly denied for high-signal "blocked risky egress"
// telemetry (they would also be denied by DefaultAction=deny, but the
// explicit rule makes the intent and the telemetry unambiguous).
func firewallRuleset(p FirewallPosture) []firewallPort {
	// Lateral-movement / remote-management ports denied in every
	// posture — these have no business traversing the gateway.
	risky := []firewallPort{
		{protoTCP, 23, false, "Telnet"},
		{protoTCP, 135, false, "MS-RPC"},
		{protoUDP, 137, false, "NetBIOS name"},
		{protoUDP, 138, false, "NetBIOS datagram"},
		{protoTCP, 139, false, "NetBIOS session"},
		{protoTCP, 445, false, "SMB"},
		{protoTCP, 3389, false, "RDP"},
		{protoTCP, 5900, false, "VNC"},
	}
	switch p {
	case PostureStrict:
		// TLS-only egress: no plaintext web (80) or mail (25); add
		// FTP to the denied set.
		allow := []firewallPort{
			{protoUDP, 53, true, "DNS"},
			{protoTCP, 53, true, "DNS over TCP"},
			{protoTCP, 443, true, "HTTPS"},
			{protoTCP, 587, true, "SMTP submission (STARTTLS)"},
			{protoTCP, 993, true, "IMAPS"},
			{protoTCP, 995, true, "POP3S"},
		}
		extra := []firewallPort{
			{protoTCP, 21, false, "FTP"},
			{protoTCP, 25, false, "SMTP cleartext"},
		}
		return append(append(allow, risky...), extra...)
	default: // PostureStandard
		allow := []firewallPort{
			{protoUDP, 53, true, "DNS"},
			{protoTCP, 53, true, "DNS over TCP"},
			{protoTCP, 80, true, "HTTP"},
			{protoTCP, 443, true, "HTTPS"},
			{protoTCP, 587, true, "SMTP submission (STARTTLS)"},
			{protoTCP, 993, true, "IMAPS"},
			{protoTCP, 995, true, "POP3S"},
		}
		return append(allow, risky...)
	}
}

func firewallRules(p FirewallPosture) []policy.Rule {
	set := firewallRuleset(p)
	out := make([]policy.Rule, 0, len(set))
	for _, fp := range set {
		verb := policy.VerbDeny
		action := "deny"
		if fp.allow {
			verb = policy.VerbAllow
			action = "allow"
		}
		match, _ := json.Marshal(struct {
			DstPort uint16 `json:"dst_port"`
			Proto   string `json:"protocol"`
		}{DstPort: fp.port, Proto: fp.proto})
		out = append(out, policy.Rule{
			ID:          fmt.Sprintf("pt-fw-%s-%s-%d", action, fp.proto, fp.port),
			Domain:      policy.DomainNGFW,
			Verb:        verb,
			Predicates:  []policy.Predicate{{Name: fmt.Sprintf("port:%s/%d", fp.proto, fp.port), Match: match}},
			Description: fmt.Sprintf("%s %s egress (%s/%d)", action, fp.desc, fp.proto, fp.port),
		})
	}
	return out
}

func sortedCategories(m map[URLCategory]CategoryAction) []URLCategory {
	out := make([]URLCategory, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedDetectors(m map[PIIDetector]Sensitivity) []PIIDetector {
	out := make([]PIIDetector, 0, len(m))
	for d := range m {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// canonicalJSON returns a deterministic JSON encoding of the graph.
// The graph's rules are pre-sorted by ID and every predicate Match is
// built from a struct (ordered keys), so encoding/json — which emits
// struct fields in declaration order and sorts map keys — yields
// byte-identical output for identical input.
func canonicalJSON(g policy.Graph) (json.RawMessage, error) {
	b, err := json.Marshal(g)
	if err != nil {
		return nil, fmt.Errorf("marshal rendered graph: %w", err)
	}
	return json.RawMessage(b), nil
}

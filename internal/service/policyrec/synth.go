// Package policyrec implements the traffic-derived least-privilege
// Policy Recommendation Engine.
//
// The engine answers the single highest-expertise question the control
// plane otherwise leaves to a human operator the target SME doesn't
// have: "what is the minimal policy my network actually needs?" It
// observes a tenant's recently-recorded telemetry, synthesizes a
// minimal default-deny allow-list that preserves the traffic the
// tenant legitimately relies on, then proves what applying that policy
// would change before anyone clicks apply.
//
// The design reuses the existing policy rails rather than adding
// parallel machinery:
//
//   - Synthesis emits a typed policy.Graph (the same model the
//     compiler, simulator, and evaluator already speak), so the
//     candidate is schema-validated by policy.ParseGraph and matched
//     by the same policy.GraphEvaluator the simulator uses.
//   - Coverage / impact are measured by replaying the very telemetry
//     the recommendation was synthesized from through that evaluator,
//     so the numbers an operator sees describe the exact event set the
//     allow-list was built from — no skew between "what we learned
//     from" and "what we measured against".
//   - Applying a recommendation stages the candidate as a draft via
//     policy.Service.PutDraftGraph, feeding the existing canary-rollout
//     state machine. The engine never enforces anything itself.
//
// synth.go is the deterministic synthesis core: a pure function of
// (observed envelopes, options) with no clock, RNG, or I/O, so two
// runs over the same telemetry produce byte-identical output.
package policyrec

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// Defaults for SynthesisOptions.
const (
	defaultIPv4PrefixLen   = 24
	defaultIPv6PrefixLen   = 64
	defaultMaxRules        = 200
	defaultMinObservations = 1
)

// SynthesisOptions tunes deterministic least-privilege synthesis. The
// zero value is valid and normalised to the package defaults.
type SynthesisOptions struct {
	// IPv4PrefixLen / IPv6PrefixLen aggregate observed destination
	// addresses to this prefix length when building dst_cidr matchers.
	// A coarser prefix yields fewer, broader allow rules (less precise
	// least privilege, easier to read); a finer prefix yields more,
	// tighter rules. Defaults: /24 (v4), /64 (v6).
	IPv4PrefixLen int
	IPv6PrefixLen int

	// MaxRules caps the number of synthesized allow rules. When the
	// observed traffic would produce more, the lowest-frequency groups
	// are dropped (and reported via SynthesisStats.DroppedGroups); the
	// dropped traffic then surfaces honestly as newly-denied in the
	// coverage report rather than silently widening the policy.
	// Default 200.
	MaxRules int

	// MinObservations drops any traffic group seen fewer than this many
	// times in the window — a noise floor that keeps one-off scans /
	// typos out of the synthesized allow-list. Default 1 (keep all).
	MinObservations int
}

func (o SynthesisOptions) normalize() SynthesisOptions {
	out := o
	if out.IPv4PrefixLen <= 0 || out.IPv4PrefixLen > 32 {
		out.IPv4PrefixLen = defaultIPv4PrefixLen
	}
	if out.IPv6PrefixLen <= 0 || out.IPv6PrefixLen > 128 {
		out.IPv6PrefixLen = defaultIPv6PrefixLen
	}
	if out.MaxRules <= 0 {
		out.MaxRules = defaultMaxRules
	}
	if out.MinObservations <= 0 {
		out.MinObservations = defaultMinObservations
	}
	return out
}

// SynthesisStats is the deterministic, operator-facing summary of one
// synthesis pass — what was observed and what was built from it.
type SynthesisStats struct {
	// ObservedTotal is the number of envelopes considered (every class
	// the synthesizer was handed, including ones it does not model).
	ObservedTotal int `json:"observed_total"`
	// ObservedPermitted is the count of permitted envelopes in a
	// modelled class (flow / dns / http) that fed the allow-list.
	ObservedPermitted int `json:"observed_permitted"`
	// PerClassObserved breaks ObservedPermitted down by event class.
	PerClassObserved map[string]int `json:"per_class_observed"`
	// RuleCount is the number of synthesized allow rules.
	RuleCount int `json:"rule_count"`
	// PerDomainRules breaks RuleCount down by policy domain.
	PerDomainRules map[string]int `json:"per_domain_rules"`
	// Truncated reports whether MaxRules forced low-frequency groups to
	// be dropped; DroppedGroups is how many.
	Truncated     bool `json:"truncated"`
	DroppedGroups int  `json:"dropped_groups"`
}

// permittedVerdict reports whether a telemetry verdict represents
// traffic that was permitted to flow (and so belongs in a
// least-privilege allow-list). deny / alert are excluded — the
// recommendation must never re-allow traffic the network already
// blocked.
func permittedVerdict(v schema.Verdict) bool {
	switch v {
	case schema.VerdictAllow, schema.VerdictInspect, schema.VerdictLog:
		return true
	}
	return false
}

// trafficGroup is one deduplicated unit of observed permitted traffic
// that maps to exactly one synthesized allow rule.
type trafficGroup struct {
	// classOrder orders classes deterministically in the output graph
	// (flow rules first, then dns, then http) independent of map
	// iteration order.
	classOrder int
	// key uniquely identifies the group within its class (used for the
	// rule ID and as the stable tie-breaker when truncating).
	key string
	// count is how many observed envelopes fell into this group.
	count int
	// rule is the synthesized allow rule for this group.
	rule policy.Rule
}

// Synthesize turns observed telemetry into a minimal default-deny
// least-privilege policy graph. It is pure and deterministic: the
// output graph and stats depend only on (events, opts).
func Synthesize(events []schema.Envelope, opts SynthesisOptions) (policy.Graph, SynthesisStats) {
	opts = opts.normalize()

	stats := SynthesisStats{
		ObservedTotal:    len(events),
		PerClassObserved: map[string]int{},
		PerDomainRules:   map[string]int{},
	}

	// Deduplicate observed traffic into groups keyed by class+key.
	groups := map[string]*trafficGroup{}
	upsert := func(classOrder int, key string, build func() policy.Rule) {
		g, ok := groups[key]
		if !ok {
			g = &trafficGroup{classOrder: classOrder, key: key, rule: build()}
			groups[key] = g
		}
		g.count++
	}

	for i := range events {
		env := events[i]
		switch env.EventClass {
		case schema.EventClassFlow:
			var f schema.FlowEvent
			if err := schema.UnpackPayload(env.Payload, &f); err != nil {
				continue
			}
			if !permittedVerdict(f.Verdict) {
				continue
			}
			cidr, ok := aggregateCIDR(f.DstIP, opts)
			if !ok {
				continue
			}
			// The protocol is used verbatim in the synthesized matcher
			// because the evaluator compares it for exact equality —
			// normalising it here would build a rule that fails to match
			// the very traffic it was synthesized from.
			proto := f.Protocol
			port := f.DstPort
			key := fmt.Sprintf("flow|%s|%d|%s", proto, port, cidr)
			stats.PerClassObserved[string(schema.EventClassFlow)]++
			upsert(0, key, func() policy.Rule { return flowRule(proto, port, cidr) })
		case schema.EventClassDNS:
			var d schema.DNSEvent
			if err := schema.UnpackPayload(env.Payload, &d); err != nil {
				continue
			}
			if !permittedVerdict(d.Verdict) {
				continue
			}
			// Exact-match value: the evaluator compares Query verbatim,
			// so the rule must carry the observed query unmodified.
			q := d.Query
			if strings.TrimSpace(q) == "" {
				continue
			}
			key := "dns|" + q
			stats.PerClassObserved[string(schema.EventClassDNS)]++
			upsert(1, key, func() policy.Rule { return dnsRule(q) })
		case schema.EventClassHTTP:
			var h schema.HTTPEvent
			if err := schema.UnpackPayload(env.Payload, &h); err != nil {
				continue
			}
			if !permittedVerdict(h.Verdict) {
				continue
			}
			// Exact-match value: the evaluator compares Host verbatim.
			host := h.Host
			if strings.TrimSpace(host) == "" {
				continue
			}
			key := "http|" + host
			stats.PerClassObserved[string(schema.EventClassHTTP)]++
			upsert(2, key, func() policy.Rule { return httpRule(host) })
		}
	}

	// Materialise groups, applying the noise floor.
	kept := make([]*trafficGroup, 0, len(groups))
	for _, g := range groups {
		stats.ObservedPermitted += g.count
		if g.count < opts.MinObservations {
			stats.DroppedGroups++
			continue
		}
		kept = append(kept, g)
	}

	// Stable ordering: by class, then key. This is the canonical output
	// order and also the tie-breaker for truncation.
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].classOrder != kept[j].classOrder {
			return kept[i].classOrder < kept[j].classOrder
		}
		return kept[i].key < kept[j].key
	})

	// Truncate to MaxRules, dropping the lowest-frequency groups first
	// (count desc, key asc as a deterministic tie-break).
	if len(kept) > opts.MaxRules {
		byFreq := make([]*trafficGroup, len(kept))
		copy(byFreq, kept)
		sort.SliceStable(byFreq, func(i, j int) bool {
			if byFreq[i].count != byFreq[j].count {
				return byFreq[i].count > byFreq[j].count
			}
			if byFreq[i].classOrder != byFreq[j].classOrder {
				return byFreq[i].classOrder < byFreq[j].classOrder
			}
			return byFreq[i].key < byFreq[j].key
		})
		survivors := map[string]struct{}{}
		for _, g := range byFreq[:opts.MaxRules] {
			survivors[g.key] = struct{}{}
		}
		filtered := kept[:0]
		for _, g := range kept {
			if _, ok := survivors[g.key]; ok {
				filtered = append(filtered, g)
			} else {
				stats.DroppedGroups++
			}
		}
		kept = filtered
		stats.Truncated = true
	}

	rules := make([]policy.Rule, 0, len(kept))
	for _, g := range kept {
		rules = append(rules, g.rule)
		stats.PerDomainRules[string(g.rule.Domain)]++
	}
	stats.RuleCount = len(rules)

	graph := policy.Graph{
		DefaultAction: policy.VerbDeny,
		Rules:         rules,
	}
	return graph, stats
}

// aggregateCIDR masks an observed destination IP to the configured
// prefix and returns the canonical network CIDR (e.g. "10.0.0.0/24").
// An unparseable address yields ("", false) so the flow is skipped
// rather than producing a rule that can never match.
func aggregateCIDR(ip string, opts SynthesisOptions) (string, bool) {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "", false
	}
	bits := opts.IPv4PrefixLen
	if addr.Is6() && !addr.Is4In6() {
		bits = opts.IPv6PrefixLen
	}
	prefix, err := addr.Prefix(bits)
	if err != nil {
		return "", false
	}
	return prefix.Masked().String(), true
}

// normalizeDomain lower-cases and trims a DNS query / HTTP host and
// strips a single trailing dot so "Example.com." and "example.com"
// collapse to one rule.
func normalizeDomain(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimSuffix(d, ".")
	return d
}

func flowRule(proto string, port uint16, cidr string) policy.Rule {
	preds := []policy.Predicate{{Match: mustJSON(map[string]any{"kind": "dst_cidr", "cidr": cidr})}}
	// A proto/port predicate is a separate matcher ANDed with the CIDR
	// one (the evaluator's dst_cidr matcher ignores proto/port). Omit
	// dst_port for portless protocols (icmp/other) where it is zero.
	pp := map[string]any{}
	if proto != "" {
		pp["protocol"] = proto
	}
	if port != 0 {
		pp["dst_port"] = port
	}
	if len(pp) > 0 {
		preds = append(preds, policy.Predicate{Match: mustJSON(pp)})
	}
	desc := fmt.Sprintf("Allow observed %s traffic to %s", protoLabel(proto), cidr)
	if port != 0 {
		desc = fmt.Sprintf("Allow observed %s/%d traffic to %s", protoLabel(proto), port, cidr)
	}
	return policy.Rule{
		ID:          flowRuleID(proto, port, cidr),
		Domain:      policy.DomainNGFW,
		Verb:        policy.VerbAllow,
		Predicates:  preds,
		Description: desc,
	}
}

func dnsRule(query string) policy.Rule {
	return policy.Rule{
		ID:          "rec-dns-" + query,
		Domain:      policy.DomainDNS,
		Verb:        policy.VerbAllow,
		Predicates:  []policy.Predicate{{Match: mustJSON(map[string]any{"query": query})}},
		Description: "Allow observed DNS resolution of " + query,
	}
}

func httpRule(host string) policy.Rule {
	return policy.Rule{
		ID:          "rec-swg-host-" + host,
		Domain:      policy.DomainSWG,
		Verb:        policy.VerbAllow,
		Predicates:  []policy.Predicate{{Match: mustJSON(map[string]any{"host": host})}},
		Description: "Allow observed web access to " + host,
	}
}

func flowRuleID(proto string, port uint16, cidr string) string {
	// '/' is replaced so the ID reads cleanly; it carries no semantic
	// meaning beyond uniqueness + provenance.
	safeCIDR := strings.ReplaceAll(cidr, "/", "_")
	return fmt.Sprintf("rec-ngfw-%s-%d-%s", protoLabel(proto), port, safeCIDR)
}

func protoLabel(proto string) string {
	if proto == "" {
		return "any"
	}
	return proto
}

// mustJSON marshals a small, statically-typed matcher document. The
// inputs are always plain string/uint maps built above, which never
// fail to marshal; a failure would be a programming error, so the
// error is intentionally dropped to keep call sites readable.
func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

package ai

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// IPSRuleCompiler turns a point-in-time IOCStore snapshot into a
// Suricata rule set (the inline IPS data plane's signature
// language). It is the IPS-tier sibling of IOCEnforcementCompiler:
// where that compiler folds IOCs into the signed POLICY bundle
// (firewall / DNS / SWG / malware), this one folds them into the
// signed IPS RULE bundle the edge's sng-ips crate verifies, stages
// and hot-swaps into a running Suricata.
//
// Four indicator types compile to a Suricata rule:
//
//   - IOCTypeJA3    -> a tls `ja3.hash` content match (the headline:
//     a malicious TLS CLIENT fingerprint, caught regardless of the
//     destination address or SNI).
//   - IOCTypeDomain -> a dns `dns.query` content match.
//   - IOCTypeIP     -> an ip rule with the address as the dst.
//   - IOCTypeCIDR   -> an ip rule with the range as the dst.
//
// URL and hash IOCs do NOT compile here: URLs are an SWG concern
// and hashes a malware-verdict concern (both already handled by
// IOCEnforcementCompiler), so the IPS bundle stays focused on the
// network-signature surface Suricata owns.
//
// Each emitted rule carries a Suricata classtype / msg chosen so
// that the EDGE classifier (sng_ips::rules::RuleCategory::classify)
// buckets it into the same RuleCategory the producer intended,
// which is what makes per-category enablement and hit stats line up
// with what the control plane shipped. The compiler counts its own
// output through the same classifier (classifyRuleCategory below, a
// faithful port of the Rust one) so the efficacy metric reflects
// the edge's view, not the producer's intent, even when a value's
// own text would re-bucket a rule.
type IPSRuleCompiler struct {
	snapshot func() IOCSnapshot
	// minConfidence is the floor an indicator must clear to be
	// compiled into a rule. Separate from the store's ingest floor
	// for the same reason IOCEnforcementCompiler keeps its own: the
	// store may retain lower-confidence indicators for alerting
	// while enforcement only acts on higher-confidence hits.
	minConfidence float64
	// compilerID is stamped into the bundle's `comp` field for
	// telemetry (e.g. "sng-control/threat-intel").
	compilerID string
}

// IPSRuleOption configures NewIPSRuleCompiler.
type IPSRuleOption func(*IPSRuleCompiler)

// WithIPSMinConfidence sets the floor an indicator must clear to be
// compiled into a Suricata rule. Defaults to
// defaultEnforcementMinConfidence (shared with the policy compiler).
func WithIPSMinConfidence(floor float64) IPSRuleOption {
	return func(c *IPSRuleCompiler) { c.minConfidence = clampConfidence(floor) }
}

// WithIPSCompilerID sets the free-form compiler identifier stamped
// into the bundle for telemetry.
func WithIPSCompilerID(id string) IPSRuleOption {
	return func(c *IPSRuleCompiler) {
		if id != "" {
			c.compilerID = id
		}
	}
}

const defaultIPSCompilerID = "sng-control/threat-intel"

// sidBase is the first Suricata sid the compiler assigns. Sids are
// handed out sequentially from this base over the deterministically
// sorted rule set, so they are unique and stable across compiles of
// the same snapshot. The base sits well above the Emerging Threats
// (2,000,000–2,999,999) and local (1,000,000) ranges so SNG
// threat-intel rules never collide with an operator's other feeds.
const sidBase = 3_200_000_000

// NewIPSRuleCompiler builds a compiler over the given store.
func NewIPSRuleCompiler(store *IOCStore, opts ...IPSRuleOption) *IPSRuleCompiler {
	c := &IPSRuleCompiler{
		snapshot:      store.Snapshot,
		minConfidence: defaultEnforcementMinConfidence,
		compilerID:    defaultIPSCompilerID,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CompilerID returns the telemetry identifier stamped into bundles.
func (c *IPSRuleCompiler) CompilerID() string { return c.compilerID }

// IPSRuleSet is the compiled Suricata rule text plus the per-category
// rule cardinality, computed with the edge classifier so it matches
// what per-category enablement will see.
type IPSRuleSet struct {
	// RulesText is the line-separated Suricata rule set (one rule
	// per line, trailing newline), ready to be the `rules` field of
	// a signed IPS rule bundle.
	RulesText string
	// ByCategory counts emitted rules per RuleCategory, keyed on the
	// wire-stable category id. Every category is present (zero when
	// none emitted) so a dashboard can render a stable row set.
	ByCategory map[policy.IPSRuleCategory]int
	// Total is the number of rule lines emitted.
	Total int
}

// Compile reads a fresh snapshot and returns the compiled rule set.
func (c *IPSRuleCompiler) Compile() IPSRuleSet {
	return c.compile(c.snapshot())
}

// ipsRuleDraft is a rule before its sid is assigned, carrying the
// fields needed to sort deterministically and to build the line.
type ipsRuleDraft struct {
	// sortKey orders the rule set deterministically: by indicator
	// type then value, so sid assignment is stable across compiles.
	sortKey string
	build   func(sid uint32) string
}

// compile is the snapshot-bound core of Compile, split out so tests
// can drive a fixed snapshot.
func (c *IPSRuleCompiler) compile(snap IOCSnapshot) IPSRuleSet {
	drafts := make([]ipsRuleDraft, 0,
		len(snap.JA3s)+len(snap.Domains)+len(snap.IPs)+len(snap.CIDRs))

	for _, ioc := range snap.JA3s {
		if ioc.Confidence < c.minConfidence || !ruleContentSafe(ioc.Value) {
			continue
		}
		ioc := ioc
		drafts = append(drafts, ipsRuleDraft{
			sortKey: "ja3\x00" + ioc.Value,
			build:   func(sid uint32) string { return buildJA3Rule(ioc, sid) },
		})
	}
	for _, ioc := range snap.Domains {
		if ioc.Confidence < c.minConfidence || !ruleContentSafe(ioc.Value) {
			continue
		}
		ioc := ioc
		drafts = append(drafts, ipsRuleDraft{
			sortKey: "domain\x00" + ioc.Value,
			build:   func(sid uint32) string { return buildDomainRule(ioc, sid) },
		})
	}
	for _, ioc := range snap.IPs {
		if ioc.Confidence < c.minConfidence || !ruleAddrSafe(ioc.Value) {
			continue
		}
		ioc := ioc
		drafts = append(drafts, ipsRuleDraft{
			sortKey: "ip\x00" + ioc.Value,
			build:   func(sid uint32) string { return buildAddrRule(ioc, sid) },
		})
	}
	for _, ioc := range snap.CIDRs {
		if ioc.Confidence < c.minConfidence || !ruleAddrSafe(ioc.Value) {
			continue
		}
		ioc := ioc
		drafts = append(drafts, ipsRuleDraft{
			sortKey: "cidr\x00" + ioc.Value,
			build:   func(sid uint32) string { return buildAddrRule(ioc, sid) },
		})
	}

	sort.SliceStable(drafts, func(i, j int) bool { return drafts[i].sortKey < drafts[j].sortKey })

	byCat := make(map[policy.IPSRuleCategory]int, len(policy.AllIPSRuleCategories()))
	for _, cat := range policy.AllIPSRuleCategories() {
		byCat[cat] = 0
	}
	var b strings.Builder
	for i, d := range drafts {
		line := d.build(sidBase + uint32(i))
		b.WriteString(line)
		b.WriteByte('\n')
		byCat[classifyRuleCategory(line)]++
	}
	return IPSRuleSet{RulesText: b.String(), ByCategory: byCat, Total: len(drafts)}
}

// buildJA3Rule emits a tls rule matching a JA3 client fingerprint.
func buildJA3Rule(ioc IOC, sid uint32) string {
	cat := iocThreatCategory(ioc)
	classtype, tactic := categorySuricata(cat)
	return fmt.Sprintf(
		`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"SNG THREATINTEL %s ja3 client fingerprint"; ja3.hash; content:"%s"; %ssid:%d; rev:1;%s)`,
		tactic, ioc.Value, classtypeClause(classtype), sid, metadataClause(ioc, "ja3"),
	)
}

// buildDomainRule emits a dns rule matching a query for an IOC domain.
func buildDomainRule(ioc IOC, sid uint32) string {
	cat := iocThreatCategory(ioc)
	classtype, tactic := categorySuricata(cat)
	return fmt.Sprintf(
		`alert dns $HOME_NET any -> any any (msg:"SNG THREATINTEL %s dns query"; dns.query; content:"%s"; nocase; %ssid:%d; rev:1;%s)`,
		tactic, ioc.Value, classtypeClause(classtype), sid, metadataClause(ioc, "domain"),
	)
}

// buildAddrRule emits an ip rule whose destination is the IOC
// address or CIDR range. Used for both single IPs and ranges.
func buildAddrRule(ioc IOC, sid uint32) string {
	cat := iocThreatCategory(ioc)
	classtype, tactic := categorySuricata(cat)
	label := "ip"
	if ioc.Type == IOCTypeCIDR {
		label = "cidr"
	}
	return fmt.Sprintf(
		`alert ip $HOME_NET any -> %s any (msg:"SNG THREATINTEL %s destination address"; %ssid:%d; rev:1;%s)`,
		ioc.Value, tactic, classtypeClause(classtype), sid, metadataClause(ioc, label),
	)
}

// classtypeClause renders a `classtype:foo; ` clause, or empty when
// the category has no Suricata classtype that expresses it (the edge
// classifier then reads the tactic from the msg instead).
func classtypeClause(classtype string) string {
	if classtype == "" {
		return ""
	}
	return "classtype:" + classtype + "; "
}

// metadataClause renders a trailing ` metadata:...;` clause carrying
// provenance (sanitised so it never breaks the rule grammar). The
// leading space keeps it separated from the preceding `rev:1;`.
func metadataClause(ioc IOC, kind string) string {
	parts := []string{"sng_threatintel " + kind}
	if src := sanitizeMetadata(ioc.Source); src != "" {
		parts = append(parts, "sng_source "+src)
	}
	if conf := confidenceBucket(ioc.Confidence); conf != "" {
		parts = append(parts, "sng_confidence "+conf)
	}
	return " metadata:" + strings.Join(parts, ", ") + ";"
}

// confidenceBucket coarsens a [0,1] confidence into a metadata label.
func confidenceBucket(c float64) string {
	switch {
	case c >= 0.8:
		return "high"
	case c >= 0.5:
		return "medium"
	default:
		return "low"
	}
}

// sanitizeMetadata strips a feed-supplied string down to the
// characters Suricata's metadata grammar tolerates (alphanumerics
// plus `._-`), so a source name like "abuse.ch:urlhaus" cannot
// inject a `;` or `,` that would split the rule.
func sanitizeMetadata(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

// ruleContentSafe rejects a value that could break out of a Suricata
// content:"..." string. Normalised domains and JA3 hashes never
// contain these, so this is a defensive guard, not an expected path.
func ruleContentSafe(v string) bool {
	return v != "" && !strings.ContainsAny(v, "\"\\;\n\r")
}

// ruleAddrSafe rejects an address value that could break the rule
// grammar. Canonical IPs/CIDRs only ever contain hex digits, dots,
// colons and a slash, so anything else is rejected defensively.
func ruleAddrSafe(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		case r == '.', r == ':', r == '/':
		default:
			return false
		}
	}
	return true
}

// categorySuricata maps a RuleCategory to the Suricata (classtype,
// msg-tactic-token) pair that makes the edge classifier bucket the
// rule back into the same category. Categories Suricata's stock
// classtype vocabulary can express use a classtype; the two it
// cannot (exfiltration, lateral movement) carry the tactic in the
// msg token instead, which the edge classifier reads first.
func categorySuricata(cat policy.IPSRuleCategory) (classtype, tactic string) {
	switch cat {
	case policy.IPSCategoryMalware:
		return "trojan-activity", "MALWARE"
	case policy.IPSCategoryC2:
		return "command-and-control", "C2"
	case policy.IPSCategoryExploit:
		return "web-application-attack", "EXPLOIT"
	case policy.IPSCategoryDoS:
		return "denial-of-service", "DOS"
	case policy.IPSCategoryExfiltration:
		// No stock classtype names exfiltration; the edge reads
		// "exfil" from the msg (highest classifier precedence).
		return "", "EXFIL"
	case policy.IPSCategoryLateralMovement:
		return "", "LATERAL"
	default:
		// Other: a neutral classtype the edge maps to nothing, so it
		// falls through to Other (unless the indicator's own text
		// names a tactic, which the metric honours via the edge
		// classifier).
		return "misc-activity", "GENERIC"
	}
}

// iocThreatCategory picks the threat class a single IOC's rule
// should aim for. Feed attribution (source / actor / campaign) names
// the tactic when present, mirroring how the edge classifier reads a
// rule's msg; otherwise it falls back to a per-type default. The
// keyword precedence matches RuleCategory::classify so the producer's
// intent and the edge's reading of the emitted rule agree.
func iocThreatCategory(ioc IOC) policy.IPSRuleCategory {
	hay := strings.ToLower(ioc.Source + " " + ioc.ThreatActor + " " + ioc.Campaign)
	switch {
	case wordIn(hay, "exfil"), wordIn(hay, "exfiltration"),
		strings.Contains(hay, "data theft"), strings.Contains(hay, "data leak"):
		return policy.IPSCategoryExfiltration
	case wordIn(hay, "lateral"):
		return policy.IPSCategoryLateralMovement
	case wordIn(hay, "c2"), wordIn(hay, "cnc"), wordIn(hay, "beacon"),
		strings.Contains(hay, "command and control"):
		return policy.IPSCategoryC2
	case wordIn(hay, "dos"), wordIn(hay, "ddos"),
		strings.Contains(hay, "denial of service"):
		return policy.IPSCategoryDoS
	case wordIn(hay, "exploit"), strings.Contains(hay, "cve-"),
		strings.Contains(hay, "exploit kit"):
		return policy.IPSCategoryExploit
	case strings.Contains(hay, "ransom"), wordIn(hay, "trojan"),
		wordIn(hay, "malware"), wordIn(hay, "miner"):
		return policy.IPSCategoryMalware
	}
	// Per-type default. A malicious JA3 is overwhelmingly C2/malware
	// client tooling; default it to C2 (the beaconing client), and
	// network destinations to Malware (the coarse safe bucket).
	if ioc.Type == IOCTypeJA3 {
		return policy.IPSCategoryC2
	}
	return policy.IPSCategoryMalware
}

// wordIn reports whether word appears as a whole alphanumeric token
// in hay. Mirrors the edge's msg_has_word so "lateral" matches
// "ET LATERAL" but not "collateral" and "c2" never fires on "rc2".
func wordIn(hay, word string) bool {
	for _, tok := range strings.FieldsFunc(hay, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if tok == word {
			return true
		}
	}
	return false
}

// classifyRuleCategory buckets a single Suricata rule line into a
// RuleCategory. It is a faithful Go port of the edge's
// sng_ips::rules::RuleCategory::classify, so the producer's
// per-category counts match the edge's hit-stat grouping byte for
// byte. The parity is asserted by a cross-language test
// (crates/sng-ips classify parity + this package's compiler tests).
func classifyRuleCategory(ruleLine string) policy.IPSRuleCategory {
	lower := strings.ToLower(ruleLine)
	msg := extractRuleOption(lower, "msg")
	classtype := extractRuleOption(lower, "classtype")

	// 1. msg-encoded tactics classtype cannot express.
	if msgWord(msg, "exfil") || msgWord(msg, "exfiltration") ||
		strings.Contains(msg, "data theft") || strings.Contains(msg, "data leak") {
		return policy.IPSCategoryExfiltration
	}
	if msgWord(msg, "lateral") {
		return policy.IPSCategoryLateralMovement
	}
	if msgWord(msg, "c2") || msgWord(msg, "cnc") ||
		strings.Contains(msg, "command and control") {
		return policy.IPSCategoryC2
	}

	// 2. classtype mapping — the primary signal.
	switch classtype {
	case "command-and-control":
		return policy.IPSCategoryC2
	case "trojan-activity", "malware-cnc", "coin-mining", "domain-c2":
		return policy.IPSCategoryMalware
	case "denial-of-service", "attempted-dos":
		return policy.IPSCategoryDoS
	case "web-application-attack", "attempted-admin", "attempted-user",
		"shellcode-detect", "exploit-kit", "attempted-recon":
		return policy.IPSCategoryExploit
	}

	// 3. whole-line keyword fallback.
	if strings.Contains(lower, "ransomware") || strings.Contains(lower, "trojan") ||
		strings.Contains(lower, "malware") {
		return policy.IPSCategoryMalware
	}
	if strings.Contains(lower, "exploit") || strings.Contains(lower, "cve-") {
		return policy.IPSCategoryExploit
	}
	return policy.IPSCategoryOther
}

// extractRuleOption pulls the value of a Suricata rule option
// (`key:value;`) from an already-lowercased rule line, honouring the
// quoted `msg:"..."` form. Mirrors the edge's extract_rule_option:
// the `key:` must sit on an option boundary so `xclasstype:` does not
// match `classtype:`.
func extractRuleOption(lowerLine, key string) string {
	needle := key + ":"
	from := 0
	for {
		rel := strings.Index(lowerLine[from:], needle)
		if rel < 0 {
			return ""
		}
		at := from + rel
		boundaryOK := at == 0
		if !boundaryOK {
			switch lowerLine[at-1] {
			case '(', ';', ' ', '\t':
				boundaryOK = true
			}
		}
		if boundaryOK {
			rest := strings.TrimLeft(lowerLine[at+len(needle):], " \t")
			if strings.HasPrefix(rest, `"`) {
				rest = rest[1:]
				if i := strings.IndexByte(rest, '"'); i >= 0 {
					return rest[:i]
				}
				return rest
			}
			if i := strings.IndexByte(rest, ';'); i >= 0 {
				return strings.TrimSpace(rest[:i])
			}
			return strings.TrimSpace(rest)
		}
		from = at + len(needle)
	}
}

// msgWord reports whether msg contains word as a complete
// alphanumeric token. Mirrors the edge's msg_has_word.
func msgWord(msg, word string) bool {
	for _, tok := range strings.FieldsFunc(msg, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}) {
		if tok == word {
			return true
		}
	}
	return false
}

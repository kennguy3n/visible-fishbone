package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Graph is the typed policy model. It encodes the architecture
// described in `ARCHITECTURE.md` §3.2: one graph spans NGFW, SWG,
// DNS, ZTNA, SD-WAN, and DLP enforcement domains; vertices are
// subjects (user, device, app, site, network) and predicates;
// edges are policy verbs (allow, deny, inspect, steer, decrypt,
// log, suggest-only).
//
// PR6 stored graphs as opaque JSON. PR7 introduces this typed
// model so:
//
//  1. The compiler can perform per-target rule transformations
//     (e.g. drop SWG-only rules from the endpoint bundle) instead
//     of forwarding the full document to every receiver.
//  2. Operators get schema validation at PUT time rather than at
//     compile time.
//  3. The change-simulator (Phase 3) and the AI auto-suggest path
//     can both reason about the same Go struct.
//
// The JSON shape is intentionally close to what PR6 already accepts
// so existing graphs continue to parse: any document with a
// `default_action` string and a `rules` array of well-formed rule
// objects is valid. Unknown fields under `rules[*]` are preserved
// in Extra so future versions can add fields without a migration.
type Graph struct {
	// Version is an opaque revision marker the operator can use to
	// label graphs in change-review tooling. Distinct from the
	// repository-assigned monotonic version on PolicyGraph.
	Version int `json:"version,omitempty"`

	// DefaultAction is the verb applied when no rule matches. Must
	// be one of the valid Verb values; "deny" is the safe baseline
	// the architecture mandates.
	DefaultAction Verb `json:"default_action,omitempty"`

	// Subjects, Predicates: typed vertex sets. Optional —
	// operators may inline subject/predicate matchers directly in
	// rules. When present, rules may reference these by name.
	Subjects   []Subject   `json:"subjects,omitempty"`
	Predicates []Predicate `json:"predicates,omitempty"`

	// Rules is the ordered list of enforcement rules. Order is
	// significant: the first matching rule wins, and the compiler
	// preserves order in each per-target bundle.
	Rules []Rule `json:"rules,omitempty"`
}

// Verb is a policy verb. The set mirrors ARCHITECTURE.md §3.2.
type Verb string

const (
	VerbAllow       Verb = "allow"
	VerbDeny        Verb = "deny"
	VerbInspect     Verb = "inspect"
	VerbSteer       Verb = "steer"
	VerbDecrypt     Verb = "decrypt"
	VerbLog         Verb = "log"
	VerbSuggestOnly Verb = "suggest_only"
)

// validVerbs is the set used by validation. Kept in alphabetical
// order so the error message is deterministic.
var validVerbs = []Verb{
	VerbAllow, VerbDecrypt, VerbDeny, VerbInspect,
	VerbLog, VerbSteer, VerbSuggestOnly,
}

// Domain enumerates the enforcement domain a rule applies to. The
// compiler uses Domain to decide which targets see the rule.
type Domain string

const (
	DomainNGFW  Domain = "ngfw"
	DomainSWG   Domain = "swg"
	DomainDNS   Domain = "dns"
	DomainZTNA  Domain = "ztna"
	DomainSDWAN Domain = "sdwan"
	DomainDLP   Domain = "dlp"
)

// validDomains is the set used by validation.
var validDomains = []Domain{
	DomainDLP, DomainDNS, DomainNGFW, DomainSDWAN, DomainSWG, DomainZTNA,
}

// SubjectKind enumerates the subject vertex types ARCHITECTURE.md
// §3.2 calls out.
type SubjectKind string

const (
	SubjectKindUser    SubjectKind = "user"
	SubjectKindDevice  SubjectKind = "device"
	SubjectKindApp     SubjectKind = "app"
	SubjectKindSite    SubjectKind = "site"
	SubjectKindNetwork SubjectKind = "network"
)

// Subject is a named subject vertex. Match is an opaque matcher
// blob whose schema depends on Kind — typed in PR8 once the
// matcher language is stable.
type Subject struct {
	Name  string          `json:"name"`
	Kind  SubjectKind     `json:"kind"`
	Match json.RawMessage `json:"match,omitempty"`
}

// Predicate is a named predicate vertex (e.g. "time_of_day:weekday",
// "geo:US", "category:malware").
type Predicate struct {
	Name  string          `json:"name"`
	Match json.RawMessage `json:"match,omitempty"`
}

// Rule is one enforcement edge. References to named Subject /
// Predicate vertices are stored in `SubjectRefs` / `PredicateRefs`;
// inline matchers can be embedded directly via `Subjects` /
// `Predicates`.
type Rule struct {
	// ID is a stable per-graph identifier so compiled bundles can
	// carry rule provenance and the simulator can diff rule
	// changes across versions.
	ID string `json:"id"`

	// Domain is one of {ngfw,swg,dns,ztna,sdwan,dlp}.
	Domain Domain `json:"domain"`

	// Verb is the policy verb to apply on match.
	Verb Verb `json:"verb"`

	// SubjectRefs / PredicateRefs reference named vertices.
	SubjectRefs   []string `json:"subject_refs,omitempty"`
	PredicateRefs []string `json:"predicate_refs,omitempty"`

	// Subjects / Predicates are inline matchers.
	Subjects   []Subject   `json:"subjects,omitempty"`
	Predicates []Predicate `json:"predicates,omitempty"`

	// Targets is an optional whitelist of bundle targets that
	// should include this rule. When empty (the default) the
	// compiler routes the rule based on Domain. When non-empty
	// the explicit list wins — useful for operator overrides
	// like "deploy this rule only to mobile endpoints".
	Targets []repository.PolicyBundleTarget `json:"targets,omitempty"`

	// Description is a free-form operator-facing label.
	Description string `json:"description,omitempty"`

	// Extra preserves unknown fields verbatim so future schema
	// extensions don't require a migration of existing graphs.
	// Populated by Rule.UnmarshalJSON and re-emitted with sorted
	// keys by encodeRule so the bundle bytes are deterministic.
	Extra map[string]json.RawMessage `json:"-"`
}

// knownRuleFields enumerates the JSON keys consumed by the typed
// Rule struct. Any other key on a rule object is preserved into
// Rule.Extra by UnmarshalJSON below so the compiler does not
// silently strip schema additions introduced after this code shipped.
var knownRuleFields = map[string]struct{}{
	"id":             {},
	"domain":         {},
	"verb":           {},
	"subject_refs":   {},
	"predicate_refs": {},
	"subjects":       {},
	"predicates":     {},
	"targets":        {},
	"description":    {},
}

// UnmarshalJSON decodes a rule object and routes unknown fields
// into Extra. Defined on a pointer receiver because json.Unmarshal
// requires it. Uses a typed alias to avoid infinite recursion into
// this method during the typed decode pass.
func (r *Rule) UnmarshalJSON(data []byte) error {
	type alias Rule
	var a alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*r = Rule(a)
	// Second pass: walk the raw object and stash anything we
	// didn't recognise into Extra.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		// A non-object payload (e.g. a JSON null) can't carry
		// Extra fields; the typed decode above already raised
		// the right error for malformed objects.
		return nil //nolint:nilerr
	}
	for k, v := range raw {
		if _, known := knownRuleFields[k]; known {
			continue
		}
		if r.Extra == nil {
			r.Extra = make(map[string]json.RawMessage, len(raw))
		}
		r.Extra[k] = v
	}
	return nil
}

// ParseGraph decodes a JSON document into a Graph and validates it.
// Empty / nil input returns the default-safe graph (default_action =
// deny, no rules) so receivers always have something concrete to
// fall back on. Returns ErrInvalidArgument-wrapped errors when the
// graph violates the schema.
func ParseGraph(raw json.RawMessage) (Graph, error) {
	if len(raw) == 0 {
		return Graph{DefaultAction: VerbDeny}, nil
	}
	var g Graph
	if err := json.Unmarshal(raw, &g); err != nil {
		return Graph{}, fmt.Errorf("decode policy graph: %w: %w", repository.ErrInvalidArgument, err)
	}
	if g.DefaultAction == "" {
		g.DefaultAction = VerbDeny
	}
	if err := g.Validate(); err != nil {
		return Graph{}, err
	}
	return g, nil
}

// Validate checks the typed graph against the schema invariants.
// Returns a wrapped repository.ErrInvalidArgument so the handler
// layer maps it to a 400.
func (g Graph) Validate() error {
	if !isValidVerb(g.DefaultAction) {
		return fmt.Errorf("default_action %q: %w", g.DefaultAction, repository.ErrInvalidArgument)
	}
	seenSubjectNames := map[string]struct{}{}
	for i, s := range g.Subjects {
		if s.Name == "" {
			return fmt.Errorf("subjects[%d]: empty name: %w", i, repository.ErrInvalidArgument)
		}
		if _, dup := seenSubjectNames[s.Name]; dup {
			return fmt.Errorf("subjects[%d]: duplicate name %q: %w", i, s.Name, repository.ErrInvalidArgument)
		}
		seenSubjectNames[s.Name] = struct{}{}
		if !isValidSubjectKind(s.Kind) {
			return fmt.Errorf("subjects[%d].kind %q: %w", i, s.Kind, repository.ErrInvalidArgument)
		}
	}
	seenPredicateNames := map[string]struct{}{}
	for i, p := range g.Predicates {
		if p.Name == "" {
			return fmt.Errorf("predicates[%d]: empty name: %w", i, repository.ErrInvalidArgument)
		}
		if _, dup := seenPredicateNames[p.Name]; dup {
			return fmt.Errorf("predicates[%d]: duplicate name %q: %w", i, p.Name, repository.ErrInvalidArgument)
		}
		seenPredicateNames[p.Name] = struct{}{}
	}
	seenRuleIDs := map[string]struct{}{}
	for i, r := range g.Rules {
		if r.ID == "" {
			return fmt.Errorf("rules[%d]: empty id: %w", i, repository.ErrInvalidArgument)
		}
		if _, dup := seenRuleIDs[r.ID]; dup {
			return fmt.Errorf("rules[%d]: duplicate id %q: %w", i, r.ID, repository.ErrInvalidArgument)
		}
		seenRuleIDs[r.ID] = struct{}{}
		if !isValidDomain(r.Domain) {
			return fmt.Errorf("rules[%d].domain %q: %w", i, r.Domain, repository.ErrInvalidArgument)
		}
		if !isValidVerb(r.Verb) {
			return fmt.Errorf("rules[%d].verb %q: %w", i, r.Verb, repository.ErrInvalidArgument)
		}
		for j, ref := range r.SubjectRefs {
			if _, ok := seenSubjectNames[ref]; !ok {
				return fmt.Errorf("rules[%d].subject_refs[%d]: unknown subject %q: %w", i, j, ref, repository.ErrInvalidArgument)
			}
		}
		for j, ref := range r.PredicateRefs {
			if _, ok := seenPredicateNames[ref]; !ok {
				return fmt.Errorf("rules[%d].predicate_refs[%d]: unknown predicate %q: %w", i, j, ref, repository.ErrInvalidArgument)
			}
		}
		for j, t := range r.Targets {
			if !isValidTarget(t) {
				return fmt.Errorf("rules[%d].targets[%d] %q: %w", i, j, t, repository.ErrInvalidArgument)
			}
		}
	}
	return nil
}

// CompileTarget returns the rule subset that applies to `target`,
// preserving rule order. The mapping from Domain to target follows
// the wire architecture in `ARCHITECTURE.md` §3.2 and §5:
//
//   - Edge VM bundle (per-edge): NGFW, SD-WAN, SWG, DNS, ZTNA.
//   - Endpoint desktop bundle: ZTNA, DLP, SD-WAN steering hints,
//     local DNS/SWG steering decisions. Excludes inspection rules
//     that only the edge can enforce.
//   - Cloud-PoP bundle: SWG, DNS, ZTNA (for cloud-delivered
//     inspection); excludes per-site NGFW / SD-WAN rules.
//   - Mobile endpoint bundle: ZTNA only — the mobile platform
//     can't run the desktop posture/DLP stack.
//
// Explicit Rule.Targets overrides this mapping when non-empty.
func (g Graph) CompileTarget(target repository.PolicyBundleTarget) []Rule {
	out := make([]Rule, 0, len(g.Rules))
	for _, r := range g.Rules {
		if len(r.Targets) > 0 {
			if containsTarget(r.Targets, target) {
				out = append(out, r)
			}
			continue
		}
		if domainTargets(r.Domain)[target] {
			out = append(out, r)
		}
	}
	return out
}

// SortedExtra returns the rule's Extra fields with keys sorted, used
// when serialising a rule to ensure byte-identical output.
func (r Rule) SortedExtra() []string {
	if len(r.Extra) == 0 {
		return nil
	}
	keys := make([]string, 0, len(r.Extra))
	for k := range r.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isValidVerb(v Verb) bool {
	for _, w := range validVerbs {
		if v == w {
			return true
		}
	}
	return false
}

func isValidDomain(d Domain) bool {
	for _, w := range validDomains {
		if d == w {
			return true
		}
	}
	return false
}

func isValidSubjectKind(k SubjectKind) bool {
	switch k {
	case SubjectKindUser, SubjectKindDevice, SubjectKindApp, SubjectKindSite, SubjectKindNetwork:
		return true
	}
	return false
}

func isValidTarget(t repository.PolicyBundleTarget) bool {
	switch t {
	case repository.PolicyBundleTargetEdge,
		repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud,
		repository.PolicyBundleTargetMobile:
		return true
	}
	return false
}

func containsTarget(ts []repository.PolicyBundleTarget, t repository.PolicyBundleTarget) bool {
	for _, x := range ts {
		if x == t {
			return true
		}
	}
	return false
}

// domainTargets is the canonical Domain → {target: bool} routing
// matrix the compiler falls back to when a Rule does not pin its
// targets explicitly. Comments cite the ARCHITECTURE.md sections
// each route descends from.
func domainTargets(d Domain) map[repository.PolicyBundleTarget]bool {
	switch d {
	case DomainNGFW:
		// §4 Edge / §5 (mobile cannot run NGFW). NGFW rules ship
		// to the edge VM only — the endpoint kernel hooks
		// already enforce host-firewall posture separately.
		return map[repository.PolicyBundleTarget]bool{
			repository.PolicyBundleTargetEdge: true,
		}
	case DomainSWG:
		// §3.2 + §4: SWG is enforced at the edge and the cloud
		// PoP. Endpoint receives steering hints (covered in
		// SD-WAN below) but not the URL category tables.
		return map[repository.PolicyBundleTarget]bool{
			repository.PolicyBundleTargetEdge:  true,
			repository.PolicyBundleTargetCloud: true,
		}
	case DomainDNS:
		// §3.2: DNS rules apply at every recursive resolver in
		// the path — edge, cloud, and the endpoint stub
		// resolver. Mobile gets DNS via the endpoint bundle, not
		// a separate mobile-DNS bundle.
		return map[repository.PolicyBundleTarget]bool{
			repository.PolicyBundleTargetEdge:     true,
			repository.PolicyBundleTargetCloud:    true,
			repository.PolicyBundleTargetEndpoint: true,
		}
	case DomainZTNA:
		// §5.3: ZTNA rules ship to every receiver because the
		// device-bound mTLS identity is enforced at every hop.
		return map[repository.PolicyBundleTarget]bool{
			repository.PolicyBundleTargetEdge:     true,
			repository.PolicyBundleTargetCloud:    true,
			repository.PolicyBundleTargetEndpoint: true,
			repository.PolicyBundleTargetMobile:   true,
		}
	case DomainSDWAN:
		// §4: SD-WAN steering rules ship to the edge (where the
		// overlay tunnels terminate) and the endpoint (which
		// uses the steering hints to pick the right tunnel).
		return map[repository.PolicyBundleTarget]bool{
			repository.PolicyBundleTargetEdge:     true,
			repository.PolicyBundleTargetEndpoint: true,
		}
	case DomainDLP:
		// §3.2: DLP is enforced at the endpoint (clipboard,
		// upload-channel) and at the edge / cloud (for outbound
		// inspection). Mobile DLP is out of scope until PR9.
		return map[repository.PolicyBundleTarget]bool{
			repository.PolicyBundleTargetEdge:     true,
			repository.PolicyBundleTargetCloud:    true,
			repository.PolicyBundleTargetEndpoint: true,
		}
	}
	return nil
}

// EncodeRules canonicalises the rule set for inclusion in the
// bundle envelope. Keys inside `Extra` are sorted, struct fields
// are emitted in declaration order, and unset optional fields are
// omitted via `omitempty` so empty bundles produce identical bytes
// across runs.
func EncodeRules(rules []Rule) (json.RawMessage, error) {
	if len(rules) == 0 {
		return json.RawMessage(`[]`), nil
	}
	out := []byte{'['}
	for i, r := range rules {
		if i > 0 {
			out = append(out, ',')
		}
		// Hand-roll the JSON so Extra is emitted with sorted
		// keys and we keep byte-determinism across runs without
		// pulling in a third-party canonical-json package.
		buf, err := encodeRule(r)
		if err != nil {
			return nil, err
		}
		out = append(out, buf...)
	}
	out = append(out, ']')
	return out, nil
}

func encodeRule(r Rule) ([]byte, error) {
	type alias Rule // avoid recursion into our custom MarshalJSON
	a := alias(r)
	buf, err := json.Marshal(&a)
	if err != nil {
		return nil, err
	}
	if len(r.Extra) == 0 {
		return buf, nil
	}
	// Merge Extra into the encoded object, sorted by key, before
	// the closing brace. We only support a single-level merge
	// because Extra holds raw JSON sub-documents.
	if len(buf) < 2 || buf[len(buf)-1] != '}' {
		return nil, errors.New("encode rule: malformed json")
	}
	keys := r.SortedExtra()
	body := buf[:len(buf)-1]
	if !strings.HasSuffix(string(body), "{") {
		body = append(body, ',')
	}
	for i, k := range keys {
		if i > 0 {
			body = append(body, ',')
		}
		kb, _ := json.Marshal(k)
		body = append(body, kb...)
		body = append(body, ':')
		body = append(body, []byte(r.Extra[k])...)
	}
	body = append(body, '}')
	return body, nil
}

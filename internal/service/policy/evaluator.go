// Package policy — evaluator.go implements GraphEvaluator, the
// default Simulator.Evaluator backed by a parsed policy Graph.
//
// The evaluator is the runtime counterpart of the per-target
// compiler in graph.go: where CompileTarget slices the graph
// down to "rules that ship to target X", GraphEvaluator walks
// those rules at simulation time to predict the verdict a real
// edge / endpoint would apply to a given envelope. It is
// deliberately a *simulation* model — the production data plane
// is the Rust enforcement stack, and exact byte-for-byte parity
// with its matchers is out of scope for this PR. What
// GraphEvaluator does guarantee:
//
//   - Deterministic, side-effect-free. Same (graph, envelope)
//     always produces the same verdict.
//   - Rule order is preserved (first match wins) so the
//     evaluator's verdict matches the agent's for any rule the
//     simulator understands.
//   - Domain-to-event-class routing matches the same matrix the
//     compiler uses (domainTargets) so an NGFW rule that the
//     compiler routes only to the edge target also matches only
//     flow events at simulation time.
//   - Unknown matcher dialects degrade to "no match" (the rule
//     is skipped, never matched-against-a-broken-predicate),
//     which keeps the simulator from over-reporting changes.
//   - When no rule matches, the graph's DefaultAction is
//     applied — same as the agent.
//
// Matcher language scope for this PR:
//
//   - SubjectRefs / inline Subjects: matched against the
//     envelope's TenantID / DeviceID / SiteID via a JSON
//     equality predicate on a small set of fields (id, ids).
//     Anything else in Subject.Match is treated as a no-op
//     match — the simulator deliberately under-matches rather
//     than over-matches.
//   - PredicateRefs / inline Predicates: matched against the
//     event payload via a small JSON equality DSL keyed on
//     payload field names. Same under-match-on-unknown
//     fallback.
//   - Rule.Extra fields are passed through but never matched
//     (they're operator-facing labels, not match input).
//
// The matcher language is intentionally a strict subset of what
// the production data plane supports. As the typed matcher
// language (PR8, per graph.go:111) lands, this evaluator will
// pick up the new dialects automatically — the parsed Subject /
// Predicate structs are shared.

package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// GraphEvaluatorFactory is the default EvaluatorFactory. It
// parses a stored PolicyGraph into the typed model and wraps
// it in a GraphEvaluator. Construction is cheap (single
// json.Unmarshal); the simulator caches the per-side evaluator
// for the run.
type GraphEvaluatorFactory struct{}

// Build implements EvaluatorFactory.
func (GraphEvaluatorFactory) Build(_ context.Context, g repository.PolicyGraph) (Evaluator, error) {
	parsed, err := ParseGraph(g.Graph)
	if err != nil {
		return nil, fmt.Errorf("graph %s: %w", g.ID, err)
	}
	return &GraphEvaluator{graph: parsed}, nil
}

// GraphEvaluator implements Evaluator over a parsed Graph.
// Concurrency-safe by construction — the graph is treated as
// immutable after Build, and Evaluate reads only.
type GraphEvaluator struct {
	graph Graph
}

// Graph returns the underlying typed graph. Useful for tests
// and for callers that want to render the policy alongside the
// simulation report.
func (e *GraphEvaluator) Graph() Graph { return e.graph }

// Principal is a resolved subject identity threaded into
// evaluation by callers that know who the actor is even though
// the envelope can't carry it (the NL policy-query path resolves
// the named user from the tenant directory). It carries the
// user's own ID plus the IDs of the roles/groups it belongs to,
// so a user Subject matches when its id/ids name either the user
// or any of its groups — standard membership semantics.
//
// The data-plane (edge-telemetry) path supplies no Principal:
// user identity genuinely isn't on those envelopes, so user
// Subjects fall back to under-match-on-unknown there, unchanged.
type Principal struct {
	UserID  uuid.UUID
	RoleIDs []uuid.UUID
}

// has reports whether id names the principal itself or one of
// its roles/groups.
func (p *Principal) has(id uuid.UUID) bool {
	if id == p.UserID {
		return true
	}
	for _, r := range p.RoleIDs {
		if r == id {
			return true
		}
	}
	return false
}

// PrincipalEvaluator is the optional extension an Evaluator
// implements when it can evaluate user-subject rules against a
// caller-resolved identity. GraphEvaluator implements it; the NL
// policy-query path type-asserts for it so resolving a user makes
// user-subject rules actually evaluate instead of being skipped.
type PrincipalEvaluator interface {
	EvaluateWithPrincipal(ctx context.Context, env schema.Envelope, principal *Principal) (schema.Verdict, error)
}

// Evaluate implements Evaluator. Walks the rules in order and
// returns the verb of the first matching rule as a Verdict; if
// no rule matches, returns the graph's DefaultAction. The
// returned error is non-nil only when the envelope itself is
// malformed (a real-edge-side validation failure that the
// simulator surfaces via report.PrevErrors / NextErrors).
//
// No principal is supplied on this path, so user Subjects fall
// back to under-match-on-unknown — preserving the data-plane
// simulator's behaviour for edge telemetry, which carries no
// user identity.
func (e *GraphEvaluator) Evaluate(ctx context.Context, env schema.Envelope) (schema.Verdict, error) {
	return e.evaluate(ctx, env, nil)
}

// EvaluateWithPrincipal implements PrincipalEvaluator: same as
// Evaluate, but user Subjects are tested against the resolved
// principal (its own user ID + role/group IDs) rather than being
// skipped. A nil principal is identical to Evaluate.
func (e *GraphEvaluator) EvaluateWithPrincipal(ctx context.Context, env schema.Envelope, principal *Principal) (schema.Verdict, error) {
	return e.evaluate(ctx, env, principal)
}

func (e *GraphEvaluator) evaluate(_ context.Context, env schema.Envelope, principal *Principal) (schema.Verdict, error) {
	// Decode the per-class payload once so per-rule predicate
	// matching can consult it. A failure to decode is a
	// per-envelope error, NOT a per-rule error — the same
	// envelope would have failed at the edge too.
	payload, payloadErr := decodePayload(env)
	if payloadErr != nil {
		return "", payloadErr
	}

	for i := range e.graph.Rules {
		r := e.graph.Rules[i]
		if !ruleMatchesEvent(r, env, payload, e.graph.Subjects, e.graph.Predicates, principal) {
			continue
		}
		v := verbToVerdict(r.Verb)
		if v == "" {
			// A rule with a non-mappable verb (shouldn't
			// happen post-Validate) is treated as
			// "advisory" — skip and keep looking.
			continue
		}
		return v, nil
	}
	v := verbToVerdict(e.graph.DefaultAction)
	if v == "" {
		// Defensive: a Validate-passed graph always has a
		// known default action, but if not (e.g. a future
		// graph schema introduces a new verb this binary
		// doesn't know about), fall back to deny — the
		// safe baseline the architecture mandates.
		return schema.VerdictDeny, nil
	}
	return v, nil
}

// decodePayload sniffs the envelope's EventClass and decodes
// the payload into the corresponding typed struct via the
// schema package's UnpackPayload (msgpack). Returns a non-nil
// any on success; (nil, nil) when the class is one this
// simulator doesn't have a typed view of yet (the per-rule
// matcher falls back to envelope-only matching for those
// classes). A non-nil error means the payload itself is
// malformed — the simulator surfaces it via PrevErrors /
// NextErrors on the report so an operator sees that a fraction
// of envelopes couldn't be evaluated.
func decodePayload(env schema.Envelope) (any, error) {
	if len(env.Payload) == 0 {
		return nil, nil
	}
	switch env.EventClass {
	case schema.EventClassFlow:
		var f schema.FlowEvent
		if err := schema.UnpackPayload(env.Payload, &f); err != nil {
			return nil, fmt.Errorf("flow payload: %w", err)
		}
		return f, nil
	case schema.EventClassDNS:
		var d schema.DNSEvent
		if err := schema.UnpackPayload(env.Payload, &d); err != nil {
			return nil, fmt.Errorf("dns payload: %w", err)
		}
		return d, nil
	case schema.EventClassHTTP:
		var h schema.HTTPEvent
		if err := schema.UnpackPayload(env.Payload, &h); err != nil {
			return nil, fmt.Errorf("http payload: %w", err)
		}
		return h, nil
	}
	return nil, nil
}

// ruleMatchesEvent applies the per-rule matchers. Returns true
// iff the rule should be applied to this envelope.
func ruleMatchesEvent(
	r Rule,
	env schema.Envelope,
	payload any,
	subjectDefs []Subject,
	predicateDefs []Predicate,
	principal *Principal,
) bool {
	if !domainMatchesEventClass(r.Domain, env.EventClass) {
		return false
	}

	if !matchSubjects(r, env, subjectDefs, principal) {
		return false
	}
	if !matchPredicates(r, payload, predicateDefs) {
		return false
	}
	return true
}

// domainMatchesEventClass is the simulator-side counterpart of
// graph.domainTargets: it answers "does this rule's domain
// apply to events of this class". The mapping is conservative:
// when in doubt the rule matches (the production data plane is
// always the authoritative arbiter), which keeps the simulator
// from missing changes.
func domainMatchesEventClass(d Domain, cls schema.EventClass) bool {
	switch d {
	case DomainNGFW, DomainSDWAN:
		return cls == schema.EventClassFlow
	case DomainDNS:
		return cls == schema.EventClassDNS
	case DomainSWG, DomainInlineCASB:
		// Inline-CASB rules ride the SWG bundle slice and are
		// enforced on the same HTTP path (SaaS upload/share/
		// download/delete), so they share SWG's event-class
		// mapping. Keeping this in lockstep with domainTargets
		// (which groups DomainInlineCASB with DomainSWG) means
		// policy simulation covers inline-CASB rule changes too.
		return cls == schema.EventClassHTTP || cls == schema.EventClassFlow
	case DomainZTNA:
		// ZTNA verdicts cover both flow + dedicated ZTNA events.
		return cls == schema.EventClassFlow || cls == schema.EventClassZTNA
	case DomainDLP:
		// DLP rules typically apply to HTTP uploads + flow
		// payloads. Conservative: match anything but DNS.
		return cls != schema.EventClassDNS
	}
	// Unknown domain (e.g. future schema extension) -> no
	// match in this binary; safer than over-matching.
	return false
}

// matchSubjects returns true iff every named subject reference +
// every inline subject on the rule matches the envelope. A rule
// with no subject constraints matches every envelope (matching
// the data-plane semantics of "scope-less rules").
func matchSubjects(r Rule, env schema.Envelope, defs []Subject, principal *Principal) bool {
	if len(r.SubjectRefs) == 0 && len(r.Subjects) == 0 {
		return true
	}
	for _, ref := range r.SubjectRefs {
		for _, s := range defs {
			if s.Name != ref {
				continue
			}
			if !subjectMatchesEnvelope(s, env, principal) {
				return false
			}
			break
		}
	}
	for _, s := range r.Subjects {
		if !subjectMatchesEnvelope(s, env, principal) {
			return false
		}
	}
	return true
}

// matchPredicates returns true iff every named predicate ref +
// every inline predicate matches the payload. Unknown matcher
// shapes return true (under-match-on-unknown), per the package
// header.
func matchPredicates(r Rule, payload any, defs []Predicate) bool {
	if len(r.PredicateRefs) == 0 && len(r.Predicates) == 0 {
		return true
	}
	for _, ref := range r.PredicateRefs {
		for _, p := range defs {
			if p.Name != ref {
				continue
			}
			if !predicateMatchesPayload(p, payload) {
				return false
			}
			break
		}
	}
	for _, p := range r.Predicates {
		if !predicateMatchesPayload(p, payload) {
			return false
		}
	}
	return true
}

// subjectMatchesEnvelope decodes a Subject.Match JSON document
// and tests it against the envelope. The supported dialects are
// intentionally small (id, ids) — see the package header for
// the matcher-language scope.
func subjectMatchesEnvelope(s Subject, env schema.Envelope, principal *Principal) bool {
	if len(s.Match) == 0 {
		// A subject with no Match document is a free-floating
		// label (the operator named the subject but didn't
		// constrain it). Treat as "matches everything" — the
		// compiler does the same.
		return true
	}
	var m subjectMatchDoc
	if err := json.Unmarshal(s.Match, &m); err != nil {
		return false
	}
	if s.Kind == SubjectKindUser {
		// User identity isn't on the envelope. When a caller has
		// resolved the actor (the NL policy-query path), test the
		// matcher's id/ids against the principal's identity set
		// (its own user ID + its role/group IDs) so per-user and
		// per-group user rules actually evaluate. Without a
		// principal (the data-plane simulator over edge telemetry)
		// fall back to under-match-on-unknown, unchanged.
		if principal == nil {
			return true
		}
		return matchDocAgainst(m, principal.has)
	}
	var target uuid.UUID
	switch s.Kind {
	case SubjectKindDevice:
		target = env.DeviceID
	case SubjectKindSite:
		if env.SiteID == nil {
			return false
		}
		target = *env.SiteID
	case SubjectKindApp, SubjectKindNetwork:
		// App / network identity isn't on the envelope. Leave to
		// the under-match-on-unknown fallback so the simulator
		// doesn't over-report.
		return true
	default:
		return true
	}
	return matchDocAgainst(m, func(id uuid.UUID) bool { return id == target })
}

// matchDocAgainst evaluates a subjectMatchDoc's id/ids constraints
// using the supplied membership test: an `id` constraint must be
// satisfied by it, and an `ids` constraint must be satisfied by at
// least one entry. Unparseable UUIDs in the doc fail the single-id
// constraint and are skipped in the ids set (matching the prior
// device/site semantics). Both constraints, when present, must hold.
func matchDocAgainst(m subjectMatchDoc, matches func(uuid.UUID) bool) bool {
	if m.ID != "" {
		parsed, err := uuid.Parse(m.ID)
		if err != nil || !matches(parsed) {
			return false
		}
	}
	if len(m.IDs) > 0 {
		hit := false
		for _, raw := range m.IDs {
			parsed, err := uuid.Parse(raw)
			if err != nil {
				continue
			}
			if matches(parsed) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// predicateMatchesPayload tests a Predicate against the typed
// payload. The matcher dialect is keyed on payload field names
// (e.g. "query" for DNS, "host" for HTTP, "dst_port" for flow).
func predicateMatchesPayload(p Predicate, payload any) bool {
	if len(p.Match) == 0 {
		return true
	}
	var m predicateMatchDoc
	if err := json.Unmarshal(p.Match, &m); err != nil {
		return false
	}
	switch payloadTyped := payload.(type) {
	case schema.FlowEvent:
		return matchFlow(m, payloadTyped)
	case schema.DNSEvent:
		return matchDNS(m, payloadTyped)
	case schema.HTTPEvent:
		return matchHTTP(m, payloadTyped)
	}
	// No typed payload — under-match-on-unknown.
	return true
}

// subjectMatchDoc is the JSON shape this simulator understands
// inside Subject.Match. Anything else is silently no-op (under
// match) — the operator-authored matcher is a strict subset of
// the production language.
type subjectMatchDoc struct {
	ID  string   `json:"id,omitempty"`
	IDs []string `json:"ids,omitempty"`
}

// predicateMatchDoc is the JSON shape this simulator understands
// inside Predicate.Match. All fields optional; the predicate
// matches iff every populated field matches the payload.
type predicateMatchDoc struct {
	// Common fields
	Verdict string `json:"verdict,omitempty"`

	// Flow fields
	DstIP   string `json:"dst_ip,omitempty"`
	DstPort uint16 `json:"dst_port,omitempty"`
	Proto   string `json:"protocol,omitempty"`

	// DNS fields
	Query string `json:"query,omitempty"`
	QType string `json:"qtype,omitempty"`

	// HTTP fields
	Host   string `json:"host,omitempty"`
	Method string `json:"method,omitempty"`
}

func matchFlow(m predicateMatchDoc, f schema.FlowEvent) bool {
	if m.Verdict != "" && string(f.Verdict) != m.Verdict {
		return false
	}
	if m.DstIP != "" && f.DstIP != m.DstIP {
		return false
	}
	if m.DstPort != 0 && f.DstPort != m.DstPort {
		return false
	}
	if m.Proto != "" && f.Protocol != m.Proto {
		return false
	}
	return true
}

func matchDNS(m predicateMatchDoc, d schema.DNSEvent) bool {
	if m.Verdict != "" && string(d.Verdict) != m.Verdict {
		return false
	}
	if m.Query != "" && d.Query != m.Query {
		return false
	}
	if m.QType != "" && d.QType != m.QType {
		return false
	}
	return true
}

func matchHTTP(m predicateMatchDoc, h schema.HTTPEvent) bool {
	if m.Verdict != "" && string(h.Verdict) != m.Verdict {
		return false
	}
	if m.Host != "" && h.Host != m.Host {
		return false
	}
	if m.Method != "" && h.Method != m.Method {
		return false
	}
	return true
}

// verbToVerdict maps a policy verb to the corresponding
// telemetry verdict. The mapping mirrors the production data
// plane's convention:
//   - allow / steer -> allow (steer is a routing hint, the
//     flow itself is allowed)
//   - deny -> deny
//   - inspect / decrypt -> inspect (decrypt is a TLS-MITM
//     variant of inspect)
//   - log -> log
//   - suggest_only -> log (advisory: edge logs but doesn't
//     enforce)
func verbToVerdict(v Verb) schema.Verdict {
	switch v {
	case VerbAllow, VerbSteer:
		return schema.VerdictAllow
	case VerbDeny:
		return schema.VerdictDeny
	case VerbInspect, VerbDecrypt:
		return schema.VerdictInspect
	case VerbLog, VerbSuggestOnly:
		return schema.VerdictLog
	}
	return ""
}

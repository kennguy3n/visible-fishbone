package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// Evaluation modes reported on NLQueryResponse.EvaluationMode so an
// API consumer can tell how the verdict was produced.
const (
	// evalModeCompiledBundle: the verdict came from running the
	// tenant's live compiled policy graph through the policy
	// evaluator. This is the authoritative path.
	evalModeCompiledBundle = "compiled-bundle"
	// evalModeNoPolicy: a policy graph source is wired but the
	// tenant has no live (promoted) graph yet, so the heuristic
	// default was applied.
	evalModeNoPolicy = "no-policy"
	// evalModeDefaultHeuristic: no policy graph source is wired
	// (or evaluation failed), so the heuristic default was applied.
	evalModeDefaultHeuristic = "default-heuristic"
)

// PolicyGraphSource provides read access to a tenant's live
// (promoted) policy graph. *policy.Service satisfies it via
// GetCurrentGraph; the NL-query engine uses it to evaluate questions
// against the real compiled policy rather than a heuristic default.
type PolicyGraphSource interface {
	GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (repository.PolicyGraph, error)
}

// NLQueryEngine handles natural language policy queries. It uses
// the LLM to parse intent, then evaluates against the deterministic
// policy evaluator. The LLM never produces the verdict — only the
// structured query interpretation; the verdict comes from the
// tenant's compiled policy graph (when a PolicyGraphSource is wired)
// or a conservative heuristic default otherwise.
type NLQueryEngine struct {
	llm     LLMProvider
	graphs  PolicyGraphSource
	factory policy.EvaluatorFactory
}

// NLQueryOption customises a NLQueryEngine.
type NLQueryOption func(*NLQueryEngine)

// WithPolicyGraphSource wires the engine to a tenant's live policy
// graph so verdicts are produced by the real compiled-bundle
// evaluator instead of the heuristic fallback.
func WithPolicyGraphSource(src PolicyGraphSource) NLQueryOption {
	return func(e *NLQueryEngine) { e.graphs = src }
}

// NewNLQueryEngine constructs a NLQueryEngine. llm may be nil
// (structured-query-only mode). Without WithPolicyGraphSource the
// engine falls back to a heuristic verdict.
func NewNLQueryEngine(llm LLMProvider, opts ...NLQueryOption) *NLQueryEngine {
	e := &NLQueryEngine{llm: llm, factory: policy.GraphEvaluatorFactory{}}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// NLQueryRequest is the input for a natural language policy query.
type NLQueryRequest struct {
	Question string    `json:"question"`
	TenantID uuid.UUID `json:"tenant_id"`
}

// NLQueryResponse is the deterministic answer to a policy query.
type NLQueryResponse struct {
	Verdict      string   `json:"verdict"` // allow, deny, inspect, log, alert, unknown
	MatchedRules []string `json:"matched_rules"`
	Explanation  string   `json:"explanation"`
	Confidence   float64  `json:"confidence"`
	AIGenerated  bool     `json:"ai_generated"`
	ModelID      string   `json:"model_id,omitempty"`
	// EvaluationMode records how the verdict was produced:
	// compiled-bundle (real policy graph), no-policy (no live graph),
	// or default-heuristic (no policy source / evaluation error).
	EvaluationMode string `json:"evaluation_mode,omitempty"`
}

// ParsedIntent is the structured interpretation of a natural
// language query.
type ParsedIntent struct {
	UserRef   string `json:"user_ref,omitempty"`
	AppRef    string `json:"app_ref,omitempty"`
	DeviceRef string `json:"device_ref,omitempty"`
	Action    string `json:"action,omitempty"` // access, block, etc.
}

// Query processes a natural language policy question. When the LLM
// is available it parses the free-form question into structured
// entities; when nil, it attempts direct entity extraction from the
// question text.
func (e *NLQueryEngine) Query(ctx context.Context, req NLQueryRequest) (NLQueryResponse, error) {
	if req.Question == "" {
		return NLQueryResponse{}, fmt.Errorf("ai/nl_query: empty question")
	}

	var intent ParsedIntent
	var aiGenerated bool
	var modelID string

	if e.llm != nil {
		parsed, resp, err := e.parseWithLLM(ctx, req.Question)
		if err != nil {
			// Fall back to structured parsing on LLM failure.
			intent = e.parseStructured(req.Question)
		} else {
			intent = parsed
			aiGenerated = true
			modelID = resp.ModelID
		}
	} else {
		intent = e.parseStructured(req.Question)
	}

	verdict, matchedRules, explanation, mode := e.decide(ctx, req.TenantID, intent)

	confidence := 0.5
	if aiGenerated {
		confidence = 0.8
	}
	if intent.UserRef == "" && intent.AppRef == "" && intent.DeviceRef == "" {
		confidence = 0.2
		if verdict == "unknown" {
			explanation = "Could not extract entity references from the query."
		}
	}
	// A verdict from the compiled policy graph is authoritative and
	// deterministic regardless of how the intent was parsed, so it
	// carries high confidence.
	if mode == evalModeCompiledBundle {
		confidence = 0.95
	}

	return NLQueryResponse{
		Verdict:        verdict,
		MatchedRules:   matchedRules,
		Explanation:    explanation,
		Confidence:     confidence,
		AIGenerated:    aiGenerated,
		ModelID:        modelID,
		EvaluationMode: mode,
	}, nil
}

func (e *NLQueryEngine) parseWithLLM(ctx context.Context, question string) (ParsedIntent, LLMResponse, error) {
	prompt := `You are a policy query parser for ShieldNet Gateway. ` +
		`Parse the following question into a JSON object with fields: ` +
		`"user_ref" (user identifier), "app_ref" (application), ` +
		`"device_ref" (device identifier), "action" (access/block/etc). ` +
		`Only output valid JSON, no explanation.` +
		"\n\nQuestion: " + question

	resp, err := e.llm.Complete(ctx, LLMRequest{
		Prompt:         prompt,
		TemperatureX10: 1,
		MaxTokens:      200,
	})
	if err != nil {
		return ParsedIntent{}, LLMResponse{}, err
	}

	var intent ParsedIntent
	text := strings.TrimSpace(resp.Text)
	// Extract JSON from the response (it may be wrapped in markdown).
	if idx := strings.Index(text, "{"); idx >= 0 {
		end := strings.LastIndex(text, "}")
		if end > idx {
			text = text[idx : end+1]
		}
	}
	if err := json.Unmarshal([]byte(text), &intent); err != nil {
		return ParsedIntent{}, LLMResponse{}, fmt.Errorf("ai/nl_query: parse LLM intent: %w", err)
	}
	return intent, resp, nil
}

// entityRefCutset is the punctuation trimmed from entity references
// extracted from a free-form question. Without it a trailing "?" in
// "...access app salesforce?" yields AppRef="salesforce?", which then
// matches no host/device rule and silently falls through to the
// graph's DefaultAction — an incorrect verdict reported with full
// compiled-bundle authority.
const entityRefCutset = "?!.,;:\"'`()[]{}<>"

// cleanEntityRef strips surrounding punctuation and whitespace from a
// token extracted as an entity reference.
func cleanEntityRef(s string) string {
	return strings.Trim(s, entityRefCutset)
}

func (e *NLQueryEngine) parseStructured(question string) ParsedIntent {
	q := strings.ToLower(question)
	parts := strings.Fields(q)
	var intent ParsedIntent

	for i, p := range parts {
		token := cleanEntityRef(p)
		if i+1 >= len(parts) {
			continue
		}
		next := cleanEntityRef(parts[i+1])
		if next == "" {
			continue
		}
		switch token {
		case "user":
			if intent.UserRef == "" {
				intent.UserRef = next
			}
		case "app", "application":
			if intent.AppRef == "" {
				intent.AppRef = next
			}
		case "device":
			if intent.DeviceRef == "" {
				intent.DeviceRef = next
			}
		}
	}

	if strings.Contains(q, "access") {
		intent.Action = "access"
	} else if strings.Contains(q, "block") {
		intent.Action = "block"
	}

	return intent
}

// decide resolves a verdict for the parsed intent, preferring the
// tenant's live compiled policy graph when a source is wired and
// falling back to a conservative heuristic otherwise. The returned
// mode records which path produced the verdict.
func (e *NLQueryEngine) decide(ctx context.Context, tenantID uuid.UUID, intent ParsedIntent) (verdict string, matchedRules []string, explanation, mode string) {
	if intent.UserRef == "" && intent.AppRef == "" && intent.DeviceRef == "" {
		return "unknown", nil, "No entity references could be extracted from the query.", ""
	}

	if e.graphs != nil {
		v, rules, expl, err := e.evaluateAgainstBundle(ctx, tenantID, intent)
		switch {
		case err == nil:
			return v, rules, expl, evalModeCompiledBundle
		case errors.Is(err, repository.ErrNotFound):
			// Source wired but the tenant has no live policy yet.
			hv, hr, he := e.heuristicEvaluate(intent)
			return hv, hr, he + " (no live policy graph; heuristic default applied)", evalModeNoPolicy
		default:
			// Unexpected evaluation failure: keep the endpoint
			// available via the heuristic, but flag the degraded mode.
			hv, hr, he := e.heuristicEvaluate(intent)
			return hv, hr, he, evalModeDefaultHeuristic
		}
	}

	hv, hr, he := e.heuristicEvaluate(intent)
	return hv, hr, he, evalModeDefaultHeuristic
}

// evaluateAgainstBundle runs the parsed intent through the tenant's
// live compiled policy graph via the policy evaluator. The LLM never
// reaches this path — only the structured intent does. The intent is
// synthesised into a representative telemetry envelope (best effort:
// device refs that are UUIDs map to the envelope DeviceID so device
// subject rules can match; an app ref maps to the HTTP host so SWG
// host rules can match) and the evaluator applies first-match-wins
// plus the graph's DefaultAction — exactly what a real edge/endpoint
// would. Returns repository.ErrNotFound when the tenant has no live
// graph.
func (e *NLQueryEngine) evaluateAgainstBundle(ctx context.Context, tenantID uuid.UUID, intent ParsedIntent) (verdict string, matchedRules []string, explanation string, err error) {
	g, err := e.graphs.GetCurrentGraph(ctx, tenantID)
	if err != nil {
		return "", nil, "", err
	}
	evaluator, err := e.factory.Build(ctx, g)
	if err != nil {
		return "", nil, "", fmt.Errorf("ai/nl_query: build evaluator: %w", err)
	}
	env := intentToEnvelope(tenantID, intent)
	v, err := evaluator.Evaluate(ctx, env)
	if err != nil {
		return "", nil, "", fmt.Errorf("ai/nl_query: evaluate: %w", err)
	}
	verdict = mapVerdict(v)
	matchedRules = []string{fmt.Sprintf("policy-graph:%s@v%d", g.ID, g.Version)}
	explanation = fmt.Sprintf("Verdict %q from tenant policy graph %s (v%d) for %s.",
		verdict, g.ID, g.Version, describeIntent(intent))
	return verdict, matchedRules, explanation, nil
}

// heuristicEvaluate is the conservative fallback used when no policy
// graph is available: allow unless the intent explicitly requests a
// block. It is intentionally simple and is never used when a
// compiled policy graph can be evaluated.
func (e *NLQueryEngine) heuristicEvaluate(intent ParsedIntent) (verdict string, matchedRules []string, explanation string) {
	if intent.UserRef == "" && intent.AppRef == "" && intent.DeviceRef == "" {
		return "unknown", nil, "No entity references could be extracted from the query."
	}
	entityDesc := describeIntent(intent)
	matchedRules = []string{"default-policy"}
	if intent.Action == "block" {
		return "deny", matchedRules, fmt.Sprintf("Heuristic default denies action for entities: %s", entityDesc)
	}
	return "allow", matchedRules, fmt.Sprintf("Heuristic default allows access for entities: %s", entityDesc)
}

// describeIntent renders the populated entity references as a stable
// human-readable string for explanations.
func describeIntent(intent ParsedIntent) string {
	var parts []string
	if intent.UserRef != "" {
		parts = append(parts, fmt.Sprintf("user=%s", intent.UserRef))
	}
	if intent.AppRef != "" {
		parts = append(parts, fmt.Sprintf("app=%s", intent.AppRef))
	}
	if intent.DeviceRef != "" {
		parts = append(parts, fmt.Sprintf("device=%s", intent.DeviceRef))
	}
	return strings.Join(parts, ", ")
}

// intentToEnvelope synthesises a representative HTTP access envelope
// from a parsed intent for policy evaluation. The mapping is best
// effort: an app ref becomes the HTTP host (so SWG host rules match)
// and a device ref that parses as a UUID becomes the envelope
// DeviceID (so device subject rules match). When no app ref is
// present the payload is left empty and the graph's DefaultAction
// governs the verdict.
func intentToEnvelope(tenantID uuid.UUID, intent ParsedIntent) schema.Envelope {
	env := schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      tenantID,
		Timestamp:     time.Now().UTC(),
		EventClass:    schema.EventClassHTTP,
		Platform:      schema.PlatformLinux,
	}
	if id, err := uuid.Parse(intent.DeviceRef); err == nil {
		env.DeviceID = id
	}
	if intent.AppRef != "" {
		if payload, err := schema.PackPayload(schema.HTTPEvent{
			Method:  "GET",
			Host:    intent.AppRef,
			URL:     intent.AppRef,
			Verdict: schema.VerdictAllow,
		}); err == nil {
			env.Payload = payload
		}
	}
	return env
}

// mapVerdict maps a policy evaluator verdict onto the NL-query
// response vocabulary. Unknown values degrade to "unknown".
func mapVerdict(v schema.Verdict) string {
	switch v {
	case schema.VerdictAllow:
		return "allow"
	case schema.VerdictDeny:
		return "deny"
	case schema.VerdictInspect:
		return "inspect"
	case schema.VerdictLog:
		return "log"
	case schema.VerdictAlert:
		return "alert"
	}
	return "unknown"
}

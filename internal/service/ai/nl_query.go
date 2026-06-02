package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// NLQueryEngine handles natural language policy queries. It uses
// the LLM to parse intent, then evaluates against the deterministic
// policy evaluator. The LLM never produces the verdict — only the
// structured query interpretation.
type NLQueryEngine struct {
	llm LLMProvider
}

// NewNLQueryEngine constructs a NLQueryEngine. llm may be nil
// (structured-query-only mode).
func NewNLQueryEngine(llm LLMProvider) *NLQueryEngine {
	return &NLQueryEngine{llm: llm}
}

// NLQueryRequest is the input for a natural language policy query.
type NLQueryRequest struct {
	Question string    `json:"question"`
	TenantID uuid.UUID `json:"tenant_id"`
}

// NLQueryResponse is the deterministic answer to a policy query.
type NLQueryResponse struct {
	Verdict      string   `json:"verdict"` // allow, deny, unknown
	MatchedRules []string `json:"matched_rules"`
	Explanation  string   `json:"explanation"`
	Confidence   float64  `json:"confidence"`
	AIGenerated  bool     `json:"ai_generated"`
	ModelID      string   `json:"model_id,omitempty"`
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

	verdict, matchedRules, explanation := e.evaluate(intent)

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

	return NLQueryResponse{
		Verdict:      verdict,
		MatchedRules: matchedRules,
		Explanation:  explanation,
		Confidence:   confidence,
		AIGenerated:  aiGenerated,
		ModelID:      modelID,
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

func (e *NLQueryEngine) parseStructured(question string) ParsedIntent {
	q := strings.ToLower(question)
	var intent ParsedIntent

	if strings.Contains(q, "user") {
		parts := strings.Fields(q)
		for i, p := range parts {
			if p == "user" && i+1 < len(parts) {
				intent.UserRef = parts[i+1]
				break
			}
		}
	}

	if strings.Contains(q, "app") || strings.Contains(q, "application") {
		parts := strings.Fields(q)
		for i, p := range parts {
			if (p == "app" || p == "application") && i+1 < len(parts) {
				intent.AppRef = parts[i+1]
				break
			}
		}
	}

	if strings.Contains(q, "device") {
		parts := strings.Fields(q)
		for i, p := range parts {
			if p == "device" && i+1 < len(parts) {
				intent.DeviceRef = parts[i+1]
				break
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

// evaluate performs deterministic policy evaluation based on parsed
// intent. In a full implementation this would delegate to the
// compiled policy bundle; here we implement the framework that
// returns a deterministic verdict.
func (e *NLQueryEngine) evaluate(intent ParsedIntent) (verdict string, matchedRules []string, explanation string) {
	if intent.UserRef == "" && intent.AppRef == "" && intent.DeviceRef == "" {
		return "unknown", nil, "No entity references could be extracted from the query."
	}

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

	entityDesc := strings.Join(parts, ", ")
	matchedRules = []string{"default-policy"}

	// Default policy evaluation: allow unless explicitly blocked.
	if intent.Action == "block" {
		return "deny", matchedRules, fmt.Sprintf("Policy denies action for entities: %s", entityDesc)
	}
	return "allow", matchedRules, fmt.Sprintf("Default policy allows access for entities: %s", entityDesc)
}

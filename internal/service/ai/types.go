package ai

import (
	"encoding/json"
	"time"
)

// PolicySuggestion is an AI-proposed policy graph delta that MUST
// be verified through the deterministic policy compiler before it
// can be queued. The Graph field is the raw JSON graph the caller
// would feed to policy.Service.PutGraph.
type PolicySuggestion struct {
	Graph       json.RawMessage `json:"graph"`
	Rationale   string          `json:"rationale"`
	Confidence  float64         `json:"confidence"`
	AIGenerated bool            `json:"ai_generated"`
	ModelID     string          `json:"model_id,omitempty"`
}

// Summary is the output of an incident/telemetry summarization.
// Always carries the ai_generated flag so consumers know whether
// the text was polished by an LLM or produced by the deterministic
// template engine alone.
type Summary struct {
	Text               string   `json:"text"`
	KeyFindings        []string `json:"key_findings"`
	RecommendedActions []string `json:"recommended_actions"`
	EvidenceRefs       []string `json:"evidence_refs"`
	AIGenerated        bool     `json:"ai_generated"`
	ModelID            string   `json:"model_id,omitempty"`
	LatencyMS          int64    `json:"latency_ms"`
}

// TroubleshootResult carries suggestions (never actions) for
// operator troubleshooting queries. The AI service is not
// authorised to take actions — only to propose them.
type TroubleshootResult struct {
	Suggestions    []string `json:"suggestions"`
	ReferencedDocs []string `json:"referenced_docs"`
	Confidence     float64  `json:"confidence"`
	AIGenerated    bool     `json:"ai_generated"`
	ModelID        string   `json:"model_id,omitempty"`
}

// TimeRange bounds evidence queries against the ClickHouse store.
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// VerifiedSuggestion is a PolicySuggestion that has passed
// deterministic compilation. It is ready to be queued as a
// draft graph change.
type VerifiedSuggestion struct {
	Suggestion PolicySuggestion `json:"suggestion"`
	DryRun     DryRunMeta       `json:"dry_run"`
}

// DryRunMeta records the result of the deterministic compile
// pass that verified the suggestion.
type DryRunMeta struct {
	Compiled  bool   `json:"compiled"`
	GraphID   string `json:"graph_id,omitempty"`
	CompileMS int64  `json:"compile_ms"`
}

package ai

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SuggestionCategory classifies what kind of policy tightening a
// suggestion addresses. The category determines the UI treatment
// and the default risk assessment.
type SuggestionCategory string

const (
	SuggestionCategoryUnused           SuggestionCategory = "unused"
	SuggestionCategoryShadowed         SuggestionCategory = "shadowed"
	SuggestionCategoryOverlyPermissive SuggestionCategory = "overly_permissive"
	SuggestionCategoryDenyLog          SuggestionCategory = "deny_log"
)

// Valid reports whether c is one of the recognised suggestion
// categories. Used to reject free-form categories returned by the
// LLM before they are persisted.
func (c SuggestionCategory) Valid() bool {
	switch c {
	case SuggestionCategoryUnused,
		SuggestionCategoryShadowed,
		SuggestionCategoryOverlyPermissive,
		SuggestionCategoryDenyLog:
		return true
	default:
		return false
	}
}

// SuggestionStatus tracks a suggestion through the review workflow.
type SuggestionStatus string

const (
	SuggestionStatusPending    SuggestionStatus = "pending"
	SuggestionStatusApproved   SuggestionStatus = "approved"
	SuggestionStatusRejected   SuggestionStatus = "rejected"
	SuggestionStatusApplied    SuggestionStatus = "applied"
	SuggestionStatusRolledBack SuggestionStatus = "rolled_back"
)

// Valid reports whether s is one of the recognised suggestion
// statuses. Used to reject unknown status filters from API callers.
func (s SuggestionStatus) Valid() bool {
	switch s {
	case SuggestionStatusPending,
		SuggestionStatusApproved,
		SuggestionStatusRejected,
		SuggestionStatusApplied,
		SuggestionStatusRolledBack:
		return true
	default:
		return false
	}
}

// RiskLevel categorises the risk of applying a suggestion.
type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

// PolicyChangeSuggestion is an AI-generated recommendation to
// tighten a policy rule. Every suggestion MUST compile through the
// deterministic policy compiler before being queued.
type PolicyChangeSuggestion struct {
	ID          uuid.UUID          `json:"id"`
	TenantID    uuid.UUID          `json:"tenant_id"`
	RuleID      string             `json:"rule_id"`
	Category    SuggestionCategory `json:"category"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Reasoning   string             `json:"reasoning"`
	Confidence  float64            `json:"confidence"`
	Risk        RiskAssessment     `json:"risk"`
	Impact      ExpectedImpact     `json:"impact"`
	Change      SuggestedChange    `json:"change"`
	Status      SuggestionStatus   `json:"status"`
	ReviewerID  *uuid.UUID         `json:"reviewer_id,omitempty"`
	Feedback    string             `json:"feedback,omitempty"`
	CreatedAt   time.Time          `json:"created_at"`
	ReviewedAt  *time.Time         `json:"reviewed_at,omitempty"`
}

// RiskAssessment captures the risk profile of applying a suggestion.
type RiskAssessment struct {
	Level         RiskLevel `json:"level"`
	Justification string    `json:"justification"`
}

// ExpectedImpact describes what changes when the suggestion is applied.
type ExpectedImpact struct {
	AffectedRuleCount  int    `json:"affected_rule_count"`
	TrafficDescription string `json:"traffic_description"`
}

// SuggestedChange holds the before/after delta for a rule change.
type SuggestedChange struct {
	Action        string          `json:"action"`
	BeforeRule    json.RawMessage `json:"before_rule,omitempty"`
	AfterRule     json.RawMessage `json:"after_rule,omitempty"`
	Justification string          `json:"justification"`
}

// TighteningRecommendation is a single per-rule recommendation from
// the tightening analysis.
type TighteningRecommendation struct {
	RuleID     string             `json:"rule_id"`
	Category   SuggestionCategory `json:"category"`
	Change     SuggestedChange    `json:"suggested_change"`
	Confidence float64            `json:"confidence"`
	Reasoning  string             `json:"reasoning"`
}

// TighteningReport is the output of a full tightening analysis run.
type TighteningReport struct {
	TenantID        uuid.UUID                  `json:"tenant_id"`
	Recommendations []TighteningRecommendation `json:"recommendations"`
	AnalysisWindow  int                        `json:"analysis_window_days"`
	RulesAnalyzed   int                        `json:"rules_analyzed"`
	GeneratedAt     time.Time                  `json:"generated_at"`
}

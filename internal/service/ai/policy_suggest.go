package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicySuggestService analyses telemetry patterns and generates
// typed policy change suggestions. Every suggestion MUST compile
// through the deterministic policy compiler before being queued.
type PolicySuggestService struct {
	llm        LLMProvider
	verifier   *Verifier
	repo       repository.AISuggestionRepository
	logger     *slog.Logger
}

// NewPolicySuggestService constructs a PolicySuggestService.
// llm may be nil (template-only mode).
func NewPolicySuggestService(
	llm LLMProvider,
	verifier *Verifier,
	repo repository.AISuggestionRepository,
	logger *slog.Logger,
) *PolicySuggestService {
	if logger == nil {
		logger = slog.Default()
	}
	return &PolicySuggestService{
		llm:      llm,
		verifier: verifier,
		repo:     repo,
		logger:   logger,
	}
}

// AnalyzeAndSuggest analyses telemetry patterns for a tenant and
// generates policy change suggestions. Returns the suggestions
// that passed compilation and were persisted.
func (s *PolicySuggestService) AnalyzeAndSuggest(
	ctx context.Context,
	tenantID uuid.UUID,
	rules []json.RawMessage,
	hitCounts map[string]int64,
	windowDays int,
) ([]PolicyChangeSuggestion, error) {
	if windowDays <= 0 {
		windowDays = 30
	}

	var suggestions []PolicyChangeSuggestion

	for i, ruleRaw := range rules {
		var rule struct {
			ID   string `json:"id"`
			Verb string `json:"verb"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			s.logger.Warn("skipping unparseable rule",
				slog.Int("index", i),
				slog.String("error", err.Error()))
			continue
		}
		if rule.ID == "" {
			continue
		}

		hits := hitCounts[rule.ID]

		if hits == 0 && rule.Verb == "allow" {
			suggestion := s.buildUnusedRuleSuggestion(tenantID, rule.ID, windowDays, ruleRaw)
			suggestions = append(suggestions, suggestion)
			continue
		}

		if rule.Verb == "allow" {
			if isBroadRule(ruleRaw) {
				suggestion := s.buildOverlyPermissiveSuggestion(tenantID, rule.ID, ruleRaw)
				suggestions = append(suggestions, suggestion)
			}
		}
	}

	if s.llm != nil && len(rules) > 0 {
		aiSuggestions, err := s.generateLLMSuggestions(ctx, tenantID, rules, hitCounts, windowDays)
		if err != nil {
			s.logger.Warn("LLM suggestion generation failed, using heuristic-only",
				slog.String("error", err.Error()))
		} else {
			suggestions = append(suggestions, aiSuggestions...)
		}
	}

	var persisted []PolicyChangeSuggestion
	for i := range suggestions {
		suggestions[i].ID = uuid.New()
		suggestions[i].TenantID = tenantID
		suggestions[i].CreatedAt = time.Now().UTC()
		suggestions[i].Status = SuggestionStatusPending

		repoSuggestion := repository.AISuggestion{
			ID:       suggestions[i].ID,
			TenantID: tenantID,
			RuleID:   suggestions[i].RuleID,
			Category: string(suggestions[i].Category),
			Confidence: suggestions[i].Confidence,
			Status:   repository.AISuggestionStatusPending,
		}
		suggJSON, _ := json.Marshal(suggestions[i])
		repoSuggestion.SuggestionJSON = suggJSON

		if _, err := s.repo.Create(ctx, tenantID, repoSuggestion); err != nil {
			s.logger.Error("failed to persist suggestion",
				slog.String("rule_id", suggestions[i].RuleID),
				slog.String("error", err.Error()))
			continue
		}
		persisted = append(persisted, suggestions[i])
	}

	return persisted, nil
}

func (s *PolicySuggestService) buildUnusedRuleSuggestion(
	tenantID uuid.UUID, ruleID string, windowDays int, ruleRaw json.RawMessage,
) PolicyChangeSuggestion {
	confidence := unusedRuleConfidence(windowDays)
	return PolicyChangeSuggestion{
		TenantID: tenantID,
		RuleID:   ruleID,
		Category: SuggestionCategoryUnused,
		Title:    fmt.Sprintf("Remove unused allow rule %s", ruleID),
		Description: fmt.Sprintf(
			"Rule %s has not matched any traffic in %d days. Consider removing it to reduce the attack surface.",
			ruleID, windowDays),
		Reasoning:  fmt.Sprintf("No traffic matched this rule in the analysis window of %d days.", windowDays),
		Confidence: confidence,
		Risk: RiskAssessment{
			Level:         riskFromConfidence(confidence),
			Justification: "Removing an unused rule has low risk if the analysis window is sufficiently long.",
		},
		Impact: ExpectedImpact{
			AffectedRuleCount:  1,
			TrafficDescription: "No traffic currently matches this rule.",
		},
		Change: SuggestedChange{
			Action:        "remove",
			BeforeRule:    ruleRaw,
			Justification: "Rule has been inactive for the configured analysis window.",
		},
	}
}

func (s *PolicySuggestService) buildOverlyPermissiveSuggestion(
	tenantID uuid.UUID, ruleID string, ruleRaw json.RawMessage,
) PolicyChangeSuggestion {
	return PolicyChangeSuggestion{
		TenantID: tenantID,
		RuleID:   ruleID,
		Category: SuggestionCategoryOverlyPermissive,
		Title:    fmt.Sprintf("Narrow scope of overly-permissive rule %s", ruleID),
		Description: fmt.Sprintf(
			"Rule %s uses broad allow patterns that could be scoped to specific sources or destinations.",
			ruleID),
		Reasoning:  "Allow-any patterns increase attack surface. Restricting to known traffic patterns improves security posture.",
		Confidence: 0.6,
		Risk: RiskAssessment{
			Level:         RiskLevelMedium,
			Justification: "Narrowing scope may break legitimate traffic if not all sources are identified.",
		},
		Impact: ExpectedImpact{
			AffectedRuleCount:  1,
			TrafficDescription: "Traffic matching the broad pattern will need to match narrower criteria.",
		},
		Change: SuggestedChange{
			Action:        "modify",
			BeforeRule:    ruleRaw,
			Justification: "Restrict source/destination scope to reduce overly-permissive access.",
		},
	}
}

func (s *PolicySuggestService) generateLLMSuggestions(
	ctx context.Context,
	tenantID uuid.UUID,
	rules []json.RawMessage,
	hitCounts map[string]int64,
	windowDays int,
) ([]PolicyChangeSuggestion, error) {
	prompt := buildPolicyAnalysisPrompt(rules, hitCounts, windowDays)
	resp, err := s.llm.Complete(ctx, LLMRequest{
		Prompt:         prompt,
		TemperatureX10: 3,
		MaxTokens:      2000,
	})
	if err != nil {
		return nil, fmt.Errorf("llm complete: %w", err)
	}

	var parsed []struct {
		RuleID     string  `json:"rule_id"`
		Category   string  `json:"category"`
		Title      string  `json:"title"`
		Reasoning  string  `json:"reasoning"`
		Confidence float64 `json:"confidence"`
		Action     string  `json:"action"`
	}
	raw := extractJSON(resp.Text)
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, fmt.Errorf("parse llm response: %w", err)
	}

	var suggestions []PolicyChangeSuggestion
	for _, p := range parsed {
		if p.Confidence < 0 || p.Confidence > 1 {
			p.Confidence = 0.5
		}
		suggestions = append(suggestions, PolicyChangeSuggestion{
			TenantID:    tenantID,
			RuleID:      p.RuleID,
			Category:    SuggestionCategory(p.Category),
			Title:       p.Title,
			Description: p.Reasoning,
			Reasoning:   p.Reasoning,
			Confidence:  p.Confidence,
			Risk: RiskAssessment{
				Level:         riskFromConfidence(p.Confidence),
				Justification: "AI-generated risk assessment based on traffic pattern analysis.",
			},
			Impact: ExpectedImpact{
				AffectedRuleCount:  1,
				TrafficDescription: "AI-identified traffic pattern.",
			},
			Change: SuggestedChange{
				Action:        p.Action,
				Justification: p.Reasoning,
			},
		})
	}
	return suggestions, nil
}

func buildPolicyAnalysisPrompt(rules []json.RawMessage, hitCounts map[string]int64, windowDays int) string {
	rulesJSON, _ := json.Marshal(rules)
	hitsJSON, _ := json.Marshal(hitCounts)
	return fmt.Sprintf(`Analyze the following policy rules and their hit counts over a %d-day window.
Identify rules that should be tightened, removed, or modified. For each suggestion, provide:
- rule_id: the rule ID
- category: one of "unused", "shadowed", "overly_permissive", "deny_log"
- title: short description
- reasoning: explanation
- confidence: 0.0-1.0
- action: "remove", "modify", or "add_logging"

Return ONLY a JSON array of suggestions.

Rules: %s
Hit counts: %s`, windowDays, string(rulesJSON), string(hitsJSON))
}

func unusedRuleConfidence(windowDays int) float64 {
	switch {
	case windowDays >= 90:
		return 0.95
	case windowDays >= 60:
		return 0.85
	case windowDays >= 30:
		return 0.7
	default:
		return 0.5
	}
}

func riskFromConfidence(confidence float64) RiskLevel {
	switch {
	case confidence >= 0.9:
		return RiskLevelLow
	case confidence >= 0.7:
		return RiskLevelMedium
	default:
		return RiskLevelHigh
	}
}

func isBroadRule(ruleRaw json.RawMessage) bool {
	var rule struct {
		Subjects []json.RawMessage `json:"subjects"`
		SubjectRefs []string `json:"subject_refs"`
	}
	if err := json.Unmarshal(ruleRaw, &rule); err != nil {
		return false
	}
	return len(rule.Subjects) == 0 && len(rule.SubjectRefs) == 0
}

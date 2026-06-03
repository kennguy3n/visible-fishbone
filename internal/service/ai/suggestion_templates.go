package ai

import (
	"encoding/json"
	"fmt"
)

// SuggestionTemplate defines a reusable pattern for generating
// policy change suggestions. Each template includes explanation
// text, risk assessment, and required operator context.
type SuggestionTemplate struct {
	Name              string             `json:"name"`
	Category          SuggestionCategory `json:"category"`
	TitleTemplate     string             `json:"title_template"`
	DescTemplate      string             `json:"description_template"`
	DefaultRisk       RiskLevel          `json:"default_risk"`
	RiskJustification string             `json:"risk_justification"`
	RequiredContext   []string           `json:"required_context"`
	Action            string             `json:"action"`
}

// BuiltinTemplates returns the set of common suggestion patterns.
func BuiltinTemplates() []SuggestionTemplate {
	return []SuggestionTemplate{
		removeUnusedRuleTemplate(),
		narrowSourceScopeTemplate(),
		addTimeRestrictionTemplate(),
		enableLoggingTemplate(),
	}
}

func removeUnusedRuleTemplate() SuggestionTemplate {
	return SuggestionTemplate{
		Name:          "remove_unused_rule",
		Category:      SuggestionCategoryUnused,
		TitleTemplate: "Remove unused rule %s",
		DescTemplate: "Rule %s has not matched any traffic in %d days. " +
			"Removing it reduces the attack surface without affecting active flows.",
		DefaultRisk:       RiskLevelLow,
		RiskJustification: "Removing an unused rule has low risk if the analysis window covers representative traffic patterns. Confidence increases with longer inactivity windows.",
		RequiredContext: []string{
			"Analysis window duration (days)",
			"Last known hit timestamp (if available)",
			"Rule creation date",
		},
		Action: "remove",
	}
}

func narrowSourceScopeTemplate() SuggestionTemplate {
	return SuggestionTemplate{
		Name:          "narrow_source_scope",
		Category:      SuggestionCategoryOverlyPermissive,
		TitleTemplate: "Narrow source scope of rule %s",
		DescTemplate: "Rule %s allows traffic from all sources (analyzed over %d days). " +
			"Restricting the source CIDR or identity to observed patterns reduces exposure.",
		DefaultRisk:       RiskLevelMedium,
		RiskJustification: "Narrowing scope may inadvertently block legitimate traffic from unobserved sources. Requires validation against recent traffic logs.",
		RequiredContext: []string{
			"Observed source CIDRs from traffic logs",
			"Known legitimate source identities",
			"Business justification for current broad scope",
		},
		Action: "modify",
	}
}

func addTimeRestrictionTemplate() SuggestionTemplate {
	return SuggestionTemplate{
		Name:          "add_time_restriction",
		Category:      SuggestionCategoryOverlyPermissive,
		TitleTemplate: "Add time-based restriction to rule %s",
		DescTemplate: "Rule %s allows traffic at all hours (analyzed over %d days). " +
			"Adding business-hours-only restriction reduces the attack window.",
		DefaultRisk:       RiskLevelMedium,
		RiskJustification: "Time restrictions may block legitimate after-hours operations (maintenance, deployments, on-call). Requires verification of operational patterns.",
		RequiredContext: []string{
			"Business hours for the tenant's timezone",
			"Known after-hours operational windows",
			"On-call and maintenance schedules",
		},
		Action: "modify",
	}
}

func enableLoggingTemplate() SuggestionTemplate {
	return SuggestionTemplate{
		Name:          "enable_logging",
		Category:      SuggestionCategoryDenyLog,
		TitleTemplate: "Enable logging on allow rule %s",
		DescTemplate: "Rule %s allows traffic without logging (analyzed over %d days). " +
			"Adding log action provides visibility without changing the verdict.",
		DefaultRisk:       RiskLevelLow,
		RiskJustification: "Enabling logging on an allow rule does not change the traffic verdict and poses minimal risk. The only concern is additional log volume.",
		RequiredContext: []string{
			"Current log volume and storage capacity",
			"Estimated traffic volume for this rule",
		},
		Action: "add_logging",
	}
}

// ApplyTemplate generates a PolicyChangeSuggestion from a template
// and context values.
func ApplyTemplate(
	tmpl SuggestionTemplate,
	ruleID string,
	windowDays int,
	ruleRaw json.RawMessage,
) PolicyChangeSuggestion {
	confidence := templateConfidence(tmpl, windowDays)
	return PolicyChangeSuggestion{
		RuleID:      ruleID,
		Category:    tmpl.Category,
		Title:       fmt.Sprintf(tmpl.TitleTemplate, ruleID),
		Description: fmt.Sprintf(tmpl.DescTemplate, ruleID, windowDays),
		Reasoning:   tmpl.RiskJustification,
		Confidence:  confidence,
		Risk: RiskAssessment{
			Level:         tmpl.DefaultRisk,
			Justification: tmpl.RiskJustification,
		},
		Impact: ExpectedImpact{
			AffectedRuleCount:  1,
			TrafficDescription: "Traffic matching this rule pattern.",
		},
		Change: SuggestedChange{
			Action:        tmpl.Action,
			BeforeRule:    ruleRaw,
			Justification: tmpl.RiskJustification,
		},
	}
}

func templateConfidence(tmpl SuggestionTemplate, windowDays int) float64 {
	switch tmpl.Name {
	case "remove_unused_rule":
		return unusedRuleConfidence(windowDays)
	case "enable_logging":
		return 0.95
	default:
		return 0.6
	}
}

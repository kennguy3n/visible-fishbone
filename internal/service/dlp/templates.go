package dlp

import (
	"context"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// builtinTemplates is the catalog of pre-baked DLP policy templates.
var builtinTemplates = []PolicyTemplate{
	{
		ID:          "pci-dss",
		Name:        "PCI-DSS",
		Description: "Detects credit card numbers (Luhn-validated) and blocks transmission.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "credit_card", SensitivityLevel: "high"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "hipaa",
		Name:        "HIPAA — PHI Detection",
		Description: "Detects protected health information: MRN, ICD-10 diagnosis codes, patient names with medical context.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "mrn", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "icd10", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeKeyword, Pattern: "diagnosis", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeKeyword, Pattern: "patient", SensitivityLevel: "medium"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "pii-general",
		Name:        "PII — General",
		Description: "Detects SSN, passport, driver's license, and bank account numbers.",
		Category:    "pii",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "ssn_us", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "passport_us", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "drivers_license", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "gdpr",
		Name:        "GDPR — EU PII",
		Description: "EU-specific PII detection: national IDs, IBAN, phone numbers.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "ni_uk", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "iban", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "financial",
		Name:        "Financial Data",
		Description: "Detects bank account numbers, routing numbers, SWIFT/BIC codes.",
		Category:    "financial",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "routing_number", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "swift", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "iban", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "credit_card", SensitivityLevel: "high"},
		},
		Action: repository.DLPActionBlock,
	},
}

// ListTemplates returns the catalog of pre-baked DLP policy templates.
func (s *Service) ListTemplates() []PolicyTemplate {
	out := make([]PolicyTemplate, len(builtinTemplates))
	copy(out, builtinTemplates)
	return out
}

// ApplyTemplate creates a DLP policy from a template. The resulting
// policy is enabled by default.
func (s *Service) ApplyTemplate(ctx context.Context, tenantID uuid.UUID, templateID string) (repository.DLPPolicy, error) {
	var tmpl *PolicyTemplate
	for i := range builtinTemplates {
		if builtinTemplates[i].ID == templateID {
			tmpl = &builtinTemplates[i]
			break
		}
	}
	if tmpl == nil {
		return repository.DLPPolicy{}, repository.ErrNotFound
	}
	rules := make([]repository.DLPRule, len(tmpl.Rules))
	copy(rules, tmpl.Rules)
	return s.policies.Create(ctx, tenantID, repository.DLPPolicy{
		Name:        tmpl.Name,
		Description: tmpl.Description,
		Rules:       rules,
		Action:      tmpl.Action,
		Enabled:     true,
	})
}

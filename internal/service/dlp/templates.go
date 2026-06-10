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
	{
		ID:          "pipl-china",
		Name:        "PIPL — China PII",
		Description: "China PIPL: resident identity card (check-digit validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "china_resident_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "appi-japan",
		Name:        "APPI — Japan PII",
		Description: "Japan APPI: My Number (check-digit validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "japan_my_number", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "pipa-korea",
		Name:        "PIPA — Korea PII",
		Description: "Korea PIPA: Resident Registration Number (check-digit validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "korea_rrn", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "pdpa-singapore",
		Name:        "PDPA — Singapore PII",
		Description: "Singapore PDPA: NRIC/FIN (check-letter validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "singapore_nric", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "pdpa-thailand",
		Name:        "PDPA — Thailand PII",
		Description: "Thailand PDPA: national ID (check-digit validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "thailand_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "india-pii",
		Name:        "India PII",
		Description: "India: Aadhaar (Verhoeff validated), PAN, phone, email.",
		Category:    "pii",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "india_aadhaar", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "india_pan", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "malaysia-pii",
		Name:        "Malaysia PII",
		Description: "Malaysia: MyKad (date/state validated), phone, email.",
		Category:    "pii",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "malaysia_mykad", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "pdpl-saudi",
		Name:        "PDPL — Saudi PII",
		Description: "Saudi PDPL: national/Iqama ID and Emirates ID (Luhn validated), phone, email, IBAN.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "saudi_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "uae_emirates_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "iban", SensitivityLevel: "high"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "gcc-pii",
		Name:        "GCC PII (UAE/Qatar/Kuwait/Bahrain)",
		Description: "GCC: Emirates ID, Qatar QID, Kuwait Civil ID, Bahrain CPR, phone, email, IBAN.",
		Category:    "pii",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "uae_emirates_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "qatar_qid", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "kuwait_civil_id", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "bahrain_cpr", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "iban", SensitivityLevel: "high"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "australia-privacy-act",
		Name:        "Australia Privacy Act",
		Description: "Australia Privacy Act / APPs: Tax File Number (weighted check) and Medicare number (check-digit validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "tfn_au", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "australia_medicare", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "uk-dpa-2018",
		Name:        "UK DPA 2018 / UK GDPR",
		Description: "UK Data Protection Act 2018: National Insurance number and NHS number (check-digit validated), IBAN, phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "ni_uk", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "uk_nhs", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "iban", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
	{
		ID:          "japan-appi",
		Name:        "Japan APPI — Individual Number",
		Description: "Japan Act on the Protection of Personal Information: My Number / Individual Number (check-digit validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "japan_my_number", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "brazil-lgpd",
		Name:        "Brazil LGPD",
		Description: "Brazil Lei Geral de Proteção de Dados: CPF and CNPJ (modulus-11 validated), phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "brazil_cpf", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "brazil_cnpj", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "gcc-pdpl",
		Name:        "GCC PDPL (Gulf)",
		Description: "Gulf Cooperation Council data-protection laws: Emirates ID, Saudi/Iqama ID, Qatar QID, Kuwait Civil ID, Bahrain CPR, IBAN, phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "uae_emirates_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "saudi_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "qatar_qid", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "kuwait_civil_id", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "bahrain_cpr", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "iban", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionBlock,
	},
	{
		ID:          "sea-pdpa",
		Name:        "Southeast Asia PDPA",
		Description: "Southeast Asian personal-data laws: Singapore NRIC/FIN, Thailand national ID, Philippines UMID/CRN, Indonesia NIK — all check/format validated — plus phone, email.",
		Category:    "compliance",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: "singapore_nric", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "thailand_id", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "philippines_umid", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "indonesia_nik", SensitivityLevel: "high"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "phone", SensitivityLevel: "medium"},
			{Type: repository.DLPRuleTypeRegex, Pattern: "email", SensitivityLevel: "low"},
		},
		Action: repository.DLPActionRedact,
	},
}

// ListTemplates returns the catalog of pre-baked DLP policy templates.
func (s *Service) ListTemplates() []PolicyTemplate {
	out := make([]PolicyTemplate, len(builtinTemplates))
	for i, t := range builtinTemplates {
		t.Rules = append([]repository.DLPRule(nil), t.Rules...)
		out[i] = t
	}
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

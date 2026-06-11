package policytemplates

import (
	"fmt"
	"sort"
	"strings"
)

// Industry is the SME's line of business. It is one half of a
// Selection and selects the acceptable-use category posture, the
// firewall strictness tier, and any industry-specific DLP detectors
// (e.g. PHI for healthcare).
type Industry string

const (
	IndustryHealthcare   Industry = "healthcare"
	IndustryFinance      Industry = "finance"
	IndustryRetail       Industry = "retail"
	IndustryProfessional Industry = "professional-services"
	IndustryEducation    Industry = "education"
	IndustryTechnology   Industry = "technology"
	IndustryLegal        Industry = "legal"
	// IndustryGeneral is the safe fallback for an SME whose sector is
	// not (yet) modelled. It still gets the universal security baseline
	// plus a conservative acceptable-use posture.
	IndustryGeneral Industry = "general"
)

// Country is an ISO 3166-1 alpha-2 country code. It is the other half
// of a Selection and selects the compliance regime, which in turn
// drives which PII detectors the DLP plane runs.
type Country string

// ComplianceRegime is the data-protection regime a country falls
// under. Multiple countries can share a regime (every EU member maps
// to eu-gdpr), so DLP detector sets are authored once per regime.
type ComplianceRegime string

const (
	RegimeEUGDPR     ComplianceRegime = "eu-gdpr"
	RegimeUKDPA      ComplianceRegime = "uk-dpa"
	RegimeAUPrivacy  ComplianceRegime = "au-privacy"
	RegimeCAPIPEDA   ComplianceRegime = "ca-pipeda"
	RegimeUSBaseline ComplianceRegime = "us-baseline"
)

// TemplateKind partitions the catalog into the three composable layers
// a Selection pulls together.
type TemplateKind string

const (
	// KindBaseline is the single universal template applied to every
	// tenant: block the security-critical categories everywhere.
	KindBaseline TemplateKind = "baseline"
	// KindIndustry is the per-industry acceptable-use + firewall +
	// industry-DLP profile.
	KindIndustry TemplateKind = "industry"
	// KindCompliance is the per-regime DLP detector profile.
	KindCompliance TemplateKind = "compliance"
)

// CategoryRule is one safe-browsing decision: what to do with a URL
// category. Authored in profiles; rendered to DNS + SWG graph rules.
type CategoryRule struct {
	Category URLCategory    `json:"category"`
	Action   CategoryAction `json:"action"`
}

// DetectorRule is one DLP decision: which PII detector to run and at
// what sensitivity (which in turn fixes the enforcement verb).
type DetectorRule struct {
	Detector    PIIDetector `json:"detector"`
	Sensitivity Sensitivity `json:"sensitivity"`
}

// Spec is the structured, JSON-serialisable intent a single template
// contributes. It is deliberately declarative (no graph rules): the
// renderer (render.go) is the only place that turns a Spec into
// policy.Graph rules, so the mapping lives in exactly one spot.
type Spec struct {
	Categories []CategoryRule `json:"categories,omitempty"`
	Detectors  []DetectorRule `json:"detectors,omitempty"`
	// Firewall is set only on industry templates; the baseline and
	// compliance templates leave it empty.
	Firewall FirewallPosture `json:"firewall_posture,omitempty"`
}

// Template is one catalog entry. Industry templates set Industry;
// compliance templates set Regime; the baseline sets neither.
type Template struct {
	ID          string           `json:"id"`
	Kind        TemplateKind     `json:"kind"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Industry    Industry         `json:"industry,omitempty"`
	Regime      ComplianceRegime `json:"regime,omitempty"`
	Spec        Spec             `json:"spec"`
}

// baselineTemplateID is the stable id of the one universal template.
const baselineTemplateID = "baseline/global"

func industryTemplateID(i Industry) string           { return "industry/" + string(i) }
func complianceTemplateID(r ComplianceRegime) string { return "compliance/" + string(r) }

// countryRegimes maps each supported country to its compliance regime.
// Adding a country is a one-line change here; the catalog and the
// renderer pick it up automatically.
var countryRegimes = map[Country]ComplianceRegime{
	// United Kingdom — UK GDPR / DPA 2018.
	"GB": RegimeUKDPA,
	// Australia — Privacy Act / APPs.
	"AU": RegimeAUPrivacy,
	// Canada — PIPEDA.
	"CA": RegimeCAPIPEDA,
	// United States — no omnibus federal law; baseline PII/PCI set.
	"US": RegimeUSBaseline,
	// European Union / EEA member states — GDPR.
	"AT": RegimeEUGDPR, "BE": RegimeEUGDPR, "BG": RegimeEUGDPR, "HR": RegimeEUGDPR,
	"CY": RegimeEUGDPR, "CZ": RegimeEUGDPR, "DK": RegimeEUGDPR, "EE": RegimeEUGDPR,
	"FI": RegimeEUGDPR, "FR": RegimeEUGDPR, "DE": RegimeEUGDPR, "GR": RegimeEUGDPR,
	"HU": RegimeEUGDPR, "IE": RegimeEUGDPR, "IT": RegimeEUGDPR, "LV": RegimeEUGDPR,
	"LT": RegimeEUGDPR, "LU": RegimeEUGDPR, "MT": RegimeEUGDPR, "NL": RegimeEUGDPR,
	"PL": RegimeEUGDPR, "PT": RegimeEUGDPR, "RO": RegimeEUGDPR, "SK": RegimeEUGDPR,
	"SI": RegimeEUGDPR, "ES": RegimeEUGDPR, "SE": RegimeEUGDPR,
}

// RegimeForCountry returns the compliance regime for a country code
// (case-insensitive). ok is false for an unmodelled country, letting
// the caller fall back to a sensible default or reject.
func RegimeForCountry(c Country) (ComplianceRegime, bool) {
	r, ok := countryRegimes[Country(strings.ToUpper(string(c)))]
	return r, ok
}

// --- Profiles: the authored source data the catalog is built from ---

// baselineProfile is the universal security floor. These categories
// are blocked for every tenant in every industry and country.
var baselineProfile = Spec{
	Categories: []CategoryRule{
		{CategorySecurityThreat, CategoryBlock},
		{CategorySecurityHacking, CategoryBlock},
		{CategoryAnonymizer, CategoryBlock},
	},
}

// industryProfiles holds each industry's acceptable-use categories,
// firewall posture, and industry-specific DLP detectors.
var industryProfiles = map[Industry]Spec{
	IndustryHealthcare: {
		Firewall: PostureStrict,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryBlock},
			{CategoryViolence, CategoryBlock},
			{CategoryDrugs, CategoryBlock},
			{CategorySocialMedia, CategoryMonitor},
		},
		// PHI: medical record numbers and ICD-10 diagnosis codes.
		Detectors: []DetectorRule{
			{"mrn", SensitivityHigh},
			{"icd10", SensitivityHigh},
		},
	},
	IndustryFinance: {
		Firewall: PostureStrict,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryBlock},
			{CategorySocialMedia, CategoryMonitor},
			{CategoryWebmail, CategoryMonitor},
		},
		// Cardholder + payment-rail identifiers (PCI-DSS adjacent).
		Detectors: []DetectorRule{
			{"credit_card", SensitivityHigh},
			{"iban", SensitivityHigh},
			{"swift", SensitivityHigh},
			{"routing_number", SensitivityHigh},
		},
	},
	IndustryRetail: {
		Firewall: PostureStandard,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryMonitor},
			{CategorySocialMedia, CategoryMonitor},
		},
		Detectors: []DetectorRule{
			{"credit_card", SensitivityHigh},
		},
	},
	IndustryProfessional: {
		Firewall: PostureStandard,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryBlock},
			{CategorySocialMedia, CategoryMonitor},
		},
	},
	IndustryEducation: {
		Firewall: PostureStandard,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryViolence, CategoryBlock},
			{CategoryDrugs, CategoryBlock},
			{CategoryGambling, CategoryBlock},
			{CategorySocialMedia, CategoryMonitor},
		},
	},
	IndustryTechnology: {
		Firewall: PostureStandard,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryMonitor},
		},
	},
	IndustryLegal: {
		Firewall: PostureStrict,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryBlock},
			{CategorySocialMedia, CategoryMonitor},
		},
	},
	IndustryGeneral: {
		Firewall: PostureStandard,
		Categories: []CategoryRule{
			{CategoryAdultContent, CategoryBlock},
			{CategoryGambling, CategoryBlock},
		},
	},
}

// complianceProfiles holds the DLP detector set that matters in each
// regime. Detectors are the builtin pattern names (see vocabulary.go).
var complianceProfiles = map[ComplianceRegime]Spec{
	RegimeEUGDPR: {
		Detectors: []DetectorRule{
			{"iban", SensitivityHigh},
			{"eu_vat", SensitivityMedium},
			{"phone", SensitivityMedium},
			{"email", SensitivityLow},
		},
	},
	RegimeUKDPA: {
		Detectors: []DetectorRule{
			{"ni_uk", SensitivityHigh},
			{"uk_nhs", SensitivityHigh},
			{"iban", SensitivityHigh},
			{"phone", SensitivityMedium},
			{"email", SensitivityLow},
		},
	},
	RegimeAUPrivacy: {
		Detectors: []DetectorRule{
			{"tfn_au", SensitivityHigh},
			{"australia_medicare", SensitivityHigh},
			{"phone", SensitivityMedium},
			{"email", SensitivityLow},
		},
	},
	RegimeCAPIPEDA: {
		Detectors: []DetectorRule{
			{"canada_sin", SensitivityHigh},
			{"phone", SensitivityMedium},
			{"email", SensitivityLow},
		},
	},
	RegimeUSBaseline: {
		Detectors: []DetectorRule{
			{"ssn_us", SensitivityHigh},
			{"credit_card", SensitivityHigh},
			{"passport_us", SensitivityMedium},
			{"phone", SensitivityLow},
			{"email", SensitivityLow},
		},
	},
}

// industryNames / regimeNames give the catalog human-friendly labels.
var industryNames = map[Industry]string{
	IndustryHealthcare:   "Healthcare",
	IndustryFinance:      "Finance & Banking",
	IndustryRetail:       "Retail & E-commerce",
	IndustryProfessional: "Professional Services",
	IndustryEducation:    "Education",
	IndustryTechnology:   "Technology",
	IndustryLegal:        "Legal",
	IndustryGeneral:      "General Business",
}

var regimeNames = map[ComplianceRegime]string{
	RegimeEUGDPR:     "EU GDPR",
	RegimeUKDPA:      "UK GDPR / DPA 2018",
	RegimeAUPrivacy:  "Australia Privacy Act",
	RegimeCAPIPEDA:   "Canada PIPEDA",
	RegimeUSBaseline: "US Baseline (PII/PCI)",
}

// Industries returns the supported industries in stable order.
func Industries() []Industry {
	out := make([]Industry, 0, len(industryProfiles))
	for i := range industryProfiles {
		out = append(out, i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// Regimes returns the supported compliance regimes in stable order.
func Regimes() []ComplianceRegime {
	out := make([]ComplianceRegime, 0, len(complianceProfiles))
	for r := range complianceProfiles {
		out = append(out, r)
	}
	sort.Slice(out, func(a, b int) bool { return out[a] < out[b] })
	return out
}

// buildCatalog assembles the full immutable template catalog from the
// authored profiles: one baseline, one per industry, one per regime.
// The slice is sorted by id for deterministic listing and seeding.
func buildCatalog() []Template {
	out := make([]Template, 0, 1+len(industryProfiles)+len(complianceProfiles))

	out = append(out, Template{
		ID:          baselineTemplateID,
		Kind:        KindBaseline,
		Name:        "Universal security baseline",
		Description: "Blocks malware, phishing, hacking-tool and anonymiser categories at the DNS and SWG planes for every tenant.",
		Spec:        cloneSpec(baselineProfile),
	})

	for _, i := range Industries() {
		spec := industryProfiles[i]
		out = append(out, Template{
			ID:          industryTemplateID(i),
			Kind:        KindIndustry,
			Name:        industryNames[i] + " acceptable-use & firewall",
			Description: industryDescription(i, spec),
			Industry:    i,
			Spec:        cloneSpec(spec),
		})
	}

	for _, r := range Regimes() {
		spec := complianceProfiles[r]
		out = append(out, Template{
			ID:          complianceTemplateID(r),
			Kind:        KindCompliance,
			Name:        regimeNames[r] + " data-protection",
			Description: regimeDescription(r, spec),
			Regime:      r,
			Spec:        cloneSpec(spec),
		})
	}

	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out
}

func industryDescription(i Industry, s Spec) string {
	blocked, monitored := splitCategoryActions(s.Categories)
	parts := []string{fmt.Sprintf("%s firewall posture", s.Firewall)}
	if len(blocked) > 0 {
		parts = append(parts, "blocks "+strings.Join(blocked, ", "))
	}
	if len(monitored) > 0 {
		parts = append(parts, "monitors "+strings.Join(monitored, ", "))
	}
	if len(s.Detectors) > 0 {
		parts = append(parts, "adds "+strings.Join(detectorNames(s.Detectors), ", ")+" DLP detection")
	}
	return fmt.Sprintf("%s profile: %s.", industryNames[i], strings.Join(parts, "; "))
}

func regimeDescription(r ComplianceRegime, s Spec) string {
	return fmt.Sprintf("%s: DLP detection for %s.", regimeNames[r], strings.Join(detectorNames(s.Detectors), ", "))
}

func splitCategoryActions(rules []CategoryRule) (blocked, monitored []string) {
	for _, r := range rules {
		switch r.Action {
		case CategoryBlock:
			blocked = append(blocked, string(r.Category))
		case CategoryMonitor:
			monitored = append(monitored, string(r.Category))
		}
	}
	return blocked, monitored
}

func detectorNames(rules []DetectorRule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = string(r.Detector)
	}
	return out
}

// cloneSpec deep-copies a Spec so catalog consumers cannot mutate the
// authored profile data through the returned slices.
func cloneSpec(s Spec) Spec {
	out := Spec{Firewall: s.Firewall}
	if len(s.Categories) > 0 {
		out.Categories = append([]CategoryRule(nil), s.Categories...)
	}
	if len(s.Detectors) > 0 {
		out.Detectors = append([]DetectorRule(nil), s.Detectors...)
	}
	return out
}

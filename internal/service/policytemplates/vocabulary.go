package policytemplates

// This file pins the controlled vocabularies the rendered Policy-Graph
// intent is built from. Every value here MUST be one the downstream
// data plane already understands, so a rendered baseline is a policy
// the edge can actually enforce — not a plausible-looking graph that
// silently never matches.
//
// Sources of truth (kept in sync by the parity tests in this package):
//   - URL categories: the dotted-category namespace shared by DNS, the
//     firewall L7 AppId table and the SWG categoriser
//     (crates/sng-swg/src/categorizer.rs; the Go canonicaliser
//     internal/service/appdb.mapCommunityCategory).
//   - PII detectors: the builtin DLP detector pattern names
//     (internal/service/dlp/templates.go + .../engine/proximity.go,
//     mirrored from crates/sng-dlp/src/detectors).

// URLCategory is a dotted URL-category token from the shared
// categoriser vocabulary. The SWG verdict layer and the DNS resolver
// both interpret these identically.
type URLCategory string

const (
	// Security-critical categories — blocked for every tenant
	// regardless of industry/country (see baselineProfile).
	CategorySecurityThreat  URLCategory = "security.threat"  // malware, phishing, fraud, C2
	CategorySecurityHacking URLCategory = "security.hacking" // hacking tools, exploit kits
	CategoryAnonymizer      URLCategory = "anonymizer"       // open proxies, anonymising VPNs

	// Acceptable-use categories — blocked or monitored per industry.
	CategoryAdultContent URLCategory = "adult.content"
	CategoryGambling     URLCategory = "gambling"
	CategoryViolence     URLCategory = "violence"
	CategoryDrugs        URLCategory = "drugs"
	CategorySocialMedia  URLCategory = "social.media"
	CategoryWebmail      URLCategory = "webmail"
	CategoryAdvertising  URLCategory = "advertising"
)

// knownCategories is the closed set this package will emit. A parity
// test cross-checks it against the canonicaliser vocabulary so a
// category that the data plane cannot resolve never ships in a
// baseline.
var knownCategories = map[URLCategory]struct{}{
	CategorySecurityThreat:  {},
	CategorySecurityHacking: {},
	CategoryAnonymizer:      {},
	CategoryAdultContent:    {},
	CategoryGambling:        {},
	CategoryViolence:        {},
	CategoryDrugs:           {},
	CategorySocialMedia:     {},
	CategoryWebmail:         {},
	CategoryAdvertising:     {},
}

// CategoryAction is what a baseline does with a URL category.
type CategoryAction string

const (
	// CategoryBlock denies the category at both the DNS plane
	// (sinkhole) and the SWG plane (URL filter) — defence in depth.
	CategoryBlock CategoryAction = "block"
	// CategoryMonitor allows the category but logs hits at the SWG
	// plane so the operator gets visibility without disruption.
	CategoryMonitor CategoryAction = "monitor"
)

// Sensitivity is the DLP confidence/handling tier carried on a DLP
// rule. It mirrors the SensitivityLevel strings used by the existing
// DLP policy templates (internal/service/dlp): high → block,
// medium → inspect/redact, low → log.
type Sensitivity string

const (
	SensitivityHigh   Sensitivity = "high"
	SensitivityMedium Sensitivity = "medium"
	SensitivityLow    Sensitivity = "low"
)

// PIIDetector is a builtin DLP detector pattern name. The values are a
// curated subset of the detectors registered in internal/service/dlp;
// a parity-style test asserts each one is a real, known detector so a
// baseline cannot reference a pattern the classifier will not run.
type PIIDetector string

// knownDetectors is the closed set of detector pattern names this
// package is allowed to emit. Mirrors the builtin DLP detectors.
var knownDetectors = map[PIIDetector]struct{}{
	// Cross-jurisdiction financial / contact identifiers.
	"credit_card":     {},
	"iban":            {},
	"swift":           {},
	"routing_number":  {},
	"email":           {},
	"phone":           {},
	"eu_vat":          {},
	"passport_us":     {},
	"ssn_us":          {},
	"drivers_license": {},
	// National identifiers, by jurisdiction.
	"ni_uk":                   {},
	"uk_nhs":                  {},
	"france_insee":            {},
	"germany_personalausweis": {},
	"canada_sin":              {},
	"tfn_au":                  {},
	"australia_medicare":      {},
	"brazil_cpf":              {},
	"brazil_cnpj":             {},
	"india_aadhaar":           {},
	"india_pan":               {},
	"china_resident_id":       {},
	"japan_my_number":         {},
	"korea_rrn":               {},
	"singapore_nric":          {},
	"thailand_id":             {},
	"philippines_umid":        {},
	"indonesia_nik":           {},
	"malaysia_mykad":          {},
	"uae_emirates_id":         {},
	"saudi_id":                {},
	"qatar_qid":               {},
	"kuwait_civil_id":         {},
	"bahrain_cpr":             {},
	// Healthcare identifiers (used by the healthcare industry profile).
	"mrn":   {},
	"icd10": {},
}

// FirewallPosture is the baseline NGFW egress strictness tier. The
// data plane enforces the emitted port rules verbatim; the tier only
// selects WHICH rule set a profile pulls in (see firewallRuleset).
type FirewallPosture string

const (
	// PostureStandard allows plaintext web (80) alongside TLS and
	// denies the lateral-movement / remote-management ports.
	PostureStandard FirewallPosture = "standard"
	// PostureStrict additionally forces TLS (denies plaintext 80 and
	// 25/telnet/FTP) for regulated industries handling sensitive data.
	PostureStrict FirewallPosture = "strict"
)

// l4Proto is the transport a firewall rule matches. Kept as a typed
// constant set so a profile cannot emit a bogus protocol token.
const (
	protoTCP = "tcp"
	protoUDP = "udp"
)

package engine

import (
	"strings"
	"unicode/utf8"
)

// Proximity context analysis adjusts a hit's confidence using the
// text surrounding the match. A locale field-label nearby lifts a
// hit; a counter-context word ("example"/"test"/"sample") sinks it.
// This mirrors the ProximityAnalyzer in
// crates/sng-dlp/src/classifier.rs and must agree with it.

const (
	// confidenceValidated is the base confidence for a regex hit
	// whose validator passed (or credit_card via Luhn): a strong
	// structural signal, so proximity can only reduce it.
	confidenceValidated = 1.0
	// confidenceBare is the base confidence for a bare regex hit with
	// no validator; proximity context can lift it or sink it.
	confidenceBare = 0.5
	// proximityContextBoost is added when a locale context keyword is
	// found within the window (capped at 1.0).
	proximityContextBoost = 0.15
	// proximityCounterPenalty is subtracted when a counter-context
	// keyword is found within the window.
	proximityCounterPenalty = 0.30
	// proximityFloor is the hard floor after a counter-context penalty.
	proximityFloor = 0.1
	// proximityWindowBytes is scanned on each side of a hit, clamped
	// to UTF-8 boundaries before search.
	proximityWindowBytes = 200
)

// counterContext marks a hit as illustrative rather than real PII,
// anywhere in any locale. Mirrors COUNTER_CONTEXT in classifier.rs.
// Stored lower-cased so the ASCII-case-insensitive window scan is a
// simple substring test.
var counterContext = []string{"example", "test", "sample"}

// contextKeywords maps a builtin pattern name to the locale field
// labels (local language + English) a real document carries near the
// identifier. Mirrors `context_keywords` in classifier.rs. ASCII
// cues are stored lower-cased; CJK / Arabic cues are caseless.
var contextKeywords = map[string][]string{
	"china_resident_id": {"身份证", "证件号", "身份证号码", "id number", "identity"},
	"japan_my_number":   {"マイナンバー", "個人番号", "my number"},
	"india_aadhaar":     {"आधार", "aadhaar", "uid"},
	"uae_emirates_id":   {"الهوية", "emirates id", "هوية"},
	"saudi_id":          {"الهوية الوطنية", "national id", "إقامة", "iqama"},
	// Patterns without a check-digit validator lean on proximity
	// alone, so give them English field-label cues.
	"qatar_qid":   {"qatar id", "qid", "national id"},
	"bahrain_cpr": {"cpr", "bahrain", "personal number"},

	// --- WS5 jurisdiction breadth (mirrors the detectors registry) ---
	"ni_uk":                   {"national insurance", "nino", "ni number", "ni no"},
	"uk_nhs":                  {"nhs", "nhs number", "national health"},
	"canada_sin":              {"social insurance", "sin", "numéro d'assurance sociale", "nas"},
	"tfn_au":                  {"tax file number", "tfn", "ato"},
	"australia_medicare":      {"medicare"},
	"germany_personalausweis": {"personalausweis", "ausweisnummer", "identity card", "id card"},
	"france_insee":            {"insee", "sécurité sociale", "securite sociale", "numéro de sécurité sociale", "social security", "nir"},
	"korea_rrn":               {"주민등록번호", "rrn", "resident registration"},
	"india_pan":               {"pan", "permanent account", "income tax"},
	"brazil_cpf":              {"cpf", "cadastro de pessoas", "receita federal"},
	"brazil_cnpj":             {"cnpj", "cadastro nacional", "pessoa jurídica"},
	"iban":                    {"iban", "bank account", "account number", "swift", "bic"},
	"eu_vat":                  {"vat", "vat number", "ust-idnr", "tva", "btw", "p.iva", "iva"},
	"philippines_umid":        {"umid", "crn", "common reference", "sss", "gsis"},
	"thailand_id":             {"บัตรประชาชน", "national id", "thai id"},
	"indonesia_nik":           {"nik", "ktp", "nomor induk kependudukan"},

	// --- WS-10c jurisdiction breadth (mirrors the detectors registry) ---
	"ireland_ppsn":    {"pps", "ppsn", "pps number", "personal public service", "uimhir psp"},
	"switzerland_ahv": {"ahv", "avs", "ahv-nummer", "sozialversicherungsnummer", "social security"},
	"israel_id":       {"תעודת זהות", "teudat zehut", "national id", "id number"},
	"romania_cnp":     {"cnp", "cod numeric personal", "personal numeric code"},
	"mexico_curp":     {"curp", "clave única de registro", "registro de población"},
}

// proximityKeywords returns the locale context keywords for a pattern
// name, or nil when the pattern has no proximity dictionary.
func proximityKeywords(name string) []string {
	return contextKeywords[name]
}

// proximityAdjust returns base adjusted by the context found within
// proximityWindowBytes on either side of the start..end hit.
// Counter-context dominates a context boost: an "example" nearby
// sinks confidence even if a label is also present. keywords are the
// locale cues for the pattern (already known non-empty).
func proximityAdjust(text string, start, end int, base float64, keywords []string) float64 {
	lo := floorCharBoundary(text, saturatingSub(start, proximityWindowBytes))
	hi := ceilCharBoundary(text, min(end+proximityWindowBytes, len(text)))
	// ASCII-lower the window once so the case-insensitive scan over
	// ASCII cues is a plain substring test; CJK / Arabic are caseless.
	window := asciiLower(text[lo:hi])

	for _, c := range counterContext {
		if strings.Contains(window, c) {
			return maxF(base-proximityCounterPenalty, proximityFloor)
		}
	}
	for _, k := range keywords {
		if strings.Contains(window, asciiLower(k)) {
			return minF(base+proximityContextBoost, 1.0)
		}
	}
	return base
}

// asciiLower lower-cases only ASCII A–Z, leaving all other bytes
// untouched, matching Aho-Corasick's ascii_case_insensitive on the
// Rust side.
func asciiLower(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

func saturatingSub(a, b int) int {
	if a < b {
		return 0
	}
	return a - b
}

// floorCharBoundary returns the largest UTF-8 boundary <= i in s.
func floorCharBoundary(s string, i int) int {
	if i > len(s) {
		i = len(s)
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}

// ceilCharBoundary returns the smallest UTF-8 boundary >= i in s.
func ceilCharBoundary(s string, i int) int {
	if i > len(s) {
		return len(s)
	}
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return i
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

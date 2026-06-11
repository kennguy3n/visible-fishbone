// Package engine contains the DLP detection engines: regex/keyword
// matching, MIP label reading, and document fingerprinting.
package engine

import (
	"container/list"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sync/singleflight"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// maxCustomCacheSize is the upper bound on cached custom regex
// patterns. When the limit is reached the least-recently-used
// entry is evicted.
const maxCustomCacheSize = 1024

// builtinPatterns maps well-known PII pattern names to compiled
// regular expressions. The keys are used as the Pattern field in
// DLPRule entries with type "regex".
var builtinPatterns = map[string]*regexp.Regexp{
	// Credit card: 13-19 digit sequences with optional separators.
	"credit_card": regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`),
	// US SSN: 3-2-4 digit pattern.
	"ssn_us": regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
	// UK National Insurance number.
	"ni_uk": regexp.MustCompile(`(?i)\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`),
	// AU Tax File Number: 8-9 digits.
	"tfn_au": regexp.MustCompile(`\b\d{3}\s?\d{3}\s?\d{2,3}\b`),
	// Email address.
	"email": regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`),
	// International phone numbers: +country code with 7-15 digits.
	"phone": regexp.MustCompile(`\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}`),
	// IBAN: 2 letter country code + 2 check digits + up to 30 alphanums.
	"iban": regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b`),
	// SWIFT/BIC code.
	"swift": regexp.MustCompile(`\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b`),
	// US routing number: 9 digits.
	"routing_number": regexp.MustCompile(`\b\d{9}\b`),
	// US passport: 1 letter + 8 digits (simplified).
	"passport_us": regexp.MustCompile(`\b[A-Z]\d{8}\b`),
	// US driver's license: simplified multi-state pattern.
	"drivers_license": regexp.MustCompile(`\b[A-Z]\d{4,8}\b`),
	// ICD-10 diagnosis codes.
	"icd10": regexp.MustCompile(`\b[A-TV-Z]\d{2}(\.\d{1,4})?\b`),
	// Medical Record Number (MRN): 6-10 digits.
	"mrn": regexp.MustCompile(`\b\d{6,10}\b`),

	// --- Asia national IDs (confirmed by validators.go) ---
	// China resident identity card: 17 digits + check (digit or X).
	"china_resident_id": regexp.MustCompile(`\b\d{17}[\dXx]\b`),
	// Japan My Number: 12 digits in 4-4-4 groups.
	"japan_my_number": regexp.MustCompile(`\b\d{4}\s?\d{4}\s?\d{4}\b`),
	// South Korea RRN: 6 + 7 digits, optional hyphen.
	"korea_rrn": regexp.MustCompile(`\b\d{6}-?\d{7}\b`),
	// Singapore NRIC / FIN: prefix letter + 7 digits + check letter.
	"singapore_nric": regexp.MustCompile(`(?i)\b[STFGM]\d{7}[A-Z]\b`),
	// Malaysia MyKad: 12 digits, optional 6-2-4 hyphenation.
	"malaysia_mykad": regexp.MustCompile(`\b\d{6}-?\d{2}-?\d{4}\b`),
	// Thailand national ID: 13 digits, optional 1-4-5-2-1 hyphenation.
	"thailand_id": regexp.MustCompile(`\b\d{1}-?\d{4}-?\d{5}-?\d{2}-?\d{1}\b`),
	// India Aadhaar: 12 digits in 4-4-4 groups.
	"india_aadhaar": regexp.MustCompile(`\b\d{4}\s?\d{4}\s?\d{4}\b`),
	// India PAN: 5 letters + 4 digits + 1 letter.
	"india_pan": regexp.MustCompile(`\b[A-Z]{5}\d{4}[A-Z]\b`),

	// --- GCC national IDs ---
	// UAE Emirates ID: 784 + 4 + 7 + 1 digits, optional hyphens.
	"uae_emirates_id": regexp.MustCompile(`\b784-?\d{4}-?\d{7}-?\d{1}\b`),
	// Saudi national / Iqama ID: 10 digits starting 1 or 2.
	"saudi_id": regexp.MustCompile(`\b[12]\d{9}\b`),
	// Qatar QID: 11 digits (no validator; proximity-gated).
	"qatar_qid": regexp.MustCompile(`\b\d{11}\b`),
	// Kuwait Civil ID: 12 digits.
	"kuwait_civil_id": regexp.MustCompile(`\b\d{12}\b`),
	// Bahrain CPR: 9 digits (no validator; proximity-gated).
	"bahrain_cpr": regexp.MustCompile(`\b\d{9}\b`),

	// --- WS5 jurisdiction breadth (validators in validators_ws5.go) ---
	// UK NHS number: 3-3-4 digits, modulus-11 check.
	"uk_nhs": regexp.MustCompile(`\b\d{3}\s?\d{3}\s?\d{4}\b`),
	// Canada SIN: 3-3-3 digits with optional space/hyphen, Luhn.
	"canada_sin": regexp.MustCompile(`\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b`),
	// Australia Medicare: leading 2-6, then 3+5+1 digits.
	"australia_medicare": regexp.MustCompile(`\b[2-6]\d{3}\s?\d{5}\s?\d\b`),
	// Germany Personalausweis: 9 alphanumerics + check digit.
	"germany_personalausweis": regexp.MustCompile(`\b[0-9A-Z]{9}\d\b`),
	// France INSEE / NIR: sex + DOB + dept (incl. Corsica A/B) + order + key.
	"france_insee": regexp.MustCompile(`\b[1-8]\s?\d{2}\s?\d{2}\s?\d[AB0-9]\s?\d{3}\s?\d{3}\s?\d{2}\b`),
	// Brazil CPF: 3.3.3-2 digits with optional punctuation.
	"brazil_cpf": regexp.MustCompile(`\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b`),
	// Brazil CNPJ: 2.3.3/4-2 digits with optional punctuation.
	"brazil_cnpj": regexp.MustCompile(`\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b`),
	// EU VAT: country prefix + 2-12 alphanumerics (+,* for some states).
	"eu_vat": regexp.MustCompile(`\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[0-9A-Za-z+*]{2,12}\b`),
	// Philippines UMID / CRN: 4-7-1 digits.
	"philippines_umid": regexp.MustCompile(`\b\d{4}-?\d{7}-?\d\b`),
	// Indonesia NIK (KTP): 16 digits.
	"indonesia_nik": regexp.MustCompile(`\b\d{16}\b`),

	// --- Secret / credential detectors (confirmed by validators.go) ---
	// Distinctive vendor prefixes make these near-zero-FP; each
	// resolves to a structural validator in validatorFor that
	// re-asserts the exact prefix + charset + length (or, for the JWT,
	// a decodable header). The shapes mirror `builtin_pattern` in
	// crates/sng-dlp/src/classifier.rs.
	"private_key_block": regexp.MustCompile(`(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
	"aws_access_key_id": regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`),
	"google_api_key":    regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	"github_token":      regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`),
	"github_pat":        regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{82}\b`),
	"slack_token":       regexp.MustCompile(`\bxox[abprs]-[0-9A-Za-z-]{10,}\b`),
	"stripe_secret_key": regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b`),
	"jwt":               regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
}

// RegexEngine provides pre-compiled regex matching for PII patterns.
// Tenant-defined custom patterns are compiled on first use and
// cached in a bounded LRU cache. Concurrent compilations of the
// same pattern are coalesced via singleflight.
type RegexEngine struct {
	mu    sync.Mutex
	cache map[string]*list.Element
	order *list.List
	sfg   singleflight.Group
}

type cacheEntry struct {
	pattern string
	re      *regexp.Regexp
}

// NewRegexEngine constructs a regex engine with an empty custom
// pattern cache.
func NewRegexEngine() *RegexEngine {
	return &RegexEngine{
		cache: make(map[string]*list.Element, maxCustomCacheSize),
		order: list.New(),
	}
}

// Match evaluates content against the provided rules and returns
// all matches. For rules whose Pattern matches a builtin name the
// builtin regex is used; otherwise the pattern is compiled as a
// custom regex.
func (e *RegexEngine) Match(content []byte, rules []repository.DLPRule) []Match {
	// NFC-normalize before scanning so Arabic diacritics and CJK
	// full-/half-width variants compare equal to the shipped patterns.
	// ASCII is unchanged, so existing offsets / snippets are preserved.
	text := normalizeNFC(string(content))
	var out []Match
	for _, r := range rules {
		if r.Type != repository.DLPRuleTypeRegex && r.Type != repository.DLPRuleTypeKeyword {
			continue
		}
		re := e.resolve(r)
		if re == nil {
			continue
		}
		// A regex rule may carry a check-digit validator and/or a
		// proximity dictionary; keyword rules keep the legacy 0.8.
		var validator func(string) bool
		var keywords []string
		if r.Type == repository.DLPRuleTypeRegex {
			if r.Pattern == "credit_card" {
				validator = luhnValid
			} else {
				validator = validatorFor(r.Pattern)
			}
			keywords = proximityKeywords(r.Pattern)
		}

		locs := re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			snippet := text[loc[0]:loc[1]]
			conf := 0.8
			if r.Type == repository.DLPRuleTypeRegex {
				validated := true
				if validator != nil {
					if !validator(snippet) {
						// A failed check digit means same-shaped noise.
						continue
					}
				} else {
					validated = false
				}
				if validated {
					conf = confidenceValidated
				} else {
					conf = confidenceBare
				}
				if keywords != nil {
					conf = proximityAdjust(text, loc[0], loc[1], conf, keywords)
				}
			}
			out = append(out, Match{
				RuleType:   r.Type,
				Pattern:    r.Pattern,
				Offset:     loc[0],
				Length:     loc[1] - loc[0],
				Snippet:    snippet,
				Confidence: conf,
			})
		}
	}
	return out
}

// resolve returns the compiled regex for a rule. Builtin patterns
// are preferred; custom patterns are compiled and cached.
func (e *RegexEngine) resolve(r repository.DLPRule) *regexp.Regexp {
	if r.Type == repository.DLPRuleTypeKeyword {
		return e.compileCustom(`(?i)\b` + regexp.QuoteMeta(r.Pattern) + `\b`)
	}
	if bi, ok := builtinPatterns[r.Pattern]; ok {
		return bi
	}
	return e.compileCustom(r.Pattern)
}

func (e *RegexEngine) compileCustom(pattern string) *regexp.Regexp {
	e.mu.Lock()
	if elem, ok := e.cache[pattern]; ok {
		e.order.MoveToFront(elem)
		e.mu.Unlock()
		return elem.Value.(*cacheEntry).re
	}
	e.mu.Unlock()

	v, _, _ := e.sfg.Do(pattern, func() (any, error) {
		return regexp.Compile(pattern)
	})
	re, _ := v.(*regexp.Regexp)
	if re == nil {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if elem, ok := e.cache[pattern]; ok {
		e.order.MoveToFront(elem)
		return elem.Value.(*cacheEntry).re
	}
	if e.order.Len() >= maxCustomCacheSize {
		oldest := e.order.Back()
		delete(e.cache, oldest.Value.(*cacheEntry).pattern)
		e.order.Remove(oldest)
	}
	elem := e.order.PushFront(&cacheEntry{pattern: pattern, re: re})
	e.cache[pattern] = elem
	return re
}

// luhnValid checks whether a digit string passes the Luhn algorithm.
func luhnValid(s string) bool {
	digits := stripNonDigits(s)
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	var sum int
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n, err := strconv.Atoi(string(digits[i]))
		if err != nil {
			return false
		}
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func stripNonDigits(s string) string {
	var b strings.Builder
	for _, c := range s {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

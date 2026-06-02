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
	text := string(content)
	var out []Match
	for _, r := range rules {
		if r.Type != repository.DLPRuleTypeRegex && r.Type != repository.DLPRuleTypeKeyword {
			continue
		}
		re := e.resolve(r)
		if re == nil {
			continue
		}
		locs := re.FindAllStringIndex(text, -1)
		for _, loc := range locs {
			snippet := text[loc[0]:loc[1]]
			conf := 0.8
			if r.Type == repository.DLPRuleTypeRegex && r.Pattern == "credit_card" {
				if luhnValid(snippet) {
					conf = 1.0
				} else {
					continue
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

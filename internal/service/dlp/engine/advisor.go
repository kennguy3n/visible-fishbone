package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// FP/FN advisor.
//
// RegexEngine compiles any non-builtin pattern as a raw custom regex
// (see resolve / compileCustom), so a tenant can already author a
// "bring-your-own" regex/keyword rule. Those custom rules ship with no
// safety net: nothing measures their false-positive / false-negative
// behaviour, and nothing suggests how to tighten or loosen them.
//
// AdviseRule closes that gap. Given a candidate rule (built-in or
// custom) and a set of tenant-supplied labeled samples, it scores the
// rule on the *real* decision path (RegexEngine.Match — so check-digit
// validators and proximity context already count), reports the
// confusion matrix + rates, and emits deterministic, actionable
// suggestions. It is a pure function over caller-supplied text:
// operator-invoked on demand, no background sweep, no persisted state,
// so dormant tenants pay nothing. This is the coach-first pre-activation
// safety check for tenant custom-rule add-ons.

// LabeledSample is one piece of tenant-supplied text annotated with
// whether the rule is *expected* to match it. Samples with ShouldMatch
// true drive false-negative measurement; the rest drive false-positive
// measurement.
type LabeledSample struct {
	Text        string
	ShouldMatch bool
}

// RuleQuality is the confusion-matrix summary of a rule scored against
// a labeled sample set. Rates are in [0,1].
type RuleQuality struct {
	// Positives is the count of samples labeled ShouldMatch; Negatives
	// the rest.
	Positives int
	Negatives int

	TruePositives  int
	FalsePositives int
	FalseNegatives int
	TrueNegatives  int

	// Precision is TP/(TP+FP); 1.0 when the rule predicted no
	// positives (it raised no false alarms).
	Precision float64
	// Recall is TP/(TP+FN); 1.0 when no positives were expected.
	Recall float64
	// FalsePositiveRate is FP/Negatives (0 when no negatives given).
	FalsePositiveRate float64
	// FalseNegativeRate is FN/Positives (0 when no positives given).
	FalseNegativeRate float64
	// F1 is the harmonic mean of precision and recall.
	F1 float64
}

// fill derives the rates from the raw confusion-matrix counts.
func (q *RuleQuality) fill() {
	if predicted := q.TruePositives + q.FalsePositives; predicted > 0 {
		q.Precision = float64(q.TruePositives) / float64(predicted)
	} else {
		q.Precision = 1.0
	}
	if q.Positives > 0 {
		q.Recall = float64(q.TruePositives) / float64(q.Positives)
		q.FalseNegativeRate = float64(q.FalseNegatives) / float64(q.Positives)
	} else {
		q.Recall = 1.0
	}
	if q.Negatives > 0 {
		q.FalsePositiveRate = float64(q.FalsePositives) / float64(q.Negatives)
	}
	if q.Precision+q.Recall > 0 {
		q.F1 = 2 * q.Precision * q.Recall / (q.Precision + q.Recall)
	}
}

// SuggestionCode is a stable identifier for an advisor finding, so
// callers can localise or act on it programmatically.
type SuggestionCode string

const (
	// SuggestInvalidPattern: the custom pattern is not a valid regex.
	SuggestInvalidPattern SuggestionCode = "invalid_pattern"
	// SuggestUseBuiltin: the custom pattern duplicates a built-in shape.
	SuggestUseBuiltin SuggestionCode = "use_builtin"
	// SuggestAnchorBoundaries: FPs + no \b/line anchors.
	SuggestAnchorBoundaries SuggestionCode = "anchor_boundaries"
	// SuggestNarrowCharClass: FPs + a broad/unbounded character class.
	SuggestNarrowCharClass SuggestionCode = "narrow_char_class"
	// SuggestAttachValidator: FPs + no structural validator attached.
	SuggestAttachValidator SuggestionCode = "attach_validator"
	// SuggestLoosenPattern: FNs (the rule missed should-match samples).
	SuggestLoosenPattern SuggestionCode = "loosen_pattern"
	// SuggestAddSamples: too few negatives to trust the FP estimate.
	SuggestAddSamples SuggestionCode = "add_samples"
)

// Suggestion is one deterministic advisor finding.
type Suggestion struct {
	Code SuggestionCode
	// Severity is "error" (blocks SafeToEnable), "warn", or "info".
	Severity string
	Message  string
}

// Advice is the full advisor output for one rule + sample set.
type Advice struct {
	Quality      RuleQuality
	Suggestions  []Suggestion
	SafeToEnable bool
}

// Advisor thresholds. A rule is only deemed safe to enable with strong,
// evidenced precision — coach-first means we default to "not safe"
// unless the samples prove otherwise.
const (
	adviseMinPrecision = 0.95
	adviseMaxFPRate    = 0.05
	adviseMinPositives = 1
	adviseMinNegatives = 5
)

// AdviseRule scores rule against samples and returns measured FP/FN
// rates plus deterministic suggestions. It mutates nothing.
func (e *RegexEngine) AdviseRule(rule repository.DLPRule, samples []LabeledSample) Advice {
	// A custom pattern that does not compile can never be safe; flag it
	// and skip scoring (every sample would trivially be a miss).
	compileFailed := e.resolve(rule) == nil

	var q RuleQuality
	for _, s := range samples {
		if s.ShouldMatch {
			q.Positives++
		} else {
			q.Negatives++
		}
		matched := false
		if !compileFailed {
			matched = len(e.Match([]byte(s.Text), []repository.DLPRule{rule})) > 0
		}
		switch {
		case s.ShouldMatch && matched:
			q.TruePositives++
		case s.ShouldMatch && !matched:
			q.FalseNegatives++
		case !s.ShouldMatch && matched:
			q.FalsePositives++
		default:
			q.TrueNegatives++
		}
	}
	q.fill()

	suggestions := e.suggest(rule, q, compileFailed)
	safe := !compileFailed &&
		q.Positives >= adviseMinPositives &&
		q.Negatives >= adviseMinNegatives &&
		q.Precision >= adviseMinPrecision &&
		q.FalsePositiveRate <= adviseMaxFPRate &&
		q.FalseNegatives == 0

	return Advice{Quality: q, Suggestions: suggestions, SafeToEnable: safe}
}

// suggest derives the deterministic findings for a scored rule.
func (e *RegexEngine) suggest(rule repository.DLPRule, q RuleQuality, compileFailed bool) []Suggestion {
	if compileFailed {
		return []Suggestion{{
			Code:     SuggestInvalidPattern,
			Severity: "error",
			Message:  "Pattern failed to compile as a regular expression; fix the syntax before enabling.",
		}}
	}

	var out []Suggestion
	_, isBuiltin := builtinPatterns[rule.Pattern]
	isCustomRegex := rule.Type == repository.DLPRuleTypeRegex && !isBuiltin

	if isCustomRegex {
		if name := builtinEquivalent(rule.Pattern); name != "" {
			out = append(out, Suggestion{
				Code:     SuggestUseBuiltin,
				Severity: "warn",
				Message: fmt.Sprintf("This pattern is identical to the built-in %q detector; "+
					"reference it by name to inherit its check-digit validator and proximity "+
					"context (higher precision, no tuning).", name),
			})
		}
	}

	if q.FalsePositives > 0 && isCustomRegex {
		if !hasBoundaryAnchor(rule.Pattern) {
			out = append(out, Suggestion{
				Code:     SuggestAnchorBoundaries,
				Severity: "warn",
				Message: "False positives observed and the pattern has no word-boundary (\\b) or " +
					"line anchors; add anchors so it does not match inside larger tokens.",
			})
		}
		if hasBroadClass(rule.Pattern) {
			out = append(out, Suggestion{
				Code:     SuggestNarrowCharClass,
				Severity: "warn",
				Message: "False positives observed and the pattern uses a broad class (., \\w, or an " +
					"unbounded [A-Za-z0-9]+); narrow the character class or add a length bound.",
			})
		}
		if validatorFor(rule.Pattern) == nil {
			out = append(out, Suggestion{
				Code:     SuggestAttachValidator,
				Severity: "info",
				Message: "No structural validator is attached; if this identifier carries a checksum, " +
					"model it as a built-in detector so a validator can reject same-shaped noise.",
			})
		}
	}

	if q.FalseNegatives > 0 {
		out = append(out, Suggestion{
			Code:     SuggestLoosenPattern,
			Severity: "warn",
			Message: "False negatives observed: the pattern missed samples you labeled should-match; " +
				"loosen it (e.g. allow optional separators/whitespace or add the case-insensitive (?i) flag).",
		})
	}

	if q.Negatives < adviseMinNegatives {
		out = append(out, Suggestion{
			Code:     SuggestAddSamples,
			Severity: "info",
			Message: fmt.Sprintf("Only %d negative sample(s) provided; supply at least %d realistic "+
				"non-matching samples so the false-positive estimate is meaningful before enabling.",
				q.Negatives, adviseMinNegatives),
		})
	}

	return out
}

// builtinEquivalent returns the name of the built-in pattern whose
// regex source is byte-identical to pattern, or "" if none. Names are
// scanned in sorted order so the result is deterministic.
func builtinEquivalent(pattern string) string {
	names := make([]string, 0, len(builtinPatterns))
	for name := range builtinPatterns {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if builtinPatterns[name].String() == pattern {
			return name
		}
	}
	return ""
}

// hasBoundaryAnchor reports whether a pattern carries any word-boundary
// or line/string anchor, the cheapest defence against matching inside a
// larger token.
func hasBoundaryAnchor(pattern string) bool {
	for _, anchor := range []string{`\b`, `\A`, `\z`, `\B`, "^", "$"} {
		if strings.Contains(pattern, anchor) {
			return true
		}
	}
	return false
}

// broadUnboundedClass flags an unbounded repetition of a character
// class, e.g. [A-Za-z0-9]+ or [0-9]*, which tends to over-match.
var broadUnboundedClass = regexp.MustCompile(`\[[^\]]+\][*+]`)

// hasBroadClass reports whether a pattern leans on a broad,
// length-unbounded character class likely to over-match.
func hasBroadClass(pattern string) bool {
	return strings.Contains(pattern, `\w`) ||
		strings.Contains(pattern, ".*") ||
		strings.Contains(pattern, ".+") ||
		broadUnboundedClass.MatchString(pattern)
}

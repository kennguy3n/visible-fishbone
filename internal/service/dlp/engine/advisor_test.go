package engine

import (
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func regexRule(pattern string) repository.DLPRule {
	return repository.DLPRule{Type: repository.DLPRuleTypeRegex, Pattern: pattern}
}

func hasSuggestion(a Advice, code SuggestionCode) bool {
	for _, s := range a.Suggestions {
		if s.Code == code {
			return true
		}
	}
	return false
}

// A precise built-in rule on clean, well-labeled samples should score
// perfectly and be deemed safe to enable.
func TestAdviseRule_SafeToEnable(t *testing.T) {
	e := NewRegexEngine()
	samples := []LabeledSample{
		{Text: "contact alice@example.com for access", ShouldMatch: true},
		{Text: "billing bob.smith@corp.co.uk please", ShouldMatch: true},
		{Text: "the quarterly report is attached", ShouldMatch: false},
		{Text: "no identifiers in this sentence", ShouldMatch: false},
		{Text: "just a plain line of prose", ShouldMatch: false},
		{Text: "another harmless paragraph here", ShouldMatch: false},
		{Text: "meeting at noon tomorrow ok", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule("email"), samples)

	if a.Quality.TruePositives != 2 || a.Quality.FalsePositives != 0 ||
		a.Quality.FalseNegatives != 0 || a.Quality.TrueNegatives != 5 {
		t.Fatalf("confusion matrix = %+v", a.Quality)
	}
	if a.Quality.Precision != 1.0 || a.Quality.Recall != 1.0 || a.Quality.FalsePositiveRate != 0 {
		t.Fatalf("rates = %+v", a.Quality)
	}
	if !a.SafeToEnable {
		t.Fatalf("expected SafeToEnable, got false; suggestions=%+v", a.Suggestions)
	}
}

// A broad, unanchored custom regex that fires inside larger tokens
// should report false positives and earn the tighten-it suggestions,
// and must NOT be deemed safe.
func TestAdviseRule_FalsePositivesTighten(t *testing.T) {
	e := NewRegexEngine()
	samples := []LabeledSample{
		{Text: "PIN is 4321 today", ShouldMatch: true},
		{Text: "order number 99887766 shipped", ShouldMatch: false},
		{Text: "invoice 12345678 paid", ShouldMatch: false},
		{Text: "reference 55667788 closed", ShouldMatch: false},
		{Text: "ticket 44556677 resolved", ShouldMatch: false},
		{Text: "case 33445566 archived", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule(`\d{4}`), samples)

	if a.Quality.FalsePositives == 0 {
		t.Fatalf("expected false positives, quality=%+v", a.Quality)
	}
	if !hasSuggestion(a, SuggestAnchorBoundaries) {
		t.Errorf("expected anchor_boundaries suggestion; got %+v", a.Suggestions)
	}
	if !hasSuggestion(a, SuggestAttachValidator) {
		t.Errorf("expected attach_validator suggestion; got %+v", a.Suggestions)
	}
	if a.SafeToEnable {
		t.Errorf("a rule with false positives must not be safe to enable")
	}
}

// An unbounded broad character class earns the narrow-class suggestion.
func TestAdviseRule_BroadClass(t *testing.T) {
	e := NewRegexEngine()
	samples := []LabeledSample{
		{Text: "token abc123", ShouldMatch: true},
		{Text: "hello world", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule(`[A-Za-z0-9]+`), samples)
	if !hasSuggestion(a, SuggestNarrowCharClass) {
		t.Fatalf("expected narrow_char_class suggestion; got %+v", a.Suggestions)
	}
}

// A custom pattern byte-identical to a built-in should be steered to the
// built-in (which carries a validator + proximity dictionary).
func TestAdviseRule_UseBuiltin(t *testing.T) {
	e := NewRegexEngine()
	// routing_number / bahrain_cpr / israel_id all use `\b\d{9}\b`.
	samples := []LabeledSample{
		{Text: "routing 123456789 here", ShouldMatch: true},
		{Text: "nothing relevant", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule(`\b\d{9}\b`), samples)
	if !hasSuggestion(a, SuggestUseBuiltin) {
		t.Fatalf("expected use_builtin suggestion; got %+v", a.Suggestions)
	}
}

// A too-strict (case-sensitive) custom regex that misses a should-match
// sample reports a false negative and the loosen suggestion.
func TestAdviseRule_FalseNegativeLoosen(t *testing.T) {
	e := NewRegexEngine()
	samples := []LabeledSample{
		{Text: "this document is confidential", ShouldMatch: true},
		{Text: "public marketing copy", ShouldMatch: false},
		{Text: "another public note", ShouldMatch: false},
		{Text: "press release draft", ShouldMatch: false},
		{Text: "open data set readme", ShouldMatch: false},
		{Text: "weekly status email", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule(`\bCONFIDENTIAL\b`), samples)
	if a.Quality.FalseNegatives != 1 {
		t.Fatalf("expected 1 false negative, quality=%+v", a.Quality)
	}
	if !hasSuggestion(a, SuggestLoosenPattern) {
		t.Errorf("expected loosen_pattern suggestion; got %+v", a.Suggestions)
	}
	if a.SafeToEnable {
		t.Errorf("a rule with false negatives must not be safe to enable")
	}
}

// Too few negative samples cannot evidence a safe verdict.
func TestAdviseRule_AddSamples(t *testing.T) {
	e := NewRegexEngine()
	samples := []LabeledSample{
		{Text: "contact alice@example.com", ShouldMatch: true},
		{Text: "a harmless line", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule("email"), samples)
	if !hasSuggestion(a, SuggestAddSamples) {
		t.Errorf("expected add_samples suggestion; got %+v", a.Suggestions)
	}
	if a.SafeToEnable {
		t.Errorf("must not be safe with only %d negative(s)", a.Quality.Negatives)
	}
}

// A pattern that does not compile is flagged and never safe.
func TestAdviseRule_InvalidPattern(t *testing.T) {
	e := NewRegexEngine()
	samples := []LabeledSample{
		{Text: "anything", ShouldMatch: true},
		{Text: "anything else", ShouldMatch: false},
	}
	a := e.AdviseRule(regexRule(`[unterminated`), samples)
	if !hasSuggestion(a, SuggestInvalidPattern) {
		t.Fatalf("expected invalid_pattern suggestion; got %+v", a.Suggestions)
	}
	if len(a.Suggestions) != 1 {
		t.Errorf("invalid pattern should short-circuit to one suggestion, got %+v", a.Suggestions)
	}
	if a.SafeToEnable {
		t.Errorf("an invalid pattern must not be safe to enable")
	}
}

// builtinEquivalent is deterministic and matches by regex source.
func TestBuiltinEquivalent(t *testing.T) {
	if got := builtinEquivalent(`\b\d{9}\b`); got == "" {
		t.Errorf("expected a builtin match for the 9-digit shape, got none")
	}
	if got := builtinEquivalent(`this-shape-matches-nothing`); got != "" {
		t.Errorf("expected no builtin match, got %q", got)
	}
}

func TestHasBoundaryAnchorAndBroadClass(t *testing.T) {
	if hasBoundaryAnchor(`\d{4}`) {
		t.Errorf("\\d{4} has no boundary anchor")
	}
	if !hasBoundaryAnchor(`\b\d{4}\b`) {
		t.Errorf("\\b...\\b should be detected as anchored")
	}
	if !hasBroadClass(`[A-Za-z0-9]+`) {
		t.Errorf("unbounded class should be flagged broad")
	}
	if hasBroadClass(`\d{4}`) {
		t.Errorf("bounded \\d{4} should not be flagged broad")
	}
}

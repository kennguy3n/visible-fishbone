package engine

import (
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestRegexEngine_CreditCard_LuhnValid(t *testing.T) {
	e := NewRegexEngine()
	// Visa test card number (Luhn-valid).
	content := []byte("card: 4111 1111 1111 1111")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: "credit_card"},
	}
	matches := e.Match(content, rules)
	if len(matches) == 0 {
		t.Fatal("expected at least one credit card match")
	}
	if matches[0].Confidence != 1.0 {
		t.Errorf("expected confidence 1.0 for Luhn-valid card, got %f", matches[0].Confidence)
	}
}

func TestRegexEngine_CreditCard_LuhnInvalid(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("card: 4111 1111 1111 1112")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: "credit_card"},
	}
	matches := e.Match(content, rules)
	if len(matches) != 0 {
		t.Fatalf("expected no matches for Luhn-invalid card, got %d", len(matches))
	}
}

func TestRegexEngine_SSN(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("SSN: 123-45-6789")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: "ssn_us"},
	}
	matches := e.Match(content, rules)
	if len(matches) != 1 {
		t.Fatalf("expected 1 SSN match, got %d", len(matches))
	}
	if matches[0].Snippet != "123-45-6789" {
		t.Errorf("unexpected snippet: %q", matches[0].Snippet)
	}
}

func TestRegexEngine_Email(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("contact: alice@example.com and bob@test.org")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: "email"},
	}
	matches := e.Match(content, rules)
	if len(matches) != 2 {
		t.Fatalf("expected 2 email matches, got %d", len(matches))
	}
}

func TestRegexEngine_Phone(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("call +1-555-123-4567")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: "phone"},
	}
	matches := e.Match(content, rules)
	if len(matches) == 0 {
		t.Fatal("expected at least one phone match")
	}
}

func TestRegexEngine_Keyword(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("The patient diagnosis was confirmed by the doctor.")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeKeyword, Pattern: "diagnosis"},
	}
	matches := e.Match(content, rules)
	if len(matches) != 1 {
		t.Fatalf("expected 1 keyword match, got %d", len(matches))
	}
}

func TestRegexEngine_CustomPattern(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("Project: ALPHA-12345")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: `ALPHA-\d{5}`},
	}
	matches := e.Match(content, rules)
	if len(matches) != 1 {
		t.Fatalf("expected 1 custom pattern match, got %d", len(matches))
	}
	if matches[0].Snippet != "ALPHA-12345" {
		t.Errorf("unexpected snippet: %q", matches[0].Snippet)
	}
}

func TestRegexEngine_InvalidRegex(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("test data")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: `(?P<bad`},
	}
	matches := e.Match(content, rules)
	if len(matches) != 0 {
		t.Fatalf("expected 0 matches for invalid regex, got %d", len(matches))
	}
}

func TestRegexEngine_UKNI(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("NI number: AB 12 34 56 C")
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: "ni_uk"},
	}
	matches := e.Match(content, rules)
	if len(matches) == 0 {
		t.Fatal("expected at least one UK NI match")
	}
}

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		input string
		valid bool
	}{
		{"4111111111111111", true},
		{"4111111111111112", false},
		{"5500000000000004", true},
		{"378282246310005", true},
		{"12345", false},
	}
	for _, tt := range tests {
		if got := luhnValid(tt.input); got != tt.valid {
			t.Errorf("luhnValid(%q) = %v, want %v", tt.input, got, tt.valid)
		}
	}
}

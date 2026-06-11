package engine

import (
	"fmt"
	"strings"
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

func TestRegexEngine_CacheEviction(t *testing.T) {
	e := NewRegexEngine()
	content := []byte("MATCH-000")

	// Fill the cache beyond maxCustomCacheSize.
	for i := 0; i <= maxCustomCacheSize; i++ {
		pat := fmt.Sprintf(`MATCH-%03d`, i)
		rules := []repository.DLPRule{
			{Type: repository.DLPRuleTypeRegex, Pattern: pat},
		}
		e.Match([]byte(pat), rules)
	}

	// Cache size must not exceed the limit.
	e.mu.Lock()
	size := len(e.cache)
	e.mu.Unlock()
	if size > maxCustomCacheSize {
		t.Fatalf("cache size %d exceeds max %d", size, maxCustomCacheSize)
	}

	// The most recently used pattern should still be cached and match.
	latest := fmt.Sprintf(`MATCH-%03d`, maxCustomCacheSize)
	rules := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: latest},
	}
	matches := e.Match([]byte(latest), rules)
	if len(matches) == 0 {
		t.Fatal("expected match for most recently cached pattern")
	}

	// Earliest pattern (index 0) should have been evicted but still
	// compiles on demand (just not in cache before this call).
	rules0 := []repository.DLPRule{
		{Type: repository.DLPRuleTypeRegex, Pattern: `MATCH-000`},
	}
	matches0 := e.Match(content, rules0)
	if len(matches0) == 0 {
		t.Fatal("expected match after re-compile of evicted pattern")
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

// secretMatch reports whether the builtin pattern named by `pattern`
// (resolved + validator-confirmed) fires on `content`.
func secretMatch(t *testing.T, pattern, content string) bool {
	t.Helper()
	e := NewRegexEngine()
	rules := []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: pattern}}
	return len(e.Match([]byte(content), rules)) > 0
}

// Mirrors the Rust classifier secret-detector tests: the regex bounds
// the candidate and the structural validator confirms it, so a real
// credential fires and same-shaped noise is suppressed.
func TestRegexEngine_SecretDetectors(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		content string
		want    bool
	}{
		{"aws hit", "aws_access_key_id", "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", true},
		{"aws one char short", "aws_access_key_id", "id=AKIAIOSFODNN7EXAMPL ok", false},
		{"google hit", "google_api_key", "key=AIza" + strings.Repeat("a", 35), true},
		{"github hit", "github_token", "token ghp_0123456789abcdefABCDEF0123456789abcd done", true},
		{"github pat hit", "github_pat", "github_pat_" + strings.Repeat("a", 82), true},
		{"slack hit", "slack_token", "slack=xoxb-1234567890-abcdefghij", true},
		{"stripe live hit", "stripe_secret_key", "key sk_live_0123456789abcdefABCDEF here", true},
		{"stripe test miss", "stripe_secret_key", "key sk_test_0123456789abcdefABCDEF here", false},
		{"jwt hit", "jwt", "auth eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92 x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := secretMatch(t, tc.pattern, tc.content); got != tc.want {
				t.Errorf("%s: match=%v, want %v", tc.pattern, got, tc.want)
			}
		})
	}
}

func TestRegexEngine_PrivateKeyBlockRequiresBody(t *testing.T) {
	body := strings.Repeat("A", 100)
	pem := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
	if !secretMatch(t, "private_key_block", pem) {
		t.Error("PEM with a real body should match")
	}
	if secretMatch(t, "private_key_block", "-----BEGIN PRIVATE KEY----------END PRIVATE KEY-----") {
		t.Error("empty placeholder armor should not match")
	}
}

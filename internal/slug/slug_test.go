package slug_test

import (
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/slug"
)

func TestDerive(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"Acme Corp":      "acme-corp",
		"  Café 99   ":   "caf-99",
		"---":            "",
		"a":              "a",
		"A--B":           "a-b",
		"!!!":            "",
		"Hello World 42": "hello-world-42",
	}
	for input, want := range cases {
		if got := slug.Derive(input); got != want {
			t.Errorf("Derive(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestDerive_MaxLen(t *testing.T) {
	t.Parallel()
	long := ""
	for i := 0; i < 70; i++ {
		long += "a"
	}
	got := slug.Derive(long)
	if len(got) > slug.MaxLen {
		t.Errorf("len = %d, want <= %d", len(got), slug.MaxLen)
	}
}

func TestIsValid(t *testing.T) {
	t.Parallel()
	valid := []string{"a", "abc", "a-b", "a1-b2"}
	for _, s := range valid {
		if !slug.IsValid(s) {
			t.Errorf("IsValid(%q) = false, want true", s)
		}
	}
	invalid := []string{"", "-abc", "abc-", "a--b", "ABC", "a b"}
	for _, s := range invalid {
		if slug.IsValid(s) {
			t.Errorf("IsValid(%q) = true, want false", s)
		}
	}
}

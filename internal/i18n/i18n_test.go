package i18n

import (
	"testing"

	"golang.org/x/text/language"
)

func mustBundle(t *testing.T) *Bundle {
	t.Helper()
	b, err := Default()
	if err != nil {
		t.Fatalf("load default bundle: %v", err)
	}
	return b
}

func TestEveryLocaleHasEveryEnglishKey(t *testing.T) {
	t.Parallel()
	b := mustBundle(t)
	enKeys := b.messages[FallbackLocale]
	if len(enKeys) == 0 {
		t.Fatal("english catalog is empty")
	}
	for _, tag := range supported {
		if tag == FallbackLocale {
			continue
		}
		cat := b.messages[tag]
		for id := range enKeys {
			if msg, ok := cat[id]; !ok || msg == "" {
				t.Errorf("locale %s missing key %q", localeFileName[tag], id)
			}
		}
	}
}

func TestMatchNegotiation(t *testing.T) {
	t.Parallel()
	b := mustBundle(t)
	cases := []struct {
		header string
		want   language.Tag
	}{
		{"", FallbackLocale},
		{"   ", FallbackLocale},
		{"not-a-language", FallbackLocale},
		{"de", language.German},
		{"de-DE,de;q=0.9", language.German},
		{"fr-FR", language.French},
		{"ja", language.Japanese},
		{"ko-KR", language.Korean},
		{"ar", language.Arabic},
		{"th", language.Thai},
		{"vi", language.Vietnamese},
		{"ms-MY", language.Malay},
		{"id-ID", language.Indonesian},
		{"zh-Hans", language.SimplifiedChinese},
		{"zh-CN", language.SimplifiedChinese},
		{"zh-Hant", language.TraditionalChinese},
		{"zh-TW", language.TraditionalChinese},
	}
	for _, tc := range cases {
		got := b.Match(tc.header).Tag()
		if got != tc.want {
			t.Errorf("Match(%q).Tag() = %v, want %v", tc.header, got, tc.want)
		}
	}
}

func TestMessageFallsBackToEnglish(t *testing.T) {
	t.Parallel()
	b := mustBundle(t)
	// A locale with no translation for an unknown key falls back to
	// the key id (defined in neither catalog).
	if got := b.Match("de").Message("nonexistent.key"); got != "nonexistent.key" {
		t.Errorf("unknown key = %q, want echo of id", got)
	}
	// A known key resolves to the German translation, not English.
	en := b.Match("en").Message("error.not_found")
	de := b.Match("de").Message("error.not_found")
	if de == "" || de == en {
		t.Errorf("german error.not_found = %q (en = %q), expected a distinct translation", de, en)
	}
}

func TestMessagefFormats(t *testing.T) {
	t.Parallel()
	b := mustBundle(t)
	got := b.Match("en").Messagef("report.summary", 3, 7)
	if got != "3 of 7 controls satisfied" {
		t.Errorf("Messagef = %q", got)
	}
	// Non-English locales keep the same %d verbs so formatting works
	// identically; just assert it does not panic and substitutes.
	for _, loc := range SupportedLocales() {
		out := b.Match(loc).Messagef("report.summary", 3, 7)
		if out == "" || out == "report.summary" {
			t.Errorf("locale %s report.summary did not format: %q", loc, out)
		}
	}
}

func TestRTL(t *testing.T) {
	t.Parallel()
	b := mustBundle(t)
	if !b.Match("ar").IsRTL() {
		t.Error("arabic should be RTL")
	}
	if b.Match("en").IsRTL() {
		t.Error("english should not be RTL")
	}
}

func TestSupportedLocalesOrder(t *testing.T) {
	t.Parallel()
	locales := SupportedLocales()
	if len(locales) != 12 {
		t.Fatalf("expected 12 locales, got %d: %v", len(locales), locales)
	}
	if locales[0] != "en" {
		t.Errorf("first locale = %q, want en (fallback first)", locales[0])
	}
}

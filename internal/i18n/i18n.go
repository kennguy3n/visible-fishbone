// Package i18n is the control-plane internationalization framework.
//
// It loads a per-locale message catalog from embedded JSON files
// (one file per locale, keyed by a stable message ID) and negotiates
// the response locale from a request's Accept-Language header using
// the golang.org/x/text language matcher. Lookups always fall back to
// English: a message missing from a non-English catalog (or a request
// for an unsupported language) resolves against `en`, and a message
// missing from `en` too resolves to its own ID so a caller never
// receives an empty string.
//
// Catalogs are embedded (go:embed) so the binary is self-contained —
// there is no runtime dependency on a locales directory on disk. The
// default Bundle is built once at package init from those embedded
// files; handlers obtain a request-scoped Localizer via Match.
//
// Priority locales (the set the admin UI mirrors): en, zh-Hans,
// zh-Hant, ms, id, th, vi, ja, ko, ar, de, fr. English is the
// canonical source catalog and the fallback for every other locale.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"golang.org/x/text/language"
)

//go:embed locales/*.json
var localeFS embed.FS

// FallbackLocale is the language every lookup falls back to and the
// canonical source catalog. It is always the first tag offered to the
// matcher, so an unparseable or unsupported Accept-Language resolves
// here.
var FallbackLocale = language.English

// supported is the ordered set of locales the framework ships. The
// first entry MUST be FallbackLocale: golang.org/x/text's matcher
// treats the first supported tag as the default it returns when no
// offered tag is a confident match.
var supported = []language.Tag{
	language.English,            // en  — canonical source + fallback
	language.SimplifiedChinese,  // zh-Hans
	language.TraditionalChinese, // zh-Hant
	language.Malay,              // ms
	language.Indonesian,         // id
	language.Thai,               // th
	language.Vietnamese,         // vi
	language.Japanese,           // ja
	language.Korean,             // ko
	language.Arabic,             // ar
	language.German,             // de
	language.French,             // fr
}

// localeFileName maps a supported tag to its catalog file stem. Kept
// explicit (rather than derived from Tag.String()) so the on-disk
// names stay stable and human-readable regardless of how x/text
// canonicalises a tag.
var localeFileName = map[language.Tag]string{
	language.English:            "en",
	language.SimplifiedChinese:  "zh-Hans",
	language.TraditionalChinese: "zh-Hant",
	language.Malay:              "ms",
	language.Indonesian:         "id",
	language.Thai:               "th",
	language.Vietnamese:         "vi",
	language.Japanese:           "ja",
	language.Korean:             "ko",
	language.Arabic:             "ar",
	language.German:             "de",
	language.French:             "fr",
}

// rtlBase is the set of right-to-left base languages. The admin UI
// reads this (via the negotiated locale) to set dir="rtl"; it is
// exposed here so the control plane and UI share one source of truth.
var rtlBase = map[language.Tag]bool{
	language.Arabic: true,
}

// Bundle holds every loaded catalog plus the matcher used to
// negotiate a request locale. It is safe for concurrent use after
// construction (all fields are read-only thereafter).
type Bundle struct {
	messages map[language.Tag]map[string]string
	matcher  language.Matcher
}

var (
	defaultBundle *Bundle
	defaultOnce   sync.Once
	defaultErr    error
)

// Default returns the process-wide Bundle built from the embedded
// locale files. The first call loads and validates every catalog;
// subsequent calls return the cached Bundle. An error is returned
// only when an embedded catalog is malformed, which is a build-time
// (not runtime) defect surfaced loudly at startup.
func Default() (*Bundle, error) {
	defaultOnce.Do(func() {
		defaultBundle, defaultErr = NewBundleFromFS(localeFS, "locales")
	})
	return defaultBundle, defaultErr
}

// MustDefault returns the default Bundle or panics if the embedded
// catalogs are malformed. Intended for package-level initialisation
// in main()/wiring where a broken catalog must fail fast.
func MustDefault() *Bundle {
	b, err := Default()
	if err != nil {
		panic(fmt.Sprintf("i18n: load embedded catalogs: %v", err))
	}
	return b
}

// NewBundleFromFS loads every `<dir>/<locale>.json` catalog for the
// supported locales from fsys. The English catalog is mandatory (it
// is the fallback); a missing non-English catalog is tolerated as an
// empty catalog so the framework degrades to English for that locale
// rather than failing to start.
func NewBundleFromFS(fsys fs.FS, dir string) (*Bundle, error) {
	messages := make(map[language.Tag]map[string]string, len(supported))
	for _, tag := range supported {
		name := localeFileName[tag]
		data, err := fs.ReadFile(fsys, path.Join(dir, name+".json"))
		if err != nil {
			if tag == FallbackLocale {
				return nil, fmt.Errorf("i18n: read fallback catalog %q: %w", name, err)
			}
			messages[tag] = map[string]string{}
			continue
		}
		cat := map[string]string{}
		if err := json.Unmarshal(data, &cat); err != nil {
			return nil, fmt.Errorf("i18n: parse catalog %q: %w", name, err)
		}
		messages[tag] = cat
	}
	if len(messages[FallbackLocale]) == 0 {
		return nil, fmt.Errorf("i18n: fallback catalog %q is empty", localeFileName[FallbackLocale])
	}
	return &Bundle{
		messages: messages,
		matcher:  language.NewMatcher(supported),
	}, nil
}

// Match negotiates the best supported locale for an Accept-Language
// header value and returns a request-scoped Localizer. An empty or
// unparseable header resolves to the fallback locale. The returned
// Localizer never nil.
func (b *Bundle) Match(acceptLanguage string) *Localizer {
	tag := b.matchTag(acceptLanguage)
	return &Localizer{bundle: b, tag: tag}
}

// matchTag resolves an Accept-Language header to one of the supported
// tags, always returning a usable tag (the fallback when negotiation
// is inconclusive).
func (b *Bundle) matchTag(acceptLanguage string) language.Tag {
	acceptLanguage = strings.TrimSpace(acceptLanguage)
	if acceptLanguage == "" {
		return FallbackLocale
	}
	desired, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(desired) == 0 {
		return FallbackLocale
	}
	_, idx, conf := b.matcher.Match(desired...)
	if conf == language.No {
		return FallbackLocale
	}
	// matcher.Match returns the index into the supported slice it was
	// built from, which is the authoritative tag to key catalogs by.
	if idx < 0 || idx >= len(supported) {
		return FallbackLocale
	}
	return supported[idx]
}

// SupportedLocales returns the BCP-47 string identifiers of every
// locale the framework supports, in priority order (English first).
// The admin UI consumes this to build its language switcher from the
// same source the API negotiates against.
func SupportedLocales() []string {
	out := make([]string, len(supported))
	for i, tag := range supported {
		out[i] = localeFileName[tag]
	}
	return out
}

// Localizer resolves message IDs for a single negotiated locale.
type Localizer struct {
	bundle *Bundle
	tag    language.Tag
}

// Tag returns the negotiated locale tag.
func (l *Localizer) Tag() language.Tag { return l.tag }

// Locale returns the BCP-47 string identifier of the negotiated
// locale (e.g. "en", "zh-Hans", "ar").
func (l *Localizer) Locale() string {
	if name, ok := localeFileName[l.tag]; ok {
		return name
	}
	return l.tag.String()
}

// IsRTL reports whether the negotiated locale is written
// right-to-left (currently Arabic).
func (l *Localizer) IsRTL() bool { return rtlBase[l.tag] }

// Message resolves id for the negotiated locale, falling back to
// English and finally to the id itself when no catalog defines it.
func (l *Localizer) Message(id string) string {
	if l.bundle == nil {
		return id
	}
	if cat, ok := l.bundle.messages[l.tag]; ok {
		if msg, ok := cat[id]; ok && msg != "" {
			return msg
		}
	}
	if l.tag != FallbackLocale {
		if cat, ok := l.bundle.messages[FallbackLocale]; ok {
			if msg, ok := cat[id]; ok && msg != "" {
				return msg
			}
		}
	}
	return id
}

// Messagef resolves id and formats it with fmt.Sprintf. Catalog
// templates use standard Go verbs (%s, %d, …); the verbs are
// identical across every locale so a translator only reorders the
// surrounding text, never the verbs.
func (l *Localizer) Messagef(id string, args ...any) string {
	tmpl := l.Message(id)
	if len(args) == 0 {
		return tmpl
	}
	return fmt.Sprintf(tmpl, args...)
}

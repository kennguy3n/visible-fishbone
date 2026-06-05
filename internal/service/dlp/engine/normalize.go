package engine

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// normalizeNFC canonicalises text to Unicode Normalization Form C
// before the regex / keyword detectors run, so Arabic diacritics and
// CJK full-/half-width variants compare equal to the shipped
// patterns. ASCII is unchanged by NFC, so existing ASCII offset and
// snippet semantics are preserved. The Rust endpoint applies the
// identical normalization in `crates/sng-dlp/src/classifier.rs`.
func normalizeNFC(s string) string {
	return norm.NFC.String(s)
}

// isCJK reports whether r is a CJK Unified Ideograph
// (U+4E00..=U+9FFF). Mirrors `is_cjk` in the Rust classifier.
func isCJK(r rune) bool {
	return r >= 0x4E00 && r <= 0x9FFF
}

// isThai reports whether r is in the Thai block (U+0E00..=U+0E7F).
// Mirrors `is_thai` in the Rust classifier.
func isThai(r rune) bool {
	return r >= 0x0E00 && r <= 0x0E7F
}

// simhashTokens tokenizes text for SimHash with the same script-aware
// rule as the Rust side (see fingerprint.go / classifier.rs):
//
//   - CJK present                -> overlapping character bigrams
//   - Thai present (and no CJK)  -> overlapping character trigrams
//   - otherwise                  -> whitespace-delimited tokens
//
// The two implementations must agree byte-for-byte so a fingerprint
// registered on the control plane matches on the endpoint.
func simhashTokens(text string) []string {
	hasCJK := strings.IndexFunc(text, isCJK) >= 0
	hasThai := !hasCJK && strings.IndexFunc(text, isThai) >= 0

	if hasCJK {
		return charShingles(text, 2)
	}
	if hasThai {
		return charShingles(text, 3)
	}
	return strings.Fields(text)
}

// charShingles returns the overlapping character n-grams over the
// non-whitespace runes of text. If fewer than n runes remain the
// whole sequence is emitted as a single token. Mirrors
// `char_shingles` in the Rust classifier.
func charShingles(text string, n int) []string {
	var runes []rune
	for _, r := range text {
		if !unicode.IsSpace(r) {
			runes = append(runes, r)
		}
	}
	if len(runes) == 0 {
		return nil
	}
	if len(runes) < n {
		return []string{string(runes)}
	}
	out := make([]string, 0, len(runes)-n+1)
	for i := 0; i+n <= len(runes); i++ {
		out = append(out, string(runes[i:i+n]))
	}
	return out
}

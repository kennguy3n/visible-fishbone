// Package dlpidm is the control-plane service for WP4 DLP OCR/IDM
// state: managing per-tenant protected-document fingerprint sets for
// Indexed Document Matching (IDM) and the per-tenant OCR/IDM
// configuration.
//
// The fingerprinting in this file is a faithful Go port of the Rust
// data-plane algorithm in crates/sng-dlp/src/idm. The two
// implementations MUST produce byte-identical fingerprint sets for the
// same input and parameters so that a protected document registered
// via the control plane matches what the edge computes for inspected
// content. That parity is locked by a cross-language golden-vector
// test (fingerprint_test.go here and idm/tests.rs on the Rust side).
//
// Only fingerprints (64-bit SHA-256-derived shingle hashes) are ever
// returned and persisted; the raw protected document is fingerprinted
// once and discarded.
package dlpidm

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fingerprinting defaults. These mirror crates/sng-dlp::idm DEFAULT_*
// and the classifier scan cap exactly; tenants never tune them.
const (
	// DefaultShingleSize is the number of tokens per shingle (k).
	DefaultShingleSize = 5
	// DefaultWindowSize is the winnowing window over shingle hashes.
	DefaultWindowSize = 8
	// DefaultMaxFingerprints caps fingerprints per document
	// (2048 * 8 bytes = 16 KiB).
	DefaultMaxFingerprints = 2048
	// DefaultSimilarityThreshold is the containment threshold for
	// reporting a match (mirrors FINGERPRINT_SIMILARITY_THRESHOLD).
	DefaultSimilarityThreshold = 0.8
	// DefaultMaxScanBytes bounds content before shingling (1 MiB),
	// matching the classifier's scan cap.
	DefaultMaxScanBytes = 1 << 20
)

// FingerprintParams controls fingerprint generation. It mirrors the
// Rust FingerprintParams; the defaults are the no-ops values.
type FingerprintParams struct {
	// ShingleSize is the number of tokens per shingle (k), clamped to
	// at least 1.
	ShingleSize int
	// Window is the winnowing window width over shingle hashes,
	// clamped to at least 1.
	Window int
	// MaxFingerprints caps the fingerprints kept per document,
	// clamped to at least 1.
	MaxFingerprints int
	// MaxScanBytes is the byte cap applied to content before
	// shingling, clamped to at least 1.
	MaxScanBytes int
}

// DefaultFingerprintParams returns the no-ops default parameters.
func DefaultFingerprintParams() FingerprintParams {
	return FingerprintParams{
		ShingleSize:     DefaultShingleSize,
		Window:          DefaultWindowSize,
		MaxFingerprints: DefaultMaxFingerprints,
		MaxScanBytes:    DefaultMaxScanBytes,
	}
}

// sanitized clamps every field into its valid range so a misconfigured
// bundle can never produce a panic (zero window/shingle) or an
// unbounded run. Mirrors FingerprintParams::sanitized in Rust.
func (p FingerprintParams) sanitized() FingerprintParams {
	if p.ShingleSize < 1 {
		p.ShingleSize = 1
	}
	if p.Window < 1 {
		p.Window = 1
	}
	if p.MaxFingerprints < 1 {
		p.MaxFingerprints = 1
	}
	if p.MaxScanBytes < 1 {
		p.MaxScanBytes = 1
	}
	return p
}

// FingerprintDocument computes the canonical fingerprint set of a
// protected document: sorted ascending, de-duplicated, and capped to
// params.MaxFingerprints. It is byte-for-byte reproducible against the
// Rust edge's fingerprint_document.
func FingerprintDocument(text string, params FingerprintParams) []uint64 {
	params = params.sanitized()
	scanned := truncateOnCharBoundary(text, params.MaxScanBytes)
	tokens := tokenize(scanned)
	hashes := shingleHashes(tokens, params.ShingleSize)
	winnowed := winnow(hashes, params.Window)
	return finalize(winnowed, params.MaxFingerprints)
}

// truncateOnCharBoundary truncates text to at most maxBytes without
// splitting a UTF-8 character. Mirrors Rust truncate_on_char_boundary.
func truncateOnCharBoundary(text string, maxBytes int) string {
	if len(text) <= maxBytes {
		return text
	}
	end := maxBytes
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

// hashShingle hashes one shingle to a 64-bit code: SHA-256, leading 8
// bytes, big-endian. Identical primitive to the Rust hash_shingle and
// classifier simhash per-token hash.
func hashShingle(shingle string) uint64 {
	digest := sha256.Sum256([]byte(shingle))
	return binary.BigEndian.Uint64(digest[:8])
}

// shingleHashes produces overlapping k-token shingles hashed to 64-bit
// codes. Tokens join with a single space. Fewer than k tokens collapse
// to a single whole-sequence shingle. Mirrors Rust shingle_hashes.
func shingleHashes(tokens []string, k int) []uint64 {
	if len(tokens) == 0 {
		return nil
	}
	if len(tokens) < k {
		return []uint64{hashShingle(strings.Join(tokens, " "))}
	}
	hashes := make([]uint64, 0, len(tokens)-k+1)
	for i := 0; i+k <= len(tokens); i++ {
		hashes = append(hashes, hashShingle(strings.Join(tokens[i:i+k], " ")))
	}
	return hashes
}

// winnow performs winnowing over shingle hashes (Schleimer et al.). In
// each window of `window` consecutive hashes the minimum is selected;
// on ties the rightmost position wins; a fingerprint is recorded only
// when the selected position changes from the previous window. Mirrors
// Rust winnow exactly, including the `<=` tie-break.
func winnow(hashes []uint64, window int) []uint64 {
	if len(hashes) == 0 {
		return nil
	}
	w := window
	if w < 1 {
		w = 1
	}
	if w > len(hashes) {
		w = len(hashes)
	}
	lastStart := len(hashes) - w
	var selected []uint64
	prevPos := -1
	for start := 0; start <= lastStart; start++ {
		minPos := start
		for pos := start; pos < start+w; pos++ {
			// `<=` makes the rightmost minimum win on ties, matching
			// the Rust edge exactly.
			if hashes[pos] <= hashes[minPos] {
				minPos = pos
			}
		}
		if prevPos != minPos {
			selected = append(selected, hashes[minPos])
			prevPos = minPos
		}
	}
	return selected
}

// finalize sorts ascending, de-duplicates, and keeps at most maxCount
// fingerprints (the numerically smallest — a stable bottom-k sample).
// Mirrors Rust finalize.
func finalize(fingerprints []uint64, maxCount int) []uint64 {
	sort.Slice(fingerprints, func(i, j int) bool { return fingerprints[i] < fingerprints[j] })
	fingerprints = dedupSorted(fingerprints)
	if len(fingerprints) > maxCount {
		fingerprints = fingerprints[:maxCount]
	}
	return fingerprints
}

// dedupSorted removes adjacent duplicates from a sorted slice in place.
func dedupSorted(values []uint64) []uint64 {
	if len(values) < 2 {
		return values
	}
	out := values[:1]
	for _, v := range values[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

// tokenize splits text with the same script-aware rule the SimHash
// path uses: CJK → character bigrams, Thai → character trigrams,
// otherwise whitespace-delimited tokens. Mirrors Rust tokenize.
func tokenize(text string) []string {
	hasCJK := false
	for _, c := range text {
		if isCJK(c) {
			hasCJK = true
			break
		}
	}
	hasThai := false
	if !hasCJK {
		for _, c := range text {
			if isThai(c) {
				hasThai = true
				break
			}
		}
	}
	if hasCJK {
		return charShingles(text, 2)
	}
	if hasThai {
		return charShingles(text, 3)
	}
	return strings.Fields(text)
}

// charShingles produces overlapping character n-grams over the
// non-whitespace characters of text. Mirrors Rust char_shingles.
func charShingles(text string, n int) []string {
	var chars []rune
	for _, c := range text {
		if !unicode.IsSpace(c) {
			chars = append(chars, c)
		}
	}
	if len(chars) == 0 {
		return nil
	}
	if len(chars) < n {
		return []string{string(chars)}
	}
	out := make([]string, 0, len(chars)-n+1)
	for i := 0; i+n <= len(chars); i++ {
		out = append(out, string(chars[i:i+n]))
	}
	return out
}

// isCJK reports whether c is a CJK Unified Ideograph (U+4E00..=U+9FFF).
func isCJK(c rune) bool {
	return c >= '\u4E00' && c <= '\u9FFF'
}

// isThai reports whether c is in the Thai block (U+0E00..=U+0E7F).
func isThai(c rune) bool {
	return c >= '\u0E00' && c <= '\u0E7F'
}

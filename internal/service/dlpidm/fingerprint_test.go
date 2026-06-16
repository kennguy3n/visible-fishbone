package dlpidm

import (
	"reflect"
	"testing"
)

// goldenVectorText and goldenVectorFingerprints lock cross-language
// parity with the Rust edge. The identical assertion exists in
// crates/sng-dlp/src/idm/tests.rs. If either side changes the
// tokenize / shingle / hash / winnow / finalize pipeline this test
// (and its Rust twin) must fail.
const goldenVectorText = "the quick brown fox jumps over the lazy dog"

var goldenVectorFingerprints = []uint64{
	9093497140874896414,
	9727984356536241109,
	11621772664254813023,
}

func TestFingerprintDocumentGoldenVectorParity(t *testing.T) {
	params := FingerprintParams{
		ShingleSize:     3,
		Window:          4,
		MaxFingerprints: 8,
		MaxScanBytes:    DefaultMaxScanBytes,
	}
	got := FingerprintDocument(goldenVectorText, params)
	if !reflect.DeepEqual(got, goldenVectorFingerprints) {
		t.Fatalf("golden vector mismatch:\n got = %v\nwant = %v", got, goldenVectorFingerprints)
	}
}

func TestFingerprintDocumentIsSortedDedupedAndCapped(t *testing.T) {
	text := "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu nu xi omicron pi"
	params := FingerprintParams{ShingleSize: 2, Window: 2, MaxFingerprints: 4, MaxScanBytes: DefaultMaxScanBytes}
	got := FingerprintDocument(text, params)
	if len(got) > params.MaxFingerprints {
		t.Fatalf("expected at most %d fingerprints, got %d", params.MaxFingerprints, len(got))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Fatalf("fingerprints not strictly ascending at %d: %v", i, got)
		}
	}
}

func TestFingerprintDocumentDeterministic(t *testing.T) {
	params := DefaultFingerprintParams()
	a := FingerprintDocument(goldenVectorText, params)
	b := FingerprintDocument(goldenVectorText, params)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("fingerprinting not deterministic: %v vs %v", a, b)
	}
}

func TestFingerprintDocumentEmptyAndWhitespace(t *testing.T) {
	params := DefaultFingerprintParams()
	if got := FingerprintDocument("", params); len(got) != 0 {
		t.Fatalf("expected no fingerprints for empty input, got %v", got)
	}
	if got := FingerprintDocument("   \t\n  ", params); len(got) != 0 {
		t.Fatalf("expected no fingerprints for whitespace input, got %v", got)
	}
}

func TestFingerprintParamsSanitizedClampsToOne(t *testing.T) {
	p := FingerprintParams{ShingleSize: 0, Window: 0, MaxFingerprints: 0, MaxScanBytes: 0}.sanitized()
	if p.ShingleSize != 1 || p.Window != 1 || p.MaxFingerprints != 1 || p.MaxScanBytes != 1 {
		t.Fatalf("sanitized did not clamp to 1: %+v", p)
	}
}

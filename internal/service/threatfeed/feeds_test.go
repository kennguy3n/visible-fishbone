package threatfeed

import (
	"testing"
	"time"
)

func TestDefaultFeeds(t *testing.T) {
	t.Parallel()
	feeds := DefaultFeeds(nil, 0)
	if len(feeds) != len(builtinFeedSpecs) {
		t.Fatalf("got %d feeds, want %d", len(feeds), len(builtinFeedSpecs))
	}
	seen := map[string]bool{}
	for _, f := range feeds {
		if f.Name == "" || f.Parser == nil || f.Fetcher == nil {
			t.Fatalf("feed not fully wired: %+v", f)
		}
		if f.Weight <= 0 || f.Weight > 1 {
			t.Fatalf("feed %s weight out of (0,1]: %v", f.Name, f.Weight)
		}
		if seen[f.Name] {
			t.Fatalf("duplicate feed name %q", f.Name)
		}
		seen[f.Name] = true
		hf, ok := f.Fetcher.(*HTTPFetcher)
		if !ok || hf.URL != f.URL {
			t.Fatalf("feed %s fetcher not wired to URL: %+v", f.Name, f.Fetcher)
		}
	}
	// Corroboration is designed in: two distinct URL feeds overlap.
	if !seen["abuse.ch:urlhaus"] || !seen["openphish"] {
		t.Fatal("expected overlapping URL feeds for corroboration")
	}
}

func TestSourcesFromFeeds(t *testing.T) {
	t.Parallel()
	feeds := []Feed{
		{Name: "f1", DisplayName: "F1", Kind: "ip", URL: "http://x", Weight: 0.9, DefaultTTL: 48 * time.Hour},
		{Name: "f2", DisplayName: "F2", Kind: "weird", URL: "", Weight: 0.5},
	}
	rows := SourcesFromFeeds(feeds)
	if len(rows) != 2 {
		t.Fatalf("got %d rows", len(rows))
	}
	if rows[0].Kind != "ip" || rows[0].DefaultTTLSeconds != int64(48*time.Hour/time.Second) {
		t.Fatalf("row0 = %+v", rows[0])
	}
	if !rows[0].Enabled {
		t.Fatal("seeded sources should be enabled")
	}
	// Unknown kind normalized to "mixed" so the CHECK constraint holds.
	if rows[1].Kind != "mixed" {
		t.Fatalf("unknown kind = %q, want mixed", rows[1].Kind)
	}
}

func TestWeightMap(t *testing.T) {
	t.Parallel()
	feeds := []Feed{{Name: "a", Weight: 0.9}, {Name: "b", Weight: 0.7}}
	m := weightMap(feeds)
	if m["a"] != 0.9 || m["b"] != 0.7 {
		t.Fatalf("weightMap = %v", m)
	}
}

func TestNormalizeKind(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"domain", "ip", "url", "hash", "mixed"} {
		if normalizeKind(k) != k {
			t.Fatalf("normalizeKind(%q) changed a valid kind", k)
		}
	}
	for _, k := range []string{"", "bogus", "IP"} {
		if normalizeKind(k) != "mixed" {
			t.Fatalf("normalizeKind(%q) = %q, want mixed", k, normalizeKind(k))
		}
	}
}

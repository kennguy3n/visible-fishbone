package threatintel

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Evil.Example.com", "evil.example.com"},
		{"trailing dot", "evil.example.", "evil.example"},
		{"wildcard prefix", "*.ads.example", "ads.example"},
		{"surrounding space", "  evil.example  ", "evil.example"},
		{"single label rejected", "localhost", ""},
		{"empty rejected", "", ""},
		{"url rejected", "http://evil.example/path", ""},
		{"has path rejected", "evil.example/x", ""},
		{"has port rejected", "evil.example:8080", ""},
		{"has at rejected", "user@evil.example", ""},
		{"ipv4 rejected", "1.2.3.4", ""},
		{"numeric tld rejected", "foo.123", ""},
		{"underscore label allowed", "_dmarc.example.com", "_dmarc.example.com"},
		{"leading digit label", "3vil.example.com", "3vil.example.com"},
		{"unicode rejected", "evíl.example", ""},
		{"overlong label rejected", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeDomain(tc.in); got != tc.want {
				t.Fatalf("normalizeDomain(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseDomainList(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"# comment line",
		"; another comment",
		"",
		"   ",
		"evil.example",
		"0.0.0.0 ads.example       # inline comment",
		"127.0.0.1\ttracker.example",
		"*.gambling.example",
		"GoodCaps.Example",
		"http://skip.example/x",
		"localhost",
		"1.2.3.4",
		"dup.example",
		"dup.example",
	}, "\n"))

	got := parseDomainList(raw)
	want := []string{
		"evil.example",
		"ads.example",
		"tracker.example",
		"gambling.example",
		"goodcaps.example",
		// localhost / url / ipv4 dropped
		"dup.example",
		"dup.example", // dedup is deferred to bundle assembly
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDomainList mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestParseDomainListEmpty(t *testing.T) {
	if got := parseDomainList([]byte("# only comments\n\n   \n")); len(got) != 0 {
		t.Fatalf("expected no domains, got %v", got)
	}
}

// TestParseDomainListMultiField covers lines carrying more than one
// token: multi-alias hosts-file rows and "domain + trailing metadata"
// rows must keep every genuine domain rather than only the last field.
func TestParseDomainListMultiField(t *testing.T) {
	raw := []byte(strings.Join([]string{
		"0.0.0.0 primary.example alias.example",   // multi-alias hosts row
		"evil.example 1700000000",                 // domain + trailing counter
		"127.0.0.1 a.example b.example c.example", // three aliases
	}, "\n"))
	got := parseDomainList(raw)
	want := []string{
		"primary.example", "alias.example",
		"evil.example",
		"a.example", "b.example", "c.example",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("multi-field parse mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestSnapshotFetcher(t *testing.T) {
	f := SnapshotFetcher{Provider: func() []string {
		return []string{"evil.example", "bad.example"}
	}}
	raw, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	// The bytes must flow through parseDomainList exactly like an
	// upstream feed body would, so the same canonicalization applies.
	got := parseDomainList(raw)
	want := []string{"evil.example", "bad.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot parse mismatch:\n got=%v\nwant=%v", got, want)
	}
}

func TestSnapshotFetcherEmptyProvider(t *testing.T) {
	f := SnapshotFetcher{Provider: func() []string { return nil }}
	raw, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(parseDomainList(raw)) != 0 {
		t.Fatalf("expected no domains from empty provider, got %q", raw)
	}
}

func TestSnapshotFetcherNilProvider(t *testing.T) {
	var f SnapshotFetcher // nil Provider
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("expected error from nil provider")
	}
}

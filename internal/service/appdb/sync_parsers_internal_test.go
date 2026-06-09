package appdb

import (
	"net/netip"
	"testing"
)

func hasPrefix(ranges []netip.Prefix, want string) bool {
	wp := netip.MustParsePrefix(want)
	for _, p := range ranges {
		if p == wp {
			return true
		}
	}
	return false
}

func TestParsePlaintextCIDRList(t *testing.T) {
	// Shape Zoom / Cloudflare publish: one CIDR per line, with the odd
	// comment, blank line, bare address, and trailing junk token.
	body := []byte("# Zoom egress ranges\n3.7.35.0/25\n\n  15.220.80.0/24  \n;note\n203.0.113.7\nnot-an-ip\n2001:db8::/32\n")
	domains, ranges, err := parsePlaintextCIDRList(body, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 0 {
		t.Fatalf("plaintext feed should not yield domains, got %v", domains)
	}
	for _, want := range []string{"3.7.35.0/25", "15.220.80.0/24", "203.0.113.7/32", "2001:db8::/32"} {
		if !hasPrefix(ranges, want) {
			t.Errorf("missing expected prefix %s in %v", want, ranges)
		}
	}
	if len(ranges) != 4 {
		t.Fatalf("expected 4 prefixes (junk/comments skipped), got %d: %v", len(ranges), ranges)
	}
}

func TestParseGitHubMeta(t *testing.T) {
	body := []byte(`{
		"verifiable_password_authentication": false,
		"ssh_key_fingerprints": {"SHA256_ED25519": "abc"},
		"ssh_keys": ["ssh-ed25519 AAAA"],
		"hooks": ["192.30.252.0/22"],
		"web": ["140.82.112.0/20", "2a0a:a440::/29"],
		"api": ["bogus/notcidr"],
		"domains": {"website": ["github.com", "*.github.io"], "codeload": ["codeload.github.com"]}
	}`)
	domains, ranges, err := parseGitHubMeta(body, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"192.30.252.0/22", "140.82.112.0/20", "2a0a:a440::/29"} {
		if !hasPrefix(ranges, want) {
			t.Errorf("missing expected prefix %s in %v", want, ranges)
		}
	}
	if hasPrefix(ranges, "192.30.252.0/22") && len(ranges) != 3 {
		t.Errorf("expected exactly 3 valid prefixes (non-CIDR + ssh_keys skipped), got %d: %v", len(ranges), ranges)
	}
	got := map[string]bool{}
	for _, d := range domains {
		got[d] = true
	}
	for _, want := range []string{"github.com", "*.github.io", "codeload.github.com"} {
		if !got[want] {
			t.Errorf("missing expected domain %q in %v", want, domains)
		}
	}
}

func TestParseFastlyIPList(t *testing.T) {
	body := []byte(`{"addresses":["23.235.32.0/20","104.156.80.0/20"],"ipv6_addresses":["2a04:4e40::/32"]}`)
	_, ranges, err := parseFastlyIPList(body, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"23.235.32.0/20", "104.156.80.0/20", "2a04:4e40::/32"} {
		if !hasPrefix(ranges, want) {
			t.Errorf("missing expected prefix %s in %v", want, ranges)
		}
	}
}

// TestNewSyncerRegistersFeedParsers pins that the bespoke feeds are
// dispatched to their parser rather than silently falling back to the
// generic JSON parser (which would no-op or error on these shapes).
func TestNewSyncerRegistersFeedParsers(t *testing.T) {
	s := NewSyncer(&Service{}, nil)
	cases := map[string]string{
		"https://assets.zoom.us/docs/ipranges/Zoom.txt": "assets.zoom.us",
		"https://www.cloudflare.com/ips-v4":             "www.cloudflare.com",
		"https://api.github.com/meta":                   "api.github.com",
		"https://api.fastly.com/public-ip-list":         "api.fastly.com",
	}
	for url, host := range cases {
		if got := hostFromURL(url); got != host {
			t.Errorf("hostFromURL(%q) = %q, want %q", url, got, host)
		}
		if _, ok := s.parsers[host]; !ok {
			t.Errorf("no parser registered for host %q (url %q)", host, url)
		}
	}
}

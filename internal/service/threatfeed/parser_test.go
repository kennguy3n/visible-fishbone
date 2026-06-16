package threatfeed

import (
	"sort"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// values projects the normalized Value of each parsed IOC, sorted, so a
// parser's output can be asserted independent of input order.
func values(iocs []ai.IOC) []string {
	out := make([]string, 0, len(iocs))
	for _, ioc := range iocs {
		out = append(out, ioc.Value)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDomainListParser(t *testing.T) {
	t.Parallel()
	raw := []byte(`# comment line
; another comment style
// slash comment
EVIL.example.COM
*.wildcard.example
trailing-dot.example.
  spaced.example  
good.example # inline comment
203.0.113.10
not_a_domain
`)
	p := DomainListParser{Source: "test", Confidence: 0.5}
	if p.Name() != "test" {
		t.Fatalf("Name() = %q", p.Name())
	}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := values(iocs)
	want := []string{
		"evil.example.com",     // lowercased
		"good.example",         // inline comment stripped
		"spaced.example",       // surrounding whitespace trimmed
		"trailing-dot.example", // trailing root dot stripped
		"wildcard.example",     // leading "*." stripped
	}
	// "203.0.113.10" (IP literal) and "not_a_domain" (no dot) are dropped.
	if !equalStrings(got, want) {
		t.Fatalf("domains = %v, want %v", got, want)
	}
	for _, ioc := range iocs {
		if ioc.Type != ai.IOCTypeDomain {
			t.Fatalf("type = %q, want domain", ioc.Type)
		}
		if ioc.Source != "test" || ioc.Confidence != 0.5 {
			t.Fatalf("meta not applied: %+v", ioc)
		}
	}
}

func TestDomainListParser_HostsFile(t *testing.T) {
	t.Parallel()
	raw := []byte(`# hosts-file format from URLhaus
0.0.0.0 malware-one.example
127.0.0.1	malware-two.example
0.0.0.0 malware-three.example # tagged
bare-host.example
::1 ipv6-host.example
`)
	p := DomainListParser{Source: "hostfile", HostsFile: true}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := values(iocs)
	want := []string{
		"bare-host.example",   // single-field row falls back to hostname
		"ipv6-host.example",   // IPv6 sinkhole address dropped
		"malware-one.example", // 0.0.0.0 address field dropped
		"malware-three.example",
		"malware-two.example", // tab-separated
	}
	if !equalStrings(got, want) {
		t.Fatalf("hosts-file domains = %v, want %v", got, want)
	}
}

func TestIPListParser_IPAndCIDR(t *testing.T) {
	t.Parallel()
	raw := []byte(`# Feodo-style IP blocklist
203.0.113.10
198.51.100.0/24
2001:db8::1
not-an-ip
10.0.0.5  ; inline comment
`)
	p := IPListParser{Source: "ipfeed"}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byType := map[ai.IOCType][]string{}
	for _, ioc := range iocs {
		byType[ioc.Type] = append(byType[ioc.Type], ioc.Value)
	}
	for _, v := range byType {
		sort.Strings(v)
	}
	wantIP := []string{"10.0.0.5", "2001:db8::1", "203.0.113.10"}
	if !equalStrings(byType[ai.IOCTypeIP], wantIP) {
		t.Fatalf("ips = %v, want %v", byType[ai.IOCTypeIP], wantIP)
	}
	wantCIDR := []string{"198.51.100.0/24"}
	if !equalStrings(byType[ai.IOCTypeCIDR], wantCIDR) {
		t.Fatalf("cidrs = %v, want %v", byType[ai.IOCTypeCIDR], wantCIDR)
	}
}

func TestURLListParser(t *testing.T) {
	t.Parallel()
	raw := []byte(`# URLhaus text feed
http://evil.example/path
HTTPS://Phish.Example/Login
ftp://unsupported.example/x
not a url
https://ok.example
`)
	p := URLListParser{Source: "urlfeed"}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := values(iocs)
	want := []string{
		"http://evil.example/path",
		"https://ok.example",
		"https://phish.example/Login", // scheme+host lowercased, path preserved
	}
	if !equalStrings(got, want) {
		t.Fatalf("urls = %v, want %v", got, want)
	}
}

func TestHashListParser_AlgoDetection(t *testing.T) {
	t.Parallel()
	md5 := "d41d8cd98f00b204e9800998ecf8427e"
	sha1 := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	sha256 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	raw := []byte("# MalwareBazaar recent\n\"" + sha256 + "\"\n" + md5 + "\n" + sha1 + "\nnothex_zz\n" + "abc123\n")
	p := HashListParser{Source: "hashfeed"}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	algos := map[string]ai.HashAlgo{}
	for _, ioc := range iocs {
		if ioc.Type != ai.IOCTypeHash {
			t.Fatalf("type = %q, want hash", ioc.Type)
		}
		algos[ioc.Value] = ioc.HashAlgo
	}
	if algos[md5] != ai.HashAlgoMD5 {
		t.Fatalf("md5 algo = %q", algos[md5])
	}
	if algos[sha1] != ai.HashAlgoSHA1 {
		t.Fatalf("sha1 algo = %q", algos[sha1])
	}
	if algos[sha256] != ai.HashAlgoSHA256 {
		t.Fatalf("sha256 algo = %q (quotes should be trimmed)", algos[sha256])
	}
	if len(iocs) != 3 {
		t.Fatalf("hash count = %d, want 3 (non-hex/short rows dropped)", len(iocs))
	}
}

func TestLineTokens_EmptyAndCommentOnly(t *testing.T) {
	t.Parallel()
	raw := []byte("\n   \n# only comments\n;\n//\n")
	if toks := lineTokens(raw, false); len(toks) != 0 {
		t.Fatalf("tokens = %v, want none", toks)
	}
}

func TestLooksLikeIP(t *testing.T) {
	t.Parallel()
	if !looksLikeIP("203.0.113.10") {
		t.Fatal("203.0.113.10 should look like an IP")
	}
	if !looksLikeIP("2001:db8::1") {
		t.Fatal("IPv6 should look like an IP")
	}
	if looksLikeIP("evil.example") {
		t.Fatal("domain should not look like an IP")
	}
}

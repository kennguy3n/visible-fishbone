package threatfeed

import (
	"bufio"
	"bytes"
	"strings"

	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// The parsers below cover the four plaintext shapes the built-in open
// feeds publish (domain lists, IP/CIDR lists, URL lists, hash lists).
// They are intentionally line-oriented and tolerant: blank lines and
// comments are skipped, malformed tokens are dropped (never aborting
// the batch), and every surviving token is normalized through
// ai.NewIOC — so domains are lowercased + trailing-dot/wildcard
// stripped, IPs/CIDRs are canonicalized, URLs are normalized, and hash
// algorithms are detected from length, exactly like the rest of the
// codebase. Each parser implements ai.FeedParser (the same pure,
// network-free contract the ai feed parsers honor), so they are unit
// tested directly against fixture bytes.
//
// Observation timestamps (FirstSeen/LastSeen/ExpiresAt) are left zero
// here; the engine stamps them at ingest time from the fetch instant
// and the feed's configured TTL, keeping the parsers pure and the TTL
// policy in one place.

// commentPrefixes are the line-comment markers the open feeds use.
var commentPrefixes = []string{"#", ";", "//"}

// lineTokens extracts candidate indicator tokens from a plaintext feed
// body. When hostsFile is true the first whitespace field of a
// "0.0.0.0 evil.example" style line is dropped and the hostname is
// returned; otherwise the first field of each line is used. Comment and
// blank lines are skipped. A trailing inline comment (" # ...") is
// trimmed.
func lineTokens(raw []byte, hostsFile bool) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(raw))
	// Allow long lines (some URL feeds carry very long URLs).
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || isComment(line) {
			continue
		}
		// Strip an inline trailing comment.
		for _, p := range commentPrefixes {
			if idx := strings.Index(line, " "+p); idx >= 0 {
				line = strings.TrimSpace(line[:idx])
			}
		}
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		token := fields[0]
		if hostsFile {
			// hosts-file rows are "<ip> <hostname> [aliases...]"; the
			// indicator is the hostname. A bare single-field line falls
			// back to treating that field as the hostname.
			if len(fields) >= 2 && looksLikeIP(fields[0]) {
				token = fields[1]
			}
		}
		out = append(out, token)
	}
	return out
}

func isComment(line string) bool {
	for _, p := range commentPrefixes {
		if strings.HasPrefix(line, p) {
			return true
		}
	}
	return false
}

// looksLikeIP reports whether s parses as a bare IP address, used to
// detect the leading address field of a hosts-file row.
func looksLikeIP(s string) bool {
	_, ok := ai.NewIOC(ai.IOCTypeIP, s, ai.IOCMeta{})
	return ok
}

// parserConfig is the shared configuration for the line parsers.
type parserConfig struct {
	source     string
	confidence float64
}

func (c parserConfig) meta() ai.IOCMeta {
	return ai.IOCMeta{Source: c.source, Confidence: c.confidence}
}

// DomainListParser parses a plaintext domain blocklist (one domain per
// line, or hosts-file format when HostsFile is set).
type DomainListParser struct {
	Source     string
	Confidence float64
	HostsFile  bool
}

func (p DomainListParser) Name() string { return p.Source }

func (p DomainListParser) Parse(raw []byte) ([]ai.IOC, error) {
	cfg := parserConfig{source: p.Source, confidence: p.Confidence}
	var out []ai.IOC
	for _, tok := range lineTokens(raw, p.HostsFile) {
		if ioc, ok := ai.NewIOC(ai.IOCTypeDomain, tok, cfg.meta()); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

// IPListParser parses a plaintext IP / CIDR blocklist. A token bearing
// a prefix length is stored as a CIDR indicator; a bare address as an
// IP indicator — so a feed that mixes hosts and ranges round-trips both
// rather than dropping the ranges.
type IPListParser struct {
	Source     string
	Confidence float64
}

func (p IPListParser) Name() string { return p.Source }

func (p IPListParser) Parse(raw []byte) ([]ai.IOC, error) {
	cfg := parserConfig{source: p.Source, confidence: p.Confidence}
	var out []ai.IOC
	for _, tok := range lineTokens(raw, false) {
		t := ai.IOCTypeIP
		if strings.Contains(tok, "/") {
			t = ai.IOCTypeCIDR
		}
		if ioc, ok := ai.NewIOC(t, tok, cfg.meta()); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

// URLListParser parses a plaintext URL blocklist (one URL per line).
type URLListParser struct {
	Source     string
	Confidence float64
}

func (p URLListParser) Name() string { return p.Source }

func (p URLListParser) Parse(raw []byte) ([]ai.IOC, error) {
	cfg := parserConfig{source: p.Source, confidence: p.Confidence}
	var out []ai.IOC
	for _, tok := range lineTokens(raw, false) {
		if ioc, ok := ai.NewIOC(ai.IOCTypeURL, tok, cfg.meta()); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

// HashListParser parses a plaintext file-hash blocklist (one hex digest
// per line; MD5/SHA-1/SHA-256 distinguished by length).
type HashListParser struct {
	Source     string
	Confidence float64
}

func (p HashListParser) Name() string { return p.Source }

func (p HashListParser) Parse(raw []byte) ([]ai.IOC, error) {
	cfg := parserConfig{source: p.Source, confidence: p.Confidence}
	var out []ai.IOC
	for _, tok := range lineTokens(raw, false) {
		// abuse.ch hash exports sometimes quote the digest.
		tok = strings.Trim(tok, `"`)
		if ioc, ok := ai.NewIOC(ai.IOCTypeHash, tok, cfg.meta()); ok {
			out = append(out, ioc)
		}
	}
	return out, nil
}

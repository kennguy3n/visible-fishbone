// Package threatintel implements the MANAGED threat-intel feed
// pipeline for the DNS subsystem: the leader-gated control-plane loop
// that fetches DNS reputation and category feeds from configured
// upstream URLs on a cadence, normalizes them into the feed format the
// `sng-dns` crate consumes (reputation FQDN list + per-category domain
// membership), and signs + distributes the resulting bundle over NATS
// using the same Ed25519 trust model as the policy / compliance-evidence
// bundles.
//
// Scope boundary: `sng-dns` already CONSUMES reputation / category
// feeds (crates/sng-dns reputation.rs, category.rs) loaded in-memory
// and hot-swapped on reload. What this package adds is the PRODUCER:
// the managed pipeline that keeps those feeds fresh and authenticated
// instead of relying on operator-supplied static lists. The pipeline
// is platform-level (the produced bundle is global, not tenant-scoped)
// — DNS reputation / category data is shared threat intelligence, never
// tenant PII — so nothing here is bound to a tenant.
//
// The whole pipeline is gated behind THREAT_INTEL_ENABLED (default
// false): with the flag off the loop is never registered and no
// network calls are made. With it on but no source URLs configured the
// loop runs but pulls nothing, mirroring the fail-safe "configured
// upstream or no-op" posture of the existing enrichment features.
package threatintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Kind classifies what a source contributes to the produced bundle.
type Kind int

const (
	// KindReputation feeds are exact-match known-bad FQDN lists. They
	// land in the bundle's Reputation set and drive the `sng-dns`
	// reputation filter (exact-match → NXDOMAIN).
	KindReputation Kind = iota
	// KindCategory feeds are domain-membership lists for a single
	// category bucket (ads, gambling, …). They land under the source's
	// Category key in the bundle and drive the `sng-dns` category
	// filter (suffix-match → operator-configured Allow/Log/Block).
	KindCategory
)

// String renders the kind for logs / telemetry.
func (k Kind) String() string {
	switch k {
	case KindReputation:
		return "reputation"
	case KindCategory:
		return "category"
	default:
		return "unknown"
	}
}

// Fetcher retrieves the raw bytes for one upstream feed. The default
// implementation is HTTPFetcher; tests inject StaticFetcher so no test
// touches the network (normalization is validated directly against
// sample payloads, and the service is validated against an in-memory
// fetcher + publisher).
type Fetcher interface {
	Fetch(ctx context.Context) ([]byte, error)
}

// defaultMaxFeedBytes caps a single feed response so a misbehaving or
// hostile upstream cannot exhaust control-plane memory. Category feeds
// can be large (millions of domains) but a single 64 MiB text body is
// already ~2M average-length domains; anything larger is rejected as a
// misconfiguration rather than silently truncated.
const defaultMaxFeedBytes int64 = 64 << 20

// defaultHTTPTimeout bounds a single feed fetch.
const defaultHTTPTimeout = 30 * time.Second

// HTTPFetcher fetches a feed over HTTP(S). Real network calls are gated
// behind explicit configuration: a Source is only wired with an
// HTTPFetcher when an operator supplies its URL, so unit tests never
// instantiate this type.
type HTTPFetcher struct {
	// URL is the feed endpoint.
	URL string
	// Header carries per-feed auth (e.g. a vendor API key) and any
	// other request headers.
	Header http.Header
	// Client defaults to an HTTP client with defaultHTTPTimeout.
	Client *http.Client
	// MaxBytes caps the response body. Zero applies defaultMaxFeedBytes.
	MaxBytes int64
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("threatintel: build request: %w", err)
	}
	for k, vs := range f.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: defaultHTTPTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("threatintel: fetch %s: %w", f.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("threatintel: fetch %s: unexpected status %d", f.URL, resp.StatusCode)
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = defaultMaxFeedBytes
	}
	// Read one byte past the limit so an oversized body is reported as
	// an explicit error rather than silently truncated (a half-ingested
	// feed that drops protections is worse than a skipped refresh, which
	// retries on the next interval and meanwhile keeps last-known-good).
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("threatintel: read body %s: %w", f.URL, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("threatintel: fetch %s: response exceeds %d-byte limit", f.URL, limit)
	}
	return body, nil
}

// StaticFetcher returns fixed bytes. Used by the service tests to drive
// the refresh loop deterministically without a network dependency.
type StaticFetcher struct {
	Data []byte
	Err  error
}

// Fetch implements Fetcher.
func (s StaticFetcher) Fetch(context.Context) ([]byte, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	return s.Data, nil
}

// SnapshotFetcher adapts an in-process domain provider into a feed
// Fetcher so a set of domains already held in memory (e.g. the WS8 IOC
// aggregator's IOCStore) flows into the SAME signed DNS bundle as the
// upstream URL feeds, rather than needing a second distribution path.
//
// The provider is invoked on every refresh and must be safe for
// concurrent use; it returns the current domain set, already filtered
// to the indicators the caller wants enforced (e.g. confidence-gated).
// The returned slice is joined into the newline-delimited shape
// parseDomainList already accepts, so the same canonicalization /
// validity gate applies uniformly to in-process and upstream feeds.
//
// A nil Provider is a configuration error surfaced on the first fetch
// (treated by the refresh loop as a failed source falling back to
// last-known-good) rather than a panic.
type SnapshotFetcher struct {
	// Provider returns the current domain set to fold into the bundle.
	Provider func() []string
}

// Fetch implements Fetcher.
func (s SnapshotFetcher) Fetch(context.Context) ([]byte, error) {
	if s.Provider == nil {
		return nil, errors.New("threatintel: nil snapshot provider")
	}
	return []byte(strings.Join(s.Provider(), "\n")), nil
}

// Source binds a fetcher to the bundle slot it populates. One Source
// corresponds to a single upstream (a reputation list, or a single
// category's domain export).
type Source struct {
	// Name uniquely identifies the source in the pipeline (telemetry,
	// last-known-good cache key). Must be non-empty and unique.
	Name string
	// Kind selects the bundle slot the parsed domains land in.
	Kind Kind
	// Category is the category bucket KindCategory domains are filed
	// under (e.g. "ads"). Ignored for KindReputation. Must be non-empty
	// for KindCategory sources.
	Category string
	// Fetcher retrieves the raw feed bytes.
	Fetcher Fetcher
	// AllowEmpty marks a source whose empty result is a legitimate
	// state rather than a sign of a broken upstream. For URL feeds an
	// empty parse is suspicious (truncated body, wrong endpoint, format
	// change), so fetchSource keeps the last-known-good set; for an
	// in-process SnapshotFetcher bridging the IOC store, empty means the
	// store genuinely holds no (unexpired) domains, so the last set must
	// drain rather than persist past the indicators' TTL. Set on the
	// IOC-aggregator bridge source; leave false for upstream URL feeds.
	AllowEmpty bool
}

// parseDomainList normalizes a plain-text feed body into a slice of
// canonical domains. The parser is intentionally pure (same bytes →
// same domains, never reaches the network) and tolerant: it skips
// blank lines, `#`/`;` comments, and inline comments, and accepts both
// the "domain per line" and hosts-file ("0.0.0.0 evil.example") shapes
// commercial / community feeds publish. Malformed rows are dropped
// rather than failing the whole batch.
//
// Every whitespace-separated field on a line is run through
// normalizeDomain and the valid ones are kept. This handles the
// one-domain-per-line, hosts-file ("0.0.0.0 evil.example" — the leading
// IP is rejected by normalizeDomain), multi-alias hosts-file
// ("0.0.0.0 a.example b.example"), and "domain + trailing metadata"
// ("evil.example 1700000000") shapes uniformly: non-domain tokens (IPs,
// counters, CSV artifacts) fail the validity gate and drop out while
// every genuine domain on the line is captured. De-duplication and
// sorting are deferred to bundle assembly so the canonical signed bytes
// are stable regardless of source ordering.
func parseDomainList(raw []byte) []string {
	// Pre-size generously: most feeds are one domain per line.
	out := make([]string, 0, 256)
	for _, rawLine := range strings.Split(string(raw), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		// Strip a trailing inline comment.
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
			if line == "" {
				continue
			}
		}
		for _, field := range strings.Fields(line) {
			if d := normalizeDomain(field); d != "" {
				out = append(out, d)
			}
		}
	}
	return out
}

// normalizeDomain lowercases, trims the trailing root dot, and applies
// a conservative validity gate so junk rows (URLs, IPs, wildcards,
// whitespace) never reach the signed bundle. It deliberately mirrors
// the canonicalization the `sng-dns` consumer applies
// (query::canonicalize_name) so a producer entry and an edge query
// collide correctly, but the consumer re-canonicalizes on load anyway,
// so this is a quality gate, not a trust boundary.
func normalizeDomain(s string) string {
	d := strings.ToLower(strings.TrimSpace(s))
	// Strip an optional leading "*." wildcard — category feeds publish
	// these for suffix coverage, which is exactly the consumer's
	// suffix-match semantics, so the bare registrable domain suffices.
	d = strings.TrimPrefix(d, "*.")
	d = strings.TrimSuffix(d, ".")
	if d == "" || len(d) > 253 {
		return ""
	}
	// Reject anything that is clearly not a bare hostname: schemes,
	// paths, ports, whitespace, or a missing dot (a single label is
	// never a useful feed entry and is almost always a parser artifact
	// such as a CSV header token).
	if strings.ContainsAny(d, " \t/\\:@?") || !strings.Contains(d, ".") {
		return ""
	}
	// Every label must be a plausible DNS label (LDH + leading-digit
	// allowance). This drops "comment,domain" CSV artifacts while
	// staying cheap.
	labels := strings.Split(d, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return ""
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z':
			case c >= '0' && c <= '9':
			case c == '-' || c == '_':
			default:
				return ""
			}
		}
	}
	// Reject IPv4 literals (and any "domain" whose TLD is all-numeric):
	// a real TLD always contains a non-digit, so an all-numeric final
	// label means this is an address, not a name — never a useful feed
	// entry for an FQDN reputation / category list.
	if tld := labels[len(labels)-1]; !strings.ContainsFunc(tld, func(r rune) bool { return r < '0' || r > '9' }) {
		return ""
	}
	return d
}

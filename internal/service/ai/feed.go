package ai

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// FeedParser turns a feed's raw response bytes into normalized
// IOCs. Every concrete feed format (STIX/TAXII, CSV/JSON, OTX,
// abuse.ch) implements this interface; the parser is the unit the
// table-driven unit tests exercise against realistic sample
// payloads, decoupled from any network IO.
//
// Implementations MUST be pure: given the same bytes they return
// the same IOCs, never reach the network, and skip malformed rows
// rather than failing the whole batch (returning an error only
// when the payload envelope itself is unparseable).
type FeedParser interface {
	// Name identifies the feed/format for telemetry and as the
	// default IOC Source when a parser does not set one.
	Name() string
	// Parse decodes raw into normalized IOCs.
	Parse(raw []byte) ([]IOC, error)
}

// FeedFetcher retrieves the raw bytes for a feed. The default
// implementation is HTTPFetcher; tests inject a static fetcher so
// no test ever touches the network (the parsers are validated
// directly against sample payloads, and the manager is validated
// against an in-memory fetcher).
type FeedFetcher interface {
	Fetch(ctx context.Context) ([]byte, error)
}

// HTTPFetcher fetches a feed over HTTP(S). Real network calls are
// gated behind explicit configuration (a Feed is only wired with
// an HTTPFetcher when an operator supplies its URL), keeping the
// "mocks only when absolutely required" rule: unit tests use
// parsers + StaticFetcher, never this type.
type HTTPFetcher struct {
	// URL is the feed endpoint.
	URL string
	// Method defaults to GET.
	Method string
	// Header carries auth (e.g. OTX "X-OTX-API-KEY", TAXII
	// "Accept: application/taxii+json;version=2.1") and any other
	// per-feed headers.
	Header http.Header
	// Client defaults to a 30s-timeout http.Client.
	Client *http.Client
	// MaxBytes caps the response body read to bound memory on a
	// misbehaving or hostile feed. Zero applies defaultMaxFeedBytes.
	MaxBytes int64
}

const defaultMaxFeedBytes = 64 << 20 // 64 MiB

// Fetch implements FeedFetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context) ([]byte, error) {
	method := f.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, f.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("ai/feed: build request: %w", err)
	}
	for k, vs := range f.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ai/feed: fetch %s: %w", f.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ai/feed: fetch %s: unexpected status %d", f.URL, resp.StatusCode)
	}
	limit := f.MaxBytes
	if limit <= 0 {
		limit = defaultMaxFeedBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, fmt.Errorf("ai/feed: read body %s: %w", f.URL, err)
	}
	return body, nil
}

// StaticFetcher returns fixed bytes. Used by the feed-manager
// tests to drive the ingest loop deterministically without a
// network dependency.
type StaticFetcher struct {
	Data []byte
	Err  error
}

// Fetch implements FeedFetcher.
func (s StaticFetcher) Fetch(context.Context) ([]byte, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	return s.Data, nil
}

// Feed binds a parser to a fetcher and the scheduling / scoring
// knobs the manager applies on ingest. One Feed corresponds to a
// single upstream source (a TAXII collection, a CERT CSV export,
// an OTX subscription, a specific abuse.ch list).
type Feed struct {
	// Name uniquely identifies the feed in the manager and is
	// stamped as the IOC Source when the parser does not set one.
	Name string
	// Parser decodes the fetched bytes.
	Parser FeedParser
	// Fetcher retrieves the raw bytes.
	Fetcher FeedFetcher
	// Interval is how often the feed is refreshed. Zero applies
	// DefaultFeedInterval (hourly).
	Interval time.Duration
	// DefaultTTL is applied to parsed IOCs that the parser did
	// not give an explicit ExpiresAt. Zero leaves them permanent
	// (the store treats a zero ExpiresAt as never-expiring,
	// matching the demotion engine's threat_feed TTL).
	DefaultTTL time.Duration
	// MinConfidence drops parsed IOCs below this floor before
	// they reach the store (in addition to the store-wide floor).
	MinConfidence float64
}

// DefaultFeedInterval is the default per-feed refresh cadence
// mandated by the workstream spec ("default: hourly").
const DefaultFeedInterval = time.Hour

// effectiveInterval returns the feed's refresh cadence, applying
// the hourly default.
func (f Feed) effectiveInterval() time.Duration {
	if f.Interval <= 0 {
		return DefaultFeedInterval
	}
	return f.Interval
}

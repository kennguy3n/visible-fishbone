package threatfeed

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DefaultMaxFeedBytes bounds a single feed response so a misbehaving or
// hostile upstream cannot exhaust control-plane memory.
const DefaultMaxFeedBytes = 16 << 20 // 16 MiB

// DefaultHTTPTimeout bounds a single feed fetch.
const DefaultHTTPTimeout = 30 * time.Second

// FetchResult is the outcome of one feed fetch. When NotModified is
// true the upstream confirmed (HTTP 304) that the content is unchanged
// since the supplied validators, so Body is empty and the caller reuses
// its last good parse — the incremental-refresh fast path.
type FetchResult struct {
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
}

// Fetcher retrieves the raw bytes for a managed feed, supporting
// conditional requests for incremental refresh. The engine passes the
// validators it stored from the previous fetch; an implementation that
// cannot do conditional requests simply ignores them and always returns
// fresh bytes.
//
// Implementations MUST bound the response size and honor ctx
// cancellation/deadline.
type Fetcher interface {
	Fetch(ctx context.Context, prevETag, prevLastModified string) (FetchResult, error)
}

// HTTPFetcher fetches a feed over HTTP(S) with conditional-GET support.
// Unlike ai.HTTPFetcher it echoes the ETag / Last-Modified validators
// back on the next request and reports a 304 as NotModified, so an
// unchanged upstream costs one cheap conditional round-trip instead of
// a full re-download + re-parse — the property that keeps the bounded
// refresh schedule cheap at fleet scale.
type HTTPFetcher struct {
	// URL is the feed endpoint.
	URL string
	// Client defaults to a DefaultHTTPTimeout http.Client.
	Client *http.Client
	// MaxBytes caps the response body. Zero applies DefaultMaxFeedBytes.
	MaxBytes int64
	// Header carries any per-feed headers (rarely needed for the
	// built-in open feeds, which are unauthenticated).
	Header http.Header
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context, prevETag, prevLastModified string) (FetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("threatfeed: build request %s: %w", f.URL, err)
	}
	for k, vs := range f.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	// Conditional GET: ask the upstream to answer 304 if nothing changed.
	if prevETag != "" {
		req.Header.Set("If-None-Match", prevETag)
	}
	if prevLastModified != "" {
		req.Header.Set("If-Modified-Since", prevLastModified)
	}

	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("threatfeed: fetch %s: %w", f.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotModified {
		return FetchResult{
			NotModified:  true,
			ETag:         firstNonEmpty(resp.Header.Get("ETag"), prevETag),
			LastModified: firstNonEmpty(resp.Header.Get("Last-Modified"), prevLastModified),
		}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return FetchResult{}, fmt.Errorf("threatfeed: fetch %s: unexpected status %d", f.URL, resp.StatusCode)
	}

	limit := f.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxFeedBytes
	}
	// Read one byte past the limit so an oversized body is an explicit
	// error rather than a silently truncated (half-ingested) feed.
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return FetchResult{}, fmt.Errorf("threatfeed: read body %s: %w", f.URL, err)
	}
	if int64(len(body)) > limit {
		return FetchResult{}, fmt.Errorf("threatfeed: fetch %s: response exceeds %d-byte limit", f.URL, limit)
	}
	return FetchResult{
		Body:         body,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// StaticFetcher returns fixed bytes; tests drive the engine with it so
// no test touches the network. It simulates the conditional-GET path:
// when the caller's prevETag matches ETag (and AlwaysModified is
// false) it reports NotModified.
type StaticFetcher struct {
	Body           []byte
	ETag           string
	LastModified   string
	Err            error
	AlwaysModified bool
}

// Fetch implements Fetcher.
func (s StaticFetcher) Fetch(_ context.Context, prevETag, _ string) (FetchResult, error) {
	if s.Err != nil {
		return FetchResult{}, s.Err
	}
	if !s.AlwaysModified && s.ETag != "" && prevETag == s.ETag {
		return FetchResult{NotModified: true, ETag: s.ETag, LastModified: s.LastModified}, nil
	}
	return FetchResult{Body: s.Body, ETag: s.ETag, LastModified: s.LastModified}, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

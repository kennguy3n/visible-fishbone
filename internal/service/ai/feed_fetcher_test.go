package ai

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHTTPFetcher_OversizeBodyIsError guards the MaxBytes handling:
// a body larger than the limit must surface as an explicit
// "response exceeds limit" error rather than a silently truncated
// (and then mis-parsed) payload. A body exactly at the limit is fine.
func TestHTTPFetcher_OversizeBodyIsError(t *testing.T) {
	t.Parallel()
	const limit = 16
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back exactly the number of bytes the test asks for via
		// the query string length so one server drives both cases.
		_, _ = w.Write([]byte(r.URL.RawQuery))
	}))
	defer srv.Close()

	atLimit := &HTTPFetcher{URL: srv.URL + "?" + strings.Repeat("a", limit), MaxBytes: limit}
	body, err := atLimit.Fetch(context.Background())
	if err != nil {
		t.Fatalf("body at limit should succeed: %v", err)
	}
	if len(body) != limit {
		t.Fatalf("body at limit length = %d, want %d", len(body), limit)
	}

	oversize := &HTTPFetcher{URL: srv.URL + "?" + strings.Repeat("a", limit+1), MaxBytes: limit}
	if _, err := oversize.Fetch(context.Background()); err == nil {
		t.Fatal("oversize body should return an error, got nil (silent truncation)")
	} else if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversize error = %q, want it to mention the size limit", err)
	}
}

// TestHTTPFetcher_Non2xxIsError confirms a non-2xx upstream status
// is a fetch error (a skipped refresh) rather than a body parse.
func TestHTTPFetcher_Non2xxIsError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := &HTTPFetcher{URL: srv.URL}
	if _, err := f.Fetch(context.Background()); err == nil {
		t.Fatal("non-2xx status should return an error")
	}
}

package threatfeed

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPFetcher_FullBody(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 01 Jun 2026 00:00:00 GMT")
		_, _ = w.Write([]byte("203.0.113.10\n"))
	}))
	defer srv.Close()

	f := &HTTPFetcher{URL: srv.URL}
	res, err := f.Fetch(context.Background(), "", "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if res.NotModified {
		t.Fatal("first fetch should not be NotModified")
	}
	if string(res.Body) != "203.0.113.10\n" {
		t.Fatalf("body = %q", res.Body)
	}
	if res.ETag != `"v1"` {
		t.Fatalf("etag = %q", res.ETag)
	}
}

func TestHTTPFetcher_ConditionalNotModified(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	f := &HTTPFetcher{URL: srv.URL}
	res, err := f.Fetch(context.Background(), `"v1"`, "")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if !res.NotModified {
		t.Fatal("matching ETag should yield NotModified")
	}
	if len(res.Body) != 0 {
		t.Fatalf("NotModified body should be empty, got %q", res.Body)
	}
}

func TestHTTPFetcher_NonSuccessStatus(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := &HTTPFetcher{URL: srv.URL}
	if _, err := f.Fetch(context.Background(), "", ""); err == nil {
		t.Fatal("5xx should be an error")
	}
}

func TestHTTPFetcher_OversizedBody(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 1024)))
	}))
	defer srv.Close()

	f := &HTTPFetcher{URL: srv.URL, MaxBytes: 16}
	if _, err := f.Fetch(context.Background(), "", ""); err == nil {
		t.Fatal("body over MaxBytes should error rather than silently truncate")
	}
}

func TestStaticFetcher(t *testing.T) {
	t.Parallel()
	// First fetch returns the body.
	s := StaticFetcher{Body: []byte("x"), ETag: "e1"}
	res, err := s.Fetch(context.Background(), "", "")
	if err != nil || res.NotModified || string(res.Body) != "x" {
		t.Fatalf("first fetch = %+v err=%v", res, err)
	}
	// Same ETag -> NotModified.
	res, err = s.Fetch(context.Background(), "e1", "")
	if err != nil || !res.NotModified {
		t.Fatalf("matching etag fetch = %+v err=%v", res, err)
	}
	// AlwaysModified bypasses the conditional path.
	s.AlwaysModified = true
	res, err = s.Fetch(context.Background(), "e1", "")
	if err != nil || res.NotModified {
		t.Fatalf("AlwaysModified should always return body: %+v err=%v", res, err)
	}
}

func TestFirstNonEmpty(t *testing.T) {
	t.Parallel()
	if firstNonEmpty("a", "b") != "a" {
		t.Fatal("should prefer first non-empty")
	}
	if firstNonEmpty("", "b") != "b" {
		t.Fatal("should fall back to second")
	}
}

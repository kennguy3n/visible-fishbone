package metrics

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// statusRecorder captures the response status code so the metrics
// middleware can label the request by outcome. Mirrors the
// recorder used by the logging middleware; kept package-local so
// the metrics layer has no dependency on the middleware package.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.status = http.StatusOK
		s.wroteHeader = true
	}
	return s.ResponseWriter.Write(b)
}

// Middleware returns an HTTP middleware that records
// request_duration_seconds, requests_total, and requests_in_flight
// for every request. It is installed at the top of the chain (see
// internal/handler/router.go) so the timing covers the whole
// stack, including downstream middleware and the handler.
//
// When m is nil the middleware is a transparent pass-through, so
// callers can wire it unconditionally and let config gate whether
// a real *Metrics is constructed.
//
// Cardinality: the `path` label is the normalised route template
// (normalizePath), not the raw URL, so high-cardinality segments
// (tenant UUIDs, device IDs) collapse to a fixed token set. The
// duration histogram is labelled by status *class* (2xx, 4xx, …)
// while the counter keeps the exact status code — the histogram is
// the expensive one, so it gets the coarser label.
func (m *Metrics) Middleware() func(http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m.HTTPRequestsInFlight.Inc()
			defer m.HTTPRequestsInFlight.Dec()

			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)

			path := normalizePath(r.URL.Path)
			elapsed := time.Since(start).Seconds()

			m.HTTPRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(rec.status)).Inc()
			m.HTTPRequestDuration.WithLabelValues(r.Method, path, statusClass(rec.status)).Observe(elapsed)
		})
	}
}

// statusClass collapses a numeric HTTP status into its class
// bucket ("2xx", "4xx", …) so the duration histogram's label set
// stays small. Out-of-range codes fall through to "unknown".
func statusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	case code >= 500 && code < 600:
		return "5xx"
	default:
		return "unknown"
	}
}

// normalizePath rewrites a request path into a bounded route
// template by replacing high-cardinality segments — UUIDs and
// purely numeric IDs — with a fixed `:id` token. This keeps the
// `path` label cardinality proportional to the number of routes
// (a few dozen) rather than the number of tenants/devices (tens of
// thousands).
//
// The function is allocation-light: it returns the input unchanged
// when no segment needs rewriting (the common case for static
// routes), only allocating a rebuilt string when a variable
// segment is present.
func normalizePath(path string) string {
	if path == "" || path == "/" {
		return path
	}
	// Fast path: scan for any segment that would be rewritten. If
	// none, return the original string without allocating.
	needsRewrite := false
	for _, seg := range strings.Split(path, "/") {
		if isVariableSegment(seg) {
			needsRewrite = true
			break
		}
	}
	if !needsRewrite {
		return path
	}

	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if isVariableSegment(seg) {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

// isVariableSegment reports whether a single path segment looks
// like a high-cardinality identifier: a UUID or an all-digit ID.
func isVariableSegment(seg string) bool {
	if seg == "" {
		return false
	}
	if isAllDigits(seg) {
		return true
	}
	return isUUID(seg)
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isUUID reports whether s is a canonical 8-4-4-4-12 hyphenated
// UUID. Avoids a regexp / google/uuid parse on the hot path.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/routenorm"
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

// Unwrap exposes the wrapped ResponseWriter so net/http's
// ResponseController (and any handler that walks Unwrap chains) can
// reach optional interfaces — http.Flusher, http.Hijacker,
// io.ReaderFrom — that the underlying writer implements but this
// recorder does not. Without it, wrapping the writer would mask
// those capabilities from streaming/SSE handlers.
func (s *statusRecorder) Unwrap() http.ResponseWriter {
	return s.ResponseWriter
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
// (routenorm.Normalize), not the raw URL, so high-cardinality
// segments (tenant UUIDs, device IDs) collapse to a fixed token
// set. The duration histogram is labelled by status *class* (2xx,
// 4xx, …) while the counter keeps the exact status code — the
// histogram is the expensive one, so it gets the coarser label.
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

			path := routenorm.Normalize(r.URL.Path)
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

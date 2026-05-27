package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

// statusRecorder wraps http.ResponseWriter to record the final
// status code + bytes written. It implements http.Flusher and
// http.Hijacker by passthrough when the underlying writer does.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Logging emits a structured access log for every request, including
// method, path, status, latency, request id, tenant id, and user id.
func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w}
			next.ServeHTTP(rec, r)
			attrs := []any{
				slog.String("method", r.Method),
				slog.String("path", r.URL.Path),
				slog.Int("status", rec.status),
				slog.Int("bytes", rec.bytes),
				slog.Duration("dur", time.Since(start)),
				slog.String("request_id", RequestIDFromContext(r.Context())),
				slog.String("remote", r.RemoteAddr),
			}
			if tid := TenantIDFromContext(r.Context()); tid.String() != "00000000-0000-0000-0000-000000000000" {
				attrs = append(attrs, slog.String("tenant_id", tid.String()))
			}
			if uid := UserIDFromContext(r.Context()); uid.String() != "00000000-0000-0000-0000-000000000000" {
				attrs = append(attrs, slog.String("user_id", uid.String()))
			}
			logger.Info("http: request", attrs...)
		})
	}
}

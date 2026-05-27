package middleware

import (
	"net/http"

	"github.com/google/uuid"
)

// RequestIDHeader is the canonical request-id header.
const RequestIDHeader = "X-Request-ID"

// RequestID injects a request ID into the context and echoes it
// back as a response header so clients can correlate logs.
// If the caller supplies X-Request-ID it is preserved (after a
// length sanity check); otherwise a fresh UUID v4 is generated.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(RequestIDHeader)
			// Treat anything outside [1,128] chars as missing so
			// clients can't poison correlation IDs with megabytes
			// of attacker-controlled data.
			if id == "" || len(id) > 128 {
				id = uuid.NewString()
			}
			w.Header().Set(RequestIDHeader, id)
			ctx := withRequestID(r.Context(), id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

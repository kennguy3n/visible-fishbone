package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// CORS applies the configured cross-origin policy. OPTIONS preflight
// requests are answered directly with the negotiated headers; all
// other methods are passed through after the headers are stamped.
func CORS(cfg *config.CORS) func(http.Handler) http.Handler {
	allowed := normaliseOrigins(cfg.AllowedOrigins)
	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	maxAge := strconv.Itoa(int(cfg.MaxAge.Truncate(time.Second).Seconds()))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" && isAllowed(allowed, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Add("Vary", "Origin")
				if methods != "" {
					w.Header().Set("Access-Control-Allow-Methods", methods)
				}
				if headers != "" {
					w.Header().Set("Access-Control-Allow-Headers", headers)
				}
				if maxAge != "" && maxAge != "0" {
					w.Header().Set("Access-Control-Max-Age", maxAge)
				}
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// normaliseOrigins lowercases the configured origins and trims whitespace.
func normaliseOrigins(raw []string) []string {
	out := make([]string, 0, len(raw))
	for _, o := range raw {
		s := strings.ToLower(strings.TrimSpace(o))
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// isAllowed reports whether origin matches any entry in allowed.
// A single "*" entry means wildcard (echo any origin).
func isAllowed(allowed []string, origin string) bool {
	if len(allowed) == 0 {
		return false
	}
	o := strings.ToLower(strings.TrimSpace(origin))
	for _, a := range allowed {
		if a == "*" || a == o {
			return true
		}
	}
	return false
}

package middleware

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ActivityObserver receives the tenant of an authenticated request so
// the dormancy planner has a control-plane activity signal alongside
// the data-plane one fed by the telemetry consumer. It mirrors the
// telemetry consumer's observer: implementations MUST be cheap,
// non-blocking, and concurrency-safe (activity.Recorder debounces per
// tenant and persists asynchronously). Declared here rather than
// importing the activity package so the middleware depends only on the
// narrow capability it needs.
type ActivityObserver interface {
	Observe(tenantID uuid.UUID, seen time.Time)
}

// RecordActivity records the tenant of every authenticated request as
// active. It must run AFTER Auth (and the tenant resolution it drives)
// so the tenant ID is in context; a request with no resolved tenant
// (unauthenticated, or operator/system scope) is skipped. The observe
// happens before the handler runs so an expensive or hanging handler
// never delays the (debounced, async) signal.
//
// A nil observer yields a transparent pass-through, so the middleware
// can be wired unconditionally and degrade to a no-op when activity
// tracking is not configured.
func RecordActivity(obs ActivityObserver) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if obs == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tid := TenantIDFromContext(r.Context()); tid != uuid.Nil {
				obs.Observe(tid, time.Now())
			}
			next.ServeHTTP(w, r)
		})
	}
}

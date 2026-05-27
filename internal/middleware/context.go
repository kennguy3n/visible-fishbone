// Package middleware contains the HTTP middleware stack for the
// ShieldNet Gateway control plane. Each middleware is independently
// testable and wired together by `Chain` (or the standard
// `http.Handler` composition pattern in the router).
//
// Order matters. The recommended boot-time chain is:
//
//	requestID -> logging -> recovery -> cors -> ratelimit -> auth -> tenant
//
// so that:
//
//   - every request gets an X-Request-ID (even panics);
//   - logging sees the final status + latency for the entire stack;
//   - recovery converts panics to 500 + a logged stack trace;
//   - CORS preflights short-circuit before any auth work;
//   - rate limit drops attackers before auth burns crypto;
//   - auth resolves the identity for subsequent layers;
//   - tenant pulls the tenant ID out of the auth claims and stores
//     it in the request context so handlers can scope the
//     repository GUC against it.
package middleware

import (
	"context"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// contextKey is a typed key to avoid collisions with other packages
// storing values in request contexts.
type contextKey string

const (
	keyRequestID   contextKey = "request_id"
	keyTenantID    contextKey = "tenant_id"
	keyUserID      contextKey = "user_id"
	keyAPIKeyID    contextKey = "api_key_id"
	keyAuthSubject contextKey = "auth_subject"
	keyRequestMeta contextKey = "request_meta"
)

// RequestMeta carries mutable, late-bound identity attributes that
// downstream middleware (auth, tenant guard) populate after they
// have run, so that *outer* middleware (e.g. Logging) can still
// observe them when the handler chain unwinds.
//
// Why this exists: contexts are immutable. When the Auth middleware
// calls next.ServeHTTP(w, r.WithContext(ctx)), it builds a NEW
// request whose context contains the resolved tenant/user IDs.
// That enriched request is visible to handlers downstream — but
// NOT to the outer Logging middleware, which still holds a pointer
// to the ORIGINAL r. So the access log would always observe
// uuid.Nil for tenant_id / user_id even on a fully authenticated
// request.
//
// The fix is to install a pointer-to-RequestMeta into the original
// context BEFORE Logging calls next. Inner middleware then writes
// the resolved identity into *that* struct (in addition to
// stamping the context values that handlers consume). Because the
// pointer is captured before the WithContext call, Logging reads
// the populated struct after the handler returns.
//
// RequestMeta is safe for concurrent reads after Auth has run
// because:
//   - the writers (Auth, RequireTenant) run synchronously on the
//     request goroutine before next.ServeHTTP returns;
//   - the reader (Logging) runs after next.ServeHTTP returns,
//     happens-before relationship guaranteed by the call/return.
//
// The mutex is for defence-in-depth: if a future middleware spawns
// a goroutine that touches the meta concurrently with the logger,
// we want a clean panic-free read rather than a torn write.
type RequestMeta struct {
	mu       sync.Mutex
	tenantID uuid.UUID
	userID   uuid.UUID
}

// SetTenantID sets the tenant ID on the request meta. Safe for
// concurrent use.
func (m *RequestMeta) SetTenantID(id uuid.UUID) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.tenantID = id
	m.mu.Unlock()
}

// SetUserID sets the user ID on the request meta. Safe for
// concurrent use.
func (m *RequestMeta) SetUserID(id uuid.UUID) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.userID = id
	m.mu.Unlock()
}

// TenantID returns the tenant ID populated by inner middleware.
func (m *RequestMeta) TenantID() uuid.UUID {
	if m == nil {
		return uuid.Nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.tenantID
}

// UserID returns the user ID populated by inner middleware.
func (m *RequestMeta) UserID() uuid.UUID {
	if m == nil {
		return uuid.Nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.userID
}

// withRequestMeta returns a context carrying a pointer to the
// RequestMeta. The pointer (not a copy) is what makes the
// late-binding work — inner middleware writes through the pointer.
func withRequestMeta(ctx context.Context, meta *RequestMeta) context.Context {
	return context.WithValue(ctx, keyRequestMeta, meta)
}

// RequestMetaFromContext retrieves the late-binding identity
// container installed by the Logging middleware. Returns nil if
// Logging is not in the chain (e.g. unit tests that wire Auth
// directly).
func RequestMetaFromContext(ctx context.Context) *RequestMeta {
	v, _ := ctx.Value(keyRequestMeta).(*RequestMeta)
	return v
}

// RequestIDFromContext returns the X-Request-ID stamped onto the
// request, or "" if the requestID middleware did not run.
func RequestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyRequestID).(string)
	return v
}

// TenantIDFromContext returns the resolved tenant UUID, or uuid.Nil
// if no tenant was bound to the request (e.g. unauthenticated paths
// or paths that don't need a tenant scope).
func TenantIDFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(keyTenantID).(uuid.UUID)
	return v
}

// UserIDFromContext returns the authenticated user UUID, or uuid.Nil
// if no user was bound (e.g. API-key auth, public endpoints).
func UserIDFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(keyUserID).(uuid.UUID)
	return v
}

// APIKeyIDFromContext returns the API-key identifier used to
// authenticate the request, or "" if the request was authenticated
// some other way.
func APIKeyIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyAPIKeyID).(string)
	return v
}

// AuthSubjectFromContext returns the raw JWT `sub` claim or the
// API-key descriptive name, used for audit logging.
func AuthSubjectFromContext(ctx context.Context) string {
	v, _ := ctx.Value(keyAuthSubject).(string)
	return v
}

// withRequestID returns a new context carrying the request ID.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

// withTenantID stamps the tenant UUID onto the context.
func withTenantID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, keyTenantID, id)
}

// withUserID stamps the user UUID onto the context.
func withUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, keyUserID, id)
}

// withAPIKeyID stamps the API key id onto the context.
func withAPIKeyID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyAPIKeyID, id)
}

// withAuthSubject stamps the auth subject (JWT sub or key name).
func withAuthSubject(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, keyAuthSubject, sub)
}

// Chain composes middlewares in left-to-right order. The first
// middleware in the list is the outermost layer.
func Chain(mws ...func(http.Handler) http.Handler) func(http.Handler) http.Handler {
	return func(final http.Handler) http.Handler {
		h := final
		for i := len(mws) - 1; i >= 0; i-- {
			h = mws[i](h)
		}
		return h
	}
}

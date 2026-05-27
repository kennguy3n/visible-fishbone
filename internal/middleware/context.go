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
)

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

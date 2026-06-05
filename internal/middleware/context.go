// Package middleware contains the HTTP middleware stack for the
// ShieldNet Gateway control plane. Each middleware is independently
// testable and wired together by `Chain` (or the standard
// `http.Handler` composition pattern in the router).
//
// Order matters. The recommended boot-time chain is:
//
//	requestID -> metrics -> logging -> recovery -> tracing -> cors -> ratelimit -> auth -> tenant
//
// so that:
//
//   - every request gets an X-Request-ID (even panics);
//   - metrics and logging sit OUTSIDE recovery, so a panic — which
//     recovery turns into a 500 — is still counted in Prometheus and
//     emitted as an access-log line with its 500 status. A
//     middleware placed inside recovery has its post-handler code
//     skipped when the panic unwinds through it, so it would miss
//     panicked requests entirely;
//   - logging sees the final status + latency for the entire stack;
//   - recovery converts panics to 500 + a logged stack trace;
//   - tracing sits inside recovery and after logging so the
//     late-bound RequestMeta (installed by logging) is present when
//     the span records tenant_id, and so its deferred span
//     annotation can re-raise the panic for recovery to convert to a
//     500;
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
	keyRequestID      contextKey = "request_id"
	keyTenantID       contextKey = "tenant_id"
	keyMSPID          contextKey = "msp_id"
	keyUserID         contextKey = "user_id"
	keyAPIKeyID       contextKey = "api_key_id"
	keyAuthSubject    contextKey = "auth_subject"
	keyRequestMeta    contextKey = "request_meta"
	keyMobileClaims   contextKey = "mobile_claims"
	keyExpectedTenant contextKey = "expected_rls_tenant"
)

// MobileClaims carries the device-bound custom claims that the
// mobile native-SSO session JWT (minted by OIDCService.mintSession)
// rides on top of the standard iss/aud/sub/tenant_id set. The base
// Auth middleware authenticates the token the same way it does an
// operator-console token; these extra claims are surfaced ON TOP so
// the mobile self-service endpoints (device enrolment + posture
// reporting) can scope an action to the exact device the session is
// bound to, WITHOUT re-parsing or re-verifying the JWT in the
// handler (which would force the handler to know the signing
// secret/iss/aud and duplicate the verification the middleware has
// already done).
//
// Surfacing happens only after the signature + iss/aud/exp checks
// pass, so a handler that reads MobileClaimsFromContext can trust
// the values are from a cryptographically-valid token.
type MobileClaims struct {
	// TokenType is the `token_type` claim. "mobile" marks a
	// device-bound session minted by the mobile token-exchange
	// flow. Empty/absent for operator-console and API-key auth.
	TokenType string
	// DeviceKey is the base64 Ed25519 device public key the session
	// is bound to (`device_key` claim).
	DeviceKey string
	// OIDCSubject is the upstream IdP `sub` (`oidc_sub` claim) — the
	// stable provider-scoped user identifier.
	OIDCSubject string
	// OIDCIssuer is the upstream IdP issuer (`oidc_iss` claim).
	OIDCIssuer string
}

// IsMobile reports whether the claims describe a device-bound mobile
// session (token_type == "mobile").
func (c MobileClaims) IsMobile() bool {
	return c.TokenType == "mobile"
}

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

// MSPIDFromContext returns the resolved MSP UUID for the request,
// or uuid.Nil if no MSP scope was bound (e.g. tenant-only paths).
// Populated by RequireMSP (and indirectly by RequireMSPScope) after
// it has authorized the caller against the path's msp_id.
func MSPIDFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(keyMSPID).(uuid.UUID)
	return v
}

// WithMSPID returns a derived context carrying the given MSP UUID.
// Exported for service-layer tests that need to simulate an
// MSP-scoped caller without spinning up the full middleware stack;
// production code goes through RequireMSP / RequireMSPScope.
func WithMSPID(ctx context.Context, id uuid.UUID) context.Context {
	return withMSPID(ctx, id)
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

// withMSPID stamps the MSP UUID onto the context.
func withMSPID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, keyMSPID, id)
}

// withExpectedTenant records the tenant that downstream data-layer
// code is expected to scope the RLS GUC (`sng.tenant_id`) to. It is
// stamped by AssertTenantContext once the request's tenant has been
// authoritatively resolved, so the repository layer's GUC read-back
// (see internal/repository/postgres.setTenantGUC) has a single,
// trusted value to assert the live connection state against.
func withExpectedTenant(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, keyExpectedTenant, id)
}

// ExpectedRLSTenantFromContext returns the tenant the request was
// authoritatively resolved to (the value RLS-scoped queries MUST run
// under), or uuid.Nil if no tenant assertion has run for this
// request. Populated by AssertTenantContext.
func ExpectedRLSTenantFromContext(ctx context.Context) uuid.UUID {
	v, _ := ctx.Value(keyExpectedTenant).(uuid.UUID)
	return v
}

// withUserID stamps the user UUID onto the context.
func withUserID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, keyUserID, id)
}

// withAPIKeyID stamps the API key id onto the context.
func withAPIKeyID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyAPIKeyID, id)
}

// ContextWithAPIKeyID returns a derived context carrying the
// given API-key identifier so consumers of APIKeyIDFromContext
// observe an API-key-authenticated request. This is exported for
// service-layer tests that need to simulate an API-key-authed
// caller without spinning up the full auth middleware stack —
// production code MUST go through the auth middleware (which
// calls the unexported withAPIKeyID after a real Lookup), not
// through this helper.
func ContextWithAPIKeyID(ctx context.Context, id string) context.Context {
	return withAPIKeyID(ctx, id)
}

// WithUserIDForTest stamps the user UUID onto the context for
// tests that need to simulate an authenticated user without
// spinning up the full Auth middleware. Production code goes
// through the Auth middleware (which calls the unexported
// withUserID after a real JWT Verify), not through this helper.
func WithUserIDForTest(ctx context.Context, id uuid.UUID) context.Context {
	return withUserID(ctx, id)
}

// withAuthSubject stamps the auth subject (JWT sub or key name).
func withAuthSubject(ctx context.Context, sub string) context.Context {
	return context.WithValue(ctx, keyAuthSubject, sub)
}

// withMobileClaims stamps the device-bound mobile session claims
// onto the context. Called by Auth only after the JWT signature +
// registered-claim checks pass.
func withMobileClaims(ctx context.Context, c MobileClaims) context.Context {
	return context.WithValue(ctx, keyMobileClaims, c)
}

// MobileClaimsFromContext returns the device-bound mobile session
// claims surfaced by the Auth middleware. The second return value is
// false when the request was not authenticated by a JWT carrying any
// of the mobile custom claims (e.g. operator-console JWT, API-key
// auth, or a public endpoint). Use MobileClaims.IsMobile() to gate
// the mobile self-service endpoints.
func MobileClaimsFromContext(ctx context.Context) (MobileClaims, bool) {
	v, ok := ctx.Value(keyMobileClaims).(MobileClaims)
	return v, ok
}

// WithMobileClaimsForTest stamps mobile session claims onto the
// context for tests that need to simulate a device-bound mobile
// caller without minting + verifying a real JWT through the Auth
// middleware. Production code goes through Auth (which calls the
// unexported withMobileClaims after a real Verify).
func WithMobileClaimsForTest(ctx context.Context, c MobileClaims) context.Context {
	return withMobileClaims(ctx, c)
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

package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// APIKeyLookup resolves an API key (presented in the configured
// header) to its metadata. Implementations live in the API-key
// service (PR8 follow-up); the middleware accepts the interface so
// it can be unit-tested without a real store.
type APIKeyLookup interface {
	Lookup(ctx context.Context, key string) (APIKeyInfo, error)
}

// APIKeyInfo carries the resolved API-key identity.
type APIKeyInfo struct {
	ID       string
	TenantID uuid.UUID
	Subject  string
}

// ErrAPIKeyNotFound is returned by APIKeyLookup implementations when
// no key matches.
var ErrAPIKeyNotFound = errors.New("middleware: api key not found")

// ErrMobileDeviceRevoked is the sentinel a MobileDeviceStatusResolver
// returns when the device a verified mobile session JWT is bound to
// has been administratively suspended or soft-deleted (or no longer
// exists). The Auth middleware translates it into a 403, so an admin
// suspend/delete is an effective kill-switch even against an
// unexpired, stateless session token.
var ErrMobileDeviceRevoked = errors.New("middleware: mobile device revoked")

// MobileDeviceStatusResolver reports whether a verified mobile session
// JWT may still be used, based on the LIVE status of the device it is
// bound to. The mobile session JWT is self-contained (HMAC-signed, no
// server-side session store), so without this check an admin
// suspend/delete only takes effect once the token expires. Auth
// consults the resolver on every request that carries mobile claims,
// so a revoked device is cut off across ALL endpoints — not just the
// mobile self-service ones (which also re-check at the service layer).
type MobileDeviceStatusResolver interface {
	// MobileSessionAllowed returns nil when the device identified by
	// (tenantID, deviceKey) is active and may continue to use the
	// session, ErrMobileDeviceRevoked when it has been
	// suspended/deleted/removed, or any other error on an
	// infrastructure failure. Auth fails OPEN on a non-revoked error
	// (see its doc comment).
	MobileSessionAllowed(ctx context.Context, tenantID uuid.UUID, deviceKey string) error
}

// authOptions holds the optional, additive behaviours of Auth.
type authOptions struct {
	deviceStatus MobileDeviceStatusResolver
	// iamCore, when set, validates Bearer tokens issued by the upstream
	// iam-core IdP (Session 2A). Tokens whose `iss` matches its issuer
	// take this path; all others use the legacy verifier.
	iamCore IAMCoreValidator
	// tenantResolver maps an iam-core tenant_id claim onto the SNG
	// tenant model. Optional; see WithIAMCore.
	tenantResolver TenantResolver
	// bruteForce, when set, throttles credential-validation failures
	// per source IP (see WithBruteForceGuard). Optional; nil disables
	// the IP cooldown entirely.
	bruteForce *AttemptLimiter
	// logger, when set, emits a structured warning for every failed
	// auth attempt (source IP, reason, resolved tenant when known).
	// Optional; nil suppresses the failure log.
	logger *slog.Logger
}

// AuthOption configures optional Auth behaviour without breaking the
// base (cfg, keys) signature used across the codebase + tests.
type AuthOption func(*authOptions)

// WithMobileDeviceStatus enables the device-revocation check for
// mobile session JWTs. When omitted, Auth behaves exactly as before
// (no per-request device lookup).
func WithMobileDeviceStatus(r MobileDeviceStatusResolver) AuthOption {
	return func(o *authOptions) { o.deviceStatus = r }
}

// WithBruteForceGuard enables IP-keyed brute-force protection on the
// auth middleware and structured logging of every failed auth attempt.
//
// guard (when non-nil) accumulates credential-validation failures
// (bad API key, unverifiable/expired Bearer token, rejected iam-core
// token) per source IP; once its threshold is reached the IP is put
// into a cooldown during which further requests are rejected 429 with
// a Retry-After, until a successful authentication clears it. A
// request that merely omits credentials, or a server-side
// misconfiguration, is logged but never counted — only genuine
// credential rejections feed the lockout, so a client that forgets its
// header cannot lock itself out.
//
// logger (when non-nil) receives a warning for EVERY failed auth
// attempt with the source IP, the failure reason, and the resolved
// tenant when one is known. Both arguments are independent: either may
// be nil. When both are nil this option is a no-op and Auth behaves
// exactly as before.
func WithBruteForceGuard(guard *AttemptLimiter, logger *slog.Logger) AuthOption {
	return func(o *authOptions) {
		o.bruteForce = guard
		o.logger = logger
	}
}

// recordAuthFailure feeds a credential-validation failure to the
// brute-force guard (when configured) and logs it. Only call this for
// genuine credential rejections that should count toward the IP
// cooldown.
func (o *authOptions) recordAuthFailure(r *http.Request, ip, reason string) {
	if o.bruteForce != nil && ip != "" {
		o.bruteForce.RecordFailure(ip)
	}
	o.logAuthFailure(r, ip, reason)
}

// logAuthFailure emits the structured "auth failed" warning. It is
// used both for counted failures (via recordAuthFailure) and for
// non-counted ones (missing credentials, revoked device) so the audit
// trail captures every rejection.
func (o *authOptions) logAuthFailure(r *http.Request, ip, reason string) {
	if o.logger == nil {
		return
	}
	src := ip
	if src == "" {
		src = clientIP(r, nil)
	}
	attrs := []any{
		slog.String("event", "auth_failed"),
		slog.String("reason", reason),
		slog.String("source_ip", src),
		slog.String("method", r.Method),
		slog.String("path", r.URL.Path),
	}
	if tid := TenantIDFromContext(r.Context()); tid != uuid.Nil {
		attrs = append(attrs, slog.String("tenant_id", tid.String()))
	}
	o.logger.Warn("authentication failed", attrs...)
}

// recordAuthSuccess clears the source IP's failure counter after a
// successful authentication.
func (o *authOptions) recordAuthSuccess(ip string) {
	if o.bruteForce != nil && ip != "" {
		o.bruteForce.RecordSuccess(ip)
	}
}

// Auth wires JWT (operator console) and API-key (M2M) auth. At
// least one credential is required for the protected routes. A
// request with neither is rejected 401.
func Auth(cfg *config.Auth, keys APIKeyLookup, opts ...AuthOption) func(http.Handler) http.Handler {
	header := cfg.APIKeyHeader
	if header == "" {
		header = "X-SNG-API-Key"
	}
	var o authOptions
	for _, fn := range opts {
		fn(&o)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Brute-force gate: if this source IP is in cooldown after
			// repeated credential failures, reject before doing any
			// crypto so an attacker gets no oracle and spends no CPU.
			var ip string
			if o.bruteForce != nil {
				ip = o.bruteForce.ClientIP(r)
				if retryAfter, blocked := o.bruteForce.Blocked(ip); blocked {
					o.logAuthFailure(r, ip, "ip_in_cooldown")
					w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
					writeAuthErrorStatus(w, http.StatusTooManyRequests, "too_many_failed_attempts",
						"too many failed authentication attempts; try again later")
					return
				}
			}

			// API-key path — try first because it's cheaper than
			// JWT verification.
			if k := r.Header.Get(header); k != "" {
				if keys == nil {
					// Server misconfiguration, not a credential
					// rejection: log but do not count toward the
					// IP cooldown.
					o.logAuthFailure(r, ip, "api_key_not_configured")
					writeAuthError(w, "api_key_not_configured")
					return
				}
				info, err := keys.Lookup(r.Context(), k)
				if err != nil {
					o.recordAuthFailure(r, ip, "invalid_api_key")
					writeAuthError(w, "invalid_api_key")
					return
				}
				ctx := withAPIKeyID(r.Context(), info.ID)
				ctx = withAuthSubject(ctx, info.Subject)
				if info.TenantID != uuid.Nil {
					ctx = withTenantID(ctx, info.TenantID)
					// Late-bind tenant_id onto the outer Logging
					// middleware's RequestMeta so the access log
					// can observe it after the handler returns.
					// See RequestMeta's doc comment for the
					// rationale.
					RequestMetaFromContext(ctx).SetTenantID(info.TenantID)
				}
				o.recordAuthSuccess(ip)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// JWT path.
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				// No credentials presented: log but do not count.
				o.logAuthFailure(r, ip, "missing_credentials")
				writeAuthError(w, "missing_credentials")
				return
			}
			raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			if raw == "" {
				o.logAuthFailure(r, ip, "missing_credentials")
				writeAuthError(w, "missing_credentials")
				return
			}
			// iam-core path (Session 2A): when the integration is wired
			// and the token claims the iam-core issuer, validate it
			// against iam-core's JWKS (asymmetric, fail-closed) instead
			// of the legacy HMAC verifier. Routing on the UNVERIFIED iss
			// only selects which verifier runs; the selected verifier
			// performs the real signature + claim validation. Tokens for
			// any other issuer fall through to the existing path, so
			// operator-console / mobile / API-key auth is untouched.
			if o.iamCore != nil && unverifiedIssuer(raw) == o.iamCore.Issuer() {
				if ctx, handled := o.authenticateIAMCore(w, r, raw); handled {
					if ctx != nil {
						o.recordAuthSuccess(ip)
						next.ServeHTTP(w, r.WithContext(ctx))
					} else {
						// authenticateIAMCore wrote a 401/403: a
						// rejected iam-core token is a credential
						// failure, count it toward the IP cooldown.
						o.recordAuthFailure(r, ip, "invalid_iam_core_token")
					}
					return
				}
			}
			// The symmetric (HMAC) verification path is build-tagged:
			// the real implementation is compiled only into
			// non-production builds (auth_hmac.go), while production
			// builds link a stub (auth_hmac_prod.go) that always
			// refuses, so a production binary physically cannot verify
			// an HMAC token. See SECURITY.md and the //go:build guards.
			claims, errCode, err := verifyBearerJWT(cfg, raw)
			if err != nil {
				o.recordAuthFailure(r, ip, errCode)
				writeAuthError(w, errCode)
				return
			}

			ctx := r.Context()
			meta := RequestMetaFromContext(ctx)
			if sub, _ := claims["sub"].(string); sub != "" {
				ctx = withAuthSubject(ctx, sub)
				if uid, parseErr := uuid.Parse(sub); parseErr == nil {
					ctx = withUserID(ctx, uid)
					meta.SetUserID(uid)
				}
			}
			if tid, _ := claims["tenant_id"].(string); tid != "" {
				if u, parseErr := uuid.Parse(tid); parseErr == nil {
					ctx = withTenantID(ctx, u)
					meta.SetTenantID(u)
				}
			}
			// Surface the device-bound mobile session claims (if any)
			// so the mobile self-service endpoints can scope an action
			// to the exact device the session is bound to. These are
			// stashed only after the signature + iss/aud/exp checks
			// above have passed, so handlers can trust them. Absent on
			// operator-console / API-key auth (mc stays zero-valued).
			if mc := extractMobileClaims(claims); mc != (MobileClaims{}) {
				ctx = withMobileClaims(ctx, mc)
				// Defense-in-depth revocation: the session JWT is
				// stateless (valid until exp), so an admin suspend /
				// delete would otherwise stay bypassable until the
				// token expired. Resolve the bound device's live
				// status and refuse the request when it has been
				// revoked, so the kill-switch covers EVERY endpoint a
				// mobile token can reach. Only mobile sessions pay
				// this lookup; operator-console / API-key auth is
				// untouched.
				if o.deviceStatus != nil && mc.IsMobile() && mc.DeviceKey != "" {
					if err := o.deviceStatus.MobileSessionAllowed(ctx, TenantIDFromContext(ctx), mc.DeviceKey); err != nil {
						if errors.Is(err, ErrMobileDeviceRevoked) {
							// Valid token bound to a revoked device:
							// log the rejection but do NOT count it —
							// the cryptographic credential is genuine,
							// so this is not a brute-force signal.
							o.logAuthFailure(r, ip, "device_revoked")
							writeAuthErrorStatus(w, http.StatusForbidden, "device_revoked",
								"device has been administratively disabled")
							return
						}
						// Infrastructure failure (not a definitive
						// revocation): fail OPEN. The token is already
						// cryptographically valid, and the
						// security-sensitive mobile self-service endpoints
						// independently re-check device status at the
						// service layer and fail CLOSED there. A transient
						// status-store outage must not lock the entire
						// mobile fleet out of every endpoint.
					}
				}
			}
			o.recordAuthSuccess(ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractMobileClaims pulls the device-bound custom claims off a
// verified mobile session JWT. Returns the zero value when none of
// the mobile claims are present (operator-console / API-key auth),
// which the caller treats as "not a mobile session". It operates on
// a plain claim map so the call site does not depend on the JWT
// library (which lives behind the build-tagged verifier).
func extractMobileClaims(claims map[string]any) MobileClaims {
	var mc MobileClaims
	mc.TokenType, _ = claims["token_type"].(string)
	mc.DeviceKey, _ = claims["device_key"].(string)
	mc.OIDCSubject, _ = claims["oidc_sub"].(string)
	mc.OIDCIssuer, _ = claims["oidc_iss"].(string)
	return mc
}

// writeAuthError emits a structured 401 JSON response.
func writeAuthError(w http.ResponseWriter, code string) {
	writeAuthErrorStatus(w, http.StatusUnauthorized, code, "authentication failed")
}

// writeAuthErrorStatus emits a structured auth-failure JSON response
// with an explicit status code + message, for cases beyond a plain
// 401 (e.g. a 403 when a mobile device's session has been revoked).
func writeAuthErrorStatus(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

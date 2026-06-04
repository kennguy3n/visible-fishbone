package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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

// Auth wires JWT (operator console) and API-key (M2M) auth. At
// least one credential is required for the protected routes. A
// request with neither is rejected 401.
func Auth(cfg *config.Auth, keys APIKeyLookup, opts ...AuthOption) func(http.Handler) http.Handler {
	header := cfg.APIKeyHeader
	if header == "" {
		header = "X-SNG-API-Key"
	}
	secret := []byte(cfg.JWTSecret)
	var o authOptions
	for _, fn := range opts {
		fn(&o)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// API-key path — try first because it's cheaper than
			// JWT verification.
			if k := r.Header.Get(header); k != "" {
				if keys == nil {
					writeAuthError(w, "api_key_not_configured")
					return
				}
				info, err := keys.Lookup(r.Context(), k)
				if err != nil {
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
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// JWT path.
			authz := r.Header.Get("Authorization")
			if !strings.HasPrefix(authz, "Bearer ") {
				writeAuthError(w, "missing_credentials")
				return
			}
			raw := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
			if raw == "" {
				writeAuthError(w, "missing_credentials")
				return
			}
			if len(secret) == 0 {
				writeAuthError(w, "jwt_not_configured")
				return
			}
			claims := jwt.MapClaims{}
			tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, errors.New("unexpected signing method")
				}
				return secret, nil
			}, jwt.WithIssuer(cfg.JWTIssuer), jwt.WithAudience(cfg.JWTAudience), jwt.WithValidMethods([]string{"HS256"}))
			if err != nil || !tok.Valid {
				writeAuthError(w, "invalid_token")
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
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractMobileClaims pulls the device-bound custom claims off a
// verified mobile session JWT. Returns the zero value when none of
// the mobile claims are present (operator-console / API-key auth),
// which the caller treats as "not a mobile session".
func extractMobileClaims(claims jwt.MapClaims) MobileClaims {
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

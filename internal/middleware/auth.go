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

// Auth wires JWT (operator console) and API-key (M2M) auth. At
// least one credential is required for the protected routes. A
// request with neither is rejected 401.
func Auth(cfg *config.Auth, keys APIKeyLookup) func(http.Handler) http.Handler {
	header := cfg.APIKeyHeader
	if header == "" {
		header = "X-SNG-API-Key"
	}
	secret := []byte(cfg.JWTSecret)

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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": "authentication failed"},
	})
}

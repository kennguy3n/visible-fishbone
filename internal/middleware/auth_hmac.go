//go:build !production

package middleware

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// verifyBearerJWT verifies a Bearer token using the symmetric (HMAC)
// dev-signing scheme and returns its claims as a plain map.
//
// This implementation is compiled ONLY into non-production builds
// (the //go:build !production tag above). It is the developer
// convenience path that lets an operator mint and verify console
// JWTs with a shared AUTH_JWT_SECRET without standing up an IdP.
//
// In production (uat/prod) identity is terminated at the gateway via
// OIDC and this file is excluded from the binary entirely; the
// production stub in auth_hmac_prod.go is linked instead, so a
// production binary has no HMAC verification code at all. The config
// layer additionally refuses to boot a production environment that
// sets AUTH_JWT_SECRET (see internal/config.validate). Together these
// make the HMAC path unreachable in production by construction rather
// than by runtime check. See SECURITY.md.
//
// On success it returns (claims, "", nil). On failure it returns a
// nil map, a stable error code suitable for the auth-failure JSON
// envelope, and a non-nil error.
func verifyBearerJWT(cfg *config.Auth, raw string) (map[string]any, string, error) {
	secret := []byte(cfg.JWTSecret)
	if len(secret) == 0 {
		return nil, "jwt_not_configured", errors.New("middleware: jwt secret not configured")
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return secret, nil
	}, jwt.WithIssuer(cfg.JWTIssuer), jwt.WithAudience(cfg.JWTAudience), jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !tok.Valid {
		return nil, "invalid_token", errors.New("middleware: invalid token")
	}
	return map[string]any(claims), "", nil
}

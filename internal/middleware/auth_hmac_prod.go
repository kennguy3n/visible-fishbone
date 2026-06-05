//go:build production

package middleware

import (
	"errors"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// ErrHMACDisabledInProduction is returned by the production stub of
// verifyBearerJWT. Its presence in a production binary is the whole
// point of the build tag: the symmetric (HMAC) JWT verification code
// is not compiled in, so a production control plane cannot verify an
// HMAC-signed operator token even if one is presented. Production
// terminates identity at the gateway via OIDC instead. See
// SECURITY.md and the non-production implementation in auth_hmac.go.
var ErrHMACDisabledInProduction = errors.New("middleware: HMAC JWT verification is disabled in production builds")

// verifyBearerJWT is the production stub: it always refuses, so the
// Bearer-token path returns a stable "jwt_hmac_disabled" auth error.
// The cfg/raw arguments are intentionally ignored — no HMAC secret is
// consulted and no token is parsed.
func verifyBearerJWT(_ *config.Auth, _ string) (map[string]any, string, error) {
	return nil, "jwt_hmac_disabled", ErrHMACDisabledInProduction
}

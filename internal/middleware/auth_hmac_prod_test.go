//go:build production

package middleware

import (
	"errors"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// TestVerifyBearerJWT_DisabledInProduction asserts that the
// production-tagged stub refuses every Bearer token regardless of the
// configured secret, so a production binary cannot verify an
// HMAC-signed token. This test compiles and runs only under
// `-tags production` (matching the stub it exercises).
func TestVerifyBearerJWT_DisabledInProduction(t *testing.T) {
	cfg := &config.Auth{JWTSecret: "supersecret", JWTIssuer: "sng-control", JWTAudience: "sng-control"}
	claims, code, err := verifyBearerJWT(cfg, "any.bearer.token")
	if claims != nil {
		t.Errorf("claims = %v, want nil", claims)
	}
	if code != "jwt_hmac_disabled" {
		t.Errorf("code = %q, want jwt_hmac_disabled", code)
	}
	if !errors.Is(err, ErrHMACDisabledInProduction) {
		t.Errorf("err = %v, want ErrHMACDisabledInProduction", err)
	}
}

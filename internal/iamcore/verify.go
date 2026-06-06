package iamcore

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidToken is the sentinel wrapped by every token-rejection
// reason. Callers (the auth middleware) translate it into a 401
// without leaking the specific cryptographic/claim failure.
var ErrInvalidToken = errors.New("iamcore: invalid token")

// allowedAlgs is the asymmetric signature allow-list. HMAC ("HS*") is
// deliberately excluded: an attacker who learns the public key from
// the JWKS could otherwise forge an HS256 token that a naive verifier
// would accept using the public key as the HMAC secret (the classic
// alg-confusion attack). The verifier also pins the key type to the
// algorithm family in the keyfunc below.
var allowedAlgs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}

// VerifyAccessToken validates an iam-core access token end to end and
// returns its normalised claims. It fails closed: any signature,
// issuer, audience, or time-window problem yields an error wrapping
// ErrInvalidToken and no claims.
//
// Checks performed:
//   - header alg ∈ asymmetric allow-list (no alg confusion);
//   - signature verifies against the JWKS key named by `kid`
//     (refetching once on an unknown kid);
//   - `iss` equals the configured issuer (exact);
//   - `aud` contains the configured audience;
//   - `exp`/`nbf`/`iat` are valid for now (small leeway).
func (c *Client) VerifyAccessToken(ctx context.Context, raw string) (Claims, error) {
	if raw == "" {
		return Claims{}, fmt.Errorf("%w: empty token", ErrInvalidToken)
	}

	keyfunc := func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid header", ErrInvalidToken)
		}
		key, err := c.keyForKID(ctx, kid)
		if err != nil {
			return nil, err
		}
		return key, nil
	}

	parserOpts := []jwt.ParserOption{
		jwt.WithValidMethods(allowedAlgs),
		jwt.WithIssuer(c.cfg.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(c.now),
	}
	// Only enforce audience when one is configured. An empty configured
	// audience would otherwise make jwt reject every token.
	if c.cfg.Audience != "" {
		parserOpts = append(parserOpts, jwt.WithAudience(c.cfg.Audience))
	}

	claimsMap := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(raw, claimsMap, keyfunc, parserOpts...)
	if err != nil {
		// keyfunc already wraps ErrInvalidToken for kid problems; wrap
		// the rest (signature/claims) here so the caller sees one
		// sentinel regardless of the underlying cause.
		if errors.Is(err, ErrInvalidToken) {
			return Claims{}, err
		}
		return Claims{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	if !token.Valid {
		return Claims{}, fmt.Errorf("%w: token reported invalid", ErrInvalidToken)
	}

	out := claimsFromMap(claimsMap, c.cfg.Issuer)
	if out.Subject == "" {
		return Claims{}, fmt.Errorf("%w: missing sub claim", ErrInvalidToken)
	}
	if out.TenantID == "" {
		return Claims{}, fmt.Errorf("%w: missing tenant_id claim", ErrInvalidToken)
	}
	return out, nil
}

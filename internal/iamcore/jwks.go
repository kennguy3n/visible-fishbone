package iamcore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// jwksMinRefreshInterval throttles JWKS refetches triggered by an
// unknown `kid`. Without it, a flood of tokens bearing bogus key ids
// would hammer the provider's JWKS endpoint (a trivial DoS amplifier).
// A legitimate key rotation is still picked up within this window.
const jwksMinRefreshInterval = 30 * time.Second

// jwkSet is the JWKS document shape (RFC 7517).
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// keyForKID returns the cached public key for kid, refetching the
// JWKS once (throttled) when the kid is unknown — the standard
// response to a key rotation. It fails closed: a fetch error or an
// absent key returns an error and the caller rejects the token.
func (c *Client) keyForKID(ctx context.Context, kid string) (any, error) {
	c.jwksMu.RLock()
	key, ok := c.jwksKeys[kid]
	fetched := c.jwksFetched
	c.jwksMu.RUnlock()
	if ok {
		return key, nil
	}

	// Unknown kid: refresh, unless we just did (throttle).
	if !fetched.IsZero() && c.now().Sub(fetched) < jwksMinRefreshInterval {
		return nil, fmt.Errorf("iamcore: no signing key for kid %q (refresh throttled)", kid)
	}
	if err := c.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	c.jwksMu.RLock()
	key, ok = c.jwksKeys[kid]
	c.jwksMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("iamcore: no signing key for kid %q after refresh", kid)
	}
	return key, nil
}

// refreshJWKS fetches and parses the JWKS, replacing the cache. A
// fetch that yields zero usable keys is treated as an error and the
// previous cache is left intact (fail-closed; do not blow away good
// keys because of a transient bad response).
func (c *Client) refreshJWKS(ctx context.Context) error {
	if c.cfg.JWKSURL == "" {
		return fmt.Errorf("%w: JWKS URL", ErrNotConfigured)
	}
	var set jwkSet
	if err := c.getJSON(ctx, c.cfg.JWKSURL, &set); err != nil {
		return fmt.Errorf("iamcore: fetch jwks: %w", err)
	}
	keys, err := parseJWKS(set)
	if err != nil {
		return err
	}
	c.jwksMu.Lock()
	c.jwksKeys = keys
	c.jwksFetched = c.now()
	c.jwksMu.Unlock()
	return nil
}

// parseJWKS converts a JWKS document into a kid->public-key map,
// skipping non-signing and unparseable entries.
func parseJWKS(set jwkSet) (map[string]any, error) {
	keys := map[string]any{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if k.Kid == "" {
			continue
		}
		var (
			pub any
			err error
		)
		switch k.Kty {
		case "RSA", "":
			pub, err = parseRSAJWK(k)
		case "EC":
			pub, err = parseECJWK(k)
		default:
			continue
		}
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("iamcore: jwks contained no usable RSA or EC signing keys")
	}
	return keys, nil
}

func parseRSAJWK(k jwk) (*rsa.PublicKey, error) {
	if k.N == "" || k.E == "" {
		return nil, errors.New("rsa jwk missing modulus or exponent")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, errors.New("invalid rsa exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

func parseECJWK(k jwk) (*ecdsa.PublicKey, error) {
	if k.X == "" || k.Y == "" {
		return nil, errors.New("ec jwk missing x or y coordinate")
	}
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ec curve %q", k.Crv)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode ec x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode ec y: %w", err)
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("ec jwk point is not on the named curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

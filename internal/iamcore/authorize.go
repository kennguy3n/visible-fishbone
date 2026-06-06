package iamcore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// PKCE holds a generated PKCE pair for one authorization-code flow.
// Verifier is kept server-side (in the login state) and replayed at
// the token exchange; Challenge is sent on the authorize redirect.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string // always "S256"
}

// GeneratePKCE returns a fresh S256 PKCE pair (RFC 7636). The verifier
// is 43 chars of base64url-encoded entropy (32 random bytes), within
// the spec's 43–128 length bounds.
func GeneratePKCE() (PKCE, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return PKCE{}, fmt.Errorf("iamcore: generate pkce verifier: %w", err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return PKCE{Verifier: verifier, Challenge: challenge, Method: "S256"}, nil
}

// GenerateState returns a high-entropy opaque value suitable for the
// OAuth2 `state` (CSRF binding) or OIDC `nonce`.
func GenerateState() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("iamcore: generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// AuthorizeParams are the per-request inputs to the authorization
// redirect. RedirectURI must exactly match the value later passed to
// ExchangeCode.
type AuthorizeParams struct {
	RedirectURI   string
	State         string
	Nonce         string
	CodeChallenge string
	// Scopes requested. When empty, defaults to OIDC + offline_access.
	Scopes []string
	// Prompt, when set (e.g. "login"), forces re-authentication —
	// used by the MFA step-up path to demand a fresh factor.
	Prompt string
	// ACRValues optionally requests an authentication context (e.g.
	// an MFA assurance level) from iam-core.
	ACRValues string
}

// defaultAuthorizeScopes is the scope set requested when the caller
// does not specify one: OIDC identity + a refresh token.
var defaultAuthorizeScopes = []string{"openid", "profile", "email", "offline_access"}

// AuthorizeURL builds the iam-core /oauth2/authorize redirect for the
// authorization-code + PKCE flow. The authorization endpoint is taken
// from discovery (falling back to the conventional path), so the
// control plane never hard-codes it.
func (c *Client) AuthorizeURL(ctx context.Context, p AuthorizeParams) (string, error) {
	if c.cfg.ClientID == "" {
		return "", fmt.Errorf("%w: client id", ErrNotConfigured)
	}
	if p.RedirectURI == "" {
		return "", fmt.Errorf("iamcore: authorize: redirect URI required")
	}
	if p.State == "" {
		return "", fmt.Errorf("iamcore: authorize: state required")
	}
	if p.CodeChallenge == "" {
		return "", fmt.Errorf("iamcore: authorize: PKCE code challenge required")
	}

	ep, _ := c.Discovery(ctx)
	authEndpoint := ep.AuthorizationEndpoint
	if authEndpoint == "" {
		authEndpoint = c.cfg.Issuer + "/oauth2/authorize"
	}
	u, err := url.Parse(authEndpoint)
	if err != nil {
		return "", fmt.Errorf("iamcore: parse authorize endpoint: %w", err)
	}

	scopes := p.Scopes
	if len(scopes) == 0 {
		scopes = defaultAuthorizeScopes
	}

	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", p.State)
	q.Set("code_challenge", p.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if c.cfg.Audience != "" {
		q.Set("audience", c.cfg.Audience)
	}
	if p.Nonce != "" {
		q.Set("nonce", p.Nonce)
	}
	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}
	if p.ACRValues != "" {
		q.Set("acr_values", p.ACRValues)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

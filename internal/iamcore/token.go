package iamcore

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// tokenResponse is the OAuth2 token endpoint response (RFC 6749 §5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// TokenResult is the normalised result of an authorization-code or
// refresh exchange used by the admin SSO flow.
type TokenResult struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Scopes       []string
}

// mgmtTokenEarlyRefresh re-mints the Management client_credentials
// token this long before its actual expiry, so an in-flight call
// never races the expiry boundary.
const mgmtTokenEarlyRefresh = 60 * time.Second

// managementToken returns a valid client_credentials access token for
// the Management API, minting and caching one on first use and
// re-minting it before expiry. Concurrent callers share a single
// in-flight mint under mgmtMu.
func (c *Client) managementToken(ctx context.Context) (string, error) {
	if c.cfg.ClientID == "" || c.cfg.ClientSecret == "" {
		return "", fmt.Errorf("%w: management client credentials", ErrNotConfigured)
	}
	c.mgmtMu.Lock()
	defer c.mgmtMu.Unlock()

	if c.mgmtToken != "" && c.now().Before(c.mgmtExpires.Add(-mgmtTokenEarlyRefresh)) {
		return c.mgmtToken, nil
	}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if c.cfg.ManagementAudience != "" {
		form.Set("audience", c.cfg.ManagementAudience)
	}

	var tr tokenResponse
	if err := c.postForm(ctx, c.tokenEndpoint(), form, c.cfg.ClientID, c.cfg.ClientSecret, &tr); err != nil {
		return "", fmt.Errorf("iamcore: mint management token: %w", err)
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("iamcore: management token response missing access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute // conservative default when omitted
	}
	c.mgmtToken = tr.AccessToken
	c.mgmtExpires = c.now().Add(ttl)
	return c.mgmtToken, nil
}

// ExchangeCode completes the authorization-code + PKCE exchange at the
// token endpoint, returning the issued tokens. redirectURI and
// codeVerifier must match the values used to build the authorization
// request.
func (c *Client) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (TokenResult, error) {
	if c.cfg.ClientID == "" {
		return TokenResult{}, fmt.Errorf("%w: client id", ErrNotConfigured)
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", codeVerifier)
	form.Set("client_id", c.cfg.ClientID)

	ep, _ := c.Discovery(ctx)
	tokenEndpoint := ep.TokenEndpoint
	if tokenEndpoint == "" {
		tokenEndpoint = c.tokenEndpoint()
	}

	var tr tokenResponse
	// Confidential clients authenticate with HTTP Basic; the client_id
	// in the form is harmless and helps providers that accept either.
	if err := c.postForm(ctx, tokenEndpoint, form, c.cfg.ClientID, c.cfg.ClientSecret, &tr); err != nil {
		return TokenResult{}, fmt.Errorf("iamcore: exchange authorization code: %w", err)
	}
	if tr.AccessToken == "" {
		return TokenResult{}, fmt.Errorf("iamcore: token response missing access_token")
	}
	ttl := time.Duration(tr.ExpiresIn) * time.Second
	res := TokenResult{
		AccessToken:  tr.AccessToken,
		IDToken:      tr.IDToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		Scopes:       strings.Fields(tr.Scope),
	}
	if ttl > 0 {
		res.ExpiresAt = c.now().Add(ttl)
	}
	return res, nil
}

func (c *Client) tokenEndpoint() string { return c.cfg.Issuer + "/oauth2/token" }

package iamcore

import (
	"context"
	"fmt"
	"time"
)

// discoveryTTL bounds how long a fetched OIDC discovery document is
// trusted before a refetch. Endpoints rarely change; a day keeps the
// SSO path fast without pinning a stale config indefinitely.
const discoveryTTL = 24 * time.Hour

// discoveryDoc is the subset of the OIDC discovery document
// (/.well-known/openid-configuration) the SSO login flow needs.
type discoveryDoc struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

// Endpoints is the resolved set of iam-core endpoints the control
// plane drives for the admin SSO flow and step-up.
type Endpoints struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	IntrospectionEndpoint string
}

// Discovery returns the iam-core endpoints, fetching and caching the
// discovery document on first use (and after the TTL). On a fetch
// failure it falls back to the conventional paths derived from the
// issuer so the SSO flow degrades gracefully rather than failing
// closed on a transient discovery outage.
func (c *Client) Discovery(ctx context.Context) (Endpoints, error) {
	c.discMu.RLock()
	doc := c.disc
	fresh := doc != nil && c.now().Sub(c.discFetched) < discoveryTTL
	c.discMu.RUnlock()
	if fresh {
		return c.endpointsFromDoc(doc), nil
	}

	if c.cfg.DiscoveryURL == "" {
		return c.fallbackEndpoints(), fmt.Errorf("%w: discovery URL", ErrNotConfigured)
	}
	var fetched discoveryDoc
	if err := c.getJSON(ctx, c.cfg.DiscoveryURL, &fetched); err != nil {
		// Degrade to conventional endpoints; surface the error so the
		// caller can log it, but still return a usable set.
		return c.fallbackEndpoints(), fmt.Errorf("iamcore: fetch discovery: %w", err)
	}
	c.discMu.Lock()
	c.disc = &fetched
	c.discFetched = c.now()
	c.discMu.Unlock()
	return c.endpointsFromDoc(&fetched), nil
}

func (c *Client) endpointsFromDoc(doc *discoveryDoc) Endpoints {
	fb := c.fallbackEndpoints()
	ep := Endpoints{
		Issuer:                firstNonEmpty(doc.Issuer, fb.Issuer),
		AuthorizationEndpoint: firstNonEmpty(doc.AuthorizationEndpoint, fb.AuthorizationEndpoint),
		TokenEndpoint:         firstNonEmpty(doc.TokenEndpoint, fb.TokenEndpoint),
		IntrospectionEndpoint: firstNonEmpty(doc.IntrospectionEndpoint, fb.IntrospectionEndpoint),
	}
	return ep
}

// fallbackEndpoints are the conventional iam-core paths used when the
// discovery document is unavailable or omits an endpoint.
func (c *Client) fallbackEndpoints() Endpoints {
	return Endpoints{
		Issuer:                c.cfg.Issuer,
		AuthorizationEndpoint: c.cfg.Issuer + "/oauth2/authorize",
		TokenEndpoint:         c.cfg.Issuer + "/oauth2/token",
		IntrospectionEndpoint: c.cfg.Issuer + "/oauth2/introspect",
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

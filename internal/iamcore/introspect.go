package iamcore

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// Introspection is the normalised RFC 7662 introspection result used
// by the MFA step-up path to confirm an active, MFA-satisfied session.
type Introspection struct {
	Active       bool
	Subject      string
	TenantID     string
	Scopes       []string
	AMR          []string
	MFASatisfied bool
	raw          map[string]any
}

// Raw exposes the full introspection response for callers that need a
// claim not surfaced as a typed field.
func (i Introspection) Raw() map[string]any { return i.raw }

// Introspect calls iam-core's /oauth2/introspect (RFC 7662) for the
// given token, authenticated as this confidential client. It is the
// authoritative server-side check for step-up: an inactive token, or
// an active one lacking an MFA marker, fails the step-up gate.
func (c *Client) Introspect(ctx context.Context, token string) (Introspection, error) {
	if c.cfg.ClientID == "" {
		return Introspection{}, fmt.Errorf("%w: client id", ErrNotConfigured)
	}
	if strings.TrimSpace(token) == "" {
		return Introspection{}, fmt.Errorf("iamcore: introspect: empty token")
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")

	ep, _ := c.Discovery(ctx)
	endpoint := ep.IntrospectionEndpoint
	if endpoint == "" {
		endpoint = c.cfg.Issuer + "/oauth2/introspect"
	}

	var raw map[string]any
	if err := c.postForm(ctx, endpoint, form, c.cfg.ClientID, c.cfg.ClientSecret, &raw); err != nil {
		return Introspection{}, fmt.Errorf("iamcore: introspect: %w", err)
	}
	active, _ := raw["active"].(bool)
	out := Introspection{
		Active:   active,
		Subject:  stringClaim(raw["sub"]),
		TenantID: stringClaim(raw["tenant_id"]),
		Scopes:   splitScopes(stringClaim(raw["scope"])),
		AMR:      stringSlice(raw["amr"]),
		raw:      raw,
	}
	out.MFASatisfied = active && mfaFromClaims(raw, out.AMR)
	return out, nil
}

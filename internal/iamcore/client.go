// Package iamcore is the ShieldNet Gateway client for the upstream
// uneycom/iam-core OAuth2 / OIDC identity provider (Session 2A).
//
// It is the single integration point both halves of the control
// plane use to talk to iam-core:
//
//   - the auth middleware validates incoming iam-core access tokens
//     against the provider's JWKS (Verifier);
//   - the admin SSO login flow drives the PKCE authorization-code
//     exchange against the discovery document (Client.Discovery,
//     Client.ExchangeCode);
//   - the SCIM bridge propagates user lifecycle changes to the
//     Management API authenticated with a cached client_credentials
//     token (Client.Management);
//   - MFA step-up confirms an active, MFA-satisfied session via RFC
//     7662 introspection (Client.Introspect).
//
// Every outbound call honours the caller's context deadline and reads
// at most a bounded response body so a hostile or broken endpoint
// cannot exhaust memory. The contract (endpoints, claim names,
// audience semantics) is the canonical ShieldNet <-> iam-core spec
// shared by both ShieldNet products.
package iamcore

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// leeway tolerates small clock skew between ShieldNet and iam-core
// when validating exp/nbf/iat.
const leeway = 60 * time.Second

// maxResponseBody caps every response body read from iam-core. The
// JWKS, discovery, token, introspection, and management payloads are
// all small JSON documents; 1 MiB is generous headroom while still
// refusing an endpoint that streams unboundedly.
const maxResponseBody = 1 << 20

// Config carries the iam-core connection settings. It mirrors the
// IAM_CORE_* environment contract; internal/config.IAMCore maps onto
// it so the wiring in main() stays a single struct copy.
type Config struct {
	// Issuer is the iam-core base URL and the exact `iss` claim
	// expected on every token (trailing slash trimmed).
	Issuer string
	// JWKSURL is the JWKS endpoint. Derived as Issuer+"/oauth2/jwks"
	// when empty.
	JWKSURL string
	// DiscoveryURL is the OIDC discovery document. Derived as
	// Issuer+"/.well-known/openid-configuration" when empty.
	DiscoveryURL string
	// ClientID / ClientSecret identify this product as a confidential
	// OAuth2 client (used for the authorization-code exchange and to
	// mint the client_credentials Management token).
	ClientID     string
	ClientSecret string
	// Audience is the expected `aud` claim on incoming access tokens.
	Audience string
	// ManagementBaseURL hosts the /api/v1/management/* endpoints.
	// Derived as Issuer when empty.
	ManagementBaseURL string
	// ManagementAudience is the audience requested when minting the
	// client_credentials token used to authenticate Management calls.
	// Empty means request no explicit audience (iam-core then issues
	// for the default management audience).
	ManagementAudience string
}

// normalize fills derived defaults and trims trailing slashes so the
// issuer compares exactly against a token's `iss`.
func (c Config) normalize() Config {
	out := c
	out.Issuer = strings.TrimRight(strings.TrimSpace(out.Issuer), "/")
	if out.JWKSURL == "" && out.Issuer != "" {
		out.JWKSURL = out.Issuer + "/oauth2/jwks"
	}
	if out.DiscoveryURL == "" && out.Issuer != "" {
		out.DiscoveryURL = out.Issuer + "/.well-known/openid-configuration"
	}
	if out.ManagementBaseURL == "" {
		out.ManagementBaseURL = out.Issuer
	}
	out.ManagementBaseURL = strings.TrimRight(strings.TrimSpace(out.ManagementBaseURL), "/")
	return out
}

// Enabled reports whether enough configuration is present to talk to
// iam-core at all. A zero/blank Issuer means the integration is off
// and the caller should not wire the middleware or bridge.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Issuer) != ""
}

// ErrNotConfigured is returned by Client methods that require a piece
// of configuration that was left empty (e.g. Management calls without
// a client id/secret to mint the M2M token).
var ErrNotConfigured = errors.New("iamcore: not configured")

// Client is the concurrency-safe iam-core API client. The zero value
// is not usable; construct it with New.
type Client struct {
	cfg        Config
	httpClient *http.Client
	now        func() time.Time

	// jwks cache (signature validation).
	jwksMu      sync.RWMutex
	jwksKeys    map[string]any
	jwksFetched time.Time

	// discovery cache (SSO authorize/token endpoints).
	discMu      sync.RWMutex
	disc        *discoveryDoc
	discFetched time.Time

	// management client_credentials token cache.
	mgmtMu      sync.Mutex
	mgmtToken   string
	mgmtExpires time.Time
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient overrides the default HTTP client (e.g. to inject a
// mTLS transport or a test client). The default has a 15s timeout.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithClock overrides the time source, used by tests to drive cache
// expiry deterministically. Production passes nothing and gets
// time.Now.
func WithClock(now func() time.Time) Option {
	return func(c *Client) {
		if now != nil {
			c.now = now
		}
	}
}

// New constructs a Client for the given configuration.
func New(cfg Config, opts ...Option) *Client {
	c := &Client{
		cfg:        cfg.normalize(),
		httpClient: &http.Client{Timeout: 15 * time.Second},
		now:        func() time.Time { return time.Now().UTC() },
		jwksKeys:   map[string]any{},
	}
	for _, fn := range opts {
		fn(c)
	}
	return c
}

// Issuer returns the canonical issuer the client validates against.
// The auth middleware uses it to route a Bearer token to the iam-core
// verifier only when the token's `iss` matches.
func (c *Client) Issuer() string { return c.cfg.Issuer }

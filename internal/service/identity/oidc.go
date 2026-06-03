package identity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultDiscoveryCacheTTL is how long an OIDC discovery document and
// its JWKS are cached per issuer before re-fetching.
const DefaultDiscoveryCacheTTL = 24 * time.Hour

// DefaultSessionTTL is the fallback SNG mobile session lifetime when
// the caller does not configure one.
const DefaultSessionTTL = time.Hour

// idTokenSigningMethods is the set of asymmetric algorithms accepted
// on incoming OIDC ID tokens. Both RSA (RS*) and ECDSA (ES*) are
// supported so EC-signing providers (e.g. Apple, which signs with
// ES256, and custom_oidc issuers) validate alongside Google, Microsoft
// and Okta. Symmetric (HS*) algorithms are rejected outright: a JWKS
// only ever publishes asymmetric public keys, so an HS-signed token
// would be an attempt to confuse the verifier into treating a public
// key as an HMAC secret.
var idTokenSigningMethods = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

// SessionSigner mints SNG session JWTs that the standard
// middleware.Auth chain accepts. It MUST mirror the operator-console
// signing parameters (HMAC secret + iss/aud) so a mobile-minted
// session authenticates the same way an operator token does.
type SessionSigner struct {
	Secret   []byte
	Issuer   string
	Audience string
}

// OIDCOptions tunes the OIDCService. Zero values fall back to the
// package defaults.
type OIDCOptions struct {
	SessionTTL        time.Duration
	DiscoveryCacheTTL time.Duration
	// AutoProvision enables just-in-time user creation when a
	// validated ID token maps to an unknown email.
	AutoProvision bool
}

// OIDCService implements control-plane IdP federation for mobile
// native SSO. A mobile agent performs the OIDC dance itself and
// presents the resulting ID token; this service validates it against
// the tenant's registered provider config (signature via JWKS +
// iss/aud/exp/email claims), maps it to an SNG user identity, and
// mints an SNG session bound to BOTH the device's Ed25519 public key
// AND the user's OIDC subject.
//
// OIDC tokens are never persisted: only the validated identity claim
// flows downstream. Discovery documents and JWKS are cached per
// issuer (default 24h) to avoid a network round-trip on every token
// exchange.
type OIDCService struct {
	configs    repository.IDPConfigRepository
	users      repository.UserRepository
	audit      repository.AuditLogRepository
	signer     SessionSigner
	logger     *slog.Logger
	httpClient *http.Client
	nowFunc    func() time.Time

	sessionTTL    time.Duration
	discoveryTTL  time.Duration
	autoProvision bool

	mu             sync.Mutex
	discoveryCache map[string]*discoveryEntry
}

// NewOIDCService returns a ready-to-use OIDC federation service.
func NewOIDCService(
	configs repository.IDPConfigRepository,
	users repository.UserRepository,
	audit repository.AuditLogRepository,
	signer SessionSigner,
	opts OIDCOptions,
	logger *slog.Logger,
) *OIDCService {
	if logger == nil {
		logger = slog.Default()
	}
	sessionTTL := opts.SessionTTL
	if sessionTTL <= 0 {
		sessionTTL = DefaultSessionTTL
	}
	discoveryTTL := opts.DiscoveryCacheTTL
	if discoveryTTL <= 0 {
		discoveryTTL = DefaultDiscoveryCacheTTL
	}
	return &OIDCService{
		configs:        configs,
		users:          users,
		audit:          audit,
		signer:         signer,
		logger:         logger,
		httpClient:     &http.Client{Timeout: 10 * time.Second},
		nowFunc:        func() time.Time { return time.Now().UTC() },
		sessionTTL:     sessionTTL,
		discoveryTTL:   discoveryTTL,
		autoProvision:  opts.AutoProvision,
		discoveryCache: map[string]*discoveryEntry{},
	}
}

// TokenExchangeInput is the input to IssueSessionFromIDToken.
type TokenExchangeInput struct {
	// IDToken is the OIDC ID token the mobile agent obtained natively.
	IDToken string
	// Issuer optionally selects which registered provider to validate
	// against. When empty the issuer is read from the (unverified)
	// token's `iss` claim and matched against the tenant's configs.
	Issuer string
	// DevicePublicKey is the base64 Ed25519 public key of the enrolled
	// device; it is bound into the minted SNG session.
	DevicePublicKey string
}

// RefreshInput is the input to RefreshSession.
type RefreshInput struct {
	// RefreshToken is the IdP refresh token issued during the original
	// native OIDC flow. It is exchanged at the provider's token
	// endpoint for a fresh ID token and never persisted server-side.
	RefreshToken string
	// Issuer selects which registered provider's token endpoint to
	// call. Required (the refresh token alone carries no issuer hint).
	Issuer string
	// DevicePublicKey re-binds the refreshed session to the same
	// device.
	DevicePublicKey string
}

// ValidatedIdentity is the SNG identity resolved from a validated ID
// token.
type ValidatedIdentity struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Email    string
	// Subject is the OIDC `sub` claim — the stable, provider-scoped
	// user identifier the SNG session is bound to.
	Subject  string
	Provider repository.IDPProviderType
	Issuer   string
	Groups   []string
}

// SessionResult is the outcome of a successful token exchange or
// refresh: a minted SNG session token plus the identity + device
// binding it encodes.
type SessionResult struct {
	AccessToken     string
	ExpiresAt       time.Time
	TTL             time.Duration
	Identity        ValidatedIdentity
	DevicePublicKey string
}

// IssueSessionFromIDToken validates a mobile-presented OIDC ID token
// and mints an SNG session bound to the device + user identity.
func (s *OIDCService) IssueSessionFromIDToken(
	ctx context.Context,
	tenantID uuid.UUID,
	in TokenExchangeInput,
) (SessionResult, error) {
	if in.IDToken == "" {
		return SessionResult{}, fmt.Errorf("id_token is required: %w", repository.ErrInvalidArgument)
	}
	if in.DevicePublicKey == "" {
		return SessionResult{}, fmt.Errorf("device_public_key is required: %w", repository.ErrInvalidArgument)
	}

	issuer := in.Issuer
	if issuer == "" {
		var err error
		issuer, err = unverifiedIssuer(in.IDToken)
		if err != nil {
			return SessionResult{}, err
		}
	}

	cfg, err := s.resolveConfig(ctx, tenantID, issuer)
	if err != nil {
		return SessionResult{}, err
	}

	claims, err := s.validateIDToken(ctx, cfg, in.IDToken)
	if err != nil {
		return SessionResult{}, err
	}

	ident, err := s.mapIdentity(ctx, tenantID, cfg, claims)
	if err != nil {
		return SessionResult{}, err
	}

	res, err := s.mintSession(ident, in.DevicePublicKey)
	if err != nil {
		return SessionResult{}, err
	}
	s.recordAudit(ctx, tenantID, ident, "mobile.session.issued")
	return res, nil
}

// RefreshSession exchanges an IdP refresh token for a fresh ID token
// at the provider's token endpoint, re-validates it, and mints a new
// SNG session re-bound to the device.
func (s *OIDCService) RefreshSession(
	ctx context.Context,
	tenantID uuid.UUID,
	in RefreshInput,
) (SessionResult, error) {
	if in.RefreshToken == "" {
		return SessionResult{}, fmt.Errorf("refresh_token is required: %w", repository.ErrInvalidArgument)
	}
	if in.Issuer == "" {
		return SessionResult{}, fmt.Errorf("issuer is required: %w", repository.ErrInvalidArgument)
	}
	if in.DevicePublicKey == "" {
		return SessionResult{}, fmt.Errorf("device_public_key is required: %w", repository.ErrInvalidArgument)
	}

	cfg, err := s.resolveConfig(ctx, tenantID, in.Issuer)
	if err != nil {
		return SessionResult{}, err
	}
	disc, err := s.discoveryFor(ctx, cfg.IssuerURL)
	if err != nil {
		return SessionResult{}, err
	}
	if disc.doc.TokenEndpoint == "" {
		return SessionResult{}, fmt.Errorf("provider %q has no token endpoint: %w", cfg.IssuerURL, repository.ErrInvalidArgument)
	}

	idToken, err := s.exchangeRefreshToken(ctx, disc.doc.TokenEndpoint, cfg.ClientID, in.RefreshToken)
	if err != nil {
		return SessionResult{}, err
	}

	claims, err := s.validateIDToken(ctx, cfg, idToken)
	if err != nil {
		return SessionResult{}, err
	}
	ident, err := s.mapIdentity(ctx, tenantID, cfg, claims)
	if err != nil {
		return SessionResult{}, err
	}
	res, err := s.mintSession(ident, in.DevicePublicKey)
	if err != nil {
		return SessionResult{}, err
	}
	s.recordAudit(ctx, tenantID, ident, "mobile.session.refreshed")
	return res, nil
}

// resolveConfig finds the tenant's enabled IdP config whose issuer
// matches `issuer`. Returns ErrNotFound when none matches.
func (s *OIDCService) resolveConfig(ctx context.Context, tenantID uuid.UUID, issuer string) (repository.IDPConfig, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	configs, err := s.configs.List(ctx, tenantID)
	if err != nil {
		return repository.IDPConfig{}, err
	}
	for _, c := range configs {
		if !c.Enabled {
			continue
		}
		if strings.TrimRight(c.IssuerURL, "/") == issuer {
			return c, nil
		}
	}
	return repository.IDPConfig{}, fmt.Errorf("no enabled idp config for issuer %q: %w", issuer, repository.ErrNotFound)
}

// validateIDToken verifies the token signature against the provider's
// JWKS and validates the iss/aud/exp claims. Returns the parsed
// claims on success.
func (s *OIDCService) validateIDToken(ctx context.Context, cfg repository.IDPConfig, idToken string) (jwt.MapClaims, error) {
	disc, err := s.discoveryFor(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, err
	}

	keyFunc := func(t *jwt.Token) (any, error) {
		// Defense in depth alongside jwt.WithValidMethods: only the
		// asymmetric RSA/ECDSA families are acceptable for a JWKS-backed
		// key. This rejects any HS* alg-confusion attempt outright.
		switch t.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
		default:
			return nil, fmt.Errorf("unexpected signing method %q", t.Method.Alg())
		}
		kid, _ := t.Header["kid"].(string)
		key, ok := disc.keyForKID(kid)
		if !ok {
			return nil, fmt.Errorf("no JWKS key for kid %q", kid)
		}
		return key, nil
	}

	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(idToken, claims, keyFunc,
		jwt.WithIssuer(strings.TrimRight(cfg.IssuerURL, "/")),
		jwt.WithAudience(cfg.ClientID),
		jwt.WithValidMethods(idTokenSigningMethods),
		jwt.WithExpirationRequired(),
	)
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("id token validation failed: %w: %v", repository.ErrInvalidArgument, err)
	}
	return claims, nil
}

// mapIdentity resolves the validated claims to an SNG user, applying
// the domain allow-list and (optionally) just-in-time provisioning.
func (s *OIDCService) mapIdentity(
	ctx context.Context,
	tenantID uuid.UUID,
	cfg repository.IDPConfig,
	claims jwt.MapClaims,
) (ValidatedIdentity, error) {
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return ValidatedIdentity{}, fmt.Errorf("id token missing sub: %w", repository.ErrInvalidArgument)
	}
	email, _ := claims["email"].(string)
	if email == "" {
		return ValidatedIdentity{}, fmt.Errorf("id token missing email: %w", repository.ErrInvalidArgument)
	}
	email = strings.ToLower(strings.TrimSpace(email))
	// Reject only an explicit email_verified=false. Absence is treated
	// as "unknown" and allowed, matching providers (e.g. Okta custom
	// auth servers) that omit the claim.
	if verified, ok := claims["email_verified"].(bool); ok && !verified {
		return ValidatedIdentity{}, fmt.Errorf("email not verified by provider: %w", repository.ErrForbidden)
	}

	if err := enforceAllowedDomains(cfg, claims, email); err != nil {
		return ValidatedIdentity{}, err
	}

	ident := ValidatedIdentity{
		TenantID: tenantID,
		Email:    email,
		Subject:  sub,
		Provider: cfg.ProviderType,
		Issuer:   strings.TrimRight(cfg.IssuerURL, "/"),
		Groups:   extractGroups(claims, cfg.GroupClaimPath),
	}

	u, err := s.users.GetByEmail(ctx, tenantID, email)
	switch {
	case err == nil:
		ident.UserID = u.ID
		return ident, nil
	case errors.Is(err, repository.ErrNotFound):
		if !s.autoProvision {
			return ValidatedIdentity{}, fmt.Errorf("user %q not provisioned: %w", email, repository.ErrNotFound)
		}
		created, perr := s.provisionUser(ctx, tenantID, email, claims, sub)
		if perr != nil {
			return ValidatedIdentity{}, perr
		}
		ident.UserID = created.ID
		return ident, nil
	default:
		return ValidatedIdentity{}, err
	}
}

// provisionUser performs just-in-time user creation from validated
// OIDC claims, mirroring the SCIM CreateUser user shape (email as the
// natural key, display name from the `name` claim, active status).
func (s *OIDCService) provisionUser(
	ctx context.Context,
	tenantID uuid.UUID,
	email string,
	claims jwt.MapClaims,
	sub string,
) (repository.User, error) {
	name, _ := claims["name"].(string)
	if name == "" {
		name = email
	}
	u, err := s.users.Create(ctx, tenantID, repository.User{
		Email:      email,
		Name:       name,
		IDPSubject: sub,
		Status:     repository.UserStatusActive,
	})
	if err != nil {
		// A concurrent request may have created the user between our
		// lookup and insert; fall back to the existing record.
		if errors.Is(err, repository.ErrConflict) {
			if existing, gerr := s.users.GetByEmail(ctx, tenantID, email); gerr == nil {
				return existing, nil
			}
		}
		return repository.User{}, err
	}
	return u, nil
}

// mintSession signs an SNG session JWT bound to the user (sub) and
// the device public key. The token is HS256-signed with the same
// secret/iss/aud the operator-console auth uses, so the standard
// middleware.Auth chain accepts it; the OIDC subject and device key
// ride along as custom claims for ZTNA enforcement downstream.
func (s *OIDCService) mintSession(ident ValidatedIdentity, devicePublicKey string) (SessionResult, error) {
	if len(s.signer.Secret) == 0 {
		return SessionResult{}, errors.New("oidc: session signer secret not configured")
	}
	now := s.nowFunc()
	exp := now.Add(s.sessionTTL)
	claims := jwt.MapClaims{
		"iss":        s.signer.Issuer,
		"aud":        s.signer.Audience,
		"sub":        ident.UserID.String(),
		"tenant_id":  ident.TenantID.String(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        exp.Unix(),
		"oidc_sub":   ident.Subject,
		"oidc_iss":   ident.Issuer,
		"device_key": devicePublicKey,
		"amr":        []string{"oidc", "mtls"},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(s.signer.Secret)
	if err != nil {
		return SessionResult{}, fmt.Errorf("sign session token: %w", err)
	}
	return SessionResult{
		AccessToken:     signed,
		ExpiresAt:       exp,
		TTL:             s.sessionTTL,
		Identity:        ident,
		DevicePublicKey: devicePublicKey,
	}, nil
}

func (s *OIDCService) recordAudit(ctx context.Context, tenantID uuid.UUID, ident ValidatedIdentity, action string) {
	details, _ := json.Marshal(map[string]string{
		"provider": string(ident.Provider),
		"issuer":   ident.Issuer,
		"oidc_sub": ident.Subject,
		"email":    ident.Email,
	})
	uid := ident.UserID
	if _, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      &uid,
		Action:       action,
		ResourceType: "mobile_session",
		ResourceID:   &uid,
		Details:      details,
	}); err != nil {
		s.logger.Warn("oidc: audit append failed", slog.String("action", action), slog.Any("error", err))
	}
}

// --- Discovery + JWKS ----------------------------------------------------

type oidcDiscoveryDoc struct {
	Issuer        string `json:"issuer"`
	JWKSURI       string `json:"jwks_uri"`
	TokenEndpoint string `json:"token_endpoint"`
}

type discoveryEntry struct {
	doc       oidcDiscoveryDoc
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

// keyForKID returns the public key (RSA or ECDSA) for the given key id.
// When the token carries no kid (or an unknown one) and the JWKS
// published exactly one key, that key is used as the unambiguous
// fallback.
func (e *discoveryEntry) keyForKID(kid string) (crypto.PublicKey, bool) {
	if k, ok := e.keys[kid]; ok {
		return k, true
	}
	if len(e.keys) == 1 {
		for _, k := range e.keys {
			return k, true
		}
	}
	return nil, false
}

// discoveryFor returns the cached (or freshly fetched) discovery
// document + JWKS for an issuer.
func (s *OIDCService) discoveryFor(ctx context.Context, issuer string) (*discoveryEntry, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")

	s.mu.Lock()
	if e, ok := s.discoveryCache[issuer]; ok && s.nowFunc().Sub(e.fetchedAt) < s.discoveryTTL {
		s.mu.Unlock()
		return e, nil
	}
	s.mu.Unlock()

	entry, err := s.fetchDiscovery(ctx, issuer)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.discoveryCache[issuer] = entry
	s.mu.Unlock()
	return entry, nil
}

func (s *OIDCService) fetchDiscovery(ctx context.Context, issuer string) (*discoveryEntry, error) {
	docURL := issuer + "/.well-known/openid-configuration"
	var doc oidcDiscoveryDoc
	if err := s.getJSON(ctx, docURL, &doc); err != nil {
		return nil, fmt.Errorf("fetch discovery document: %w", err)
	}
	// The OIDC spec requires the discovery document's issuer to match
	// the issuer we requested it from — a mismatch is a misconfigured
	// or hostile endpoint.
	if strings.TrimRight(doc.Issuer, "/") != issuer {
		return nil, fmt.Errorf("discovery issuer %q does not match %q: %w", doc.Issuer, issuer, repository.ErrInvalidArgument)
	}
	if doc.JWKSURI == "" {
		return nil, fmt.Errorf("discovery document missing jwks_uri: %w", repository.ErrInvalidArgument)
	}
	keys, err := s.fetchJWKS(ctx, doc.JWKSURI)
	if err != nil {
		return nil, err
	}
	return &discoveryEntry{doc: doc, keys: keys, fetchedAt: s.nowFunc()}, nil
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	// RSA parameters.
	N string `json:"n"`
	E string `json:"e"`
	// EC parameters.
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (s *OIDCService) fetchJWKS(ctx context.Context, jwksURI string) (map[string]crypto.PublicKey, error) {
	var set jwksDoc
	if err := s.getJSON(ctx, jwksURI, &set); err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		var (
			pub crypto.PublicKey
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
			s.logger.Warn("oidc: skipping unparseable JWKS key", slog.String("kid", k.Kid), slog.Any("error", err))
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks contained no usable RSA or EC signing keys: %w", repository.ErrInvalidArgument)
	}
	return keys, nil
}

func parseRSAJWK(k jwkKey) (*rsa.PublicKey, error) {
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
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}

// parseECJWK reconstructs an ECDSA public key from an EC JWK (RFC 7518
// §6.2.1). The crv parameter selects the curve (P-256/384/521) and the
// x/y parameters are the base64url-encoded affine coordinates.
func parseECJWK(k jwkKey) (*ecdsa.PublicKey, error) {
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

func (s *OIDCService) exchangeRefreshToken(ctx context.Context, tokenEndpoint, clientID, refreshToken string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("call token endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d: %w", resp.StatusCode, repository.ErrInvalidArgument)
	}
	var tr struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if tr.IDToken == "" {
		return "", fmt.Errorf("token endpoint response missing id_token: %w", repository.ErrInvalidArgument)
	}
	return tr.IDToken, nil
}

func (s *OIDCService) getJSON(ctx context.Context, rawURL string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s returned %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, dst)
}

// --- helpers -------------------------------------------------------------

// unverifiedIssuer reads the `iss` claim from a token WITHOUT
// verifying its signature — used only to select which registered
// config to validate against. The token is always cryptographically
// verified afterwards in validateIDToken.
func unverifiedIssuer(idToken string) (string, error) {
	var claims jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(idToken, &claims); err != nil {
		return "", fmt.Errorf("parse id token: %w: %v", repository.ErrInvalidArgument, err)
	}
	iss, _ := claims["iss"].(string)
	if iss == "" {
		return "", fmt.Errorf("id token missing iss: %w", repository.ErrInvalidArgument)
	}
	return iss, nil
}

// enforceAllowedDomains rejects the identity when the config declares
// an allow-list and neither the email domain nor the provider's
// hosted-domain (`hd`, Google) / tenant-id (`tid`, Microsoft) claim
// falls within it. An empty allow-list permits any domain.
func enforceAllowedDomains(cfg repository.IDPConfig, claims jwt.MapClaims, email string) error {
	if len(cfg.AllowedDomains) == 0 {
		return nil
	}
	candidates := map[string]bool{}
	if at := strings.LastIndex(email, "@"); at >= 0 && at < len(email)-1 {
		candidates[strings.ToLower(email[at+1:])] = true
	}
	if hd, ok := claims["hd"].(string); ok && hd != "" {
		candidates[strings.ToLower(hd)] = true
	}
	if tid, ok := claims["tid"].(string); ok && tid != "" {
		candidates[strings.ToLower(tid)] = true
	}
	for _, allowed := range cfg.AllowedDomains {
		if candidates[strings.ToLower(strings.TrimSpace(allowed))] {
			return nil
		}
	}
	return fmt.Errorf("identity domain not in allow-list: %w", repository.ErrForbidden)
}

// extractGroups resolves the configured group-claim into a string
// slice. The path is first tried as a single literal top-level claim
// key — so namespaced claims that themselves contain dots (e.g.
// "https://acme.com/roles", common with Auth0/Okta) resolve correctly
// — and only falls back to dotted-path traversal (e.g.
// "resource_access.roles") when no literal key matches. Returns nil
// when the path is empty or the claim is absent / not string-valued.
func extractGroups(claims jwt.MapClaims, path string) []string {
	if path == "" {
		return nil
	}
	cur, ok := resolveClaim(claims, path)
	if !ok {
		return nil
	}
	switch v := cur.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	case string:
		return []string{v}
	default:
		return nil
	}
}

// resolveClaim looks up a claim by path. It first treats the whole
// path as a single literal key (handling namespaced claim names that
// contain dots), then falls back to "."-separated nested traversal.
func resolveClaim(claims jwt.MapClaims, path string) (any, bool) {
	if v, ok := claims[path]; ok {
		return v, true
	}
	if !strings.Contains(path, ".") {
		return nil, false
	}
	var cur any = map[string]any(claims)
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

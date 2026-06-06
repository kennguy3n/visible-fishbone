package identity

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AdminAuthClient is the subset of *iamcore.Client the control-plane
// admin SSO flow drives. Declaring it as an interface keeps the flow
// unit-testable against a fake iam-core without a network.
type AdminAuthClient interface {
	AuthorizeURL(ctx context.Context, p iamcore.AuthorizeParams) (string, error)
	ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (iamcore.TokenResult, error)
	VerifyAccessToken(ctx context.Context, raw string) (iamcore.Claims, error)
}

// Compile-time guarantee the real client satisfies the flow's needs.
var _ AdminAuthClient = (*iamcore.Client)(nil)

// AdminSSOService wires admin (operator-console) login to iam-core via
// the OAuth2 authorization-code + PKCE flow:
//
//  1. Begin generates a PKCE pair + CSRF state + nonce and returns the
//     iam-core /oauth2/authorize redirect plus the LoginState the HTTP
//     layer must persist (e.g. in a signed, http-only cookie).
//  2. Complete validates the returned state against the persisted one,
//     exchanges the code at /oauth2/token, verifies the returned
//     access token against iam-core's JWKS, maps the iam-core tenant to
//     the SNG tenant, resolves (optionally provisions) the SNG admin
//     user, and mints an SNG session JWT the standard middleware.Auth
//     chain accepts.
//
// The iam-core tokens are never persisted; only the minted SNG session
// leaves the service.
type AdminSSOService struct {
	client  AdminAuthClient
	tenants middleware.TenantResolver
	users   repository.UserRepository
	audit   repository.AuditLogRepository
	signer  SessionSigner
	// iamCoreIssuer is the upstream iam-core `iss` the admin
	// authenticated against. It is recorded on the minted session as
	// the `oidc_iss` claim so downstream consumers can tell which IdP
	// vouched for the identity — distinct from the SNG session issuer
	// (`iss`/signer.Issuer) that merely signs the local session.
	iamCoreIssuer string
	logger        *slog.Logger
	nowFunc       func() time.Time
	sessionTTL    time.Duration
	autoProvision bool
}

// AdminSSOOption tunes the AdminSSOService.
type AdminSSOOption func(*AdminSSOService)

// WithAdminSessionTTL overrides the minted SNG admin session lifetime.
func WithAdminSessionTTL(ttl time.Duration) AdminSSOOption {
	return func(s *AdminSSOService) {
		if ttl > 0 {
			s.sessionTTL = ttl
		}
	}
}

// WithAdminAutoProvision enables just-in-time creation of the SNG admin
// user when a verified iam-core identity maps to an unknown email.
func WithAdminAutoProvision(enabled bool) AdminSSOOption {
	return func(s *AdminSSOService) { s.autoProvision = enabled }
}

// NewAdminSSOService constructs the admin SSO flow. client, tenants,
// users, audit, a non-empty iamCoreIssuer and a signer with a non-empty
// secret are required. iamCoreIssuer is the upstream iam-core issuer the
// admin authenticates against; it is recorded as the session's
// `oidc_iss` claim (distinct from the SNG session signer's issuer).
func NewAdminSSOService(
	client AdminAuthClient,
	tenants middleware.TenantResolver,
	users repository.UserRepository,
	audit repository.AuditLogRepository,
	signer SessionSigner,
	iamCoreIssuer string,
	logger *slog.Logger,
	opts ...AdminSSOOption,
) (*AdminSSOService, error) {
	if client == nil || tenants == nil || users == nil || audit == nil {
		return nil, errors.New("sso: client, tenant resolver, users and audit are required")
	}
	if len(signer.Secret) == 0 {
		return nil, errors.New("sso: session signer secret not configured")
	}
	if strings.TrimSpace(iamCoreIssuer) == "" {
		return nil, errors.New("sso: iam-core issuer not configured")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &AdminSSOService{
		client:        client,
		tenants:       tenants,
		users:         users,
		audit:         audit,
		signer:        signer,
		iamCoreIssuer: strings.TrimSpace(iamCoreIssuer),
		logger:        logger,
		nowFunc:       func() time.Time { return time.Now().UTC() },
		sessionTTL:    time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// LoginState is the transient per-login secret the HTTP layer persists
// between Begin and Complete (signed http-only cookie or server-side
// store). It binds the callback to the originating request: the
// CodeVerifier proves PKCE possession and State defeats CSRF.
type LoginState struct {
	State        string
	Nonce        string
	CodeVerifier string
	RedirectURI  string
}

// BeginResult is returned by Begin: redirect the browser to
// AuthorizationURL and persist State for the callback.
type BeginResult struct {
	AuthorizationURL string
	State            LoginState
}

// BeginOptions tune a single Begin call.
type BeginOptions struct {
	// StepUp requests a fresh authentication with MFA — used when a
	// sensitive control-plane operation requires step-up. It sets
	// prompt=login and (when provided) acr_values.
	StepUp bool
	// ACRValues optionally requests a specific authentication context
	// (e.g. an MFA assurance level). Only sent when non-empty.
	ACRValues string
	// Scopes overrides the default OIDC scope set when non-empty.
	Scopes []string
}

// Begin starts the admin SSO login: it generates PKCE + state + nonce
// and builds the iam-core authorization redirect. redirectURI must be
// the control plane's registered callback URL and is replayed verbatim
// at Complete.
func (s *AdminSSOService) Begin(ctx context.Context, redirectURI string, opts BeginOptions) (BeginResult, error) {
	if strings.TrimSpace(redirectURI) == "" {
		return BeginResult{}, fmt.Errorf("sso: redirect URI required: %w", repository.ErrInvalidArgument)
	}
	pkce, err := iamcore.GeneratePKCE()
	if err != nil {
		return BeginResult{}, err
	}
	state, err := iamcore.GenerateState()
	if err != nil {
		return BeginResult{}, err
	}
	nonce, err := iamcore.GenerateState()
	if err != nil {
		return BeginResult{}, err
	}

	params := iamcore.AuthorizeParams{
		RedirectURI:   redirectURI,
		State:         state,
		Nonce:         nonce,
		CodeChallenge: pkce.Challenge,
		Scopes:        opts.Scopes,
		ACRValues:     opts.ACRValues,
	}
	if opts.StepUp {
		// Force a fresh authentication so the resulting token carries a
		// current MFA/amr claim (Task 5 step-up).
		params.Prompt = "login"
	}

	authURL, err := s.client.AuthorizeURL(ctx, params)
	if err != nil {
		return BeginResult{}, err
	}
	return BeginResult{
		AuthorizationURL: authURL,
		State: LoginState{
			State:        state,
			Nonce:        nonce,
			CodeVerifier: pkce.Verifier,
			RedirectURI:  redirectURI,
		},
	}, nil
}

// CompleteInput carries the OAuth2 callback parameters plus the
// LoginState the HTTP layer persisted at Begin.
type CompleteInput struct {
	// Code is the authorization code from the callback query.
	Code string
	// ReturnedState is the `state` echoed back on the callback; it
	// must equal the persisted LoginState.State.
	ReturnedState string
	// Stored is the LoginState persisted at Begin.
	Stored LoginState
}

// AdminSession is the result of a successful login: an SNG session JWT
// the middleware.Auth chain accepts, plus the resolved identity.
type AdminSession struct {
	AccessToken string
	ExpiresAt   time.Time
	TTL         time.Duration
	UserID      uuid.UUID
	TenantID    uuid.UUID
	Email       string
	IAMCoreSub  string
	Roles       []string
	MFA         bool
}

// Complete finishes the login: validate state, exchange the code,
// verify the token, map tenant + user, and mint the SNG session.
func (s *AdminSSOService) Complete(ctx context.Context, in CompleteInput) (AdminSession, error) {
	if in.Code == "" {
		return AdminSession{}, fmt.Errorf("sso: missing authorization code: %w", repository.ErrInvalidArgument)
	}
	if in.Stored.State == "" || in.Stored.CodeVerifier == "" {
		return AdminSession{}, fmt.Errorf("sso: missing login state: %w", repository.ErrInvalidArgument)
	}
	// Constant-time CSRF state comparison.
	if subtle.ConstantTimeCompare([]byte(in.ReturnedState), []byte(in.Stored.State)) != 1 {
		return AdminSession{}, fmt.Errorf("sso: state mismatch: %w", repository.ErrForbidden)
	}

	tok, err := s.client.ExchangeCode(ctx, in.Code, in.Stored.RedirectURI, in.Stored.CodeVerifier)
	if err != nil {
		return AdminSession{}, fmt.Errorf("sso: code exchange: %w", err)
	}
	if tok.AccessToken == "" {
		return AdminSession{}, errors.New("sso: token exchange returned no access token")
	}

	// Verify the access token against iam-core's JWKS (signature +
	// iss/aud/exp/nbf). Fail-closed: an unverifiable token never yields
	// a session.
	claims, err := s.client.VerifyAccessToken(ctx, tok.AccessToken)
	if err != nil {
		return AdminSession{}, fmt.Errorf("sso: verify access token: %w", err)
	}
	if claims.Subject == "" || claims.TenantID == "" {
		return AdminSession{}, fmt.Errorf("sso: token missing sub/tenant_id: %w", repository.ErrInvalidArgument)
	}

	sngTenant, err := s.tenants.ResolveTenant(ctx, claims.TenantID)
	if err != nil {
		return AdminSession{}, fmt.Errorf("sso: resolve tenant: %w", err)
	}

	user, err := s.resolveAdminUser(ctx, sngTenant, claims)
	if err != nil {
		return AdminSession{}, err
	}

	session, err := s.mintAdminSession(sngTenant, user, claims)
	if err != nil {
		return AdminSession{}, err
	}
	s.recordAudit(ctx, sngTenant, user.ID, claims, "admin_session.established")
	return session, nil
}

// resolveAdminUser finds the SNG admin user for the verified iam-core
// identity by email, provisioning one just-in-time when autoProvision
// is enabled.
func (s *AdminSSOService) resolveAdminUser(ctx context.Context, tenantID uuid.UUID, claims iamcore.Claims) (repository.User, error) {
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return repository.User{}, fmt.Errorf("sso: token missing email: %w", repository.ErrInvalidArgument)
	}
	u, err := s.users.GetByEmail(ctx, tenantID, email)
	switch {
	case err == nil:
		return u, nil
	case errors.Is(err, repository.ErrNotFound):
		if !s.autoProvision {
			return repository.User{}, fmt.Errorf("sso: admin %q not provisioned: %w", email, repository.ErrNotFound)
		}
		created, perr := s.users.Create(ctx, tenantID, repository.User{
			Email:      email,
			Name:       email,
			IDPSubject: claims.Subject,
			Status:     repository.UserStatusActive,
		})
		if perr != nil {
			if errors.Is(perr, repository.ErrConflict) {
				if existing, gerr := s.users.GetByEmail(ctx, tenantID, email); gerr == nil {
					return existing, nil
				}
			}
			return repository.User{}, perr
		}
		return created, nil
	default:
		return repository.User{}, err
	}
}

// mintAdminSession signs an SNG admin session JWT bound to the resolved
// user and tenant, HS256-signed with the same secret/iss/aud the
// operator-console auth uses so the standard middleware.Auth chain
// accepts it. The iam-core subject and MFA state ride along as custom
// claims for downstream authorization + step-up gating.
func (s *AdminSSOService) mintAdminSession(tenantID uuid.UUID, user repository.User, claims iamcore.Claims) (AdminSession, error) {
	now := s.nowFunc()
	exp := now.Add(s.sessionTTL)
	amr := claims.AMR
	if len(amr) == 0 {
		amr = []string{"oidc"}
	}
	jwtClaims := jwt.MapClaims{
		"iss":        s.signer.Issuer,
		"aud":        s.signer.Audience,
		"sub":        user.ID.String(),
		"tenant_id":  tenantID.String(),
		"iat":        now.Unix(),
		"nbf":        now.Unix(),
		"exp":        exp.Unix(),
		"oidc_sub":   claims.Subject,
		"oidc_iss":   s.iamCoreIssuer,
		"email":      user.Email,
		"roles":      claims.Roles,
		"amr":        amr,
		"mfa":        claims.MFASatisfied,
		"token_type": "admin",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signed, err := tok.SignedString(s.signer.Secret)
	if err != nil {
		return AdminSession{}, fmt.Errorf("sso: sign session token: %w", err)
	}
	return AdminSession{
		AccessToken: signed,
		ExpiresAt:   exp,
		TTL:         s.sessionTTL,
		UserID:      user.ID,
		TenantID:    tenantID,
		Email:       user.Email,
		IAMCoreSub:  claims.Subject,
		Roles:       claims.Roles,
		MFA:         claims.MFASatisfied,
	}, nil
}

func (s *AdminSSOService) recordAudit(ctx context.Context, tenantID, userID uuid.UUID, claims iamcore.Claims, action string) {
	details, _ := json.Marshal(map[string]any{
		"oidc_sub": claims.Subject,
		"email":    claims.Email,
		"mfa":      claims.MFASatisfied,
	})
	uid := userID
	if _, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      &uid,
		Action:       action,
		ResourceType: "admin_session",
		ResourceID:   &uid,
		Details:      details,
	}); err != nil {
		s.logger.Warn("sso: audit append failed", slog.String("action", action), slog.Any("error", err))
	}
}

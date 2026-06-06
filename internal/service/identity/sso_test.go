package identity

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// fakeAuthClient is an in-memory AdminAuthClient: it records the
// authorize params, returns a canned token on exchange, and yields
// canned claims on verify.
type fakeAuthClient struct {
	authParams   iamcore.AuthorizeParams
	exchangeArgs struct{ code, redirectURI, verifier string }
	tokenResult  iamcore.TokenResult
	exchangeErr  error
	claims       iamcore.Claims
	verifyErr    error
	verifiedRaw  string
}

func (f *fakeAuthClient) AuthorizeURL(_ context.Context, p iamcore.AuthorizeParams) (string, error) {
	f.authParams = p
	u, _ := url.Parse("https://iam.example.com/oauth2/authorize")
	q := u.Query()
	q.Set("state", p.State)
	q.Set("code_challenge", p.CodeChallenge)
	q.Set("redirect_uri", p.RedirectURI)
	if p.Prompt != "" {
		q.Set("prompt", p.Prompt)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (f *fakeAuthClient) ExchangeCode(_ context.Context, code, redirectURI, verifier string) (iamcore.TokenResult, error) {
	f.exchangeArgs.code = code
	f.exchangeArgs.redirectURI = redirectURI
	f.exchangeArgs.verifier = verifier
	if f.exchangeErr != nil {
		return iamcore.TokenResult{}, f.exchangeErr
	}
	return f.tokenResult, nil
}

func (f *fakeAuthClient) VerifyAccessToken(_ context.Context, raw string) (iamcore.Claims, error) {
	f.verifiedRaw = raw
	if f.verifyErr != nil {
		return iamcore.Claims{}, f.verifyErr
	}
	return f.claims, nil
}

// fakeResolver maps a fixed iam-core tenant_id to a SNG tenant UUID.
type fakeResolver struct {
	want string
	id   uuid.UUID
	err  error
}

func (r fakeResolver) ResolveTenant(_ context.Context, iamCoreTenantID string) (uuid.UUID, error) {
	if r.err != nil {
		return uuid.Nil, r.err
	}
	if iamCoreTenantID != r.want {
		return uuid.Nil, repository.ErrNotFound
	}
	return r.id, nil
}

func newSSOService(t *testing.T, client AdminAuthClient, resolver fakeResolver, autoProvision bool) (*AdminSSOService, repository.UserRepository, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	resolver.id = tn.ID
	users := memory.NewUserRepository(s)
	signer := SessionSigner{Secret: []byte("test-secret-0123456789"), Issuer: "sng", Audience: "sng-admin"}
	svc, err := NewAdminSSOService(client, resolver, users, memory.NewAuditLogRepository(s), signer, nil,
		WithAdminAutoProvision(autoProvision), WithAdminSessionTTL(30*time.Minute))
	if err != nil {
		t.Fatalf("NewAdminSSOService: %v", err)
	}
	return svc, users, tn.ID
}

func TestAdminSSO_BeginBuildsPKCEAuthorizeURL(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{}
	svc, _, _ := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, true)

	res, err := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if res.State.CodeVerifier == "" || res.State.State == "" {
		t.Fatal("expected PKCE verifier and state to be generated")
	}
	if !strings.Contains(res.AuthorizationURL, "code_challenge=") {
		t.Errorf("authorize URL missing code_challenge: %s", res.AuthorizationURL)
	}
	if fc.authParams.CodeChallenge == "" {
		t.Error("expected code challenge passed to client")
	}
	// Verifier and challenge must differ (challenge = S256(verifier)).
	if fc.authParams.CodeChallenge == res.State.CodeVerifier {
		t.Error("code_challenge must be the S256 hash of the verifier, not the verifier itself")
	}
}

func TestAdminSSO_BeginStepUpForcesPromptLogin(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{}
	svc, _, _ := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, true)

	_, err := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{StepUp: true})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if fc.authParams.Prompt != "login" {
		t.Errorf("step-up must set prompt=login, got %q", fc.authParams.Prompt)
	}
}

func TestAdminSSO_CompleteMintsSession(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{
		tokenResult: iamcore.TokenResult{AccessToken: "iam-access-token"},
		claims: iamcore.Claims{
			Subject:      "iam-user-1",
			TenantID:     "iam-tenant",
			Email:        "Admin@Acme.com",
			Roles:        []string{"sng-admin"},
			AMR:          []string{"pwd", "otp"},
			MFASatisfied: true,
		},
	}
	svc, _, tid := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, true)

	begin, err := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	sess, err := svc.Complete(context.Background(), CompleteInput{
		Code:          "auth-code-xyz",
		ReturnedState: begin.State.State,
		Stored:        begin.State,
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	// PKCE verifier must be replayed to the token endpoint.
	if fc.exchangeArgs.verifier != begin.State.CodeVerifier {
		t.Errorf("verifier not replayed: got %q want %q", fc.exchangeArgs.verifier, begin.State.CodeVerifier)
	}
	if fc.verifiedRaw != "iam-access-token" {
		t.Errorf("access token not verified, got %q", fc.verifiedRaw)
	}
	if sess.TenantID != tid {
		t.Errorf("tenant = %v, want %v", sess.TenantID, tid)
	}
	if !sess.MFA {
		t.Error("expected MFA satisfied to propagate")
	}
	// Email must be normalised to lower-case for the user lookup.
	if sess.Email != "admin@acme.com" {
		t.Errorf("email = %q, want admin@acme.com", sess.Email)
	}
	// The minted token must be a valid HS256 SNG session.
	parsed, perr := jwt.Parse(sess.AccessToken, func(*jwt.Token) (any, error) {
		return []byte("test-secret-0123456789"), nil
	})
	if perr != nil || !parsed.Valid {
		t.Fatalf("minted session not valid: %v", perr)
	}
	mc := parsed.Claims.(jwt.MapClaims)
	if mc["token_type"] != "admin" {
		t.Errorf("token_type = %v, want admin", mc["token_type"])
	}
	if mc["oidc_sub"] != "iam-user-1" {
		t.Errorf("oidc_sub = %v, want iam-user-1", mc["oidc_sub"])
	}
}

func TestAdminSSO_CompleteRejectsStateMismatch(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{tokenResult: iamcore.TokenResult{AccessToken: "t"}}
	svc, _, _ := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, true)
	begin, _ := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{})

	_, err := svc.Complete(context.Background(), CompleteInput{
		Code:          "code",
		ReturnedState: "attacker-supplied-state",
		Stored:        begin.State,
	})
	if !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("state mismatch must be ErrForbidden, got %v", err)
	}
	// A rejected callback must never reach the token endpoint.
	if fc.exchangeArgs.code != "" {
		t.Error("code exchange must not run on state mismatch")
	}
}

func TestAdminSSO_CompleteFailsClosedOnVerifyError(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{
		tokenResult: iamcore.TokenResult{AccessToken: "tampered"},
		verifyErr:   errors.New("bad signature"),
	}
	svc, _, _ := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, true)
	begin, _ := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{})

	_, err := svc.Complete(context.Background(), CompleteInput{
		Code:          "code",
		ReturnedState: begin.State.State,
		Stored:        begin.State,
	})
	if err == nil {
		t.Fatal("expected failure when token verification fails")
	}
}

func TestAdminSSO_CompleteRejectsUnmappedTenant(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{
		tokenResult: iamcore.TokenResult{AccessToken: "t"},
		claims:      iamcore.Claims{Subject: "u", TenantID: "unknown-tenant", Email: "a@acme.com"},
	}
	svc, _, _ := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, true)
	begin, _ := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{})

	_, err := svc.Complete(context.Background(), CompleteInput{
		Code:          "code",
		ReturnedState: begin.State.State,
		Stored:        begin.State,
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("unmapped tenant must surface ErrNotFound, got %v", err)
	}
}

func TestAdminSSO_CompleteNoAutoProvisionRejectsUnknownUser(t *testing.T) {
	t.Parallel()
	fc := &fakeAuthClient{
		tokenResult: iamcore.TokenResult{AccessToken: "t"},
		claims:      iamcore.Claims{Subject: "u", TenantID: "iam-tenant", Email: "ghost@acme.com"},
	}
	svc, _, _ := newSSOService(t, fc, fakeResolver{want: "iam-tenant"}, false)
	begin, _ := svc.Begin(context.Background(), "https://sng.example.com/callback", BeginOptions{})

	_, err := svc.Complete(context.Background(), CompleteInput{
		Code:          "code",
		ReturnedState: begin.State.State,
		Stored:        begin.State,
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("unknown user without auto-provision must be ErrNotFound, got %v", err)
	}
}

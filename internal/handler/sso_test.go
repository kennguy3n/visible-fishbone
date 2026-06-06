package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// stubAuthClient is a minimal AdminAuthClient for handler tests.
type stubAuthClient struct {
	claims iamcore.Claims
}

func (s *stubAuthClient) AuthorizeURL(_ context.Context, p iamcore.AuthorizeParams) (string, error) {
	u, _ := url.Parse("https://iam.example.com/oauth2/authorize")
	q := u.Query()
	q.Set("state", p.State)
	q.Set("code_challenge", p.CodeChallenge)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func (s *stubAuthClient) ExchangeCode(_ context.Context, _, _, _ string) (iamcore.TokenResult, error) {
	return iamcore.TokenResult{AccessToken: "verified-access-token"}, nil
}

func (s *stubAuthClient) VerifyAccessToken(_ context.Context, _ string) (iamcore.Claims, error) {
	return s.claims, nil
}

type stubResolver struct{ id uuid.UUID }

func (r stubResolver) ResolveTenant(_ context.Context, _ string) (uuid.UUID, error) {
	return r.id, nil
}

func newSSOHandler(t *testing.T) (*AdminSSOHandler, repository.UserRepository, uuid.UUID) {
	t.Helper()
	st := memory.NewStore()
	tn, err := memory.NewTenantRepository(st).Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	users := memory.NewUserRepository(st)
	client := &stubAuthClient{claims: iamcore.Claims{
		Subject: "iam-user", TenantID: "acme", Email: "admin@acme.com", MFASatisfied: true,
	}}
	signer := identity.SessionSigner{Secret: []byte("cookie-secret-0123456789"), Issuer: "sng", Audience: "sng-admin"}
	svc, err := identity.NewAdminSSOService(client, stubResolver{id: tn.ID}, users, memory.NewAuditLogRepository(st), signer, "https://iam.example.com", nil,
		identity.WithAdminAutoProvision(true))
	if err != nil {
		t.Fatalf("NewAdminSSOService: %v", err)
	}
	h := NewAdminSSOHandler(svc, "https://sng.example.com/api/v1/auth/sso/callback", []byte("cookie-secret-0123456789"), nil)
	return h, users, tn.ID
}

func TestAdminSSOHandler_LoginRedirectsAndSetsStateCookie(t *testing.T) {
	h, _, _ := newSSOHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, "code_challenge=") {
		t.Errorf("redirect missing code_challenge: %s", loc)
	}
	var stateCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == ssoStateCookie {
			stateCookie = c
		}
	}
	if stateCookie == nil {
		t.Fatal("expected SSO state cookie to be set")
	}
	if !stateCookie.HttpOnly {
		t.Error("state cookie must be HttpOnly")
	}
}

func TestAdminSSOHandler_CallbackRoundTripMintsSession(t *testing.T) {
	h, users, tid := newSSOHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	// 1. Login to obtain the state cookie + the state value.
	loginRec := httptest.NewRecorder()
	mux.ServeHTTP(loginRec, httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil))
	stateCookie := findCookie(t, loginRec.Result().Cookies(), ssoStateCookie)
	loc, _ := url.Parse(loginRec.Header().Get("Location"))
	state := loc.Query().Get("state")

	// 2. Callback with the matching state + the persisted cookie.
	cbReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?code=abc&state="+state, nil)
	cbReq.AddCookie(stateCookie)
	cbRec := httptest.NewRecorder()
	mux.ServeHTTP(cbRec, cbReq)

	if cbRec.Code != http.StatusOK {
		t.Fatalf("callback status = %d body=%s", cbRec.Code, cbRec.Body.String())
	}
	if !strings.Contains(cbRec.Body.String(), "access_token") {
		t.Errorf("callback body missing access_token: %s", cbRec.Body.String())
	}
	if findCookie(t, cbRec.Result().Cookies(), ssoSessionCooke) == nil {
		t.Error("expected admin session cookie to be set")
	}
	// The just-in-time provisioned admin must exist in the tenant.
	if _, err := users.GetByEmail(context.Background(), tid, "admin@acme.com"); err != nil {
		t.Errorf("admin not provisioned: %v", err)
	}
}

func TestAdminSSOHandler_CallbackRejectsForgedStateWithoutCookie(t *testing.T) {
	h, _, _ := newSSOHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?code=abc&state=forged", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing state cookie must be 400, got %d", rec.Code)
	}
}

func TestAdminSSOHandler_CallbackSurfacesUpstreamError(t *testing.T) {
	h, _, _ := newSSOHandler(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?error=access_denied", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("upstream error must be 400, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "access_denied") {
		t.Errorf("body should surface upstream error: %s", rec.Body.String())
	}
}

func findCookie(t *testing.T, cookies []*http.Cookie, name string) *http.Cookie {
	t.Helper()
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

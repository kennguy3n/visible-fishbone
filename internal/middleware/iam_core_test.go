package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

// fakeValidator is a hand-rolled IAMCoreValidator: it returns canned
// claims for a known token and an error otherwise, so the middleware's
// routing / tenant / context logic can be tested without real crypto.
type fakeValidator struct {
	issuer string
	claims map[string]iamcore.Claims
}

func (f *fakeValidator) Issuer() string { return f.issuer }

func (f *fakeValidator) VerifyAccessToken(_ context.Context, raw string) (iamcore.Claims, error) {
	if c, ok := f.claims[raw]; ok {
		return c, nil
	}
	return iamcore.Claims{}, errors.New("invalid")
}

// fakeResolver maps a single iam-core tenant id onto a SNG UUID.
type fakeResolver struct {
	want string
	uuid uuid.UUID
	err  error
}

func (f *fakeResolver) ResolveTenant(_ context.Context, id string) (uuid.UUID, error) {
	if f.err != nil {
		return uuid.Nil, f.err
	}
	if id == f.want {
		return f.uuid, nil
	}
	return uuid.Nil, errors.New("no tenant mapped")
}

// makeJWT builds an unsigned-but-well-formed JWT string with the given
// issuer so unverifiedIssuer routing can be exercised. The fake
// validator keys on the whole string, so the signature is irrelevant.
func makeJWT(t *testing.T, iss string) string {
	t.Helper()
	// header.payload.sig — payload carries {"iss": iss}.
	return "eyJhbGciOiJSUzI1NiJ9." + base64URL(`{"iss":"`+iss+`"}`) + ".sig"
}

func base64URL(s string) string {
	const tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	// Minimal base64url (no padding) encoder to avoid importing here.
	src := []byte(s)
	var out []byte
	for i := 0; i < len(src); i += 3 {
		var b [3]byte
		n := copy(b[:], src[i:])
		out = append(out, tbl[b[0]>>2])
		out = append(out, tbl[(b[0]&0x03)<<4|b[1]>>4])
		if n > 1 {
			out = append(out, tbl[(b[1]&0x0f)<<2|b[2]>>6])
		}
		if n > 2 {
			out = append(out, tbl[b[2]&0x3f])
		}
	}
	return string(out)
}

func newAuthHandler(t *testing.T, opts ...AuthOption) http.Handler {
	t.Helper()
	cfg := &config.Auth{APIKeyHeader: "X-SNG-API-Key"}
	// Capture context downstream so assertions can read it.
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return Chain(
		Logging(nil), // installs RequestMeta the auth path late-binds onto
		Auth(cfg, nil, opts...),
	)(final)
}

const iamIssuer = "https://iam.example.com"

func TestAuth_IAMCore_ValidToken_BindsTenantAndIdentity(t *testing.T) {
	token := makeJWT(t, iamIssuer)
	sngTenant := uuid.New()
	validator := &fakeValidator{
		issuer: iamIssuer,
		claims: map[string]iamcore.Claims{
			token: {Subject: "user-1", TenantID: "tenant-abc", Roles: []string{"admin"}, MFASatisfied: true},
		},
	}
	resolver := &fakeResolver{want: "tenant-abc", uuid: sngTenant}

	var gotTenant uuid.UUID
	var gotIdentity IAMCoreIdentity
	var gotIdentityOK bool
	var gotExpected string
	final := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenant = TenantIDFromContext(r.Context())
		gotIdentity, gotIdentityOK = IAMCoreIdentityFromContext(r.Context())
		gotExpected, _ = postgres.ExpectedTenantFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := Chain(Logging(nil), Auth(&config.Auth{}, nil, WithIAMCore(validator, resolver)))(final)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotTenant != sngTenant {
		t.Fatalf("tenant = %s, want %s", gotTenant, sngTenant)
	}
	if gotExpected != sngTenant.String() {
		t.Fatalf("expected-tenant GUC = %q, want %s", gotExpected, sngTenant)
	}
	if !gotIdentityOK || gotIdentity.Subject != "user-1" || gotIdentity.SNGTenantID != sngTenant {
		t.Fatalf("identity = %+v ok=%v", gotIdentity, gotIdentityOK)
	}
	if !gotIdentity.HasRole("admin") {
		t.Fatalf("roles not surfaced: %v", gotIdentity.Roles)
	}
}

func TestAuth_IAMCore_InvalidToken_FailsClosed(t *testing.T) {
	validator := &fakeValidator{issuer: iamIssuer, claims: map[string]iamcore.Claims{}}
	h := newAuthHandler(t, WithIAMCore(validator, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+makeJWT(t, iamIssuer))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuth_IAMCore_TenantHeaderMismatch_403(t *testing.T) {
	token := makeJWT(t, iamIssuer)
	validator := &fakeValidator{
		issuer: iamIssuer,
		claims: map[string]iamcore.Claims{token: {Subject: "u", TenantID: "tenant-abc"}},
	}
	h := newAuthHandler(t, WithIAMCore(validator, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-OTHER")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestAuth_IAMCore_TenantHeaderMatch_OK(t *testing.T) {
	token := makeJWT(t, iamIssuer)
	validator := &fakeValidator{
		issuer: iamIssuer,
		claims: map[string]iamcore.Claims{token: {Subject: "u", TenantID: "tenant-abc"}},
	}
	h := newAuthHandler(t, WithIAMCore(validator, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "tenant-abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestAuth_IAMCore_UnmappedTenant_403(t *testing.T) {
	token := makeJWT(t, iamIssuer)
	validator := &fakeValidator{
		issuer: iamIssuer,
		claims: map[string]iamcore.Claims{token: {Subject: "u", TenantID: "tenant-unknown"}},
	}
	resolver := &fakeResolver{want: "tenant-abc", uuid: uuid.New()}
	h := newAuthHandler(t, WithIAMCore(validator, resolver))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

// A token for a different issuer must NOT be routed to the iam-core
// verifier; with no API key and an unparseable HMAC token it falls
// through to the legacy path (401 here, but crucially the iam-core
// validator is never consulted).
func TestAuth_IAMCore_OtherIssuer_FallsThrough(t *testing.T) {
	consulted := false
	validator := &issuerSpyValidator{issuer: iamIssuer, onVerify: func() { consulted = true }}
	h := newAuthHandler(t, WithIAMCore(validator, nil))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/things", nil)
	req.Header.Set("Authorization", "Bearer "+makeJWT(t, "https://other-idp.example.com"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if consulted {
		t.Fatal("iam-core validator was consulted for a non-iam-core issuer")
	}
}

type issuerSpyValidator struct {
	issuer   string
	onVerify func()
}

func (s *issuerSpyValidator) Issuer() string { return s.issuer }
func (s *issuerSpyValidator) VerifyAccessToken(_ context.Context, _ string) (iamcore.Claims, error) {
	s.onVerify()
	return iamcore.Claims{}, errors.New("should not be called")
}

func TestRequireMFA(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	t.Run("non-iam-core caller passes through", func(t *testing.T) {
		h := RequireMFA(nil)(ok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/x", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("token already MFA-satisfied passes", func(t *testing.T) {
		h := RequireMFA(nil)(ok)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = req.WithContext(WithIAMCoreIdentityForTest(req.Context(), IAMCoreIdentity{Subject: "u", MFASatisfied: true}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("no MFA and no introspector -> 401", func(t *testing.T) {
		h := RequireMFA(nil)(ok)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req = req.WithContext(WithIAMCoreIdentityForTest(req.Context(), IAMCoreIdentity{Subject: "u"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})

	t.Run("introspection confirms MFA -> pass", func(t *testing.T) {
		intro := &fakeIntrospector{res: iamcore.Introspection{Active: true, MFASatisfied: true}}
		h := RequireMFA(intro)(ok)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		req = req.WithContext(WithIAMCoreIdentityForTest(req.Context(), IAMCoreIdentity{Subject: "u"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !intro.called {
			t.Fatal("introspector not consulted")
		}
	})

	t.Run("introspection denies MFA -> 401", func(t *testing.T) {
		intro := &fakeIntrospector{res: iamcore.Introspection{Active: true, MFASatisfied: false}}
		h := RequireMFA(intro)(ok)
		req := httptest.NewRequest(http.MethodPost, "/x", nil)
		req.Header.Set("Authorization", "Bearer some-token")
		req = req.WithContext(WithIAMCoreIdentityForTest(req.Context(), IAMCoreIdentity{Subject: "u"}))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", rec.Code)
		}
	})
}

type fakeIntrospector struct {
	res    iamcore.Introspection
	called bool
}

func (f *fakeIntrospector) Introspect(_ context.Context, _ string) (iamcore.Introspection, error) {
	f.called = true
	return f.res, nil
}

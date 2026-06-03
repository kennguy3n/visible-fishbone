package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// mockIDP is an httptest-backed OIDC provider: it serves a discovery
// document + JWKS and can mint ID tokens signed with its RSA key.
type mockIDP struct {
	server      *httptest.Server
	key         *rsa.PrivateKey
	kid         string
	clientID    string
	discoveryN  int64 // discovery-doc fetch count (atomic)
	jwksN       int64 // jwks fetch count (atomic)
	tokenIDFunc func() string
}

func newMockIDP(t *testing.T, clientID string) *mockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	m := &mockIDP{key: key, kid: "test-key-1", clientID: clientID}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&m.discoveryN, 1)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         m.issuer(),
			"jwks_uri":       m.issuer() + "/jwks",
			"token_endpoint": m.issuer() + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&m.jwksN, 1)
		pub := m.key.Public().(*rsa.PublicKey)
		eBytes := big.NewInt(int64(pub.E)).Bytes()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": m.kid,
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		idTok := ""
		if m.tokenIDFunc != nil {
			idTok = m.tokenIDFunc()
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": idTok})
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockIDP) issuer() string { return m.server.URL }

// sign mints an ID token with the given claims, defaulting iss/aud/exp.
func (m *mockIDP) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = m.issuer()
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = m.clientID
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	if _, ok := claims["iat"]; !ok {
		claims["iat"] = time.Now().Add(-time.Minute).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.kid
	signed, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed
}

type oidcFixture struct {
	svc      *OIDCService
	configs  *memory.IDPConfigRepository
	users    *memory.UserRepository
	tenantID uuid.UUID
	signer   SessionSigner
}

func newOIDCFixture(t *testing.T, opts OIDCOptions) *oidcFixture {
	t.Helper()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "OIDC Test", Slug: "oidc-test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	users := memory.NewUserRepository(store)
	audit := memory.NewAuditLogRepository(store)
	signer := SessionSigner{Secret: []byte("test-secret-please-ignore"), Issuer: "sng", Audience: "sng-clients"}
	svc := NewOIDCService(configs, users, audit, signer, opts, nil)
	return &oidcFixture{svc: svc, configs: configs, users: users, tenantID: tn.ID, signer: signer}
}

func (f *oidcFixture) seedConfig(t *testing.T, c repository.IDPConfig) repository.IDPConfig {
	t.Helper()
	out, err := f.configs.Create(context.Background(), f.tenantID, c)
	if err != nil {
		t.Fatalf("seed idp config: %v", err)
	}
	return out
}

func (f *oidcFixture) parseSession(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
		return f.signer.Secret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil {
		t.Fatalf("parse minted session: %v", err)
	}
	return claims
}

func TestIssueSessionFromIDToken_AutoProvision(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderGoogleWorkspace,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-123",
		Enabled:      true,
	})

	idToken := idp.sign(t, jwt.MapClaims{
		"sub":            "google-oauth2|999",
		"email":          "Alice@acme.com",
		"email_verified": true,
		"name":           "Alice A",
	})

	res, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken:         idToken,
		DevicePublicKey: "ZGV2aWNlLWtleQ==",
	})
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}

	if res.Identity.Email != "alice@acme.com" {
		t.Errorf("email = %q, want lowercased alice@acme.com", res.Identity.Email)
	}
	if res.Identity.Subject != "google-oauth2|999" {
		t.Errorf("subject = %q", res.Identity.Subject)
	}
	if res.Identity.UserID == uuid.Nil {
		t.Error("expected a provisioned user id")
	}

	// The user must have been created just-in-time.
	u, err := f.users.GetByEmail(context.Background(), f.tenantID, "alice@acme.com")
	if err != nil {
		t.Fatalf("expected provisioned user: %v", err)
	}
	if u.IDPSubject != "google-oauth2|999" {
		t.Errorf("provisioned user idp_subject = %q", u.IDPSubject)
	}

	// The minted SNG session must bind both device key and OIDC sub.
	claims := f.parseSession(t, res.AccessToken)
	if claims["device_key"] != "ZGV2aWNlLWtleQ==" {
		t.Errorf("device_key claim = %v", claims["device_key"])
	}
	if claims["oidc_sub"] != "google-oauth2|999" {
		t.Errorf("oidc_sub claim = %v", claims["oidc_sub"])
	}
	if claims["sub"] != res.Identity.UserID.String() {
		t.Errorf("sub claim = %v, want user id %v", claims["sub"], res.Identity.UserID)
	}
	if claims["iss"] != "sng" || claims["aud"] != "sng-clients" {
		t.Errorf("session iss/aud = %v/%v", claims["iss"], claims["aud"])
	}
}

func TestIssueSessionFromIDToken_IssuerDerivedFromToken(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-xyz")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-xyz",
		Enabled:      true,
	})
	idToken := idp.sign(t, jwt.MapClaims{"sub": "okta|1", "email": "bob@acme.com"})

	// No Issuer in the input — it must be read from the token's iss.
	if _, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken:         idToken,
		DevicePublicKey: "ZGV2",
	}); err != nil {
		t.Fatalf("issue session with derived issuer: %v", err)
	}
}

func TestIssueSessionFromIDToken_Rejections(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderCustomOIDC,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-123",
		Enabled:      true,
	})
	other, _ := rsa.GenerateKey(rand.Reader, 2048)

	cases := []struct {
		name  string
		token func() string
	}{
		{"wrong audience", func() string {
			return idp.sign(t, jwt.MapClaims{"sub": "s", "email": "a@acme.com", "aud": "someone-else"})
		}},
		{"expired", func() string {
			return idp.sign(t, jwt.MapClaims{"sub": "s", "email": "a@acme.com", "exp": time.Now().Add(-time.Hour).Unix()})
		}},
		{"missing email", func() string {
			return idp.sign(t, jwt.MapClaims{"sub": "s"})
		}},
		{"email not verified", func() string {
			return idp.sign(t, jwt.MapClaims{"sub": "s", "email": "a@acme.com", "email_verified": false})
		}},
		{"bad signature", func() string {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"sub": "s", "email": "a@acme.com", "iss": idp.issuer(), "aud": "client-123",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			tok.Header["kid"] = idp.kid
			signed, _ := tok.SignedString(other)
			return signed
		}},
		{"alg confusion HS256", func() string {
			// Sign with HS256 using the (public) modulus bytes as the
			// secret — must be rejected because only RS* is accepted.
			tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"sub": "s", "email": "a@acme.com", "iss": idp.issuer(), "aud": "client-123",
				"exp": time.Now().Add(time.Hour).Unix(),
			})
			signed, _ := tok.SignedString(idp.key.Public().(*rsa.PublicKey).N.Bytes())
			return signed
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
				IDToken:         tc.token(),
				DevicePublicKey: "ZGV2",
			})
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
		})
	}
}

func TestIssueSessionFromIDToken_DomainAllowList(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType:   repository.IDPProviderGoogleWorkspace,
		IssuerURL:      idp.issuer(),
		ClientID:       "client-123",
		AllowedDomains: []string{"acme.com"},
		Enabled:        true,
	})

	// Disallowed email domain → forbidden.
	bad := idp.sign(t, jwt.MapClaims{"sub": "s1", "email": "eve@evil.com"})
	if _, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken: bad, DevicePublicKey: "ZGV2",
	}); err == nil {
		t.Fatal("expected forbidden for disallowed domain")
	}

	// hd (hosted-domain) claim within the allow-list → allowed even
	// when the email domain differs.
	ok := idp.sign(t, jwt.MapClaims{"sub": "s2", "email": "carol@mail.acme.com", "hd": "acme.com"})
	if _, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken: ok, DevicePublicKey: "ZGV2",
	}); err != nil {
		t.Fatalf("expected allow via hd claim: %v", err)
	}
}

func TestIssueSessionFromIDToken_NoProvisionWhenDisabled(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: false})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderGoogleWorkspace,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-123",
		Enabled:      true,
	})
	idToken := idp.sign(t, jwt.MapClaims{"sub": "s", "email": "ghost@acme.com"})
	_, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken: idToken, DevicePublicKey: "ZGV2",
	})
	if err == nil {
		t.Fatal("expected not-found when auto-provision disabled and user absent")
	}

	// With a pre-existing user, the same token resolves to that user.
	created, err := f.users.Create(context.Background(), f.tenantID, repository.User{
		Email: "ghost@acme.com", Name: "Ghost", Status: repository.UserStatusActive,
	})
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	res, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken: idp.sign(t, jwt.MapClaims{"sub": "s", "email": "ghost@acme.com"}), DevicePublicKey: "ZGV2",
	})
	if err != nil {
		t.Fatalf("issue with existing user: %v", err)
	}
	if res.Identity.UserID != created.ID {
		t.Errorf("user id = %v, want existing %v", res.Identity.UserID, created.ID)
	}
}

func TestResolveConfig_DisabledOrMissing(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderGoogleWorkspace,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-123",
		Enabled:      false, // disabled
	})
	idToken := idp.sign(t, jwt.MapClaims{"sub": "s", "email": "a@acme.com"})
	if _, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken: idToken, DevicePublicKey: "ZGV2",
	}); err == nil {
		t.Fatal("expected not-found for disabled config")
	}
}

func TestGroupClaimMapping(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType:   repository.IDPProviderOkta,
		IssuerURL:      idp.issuer(),
		ClientID:       "client-123",
		GroupClaimPath: "groups",
		Enabled:        true,
	})
	idToken := idp.sign(t, jwt.MapClaims{
		"sub": "s", "email": "a@acme.com",
		"groups": []string{"admins", "mobile-users"},
	})
	res, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken: idToken, DevicePublicKey: "ZGV2",
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if strings.Join(res.Identity.Groups, ",") != "admins,mobile-users" {
		t.Errorf("groups = %v", res.Identity.Groups)
	}
}

func TestExtractGroups_PathForms(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		claims jwt.MapClaims
		want   string
	}{
		{
			name:   "top-level array",
			path:   "groups",
			claims: jwt.MapClaims{"groups": []any{"a", "b"}},
			want:   "a,b",
		},
		{
			name:   "namespaced key containing dots is a literal key",
			path:   "https://acme.com/roles",
			claims: jwt.MapClaims{"https://acme.com/roles": []any{"admin"}},
			want:   "admin",
		},
		{
			name:   "nested dotted path",
			path:   "resource_access.roles",
			claims: jwt.MapClaims{"resource_access": map[string]any{"roles": []any{"x", "y"}}},
			want:   "x,y",
		},
		{
			name:   "single string value",
			path:   "role",
			claims: jwt.MapClaims{"role": "operator"},
			want:   "operator",
		},
		{
			name:   "absent claim",
			path:   "groups",
			claims: jwt.MapClaims{},
			want:   "",
		},
		{
			name:   "empty path",
			path:   "",
			claims: jwt.MapClaims{"groups": []any{"a"}},
			want:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.Join(extractGroups(tc.claims, tc.path), ",")
			if got != tc.want {
				t.Errorf("extractGroups(%q) = %q, want %q", tc.path, got, tc.want)
			}
		})
	}
}

func TestRefreshSession(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderMicrosoft365,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-123",
		Enabled:      true,
	})
	// The token endpoint mints a fresh ID token on demand.
	idp.tokenIDFunc = func() string {
		return idp.sign(t, jwt.MapClaims{"sub": "ms|42", "email": "dora@acme.com"})
	}

	res, err := f.svc.RefreshSession(context.Background(), f.tenantID, RefreshInput{
		RefreshToken:    "refresh-abc",
		Issuer:          idp.issuer(),
		DevicePublicKey: "ZGV2",
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if res.Identity.Subject != "ms|42" {
		t.Errorf("subject = %q", res.Identity.Subject)
	}
	claims := f.parseSession(t, res.AccessToken)
	if claims["oidc_sub"] != "ms|42" {
		t.Errorf("oidc_sub = %v", claims["oidc_sub"])
	}
}

func TestDiscoveryCaching(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true, DiscoveryCacheTTL: time.Hour})
	idp := newMockIDP(t, "client-123")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderGoogleWorkspace,
		IssuerURL:    idp.issuer(),
		ClientID:     "client-123",
		Enabled:      true,
	})

	now := time.Now().UTC()
	f.svc.nowFunc = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if _, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
			IDToken:         idp.sign(t, jwt.MapClaims{"sub": "s", "email": "a@acme.com"}),
			DevicePublicKey: "ZGV2",
		}); err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(&idp.discoveryN); got != 1 {
		t.Errorf("discovery fetched %d times within TTL, want 1", got)
	}

	// Advance past the TTL → next call refetches.
	now = now.Add(2 * time.Hour)
	if _, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken:         idp.sign(t, jwt.MapClaims{"sub": "s", "email": "a@acme.com"}),
		DevicePublicKey: "ZGV2",
	}); err != nil {
		t.Fatalf("issue after ttl: %v", err)
	}
	if got := atomic.LoadInt64(&idp.discoveryN); got != 2 {
		t.Errorf("discovery fetched %d times after TTL expiry, want 2", got)
	}
}

// mockECIDP is an httptest-backed OIDC provider that signs ID tokens
// with an ES256 (EC P-256) key — the family Apple Sign-In and many
// custom_oidc issuers use.
type mockECIDP struct {
	server   *httptest.Server
	key      *ecdsa.PrivateKey
	kid      string
	clientID string
}

func newMockECIDP(t *testing.T, clientID string) *mockECIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	m := &mockECIDP{key: key, kid: "ec-key-1", clientID: clientID}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         m.server.URL,
			"jwks_uri":       m.server.URL + "/jwks",
			"token_endpoint": m.server.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := m.key.PublicKey
		// P-256 coordinates are fixed-width (32 bytes); left-pad so a
		// leading-zero byte is never dropped.
		size := (pub.Curve.Params().BitSize + 7) / 8
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "EC",
				"use": "sig",
				"alg": "ES256",
				"crv": "P-256",
				"kid": m.kid,
				"x":   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
				"y":   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
			}},
		})
	})

	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockECIDP) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = m.server.URL
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = m.clientID
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = m.kid
	signed, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign ec id token: %v", err)
	}
	return signed
}

// TestIssueSessionFromIDToken_ECProvider exercises the full validation
// path against an ES256-signing IdP, covering EC JWKS parsing and the
// ECDSA branch of the signing-method check.
func TestIssueSessionFromIDToken_ECProvider(t *testing.T) {
	f := newOIDCFixture(t, OIDCOptions{AutoProvision: true})
	idp := newMockECIDP(t, "client-ec")
	f.seedConfig(t, repository.IDPConfig{
		ProviderType: repository.IDPProviderCustomOIDC,
		IssuerURL:    idp.server.URL,
		ClientID:     "client-ec",
		Enabled:      true,
	})

	idToken := idp.sign(t, jwt.MapClaims{
		"sub":            "apple|abc",
		"email":          "Eve@acme.com",
		"email_verified": true,
	})

	res, err := f.svc.IssueSessionFromIDToken(context.Background(), f.tenantID, TokenExchangeInput{
		IDToken:         idToken,
		DevicePublicKey: "ZGV2",
	})
	if err != nil {
		t.Fatalf("issue session (ES256): %v", err)
	}
	if res.Identity.Subject != "apple|abc" {
		t.Errorf("subject = %q", res.Identity.Subject)
	}
	if res.Identity.Email != "eve@acme.com" {
		t.Errorf("email = %q, want lowercased eve@acme.com", res.Identity.Email)
	}
	claims := f.parseSession(t, res.AccessToken)
	if claims["oidc_sub"] != "apple|abc" {
		t.Errorf("oidc_sub claim = %v", claims["oidc_sub"])
	}
}

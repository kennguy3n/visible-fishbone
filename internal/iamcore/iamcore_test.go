package iamcore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIAMCore is an in-test stand-in for iam-core: it serves a JWKS
// built from a locally generated RSA key, an OAuth2 token endpoint
// (client_credentials + authorization_code), an introspection
// endpoint, OIDC discovery, and the Management users API. Tests sign
// their own tokens with the same key so signature validation is real.
type fakeIAMCore struct {
	t           *testing.T
	key         *rsa.PrivateKey
	kid         string
	server      *httptest.Server
	jwksHits    int32
	tokenHits   int32
	mgmtHits    int32
	blocked     map[string]bool
	nextUserID  int32
	introspectM bool // value reported for mfa in introspection
}

func newFakeIAMCore(t *testing.T) *fakeIAMCore {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	f := &fakeIAMCore{t: t, key: key, kid: "test-key-1", blocked: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/jwks", f.handleJWKS)
	mux.HandleFunc("/oauth2/token", f.handleToken)
	mux.HandleFunc("/oauth2/introspect", f.handleIntrospect)
	mux.HandleFunc("/.well-known/openid-configuration", f.handleDiscovery)
	mux.HandleFunc("/api/v1/management/users", f.handleUsersCollection)
	mux.HandleFunc("/api/v1/management/users/", f.handleUserItem)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeIAMCore) issuer() string { return f.server.URL }

func (f *fakeIAMCore) config() Config {
	return Config{
		Issuer:       f.server.URL,
		ClientID:     "sng-gateway",
		ClientSecret: "s3cret",
		Audience:     "sng-api",
	}
}

func (f *fakeIAMCore) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	atomic.AddInt32(&f.jwksHits, 1)
	pub := f.key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	_ = json.NewEncoder(w).Encode(map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": f.kid, "n": n, "e": e,
		}},
	})
}

func (f *fakeIAMCore) handleToken(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&f.tokenHits, 1)
	_ = r.ParseForm()
	// Confidential client auth required.
	id, secret, ok := r.BasicAuth()
	if !ok || id == "" || secret == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "mgmt-token-" + r.FormValue("grant_type"),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     "id-token",
		"scope":        "openid",
	})
}

func (f *fakeIAMCore) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	resp := map[string]any{
		"active":    true,
		"sub":       "user-123",
		"tenant_id": "tenant-abc",
		"scope":     "openid policy:write",
	}
	if f.introspectM {
		resp["amr"] = []string{"pwd", "otp"}
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func (f *fakeIAMCore) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                 f.server.URL,
		"authorization_endpoint": f.server.URL + "/oauth2/authorize",
		"token_endpoint":         f.server.URL + "/oauth2/token",
		"introspection_endpoint": f.server.URL + "/oauth2/introspect",
		"jwks_uri":               f.server.URL + "/oauth2/jwks",
	})
}

func (f *fakeIAMCore) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&f.mgmtHits, 1)
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodGet:
		email := r.URL.Query().Get("email")
		users := []ManagementUser{}
		if email == "found@example.com" {
			users = append(users, ManagementUser{UserID: "user-existing", Email: email, TenantID: r.Header.Get("X-Tenant-ID")})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"users": users})
	case http.MethodPost:
		var in CreateManagementUser
		_ = json.NewDecoder(r.Body).Decode(&in)
		id := atomic.AddInt32(&f.nextUserID, 1)
		_ = json.NewEncoder(w).Encode(ManagementUser{
			UserID:   "user-" + string(rune('0'+id)),
			Email:    in.Email,
			Name:     in.Name,
			TenantID: r.Header.Get("X-Tenant-ID"),
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (f *fakeIAMCore) handleUserItem(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt32(&f.mgmtHits, 1)
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Path: /api/v1/management/users/{id}[/block|/unblock]
	const prefix = "/api/v1/management/users/"
	rest := r.URL.Path[len(prefix):]
	switch {
	case len(rest) > len("/block") && rest[len(rest)-len("/block"):] == "/block":
		f.blocked[rest[:len(rest)-len("/block")]] = true
		_ = json.NewEncoder(w).Encode(ManagementUser{UserID: rest[:len(rest)-len("/block")], Blocked: true})
	case len(rest) > len("/unblock") && rest[len(rest)-len("/unblock"):] == "/unblock":
		f.blocked[rest[:len(rest)-len("/unblock")]] = false
		_ = json.NewEncoder(w).Encode(ManagementUser{UserID: rest[:len(rest)-len("/unblock")], Blocked: false})
	case r.Method == http.MethodDelete:
		if rest == "missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	case r.Method == http.MethodGet:
		_ = json.NewEncoder(w).Encode(ManagementUser{UserID: rest, Email: "u@example.com", TenantID: r.Header.Get("X-Tenant-ID")})
	case r.Method == http.MethodPatch:
		var in UpdateManagementUser
		_ = json.NewDecoder(r.Body).Decode(&in)
		u := ManagementUser{UserID: rest, TenantID: r.Header.Get("X-Tenant-ID")}
		if in.Name != nil {
			u.Name = *in.Name
		}
		_ = json.NewEncoder(w).Encode(u)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// signToken signs a token with the fake's key and kid. Overrides let
// a test omit/alter claims to exercise rejection paths.
func (f *fakeIAMCore) signToken(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	return f.signTokenWithKID(t, claims, f.kid, jwt.SigningMethodRS256)
}

func (f *fakeIAMCore) signTokenWithKID(t *testing.T, claims jwt.MapClaims, kid string, method jwt.SigningMethod) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(f.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func validClaims(f *fakeIAMCore) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":       f.issuer(),
		"aud":       "sng-api",
		"sub":       "user-123",
		"tenant_id": "tenant-abc",
		"scope":     "openid policy:write",
		"exp":       now.Add(time.Hour).Unix(),
		"nbf":       now.Add(-time.Minute).Unix(),
		"iat":       now.Add(-time.Minute).Unix(),
	}
}

func TestVerifyAccessToken_Valid(t *testing.T) {
	f := newFakeIAMCore(t)
	c := New(f.config())
	claims := validClaims(f)
	claims[f.issuer()+"/roles"] = []string{"admin", "auditor", "admin"}
	claims["amr"] = []string{"pwd", "otp"}
	got, err := c.VerifyAccessToken(context.Background(), f.signToken(t, claims))
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if got.Subject != "user-123" || got.TenantID != "tenant-abc" {
		t.Fatalf("unexpected subject/tenant: %+v", got)
	}
	if !got.HasRole("admin") || !got.HasRole("auditor") {
		t.Fatalf("roles not extracted: %v", got.Roles)
	}
	if len(got.Roles) != 2 {
		t.Fatalf("expected deduped roles, got %v", got.Roles)
	}
	if !got.MFASatisfied {
		t.Fatalf("expected MFA satisfied from amr=otp")
	}
}

func TestVerifyAccessToken_Rejections(t *testing.T) {
	f := newFakeIAMCore(t)
	c := New(f.config())
	ctx := context.Background()

	t.Run("bad signature", func(t *testing.T) {
		other, _ := rsa.GenerateKey(rand.Reader, 2048)
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, validClaims(f))
		tok.Header["kid"] = f.kid
		signed, _ := tok.SignedString(other)
		if _, err := c.VerifyAccessToken(ctx, signed); err == nil {
			t.Fatal("expected signature failure")
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		claims := validClaims(f)
		claims["iss"] = "https://evil.example.com"
		if _, err := c.VerifyAccessToken(ctx, f.signToken(t, claims)); err == nil {
			t.Fatal("expected issuer failure")
		}
	})

	t.Run("wrong audience", func(t *testing.T) {
		claims := validClaims(f)
		claims["aud"] = "other-api"
		if _, err := c.VerifyAccessToken(ctx, f.signToken(t, claims)); err == nil {
			t.Fatal("expected audience failure")
		}
	})

	t.Run("expired", func(t *testing.T) {
		claims := validClaims(f)
		claims["exp"] = time.Now().Add(-2 * time.Hour).Unix()
		if _, err := c.VerifyAccessToken(ctx, f.signToken(t, claims)); err == nil {
			t.Fatal("expected expiry failure")
		}
	})

	t.Run("not yet valid", func(t *testing.T) {
		claims := validClaims(f)
		claims["nbf"] = time.Now().Add(2 * time.Hour).Unix()
		if _, err := c.VerifyAccessToken(ctx, f.signToken(t, claims)); err == nil {
			t.Fatal("expected nbf failure")
		}
	})

	t.Run("missing tenant", func(t *testing.T) {
		claims := validClaims(f)
		delete(claims, "tenant_id")
		if _, err := c.VerifyAccessToken(ctx, f.signToken(t, claims)); err == nil {
			t.Fatal("expected missing tenant failure")
		}
	})

	t.Run("hmac alg confusion rejected", func(t *testing.T) {
		// Forge an HS256 token; a vulnerable verifier would accept it
		// using the public key bytes as the HMAC secret.
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validClaims(f))
		tok.Header["kid"] = f.kid
		signed, _ := tok.SignedString([]byte("whatever"))
		if _, err := c.VerifyAccessToken(ctx, signed); err == nil {
			t.Fatal("expected HS256 to be rejected by alg allow-list")
		}
	})
}

func TestVerifyAccessToken_UnknownKIDRefreshesOnce(t *testing.T) {
	f := newFakeIAMCore(t)
	// Controllable clock so the prime fetch is outside the refresh
	// throttle window when we exercise the unknown-kid path.
	clock := time.Now()
	c := New(f.config(), WithClock(func() time.Time { return clock }))
	ctx := context.Background()

	// Prime the cache with a valid token.
	if _, err := c.VerifyAccessToken(ctx, f.signToken(t, validClaims(f))); err != nil {
		t.Fatalf("prime: %v", err)
	}
	hitsAfterPrime := atomic.LoadInt32(&f.jwksHits)

	// Advance past the throttle so an unknown kid triggers exactly one
	// refresh, then is rejected (still unknown).
	clock = clock.Add(2 * jwksMinRefreshInterval)
	if _, err := c.VerifyAccessToken(ctx, f.signTokenWithKID(t, validClaims(f), "rotated-kid", jwt.SigningMethodRS256)); err == nil {
		t.Fatal("expected unknown kid to be rejected")
	}
	if got := atomic.LoadInt32(&f.jwksHits); got != hitsAfterPrime+1 {
		t.Fatalf("expected exactly one refresh, got %d (was %d)", got, hitsAfterPrime)
	}

	// A second unknown-kid token within the throttle window must NOT
	// trigger another fetch.
	if _, err := c.VerifyAccessToken(ctx, f.signTokenWithKID(t, validClaims(f), "rotated-kid-2", jwt.SigningMethodRS256)); err == nil {
		t.Fatal("expected rejection")
	}
	if got := atomic.LoadInt32(&f.jwksHits); got != hitsAfterPrime+1 {
		t.Fatalf("refresh not throttled: %d", got)
	}
}

func TestManagementToken_CachedAndReused(t *testing.T) {
	f := newFakeIAMCore(t)
	c := New(f.config())
	ctx := context.Background()

	if _, err := c.CreateUser(ctx, "tenant-abc", CreateManagementUser{Email: "a@example.com", Name: "A"}); err != nil {
		t.Fatalf("create 1: %v", err)
	}
	if _, err := c.CreateUser(ctx, "tenant-abc", CreateManagementUser{Email: "b@example.com", Name: "B"}); err != nil {
		t.Fatalf("create 2: %v", err)
	}
	if got := atomic.LoadInt32(&f.tokenHits); got != 1 {
		t.Fatalf("expected management token minted once, got %d", got)
	}
}

func TestManagement_BlockUnblockDeleteFindByEmail(t *testing.T) {
	f := newFakeIAMCore(t)
	c := New(f.config())
	ctx := context.Background()

	if err := c.BlockUser(ctx, "tenant-abc", "user-1"); err != nil {
		t.Fatalf("block: %v", err)
	}
	if !f.blocked["user-1"] {
		t.Fatal("user-1 not blocked server-side")
	}
	if err := c.UnblockUser(ctx, "tenant-abc", "user-1"); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	if f.blocked["user-1"] {
		t.Fatal("user-1 still blocked server-side")
	}

	// Delete of a missing user surfaces a 404 the caller can treat as
	// idempotent.
	err := c.DeleteUser(ctx, "tenant-abc", "missing")
	if StatusCode(err) != http.StatusNotFound {
		t.Fatalf("expected 404, got %v", err)
	}

	u, found, err := c.FindUserByEmail(ctx, "tenant-abc", "found@example.com")
	if err != nil || !found || u.UserID != "user-existing" {
		t.Fatalf("find by email: found=%v u=%+v err=%v", found, u, err)
	}
	_, found, err = c.FindUserByEmail(ctx, "tenant-abc", "nobody@example.com")
	if err != nil || found {
		t.Fatalf("expected not found, got found=%v err=%v", found, err)
	}
}

func TestIntrospect_MFA(t *testing.T) {
	f := newFakeIAMCore(t)
	c := New(f.config())
	ctx := context.Background()

	res, err := c.Introspect(ctx, "some-token")
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !res.Active || res.Subject != "user-123" {
		t.Fatalf("unexpected introspection: %+v", res)
	}
	if res.MFASatisfied {
		t.Fatal("expected MFA not satisfied without amr")
	}

	f.introspectM = true
	res, err = c.Introspect(ctx, "some-token")
	if err != nil {
		t.Fatalf("introspect 2: %v", err)
	}
	if !res.MFASatisfied {
		t.Fatal("expected MFA satisfied with amr=otp")
	}
}

func TestDiscovery_CachedWithFallback(t *testing.T) {
	f := newFakeIAMCore(t)
	c := New(f.config())
	ep, err := c.Discovery(context.Background())
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	if ep.AuthorizationEndpoint != f.issuer()+"/oauth2/authorize" {
		t.Fatalf("unexpected authorize endpoint: %s", ep.AuthorizationEndpoint)
	}
	if ep.TokenEndpoint != f.issuer()+"/oauth2/token" {
		t.Fatalf("unexpected token endpoint: %s", ep.TokenEndpoint)
	}
}

func TestConfigNormalize_DerivesEndpoints(t *testing.T) {
	cfg := Config{Issuer: "https://iam.example.com/"}.normalize()
	if cfg.JWKSURL != "https://iam.example.com/oauth2/jwks" {
		t.Fatalf("jwks: %s", cfg.JWKSURL)
	}
	if cfg.DiscoveryURL != "https://iam.example.com/.well-known/openid-configuration" {
		t.Fatalf("discovery: %s", cfg.DiscoveryURL)
	}
	if cfg.ManagementBaseURL != "https://iam.example.com" {
		t.Fatalf("mgmt base: %s", cfg.ManagementBaseURL)
	}
}

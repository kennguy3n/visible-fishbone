package handler_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// handlerMockIDP is a minimal httptest OIDC provider for handler tests.
type handlerMockIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	aud    string
}

func newHandlerMockIDP(t *testing.T, aud string) *handlerMockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	m := &handlerMockIDP{key: key, kid: "k1", aud: aud}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":         m.server.URL,
			"jwks_uri":       m.server.URL + "/jwks",
			"token_endpoint": m.server.URL + "/token",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := m.key.Public().(*rsa.PublicKey)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
				"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			}},
		})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *handlerMockIDP) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"] = m.server.URL
	claims["aud"] = m.aud
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.kid
	s, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func newTestOIDCHandler(t *testing.T, maxProviders int) (*handler.OIDCHandler, *memory.IDPConfigRepository, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(t.Context(), repository.Tenant{
		Name: "h-test", Slug: "h-" + uuid.New().String()[:8],
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	users := memory.NewUserRepository(store)
	audit := memory.NewAuditLogRepository(store)
	svc := identity.NewOIDCService(configs, users, audit,
		identity.SessionSigner{Secret: []byte("secret"), Issuer: "sng", Audience: "sng-clients"},
		identity.OIDCOptions{AutoProvision: true}, nil)
	h := handler.NewOIDCHandler(configs, svc, maxProviders)
	return h, configs, tn.ID
}

// oidcDo is a thin wrapper over the package-level doJSON helper for
// the unauthenticated/router-mounted OIDC routes (no bearer token).
func oidcDo(t *testing.T, mux http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	return doJSON(t, mux, method, path, "", body)
}

func TestOIDCHandler_ConfigCRUD(t *testing.T) {
	h, _, tenantID := newTestOIDCHandler(t, 10)
	mux := http.NewServeMux()
	h.Register(mux)
	base := "/api/v1/tenants/" + tenantID.String() + "/idp-configs"

	// Create
	w := oidcDo(t, mux, "POST", base, map[string]any{
		"provider_type":   "okta",
		"issuer_url":      "https://issuer.example.com",
		"client_id":       "client-1",
		"allowed_domains": []string{"acme.com"},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("create returned no id")
	}
	if created["enabled"] != true {
		t.Errorf("enabled should default true, got %v", created["enabled"])
	}

	// List
	w = oidcDo(t, mux, "GET", base, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("list: got %d", w.Code)
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &listed)
	if len(listed.Items) != 1 {
		t.Fatalf("list items = %d, want 1", len(listed.Items))
	}

	// Get
	w = oidcDo(t, mux, "GET", base+"/"+id, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: got %d", w.Code)
	}

	// Update (disable)
	w = oidcDo(t, mux, "PUT", base+"/"+id, map[string]any{
		"provider_type": "okta",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "client-1",
		"enabled":       false,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("update: got %d: %s", w.Code, w.Body.String())
	}
	var updated map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &updated)
	if updated["enabled"] != false {
		t.Errorf("update enabled = %v, want false", updated["enabled"])
	}

	// Delete
	w = oidcDo(t, mux, "DELETE", base+"/"+id, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete: got %d", w.Code)
	}
	w = oidcDo(t, mux, "GET", base+"/"+id, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("get after delete: got %d, want 404", w.Code)
	}
}

func TestOIDCHandler_CreateValidation(t *testing.T) {
	h, _, tenantID := newTestOIDCHandler(t, 10)
	mux := http.NewServeMux()
	h.Register(mux)
	base := "/api/v1/tenants/" + tenantID.String() + "/idp-configs"

	// Missing required fields → 400.
	w := oidcDo(t, mux, "POST", base, map[string]any{"provider_type": "okta"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("missing fields: got %d, want 400", w.Code)
	}

	// Invalid provider_type → 400.
	w = oidcDo(t, mux, "POST", base, map[string]any{
		"provider_type": "not-a-provider",
		"issuer_url":    "https://x.example.com",
		"client_id":     "c",
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad provider_type: got %d, want 400", w.Code)
	}
}

// TestOIDCHandler_NormalizesIssuerTrailingSlash locks in that the
// handler canonicalizes issuer_url (trim trailing slash + whitespace)
// before storage, so "https://issuer.example.com/" is stored — and
// reported back — without the trailing slash. This is what lets the
// unique (tenant_id, issuer_url) index actually block trailing-slash
// duplicate registrations of the same issuer.
func TestOIDCHandler_NormalizesIssuerTrailingSlash(t *testing.T) {
	h, _, tenantID := newTestOIDCHandler(t, 10)
	mux := http.NewServeMux()
	h.Register(mux)
	base := "/api/v1/tenants/" + tenantID.String() + "/idp-configs"

	w := oidcDo(t, mux, "POST", base, map[string]any{
		"provider_type": "okta",
		"issuer_url":    "https://issuer.example.com/",
		"client_id":     "client-1",
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: got %d: %s", w.Code, w.Body.String())
	}
	var created map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if got := created["issuer_url"]; got != "https://issuer.example.com" {
		t.Fatalf("issuer_url = %v, want normalized https://issuer.example.com", got)
	}

	// The trailing-slash variant is now the same canonical issuer, so a
	// second create collides on the unique index and is rejected.
	w = oidcDo(t, mux, "POST", base, map[string]any{
		"provider_type": "okta",
		"issuer_url":    "https://issuer.example.com",
		"client_id":     "client-2",
	})
	if w.Code == http.StatusCreated {
		t.Fatalf("duplicate issuer create unexpectedly succeeded: %s", w.Body.String())
	}
}

func TestOIDCHandler_MaxProvidersCap(t *testing.T) {
	h, _, tenantID := newTestOIDCHandler(t, 1)
	mux := http.NewServeMux()
	h.Register(mux)
	base := "/api/v1/tenants/" + tenantID.String() + "/idp-configs"

	mk := func(client string) map[string]any {
		return map[string]any{
			"provider_type": "custom_oidc",
			"issuer_url":    "https://" + client + ".example.com",
			"client_id":     client,
		}
	}
	if w := oidcDo(t, mux, "POST", base, mk("a")); w.Code != http.StatusCreated {
		t.Fatalf("first create: got %d", w.Code)
	}
	if w := oidcDo(t, mux, "POST", base, mk("b")); w.Code != http.StatusTooManyRequests {
		t.Fatalf("second create: got %d, want 429", w.Code)
	}
}

func TestOIDCHandler_MobileToken(t *testing.T) {
	h, configs, tenantID := newTestOIDCHandler(t, 10)
	idp := newHandlerMockIDP(t, "client-1")
	if _, err := configs.Create(context.Background(), tenantID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    idp.server.URL,
		ClientID:     "client-1",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	mux := http.NewServeMux()
	h.RegisterPublic(mux)
	path := "/api/v1/tenants/" + tenantID.String() + "/auth/mobile/token"

	idToken := idp.sign(t, jwt.MapClaims{"sub": "okta|7", "email": "user@acme.com", "email_verified": true})
	w := oidcDo(t, mux, "POST", path, map[string]any{
		"id_token":          idToken,
		"device_public_key": "ZGV2aWNlLWtleQ==",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("mobile token: got %d: %s", w.Code, w.Body.String())
	}
	var resp handler.MobileSessionResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected access_token")
	}
	if resp.TokenType != "Bearer" {
		t.Errorf("token_type = %q", resp.TokenType)
	}
	if resp.Identity.Subject != "okta|7" {
		t.Errorf("identity.subject = %q", resp.Identity.Subject)
	}
	if resp.Binding.DevicePublicKey != "ZGV2aWNlLWtleQ==" {
		t.Errorf("binding.device_public_key = %q", resp.Binding.DevicePublicKey)
	}
	if resp.Binding.UserSubject != "okta|7" {
		t.Errorf("binding.user_subject = %q", resp.Binding.UserSubject)
	}
}

func TestOIDCHandler_MobileToken_BadRequest(t *testing.T) {
	h, _, tenantID := newTestOIDCHandler(t, 10)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)
	path := "/api/v1/tenants/" + tenantID.String() + "/auth/mobile/token"

	// Missing device_public_key → 400.
	w := oidcDo(t, mux, "POST", path, map[string]any{"id_token": "x"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", w.Code)
	}

	// No matching idp config → 404 (resolveConfig ErrNotFound).
	idp := newHandlerMockIDP(t, "client-1")
	idToken := idp.sign(t, jwt.MapClaims{"sub": "s", "email": "u@acme.com"})
	w = oidcDo(t, mux, "POST", path, map[string]any{
		"id_token":          idToken,
		"device_public_key": "ZGV2",
	})
	if w.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404", w.Code)
	}
}

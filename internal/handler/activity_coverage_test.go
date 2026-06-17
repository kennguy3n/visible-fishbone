package handler_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// fakeActivityObserver is a test double for the activity Recorder. It
// satisfies middleware.ActivityObserver (Observe(uuid, time)) and just
// counts touches per tenant so a coverage test can assert that a route
// recorded activity for the right tenant — without standing up the
// async recorder/store.
type fakeActivityObserver struct {
	mu   sync.Mutex
	seen map[uuid.UUID]int
}

func (f *fakeActivityObserver) Observe(tenantID uuid.UUID, _ time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.seen == nil {
		f.seen = make(map[uuid.UUID]int)
	}
	f.seen[tenantID]++
}

func (f *fakeActivityObserver) count(id uuid.UUID) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[id]
}

func (f *fakeActivityObserver) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.seen {
		n += c
	}
	return n
}

// --- public device-enroll ingress ----------------------------------------

// newEnrollHandlerForCoverage wires a DeviceHandler over in-memory
// repos with the activity observer attached, and returns a tenant that
// already exists in the store (so claim-token creation is allowed).
func newEnrollHandlerForCoverage(t *testing.T) (*handler.DeviceHandler, *memory.Store, uuid.UUID, *fakeActivityObserver) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "enroll-cov", Slug: "ec-" + uuid.New().String()[:8],
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	svc := identity.New(
		memory.NewDeviceRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		nil,
	)
	h := handler.NewDeviceHandler(svc, memory.NewDeviceRepository(s), 0)
	deviceCA, err := identity.NewCertAuthority(memory.NewDeviceCARepository(s), policy.PassthroughWrapper{}, nil)
	if err != nil {
		t.Fatalf("NewCertAuthority: %v", err)
	}
	h.SetEnrollmentService(identity.NewEnrollmentService(
		memory.NewDeviceEnrollmentRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		deviceCA,
		nil,
	))
	obs := &fakeActivityObserver{}
	h.SetActivityObserver(obs)
	return h, s, tn.ID, obs
}

// mintClaimToken creates a redeemable claim token for tenantID and
// returns its plaintext (base64url, the on-wire form).
func mintClaimToken(t *testing.T, s *memory.Store, tenantID uuid.UUID) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	hash := sha256.Sum256(raw)
	if _, err := memory.NewClaimTokenRepository(s).Create(context.Background(), tenantID, repository.ClaimToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		TokenHash: hash[:],
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("create claim token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

func TestActivityCoverage_PublicEnroll(t *testing.T) {
	h, s, tenantID, obs := newEnrollHandlerForCoverage(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	body := handler.EnrollDeviceRequest{
		ClaimToken: mintClaimToken(t, s, tenantID),
		TenantID:   tenantID.String(),
		DeviceID:   uuid.New().String(),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}
	w := doJSON(t, mux, http.MethodPost, "/api/v1/enroll", "", body)
	if w.Code != http.StatusCreated {
		t.Fatalf("enroll: got %d: %s", w.Code, w.Body.String())
	}
	if got := obs.count(tenantID); got != 1 {
		t.Fatalf("enroll recorded %d touches for tenant, want 1", got)
	}

	// A failed enrollment (bogus claim token) must NOT record activity —
	// the dormancy signal must never go false-active on an unauthorized
	// attempt.
	bad := handler.EnrollDeviceRequest{
		ClaimToken: base64.RawURLEncoding.EncodeToString([]byte("nope")),
		TenantID:   tenantID.String(),
		DeviceID:   uuid.New().String(),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	}
	w = doJSON(t, mux, http.MethodPost, "/api/v1/enroll", "", bad)
	if w.Code == http.StatusCreated {
		t.Fatalf("bogus enroll unexpectedly succeeded: %s", w.Body.String())
	}
	if got := obs.count(tenantID); got != 1 {
		t.Fatalf("failed enroll changed touch count to %d, want 1", got)
	}
}

// --- public mobile native-SSO ingress -------------------------------------

// covMockIDP is a minimal OIDC provider that serves discovery, JWKS,
// and a /token endpoint (so the refresh flow's refresh_token exchange
// returns a fresh, signed ID token).
type covMockIDP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	aud    string
}

func newCovMockIDP(t *testing.T, aud string) *covMockIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	m := &covMockIDP{key: key, kid: "cov1", aud: aud}
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
	// The refresh-token exchange returns a freshly-signed ID token.
	mux.HandleFunc("/token", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": m.sign(t, jwt.MapClaims{
			"sub": "mob|1", "email": "u@acme.com", "email_verified": true,
		})})
	})
	m.server = httptest.NewServer(mux)
	t.Cleanup(m.server.Close)
	return m
}

func (m *covMockIDP) sign(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iss"] = m.server.URL
	claims["aud"] = m.aud
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = time.Now().Add(time.Hour).Unix()
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = m.kid
	signed, err := tok.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// newMobileHandlerForCoverage wires an OIDCHandler with a registered
// provider config and the activity observers attached.
func newMobileHandlerForCoverage(t *testing.T) (*handler.OIDCHandler, uuid.UUID, *covMockIDP, *fakeActivityObserver, *fakeActivityObserver) {
	t.Helper()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "mob-cov", Slug: "mc-" + uuid.New().String()[:8],
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	svc := identity.NewOIDCService(configs,
		memory.NewUserRepository(store),
		memory.NewAuditLogRepository(store),
		identity.SessionSigner{Secret: []byte("secret"), Issuer: "sng", Audience: "sng-clients"},
		identity.OIDCOptions{AutoProvision: true}, nil)
	idp := newCovMockIDP(t, "client-1")
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    idp.server.URL,
		ClientID:     "client-1",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	tokenObs := &fakeActivityObserver{}
	refreshObs := &fakeActivityObserver{}
	h := handler.NewOIDCHandler(configs, svc, 10).WithActivityObservers(tokenObs, refreshObs)
	return h, tn.ID, idp, tokenObs, refreshObs
}

func TestActivityCoverage_MobileToken(t *testing.T) {
	h, tenantID, idp, tokenObs, refreshObs := newMobileHandlerForCoverage(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)
	path := "/api/v1/tenants/" + tenantID.String() + "/auth/mobile/token"

	idToken := idp.sign(t, jwt.MapClaims{"sub": "mob|1", "email": "u@acme.com", "email_verified": true})
	w := doJSON(t, mux, http.MethodPost, path, "", map[string]any{
		"id_token":          idToken,
		"device_public_key": testDeviceKey(t),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("mobile token: got %d: %s", w.Code, w.Body.String())
	}
	if got := tokenObs.count(tenantID); got != 1 {
		t.Fatalf("token exchange recorded %d touches, want 1", got)
	}
	if got := refreshObs.total(); got != 0 {
		t.Fatalf("refresh observer saw %d touches on a token exchange, want 0", got)
	}

	// A rejected token exchange (no device key → 400) must not record.
	w = doJSON(t, mux, http.MethodPost, path, "", map[string]any{"id_token": idToken})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad token exchange: got %d, want 400", w.Code)
	}
	if got := tokenObs.count(tenantID); got != 1 {
		t.Fatalf("rejected exchange changed touch count to %d, want 1", got)
	}
}

func TestActivityCoverage_MobileRefresh(t *testing.T) {
	h, tenantID, idp, tokenObs, refreshObs := newMobileHandlerForCoverage(t)
	mux := http.NewServeMux()
	h.RegisterPublic(mux)
	path := "/api/v1/tenants/" + tenantID.String() + "/auth/mobile/refresh"

	w := doJSON(t, mux, http.MethodPost, path, "", map[string]any{
		"refresh_token":     "refresh-xyz",
		"issuer":            idp.server.URL,
		"device_public_key": testDeviceKey(t),
	})
	if w.Code != http.StatusOK {
		t.Fatalf("mobile refresh: got %d: %s", w.Code, w.Body.String())
	}
	if got := refreshObs.count(tenantID); got != 1 {
		t.Fatalf("refresh recorded %d touches, want 1", got)
	}
	if got := tokenObs.total(); got != 0 {
		t.Fatalf("token observer saw %d touches on a refresh, want 0", got)
	}

	// A rejected refresh (missing fields → 400) must not record.
	w = doJSON(t, mux, http.MethodPost, path, "", map[string]any{"refresh_token": "x"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("bad refresh: got %d, want 400", w.Code)
	}
	if got := refreshObs.count(tenantID); got != 1 {
		t.Fatalf("rejected refresh changed touch count to %d, want 1", got)
	}
}

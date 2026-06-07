package connectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

func TestGoogle_Type(t *testing.T) {
	g := NewGoogle(http.DefaultClient, "ua")
	if g.Type() != repository.CASBConnectorGoogle {
		t.Fatalf("Type() = %q, want %q", g.Type(), repository.CASBConnectorGoogle)
	}
}

// googleSAFixture is a self-signed service account key used by the tests. The
// embedded RSA key lets the fake token endpoint verify the JWT assertion the
// connector mints, so the tests exercise the real signing path end to end.
type googleSAFixture struct {
	priv      *rsa.PrivateKey
	keyJSON   []byte // a Google service-account key file (config + secret use this)
	clientEml string
}

func newGoogleSAFixture(t *testing.T) googleSAFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	const clientEml = "sa@proj.iam.gserviceaccount.com"
	keyJSON, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"client_email":   clientEml,
		"private_key":    string(pemBytes),
		"private_key_id": "kid-123",
	})
	return googleSAFixture{priv: priv, keyJSON: keyJSON, clientEml: clientEml}
}

// googleServer is a fake Google endpoint serving both the OAuth2 token
// exchange and the Admin SDK Directory/Reports APIs. The token handler
// verifies the JWT-bearer assertion against the fixture's public key and
// asserts the standard service-account claims before issuing a token.
func googleServer(t *testing.T, fx googleSAFixture) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			handleGoogleToken(t, w, r, fx)
			return
		}
		// All API calls must carry the bearer token issued by the token
		// handler. Reject anything else so a regression that skips auth is
		// caught by the existing API tests.
		if r.Header.Get("Authorization") != "Bearer minted-access-token" {
			http.Error(w, "missing/invalid bearer", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/activity"):
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{{
					"id": map[string]any{
						"uniqueQualifier": "q1",
						"time":            "2025-06-01T10:00:00Z",
					},
					"actor":     map[string]any{"email": "alice@co.com"},
					"ipAddress": "1.2.3.4",
					"events":    []map[string]any{{"name": "login_success"}},
				}},
			})
		case strings.Contains(r.URL.Path, "/users") && r.URL.Query().Get("maxResults") == "1":
			json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"primaryEmail": "alice@co.com"},
				},
			})
		case strings.Contains(r.URL.Path, "/users"):
			json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": "u1", "primaryEmail": "alice@co.com", "name": map[string]string{"fullName": "Alice"}, "suspended": false},
					{"id": "u2", "primaryEmail": "bob@co.com", "name": map[string]string{"fullName": "Bob"}, "suspended": true},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
}

func handleGoogleToken(t *testing.T, w http.ResponseWriter, r *http.Request, fx googleSAFixture) {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if got := r.PostFormValue("grant_type"); got != jwtBearerGrant {
		t.Errorf("grant_type = %q, want %q", got, jwtBearerGrant)
	}
	assertion := r.PostFormValue("assertion")
	if assertion == "" {
		http.Error(w, "missing assertion", http.StatusBadRequest)
		return
	}
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(assertion, claims, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, jwt.ErrTokenSignatureInvalid
		}
		return &fx.priv.PublicKey, nil
	})
	if err != nil || !tok.Valid {
		http.Error(w, "assertion verify failed: "+errStr(err), http.StatusUnauthorized)
		return
	}
	if iss, _ := claims["iss"].(string); iss != fx.clientEml {
		t.Errorf("assertion iss = %q, want %q", iss, fx.clientEml)
	}
	if sub, _ := claims["sub"].(string); sub != "admin@co.com" {
		t.Errorf("assertion sub = %q, want admin@co.com", sub)
	}
	if scope, _ := claims["scope"].(string); !strings.Contains(scope, "admin.directory.user.readonly") {
		t.Errorf("assertion scope missing directory scope: %q", scope)
	}
	if kid, _ := tok.Header["kid"].(string); kid != "kid-123" {
		t.Errorf("assertion kid = %q, want kid-123", kid)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": "minted-access-token",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func googleTestCfg(t *testing.T, fx googleSAFixture) (json.RawMessage, []byte) {
	t.Helper()
	cfg, _ := json.Marshal(GoogleConfig{
		Domain:     "co.com",
		AdminEmail: "admin@co.com",
		CustomerID: "C123",
	})
	sec, _ := json.Marshal(GoogleSecret{PrivateKeyJSON: json.RawMessage(fx.keyJSON)})
	return cfg, sec
}

func newTestGoogle(t *testing.T, srv *httptest.Server) *Google {
	t.Helper()
	g := NewGoogle(srv.Client(), "test-ua")
	g.baseURL = srv.URL
	g.tokenURL = srv.URL + "/token"
	return g
}

func TestGoogle_getToken(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t, fx)

	tok, err := g.getToken(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	if tok != "minted-access-token" {
		t.Fatalf("token = %q, want minted-access-token", tok)
	}
}

func TestGoogle_getToken_Errors(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()

	cases := []struct {
		name string
		cfg  GoogleConfig
		sec  GoogleSecret
		want string
	}{
		{
			name: "missing admin email",
			cfg:  GoogleConfig{Domain: "co.com"},
			sec:  GoogleSecret{PrivateKeyJSON: json.RawMessage(fx.keyJSON)},
			want: "domain and admin_email are required",
		},
		{
			name: "missing key",
			cfg:  GoogleConfig{Domain: "co.com", AdminEmail: "admin@co.com"},
			sec:  GoogleSecret{},
			want: "private_key_json is required",
		},
		{
			name: "key without private_key",
			cfg:  GoogleConfig{Domain: "co.com", AdminEmail: "admin@co.com"},
			sec:  GoogleSecret{PrivateKeyJSON: json.RawMessage(`{"client_email":"sa@x.com"}`)},
			want: "missing private_key",
		},
		{
			name: "unparseable private key",
			cfg:  GoogleConfig{Domain: "co.com", AdminEmail: "admin@co.com"},
			sec:  GoogleSecret{PrivateKeyJSON: json.RawMessage(`{"client_email":"sa@x.com","private_key":"-----BEGIN PRIVATE KEY-----\nnope\n-----END PRIVATE KEY-----\n"}`)},
			want: "parse service account private key",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newTestGoogle(t, srv)
			cfg, _ := json.Marshal(tc.cfg)
			sec, _ := json.Marshal(tc.sec)
			_, err := g.getToken(context.Background(), cfg, sec)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidateGoogleTokenURI(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		wantErr string
	}{
		{name: "google token endpoint", uri: "https://oauth2.googleapis.com/token"},
		{name: "google accounts endpoint", uri: "https://accounts.google.com/o/oauth2/token"},
		{name: "http scheme rejected", uri: "http://oauth2.googleapis.com/token", wantErr: "must use https"},
		{name: "metadata ssrf rejected", uri: "https://169.254.169.254/latest/meta-data/", wantErr: "untrusted token_uri host"},
		{name: "internal host rejected", uri: "https://internal-svc.local/token", wantErr: "untrusted token_uri host"},
		{name: "lookalike host rejected", uri: "https://oauth2.googleapis.com.evil.com/token", wantErr: "untrusted token_uri host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateGoogleTokenURI(tc.uri)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateGoogleTokenURI(%q) = %v, want nil", tc.uri, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validateGoogleTokenURI(%q) = %v, want substring %q", tc.uri, err, tc.wantErr)
			}
		})
	}
}

func TestGoogle_getToken_RejectsUntrustedTokenURI(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()
	g := newTestGoogle(t, srv)

	// A tenant-supplied key that tries to redirect the assertion POST at an
	// internal/metadata endpoint must be rejected before any network call.
	var keyMap map[string]any
	if err := json.Unmarshal(fx.keyJSON, &keyMap); err != nil {
		t.Fatalf("unmarshal fixture key: %v", err)
	}
	keyMap["token_uri"] = "http://169.254.169.254/latest/meta-data/"
	malicious, _ := json.Marshal(keyMap)

	cfg, _ := json.Marshal(GoogleConfig{Domain: "co.com", AdminEmail: "admin@co.com"})
	sec, _ := json.Marshal(GoogleSecret{PrivateKeyJSON: json.RawMessage(malicious)})

	_, err := g.getToken(context.Background(), cfg, sec)
	if err == nil || !strings.Contains(err.Error(), "token_uri") {
		t.Fatalf("want token_uri rejection error, got %v", err)
	}
}

func TestGoogle_getToken_TokenEndpointError(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t, fx)
	_, err := g.getToken(context.Background(), cfg, sec)
	if err == nil || !strings.Contains(err.Error(), "token endpoint returned 400") {
		t.Fatalf("want token endpoint 400 error, got %v", err)
	}
}

func TestGoogle_Test_OK(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t, fx)
	if err := g.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestGoogle_ListUsers(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t, fx)
	users, err := g.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
}

func TestGoogle_ListActivity(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t, fx)
	events, err := g.ListActivity(context.Background(), cfg, sec, "2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}

func TestGoogle_AssessPosture(t *testing.T) {
	fx := newGoogleSAFixture(t)
	srv := googleServer(t, fx)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t, fx)
	report, err := g.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("expected posture checks")
	}
	if report.RiskScore < 0 || report.RiskScore > 100 {
		t.Errorf("score out of range: %d", report.RiskScore)
	}
}

var _ casb.CASBConnectorPlugin = (*Google)(nil)

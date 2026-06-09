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

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// testServiceAccountKey generates a throwaway RSA key and returns a
// GCP service-account key JSON (no token_uri, so the connector uses
// its overridable default token endpoint).
func testServiceAccountKey(t *testing.T) json.RawMessage {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	raw, _ := json.Marshal(map[string]any{
		"type":           "service_account",
		"client_email":   "sa@proj.iam.gserviceaccount.com",
		"private_key":    string(pemBytes),
		"private_key_id": "kid1",
	})
	return raw
}

func gcpServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "gcp-tok"})
		case strings.HasSuffix(r.URL.Path, ":getIamPolicy"):
			if got := r.Header.Get("Authorization"); got != "Bearer gcp-tok" {
				t.Errorf("auth header = %q", got)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"bindings": []map[string]any{
					{"role": "roles/owner", "members": []string{"user:a@x.io"}},
					{"role": "roles/viewer", "members": []string{"user:b@x.io"}},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/v2/entries:list"):
			json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]any{{
					"insertId": "i1", "timestamp": "2024-05-01T10:00:00Z",
					"protoPayload": map[string]any{
						"methodName":         "SetIamPolicy",
						"resourceName":       "projects/proj",
						"authenticationInfo": map[string]any{"principalEmail": "a@x.io"},
						"requestMetadata":    map[string]any{"callerIp": "1.2.3.4"},
					},
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestGCP(t *testing.T, srv *httptest.Server) (*GCPConsole, json.RawMessage, []byte) {
	g := NewGCPConsole(srv.Client(), "test-ua")
	g.crmBase = srv.URL
	g.loggingBase = srv.URL
	g.tokenURL = srv.URL + "/token"
	cfg, _ := json.Marshal(GCPConsoleConfig{ProjectID: "proj"})
	sec, _ := json.Marshal(GCPConsoleSecret{ServiceAccountKey: testServiceAccountKey(t)})
	return g, cfg, sec
}

func TestGCPConsole_Type(t *testing.T) {
	if NewGCPConsole(http.DefaultClient, "ua").Type() != repository.CASBConnectorGCPConsole {
		t.Fatal("wrong type")
	}
}

func TestGCPConsole_TestAndUsers(t *testing.T) {
	srv := gcpServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGCP(t, srv)
	if err := g.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := g.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	byEmail := map[string]casb.SaaSUser{}
	for _, u := range users {
		byEmail[u.Email] = u
	}
	if !byEmail["a@x.io"].Admin || byEmail["b@x.io"].Admin {
		t.Fatalf("admin flags wrong: %+v", users)
	}
}

func TestGCPConsole_ListActivity(t *testing.T) {
	srv := gcpServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGCP(t, srv)
	events, err := g.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "SetIamPolicy" || events[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestGCPConsole_AssessPosture(t *testing.T) {
	srv := gcpServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGCP(t, srv)
	report, err := g.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %+v", report.Checks)
	}
}

func TestGCPConsole_Validation(t *testing.T) {
	g := NewGCPConsole(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(GCPConsoleConfig{})
	sec, _ := json.Marshal(GCPConsoleSecret{ServiceAccountKey: json.RawMessage(`{}`)})
	if err := g.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing project_id")
	}
}

var _ casb.CASBConnectorPlugin = (*GCPConsole)(nil)

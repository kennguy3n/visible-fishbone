package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

func TestM365_Type(t *testing.T) {
	m := NewM365(http.DefaultClient, "ua")
	if m.Type() != repository.CASBConnectorM365 {
		t.Fatalf("Type() = %q, want %q", m.Type(), repository.CASBConnectorM365)
	}
}

// m365Server returns an httptest.Server that speaks the token +
// Graph API subset the M365 connector uses.
func m365Server(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// Token endpoint.
		if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "token") {
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "test-tok", "expires_in": 3600,
			})
			return
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/users"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "u1", "displayName": "Alice", "mail": "alice@co.com", "accountEnabled": true},
					{"id": "u2", "displayName": "Bob", "mail": "bob@co.com", "accountEnabled": false},
				},
			})
		case strings.Contains(r.URL.Path, "signIns"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{
					"id": "s1", "userPrincipalName": "alice@co.com",
					"createdDateTime": "2025-06-01T10:00:00Z",
					"appDisplayName":  "Browser",
					"status":          map[string]any{"errorCode": float64(0)},
				}},
			})
		case strings.HasSuffix(r.URL.Path, "/organization"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "org1", "displayName": "Acme"},
				},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{"value": []any{}})
		}
	}))
}

// m365TestCfg returns (config, secret) for the given test server.
func m365TestCfg(t *testing.T, srvURL string) (json.RawMessage, []byte) {
	t.Helper()
	cfg, _ := json.Marshal(M365Config{
		AzureTenantID: "test-tenant",
		ClientID:      "test-client",
	})
	sec, _ := json.Marshal(M365Secret{ClientSecret: "test-secret"})
	return cfg, sec
}

// newTestM365 returns an M365 that uses the given test server for
// both the Graph API and the Azure AD token endpoint.
func newTestM365(t *testing.T, srv *httptest.Server) *M365 {
	t.Helper()
	m := NewM365(srv.Client(), "test-ua")
	// Swap the base URLs so all requests go to the test server.
	m.graphBase = srv.URL
	m.tokenBaseURL = srv.URL
	return m
}

func TestM365_Test_OK(t *testing.T) {
	srv := m365Server(t)
	defer srv.Close()

	m := newTestM365(t, srv)
	cfg, sec := m365TestCfg(t, srv.URL)
	if err := m.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestM365_ListUsers(t *testing.T) {
	srv := m365Server(t)
	defer srv.Close()

	m := newTestM365(t, srv)
	cfg, sec := m365TestCfg(t, srv.URL)
	users, err := m.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
	if users[0].DisplayName != "Alice" {
		t.Errorf("users[0].DisplayName = %q", users[0].DisplayName)
	}
}

func TestM365_ListActivity(t *testing.T) {
	srv := m365Server(t)
	defer srv.Close()

	m := newTestM365(t, srv)
	cfg, sec := m365TestCfg(t, srv.URL)
	events, err := m.ListActivity(context.Background(), cfg, sec, "")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}

func TestM365_AssessPosture(t *testing.T) {
	srv := m365Server(t)
	defer srv.Close()

	m := newTestM365(t, srv)
	cfg, sec := m365TestCfg(t, srv.URL)
	report, err := m.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("expected posture checks")
	}
	if report.Score < 0 || report.Score > 100 {
		t.Errorf("score out of range: %d", report.Score)
	}
}

var _ casb.CASBConnectorPlugin = (*M365)(nil)

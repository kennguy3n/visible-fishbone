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

func TestGoogle_Type(t *testing.T) {
	g := NewGoogle(http.DefaultClient, "ua")
	if g.Type() != repository.CASBConnectorGoogle {
		t.Fatalf("Type() = %q, want %q", g.Type(), repository.CASBConnectorGoogle)
	}
}

func googleServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

func googleTestCfg(t *testing.T) (json.RawMessage, []byte) {
	t.Helper()
	cfg, _ := json.Marshal(GoogleConfig{
		Domain:     "co.com",
		AdminEmail: "admin@co.com",
		CustomerID: "C123",
	})
	sec, _ := json.Marshal(GoogleSecret{PrivateKeyJSON: json.RawMessage(`{"type":"service_account"}`)})
	return cfg, sec
}

func newTestGoogle(t *testing.T, srv *httptest.Server) *Google {
	t.Helper()
	g := NewGoogle(srv.Client(), "test-ua")
	g.baseURL = srv.URL
	return g
}

func TestGoogle_Test_OK(t *testing.T) {
	srv := googleServer(t)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t)
	if err := g.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestGoogle_ListUsers(t *testing.T) {
	srv := googleServer(t)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t)
	users, err := g.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
}

func TestGoogle_ListActivity(t *testing.T) {
	srv := googleServer(t)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t)
	events, err := g.ListActivity(context.Background(), cfg, sec, "2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}

func TestGoogle_AssessPosture(t *testing.T) {
	srv := googleServer(t)
	defer srv.Close()
	g := newTestGoogle(t, srv)
	cfg, sec := googleTestCfg(t)
	report, err := g.AssessPosture(context.Background(), cfg, sec)
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

var _ casb.CASBConnectorPlugin = (*Google)(nil)

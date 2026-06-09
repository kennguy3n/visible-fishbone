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

func zendeskServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin@x.io/token" || p != "tok" {
			t.Errorf("basic auth = %q/%q ok=%v", u, p, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/users/me.json"):
			json.NewEncoder(w).Encode(map[string]any{"user": json.RawMessage(`{"id":1}`)})
		case strings.HasSuffix(r.URL.Path, "/users.json"):
			json.NewEncoder(w).Encode(map[string]any{
				"users": []map[string]any{
					{"id": 1, "name": "Admin", "email": "a@x.io", "active": true, "role": "admin"},
					{"id": 2, "name": "Agent", "email": "b@x.io", "active": true, "role": "agent"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/audit_logs.json"):
			json.NewEncoder(w).Encode(map[string]any{
				"audit_logs": []map[string]any{{
					"id": 7, "actor_id": 1, "actor_name": "Admin", "action": "create",
					"source_type": "user", "ip_address": "1.2.3.4", "created_at": "2024-05-01T10:00:00Z",
				}},
			})
		case strings.HasSuffix(r.URL.Path, "/account/settings.json"):
			json.NewEncoder(w).Encode(map[string]any{
				"settings": map[string]any{
					"security": map[string]any{"two_factor_authentication_required": true},
				},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestZendesk(srv *httptest.Server) (*Zendesk, json.RawMessage, []byte) {
	z := NewZendesk(srv.Client(), "test-ua")
	z.defaultBase = srv.URL
	cfg, _ := json.Marshal(ZendeskConfig{})
	sec, _ := json.Marshal(ZendeskSecret{Email: "admin@x.io", APIToken: "tok"})
	return z, cfg, sec
}

func TestZendesk_Type(t *testing.T) {
	if NewZendesk(http.DefaultClient, "ua").Type() != repository.CASBConnectorZendesk {
		t.Fatal("wrong type")
	}
}

func TestZendesk_TestAndUsers(t *testing.T) {
	srv := zendeskServer(t)
	defer srv.Close()
	z, cfg, sec := newTestZendesk(srv)
	if err := z.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := z.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || !users[0].Admin || users[1].Admin {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestZendesk_ListActivity(t *testing.T) {
	srv := zendeskServer(t)
	defer srv.Close()
	z, cfg, sec := newTestZendesk(srv)
	events, err := z.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "create" || events[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestZendesk_AssessPosture(t *testing.T) {
	srv := zendeskServer(t)
	defer srv.Close()
	z, cfg, sec := newTestZendesk(srv)
	report, err := z.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 1 || report.RiskScore != 0 {
		t.Fatalf("expected 1 healthy check, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestZendesk_Validation(t *testing.T) {
	z := NewZendesk(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(ZendeskConfig{})
	sec, _ := json.Marshal(ZendeskSecret{})
	if err := z.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing email/api_token")
	}
}

func TestZendesk_RejectsPrivateBaseURL(t *testing.T) {
	z := NewZendesk(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(ZendeskConfig{BaseURL: "https://192.168.1.1"})
	sec, _ := json.Marshal(ZendeskSecret{Email: "a@x.io", APIToken: "t"})
	if err := z.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected SSRF rejection for private base_url")
	}
}

var _ casb.CASBConnectorPlugin = (*Zendesk)(nil)

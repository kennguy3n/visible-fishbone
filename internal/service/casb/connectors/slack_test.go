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

func TestSlack_Type(t *testing.T) {
	s := NewSlack(http.DefaultClient, "ua")
	if s.Type() != repository.CASBConnectorSlack {
		t.Fatalf("Type() = %q, want %q", s.Type(), repository.CASBConnectorSlack)
	}
}

func slackServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.Path, "/scim/v1/Users"):
			json.NewEncoder(w).Encode(map[string]any{
				"Resources": []map[string]any{
					{
						"id":          "u1",
						"userName":    "alice",
						"displayName": "Alice",
						"active":      true,
						"emails":      []map[string]any{{"value": "alice@co.com", "primary": true}},
					},
				},
			})
		case strings.Contains(r.URL.Path, "/audit/v1/logs"):
			json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]any{{
					"id":          "ev1",
					"date_create": 1717228800,
					"action":      "user_login",
					"actor": map[string]any{
						"user": map[string]any{"email": "alice@co.com"},
					},
				}},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
}

func slackTestCfg(t *testing.T) (json.RawMessage, []byte) {
	t.Helper()
	cfg, _ := json.Marshal(SlackConfig{WorkspaceID: "W123"})
	sec, _ := json.Marshal(SlackSecret{Token: "xoxp-test"})
	return cfg, sec
}

func newTestSlack(t *testing.T, srv *httptest.Server) *Slack {
	t.Helper()
	s := NewSlack(srv.Client(), "test-ua")
	s.baseURL = srv.URL
	return s
}

func TestSlack_Test_OK(t *testing.T) {
	srv := slackServer(t)
	defer srv.Close()
	s := newTestSlack(t, srv)
	cfg, sec := slackTestCfg(t)
	if err := s.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestSlack_ListUsers(t *testing.T) {
	srv := slackServer(t)
	defer srv.Close()
	s := newTestSlack(t, srv)
	cfg, sec := slackTestCfg(t)
	users, err := s.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("want 1 user, got %d", len(users))
	}
	if users[0].Email != "alice@co.com" {
		t.Errorf("email = %q", users[0].Email)
	}
}

func TestSlack_ListActivity(t *testing.T) {
	srv := slackServer(t)
	defer srv.Close()
	s := newTestSlack(t, srv)
	cfg, sec := slackTestCfg(t)
	events, err := s.ListActivity(context.Background(), cfg, sec, "")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}

func TestSlack_AssessPosture(t *testing.T) {
	srv := slackServer(t)
	defer srv.Close()
	s := newTestSlack(t, srv)
	cfg, sec := slackTestCfg(t)
	report, err := s.AssessPosture(context.Background(), cfg, sec)
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

var _ casb.CASBConnectorPlugin = (*Slack)(nil)

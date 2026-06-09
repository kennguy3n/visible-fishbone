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

func confluenceServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/wiki/rest/api/space"):
			json.NewEncoder(w).Encode(map[string]any{"results": []json.RawMessage{json.RawMessage(`{}`)}})
		case strings.HasSuffix(r.URL.Path, "/rest/api/3/users/search"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"accountId": "a1", "displayName": "Admin", "emailAddress": "admin@x.io", "active": true, "accountType": "atlassian"},
				{"accountId": "a2", "displayName": "Stale", "emailAddress": "s@x.io", "active": false, "accountType": "atlassian"},
			})
		case strings.HasSuffix(r.URL.Path, "/wiki/rest/api/audit"):
			json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{{
					"author":        map[string]any{"displayName": "Admin"},
					"remoteAddress": "1.2.3.4", "creationDate": 1714557600000,
					"summary": "Page removed", "category": "content",
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestConfluence(srv *httptest.Server) (*Confluence, json.RawMessage, []byte) {
	c := NewConfluence(srv.Client(), "test-ua")
	c.defaultBase = srv.URL
	cfg, _ := json.Marshal(ConfluenceConfig{})
	sec, _ := json.Marshal(ConfluenceSecret{Email: "admin@x.io", APIToken: "tok"})
	return c, cfg, sec
}

func TestConfluence_Type(t *testing.T) {
	if NewConfluence(http.DefaultClient, "ua").Type() != repository.CASBConnectorConfluence {
		t.Fatal("wrong type")
	}
}

func TestConfluence_TestAndUsers(t *testing.T) {
	srv := confluenceServer(t)
	defer srv.Close()
	c, cfg, sec := newTestConfluence(srv)
	if err := c.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := c.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
}

func TestConfluence_ListActivity(t *testing.T) {
	srv := confluenceServer(t)
	defer srv.Close()
	c, cfg, sec := newTestConfluence(srv)
	events, err := c.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "Page removed" {
		t.Fatalf("unexpected events: %+v", events)
	}
	if events[0].Timestamp.IsZero() {
		t.Error("expected epoch-millis timestamp to be parsed")
	}
}

func TestConfluence_AssessPosture(t *testing.T) {
	srv := confluenceServer(t)
	defer srv.Close()
	c, cfg, sec := newTestConfluence(srv)
	report, err := c.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	byName := map[string]casb.PostureCheck{}
	for _, ch := range report.Checks {
		byName[ch.Name] = ch
	}
	// One inactive-yet-present account → inactive_accounts warns.
	if byName["inactive_accounts"].Status != casb.CheckStatusWarn {
		t.Errorf("inactive_accounts = %+v", byName["inactive_accounts"])
	}
}

func TestConfluence_Validation(t *testing.T) {
	c := NewConfluence(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(ConfluenceConfig{})
	sec, _ := json.Marshal(ConfluenceSecret{})
	if err := c.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing email/token")
	}
}

var _ casb.CASBConnectorPlugin = (*Confluence)(nil)

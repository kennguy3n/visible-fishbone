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

func jiraServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "admin@x.io" || p != "tok" {
			t.Errorf("basic auth = %q/%q ok=%v", u, p, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/rest/api/3/myself"):
			json.NewEncoder(w).Encode(map[string]any{"accountId": "a1"})
		case strings.HasSuffix(r.URL.Path, "/rest/api/3/users/search"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"accountId": "a1", "displayName": "Admin", "emailAddress": "admin@x.io", "active": true, "accountType": "atlassian"},
				{"accountId": "a2", "displayName": "Cust", "emailAddress": "c@ext.io", "active": true, "accountType": "customer"},
				{"accountId": "a3", "displayName": "Bot", "active": true, "accountType": "app"},
			})
		case strings.HasSuffix(r.URL.Path, "/rest/api/3/auditing/record"):
			json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{{
					"id": 5, "summary": "User added to group", "created": "2024-05-01T10:00:00.000+0000",
					"authorAccountId": "a1", "remoteAddress": "1.2.3.4", "objectItem": map[string]any{"name": "jira-admins"},
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestJira(srv *httptest.Server) (*Jira, json.RawMessage, []byte) {
	j := NewJira(srv.Client(), "test-ua")
	j.defaultBase = srv.URL
	cfg, _ := json.Marshal(JiraConfig{})
	sec, _ := json.Marshal(JiraSecret{Email: "admin@x.io", APIToken: "tok"})
	return j, cfg, sec
}

func TestJira_Type(t *testing.T) {
	if NewJira(http.DefaultClient, "ua").Type() != repository.CASBConnectorJira {
		t.Fatal("wrong type")
	}
}

func TestJira_TestAndUsers(t *testing.T) {
	srv := jiraServer(t)
	defer srv.Close()
	j, cfg, sec := newTestJira(srv)
	if err := j.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := j.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	// "app" account filtered out → 2 people remain.
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d: %+v", len(users), users)
	}
}

func TestJira_ListActivity(t *testing.T) {
	srv := jiraServer(t)
	defer srv.Close()
	j, cfg, sec := newTestJira(srv)
	events, err := j.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "User added to group" || events[0].Target != "jira-admins" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestJira_AssessPosture(t *testing.T) {
	srv := jiraServer(t)
	defer srv.Close()
	j, cfg, sec := newTestJira(srv)
	report, err := j.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	byName := map[string]casb.PostureCheck{}
	for _, c := range report.Checks {
		byName[c.Name] = c
	}
	// One external customer account → external_accounts warns.
	if byName["external_accounts"].Status != casb.CheckStatusWarn {
		t.Errorf("external_accounts = %+v", byName["external_accounts"])
	}
}

func TestJira_Validation(t *testing.T) {
	j := NewJira(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(JiraConfig{})
	sec, _ := json.Marshal(JiraSecret{Email: "", APIToken: ""})
	if err := j.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing email/token")
	}
}

func TestJira_RejectsPrivateBaseURL(t *testing.T) {
	j := NewJira(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(JiraConfig{BaseURL: "https://10.0.0.5"})
	sec, _ := json.Marshal(JiraSecret{Email: "a@x.io", APIToken: "t"})
	if err := j.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected SSRF rejection for private base_url")
	}
}

var _ casb.CASBConnectorPlugin = (*Jira)(nil)

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

func githubServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer ghp-test" {
			t.Errorf("auth header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.Contains(r.URL.RawQuery, "role=admin"):
			json.NewEncoder(w).Encode([]map[string]any{{"login": "owner1", "id": 1}})
		case strings.HasSuffix(r.URL.Path, "/members"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"login": "owner1", "id": 1},
				{"login": "dev1", "id": 2},
			})
		case strings.Contains(r.URL.Path, "/audit-log"):
			json.NewEncoder(w).Encode([]map[string]any{{
				"_document_id": "ev1", "action": "repo.create", "actor": "owner1",
				"@timestamp": 1717228800000, "repo": "acme/api",
			}})
		case strings.HasSuffix(r.URL.Path, "/orgs/acme"):
			json.NewEncoder(w).Encode(map[string]any{
				"login":                                  "acme",
				"two_factor_requirement_enabled":         true,
				"default_repository_permission":          "read",
				"members_can_create_public_repositories": false,
				"web_commit_signoff_required":            true,
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestGitHub(t *testing.T, srv *httptest.Server) (*GitHub, json.RawMessage, []byte) {
	t.Helper()
	g := NewGitHub(srv.Client(), "test-ua")
	g.defaultBase = srv.URL
	cfg, _ := json.Marshal(GitHubConfig{Org: "acme"})
	sec, _ := json.Marshal(GitHubSecret{Token: "ghp-test"})
	return g, cfg, sec
}

func TestGitHub_Type(t *testing.T) {
	if NewGitHub(http.DefaultClient, "ua").Type() != repository.CASBConnectorGitHub {
		t.Fatal("wrong type")
	}
}

func TestGitHub_Test_OK(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitHub(t, srv)
	if err := g.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestGitHub_ListUsers_FlagsAdmins(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitHub(t, srv)
	users, err := g.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d", len(users))
	}
	byName := map[string]casb.SaaSUser{}
	for _, u := range users {
		byName[u.DisplayName] = u
	}
	if !byName["owner1"].Admin {
		t.Error("owner1 should be flagged admin")
	}
	if byName["dev1"].Admin {
		t.Error("dev1 should not be admin")
	}
}

func TestGitHub_ListActivity(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitHub(t, srv)
	events, err := g.ListActivity(context.Background(), cfg, sec, "2024-01-01")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "repo.create" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestGitHub_AssessPosture(t *testing.T) {
	srv := githubServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitHub(t, srv)
	report, err := g.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("expected checks")
	}
	if report.RiskScore < 0 || report.RiskScore > 100 {
		t.Errorf("score out of range: %d", report.RiskScore)
	}
	// All controls are healthy in the fixture → score should be 0.
	if report.RiskScore != 0 {
		t.Errorf("expected clean posture score 0, got %d", report.RiskScore)
	}
}

func TestGitHub_Validation(t *testing.T) {
	g := NewGitHub(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(GitHubConfig{Org: ""})
	sec, _ := json.Marshal(GitHubSecret{Token: "x"})
	if err := g.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing org")
	}
}

var _ casb.CASBConnectorPlugin = (*GitHub)(nil)

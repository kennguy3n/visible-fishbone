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

func gitlabServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer glpat-test" {
			t.Errorf("auth header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v4/user"):
			json.NewEncoder(w).Encode(map[string]any{"id": 1})
		case strings.HasSuffix(r.URL.Path, "/api/v4/users"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": 1, "username": "root", "name": "Admin", "email": "a@x.io", "state": "active", "is_admin": true},
				{"id": 2, "username": "dev", "name": "Dev", "email": "d@x.io", "state": "active", "is_admin": false},
			})
		case strings.HasSuffix(r.URL.Path, "/api/v4/audit_events"):
			json.NewEncoder(w).Encode([]map[string]any{{
				"id": 7, "author_id": 1, "author_name": "Admin", "created_at": "2024-05-01T00:00:00Z",
				"details": map[string]any{"change": "permission", "target_type": "User", "ip_address": "1.2.3.4"},
			}})
		case strings.HasSuffix(r.URL.Path, "/api/v4/application/settings"):
			json.NewEncoder(w).Encode(map[string]any{
				"require_two_factor_authentication": true,
				"signup_enabled":                    false,
				"admin_mode":                        true,
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestGitLab(srv *httptest.Server) (*GitLab, json.RawMessage, []byte) {
	g := NewGitLab(srv.Client(), "test-ua")
	g.defaultBase = srv.URL
	cfg, _ := json.Marshal(GitLabConfig{})
	sec, _ := json.Marshal(GitLabSecret{Token: "glpat-test"})
	return g, cfg, sec
}

func TestGitLab_Type(t *testing.T) {
	if NewGitLab(http.DefaultClient, "ua").Type() != repository.CASBConnectorGitLab {
		t.Fatal("wrong type")
	}
}

func TestGitLab_TestAndUsers(t *testing.T) {
	srv := gitlabServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitLab(srv)
	if err := g.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
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
	if !byName["Admin"].Admin || byName["Dev"].Admin {
		t.Errorf("admin flags wrong: %+v", users)
	}
}

func TestGitLab_ListActivity(t *testing.T) {
	srv := gitlabServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitLab(srv)
	events, err := g.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "permission" || events[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestGitLab_AssessPosture(t *testing.T) {
	srv := gitlabServer(t)
	defer srv.Close()
	g, cfg, sec := newTestGitLab(srv)
	report, err := g.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) == 0 || report.RiskScore != 0 {
		t.Fatalf("expected healthy posture, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestGitLab_Validation(t *testing.T) {
	g := NewGitLab(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(GitLabConfig{})
	sec, _ := json.Marshal(GitLabSecret{Token: ""})
	if err := g.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestGitLab_RejectsPrivateBaseURL(t *testing.T) {
	g := NewGitLab(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(GitLabConfig{BaseURL: "http://169.254.169.254"})
	sec, _ := json.Marshal(GitLabSecret{Token: "x"})
	if err := g.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected SSRF rejection for link-local base_url")
	}
}

var _ casb.CASBConnectorPlugin = (*GitLab)(nil)

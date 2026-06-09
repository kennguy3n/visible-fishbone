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

func dropboxServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer dbx-test" {
			t.Errorf("auth header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/2/team/get_info"):
			json.NewEncoder(w).Encode(map[string]any{
				"name": map[string]any{"display_name": "Acme"},
				"policies": map[string]any{
					"shared_folder_member_policy": map[string]any{".tag": "team"},
					"shared_link_create_policy":   map[string]any{".tag": "team_only"},
					"emm_state":                   map[string]any{".tag": "required"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/2/team/members/list_v2"):
			json.NewEncoder(w).Encode(map[string]any{
				"members": []map[string]any{
					{"profile": map[string]any{"team_member_id": "m1", "email": "a@x.io",
						"status": map[string]any{".tag": "active"}, "name": map[string]any{"display_name": "Admin"}},
						"role": map[string]any{".tag": "team_admin"}},
					{"profile": map[string]any{"team_member_id": "m2", "email": "b@x.io",
						"status": map[string]any{".tag": "active"}, "name": map[string]any{"display_name": "User"}},
						"role": map[string]any{".tag": "member_only"}},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/2/team_log/get_events"):
			json.NewEncoder(w).Encode(map[string]any{
				"events": []map[string]any{{
					"timestamp":  "2024-05-01T10:00:00Z",
					"event_type": map[string]any{".tag": "shared_link_create"},
					"actor":      map[string]any{"user": map[string]any{"email": "a@x.io"}},
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestDropbox(srv *httptest.Server) (*Dropbox, json.RawMessage, []byte) {
	d := NewDropbox(srv.Client(), "test-ua")
	d.baseURL = srv.URL
	cfg, _ := json.Marshal(DropboxConfig{TeamID: "t1"})
	sec, _ := json.Marshal(DropboxSecret{Token: "dbx-test"})
	return d, cfg, sec
}

func TestDropbox_Type(t *testing.T) {
	if NewDropbox(http.DefaultClient, "ua").Type() != repository.CASBConnectorDropbox {
		t.Fatal("wrong type")
	}
}

func TestDropbox_TestAndUsers(t *testing.T) {
	srv := dropboxServer(t)
	defer srv.Close()
	d, cfg, sec := newTestDropbox(srv)
	if err := d.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := d.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2, got %d", len(users))
	}
	byName := map[string]casb.SaaSUser{}
	for _, u := range users {
		byName[u.DisplayName] = u
	}
	if !byName["Admin"].Admin || byName["User"].Admin {
		t.Errorf("admin flags wrong: %+v", users)
	}
}

func TestDropbox_ListActivity(t *testing.T) {
	srv := dropboxServer(t)
	defer srv.Close()
	d, cfg, sec := newTestDropbox(srv)
	events, err := d.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "shared_link_create" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestDropbox_AssessPosture(t *testing.T) {
	srv := dropboxServer(t)
	defer srv.Close()
	d, cfg, sec := newTestDropbox(srv)
	report, err := d.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 3 || report.RiskScore != 0 {
		t.Fatalf("expected 3 healthy checks, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestDropbox_Validation(t *testing.T) {
	d := NewDropbox(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(DropboxConfig{})
	sec, _ := json.Marshal(DropboxSecret{Token: ""})
	if err := d.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing token")
	}
}

var _ casb.CASBConnectorPlugin = (*Dropbox)(nil)

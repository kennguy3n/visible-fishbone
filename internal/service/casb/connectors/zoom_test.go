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

func zoomServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth/token"):
			if u, _, _ := r.BasicAuth(); u != "cid" {
				t.Errorf("basic user = %q", u)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "zoom-tok"})
		case strings.HasSuffix(r.URL.Path, "/v2/users"):
			if got := r.Header.Get("Authorization"); got != "Bearer zoom-tok" {
				t.Errorf("auth header = %q", got)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"total_records": 2,
				"users": []map[string]any{
					{"id": "1", "email": "a@x.io", "first_name": "Ad", "last_name": "Min", "status": "active", "role_name": "Owner"},
					{"id": "2", "email": "b@x.io", "first_name": "Re", "last_name": "Gular", "status": "active", "role_name": "Member"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/v2/report/activities"):
			json.NewEncoder(w).Encode(map[string]any{
				"activity_logs": []map[string]any{{
					"email": "a@x.io", "time": "2024-05-01T10:00:00Z", "type": "Sign in", "ip_address": "1.2.3.4",
				}},
			})
		case strings.HasSuffix(r.URL.Path, "/v2/accounts/me/settings"):
			json.NewEncoder(w).Encode(map[string]any{
				"in_meeting":       map[string]any{"waiting_room": true},
				"schedule_meeting": map[string]any{"require_password_for_all_meetings": true},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestZoom(srv *httptest.Server) (*Zoom, json.RawMessage, []byte) {
	z := NewZoom(srv.Client(), "test-ua")
	z.baseURL = srv.URL
	z.tokenURL = srv.URL + "/oauth/token"
	cfg, _ := json.Marshal(ZoomConfig{AccountID: "acc", ClientID: "cid"})
	sec, _ := json.Marshal(ZoomSecret{ClientSecret: "csec"})
	return z, cfg, sec
}

func TestZoom_Type(t *testing.T) {
	if NewZoom(http.DefaultClient, "ua").Type() != repository.CASBConnectorZoom {
		t.Fatal("wrong type")
	}
}

func TestZoom_TestAndUsers(t *testing.T) {
	srv := zoomServer(t)
	defer srv.Close()
	z, cfg, sec := newTestZoom(srv)
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

func TestZoom_ListActivity(t *testing.T) {
	srv := zoomServer(t)
	defer srv.Close()
	z, cfg, sec := newTestZoom(srv)
	events, err := z.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "sign in" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestZoom_AssessPosture(t *testing.T) {
	srv := zoomServer(t)
	defer srv.Close()
	z, cfg, sec := newTestZoom(srv)
	report, err := z.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 2 || report.RiskScore != 0 {
		t.Fatalf("expected 2 healthy checks, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestZoom_Validation(t *testing.T) {
	z := NewZoom(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(ZoomConfig{})
	sec, _ := json.Marshal(ZoomSecret{ClientSecret: "x"})
	if err := z.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing account_id/client_id")
	}
}

var _ casb.CASBConnectorPlugin = (*Zoom)(nil)

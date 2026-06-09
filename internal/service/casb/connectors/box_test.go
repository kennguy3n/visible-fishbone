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

func boxServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/token"):
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse form: %v", err)
			}
			if r.PostForm.Get("box_subject_id") != "ent1" {
				t.Errorf("subject id = %q", r.PostForm.Get("box_subject_id"))
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "box-tok"})
		case strings.HasSuffix(r.URL.Path, "/2.0/users"):
			if got := r.Header.Get("Authorization"); got != "Bearer box-tok" {
				t.Errorf("auth header = %q", got)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"total_count": 2,
				"entries": []map[string]any{
					{"id": "1", "name": "Admin", "login": "a@x.io", "status": "active", "role": "admin"},
					{"id": "2", "name": "User", "login": "b@x.io", "status": "active", "role": "user"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/2.0/events"):
			json.NewEncoder(w).Encode(map[string]any{
				"entries": []map[string]any{{
					"event_id": "e1", "event_type": "UPLOAD", "created_at": "2024-05-01T10:00:00Z",
					"created_by": map[string]any{"login": "a@x.io"},
					"source":     map[string]any{"name": "doc.pdf"}, "ip_address": "1.2.3.4",
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestBox(srv *httptest.Server) (*Box, json.RawMessage, []byte) {
	b := NewBox(srv.Client(), "test-ua")
	b.baseURL = srv.URL
	b.tokenURL = srv.URL + "/oauth2/token"
	cfg, _ := json.Marshal(BoxConfig{ClientID: "cid", EnterpriseID: "ent1"})
	sec, _ := json.Marshal(BoxSecret{ClientSecret: "csec"})
	return b, cfg, sec
}

func TestBox_Type(t *testing.T) {
	if NewBox(http.DefaultClient, "ua").Type() != repository.CASBConnectorBox {
		t.Fatal("wrong type")
	}
}

func TestBox_TestAndUsers(t *testing.T) {
	srv := boxServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)
	if err := b.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := b.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || !users[0].Admin || users[1].Admin {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestBox_ListActivity(t *testing.T) {
	srv := boxServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)
	events, err := b.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "upload" || events[0].Target != "doc.pdf" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestBox_AssessPosture(t *testing.T) {
	srv := boxServer(t)
	defer srv.Close()
	b, cfg, sec := newTestBox(srv)
	report, err := b.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	// 1 admin of 2 users = 50% → elevated (warn). Warn is non-zero risk.
	if len(report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %+v", report.Checks)
	}
}

func TestBox_Validation(t *testing.T) {
	b := NewBox(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(BoxConfig{ClientID: "", EnterpriseID: ""})
	sec, _ := json.Marshal(BoxSecret{ClientSecret: "x"})
	if err := b.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing client_id/enterprise_id")
	}
}

var _ casb.CASBConnectorPlugin = (*Box)(nil)

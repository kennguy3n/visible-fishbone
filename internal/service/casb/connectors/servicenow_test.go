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

func servicenowServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "svc" || p != "pw" {
			t.Errorf("basic auth = %q/%q ok=%v", u, p, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/sys_user_has_role"):
			json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{{"user": "u1", "role.name": "admin"}},
			})
		case strings.HasSuffix(r.URL.Path, "/sys_user"):
			json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{
					{"sys_id": "1", "user_name": "alice", "name": "Alice", "email": "a@x.io", "active": "true"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/sys_audit"):
			json.NewEncoder(w).Encode(map[string]any{
				"result": []map[string]any{{
					"sys_id": "e1", "user": "alice", "fieldname": "state",
					"tablename": "incident", "sys_created_on": "2024-05-01 10:00:00",
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestServiceNow(srv *httptest.Server) (*ServiceNow, json.RawMessage, []byte) {
	s := NewServiceNow(srv.Client(), "test-ua")
	s.defaultBase = srv.URL
	cfg, _ := json.Marshal(ServiceNowConfig{})
	sec, _ := json.Marshal(ServiceNowSecret{Username: "svc", Password: "pw"})
	return s, cfg, sec
}

func TestServiceNow_Type(t *testing.T) {
	if NewServiceNow(http.DefaultClient, "ua").Type() != repository.CASBConnectorServiceNow {
		t.Fatal("wrong type")
	}
}

func TestServiceNow_TestAndUsers(t *testing.T) {
	srv := servicenowServer(t)
	defer srv.Close()
	s, cfg, sec := newTestServiceNow(srv)
	if err := s.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := s.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Email != "a@x.io" || !users[0].Active {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestServiceNow_ListActivity(t *testing.T) {
	srv := servicenowServer(t)
	defer srv.Close()
	s, cfg, sec := newTestServiceNow(srv)
	events, err := s.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "state" || events[0].Target != "incident" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestServiceNow_AssessPosture(t *testing.T) {
	srv := servicenowServer(t)
	defer srv.Close()
	s, cfg, sec := newTestServiceNow(srv)
	report, err := s.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 1 || report.Checks[0].Name != "admin_role_grants" {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
}

func TestServiceNow_Validation(t *testing.T) {
	s := NewServiceNow(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{})
	sec, _ := json.Marshal(ServiceNowSecret{})
	if err := s.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

func TestServiceNow_RejectsPrivateBaseURL(t *testing.T) {
	s := NewServiceNow(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{BaseURL: "https://127.0.0.1"})
	sec, _ := json.Marshal(ServiceNowSecret{Username: "svc", Password: "pw"})
	if err := s.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected SSRF rejection for loopback base_url")
	}
}

var _ casb.CASBConnectorPlugin = (*ServiceNow)(nil)

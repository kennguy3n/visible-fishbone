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

func workdayServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			if u, _, _ := r.BasicAuth(); u != "cid" {
				t.Errorf("basic user = %q", u)
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "wd-tok"})
		case strings.HasSuffix(r.URL.Path, "/workers"):
			if got := r.Header.Get("Authorization"); got != "Bearer wd-tok" {
				t.Errorf("auth header = %q", got)
			}
			json.NewEncoder(w).Encode(map[string]any{
				"total": 2,
				"data": []map[string]any{
					{"id": "1", "descriptor": "Alice", "isActive": true,
						"primaryWorkContactInformation": map[string]any{"primaryWorkEmail": "a@x.io"}},
					{"id": "2", "descriptor": "Bob", "isActive": false,
						"primaryWorkContactInformation": map[string]any{"primaryWorkEmail": "b@x.io"}},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/activityLogging"):
			json.NewEncoder(w).Encode(map[string]any{
				"data": []map[string]any{{
					"taskDisplayName": "View Worker", "requestTime": "2024-05-01T10:00:00Z",
					"systemAccount": "isu", "ipAddress": "1.2.3.4",
					"target": map[string]any{"descriptor": "Worker: Alice"},
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestWorkday(srv *httptest.Server) (*Workday, json.RawMessage, []byte) {
	wd := NewWorkday(srv.Client(), "test-ua")
	wd.defaultBase = srv.URL
	cfg, _ := json.Marshal(WorkdayConfig{Tenant: "acme"})
	sec, _ := json.Marshal(WorkdaySecret{ClientID: "cid", ClientSecret: "csec", RefreshToken: "rt"})
	return wd, cfg, sec
}

func TestWorkday_Type(t *testing.T) {
	if NewWorkday(http.DefaultClient, "ua").Type() != repository.CASBConnectorWorkday {
		t.Fatal("wrong type")
	}
}

func TestWorkday_TestAndUsers(t *testing.T) {
	srv := workdayServer(t)
	defer srv.Close()
	wd, cfg, sec := newTestWorkday(srv)
	if err := wd.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := wd.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || users[0].Email != "a@x.io" || !users[0].Active || users[1].Active {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestWorkday_ListActivity(t *testing.T) {
	srv := workdayServer(t)
	defer srv.Close()
	wd, cfg, sec := newTestWorkday(srv)
	events, err := wd.ListActivity(context.Background(), cfg, sec, "2024-05-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "View Worker" || events[0].Actor != "isu" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestWorkday_AssessPosture(t *testing.T) {
	srv := workdayServer(t)
	defer srv.Close()
	wd, cfg, sec := newTestWorkday(srv)
	report, err := wd.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	// One inactive worker still provisioned → offboarding_hygiene warns.
	if len(report.Checks) != 1 || report.Checks[0].Status != casb.CheckStatusWarn {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
}

func TestWorkday_Validation(t *testing.T) {
	wd := NewWorkday(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(WorkdayConfig{Tenant: ""})
	sec, _ := json.Marshal(WorkdaySecret{ClientID: "c", ClientSecret: "s", RefreshToken: "r"})
	if err := wd.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing tenant")
	}
}

func TestWorkday_RejectsPrivateBaseURL(t *testing.T) {
	wd := NewWorkday(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(WorkdayConfig{BaseURL: "https://10.1.2.3", Tenant: "acme"})
	sec, _ := json.Marshal(WorkdaySecret{ClientID: "c", ClientSecret: "s", RefreshToken: "r"})
	if err := wd.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected SSRF rejection for private base_url")
	}
}

var _ casb.CASBConnectorPlugin = (*Workday)(nil)

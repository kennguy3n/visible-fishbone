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

func teamsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "teams-tok"})
		case strings.HasSuffix(r.URL.Path, "/teams"):
			json.NewEncoder(w).Encode(map[string]any{"value": []json.RawMessage{json.RawMessage(`{}`)}})
		case strings.HasSuffix(r.URL.Path, "/users"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "1", "displayName": "Ad Min", "mail": "a@x.io", "accountEnabled": true},
					{"id": "2", "displayName": "Reg User", "userPrincipalName": "b@x.io", "accountEnabled": false},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/auditLogs/directoryAudits"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{
					"id": "e1", "activityDisplayName": "Add user", "activityDateTime": "2024-05-01T10:00:00Z",
					"initiatedBy": map[string]any{"user": map[string]any{"userPrincipalName": "a@x.io"}},
				}},
			})
		case strings.HasSuffix(r.URL.Path, "/teamwork/teamsAppSettings"):
			json.NewEncoder(w).Encode(map[string]any{"allowGuestUser": false})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestTeams(srv *httptest.Server) (*Teams, json.RawMessage, []byte) {
	tm := NewTeams(srv.Client(), "test-ua")
	tm.graphBase = srv.URL + "/v1.0"
	tm.tokenBaseURL = srv.URL
	cfg, _ := json.Marshal(TeamsConfig{AzureTenantID: "tid", ClientID: "cid"})
	sec, _ := json.Marshal(TeamsSecret{ClientSecret: "csec"})
	return tm, cfg, sec
}

func TestTeams_Type(t *testing.T) {
	if NewTeams(http.DefaultClient, "ua").Type() != repository.CASBConnectorTeams {
		t.Fatal("wrong type")
	}
}

func TestTeams_TestAndUsers(t *testing.T) {
	srv := teamsServer(t)
	defer srv.Close()
	tm, cfg, sec := newTestTeams(srv)
	if err := tm.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := tm.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || users[0].Email != "a@x.io" || users[1].Email != "b@x.io" {
		t.Fatalf("unexpected users: %+v", users)
	}
	if !users[0].Active || users[1].Active {
		t.Errorf("active flags wrong: %+v", users)
	}
}

func TestTeams_ListActivity(t *testing.T) {
	srv := teamsServer(t)
	defer srv.Close()
	tm, cfg, sec := newTestTeams(srv)
	events, err := tm.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "Add user" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestTeams_AssessPosture(t *testing.T) {
	srv := teamsServer(t)
	defer srv.Close()
	tm, cfg, sec := newTestTeams(srv)
	report, err := tm.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 1 || report.RiskScore != 0 {
		t.Fatalf("expected 1 healthy check, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestTeams_Validation(t *testing.T) {
	tm := NewTeams(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(TeamsConfig{})
	sec, _ := json.Marshal(TeamsSecret{ClientSecret: "x"})
	if err := tm.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing tenant_id/client_id")
	}
}

var _ casb.CASBConnectorPlugin = (*Teams)(nil)

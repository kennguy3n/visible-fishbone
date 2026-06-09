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

func azureServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			json.NewEncoder(w).Encode(map[string]any{"access_token": "az-tok"})
		case strings.HasSuffix(r.URL.Path, "/organization"):
			json.NewEncoder(w).Encode(map[string]any{"value": []json.RawMessage{json.RawMessage(`{}`)}})
		case strings.HasSuffix(r.URL.Path, "/users"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"id": "1", "displayName": "Ad Min", "mail": "a@x.io", "accountEnabled": true},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/auditLogs/directoryAudits"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{
					"id": "e1", "activityDisplayName": "Add role", "activityDateTime": "2024-05-01T10:00:00Z",
					"result": "success", "initiatedBy": map[string]any{"user": map[string]any{"userPrincipalName": "a@x.io"}},
				}},
			})
		case strings.HasSuffix(r.URL.Path, "/directoryRoles"):
			if !strings.Contains(r.URL.Query().Get("$filter"), "Global Administrator") {
				t.Errorf("directoryRoles filter = %q", r.URL.Query().Get("$filter"))
			}
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{{"members": []json.RawMessage{json.RawMessage(`{"id":"1"}`)}}},
			})
		case strings.HasSuffix(r.URL.Path, "/roleAssignments"):
			json.NewEncoder(w).Encode(map[string]any{
				"value": []map[string]any{
					{"properties": map[string]any{"roleDefinitionId": "/x/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"}},
				},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestAzure(srv *httptest.Server) (*AzurePortal, json.RawMessage, []byte) {
	a := NewAzurePortal(srv.Client(), "test-ua")
	a.graphBase = srv.URL + "/v1.0"
	a.armBase = srv.URL
	a.tokenBaseURL = srv.URL
	cfg, _ := json.Marshal(AzurePortalConfig{AzureTenantID: "tid", ClientID: "cid", SubscriptionID: "sub1"})
	sec, _ := json.Marshal(AzurePortalSecret{ClientSecret: "csec"})
	return a, cfg, sec
}

func TestAzurePortal_Type(t *testing.T) {
	if NewAzurePortal(http.DefaultClient, "ua").Type() != repository.CASBConnectorAzurePortal {
		t.Fatal("wrong type")
	}
}

func TestAzurePortal_TestAndUsers(t *testing.T) {
	srv := azureServer(t)
	defer srv.Close()
	a, cfg, sec := newTestAzure(srv)
	if err := a.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := a.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 || users[0].Email != "a@x.io" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestAzurePortal_ListActivity(t *testing.T) {
	srv := azureServer(t)
	defer srv.Close()
	a, cfg, sec := newTestAzure(srv)
	events, err := a.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "Add role" || events[0].Details != "success" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestAzurePortal_AssessPosture(t *testing.T) {
	srv := azureServer(t)
	defer srv.Close()
	a, cfg, sec := newTestAzure(srv)
	report, err := a.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	// global_admin_count (1 GA → pass) + subscription_owner_assignments (1 owner → pass).
	if len(report.Checks) != 2 {
		t.Fatalf("expected 2 checks, got %+v", report.Checks)
	}
	byName := map[string]casb.PostureCheck{}
	for _, c := range report.Checks {
		byName[c.Name] = c
	}
	if byName["global_admin_count"].Status != casb.CheckStatusPass {
		t.Errorf("global_admin_count = %+v", byName["global_admin_count"])
	}
	if byName["subscription_owner_assignments"].Status != casb.CheckStatusPass {
		t.Errorf("subscription_owner_assignments = %+v", byName["subscription_owner_assignments"])
	}
}

func TestAzurePortal_Validation(t *testing.T) {
	a := NewAzurePortal(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(AzurePortalConfig{})
	sec, _ := json.Marshal(AzurePortalSecret{ClientSecret: "x"})
	if err := a.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing tenant_id/client_id")
	}
}

var _ casb.CASBConnectorPlugin = (*AzurePortal)(nil)

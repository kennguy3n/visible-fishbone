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

func hubspotServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer hs-test" {
			t.Errorf("auth header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/settings/v3/users"):
			json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{
					{"id": "1", "email": "a@x.io", "firstName": "Ad", "lastName": "Min", "superAdmin": true},
					{"id": "2", "email": "b@x.io", "firstName": "Reg", "lastName": "User", "superAdmin": false},
					{"id": "3", "email": "c@x.io", "firstName": "Reg2", "lastName": "User2", "superAdmin": false},
					{"id": "4", "email": "d@x.io", "firstName": "Reg3", "lastName": "User3", "superAdmin": false},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/account-info/v3/activity/login"):
			json.NewEncoder(w).Encode(map[string]any{
				"results": []map[string]any{{
					"occurredAt": "2024-05-01T10:00:00Z", "actorId": "1", "activityType": "LOGIN", "ipAddress": "1.2.3.4",
				}},
			})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestHubSpot(srv *httptest.Server) (*HubSpot, json.RawMessage, []byte) {
	h := NewHubSpot(srv.Client(), "test-ua")
	h.baseURL = srv.URL
	cfg, _ := json.Marshal(HubSpotConfig{PortalID: "123"})
	sec, _ := json.Marshal(HubSpotSecret{Token: "hs-test"})
	return h, cfg, sec
}

func TestHubSpot_Type(t *testing.T) {
	if NewHubSpot(http.DefaultClient, "ua").Type() != repository.CASBConnectorHubSpot {
		t.Fatal("wrong type")
	}
}

func TestHubSpot_TestAndUsers(t *testing.T) {
	srv := hubspotServer(t)
	defer srv.Close()
	h, cfg, sec := newTestHubSpot(srv)
	if err := h.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := h.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 4 {
		t.Fatalf("want 4, got %d", len(users))
	}
	if users[0].DisplayName != "Ad Min" || !users[0].Admin {
		t.Errorf("unexpected first user: %+v", users[0])
	}
}

func TestHubSpot_ListActivity(t *testing.T) {
	srv := hubspotServer(t)
	defer srv.Close()
	h, cfg, sec := newTestHubSpot(srv)
	events, err := h.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "LOGIN" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestHubSpot_AssessPosture(t *testing.T) {
	srv := hubspotServer(t)
	defer srv.Close()
	h, cfg, sec := newTestHubSpot(srv)
	report, err := h.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	// 1 admin of 4 users = 25% → least-privilege pass (score 0).
	if len(report.Checks) != 1 || report.RiskScore != 0 {
		t.Fatalf("expected 1 healthy check, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestHubSpot_Validation(t *testing.T) {
	h := NewHubSpot(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(HubSpotConfig{})
	sec, _ := json.Marshal(HubSpotSecret{Token: ""})
	if err := h.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing token")
	}
}

var _ casb.CASBConnectorPlugin = (*HubSpot)(nil)

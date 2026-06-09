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

func oktaServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "SSWS tok" {
			t.Errorf("auth header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/api/v1/users"):
			json.NewEncoder(w).Encode([]map[string]any{
				{"id": "1", "status": "ACTIVE", "profile": map[string]any{
					"firstName": "Ad", "lastName": "Min", "email": "a@x.io", "login": "a@x.io"}},
				{"id": "2", "status": "SUSPENDED", "profile": map[string]any{
					"firstName": "Re", "lastName": "Gular", "email": "b@x.io", "login": "b@x.io"}},
			})
		case strings.HasSuffix(r.URL.Path, "/api/v1/logs"):
			json.NewEncoder(w).Encode([]map[string]any{{
				"uuid": "e1", "eventType": "user.session.start", "published": "2024-05-01T10:00:00Z",
				"actor":  map[string]any{"displayName": "Admin", "alternateId": "a@x.io"},
				"client": map[string]any{"ipAddress": "1.2.3.4"},
				"target": []map[string]any{{"displayName": "App"}},
			}})
		case strings.HasSuffix(r.URL.Path, "/api/v1/policies"):
			json.NewEncoder(w).Encode([]map[string]any{{"status": "ACTIVE", "system": false}})
		default:
			http.Error(w, "not found: "+r.URL.Path, http.StatusNotFound)
		}
	}))
}

func newTestOkta(srv *httptest.Server) (*Okta, json.RawMessage, []byte) {
	o := NewOkta(srv.Client(), "test-ua")
	o.defaultBase = srv.URL
	cfg, _ := json.Marshal(OktaConfig{})
	sec, _ := json.Marshal(OktaSecret{APIToken: "tok"})
	return o, cfg, sec
}

func TestOkta_Type(t *testing.T) {
	if NewOkta(http.DefaultClient, "ua").Type() != repository.CASBConnectorOkta {
		t.Fatal("wrong type")
	}
}

func TestOkta_TestAndUsers(t *testing.T) {
	srv := oktaServer(t)
	defer srv.Close()
	o, cfg, sec := newTestOkta(srv)
	if err := o.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := o.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || !users[0].Active || users[1].Active {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestOkta_ListActivity(t *testing.T) {
	srv := oktaServer(t)
	defer srv.Close()
	o, cfg, sec := newTestOkta(srv)
	events, err := o.ListActivity(context.Background(), cfg, sec, "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "user.session.start" || events[0].Actor != "a@x.io" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestOkta_AssessPosture(t *testing.T) {
	srv := oktaServer(t)
	defer srv.Close()
	o, cfg, sec := newTestOkta(srv)
	report, err := o.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) != 1 || report.RiskScore != 0 {
		t.Fatalf("expected 1 healthy check, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestOkta_Validation(t *testing.T) {
	o := NewOkta(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(OktaConfig{})
	sec, _ := json.Marshal(OktaSecret{})
	if err := o.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing api_token")
	}
}

func TestOkta_RejectsPrivateBaseURL(t *testing.T) {
	o := NewOkta(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(OktaConfig{BaseURL: "https://169.254.169.254"})
	sec, _ := json.Marshal(OktaSecret{APIToken: "t"})
	if err := o.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected SSRF rejection for link-local base_url")
	}
}

var _ casb.CASBConnectorPlugin = (*Okta)(nil)

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

func TestSalesforce_Type(t *testing.T) {
	s := NewSalesforce(http.DefaultClient, "ua")
	if s.Type() != repository.CASBConnectorSalesforce {
		t.Fatalf("Type() = %q, want %q", s.Type(), repository.CASBConnectorSalesforce)
	}
}

func salesforceServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/oauth2/token"):
			json.NewEncoder(w).Encode(map[string]any{
				"access_token": "sf-tok",
				"instance_url": "http://" + r.Host,
			})
		case strings.Contains(r.URL.Path, "/query") && strings.Contains(r.URL.RawQuery, "User"):
			json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{
					{"Id": "u1", "Name": "Alice", "Email": "alice@co.com", "IsActive": true, "Profile": map[string]any{"Name": "Admin"}},
				},
			})
		case strings.Contains(r.URL.Path, "/query") && strings.Contains(r.URL.RawQuery, "SetupAuditTrail"):
			json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{{
					"Id":          "at1",
					"CreatedDate": "2025-06-01T10:00:00.000+0000",
					"CreatedById": "uid1",
					"Display":     "Changed password policy",
					"Section":     "Security",
					"Action":      "changedPasswordPolicy",
				}},
			})
		case strings.Contains(r.URL.Path, "/query") && strings.Contains(r.URL.RawQuery, "SecurityHealthCheckRisks"):
			json.NewEncoder(w).Encode(map[string]any{
				"records": []map[string]any{},
			})
		default:
			json.NewEncoder(w).Encode(map[string]any{})
		}
	}))
}

func salesforceTestCfg(t *testing.T, srvURL string) (json.RawMessage, []byte) {
	t.Helper()
	cfg, _ := json.Marshal(SalesforceConfig{
		InstanceURL: srvURL,
		ClientID:    "test-client",
	})
	sec, _ := json.Marshal(SalesforceSecret{
		ClientSecret:  "test-secret",
		Username:      "admin@co.com",
		Password:      "pass",
		SecurityToken: "tok",
	})
	return cfg, sec
}

func newTestSalesforce(t *testing.T, srv *httptest.Server) *Salesforce {
	t.Helper()
	return NewSalesforce(srv.Client(), "test-ua")
}

func TestSalesforce_Test_OK(t *testing.T) {
	srv := salesforceServer(t)
	defer srv.Close()
	sf := newTestSalesforce(t, srv)
	cfg, sec := salesforceTestCfg(t, srv.URL)
	if err := sf.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
}

func TestSalesforce_ListUsers(t *testing.T) {
	srv := salesforceServer(t)
	defer srv.Close()
	sf := newTestSalesforce(t, srv)
	cfg, sec := salesforceTestCfg(t, srv.URL)
	users, err := sf.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("want 1 user, got %d", len(users))
	}
	if users[0].Email != "alice@co.com" {
		t.Errorf("email = %q", users[0].Email)
	}
}

func TestSalesforce_ListActivity(t *testing.T) {
	srv := salesforceServer(t)
	defer srv.Close()
	sf := newTestSalesforce(t, srv)
	cfg, sec := salesforceTestCfg(t, srv.URL)
	events, err := sf.ListActivity(context.Background(), cfg, sec, "2025-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("want 1 event, got %d", len(events))
	}
}

func TestSalesforce_AssessPosture(t *testing.T) {
	srv := salesforceServer(t)
	defer srv.Close()
	sf := newTestSalesforce(t, srv)
	cfg, sec := salesforceTestCfg(t, srv.URL)
	report, err := sf.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	if len(report.Checks) == 0 {
		t.Fatal("expected posture checks")
	}
	if report.Score < 0 || report.Score > 100 {
		t.Errorf("score out of range: %d", report.Score)
	}
}

var _ casb.CASBConnectorPlugin = (*Salesforce)(nil)

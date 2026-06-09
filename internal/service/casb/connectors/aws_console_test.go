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

func awsServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Errorf("request not SigV4-signed: %s", r.URL.Path)
		}
		if strings.Contains(r.Header.Get("X-Amz-Target"), "CloudTrail") {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			json.NewEncoder(w).Encode(map[string]any{
				"Events": []map[string]any{{
					"EventId": "e1", "EventName": "ConsoleLogin", "Username": "alice",
					"EventTime": 1714557600, "Resources": []map[string]any{{"ResourceName": "res1"}},
				}},
			})
			return
		}
		w.Header().Set("Content-Type", "text/xml")
		switch r.URL.Query().Get("Action") {
		case "GetAccountSummary":
			w.Write([]byte(`<GetAccountSummaryResponse><GetAccountSummaryResult><SummaryMap>` +
				`<entry><key>AccountMFAEnabled</key><value>1</value></entry>` +
				`<entry><key>AccountAccessKeysPresent</key><value>0</value></entry>` +
				`</SummaryMap></GetAccountSummaryResult></GetAccountSummaryResponse>`))
		case "ListUsers":
			w.Write([]byte(`<ListUsersResponse><ListUsersResult><Users>` +
				`<member><UserName>alice</UserName><UserId>AID1</UserId><Arn>arn:aws:iam::1:user/alice</Arn></member>` +
				`<member><UserName>bob</UserName><UserId>AID2</UserId><Arn>arn:aws:iam::1:user/bob</Arn></member>` +
				`</Users></ListUsersResult></ListUsersResponse>`))
		case "GetAccountPasswordPolicy":
			w.Write([]byte(`<GetAccountPasswordPolicyResponse><GetAccountPasswordPolicyResult><PasswordPolicy>` +
				`<MinimumPasswordLength>14</MinimumPasswordLength><RequireSymbols>true</RequireSymbols>` +
				`<RequireNumbers>true</RequireNumbers><RequireUppercaseCharacters>true</RequireUppercaseCharacters>` +
				`<RequireLowercaseCharacters>true</RequireLowercaseCharacters>` +
				`</PasswordPolicy></GetAccountPasswordPolicyResult></GetAccountPasswordPolicyResponse>`))
		default:
			http.Error(w, "unknown action", http.StatusBadRequest)
		}
	}))
}

func newTestAWS(srv *httptest.Server) (*AWSConsole, json.RawMessage, []byte) {
	a := NewAWSConsole(srv.Client(), "test-ua")
	a.iamBase = srv.URL
	a.trailBase = srv.URL + "/%s"
	cfg, _ := json.Marshal(AWSConsoleConfig{Region: "us-east-1"})
	sec, _ := json.Marshal(AWSConsoleSecret{AccessKeyID: "AKIA", SecretAccessKey: "sk"})
	return a, cfg, sec
}

func TestAWSConsole_Type(t *testing.T) {
	if NewAWSConsole(http.DefaultClient, "ua").Type() != repository.CASBConnectorAWSConsole {
		t.Fatal("wrong type")
	}
}

func TestAWSConsole_TestAndUsers(t *testing.T) {
	srv := awsServer(t)
	defer srv.Close()
	a, cfg, sec := newTestAWS(srv)
	if err := a.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	users, err := a.ListUsers(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 2 || users[0].DisplayName != "alice" || users[1].DisplayName != "bob" {
		t.Fatalf("unexpected users: %+v", users)
	}
}

func TestAWSConsole_ListActivity(t *testing.T) {
	srv := awsServer(t)
	defer srv.Close()
	a, cfg, sec := newTestAWS(srv)
	events, err := a.ListActivity(context.Background(), cfg, sec, "2024-05-01T00:00:00Z")
	if err != nil {
		t.Fatalf("ListActivity: %v", err)
	}
	if len(events) != 1 || events[0].Action != "ConsoleLogin" || events[0].Target != "res1" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestAWSConsole_AssessPosture(t *testing.T) {
	srv := awsServer(t)
	defer srv.Close()
	a, cfg, sec := newTestAWS(srv)
	report, err := a.AssessPosture(context.Background(), cfg, sec)
	if err != nil {
		t.Fatalf("AssessPosture: %v", err)
	}
	// root_mfa_enabled + no_root_access_keys + strong_password_policy, all healthy.
	if len(report.Checks) != 3 || report.RiskScore != 0 {
		t.Fatalf("expected 3 healthy checks, got score=%d checks=%+v", report.RiskScore, report.Checks)
	}
}

func TestAWSConsole_Validation(t *testing.T) {
	a := NewAWSConsole(http.DefaultClient, "ua")
	cfg, _ := json.Marshal(AWSConsoleConfig{})
	sec, _ := json.Marshal(AWSConsoleSecret{AccessKeyID: "", SecretAccessKey: ""})
	if err := a.Test(context.Background(), cfg, sec); err == nil {
		t.Fatal("expected error for missing credentials")
	}
}

var _ casb.CASBConnectorPlugin = (*AWSConsole)(nil)

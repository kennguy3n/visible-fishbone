package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

func TestJira_Send_CreatesIssueAndCapturesKey(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Body:       io.NopCloser(strings.NewReader(`{"id":"10001","key":"OPS-42","self":"…"}`)),
		}, nil
	}}
	j := NewJira(srv, "ua")
	cfg, _ := json.Marshal(JiraConfig{
		BaseURL:    "https://acme.atlassian.net/",
		ProjectKey: "OPS",
		IssueType:  "Incident",
		Labels:     []string{"sng"},
	})
	sec, _ := json.Marshal(JiraSecret{Email: "alice@acme.io", APIToken: "abc"})
	res, err := j.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{"headline":"siem outage","description":"d","severity":"critical"}`),
		Config:    cfg,
		Secret:    sec,
		Now:       time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExternalReference != "OPS-42" {
		t.Fatalf("want issue key OPS-42, got %q", res.ExternalReference)
	}
	if res.ResponseStatus != 201 {
		t.Fatalf("want 201, got %d", res.ResponseStatus)
	}

	// Verify body shape + auth.
	var got map[string]any
	if err := json.Unmarshal(srv.bodies[0], &got); err != nil {
		t.Fatalf("bad body: %v", err)
	}
	fields, ok := got["fields"].(map[string]any)
	if !ok {
		t.Fatalf("missing fields: %v", got)
	}
	if fields["summary"] != "siem outage" {
		t.Fatalf("summary not propagated: %v", fields)
	}
	if proj, _ := fields["project"].(map[string]any); proj["key"] != "OPS" {
		t.Fatalf("project key missing: %v", fields)
	}
	if it, _ := fields["issuetype"].(map[string]any); it["name"] != "Incident" {
		t.Fatalf("issue type missing: %v", fields)
	}
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice@acme.io:abc"))
	if srv.requests[0].Header.Get("Authorization") != expectedAuth {
		t.Fatalf("wrong auth header: %q", srv.requests[0].Header.Get("Authorization"))
	}
	// Verify URL has no trailing-slash duplication.
	if !strings.HasSuffix(srv.requests[0].URL.String(), "/rest/api/3/issue") {
		t.Fatalf("wrong path: %s", srv.requests[0].URL)
	}
}

func TestJira_Send_TransitionsWhenExternalReferencePresent(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 204, Body: io.NopCloser(bytes.NewReader(nil))}, nil
	}}
	j := NewJira(srv, "ua")
	cfg, _ := json.Marshal(JiraConfig{
		BaseURL:    "https://acme.atlassian.net",
		ProjectKey: "OPS",
		TransitionMap: map[string]string{
			"alert.resolved": "31",
		},
	})
	sec, _ := json.Marshal(JiraSecret{BearerToken: "tok"})
	res, err := j.Send(context.Background(), integration.Sendable{
		EventType:         "alert.resolved",
		ExternalReference: "OPS-42",
		Payload:           []byte(`{}`),
		Config:            cfg,
		Secret:            sec,
		Now:               time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExternalReference != "OPS-42" {
		t.Fatalf("transition should preserve external reference: %q", res.ExternalReference)
	}
	if !strings.HasSuffix(srv.requests[0].URL.Path, "/rest/api/3/issue/OPS-42/transitions") {
		t.Fatalf("wrong transition path: %s", srv.requests[0].URL.Path)
	}
	var got map[string]any
	_ = json.Unmarshal(srv.bodies[0], &got)
	if tr, _ := got["transition"].(map[string]any); tr["id"] != "31" {
		t.Fatalf("missing transition id: %v", got)
	}
	if srv.requests[0].Header.Get("Authorization") != "Bearer tok" {
		t.Fatalf("bearer auth missing")
	}
}

func TestJira_Send_NoTransitionMappedIsTerminal(t *testing.T) {
	srv := &stubHTTP{}
	j := NewJira(srv, "ua")
	cfg, _ := json.Marshal(JiraConfig{
		BaseURL:    "https://acme.atlassian.net",
		ProjectKey: "OPS",
	})
	sec, _ := json.Marshal(JiraSecret{BearerToken: "tok"})
	_, err := j.Send(context.Background(), integration.Sendable{
		EventType:         "alert.acknowledged",
		ExternalReference: "OPS-1",
		Payload:           []byte(`{}`),
		Config:            cfg,
		Secret:            sec,
		Now:               time.Now(),
	})
	if err == nil {
		t.Fatalf("expected terminal error for missing transition")
	}
	if errors.Is(err, integration.ErrTransient) {
		t.Fatalf("missing transition should be terminal, not transient: %v", err)
	}
	if len(srv.requests) != 0 {
		t.Fatalf("no HTTP call should be made for missing transition")
	}
}

func TestJira_Send_5xxIsTransient(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("busy"))}, nil
	}}
	j := NewJira(srv, "ua")
	cfg, _ := json.Marshal(JiraConfig{BaseURL: "https://acme.atlassian.net", ProjectKey: "OPS"})
	sec, _ := json.Marshal(JiraSecret{BearerToken: "t"})
	_, err := j.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{"headline":"x"}`),
		Config:    cfg,
		Secret:    sec,
		Now:       time.Now(),
	})
	if !errors.Is(err, integration.ErrTransient) {
		t.Fatalf("503 should be transient: %v", err)
	}
}

func TestJira_Parse_RejectsInvalidConfig(t *testing.T) {
	j := NewJira(&stubHTTP{}, "ua")
	cases := map[string]struct {
		cfg, sec string
	}{
		"missing base":       {`{}`, `{"bearer_token":"t"}`},
		"bad base":           {`{"base_url":"ftp://x","project_key":"P"}`, `{"bearer_token":"t"}`},
		"missing project":    {`{"base_url":"https://x"}`, `{"bearer_token":"t"}`},
		"no auth":            {`{"base_url":"https://x","project_key":"P"}`, `{}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := j.Test(context.Background(), json.RawMessage(c.cfg), json.RawMessage(c.sec))
			if err == nil || errors.Is(err, integration.ErrTransient) {
				t.Fatalf("expected non-transient parse error, got %v", err)
			}
		})
	}
}

func TestJira_Test_HitsMyself(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"accountId":"x"}`))}, nil
	}}
	j := NewJira(srv, "ua")
	cfg, _ := json.Marshal(JiraConfig{BaseURL: "https://acme.atlassian.net", ProjectKey: "OPS"})
	sec, _ := json.Marshal(JiraSecret{BearerToken: "t"})
	if err := j.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !strings.HasSuffix(srv.requests[0].URL.Path, "/rest/api/3/myself") {
		t.Fatalf("wrong probe path: %s", srv.requests[0].URL.Path)
	}
}

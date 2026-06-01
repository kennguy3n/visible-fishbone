package connectors

import (
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

func TestServiceNow_Send_CreatesIncidentAndCapturesSysID(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: 201,
			Body: io.NopCloser(strings.NewReader(
				`{"result":{"sys_id":"abc123","number":"INC0001"}}`)),
		}, nil
	}}
	s := NewServiceNow(srv, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{
		InstanceURL:     "https://acme.service-now.com/",
		Table:           "incident",
		AssignmentGroup: "Security Ops",
		ImpactByEvent:   map[string]string{"alert.created": "1"},
		UrgencyByEvent:  map[string]string{"alert.created": "2"},
		CategoryByEvent: map[string]string{"alert.created": "network"},
	})
	sec, _ := json.Marshal(ServiceNowSecret{Username: "svc", Password: "p"})
	res, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{"headline":"siem outage","description":"d","severity":"high"}`),
		Config:    cfg,
		Secret:    sec,
		Now:       time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExternalReference != "abc123" {
		t.Fatalf("want sys_id abc123, got %q", res.ExternalReference)
	}

	var body map[string]any
	if err := json.Unmarshal(srv.bodies[0], &body); err != nil {
		t.Fatalf("bad body: %v", err)
	}
	if body["short_description"] != "siem outage" {
		t.Fatalf("short_description missing: %v", body)
	}
	if body["impact"] != "1" {
		t.Fatalf("impact mapping missing: %v", body)
	}
	if body["urgency"] != "2" {
		t.Fatalf("urgency mapping missing: %v", body)
	}
	if body["assignment_group"] != "Security Ops" {
		t.Fatalf("assignment_group missing: %v", body)
	}
	if body["category"] != "network" {
		t.Fatalf("category mapping missing: %v", body)
	}
	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("svc:p"))
	if srv.requests[0].Header.Get("Authorization") != expectedAuth {
		t.Fatalf("wrong auth header: %q", srv.requests[0].Header.Get("Authorization"))
	}
	if !strings.HasSuffix(srv.requests[0].URL.Path, "/api/now/table/incident") {
		t.Fatalf("wrong path: %s", srv.requests[0].URL.Path)
	}
}

func TestServiceNow_Send_UpdatesExistingIncident(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"result":{}}`))}, nil
	}}
	s := NewServiceNow(srv, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{
		InstanceURL: "https://acme.service-now.com",
		StateTransitions: map[string]string{
			"alert.resolved": "6",
		},
	})
	sec, _ := json.Marshal(ServiceNowSecret{Username: "u", Password: "p"})
	res, err := s.Send(context.Background(), integration.Sendable{
		EventType:         "alert.resolved",
		ExternalReference: "abc123",
		Payload:           []byte(`{"description":"closed via SNG"}`),
		Config:            cfg,
		Secret:            sec,
		Now:               time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExternalReference != "abc123" {
		t.Fatalf("update should preserve sys_id, got %q", res.ExternalReference)
	}
	if srv.requests[0].Method != http.MethodPatch {
		t.Fatalf("update should PATCH, got %s", srv.requests[0].Method)
	}
	if !strings.HasSuffix(srv.requests[0].URL.Path, "/api/now/table/incident/abc123") {
		t.Fatalf("wrong path: %s", srv.requests[0].URL.Path)
	}
	var body map[string]any
	_ = json.Unmarshal(srv.bodies[0], &body)
	if body["state"] != "6" {
		t.Fatalf("state mapping missing: %v", body)
	}
	if body["work_notes"] != "closed via SNG" {
		t.Fatalf("description should be sent as work_notes: %v", body)
	}
}

func TestServiceNow_Send_NoTransitionIsTerminal(t *testing.T) {
	srv := &stubHTTP{}
	s := NewServiceNow(srv, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{InstanceURL: "https://acme.service-now.com"})
	sec, _ := json.Marshal(ServiceNowSecret{Username: "u", Password: "p"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType:         "alert.acknowledged",
		ExternalReference: "abc",
		Payload:           []byte(`{}`),
		Config:            cfg,
		Secret:            sec,
		Now:               time.Now(),
	})
	if err == nil {
		t.Fatalf("expected terminal error")
	}
	if errors.Is(err, integration.ErrTransient) {
		t.Fatalf("expected terminal: %v", err)
	}
	if len(srv.requests) != 0 {
		t.Fatalf("should not call upstream when no transition is mapped")
	}
}

func TestServiceNow_Send_5xxIsTransient(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 502, Body: io.NopCloser(strings.NewReader("bad gw"))}, nil
	}}
	s := NewServiceNow(srv, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{InstanceURL: "https://acme.service-now.com"})
	sec, _ := json.Marshal(ServiceNowSecret{BearerToken: "t"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{"headline":"x"}`),
		Config:    cfg,
		Secret:    sec,
		Now:       time.Now(),
	})
	if !errors.Is(err, integration.ErrTransient) {
		t.Fatalf("502 should be transient: %v", err)
	}
}

func TestServiceNow_Test_HitsTableWithLimit1(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"result":[]}`))}, nil
	}}
	s := NewServiceNow(srv, "ua")
	cfg, _ := json.Marshal(ServiceNowConfig{InstanceURL: "https://acme.service-now.com"})
	sec, _ := json.Marshal(ServiceNowSecret{BearerToken: "t"})
	if err := s.Test(context.Background(), cfg, sec); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if !strings.Contains(srv.requests[0].URL.String(), "sysparm_limit=1") {
		t.Fatalf("Test probe should use sysparm_limit=1, got %s", srv.requests[0].URL)
	}
}

func TestServiceNow_Parse_RejectsInvalidConfig(t *testing.T) {
	s := NewServiceNow(&stubHTTP{}, "ua")
	cases := map[string]struct {
		cfg, sec string
	}{
		"empty":         {`{}`, `{"username":"u","password":"p"}`},
		"bad scheme":    {`{"instance_url":"ftp://x"}`, `{"username":"u","password":"p"}`},
		"missing auth":  {`{"instance_url":"https://x"}`, `{}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := s.Test(context.Background(), json.RawMessage(c.cfg), json.RawMessage(c.sec))
			if err == nil || errors.Is(err, integration.ErrTransient) {
				t.Fatalf("expected non-transient parse error, got %v", err)
			}
		})
	}
}

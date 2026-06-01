package connectors

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// stubHTTP captures every request and lets the test prescribe
// the response. Sufficient to drive the SIEM / Jira / ServiceNow
// HTTP plugins without spinning up a real httptest.Server.
type stubHTTP struct {
	requests []*http.Request
	bodies   [][]byte
	respond  func(req *http.Request, body []byte) (*http.Response, error)
}

func (h *stubHTTP) Do(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	h.requests = append(h.requests, req)
	h.bodies = append(h.bodies, body)
	if h.respond != nil {
		return h.respond(req, body)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
	}, nil
}

func TestSIEM_Send_GenericVendorPostsPayloadAsIs(t *testing.T) {
	srv := &stubHTTP{}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{Endpoint: "https://siem.example.com/event"})
	payload := json.RawMessage(`{"k":"v"}`)
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   payload,
		Config:    cfg,
		Now:       time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(srv.bodies) != 1 || string(srv.bodies[0]) != `{"k":"v"}` {
		t.Fatalf("generic envelope should pass payload through, got %s", srv.bodies)
	}
}

func TestSIEM_Send_SplunkHECEnvelope(t *testing.T) {
	srv := &stubHTTP{}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{
		Endpoint:          "https://splunk.example.com/services/collector",
		Vendor:            "splunk_hec",
		IndexOrSourcetype: "sng:alert",
	})
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   json.RawMessage(`{"headline":"x"}`),
		Config:    cfg,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(srv.bodies[0], &got); err != nil {
		t.Fatalf("bad envelope: %v", err)
	}
	if got["sourcetype"] != "sng:alert" {
		t.Fatalf("missing splunk sourcetype: %v", got)
	}
	if got["time"] != float64(now.Unix()) {
		t.Fatalf("missing splunk time: %v", got)
	}
	if event, ok := got["event"].(map[string]any); !ok || event["headline"] != "x" {
		t.Fatalf("payload should be embedded under .event: %v", got)
	}
}

func TestSIEM_Send_HMACSignaturePresent(t *testing.T) {
	srv := &stubHTTP{}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{Endpoint: "https://siem/"})
	sec, _ := json.Marshal(SIEMSecret{HMACKey: "topsecret"})
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	body := json.RawMessage(`{"x":1}`)
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   body,
		Config:    cfg,
		Secret:    sec,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	req := srv.requests[0]
	if req.Header.Get("X-Sng-Timestamp") == "" {
		t.Fatalf("missing X-Sng-Timestamp")
	}
	sig := req.Header.Get("X-Sng-Signature")
	if !strings.HasPrefix(sig, "v1=") {
		t.Fatalf("signature should be v1=... got %q", sig)
	}
	ts := req.Header.Get("X-Sng-Timestamp")
	mac := hmac.New(sha256.New, []byte("topsecret"))
	mac.Write([]byte(ts + "."))
	mac.Write(srv.bodies[0])
	want := "v1=" + hex.EncodeToString(mac.Sum(nil))
	if sig != want {
		t.Fatalf("HMAC mismatch: got %q want %q", sig, want)
	}
}

func TestSIEM_Send_5xxIsTransient(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("busy"))}, nil
	}}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{Endpoint: "https://siem/"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{}`),
		Config:    cfg,
		Now:       time.Now(),
	})
	if !errors.Is(err, integration.ErrTransient) {
		t.Fatalf("503 should be transient, got %v", err)
	}
}

func TestSIEM_Send_4xxIsTerminal(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Body: io.NopCloser(strings.NewReader("bad"))}, nil
	}}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{Endpoint: "https://siem/"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{}`),
		Config:    cfg,
		Now:       time.Now(),
	})
	if err == nil {
		t.Fatalf("400 should fail")
	}
	if errors.Is(err, integration.ErrTransient) {
		t.Fatalf("400 should not be transient: %v", err)
	}
}

func TestSIEM_Send_429IsTransient(t *testing.T) {
	srv := &stubHTTP{respond: func(req *http.Request, body []byte) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{Endpoint: "https://siem/"})
	_, err := s.Send(context.Background(), integration.Sendable{
		Payload: []byte(`{}`),
		Config:  cfg,
		Now:     time.Now(),
	})
	if !errors.Is(err, integration.ErrTransient) {
		t.Fatalf("429 should be transient: %v", err)
	}
}

func TestSIEM_Test_ProbeUsesTestEvent(t *testing.T) {
	srv := &stubHTTP{}
	s := NewSIEM(srv, "ua")
	cfg, _ := json.Marshal(SIEMConfig{Endpoint: "https://siem/"})
	if err := s.Test(context.Background(), cfg, nil); err != nil {
		t.Fatalf("Test: %v", err)
	}
	if len(srv.bodies) != 1 || !strings.Contains(string(srv.bodies[0]), "connector.test") {
		t.Fatalf("expected probe event body, got %s", srv.bodies)
	}
	if got := srv.requests[0].Header.Get("X-Sng-Event"); got != "connector.test" {
		t.Fatalf("X-Sng-Event header missing: %q", got)
	}
}

func TestSIEM_Parse_RejectsInvalidConfig(t *testing.T) {
	s := NewSIEM(&stubHTTP{}, "ua")
	cases := []string{
		`{}`,
		`{"endpoint":"ftp://siem/"}`,
	}
	for _, raw := range cases {
		err := s.Test(context.Background(), json.RawMessage(raw), nil)
		if err == nil || errors.Is(err, integration.ErrTransient) {
			t.Fatalf("expected non-transient parse error for %s, got %v", raw, err)
		}
	}
}

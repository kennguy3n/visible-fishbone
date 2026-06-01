package connectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// recordingConn captures Write payloads in memory so the syslog
// frame can be asserted against the RFC 5424 grammar.
type recordingConn struct {
	mu        sync.Mutex
	written   []byte
	scheme    string
	closeErr  error
	writeErr  error
}

func (c *recordingConn) Read(p []byte) (int, error)         { return 0, net.ErrClosed }
func (c *recordingConn) LocalAddr() net.Addr                { return &net.IPAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr               { return &net.IPAddr{} }
func (c *recordingConn) SetDeadline(time.Time) error        { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error    { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error   { return nil }
func (c *recordingConn) Close() error                        { return c.closeErr }
func (c *recordingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.written = append(c.written, p...)
	return len(p), nil
}

func (c *recordingConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]byte, len(c.written))
	copy(out, c.written)
	return out
}

func TestSyslog_Send_FormatsRFC5424AndOctetCountFrames(t *testing.T) {
	rec := &recordingConn{scheme: "tcp"}
	dialer := func(_ context.Context, scheme, host string, _ *tls.Config) (net.Conn, error) {
		if scheme != "tcp" || host != "siem.example.com:514" {
			t.Fatalf("unexpected dial: %s %s", scheme, host)
		}
		return rec, nil
	}
	s := NewSyslog(dialer, time.Second, "ctl-1")
	cfg, _ := json.Marshal(SyslogConfig{
		Endpoint: "tcp://siem.example.com:514",
		AppName:  "sng-alerts",
		Facility: 16, // local0
	})
	payload, _ := json.Marshal(map[string]any{
		"event_id":  "ev-1",
		"headline":  "auth-failed:admin",
		"severity":  "high",
		"tenant_id": "tenant-A",
	})
	now := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

	res, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   payload,
		Config:    cfg,
		Now:       now,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ExternalReference != "" {
		t.Fatalf("syslog should not surface ExternalReference, got %q", res.ExternalReference)
	}

	got := string(rec.bytes())
	// PRI = facility*8 + severity = 16*8 + 3 = 131
	// Frame: "<octet-count> <PRI><PRI>1 …"
	parts := strings.SplitN(got, " ", 2)
	if len(parts) != 2 {
		t.Fatalf("expected octet-counted frame, got %q", got)
	}
	if len(parts[1]) == 0 || parts[1][0] != '<' {
		t.Fatalf("octet count not followed by RFC 5424 message: %q", got)
	}
	if !strings.HasPrefix(parts[1], "<131>1 ") {
		t.Fatalf("want PRI=131, got %q", parts[1])
	}
	if !strings.Contains(got, "sng-alerts") {
		t.Fatalf("missing app name: %q", got)
	}
	if !strings.Contains(got, "auth-failed:admin") {
		t.Fatalf("missing headline: %q", got)
	}
	if !strings.Contains(got, `event="alert.created"`) {
		t.Fatalf("missing structured-data event field: %q", got)
	}
	if !strings.Contains(got, "ALERT.CREATED") {
		t.Fatalf("MSGID should be event type upper-cased: %q", got)
	}
}

func TestSyslog_Send_UDPSkipsOctetFraming(t *testing.T) {
	rec := &recordingConn{scheme: "udp"}
	dialer := func(_ context.Context, scheme, host string, _ *tls.Config) (net.Conn, error) {
		return rec, nil
	}
	s := NewSyslog(dialer, time.Second, "ctl-1")
	cfg, _ := json.Marshal(SyslogConfig{Endpoint: "udp://siem.example.com:514"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{"headline":"hi"}`),
		Config:    cfg,
		Now:       time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(rec.bytes())
	if !strings.HasPrefix(got, "<") {
		t.Fatalf("UDP payload should begin with PRI, got %q", got)
	}
	// No "<length> <PRI>" framing for UDP.
	if strings.HasPrefix(got, "0123456789") {
		t.Fatalf("UDP payload should not be octet-counted, got %q", got)
	}
}

func TestSyslog_Send_DialErrorIsTransient(t *testing.T) {
	dialer := func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		return nil, errors.New("network unreachable")
	}
	s := NewSyslog(dialer, time.Second, "ctl-1")
	cfg, _ := json.Marshal(SyslogConfig{Endpoint: "tcp://siem.example.com:514"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{}`),
		Config:    cfg,
		Now:       time.Now(),
	})
	if !errors.Is(err, integration.ErrTransient) {
		t.Fatalf("dial error should be transient, got %v", err)
	}
}

func TestSyslog_Send_WriteErrorIsTransient(t *testing.T) {
	rec := &recordingConn{scheme: "tcp", writeErr: errors.New("broken pipe")}
	dialer := func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		return rec, nil
	}
	s := NewSyslog(dialer, time.Second, "ctl-1")
	cfg, _ := json.Marshal(SyslogConfig{Endpoint: "tcp://siem.example.com:514"})
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: "alert.created",
		Payload:   []byte(`{}`),
		Config:    cfg,
		Now:       time.Now(),
	})
	if !errors.Is(err, integration.ErrTransient) {
		t.Fatalf("write error should be transient, got %v", err)
	}
}

func TestSyslog_Test_DialsAndCloses(t *testing.T) {
	calls := 0
	dialer := func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
		calls++
		return &recordingConn{}, nil
	}
	s := NewSyslog(dialer, time.Second, "ctl-1")
	cfg, _ := json.Marshal(SyslogConfig{Endpoint: "tcp://siem.example.com:514"})
	if err := s.Test(context.Background(), cfg, nil); err != nil {
		t.Fatalf("Test should succeed on dial: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected exactly one dial, got %d", calls)
	}
}

func TestSyslog_Parse_RejectsInvalidConfig(t *testing.T) {
	s := NewSyslog(func(context.Context, string, string, *tls.Config) (net.Conn, error) { return nil, nil }, time.Second, "h")
	cases := map[string]string{
		"empty":          `{}`,
		"bad scheme":     `{"endpoint":"ftp://siem:514"}`,
		"missing host":   `{"endpoint":"tcp://"}`,
		"facility hi":    `{"endpoint":"tcp://h:1","facility":25}`,
		"facility neg":   `{"endpoint":"tcp://h:1","facility":-1}`,
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			err := s.Test(context.Background(), json.RawMessage(raw), nil)
			if err == nil || errors.Is(err, integration.ErrTransient) {
				t.Fatalf("expected non-transient parse error, got %v", err)
			}
		})
	}
}

func TestSyslog_StructuredDataEscaping(t *testing.T) {
	rec := &recordingConn{scheme: "tcp"}
	dialer := func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) { return rec, nil }
	s := NewSyslog(dialer, time.Second, "ctl-1")
	cfg, _ := json.Marshal(SyslogConfig{Endpoint: "tcp://h:1"})
	// Payload contains characters requiring SD-PARAM-VALUE escaping.
	_, err := s.Send(context.Background(), integration.Sendable{
		EventType: `pol]icy"\bad`,
		Payload:   []byte(`{"headline":"x"}`),
		Config:    cfg,
		Now:       time.Now(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := string(rec.bytes())
	if !strings.Contains(got, `event="pol\]icy\"\\bad"`) {
		t.Fatalf("SD-PARAM-VALUE escape missing: %q", got)
	}
}

func TestSyslog_SeverityMapping(t *testing.T) {
	tests := map[string]int{
		"critical": 2, "high": 3, "error": 3,
		"warning": 4, "warn": 4, "medium": 4,
		"info": 5, "notice": 5, "low": 5,
		"debug": 7, "":       6, "weird": 6,
	}
	for in, want := range tests {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %d, want %d", in, got, want)
		}
	}
}

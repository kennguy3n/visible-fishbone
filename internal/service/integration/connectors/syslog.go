package connectors

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// SyslogConfig is the per-connector configuration shape for kind=syslog.
// Stored as JSON in IntegrationConnector.Config.
//
// Endpoint is a URL whose scheme picks the transport:
//   - tcp://host:514       — plain TCP, RFC 6587 octet-counting framing.
//   - tls://host:6514      — TLS over TCP (RFC 5425).
//   - udp://host:514       — UDP datagram per message (RFC 5426).
//
// AppName is what the destination indexes as the program name —
// SNG events emit as "sng-control" by default. Facility is the
// numeric syslog facility (0..23). The dispatcher maps the alert
// severity onto the RFC 5424 severity field (0..7) per alertSeverity.
type SyslogConfig struct {
	Endpoint    string `json:"endpoint"`
	AppName     string `json:"app_name,omitempty"`
	Facility    int    `json:"facility,omitempty"`
	StructuredID string `json:"structured_id,omitempty"`
	// InsecureSkipVerify only applies when Endpoint scheme is tls://.
	// Operator-facing kill-switch for self-signed lab destinations;
	// production destinations should leave this false.
	InsecureSkipVerify bool `json:"insecure_skip_verify,omitempty"`
}

// SyslogSecret carries credentials when the operator wires a
// destination that performs TLS client-cert auth. Both fields are
// PEM-encoded. Optional — leave empty for server-auth-only TLS.
type SyslogSecret struct {
	ClientCertPEM string `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  string `json:"client_key_pem,omitempty"`
}

// SyslogDialer is the seam tests use to inject an in-memory
// connection in place of net.Dial / tls.Dial. Production paths
// pass nil to use the default dialer.
type SyslogDialer func(ctx context.Context, scheme, host string, tlsCfg *tls.Config) (net.Conn, error)

// Syslog is the kind=syslog plugin.
type Syslog struct {
	dialer  SyslogDialer
	timeout time.Duration
	hostname string
}

// NewSyslog constructs a Syslog connector. dialer may be nil
// (defaults to net.Dialer + tls.Dial). timeout bounds both
// Dial and Write — must be > 0. hostname is what the connector
// reports as the syslog HOSTNAME field; pass the control plane's
// hostname (or "-" if unavailable).
func NewSyslog(dialer SyslogDialer, timeout time.Duration, hostname string) *Syslog {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if hostname == "" {
		hostname = "-"
	}
	if dialer == nil {
		dialer = defaultSyslogDialer
	}
	return &Syslog{dialer: dialer, timeout: timeout, hostname: hostname}
}

// Kind reports IntegrationConnectorSyslog.
func (s *Syslog) Kind() repository.IntegrationConnectorType {
	return repository.IntegrationConnectorSyslog
}

// Test performs a connectivity probe: dial + immediate close, no
// message sent. We deliberately don't send a synthetic syslog
// message during Test because some destinations (managed SIEM
// collectors) treat unsolicited probe events as production
// telemetry and surface them in dashboards.
func (s *Syslog) Test(ctx context.Context, configRaw, secretRaw json.RawMessage) error {
	cfg, tlsCfg, err := s.parse(configRaw, secretRaw)
	if err != nil {
		return err
	}
	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := s.dialer(dialCtx, cfg.scheme, cfg.host, tlsCfg)
	if err != nil {
		return fmt.Errorf("syslog dial: %w: %w", err, integration.ErrTransient)
	}
	_ = conn.Close()
	return nil
}

// Send formats one delivery as an RFC 5424 syslog message and
// writes it to the destination. ExternalReference is always
// empty for syslog — the protocol doesn't return a stable id.
func (s *Syslog) Send(ctx context.Context, sn integration.Sendable) (integration.SendResult, error) {
	cfg, tlsCfg, err := s.parse(sn.Config, sn.Secret)
	if err != nil {
		return integration.SendResult{}, err
	}
	msg := s.format(cfg, sn)

	dialCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	conn, err := s.dialer(dialCtx, cfg.scheme, cfg.host, tlsCfg)
	if err != nil {
		return integration.SendResult{}, fmt.Errorf("syslog dial: %w: %w", err, integration.ErrTransient)
	}
	defer func() { _ = conn.Close() }()

	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
	} else {
		_ = conn.SetWriteDeadline(time.Now().Add(s.timeout))
	}

	var wire []byte
	switch cfg.scheme {
	case "udp":
		// RFC 5426: one message per datagram, no framing prefix.
		wire = []byte(msg)
	default:
		// RFC 6587 octet-counting: "<length> <message>".
		wire = []byte(fmt.Sprintf("%d %s", len(msg), msg))
	}
	if _, err := conn.Write(wire); err != nil {
		return integration.SendResult{}, fmt.Errorf("syslog write: %w: %w", err, integration.ErrTransient)
	}
	return integration.SendResult{ResponseStatus: 0}, nil
}

type parsedSyslogConfig struct {
	scheme   string
	host     string
	app      string
	facility int
	sdID     string
}

func (s *Syslog) parse(configRaw, secretRaw json.RawMessage) (parsedSyslogConfig, *tls.Config, error) {
	var cfg SyslogConfig
	if len(configRaw) == 0 {
		return parsedSyslogConfig{}, nil, errors.New("syslog: empty config")
	}
	if err := json.Unmarshal(configRaw, &cfg); err != nil {
		return parsedSyslogConfig{}, nil, fmt.Errorf("syslog: invalid config json: %w", err)
	}
	if cfg.Endpoint == "" {
		return parsedSyslogConfig{}, nil, errors.New("syslog: endpoint required")
	}
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return parsedSyslogConfig{}, nil, fmt.Errorf("syslog: invalid endpoint: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "tcp", "udp", "tls":
	default:
		return parsedSyslogConfig{}, nil, fmt.Errorf("syslog: unsupported scheme %q (want tcp|udp|tls)", scheme)
	}
	host := u.Host
	if host == "" {
		return parsedSyslogConfig{}, nil, errors.New("syslog: endpoint missing host")
	}
	if cfg.Facility < 0 || cfg.Facility > 23 {
		return parsedSyslogConfig{}, nil, fmt.Errorf("syslog: facility %d outside 0..23", cfg.Facility)
	}
	app := cfg.AppName
	if app == "" {
		app = "sng-control"
	}
	sdID := cfg.StructuredID
	if sdID == "" {
		sdID = "sng@53595" // private enterprise number placeholder
	}
	parsed := parsedSyslogConfig{
		scheme:   scheme,
		host:     host,
		app:      app,
		facility: cfg.Facility,
		sdID:     sdID,
	}

	var tlsCfg *tls.Config
	if scheme == "tls" {
		tlsCfg = &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // operator-controlled lab knob
			MinVersion:         tls.VersionTLS12,
		}
		if len(secretRaw) > 0 {
			var sec SyslogSecret
			if err := json.Unmarshal(secretRaw, &sec); err != nil {
				return parsedSyslogConfig{}, nil, fmt.Errorf("syslog: invalid secret json: %w", err)
			}
			if sec.ClientCertPEM != "" && sec.ClientKeyPEM != "" {
				cert, err := tls.X509KeyPair([]byte(sec.ClientCertPEM), []byte(sec.ClientKeyPEM))
				if err != nil {
					return parsedSyslogConfig{}, nil, fmt.Errorf("syslog: client cert: %w", err)
				}
				tlsCfg.Certificates = []tls.Certificate{cert}
			}
		}
	}
	return parsed, tlsCfg, nil
}

// alertEnvelope captures the subset of the event payload the
// syslog formatter consumes. Unknown fields are ignored; we only
// fish out the headline + severity used in the formatted message.
type alertEnvelope struct {
	EventID  string `json:"event_id,omitempty"`
	Headline string `json:"headline,omitempty"`
	Severity string `json:"severity,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

func (s *Syslog) format(cfg parsedSyslogConfig, sn integration.Sendable) string {
	var env alertEnvelope
	_ = json.Unmarshal(sn.Payload, &env)
	severity := mapSeverity(env.Severity)
	prival := cfg.facility*8 + severity
	timestamp := sn.Now.UTC().Format(time.RFC3339Nano)
	hostname := s.hostname
	procID := "-"
	msgID := strings.ToUpper(sn.EventType)
	if msgID == "" {
		msgID = "-"
	}
	if env.EventID == "" {
		env.EventID = "-"
	}
	if env.TenantID == "" {
		env.TenantID = "-"
	}
	// RFC 5424:
	//   <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD-ID] MSG
	sd := fmt.Sprintf(`[%s event="%s" tenant="%s"]`,
		sdEscape(cfg.sdID), sdEscape(sn.EventType), sdEscape(env.TenantID))
	msg := env.Headline
	if msg == "" {
		msg = "(no headline)"
	}
	return fmt.Sprintf("<%d>1 %s %s %s %s %s %s %s",
		prival, timestamp, hostname, cfg.app, procID, msgID, sd, msg)
}

// sdEscape applies the RFC 5424 § 6.3.3 PARAM-VALUE escape rule:
// backslash, double-quote, and right-bracket are prefixed with
// a backslash.
func sdEscape(in string) string {
	r := strings.NewReplacer(
		`\`, `\\`,
		`"`, `\"`,
		`]`, `\]`,
	)
	return r.Replace(in)
}

// mapSeverity translates the SNG alert severity name onto the
// RFC 5424 severity scale (0..7, smaller = more severe).
func mapSeverity(name string) int {
	switch strings.ToLower(name) {
	case "critical":
		return 2
	case "high", "error":
		return 3
	case "warning", "warn", "medium":
		return 4
	case "info", "notice", "low":
		return 5
	case "debug":
		return 7
	default:
		return 6 // informational
	}
}

func defaultSyslogDialer(ctx context.Context, scheme, host string, tlsCfg *tls.Config) (net.Conn, error) {
	d := &net.Dialer{}
	switch scheme {
	case "tcp":
		return d.DialContext(ctx, "tcp", host)
	case "udp":
		return d.DialContext(ctx, "udp", host)
	case "tls":
		// Use tls.Dialer so the handshake honours the context
		// deadline (tls.DialWithDialer doesn't take a context).
		td := &tls.Dialer{NetDialer: d, Config: tlsCfg}
		return td.DialContext(ctx, "tcp", host)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", scheme)
	}
}

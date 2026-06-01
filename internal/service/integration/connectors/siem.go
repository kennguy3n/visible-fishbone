package connectors

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// SIEMConfig is the per-connector configuration shape for kind=siem_webhook.
//
// Endpoint is the HTTPS URL the connector POSTs JSON to. Vendor
// is the upstream label used to pick the envelope shape:
//
//   - "splunk_hec":   Splunk HTTP Event Collector schema
//     ({"event": <payload>, "sourcetype": …}).
//   - "elastic":      Elastic _bulk-compatible ECS envelope
//     wrapping the payload under "event.original".
//   - "":             generic — payload posted as-is.
//
// Source labels the originating system in the envelope (defaults
// to "sng-control"). SignatureHeader / TimestampHeader are the
// HMAC headers the upstream verifies; defaults match the webhook
// service so SIEM operators can reuse their verification logic.
type SIEMConfig struct {
	Endpoint          string            `json:"endpoint"`
	Vendor            string            `json:"vendor,omitempty"`
	Source            string            `json:"source,omitempty"`
	SignatureHeader   string            `json:"signature_header,omitempty"`
	TimestampHeader   string            `json:"timestamp_header,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	InsecureSkipTLS   bool              `json:"insecure_skip_tls,omitempty"`
	IndexOrSourcetype string            `json:"index_or_sourcetype,omitempty"`
}

// SIEMSecret carries the HMAC signing key and any bearer/api-key
// header value. The HMAC key, if present, signs Body bytes. The
// AuthHeaderValue is sent in Authorization if non-empty (the
// caller writes the full value, e.g. "Bearer xyz" or "Splunk abc").
type SIEMSecret struct {
	HMACKey         string `json:"hmac_key,omitempty"`
	AuthHeaderValue string `json:"auth_header_value,omitempty"`
}

// SIEMHTTPDoer is the seam tests use to inject a mock HTTP client.
type SIEMHTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// SIEM is the kind=siem_webhook plugin.
type SIEM struct {
	client    SIEMHTTPDoer
	userAgent string
}

// NewSIEM constructs a SIEM connector. client may be nil
// (defaults to a tuned http.Client). userAgent is optional.
func NewSIEM(client SIEMHTTPDoer, userAgent string) *SIEM {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+integration/siem)"
	}
	return &SIEM{client: client, userAgent: userAgent}
}

// Kind reports IntegrationConnectorSIEMWebhook.
func (s *SIEM) Kind() repository.IntegrationConnectorType {
	return repository.IntegrationConnectorSIEMWebhook
}

// Test posts a single probe event (an "sng.test" event with
// trivial metadata) and checks for 2xx. Unlike syslog, SIEM
// endpoints are designed to accept arbitrary writes, so a probe
// event is the only reliable way to verify auth + routing.
func (s *SIEM) Test(ctx context.Context, configRaw, secretRaw json.RawMessage) error {
	cfg, sec, err := s.parse(configRaw, secretRaw)
	if err != nil {
		return err
	}
	probe := []byte(`{"kind":"connector.test","source":"sng-control"}`)
	status, body, doErr := s.post(ctx, cfg, sec, "connector.test", probe, time.Now().UTC())
	if doErr != nil {
		return fmt.Errorf("siem probe: %w: %w", doErr, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return fmt.Errorf("siem probe http %d: %w", status, integration.ErrTransient)
		}
		return fmt.Errorf("siem probe http %d: %s", status, truncate(body, 256))
	}
	return nil
}

// Send posts one event. SIEM responses don't carry a stable
// id; ExternalReference is always empty.
func (s *SIEM) Send(ctx context.Context, sn integration.Sendable) (integration.SendResult, error) {
	cfg, sec, err := s.parse(sn.Config, sn.Secret)
	if err != nil {
		return integration.SendResult{}, err
	}
	body, err := s.envelope(cfg, sn)
	if err != nil {
		return integration.SendResult{}, err
	}
	status, respBody, doErr := s.post(ctx, cfg, sec, sn.EventType, body, sn.Now)
	if doErr != nil {
		return integration.SendResult{ResponseStatus: status}, fmt.Errorf("siem send: %w: %w", doErr, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return integration.SendResult{ResponseStatus: status},
				fmt.Errorf("siem send http %d: %w", status, integration.ErrTransient)
		}
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("siem send http %d: %s", status, truncate(respBody, 256))
	}
	return integration.SendResult{ResponseStatus: status}, nil
}

type parsedSIEMConfig struct {
	endpoint          string
	vendor            string
	source            string
	sigHeader         string
	tsHeader          string
	headers           map[string]string
	indexOrSourcetype string
	insecureSkipTLS   bool
}

func (s *SIEM) parse(configRaw, secretRaw json.RawMessage) (parsedSIEMConfig, SIEMSecret, error) {
	var cfg SIEMConfig
	if len(configRaw) == 0 {
		return parsedSIEMConfig{}, SIEMSecret{}, errors.New("siem: empty config")
	}
	if err := json.Unmarshal(configRaw, &cfg); err != nil {
		return parsedSIEMConfig{}, SIEMSecret{}, fmt.Errorf("siem: invalid config json: %w", err)
	}
	if cfg.Endpoint == "" {
		return parsedSIEMConfig{}, SIEMSecret{}, errors.New("siem: endpoint required")
	}
	if !strings.HasPrefix(cfg.Endpoint, "http://") && !strings.HasPrefix(cfg.Endpoint, "https://") {
		return parsedSIEMConfig{}, SIEMSecret{}, fmt.Errorf("siem: endpoint must be http(s)")
	}
	source := cfg.Source
	if source == "" {
		source = "sng-control"
	}
	sigHeader := cfg.SignatureHeader
	if sigHeader == "" {
		sigHeader = "X-Sng-Signature"
	}
	tsHeader := cfg.TimestampHeader
	if tsHeader == "" {
		tsHeader = "X-Sng-Timestamp"
	}
	parsed := parsedSIEMConfig{
		endpoint:          cfg.Endpoint,
		vendor:            strings.ToLower(cfg.Vendor),
		source:            source,
		sigHeader:         sigHeader,
		tsHeader:          tsHeader,
		headers:           cfg.Headers,
		indexOrSourcetype: cfg.IndexOrSourcetype,
		insecureSkipTLS:   cfg.InsecureSkipTLS,
	}

	var sec SIEMSecret
	if len(secretRaw) > 0 {
		if err := json.Unmarshal(secretRaw, &sec); err != nil {
			return parsedSIEMConfig{}, SIEMSecret{}, fmt.Errorf("siem: invalid secret json: %w", err)
		}
	}
	return parsed, sec, nil
}

// envelope shapes the outgoing JSON per the Vendor selector.
func (s *SIEM) envelope(cfg parsedSIEMConfig, sn integration.Sendable) ([]byte, error) {
	switch cfg.vendor {
	case "splunk_hec":
		out := map[string]any{
			"event":  json.RawMessage(rawOrEmpty(sn.Payload)),
			"source": cfg.source,
			"time":   sn.Now.UTC().Unix(),
		}
		if cfg.indexOrSourcetype != "" {
			out["sourcetype"] = cfg.indexOrSourcetype
		}
		return json.Marshal(out)
	case "elastic":
		out := map[string]any{
			"@timestamp": sn.Now.UTC().Format(time.RFC3339Nano),
			"event": map[string]any{
				"kind":     "event",
				"category": []string{"network"},
				"action":   sn.EventType,
				"original": json.RawMessage(rawOrEmpty(sn.Payload)),
			},
			"agent": map[string]any{
				"type":    "sng-control",
				"version": "0.1",
			},
		}
		if cfg.indexOrSourcetype != "" {
			out["_index"] = cfg.indexOrSourcetype
		}
		return json.Marshal(out)
	default:
		// Generic — pass payload as-is. Empty payload becomes {}.
		return []byte(rawOrEmpty(sn.Payload)), nil
	}
}

func (s *SIEM) post(
	ctx context.Context,
	cfg parsedSIEMConfig,
	sec SIEMSecret,
	eventType string,
	body []byte,
	now time.Time,
) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("siem build request: %w", err)
	}
	// Apply operator-supplied custom headers FIRST so the defaults
	// and security-critical headers below cannot be silently
	// overridden. Earlier ordering (operator-last) allowed a
	// misconfigured `Content-Type: text/xml` to break JSON parsing
	// at the SIEM receiver; this ordering also pins User-Agent,
	// X-Sng-Event, Authorization, and the HMAC sig/ts headers so
	// signature verification always sees the values the connector
	// actually signed.
	for k, v := range cfg.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("X-Sng-Event", eventType)
	if sec.AuthHeaderValue != "" {
		req.Header.Set("Authorization", sec.AuthHeaderValue)
	}
	if sec.HMACKey != "" {
		ts := strconv.FormatInt(now.UTC().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(sec.HMACKey))
		signed := append([]byte(ts+"."), body...)
		mac.Write(signed)
		req.Header.Set(cfg.tsHeader, ts)
		req.Header.Set(cfg.sigHeader, "v1="+hex.EncodeToString(mac.Sum(nil)))
	}
	doer := s.client
	if cfg.insecureSkipTLS {
		// Per-connector InsecureSkipVerify cannot be applied to
		// the shared http.Client (it is shared across tenants and
		// connectors), so we build a one-shot client with a
		// custom Transport for this call. Used for self-signed
		// lab destinations only — production deployments should
		// leave insecure_skip_tls=false and trust the system CA
		// store. The allocation cost is negligible because the
		// flag is rare and SIEM Send latency is dominated by the
		// network round-trip.
		doer = &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
			},
		}
	}
	resp, err := doer.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, respBody, nil
}

func isTransientStatus(code int) bool {
	switch code {
	case http.StatusRequestTimeout, http.StatusTooManyRequests,
		http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

func rawOrEmpty(p json.RawMessage) string {
	s := strings.TrimSpace(string(p))
	if s == "" {
		return "{}"
	}
	return s
}

func truncate(b []byte, limit int) string {
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "...(truncated)"
}

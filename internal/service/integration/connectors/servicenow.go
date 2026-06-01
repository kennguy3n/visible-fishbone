package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// ServiceNowConfig is the per-connector configuration for kind=servicenow.
//
// InstanceURL is the per-tenant instance root (e.g.
// https://acme.service-now.com). Table is the Table API target —
// typically "incident", but operators may route to "sn_si_incident"
// (Security Incident Response) instead. CategoryByEvent is an
// optional event-type -> category mapping for filtering in
// ServiceNow dashboards.
//
// StateTransitions maps SNG event types to ServiceNow state codes
// (numeric strings, e.g. "2"=In Progress, "6"=Resolved, "7"=Closed).
// Defaults match the canonical incident table when the operator
// leaves the field empty.
type ServiceNowConfig struct {
	InstanceURL      string            `json:"instance_url"`
	Table            string            `json:"table,omitempty"`
	CategoryByEvent  map[string]string `json:"category_by_event,omitempty"`
	StateTransitions map[string]string `json:"state_transitions,omitempty"`
	AssignmentGroup  string            `json:"assignment_group,omitempty"`
	// ImpactByEvent and UrgencyByEvent map alert event types to
	// numeric impact/urgency values (1=high, 2=medium, 3=low)
	// per ServiceNow's ITSM scale.
	ImpactByEvent  map[string]string `json:"impact_by_event,omitempty"`
	UrgencyByEvent map[string]string `json:"urgency_by_event,omitempty"`
}

// ServiceNowSecret carries the basic-auth credentials (basic auth
// over TLS is the canonical Table API auth in ServiceNow Quebec
// onward). OAuth client-credentials is on the roadmap; the secret
// shape extends naturally — BearerToken would be added without
// breaking existing config.
type ServiceNowSecret struct {
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	BearerToken string `json:"bearer_token,omitempty"`
}

// SNHTTPDoer is the seam tests use to inject a mock client.
type SNHTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// ServiceNow is the kind=servicenow plugin.
type ServiceNow struct {
	client    SNHTTPDoer
	userAgent string
}

// NewServiceNow constructs a ServiceNow connector.
func NewServiceNow(client SNHTTPDoer, userAgent string) *ServiceNow {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+integration/servicenow)"
	}
	return &ServiceNow{client: client, userAgent: userAgent}
}

// Kind reports IntegrationConnectorServiceNow.
func (s *ServiceNow) Kind() repository.IntegrationConnectorType {
	return repository.IntegrationConnectorServiceNow
}

// Test verifies credentials by hitting the table with a
// sysparm_limit=1 GET. We do NOT create a probe incident
// because incident numbers are monotonic and a probe per Test
// inflates them.
func (s *ServiceNow) Test(ctx context.Context, configRaw, secretRaw json.RawMessage) error {
	cfg, sec, err := s.parse(configRaw, secretRaw)
	if err != nil {
		return err
	}
	status, body, doErr := s.request(ctx, cfg, sec, http.MethodGet,
		fmt.Sprintf("/api/now/table/%s?sysparm_limit=1", cfg.table), nil)
	if doErr != nil {
		return fmt.Errorf("servicenow probe: %w: %w", doErr, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return fmt.Errorf("servicenow probe http %d: %w", status, integration.ErrTransient)
		}
		return fmt.Errorf("servicenow probe http %d: %s", status, truncate(body, 256))
	}
	return nil
}

// Send creates an incident on the first event or PATCHes an
// existing one identified by ExternalReference (sys_id) on later
// events. State / urgency / impact transition through
// StateTransitions per event type.
func (s *ServiceNow) Send(ctx context.Context, sn integration.Sendable) (integration.SendResult, error) {
	cfg, sec, err := s.parse(sn.Config, sn.Secret)
	if err != nil {
		return integration.SendResult{}, err
	}
	if sn.ExternalReference == "" {
		return s.create(ctx, cfg, sec, sn)
	}
	return s.update(ctx, cfg, sec, sn)
}

func (s *ServiceNow) create(
	ctx context.Context,
	cfg parsedSNConfig,
	sec ServiceNowSecret,
	sn integration.Sendable,
) (integration.SendResult, error) {
	env := decodeAlertEnvelope(sn.Payload)
	short := env.Headline
	if short == "" {
		short = "SNG alert: " + sn.EventType
	}
	body := map[string]any{
		"short_description": short,
		"description":       env.Description,
		"category":          cfg.categoryByEvent[sn.EventType],
		"assignment_group":  cfg.assignmentGroup,
		"u_sng_event":       sn.EventType,
	}
	if v := cfg.impactByEvent[sn.EventType]; v != "" {
		body["impact"] = v
	}
	if v := cfg.urgencyByEvent[sn.EventType]; v != "" {
		body["urgency"] = v
	}
	pruneEmpty(body)

	status, respBody, err := s.request(ctx, cfg, sec, http.MethodPost,
		"/api/now/table/"+cfg.table, body)
	if err != nil {
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("servicenow create: %w: %w", err, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return integration.SendResult{ResponseStatus: status},
				fmt.Errorf("servicenow create http %d: %w", status, integration.ErrTransient)
		}
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("servicenow create http %d: %s", status, truncate(respBody, 256))
	}
	var resp struct {
		Result struct {
			SysID string `json:"sys_id"`
		} `json:"result"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil || resp.Result.SysID == "" {
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("servicenow create: missing sys_id in response: %s", truncate(respBody, 128))
	}
	return integration.SendResult{
		ResponseStatus:    status,
		ExternalReference: resp.Result.SysID,
	}, nil
}

func (s *ServiceNow) update(
	ctx context.Context,
	cfg parsedSNConfig,
	sec ServiceNowSecret,
	sn integration.Sendable,
) (integration.SendResult, error) {
	patch := map[string]any{}
	if v := cfg.stateTransitions[sn.EventType]; v != "" {
		patch["state"] = v
	}
	if v := cfg.impactByEvent[sn.EventType]; v != "" {
		patch["impact"] = v
	}
	if v := cfg.urgencyByEvent[sn.EventType]; v != "" {
		patch["urgency"] = v
	}
	env := decodeAlertEnvelope(sn.Payload)
	if env.Description != "" {
		patch["work_notes"] = env.Description
	}
	if len(patch) == 0 {
		return integration.SendResult{ExternalReference: sn.ExternalReference},
			fmt.Errorf("servicenow: no state_transitions / impact / urgency entry for event %q", sn.EventType)
	}
	path := fmt.Sprintf("/api/now/table/%s/%s", cfg.table, sn.ExternalReference)
	status, respBody, err := s.request(ctx, cfg, sec, http.MethodPatch, path, patch)
	if err != nil {
		return integration.SendResult{ResponseStatus: status, ExternalReference: sn.ExternalReference},
			fmt.Errorf("servicenow update: %w: %w", err, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return integration.SendResult{ResponseStatus: status, ExternalReference: sn.ExternalReference},
				fmt.Errorf("servicenow update http %d: %w", status, integration.ErrTransient)
		}
		return integration.SendResult{ResponseStatus: status, ExternalReference: sn.ExternalReference},
			fmt.Errorf("servicenow update http %d: %s", status, truncate(respBody, 256))
	}
	return integration.SendResult{
		ResponseStatus:    status,
		ExternalReference: sn.ExternalReference,
	}, nil
}

type parsedSNConfig struct {
	instanceURL      string
	table            string
	categoryByEvent  map[string]string
	stateTransitions map[string]string
	impactByEvent    map[string]string
	urgencyByEvent   map[string]string
	assignmentGroup  string
}

func (s *ServiceNow) parse(configRaw, secretRaw json.RawMessage) (parsedSNConfig, ServiceNowSecret, error) {
	var cfg ServiceNowConfig
	if len(configRaw) == 0 {
		return parsedSNConfig{}, ServiceNowSecret{}, errors.New("servicenow: empty config")
	}
	if err := json.Unmarshal(configRaw, &cfg); err != nil {
		return parsedSNConfig{}, ServiceNowSecret{}, fmt.Errorf("servicenow: invalid config json: %w", err)
	}
	if cfg.InstanceURL == "" || (!strings.HasPrefix(cfg.InstanceURL, "https://") && !strings.HasPrefix(cfg.InstanceURL, "http://")) {
		return parsedSNConfig{}, ServiceNowSecret{}, errors.New("servicenow: instance_url must be http(s)")
	}
	if cfg.Table == "" {
		cfg.Table = "incident"
	}
	parsed := parsedSNConfig{
		instanceURL:      strings.TrimRight(cfg.InstanceURL, "/"),
		table:            cfg.Table,
		categoryByEvent:  cfg.CategoryByEvent,
		stateTransitions: cfg.StateTransitions,
		impactByEvent:    cfg.ImpactByEvent,
		urgencyByEvent:   cfg.UrgencyByEvent,
		assignmentGroup:  cfg.AssignmentGroup,
	}
	var sec ServiceNowSecret
	if len(secretRaw) > 0 {
		if err := json.Unmarshal(secretRaw, &sec); err != nil {
			return parsedSNConfig{}, ServiceNowSecret{}, fmt.Errorf("servicenow: invalid secret json: %w", err)
		}
	}
	if sec.BearerToken == "" && (sec.Username == "" || sec.Password == "") {
		return parsedSNConfig{}, ServiceNowSecret{}, errors.New("servicenow: secret must include either bearer_token or (username + password)")
	}
	return parsed, sec, nil
}

func (s *ServiceNow) request(
	ctx context.Context,
	cfg parsedSNConfig,
	sec ServiceNowSecret,
	method, path string,
	body any,
) (int, []byte, error) {
	url := cfg.instanceURL + path
	var reqBody io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, nil, fmt.Errorf("encode body: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sec.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+sec.BearerToken)
	} else {
		auth := base64.StdEncoding.EncodeToString([]byte(sec.Username + ":" + sec.Password))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, respBody, nil
}

// pruneEmpty drops keys with zero values so we don't overwrite
// the destination's defaults (ServiceNow treats null and ""
// differently in some fields).
func pruneEmpty(m map[string]any) {
	for k, v := range m {
		switch tv := v.(type) {
		case string:
			if tv == "" {
				delete(m, k)
			}
		case nil:
			delete(m, k)
		}
	}
}

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

// JiraConfig is the per-connector configuration for kind=jira.
// BaseURL is the Atlassian site root (e.g. https://acme.atlassian.net).
// ProjectKey scopes new issues; IssueType is the create-shape type
// (e.g. "Task", "Bug", "Incident"). TransitionMap routes alert
// event types onto Jira workflow transition IDs:
//
//	{"alert.acknowledged": "21", "alert.resolved": "31"}
//
// Transitions are looked up by the Jira REST POST .../transitions
// endpoint at update time. Unknown event types are no-ops on the
// upstream and surface as a non-transient failure ("no transition
// configured") so operators see configuration gaps without burning
// the retry budget.
type JiraConfig struct {
	BaseURL       string            `json:"base_url"`
	ProjectKey    string            `json:"project_key"`
	IssueType     string            `json:"issue_type,omitempty"`
	TransitionMap map[string]string `json:"transition_map,omitempty"`
	// Labels are applied to every created issue. ServiceTier
	// is an extra label appended dynamically (often the
	// per-tenant tier). LabelEventType, when true, also
	// adds a label of the originating event type.
	Labels         []string `json:"labels,omitempty"`
	LabelEventType bool     `json:"label_event_type,omitempty"`
}

// JiraSecret carries the per-tenant credentials. Email + APIToken
// is the standard Atlassian Cloud combo (basic auth). For Jira
// Server / Data Center, BearerToken (a personal access token) is
// used in the Authorization header instead.
type JiraSecret struct {
	Email       string `json:"email,omitempty"`
	APIToken    string `json:"api_token,omitempty"`
	BearerToken string `json:"bearer_token,omitempty"`
}

// JiraHTTPDoer is the seam tests use to inject a mock client.
type JiraHTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Jira is the kind=jira plugin.
type Jira struct {
	client    JiraHTTPDoer
	userAgent string
}

// NewJira constructs a Jira connector.
func NewJira(client JiraHTTPDoer, userAgent string) *Jira {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+integration/jira)"
	}
	return &Jira{client: client, userAgent: userAgent}
}

// Kind reports IntegrationConnectorJira.
func (j *Jira) Kind() repository.IntegrationConnectorType {
	return repository.IntegrationConnectorJira
}

// Test verifies credentials by hitting /rest/api/3/myself, the
// canonical "who am I" endpoint. We do NOT create a probe issue
// because Jira issue counters are scoped to the project and an
// extra create on every Test would inflate them.
func (j *Jira) Test(ctx context.Context, configRaw, secretRaw json.RawMessage) error {
	cfg, sec, err := j.parse(configRaw, secretRaw)
	if err != nil {
		return err
	}
	status, body, doErr := j.request(ctx, cfg, sec, http.MethodGet,
		"/rest/api/3/myself", nil)
	if doErr != nil {
		return fmt.Errorf("jira probe: %w: %w", doErr, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return fmt.Errorf("jira probe http %d: %w", status, integration.ErrTransient)
		}
		return fmt.Errorf("jira probe http %d: %s", status, truncate(body, 256))
	}
	return nil
}

// Send creates an issue on the first event for a given alert, or
// transitions an existing issue identified by ExternalReference on
// subsequent events. The remote object's key (e.g. "OPS-42") is
// returned in SendResult.ExternalReference and persisted on the
// IntegrationDelivery row so the follow-up event finds it.
func (j *Jira) Send(ctx context.Context, sn integration.Sendable) (integration.SendResult, error) {
	cfg, sec, err := j.parse(sn.Config, sn.Secret)
	if err != nil {
		return integration.SendResult{}, err
	}
	if sn.ExternalReference == "" {
		return j.create(ctx, cfg, sec, sn)
	}
	return j.transition(ctx, cfg, sec, sn)
}

func (j *Jira) create(
	ctx context.Context,
	cfg parsedJiraConfig,
	sec JiraSecret,
	sn integration.Sendable,
) (integration.SendResult, error) {
	env := decodeAlertEnvelope(sn.Payload)
	summary := env.Headline
	if summary == "" {
		summary = "SNG alert: " + sn.EventType
	}
	labels := append([]string{}, cfg.labels...)
	if cfg.labelEventType {
		labels = append(labels, "event:"+sn.EventType)
	}
	body := map[string]any{
		"fields": map[string]any{
			"project":     map[string]string{"key": cfg.projectKey},
			"summary":     summary,
			"description": adfFromString(env.Description),
			"issuetype":   map[string]string{"name": cfg.issueType},
		},
	}
	if len(labels) > 0 {
		body["fields"].(map[string]any)["labels"] = labels
	}
	status, respBody, err := j.request(ctx, cfg, sec, http.MethodPost,
		"/rest/api/3/issue", body)
	if err != nil {
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("jira create: %w: %w", err, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return integration.SendResult{ResponseStatus: status},
				fmt.Errorf("jira create http %d: %w", status, integration.ErrTransient)
		}
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("jira create http %d: %s", status, truncate(respBody, 256))
	}
	var resp struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(respBody, &resp); err != nil || resp.Key == "" {
		return integration.SendResult{ResponseStatus: status},
			fmt.Errorf("jira create: missing issue key in response: %s", truncate(respBody, 128))
	}
	return integration.SendResult{
		ResponseStatus:    status,
		ExternalReference: resp.Key,
	}, nil
}

func (j *Jira) transition(
	ctx context.Context,
	cfg parsedJiraConfig,
	sec JiraSecret,
	sn integration.Sendable,
) (integration.SendResult, error) {
	transitionID := cfg.transitionMap[sn.EventType]
	if transitionID == "" {
		// No-op for events the operator hasn't mapped. Return
		// terminal so we don't burn the retry budget on a
		// configuration gap that won't fix itself.
		return integration.SendResult{ExternalReference: sn.ExternalReference},
			fmt.Errorf("jira: no transition_map entry for event %q", sn.EventType)
	}
	path := fmt.Sprintf("/rest/api/3/issue/%s/transitions", sn.ExternalReference)
	body := map[string]any{
		"transition": map[string]string{"id": transitionID},
	}
	status, respBody, err := j.request(ctx, cfg, sec, http.MethodPost, path, body)
	if err != nil {
		return integration.SendResult{ResponseStatus: status, ExternalReference: sn.ExternalReference},
			fmt.Errorf("jira transition: %w: %w", err, integration.ErrTransient)
	}
	if status < 200 || status >= 300 {
		if isTransientStatus(status) {
			return integration.SendResult{ResponseStatus: status, ExternalReference: sn.ExternalReference},
				fmt.Errorf("jira transition http %d: %w", status, integration.ErrTransient)
		}
		return integration.SendResult{ResponseStatus: status, ExternalReference: sn.ExternalReference},
			fmt.Errorf("jira transition http %d: %s", status, truncate(respBody, 256))
	}
	return integration.SendResult{
		ResponseStatus:    status,
		ExternalReference: sn.ExternalReference,
	}, nil
}

type parsedJiraConfig struct {
	baseURL        string
	projectKey     string
	issueType      string
	transitionMap  map[string]string
	labels         []string
	labelEventType bool
}

func (j *Jira) parse(configRaw, secretRaw json.RawMessage) (parsedJiraConfig, JiraSecret, error) {
	var cfg JiraConfig
	if len(configRaw) == 0 {
		return parsedJiraConfig{}, JiraSecret{}, errors.New("jira: empty config")
	}
	if err := json.Unmarshal(configRaw, &cfg); err != nil {
		return parsedJiraConfig{}, JiraSecret{}, fmt.Errorf("jira: invalid config json: %w", err)
	}
	if cfg.BaseURL == "" || (!strings.HasPrefix(cfg.BaseURL, "http://") && !strings.HasPrefix(cfg.BaseURL, "https://")) {
		return parsedJiraConfig{}, JiraSecret{}, errors.New("jira: base_url must be http(s)")
	}
	if cfg.ProjectKey == "" {
		return parsedJiraConfig{}, JiraSecret{}, errors.New("jira: project_key required")
	}
	if cfg.IssueType == "" {
		cfg.IssueType = "Task"
	}
	parsed := parsedJiraConfig{
		baseURL:        strings.TrimRight(cfg.BaseURL, "/"),
		projectKey:     cfg.ProjectKey,
		issueType:      cfg.IssueType,
		transitionMap:  cfg.TransitionMap,
		labels:         cfg.Labels,
		labelEventType: cfg.LabelEventType,
	}
	var sec JiraSecret
	if len(secretRaw) > 0 {
		if err := json.Unmarshal(secretRaw, &sec); err != nil {
			return parsedJiraConfig{}, JiraSecret{}, fmt.Errorf("jira: invalid secret json: %w", err)
		}
	}
	if sec.BearerToken == "" && (sec.Email == "" || sec.APIToken == "") {
		return parsedJiraConfig{}, JiraSecret{}, errors.New("jira: secret must include either bearer_token or (email + api_token)")
	}
	return parsed, sec, nil
}

func (j *Jira) request(
	ctx context.Context,
	cfg parsedJiraConfig,
	sec JiraSecret,
	method, path string,
	body any,
) (int, []byte, error) {
	url := cfg.baseURL + path
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
	req.Header.Set("User-Agent", j.userAgent)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if sec.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+sec.BearerToken)
	} else {
		auth := base64.StdEncoding.EncodeToString([]byte(sec.Email + ":" + sec.APIToken))
		req.Header.Set("Authorization", "Basic "+auth)
	}
	resp, err := j.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, respBody, nil
}

// adfFromString wraps a plain-text description into Atlassian
// Document Format. Jira Cloud's /rest/api/3 endpoints require
// rich-text fields to be encoded as ADF JSON objects.
func adfFromString(text string) map[string]any {
	if text == "" {
		text = "(no description)"
	}
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": []any{
			map[string]any{
				"type": "paragraph",
				"content": []any{
					map[string]any{
						"type": "text",
						"text": text,
					},
				},
			},
		},
	}
}

func decodeAlertEnvelope(p json.RawMessage) struct {
	Headline    string
	Description string
	Severity    string
} {
	var raw struct {
		Headline    string `json:"headline"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	}
	_ = json.Unmarshal(p, &raw)
	return struct {
		Headline    string
		Description string
		Severity    string
	}{raw.Headline, raw.Description, raw.Severity}
}

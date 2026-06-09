package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// OktaConfig holds the non-sensitive connector configuration.
// BaseURL is the Okta org URL (https://acme.okta.com).
type OktaConfig struct {
	BaseURL string `json:"base_url"`
}

// OktaSecret holds the Okta API token (SSWS scheme).
type OktaSecret struct {
	APIToken string `json:"api_token"`
}

// Okta implements CASBConnectorPlugin for an Okta org via the Okta
// Management API v1. Okta authenticates with the "SSWS" scheme
// rather than OAuth Bearer.
type Okta struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string // test seam; empty in production (base_url is tenant-supplied)
}

// NewOkta constructs an Okta CASB connector.
func NewOkta(client HTTPDoer, userAgent string) *Okta {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/okta)"
	}
	return &Okta{client: client, userAgent: userAgent}
}

func (o *Okta) Type() repository.CASBConnectorType { return repository.CASBConnectorOkta }

func (o *Okta) resolve(config json.RawMessage, secret []byte) (base, token string, err error) {
	var cfg OktaConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", fmt.Errorf("okta: invalid config: %w", err)
	}
	var sec OktaSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", fmt.Errorf("okta: invalid secret: %w", err)
	}
	if sec.APIToken == "" {
		return "", "", fmt.Errorf("okta: api_token is required")
	}
	if base, err = resolveTenantBase("okta", cfg.BaseURL, o.defaultBase); err != nil {
		return "", "", err
	}
	return base, sec.APIToken, nil
}

func (o *Okta) get(ctx context.Context, base, token, path string, out any) error {
	req, err := newJSONRequest(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return fmt.Errorf("okta: %w", err)
	}
	req.Header.Set("Authorization", "SSWS "+token)
	return doJSON(o.client, o.userAgent, "okta", req, out)
}

func (o *Okta) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return o.Test(ctx, config, secret)
}

func (o *Okta) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, token, err := o.resolve(config, secret)
	if err != nil {
		return err
	}
	var users []json.RawMessage
	if err := o.get(ctx, base, token, "/api/v1/users?limit=1", &users); err != nil {
		return fmt.Errorf("okta: test failed: %w", err)
	}
	return nil
}

func (o *Okta) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, token, err := o.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Profile struct {
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
			Email     string `json:"email"`
			Login     string `json:"login"`
		} `json:"profile"`
	}
	if err := o.get(ctx, base, token, "/api/v1/users?limit=200", &raw); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(raw))
	for _, u := range raw {
		name := strings.TrimSpace(u.Profile.FirstName + " " + u.Profile.LastName)
		if name == "" {
			name = u.Profile.Login
		}
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       u.Profile.Email,
			DisplayName: name,
			Active:      u.Status == "ACTIVE",
		})
	}
	return users, nil
}

func (o *Okta) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, token, err := o.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := "/api/v1/logs?limit=100"
	if since != "" {
		endpoint += "&since=" + url.QueryEscape(since)
	}
	var raw []struct {
		UUID      string `json:"uuid"`
		EventType string `json:"eventType"`
		Published string `json:"published"`
		Actor     struct {
			DisplayName string `json:"displayName"`
			AlternateID string `json:"alternateId"`
		} `json:"actor"`
		Client struct {
			IPAddress string `json:"ipAddress"`
		} `json:"client"`
		Target []struct {
			DisplayName string `json:"displayName"`
		} `json:"target"`
	}
	if err := o.get(ctx, base, token, endpoint, &raw); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(raw))
	for _, e := range raw {
		ts, _ := time.Parse(time.RFC3339, e.Published)
		actor := e.Actor.AlternateID
		if actor == "" {
			actor = e.Actor.DisplayName
		}
		var target string
		if len(e.Target) > 0 {
			target = e.Target[0].DisplayName
		}
		events = append(events, casb.ActivityEvent{
			ID:        e.UUID,
			Actor:     actor,
			Action:    e.EventType,
			Target:    target,
			IP:        e.Client.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (o *Okta) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, token, err := o.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	// An active MFA enrollment policy is the core Okta posture
	// control: without one, strong authentication is not enforced.
	var policies []struct {
		Status string `json:"status"`
		System bool   `json:"system"`
	}
	if err := o.get(ctx, base, token, "/api/v1/policies?type=MFA_ENROLL", &policies); err != nil {
		return casb.PostureReport{}, err
	}
	activeMFA := false
	for _, p := range policies {
		if p.Status == "ACTIVE" {
			activeMFA = true
			break
		}
	}
	checks := []casb.PostureCheck{
		boolCheck("mfa_enrollment_policy_active", "authentication", activeMFA,
			"an active MFA enrollment policy is configured",
			"no active MFA enrollment policy (strong authentication is not enforced)"),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

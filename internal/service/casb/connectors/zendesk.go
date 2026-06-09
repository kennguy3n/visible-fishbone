package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// ZendeskConfig holds the non-sensitive connector configuration.
// BaseURL is the Zendesk subdomain root (https://acme.zendesk.com).
type ZendeskConfig struct {
	BaseURL string `json:"base_url"`
}

// ZendeskSecret holds the API-token Basic-auth credentials. Zendesk
// authenticates an API token as the username "{email}/token".
type ZendeskSecret struct {
	Email    string `json:"email"`
	APIToken string `json:"api_token"`
}

// Zendesk implements CASBConnectorPlugin for a Zendesk account via
// the Zendesk REST API v2.
type Zendesk struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string // test seam; empty in production (base_url is tenant-supplied)
}

// NewZendesk constructs a Zendesk CASB connector.
func NewZendesk(client HTTPDoer, userAgent string) *Zendesk {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/zendesk)"
	}
	return &Zendesk{client: client, userAgent: userAgent}
}

func (z *Zendesk) Type() repository.CASBConnectorType { return repository.CASBConnectorZendesk }

func (z *Zendesk) resolve(config json.RawMessage, secret []byte) (base, user, pass string, err error) {
	var cfg ZendeskConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", "", fmt.Errorf("zendesk: invalid config: %w", err)
	}
	var sec ZendeskSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", "", fmt.Errorf("zendesk: invalid secret: %w", err)
	}
	if sec.Email == "" || sec.APIToken == "" {
		return "", "", "", fmt.Errorf("zendesk: email and api_token are required")
	}
	if base, err = resolveTenantBase("zendesk", cfg.BaseURL, z.defaultBase); err != nil {
		return "", "", "", err
	}
	// Zendesk API-token auth uses "{email}/token" as the Basic user.
	return base, sec.Email + "/token", sec.APIToken, nil
}

func (z *Zendesk) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return z.Test(ctx, config, secret)
}

func (z *Zendesk) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, user, pass, err := z.resolve(config, secret)
	if err != nil {
		return err
	}
	var out struct {
		User json.RawMessage `json:"user"`
	}
	if err := getJSONBasic(ctx, z.client, z.userAgent, "zendesk",
		base+"/api/v2/users/me.json", user, pass, &out); err != nil {
		return fmt.Errorf("zendesk: test failed: %w", err)
	}
	return nil
}

func (z *Zendesk) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, user, pass, err := z.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	var out struct {
		Users []struct {
			ID       int64  `json:"id"`
			Name     string `json:"name"`
			Email    string `json:"email"`
			Active   bool   `json:"active"`
			Role     string `json:"role"`
			Verified bool   `json:"verified"`
		} `json:"users"`
	}
	if err := getJSONBasic(ctx, z.client, z.userAgent, "zendesk",
		base+"/api/v2/users.json?per_page=100", user, pass, &out); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(out.Users))
	for _, u := range out.Users {
		users = append(users, casb.SaaSUser{
			ID:          strconv.FormatInt(u.ID, 10),
			Email:       u.Email,
			DisplayName: u.Name,
			Active:      u.Active,
			Admin:       u.Role == "admin",
		})
	}
	return users, nil
}

func (z *Zendesk) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, user, pass, err := z.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := base + "/api/v2/audit_logs.json?per_page=100&sort_by=created_at&sort_order=desc"
	if since != "" {
		endpoint += "&filter[created_at][]=" + url.QueryEscape(since)
	}
	var out struct {
		AuditLogs []struct {
			ID         int64  `json:"id"`
			ActorID    int64  `json:"actor_id"`
			ActorName  string `json:"actor_name"`
			Action     string `json:"action"`
			SourceType string `json:"source_type"`
			IPAddress  string `json:"ip_address"`
			CreatedAt  string `json:"created_at"`
		} `json:"audit_logs"`
	}
	if err := getJSONBasic(ctx, z.client, z.userAgent, "zendesk", endpoint, user, pass, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.AuditLogs))
	for _, e := range out.AuditLogs {
		ts, _ := time.Parse(time.RFC3339, e.CreatedAt)
		actor := e.ActorName
		if actor == "" {
			actor = strconv.FormatInt(e.ActorID, 10)
		}
		events = append(events, casb.ActivityEvent{
			ID:        strconv.FormatInt(e.ID, 10),
			Actor:     actor,
			Action:    e.Action,
			Target:    e.SourceType,
			IP:        e.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (z *Zendesk) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, user, pass, err := z.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	var out struct {
		Settings struct {
			Security struct {
				TwoFactorRequired bool `json:"two_factor_authentication_required"`
			} `json:"security"`
			Apps struct {
				Enabled bool `json:"enabled"`
			} `json:"apps"`
		} `json:"settings"`
	}
	if err := getJSONBasic(ctx, z.client, z.userAgent, "zendesk",
		base+"/api/v2/account/settings.json", user, pass, &out); err != nil {
		return casb.PostureReport{}, err
	}
	checks := []casb.PostureCheck{
		boolCheck("two_factor_required", "authentication", out.Settings.Security.TwoFactorRequired,
			"two-factor authentication is required for staff",
			"two-factor authentication is not required for staff"),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// ConfluenceConfig holds the non-sensitive connector configuration.
// BaseURL is the Atlassian Cloud site (https://acme.atlassian.net).
type ConfluenceConfig struct {
	BaseURL string `json:"base_url"`
}

// ConfluenceSecret holds the Atlassian Basic-auth credentials.
type ConfluenceSecret struct {
	Email    string `json:"email"`
	APIToken string `json:"api_token"`
}

// Confluence implements CASBConnectorPlugin for Confluence Cloud.
// User and audit data live on the shared Atlassian site surface
// (Jira REST + the platform audit log under /wiki), so the user
// model and posture mirror the Jira connector.
type Confluence struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string // test seam; empty in production (base_url is tenant-supplied)
}

// NewConfluence constructs a Confluence CASB connector.
func NewConfluence(client HTTPDoer, userAgent string) *Confluence {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/confluence)"
	}
	return &Confluence{client: client, userAgent: userAgent}
}

func (c *Confluence) Type() repository.CASBConnectorType { return repository.CASBConnectorConfluence }

func (c *Confluence) resolve(config json.RawMessage, secret []byte) (base, email, token string, err error) {
	var cfg ConfluenceConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", "", fmt.Errorf("confluence: invalid config: %w", err)
	}
	var sec ConfluenceSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", "", fmt.Errorf("confluence: invalid secret: %w", err)
	}
	if sec.Email == "" || sec.APIToken == "" {
		return "", "", "", fmt.Errorf("confluence: email and api_token are required")
	}
	if base, err = resolveTenantBase("confluence", cfg.BaseURL, c.defaultBase); err != nil {
		return "", "", "", err
	}
	return base, sec.Email, sec.APIToken, nil
}

func (c *Confluence) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return c.Test(ctx, config, secret)
}

func (c *Confluence) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, email, token, err := c.resolve(config, secret)
	if err != nil {
		return err
	}
	var space struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := getJSONBasic(ctx, c.client, c.userAgent, "confluence",
		base+"/wiki/rest/api/space?limit=1", email, token, &space); err != nil {
		return fmt.Errorf("confluence: test failed: %w", err)
	}
	return nil
}

func (c *Confluence) fetchUsers(ctx context.Context, base, email, token string) ([]jiraUser, error) {
	// Confluence Cloud shares the Atlassian identity directory; user
	// enumeration uses the platform user-search endpoint.
	var users []jiraUser
	if err := getJSONBasic(ctx, c.client, c.userAgent, "confluence",
		base+"/rest/api/3/users/search?maxResults=200", email, token, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (c *Confluence) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, email, token, err := c.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	raw, err := c.fetchUsers(ctx, base, email, token)
	if err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(raw))
	for _, u := range raw {
		if u.AccountType == "app" {
			continue
		}
		users = append(users, casb.SaaSUser{
			ID:          u.AccountID,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Active:      u.Active,
		})
	}
	return users, nil
}

func (c *Confluence) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, email, token, err := c.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := base + "/wiki/rest/api/audit?limit=100"
	if since != "" {
		// Confluence audit takes epoch-millis bounds; callers pass an
		// RFC3339 timestamp which we convert.
		if ts, perr := time.Parse(time.RFC3339, since); perr == nil {
			endpoint += "&startDate=" + url.QueryEscape(fmt.Sprintf("%d", ts.UnixMilli()))
		}
	}
	var out struct {
		Results []struct {
			Author struct {
				DisplayName string `json:"displayName"`
			} `json:"author"`
			RemoteAddress string `json:"remoteAddress"`
			CreationDate  int64  `json:"creationDate"`
			Summary       string `json:"summary"`
			Category      string `json:"category"`
		} `json:"results"`
	}
	if err := getJSONBasic(ctx, c.client, c.userAgent, "confluence", endpoint, email, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Results))
	for i, r := range out.Results {
		action := r.Summary
		if action == "" {
			action = r.Category
		}
		events = append(events, casb.ActivityEvent{
			ID:        fmt.Sprintf("%d-%d", r.CreationDate, i),
			Actor:     r.Author.DisplayName,
			Action:    action,
			IP:        r.RemoteAddress,
			Timestamp: time.UnixMilli(r.CreationDate).UTC(),
		})
	}
	return events, nil
}

func (c *Confluence) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, email, token, err := c.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	raw, err := c.fetchUsers(ctx, base, email, token)
	if err != nil {
		return casb.PostureReport{}, err
	}
	checks := atlassianUserPostureChecks("confluence", raw)
	return casb.PostureReport{
		Checks:     checks,
		RiskScore:  computePostureScore(checks),
		AssessedAt: time.Now().UTC(),
	}, nil
}

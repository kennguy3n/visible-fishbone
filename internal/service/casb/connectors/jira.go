package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// JiraConfig holds the non-sensitive connector configuration.
// BaseURL is the Atlassian Cloud site (https://acme.atlassian.net).
type JiraConfig struct {
	BaseURL string `json:"base_url"`
}

// JiraSecret holds the Atlassian Basic-auth credentials (account
// email + API token).
type JiraSecret struct {
	Email    string `json:"email"`
	APIToken string `json:"api_token"`
}

// Jira implements CASBConnectorPlugin for Jira Cloud via the Jira
// REST API v3.
type Jira struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string // test seam; empty in production (base_url is tenant-supplied)
}

// NewJira constructs a Jira CASB connector.
func NewJira(client HTTPDoer, userAgent string) *Jira {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/jira)"
	}
	return &Jira{client: client, userAgent: userAgent}
}

func (j *Jira) Type() repository.CASBConnectorType { return repository.CASBConnectorJira }

func (j *Jira) resolve(config json.RawMessage, secret []byte) (base, email, token string, err error) {
	var cfg JiraConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", "", fmt.Errorf("jira: invalid config: %w", err)
	}
	var sec JiraSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", "", fmt.Errorf("jira: invalid secret: %w", err)
	}
	if sec.Email == "" || sec.APIToken == "" {
		return "", "", "", fmt.Errorf("jira: email and api_token are required")
	}
	if base, err = resolveTenantBase("jira", cfg.BaseURL, j.defaultBase); err != nil {
		return "", "", "", err
	}
	return base, sec.Email, sec.APIToken, nil
}

func (j *Jira) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return j.Test(ctx, config, secret)
}

func (j *Jira) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, email, token, err := j.resolve(config, secret)
	if err != nil {
		return err
	}
	var me struct {
		AccountID string `json:"accountId"`
	}
	if err := getJSONBasic(ctx, j.client, j.userAgent, "jira", base+"/rest/api/3/myself", email, token, &me); err != nil {
		return fmt.Errorf("jira: test failed: %w", err)
	}
	return nil
}

// jiraUser is the shared shape returned by Atlassian user search.
type jiraUser struct {
	AccountID   string `json:"accountId"`
	DisplayName string `json:"displayName"`
	Email       string `json:"emailAddress"`
	Active      bool   `json:"active"`
	AccountType string `json:"accountType"`
}

func (j *Jira) fetchUsers(ctx context.Context, base, email, token string) ([]jiraUser, error) {
	var users []jiraUser
	if err := getJSONBasic(ctx, j.client, j.userAgent, "jira",
		base+"/rest/api/3/users/search?maxResults=200", email, token, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func (j *Jira) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, email, token, err := j.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	raw, err := j.fetchUsers(ctx, base, email, token)
	if err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(raw))
	for _, u := range raw {
		// "app" account types are bots/integrations, not people.
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

func (j *Jira) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, email, token, err := j.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := base + "/rest/api/3/auditing/record?limit=100"
	if since != "" {
		endpoint += "&from=" + url.QueryEscape(since)
	}
	var out struct {
		Records []struct {
			ID            int64  `json:"id"`
			Summary       string `json:"summary"`
			Created       string `json:"created"`
			AuthorKey     string `json:"authorKey"`
			AuthorAccount string `json:"authorAccountId"`
			RemoteAddress string `json:"remoteAddress"`
			ObjectItem    struct {
				Name string `json:"name"`
			} `json:"objectItem"`
		} `json:"records"`
	}
	if err := getJSONBasic(ctx, j.client, j.userAgent, "jira", endpoint, email, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Records))
	for _, r := range out.Records {
		ts, _ := time.Parse(time.RFC3339, r.Created)
		actor := r.AuthorAccount
		if actor == "" {
			actor = r.AuthorKey
		}
		events = append(events, casb.ActivityEvent{
			ID:        strconv.FormatInt(r.ID, 10),
			Actor:     actor,
			Action:    r.Summary,
			Target:    r.ObjectItem.Name,
			IP:        r.RemoteAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (j *Jira) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, email, token, err := j.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	raw, err := j.fetchUsers(ctx, base, email, token)
	if err != nil {
		return casb.PostureReport{}, err
	}
	checks := atlassianUserPostureChecks("jira", raw)
	return casb.PostureReport{
		Checks:     checks,
		RiskScore:  computePostureScore(checks),
		AssessedAt: time.Now().UTC(),
	}, nil
}

// atlassianUserPostureChecks derives data-exposure and hygiene
// signals from an Atlassian site's user roster: the presence of
// external customer accounts (data-sharing surface) and stale
// deactivated-yet-present accounts.
func atlassianUserPostureChecks(prefix string, users []jiraUser) []casb.PostureCheck {
	var external, inactive, total int
	for _, u := range users {
		if u.AccountType == "app" {
			continue
		}
		total++
		if u.AccountType == "customer" {
			external++
		}
		if !u.Active {
			inactive++
		}
	}
	extEvidence := fmt.Sprintf("%s: %d external customer accounts of %d", prefix, external, total)
	extStatus := casb.CheckStatusPass
	if external > 0 {
		extStatus = casb.CheckStatusWarn
		extEvidence += " (external collaboration is a data-exposure surface)"
	}
	inactiveEvidence := fmt.Sprintf("%s: %d inactive accounts still provisioned of %d", prefix, inactive, total)
	inactiveStatus := casb.CheckStatusPass
	if inactive > 0 {
		inactiveStatus = casb.CheckStatusWarn
		inactiveEvidence += " (deprovision to reduce attack surface)"
	}
	return []casb.PostureCheck{
		{Name: "external_accounts", Category: "data_protection", Status: extStatus, Evidence: strings.TrimSpace(extEvidence)},
		{Name: "inactive_accounts", Category: "access_control", Status: inactiveStatus, Evidence: strings.TrimSpace(inactiveEvidence)},
	}
}

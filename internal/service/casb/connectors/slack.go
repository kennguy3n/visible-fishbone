package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// SlackConfig holds the non-sensitive connector configuration.
type SlackConfig struct {
	WorkspaceID string `json:"workspace_id"`
}

// SlackSecret holds the OAuth token.
type SlackSecret struct {
	Token string `json:"token"`
}

// Slack implements CASBConnectorPlugin for Slack via SCIM API +
// Audit Logs API.
type Slack struct {
	client    HTTPDoer
	userAgent string
	baseURL   string
}

// NewSlack constructs a Slack CASB connector.
func NewSlack(client HTTPDoer, userAgent string) *Slack {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/slack)"
	}
	return &Slack{client: client, userAgent: userAgent, baseURL: "https://api.slack.com"}
}

func (s *Slack) Type() repository.CASBConnectorType {
	return repository.CASBConnectorSlack
}

func (s *Slack) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return s.Test(ctx, config, secret)
}

func (s *Slack) Test(ctx context.Context, _ json.RawMessage, secret []byte) error {
	token, err := parseSlackToken(secret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.baseURL+"/scim/v1/Users?count=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: test request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("slack: test returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (s *Slack) ListUsers(ctx context.Context, _ json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := parseSlackToken(secret)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.baseURL+"/scim/v1/Users?count=1000", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: list users failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("slack: list users returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Resources []struct {
			ID          string `json:"id"`
			UserName    string `json:"userName"`
			DisplayName string `json:"displayName"`
			Active      bool   `json:"active"`
			Emails      []struct {
				Value   string `json:"value"`
				Primary bool   `json:"primary"`
			} `json:"emails"`
		} `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("slack: decode users: %w", err)
	}
	users := make([]casb.SaaSUser, 0, len(result.Resources))
	for _, u := range result.Resources {
		email := u.UserName
		for _, e := range u.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       email,
			DisplayName: u.DisplayName,
			Active:      u.Active,
		})
	}
	return users, nil
}

func (s *Slack) ListActivity(ctx context.Context, _ json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := parseSlackToken(secret)
	if err != nil {
		return nil, err
	}
	endpoint := s.baseURL + "/audit/v1/logs?limit=100"
	if since != "" {
		endpoint += "&oldest=" + since
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: list activity failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("slack: list activity returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Entries []struct {
			ID     string `json:"id"`
			Action string `json:"action"`
			Actor  struct {
				User struct {
					Email string `json:"email"`
				} `json:"user"`
			} `json:"actor"`
			Context struct {
				IPAddress string `json:"ip_address"`
			} `json:"context"`
			DateCreate int64 `json:"date_create"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("slack: decode activity: %w", err)
	}
	events := make([]casb.ActivityEvent, 0, len(result.Entries))
	for _, e := range result.Entries {
		events = append(events, casb.ActivityEvent{
			ID:        e.ID,
			Actor:     e.Actor.User.Email,
			Action:    e.Action,
			IP:        e.Context.IPAddress,
			Timestamp: time.Unix(e.DateCreate, 0).UTC(),
		})
	}
	return events, nil
}

func (s *Slack) AssessPosture(_ context.Context, _ json.RawMessage, _ []byte) (casb.PostureReport, error) {
	now := time.Now().UTC()
	var checks []casb.PostureCheck

	checks = append(checks, casb.PostureCheck{
		CheckName: "sso_enforcement",
		Status:    "warn",
		Details:   "SSO enforcement status requires Slack admin settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		CheckName: "two_factor_auth",
		Status:    "warn",
		Details:   "2FA enforcement status requires workspace settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		CheckName: "external_sharing",
		Status:    "warn",
		Details:   "external sharing policy requires workspace settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		CheckName: "app_install_permissions",
		Status:    "warn",
		Details:   "app installation permissions require workspace admin settings inspection",
	})

	score := computePostureScore(checks)
	return casb.PostureReport{
		Checks:     checks,
		Score:      score,
		AssessedAt: now,
	}, nil
}

func parseSlackToken(secret []byte) (string, error) {
	var sec SlackSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("slack: invalid secret: %w", err)
	}
	if sec.Token == "" {
		return "", fmt.Errorf("slack: token is required")
	}
	return sec.Token, nil
}

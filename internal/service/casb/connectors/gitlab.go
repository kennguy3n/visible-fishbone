package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// GitLabConfig holds the non-sensitive connector configuration.
// BaseURL is the GitLab instance root (https://gitlab.com or a
// self-managed host); empty defaults to GitLab.com.
type GitLabConfig struct {
	BaseURL string `json:"base_url,omitempty"`
}

// GitLabSecret holds the personal/group access token.
type GitLabSecret struct {
	Token string `json:"token"`
}

// GitLab implements CASBConnectorPlugin for a GitLab instance via
// the GitLab REST API v4.
type GitLab struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string
}

// NewGitLab constructs a GitLab CASB connector.
func NewGitLab(client HTTPDoer, userAgent string) *GitLab {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/gitlab)"
	}
	return &GitLab{client: client, userAgent: userAgent, defaultBase: "https://gitlab.com"}
}

func (g *GitLab) Type() repository.CASBConnectorType { return repository.CASBConnectorGitLab }

func (g *GitLab) resolve(config json.RawMessage, secret []byte) (base, token string, err error) {
	var cfg GitLabConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", fmt.Errorf("gitlab: invalid config: %w", err)
	}
	var sec GitLabSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", fmt.Errorf("gitlab: invalid secret: %w", err)
	}
	if strings.TrimSpace(sec.Token) == "" {
		return "", "", fmt.Errorf("gitlab: token is required")
	}
	if base, err = resolveTenantBase("gitlab", cfg.BaseURL, g.defaultBase); err != nil {
		return "", "", err
	}
	return base, sec.Token, nil
}

func (g *GitLab) get(ctx context.Context, base, token, path string, out any) error {
	req, err := newJSONRequest(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return fmt.Errorf("gitlab: %w", err)
	}
	bearer(req, token)
	return doJSON(g.client, g.userAgent, "gitlab", req, out)
}

func (g *GitLab) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return g.Test(ctx, config, secret)
}

func (g *GitLab) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, token, err := g.resolve(config, secret)
	if err != nil {
		return err
	}
	var me struct {
		ID int64 `json:"id"`
	}
	if err := g.get(ctx, base, token, "/api/v4/user", &me); err != nil {
		return fmt.Errorf("gitlab: test failed: %w", err)
	}
	return nil
}

func (g *GitLab) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, token, err := g.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Name     string `json:"name"`
		Email    string `json:"email"`
		State    string `json:"state"`
		IsAdmin  bool   `json:"is_admin"`
	}
	if err := g.get(ctx, base, token, "/api/v4/users?per_page=100&without_project_bots=true", &raw); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(raw))
	for _, u := range raw {
		name := u.Name
		if name == "" {
			name = u.Username
		}
		users = append(users, casb.SaaSUser{
			ID:          strconv.FormatInt(u.ID, 10),
			Email:       u.Email,
			DisplayName: name,
			Active:      u.State == "active",
			Admin:       u.IsAdmin,
		})
	}
	return users, nil
}

func (g *GitLab) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, token, err := g.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := "/api/v4/audit_events?per_page=100"
	if since != "" {
		endpoint += "&created_after=" + since
	}
	var raw []struct {
		ID         int64  `json:"id"`
		AuthorID   int64  `json:"author_id"`
		AuthorName string `json:"author_name"`
		CreatedAt  string `json:"created_at"`
		Details    struct {
			Change     string `json:"change"`
			TargetType string `json:"target_type"`
			IPAddress  string `json:"ip_address"`
		} `json:"details"`
	}
	if err := g.get(ctx, base, token, endpoint, &raw); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(raw))
	for _, e := range raw {
		ts, _ := time.Parse(time.RFC3339, e.CreatedAt)
		action := e.Details.Change
		if action == "" {
			action = "audit_event"
		}
		events = append(events, casb.ActivityEvent{
			ID:        strconv.FormatInt(e.ID, 10),
			Actor:     e.AuthorName,
			Action:    action,
			Target:    e.Details.TargetType,
			IP:        e.Details.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (g *GitLab) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, token, err := g.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	var s struct {
		SignupEnabled    bool `json:"signup_enabled"`
		RequireTwoFactor bool `json:"require_two_factor_authentication"`
		AdminMode        bool `json:"admin_mode"`
	}
	if err := g.get(ctx, base, token, "/api/v4/application/settings", &s); err != nil {
		return casb.PostureReport{}, err
	}
	checks := []casb.PostureCheck{
		boolCheck("two_factor_required", "authentication", s.RequireTwoFactor,
			"instance requires two-factor authentication",
			"instance does not require two-factor authentication"),
		boolCheck("public_signup_disabled", "access_control", !s.SignupEnabled,
			"public sign-up is disabled",
			"public sign-up is enabled (anyone can create an account)"),
		boolCheck("admin_mode_enabled", "access_control", s.AdminMode,
			"admin mode (re-authentication for admin actions) is enabled",
			"admin mode is disabled — admin actions do not require re-authentication"),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

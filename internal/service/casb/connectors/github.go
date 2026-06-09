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

// GitHubConfig holds the non-sensitive connector configuration.
// Org is the GitHub organization login the connector inventories.
// APIBaseURL overrides the API root for GitHub Enterprise Server
// (e.g. https://github.example.com/api/v3); empty means GitHub.com.
type GitHubConfig struct {
	Org        string `json:"org"`
	APIBaseURL string `json:"api_base_url,omitempty"`
}

// GitHubSecret holds the personal-access-token / GitHub-App token.
type GitHubSecret struct {
	Token string `json:"token"`
}

// GitHub implements CASBConnectorPlugin for a GitHub organization
// via the GitHub REST API v3.
type GitHub struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string
}

// NewGitHub constructs a GitHub CASB connector.
func NewGitHub(client HTTPDoer, userAgent string) *GitHub {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/github)"
	}
	return &GitHub{client: client, userAgent: userAgent, defaultBase: "https://api.github.com"}
}

func (g *GitHub) Type() repository.CASBConnectorType { return repository.CASBConnectorGitHub }

// resolve validates config+secret and returns the API base URL and
// token. The base URL is sanitized when tenant-supplied (GHES).
func (g *GitHub) resolve(config json.RawMessage, secret []byte) (base, org, token string, err error) {
	var cfg GitHubConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", "", fmt.Errorf("github: invalid config: %w", err)
	}
	var sec GitHubSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", "", fmt.Errorf("github: invalid secret: %w", err)
	}
	if strings.TrimSpace(cfg.Org) == "" {
		return "", "", "", fmt.Errorf("github: org is required")
	}
	if strings.TrimSpace(sec.Token) == "" {
		return "", "", "", fmt.Errorf("github: token is required")
	}
	base = g.defaultBase
	if cfg.APIBaseURL != "" {
		if base, err = sanitizeBaseURL("github", cfg.APIBaseURL); err != nil {
			return "", "", "", err
		}
	}
	return base, cfg.Org, sec.Token, nil
}

func (g *GitHub) get(ctx context.Context, base, token, path string, out any) error {
	req, err := newJSONRequest(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	bearer(req, token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return doJSON(g.client, g.userAgent, "github", req, out)
}

func (g *GitHub) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return g.Test(ctx, config, secret)
}

func (g *GitHub) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, org, token, err := g.resolve(config, secret)
	if err != nil {
		return err
	}
	var org0 struct {
		Login string `json:"login"`
	}
	if err := g.get(ctx, base, token, "/orgs/"+url.PathEscape(org), &org0); err != nil {
		return fmt.Errorf("github: test failed: %w", err)
	}
	return nil
}

func (g *GitHub) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, org, token, err := g.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	// Admins (owners) are fetched separately so we can flag them;
	// GitHub's members list does not carry the org role.
	var admins []struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if err := g.get(ctx, base, token,
		"/orgs/"+url.PathEscape(org)+"/members?role=admin&per_page=100", &admins); err != nil {
		return nil, err
	}
	adminSet := make(map[string]struct{}, len(admins))
	for _, a := range admins {
		adminSet[a.Login] = struct{}{}
	}
	var members []struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if err := g.get(ctx, base, token,
		"/orgs/"+url.PathEscape(org)+"/members?per_page=100", &members); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(members))
	for _, m := range members {
		_, isAdmin := adminSet[m.Login]
		users = append(users, casb.SaaSUser{
			ID:          strconv.FormatInt(m.ID, 10),
			DisplayName: m.Login,
			Active:      true,
			Admin:       isAdmin,
		})
	}
	return users, nil
}

func (g *GitHub) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, org, token, err := g.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := "/orgs/" + url.PathEscape(org) + "/audit-log?per_page=100&include=all"
	if since != "" {
		endpoint += "&phrase=" + url.QueryEscape("created:>="+since)
	}
	var entries []struct {
		DocumentID string `json:"_document_id"`
		Action     string `json:"action"`
		Actor      string `json:"actor"`
		CreatedAt  int64  `json:"@timestamp"`
		Repo       string `json:"repo"`
	}
	if err := g.get(ctx, base, token, endpoint, &entries); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(entries))
	for _, e := range entries {
		events = append(events, casb.ActivityEvent{
			ID:        e.DocumentID,
			Actor:     e.Actor,
			Action:    e.Action,
			Target:    e.Repo,
			Timestamp: time.UnixMilli(e.CreatedAt).UTC(),
		})
	}
	return events, nil
}

func (g *GitHub) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, org, token, err := g.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	var o struct {
		TwoFactorRequired        bool   `json:"two_factor_requirement_enabled"`
		DefaultRepoPermission    string `json:"default_repository_permission"`
		MembersCanCreatePublic   bool   `json:"members_can_create_public_repositories"`
		MembersCanCreateRepos    bool   `json:"members_can_create_repositories"`
		WebCommitSignoffRequired bool   `json:"web_commit_signoff_required"`
	}
	if err := g.get(ctx, base, token, "/orgs/"+url.PathEscape(org), &o); err != nil {
		return casb.PostureReport{}, err
	}
	checks := []casb.PostureCheck{
		boolCheck("two_factor_enforcement", "authentication", o.TwoFactorRequired,
			"organization requires two-factor authentication for all members",
			"organization does not enforce two-factor authentication"),
		boolCheck("public_repo_creation_restricted", "data_protection", !o.MembersCanCreatePublic,
			"members cannot create public repositories",
			"members may create public repositories (data-exposure risk)"),
		boolCheck("web_commit_signoff_required", "data_protection", o.WebCommitSignoffRequired,
			"web commit sign-off is required",
			"web commit sign-off is not required"),
	}
	switch o.DefaultRepoPermission {
	case "none", "read":
		checks = append(checks, casb.PostureCheck{Name: "default_repo_permission", Category: "access_control",
			Status: casb.CheckStatusPass, Evidence: "least-privilege default repository permission: " + o.DefaultRepoPermission})
	case "write":
		checks = append(checks, casb.PostureCheck{Name: "default_repo_permission", Category: "access_control",
			Status: casb.CheckStatusWarn, Evidence: "default repository permission is broad: write"})
	default:
		checks = append(checks, casb.PostureCheck{Name: "default_repo_permission", Category: "access_control",
			Status: casb.CheckStatusFail, Evidence: "default repository permission is overly broad: " + o.DefaultRepoPermission})
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

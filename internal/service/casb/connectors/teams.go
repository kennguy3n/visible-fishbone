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

// TeamsConfig holds the non-sensitive connector configuration for a
// Microsoft Teams (Microsoft Graph) app registration.
type TeamsConfig struct {
	AzureTenantID string `json:"tenant_id"`
	ClientID      string `json:"client_id"`
}

// TeamsSecret holds the app-registration client secret.
type TeamsSecret struct {
	ClientSecret string `json:"client_secret"`
}

// Teams implements CASBConnectorPlugin for Microsoft Teams via
// Microsoft Graph v1.0 (Teams shares the Graph user/audit surface;
// the posture checks focus on Teams external-access controls).
type Teams struct {
	client       HTTPDoer
	userAgent    string
	graphBase    string
	tokenBaseURL string
}

// NewTeams constructs a Microsoft Teams CASB connector.
func NewTeams(client HTTPDoer, userAgent string) *Teams {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/teams)"
	}
	return &Teams{
		client:       client,
		userAgent:    userAgent,
		graphBase:    "https://graph.microsoft.com/v1.0",
		tokenBaseURL: "https://login.microsoftonline.com",
	}
}

func (t *Teams) Type() repository.CASBConnectorType { return repository.CASBConnectorTeams }

func (t *Teams) token(ctx context.Context, config json.RawMessage, secret []byte) (string, error) {
	var cfg TeamsConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("teams: invalid config: %w", err)
	}
	var sec TeamsSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("teams: invalid secret: %w", err)
	}
	if cfg.AzureTenantID == "" || cfg.ClientID == "" || sec.ClientSecret == "" {
		return "", fmt.Errorf("teams: tenant_id, client_id, and client_secret are required")
	}
	return azureADToken(ctx, t.client, t.userAgent, "teams", t.tokenBaseURL,
		cfg.AzureTenantID, cfg.ClientID, sec.ClientSecret, "https://graph.microsoft.com/.default")
}

func (t *Teams) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, err := t.token(ctx, config, secret)
	return err
}

func (t *Teams) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	token, err := t.token(ctx, config, secret)
	if err != nil {
		return err
	}
	var out struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := getJSON(ctx, t.client, t.userAgent, "teams",
		t.graphBase+"/teams?$top=1", token, &out); err != nil {
		return fmt.Errorf("teams: test failed: %w", err)
	}
	return nil
}

func (t *Teams) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := t.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []struct {
			ID             string `json:"id"`
			DisplayName    string `json:"displayName"`
			Mail           string `json:"mail"`
			UPN            string `json:"userPrincipalName"`
			AccountEnabled bool   `json:"accountEnabled"`
		} `json:"value"`
	}
	if err := getJSON(ctx, t.client, t.userAgent, "teams",
		t.graphBase+"/users?$select=id,displayName,mail,userPrincipalName,accountEnabled&$top=999", token, &out); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(out.Value))
	for _, u := range out.Value {
		email := u.Mail
		if email == "" {
			email = u.UPN
		}
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       email,
			DisplayName: u.DisplayName,
			Active:      u.AccountEnabled,
		})
	}
	return users, nil
}

func (t *Teams) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := t.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	q := url.Values{"$top": {"100"}}
	if since != "" {
		// OData filter values contain spaces and operators that must
		// be percent-encoded; building via url.Values guarantees a
		// well-formed request line.
		q.Set("$filter", "activityDateTime ge "+since)
	}
	endpoint := t.graphBase + "/auditLogs/directoryAudits?" + q.Encode()
	var out struct {
		Value []struct {
			ID                  string `json:"id"`
			ActivityDisplayName string `json:"activityDisplayName"`
			ActivityDateTime    string `json:"activityDateTime"`
			InitiatedBy         struct {
				User struct {
					UPN string `json:"userPrincipalName"`
				} `json:"user"`
			} `json:"initiatedBy"`
		} `json:"value"`
	}
	if err := getJSON(ctx, t.client, t.userAgent, "teams", endpoint, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Value))
	for _, e := range out.Value {
		ts, _ := time.Parse(time.RFC3339, e.ActivityDateTime)
		events = append(events, casb.ActivityEvent{
			ID:        e.ID,
			Actor:     e.InitiatedBy.User.UPN,
			Action:    e.ActivityDisplayName,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (t *Teams) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	token, err := t.token(ctx, config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	// Teams external/federation posture is governed by the
	// cross-tenant access defaults and the Teams client config.
	var cfg struct {
		AllowGuestUser bool `json:"allowGuestUser"`
	}
	if err := getJSON(ctx, t.client, t.userAgent, "teams",
		t.graphBase+"/teamwork/teamsAppSettings", token, &cfg); err != nil {
		// Fall back to a directory-level guest policy check when the
		// Teams app-settings surface is unavailable to the app.
		return t.assessGuestPolicy(ctx, token)
	}
	checks := []casb.PostureCheck{
		boolCheck("teams_guest_access_controlled", "data_protection", !cfg.AllowGuestUser,
			"Teams guest access is disabled",
			"Teams guest access is enabled (external users can join teams)"),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

func (t *Teams) assessGuestPolicy(ctx context.Context, token string) (casb.PostureReport, error) {
	var pol struct {
		AllowInvitesFrom string `json:"allowInvitesFrom"`
	}
	if err := getJSON(ctx, t.client, t.userAgent, "teams",
		t.graphBase+"/policies/authorizationPolicy", token, &pol); err != nil {
		return casb.PostureReport{}, err
	}
	restricted := pol.AllowInvitesFrom == "none" || pol.AllowInvitesFrom == "adminsAndGuestInviters"
	checks := []casb.PostureCheck{
		boolCheck("guest_invitations_restricted", "data_protection", restricted,
			"guest invitations restricted to "+pol.AllowInvitesFrom,
			"guest invitations allowed from: "+pol.AllowInvitesFrom),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

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

// BoxConfig holds the non-sensitive connector configuration for a
// Box enterprise using a Client Credentials Grant (CCG) app.
type BoxConfig struct {
	ClientID     string `json:"client_id"`
	EnterpriseID string `json:"enterprise_id"`
}

// BoxSecret holds the CCG client secret.
type BoxSecret struct {
	ClientSecret string `json:"client_secret"`
}

// Box implements CASBConnectorPlugin for Box via the Box Content API
// authenticated with a server-side Client Credentials Grant.
type Box struct {
	client    HTTPDoer
	userAgent string
	baseURL   string
	tokenURL  string
}

// NewBox constructs a Box CASB connector.
func NewBox(client HTTPDoer, userAgent string) *Box {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/box)"
	}
	return &Box{
		client:    client,
		userAgent: userAgent,
		baseURL:   "https://api.box.com",
		tokenURL:  "https://api.box.com/oauth2/token",
	}
}

func (b *Box) Type() repository.CASBConnectorType { return repository.CASBConnectorBox }

func (b *Box) token(ctx context.Context, config json.RawMessage, secret []byte) (string, error) {
	var cfg BoxConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("box: invalid config: %w", err)
	}
	var sec BoxSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("box: invalid secret: %w", err)
	}
	if cfg.ClientID == "" || cfg.EnterpriseID == "" {
		return "", fmt.Errorf("box: client_id and enterprise_id are required")
	}
	if sec.ClientSecret == "" {
		return "", fmt.Errorf("box: client_secret is required")
	}
	form := url.Values{
		"grant_type":       {"client_credentials"},
		"client_id":        {cfg.ClientID},
		"client_secret":    {sec.ClientSecret},
		"box_subject_type": {"enterprise"},
		"box_subject_id":   {cfg.EnterpriseID},
	}
	return clientCredentialsToken(ctx, b.client, b.userAgent, "box", b.tokenURL, form, "", "")
}

func (b *Box) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, err := b.token(ctx, config, secret)
	return err
}

func (b *Box) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	token, err := b.token(ctx, config, secret)
	if err != nil {
		return err
	}
	var out struct {
		TotalCount int `json:"total_count"`
	}
	if err := getJSON(ctx, b.client, b.userAgent, "box",
		b.baseURL+"/2.0/users?limit=1", token, &out); err != nil {
		return fmt.Errorf("box: test failed: %w", err)
	}
	return nil
}

func (b *Box) listUsers(ctx context.Context, token string) ([]struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Login  string `json:"login"`
	Status string `json:"status"`
	Role   string `json:"role"`
}, error,
) {
	var out struct {
		Entries []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Login  string `json:"login"`
			Status string `json:"status"`
			Role   string `json:"role"`
		} `json:"entries"`
	}
	if err := getJSON(ctx, b.client, b.userAgent, "box",
		b.baseURL+"/2.0/users?limit=1000&fields=id,name,login,status,role", token, &out); err != nil {
		return nil, err
	}
	return out.Entries, nil
}

func (b *Box) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := b.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	entries, err := b.listUsers(ctx, token)
	if err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(entries))
	for _, e := range entries {
		users = append(users, casb.SaaSUser{
			ID:          e.ID,
			Email:       e.Login,
			DisplayName: e.Name,
			Active:      e.Status == "active",
			Admin:       e.Role == "admin" || e.Role == "coadmin",
		})
	}
	return users, nil
}

func (b *Box) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := b.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := b.baseURL + "/2.0/events?stream_type=admin_logs&limit=100"
	if since != "" {
		endpoint += "&created_after=" + url.QueryEscape(since)
	}
	var out struct {
		Entries []struct {
			EventID   string `json:"event_id"`
			EventType string `json:"event_type"`
			CreatedAt string `json:"created_at"`
			CreatedBy struct {
				Login string `json:"login"`
			} `json:"created_by"`
			Source struct {
				Name string `json:"name"`
			} `json:"source"`
			IPAddress string `json:"ip_address"`
		} `json:"entries"`
	}
	if err := getJSON(ctx, b.client, b.userAgent, "box", endpoint, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Entries))
	for _, e := range out.Entries {
		ts, _ := time.Parse(time.RFC3339, e.CreatedAt)
		events = append(events, casb.ActivityEvent{
			ID:        e.EventID,
			Actor:     e.CreatedBy.Login,
			Action:    strings.ToLower(e.EventType),
			Target:    e.Source.Name,
			IP:        e.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (b *Box) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	token, err := b.token(ctx, config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	entries, err := b.listUsers(ctx, token)
	if err != nil {
		return casb.PostureReport{}, err
	}
	admins := 0
	for _, e := range entries {
		if e.Role == "admin" || e.Role == "coadmin" {
			admins++
		}
	}
	checks := []casb.PostureCheck{leastPrivilegeAdminCheck("box", len(entries), admins)}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// GoogleConfig holds the non-sensitive connector configuration.
type GoogleConfig struct {
	Domain         string `json:"domain"`
	AdminEmail     string `json:"admin_email"`
	CustomerID     string `json:"customer_id"`
	ServiceAccount string `json:"service_account_email"`
}

// GoogleSecret holds the service account private key JSON.
type GoogleSecret struct {
	PrivateKeyJSON json.RawMessage `json:"private_key_json"`
}

// Google implements CASBConnectorPlugin for Google Workspace via
// Admin SDK + Reports API with service account domain-wide delegation.
type Google struct {
	client    HTTPDoer
	userAgent string
	baseURL   string // overridable for testing; defaults to https://admin.googleapis.com
}

// NewGoogle constructs a Google Workspace CASB connector.
func NewGoogle(client HTTPDoer, userAgent string) *Google {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/google)"
	}
	return &Google{
		client:    client,
		userAgent: userAgent,
		baseURL:   "https://admin.googleapis.com",
	}
}

func (g *Google) Type() repository.CASBConnectorType {
	return repository.CASBConnectorGoogle
}

func (g *Google) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return g.Test(ctx, config, secret)
}

func (g *Google) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	token, err := g.getToken(ctx, config, secret)
	if err != nil {
		return fmt.Errorf("google: auth failed: %w", err)
	}
	var cfg GoogleConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("google: invalid config: %w", err)
	}
	customerID := cfg.CustomerID
	if customerID == "" {
		customerID = "my_customer"
	}
	endpoint := fmt.Sprintf(
		g.baseURL+"/admin/directory/v1/users?customer=%s&maxResults=1",
		url.QueryEscape(customerID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", g.userAgent)
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("google: test request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("google: test returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (g *Google) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := g.getToken(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	var cfg GoogleConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, err
	}
	customerID := cfg.CustomerID
	if customerID == "" {
		customerID = "my_customer"
	}
	endpoint := fmt.Sprintf(
		g.baseURL+"/admin/directory/v1/users?customer=%s&maxResults=500",
		url.QueryEscape(customerID))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", g.userAgent)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google: list users failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("google: list users returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Users []struct {
			ID           string `json:"id"`
			PrimaryEmail string `json:"primaryEmail"`
			Name         struct {
				FullName string `json:"fullName"`
			} `json:"name"`
			Suspended bool `json:"suspended"`
			IsAdmin   bool `json:"isAdmin"`
		} `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("google: decode users: %w", err)
	}
	users := make([]casb.SaaSUser, 0, len(result.Users))
	for _, u := range result.Users {
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       u.PrimaryEmail,
			DisplayName: u.Name.FullName,
			Active:      !u.Suspended,
			Admin:       u.IsAdmin,
		})
	}
	return users, nil
}

func (g *Google) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := g.getToken(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := g.baseURL + "/admin/reports/v1/activity/users/all/applications/login?maxResults=100"
	if since != "" {
		endpoint += "&startTime=" + since
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", g.userAgent)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google: list activity failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("google: list activity returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Items []struct {
			ID struct {
				UniqueQualifier string `json:"uniqueQualifier"`
				Time            string `json:"time"`
			} `json:"id"`
			Actor struct {
				Email string `json:"email"`
			} `json:"actor"`
			IPAddress string `json:"ipAddress"`
			Events    []struct {
				Name string `json:"name"`
			} `json:"events"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("google: decode activity: %w", err)
	}
	events := make([]casb.ActivityEvent, 0, len(result.Items))
	for _, item := range result.Items {
		ts, _ := time.Parse(time.RFC3339, item.ID.Time)
		action := "login"
		if len(item.Events) > 0 {
			action = item.Events[0].Name
		}
		events = append(events, casb.ActivityEvent{
			ID:        item.ID.UniqueQualifier,
			Actor:     item.Actor.Email,
			Action:    action,
			IP:        item.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (g *Google) AssessPosture(_ context.Context, _ json.RawMessage, _ []byte) (casb.PostureReport, error) {
	now := time.Now().UTC()
	var checks []casb.PostureCheck

	checks = append(checks, casb.PostureCheck{
		CheckName: "2sv_enforcement",
		Status:    "warn",
		Details:   "2-Step Verification enforcement requires Admin SDK org unit settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		CheckName: "recovery_options",
		Status:    "warn",
		Details:   "recovery phone/email settings require per-user inspection",
	})
	checks = append(checks, casb.PostureCheck{
		CheckName: "oauth_app_access",
		Status:    "warn",
		Details:   "OAuth app access control requires domain settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		CheckName: "external_sharing",
		Status:    "warn",
		Details:   "Drive external sharing policy requires Drive SDK settings inspection",
	})

	score := computePostureScore(checks)
	return casb.PostureReport{
		Checks:     checks,
		Score:      score,
		AssessedAt: now,
	}, nil
}

func (g *Google) getToken(_ context.Context, config json.RawMessage, secret []byte) (string, error) {
	var cfg GoogleConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("google: invalid config: %w", err)
	}
	if cfg.Domain == "" || cfg.AdminEmail == "" {
		return "", fmt.Errorf("google: domain and admin_email are required")
	}
	var sec GoogleSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("google: invalid secret: %w", err)
	}
	if len(sec.PrivateKeyJSON) == 0 {
		return "", fmt.Errorf("google: service account private_key_json is required")
	}
	// In production this would perform JWT-based service account
	// authentication with domain-wide delegation. For the initial
	// scaffold the token exchange is represented but the JWT
	// signing is deferred to a future PR that brings in a proper
	// JWT library or the Google auth SDK.
	return "google-sa-token-placeholder", nil
}

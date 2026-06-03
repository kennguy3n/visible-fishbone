package connectors

import (
	"bytes"
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

// SalesforceConfig holds the non-sensitive connector configuration.
type SalesforceConfig struct {
	InstanceURL string `json:"instance_url"`
	ClientID    string `json:"client_id"`
}

// SalesforceSecret holds the sensitive credentials.
type SalesforceSecret struct {
	ClientSecret  string `json:"client_secret"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	SecurityToken string `json:"security_token"`
}

// Salesforce implements CASBConnectorPlugin for Salesforce via
// the Salesforce REST API.
type Salesforce struct {
	client    HTTPDoer
	userAgent string
}

// NewSalesforce constructs a Salesforce CASB connector.
func NewSalesforce(client HTTPDoer, userAgent string) *Salesforce {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/salesforce)"
	}
	return &Salesforce{client: client, userAgent: userAgent}
}

func (sf *Salesforce) Type() repository.CASBConnectorType {
	return repository.CASBConnectorSalesforce
}

func (sf *Salesforce) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, _, err := sf.getToken(ctx, config, secret)
	return err
}

func (sf *Salesforce) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	token, instanceURL, err := sf.getToken(ctx, config, secret)
	if err != nil {
		return fmt.Errorf("salesforce: auth failed: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		instanceURL+"/services/data/v60.0/sobjects/User?q=SELECT+Id+FROM+User+LIMIT+1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", sf.userAgent)
	resp, err := sf.client.Do(req)
	if err != nil {
		return fmt.Errorf("salesforce: test request failed: %w", err)
	}
	defer resp.Body.Close()
	// Salesforce may return 200 or 400 for a test query; we accept
	// non-401/403 as a successful auth test.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("salesforce: test returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (sf *Salesforce) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, instanceURL, err := sf.getToken(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	query := url.QueryEscape("SELECT Id, Name, Email, IsActive, Profile.Name FROM User WHERE IsActive = true LIMIT 2000")
	endpoint := fmt.Sprintf("%s/services/data/v60.0/query?q=%s", instanceURL, query)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", sf.userAgent)
	resp, err := sf.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("salesforce: list users failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("salesforce: list users returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Records []struct {
			ID      string `json:"Id"`
			Name    string `json:"Name"`
			Email   string `json:"Email"`
			Active  bool   `json:"IsActive"`
			Profile struct {
				Name string `json:"Name"`
			} `json:"Profile"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("salesforce: decode users: %w", err)
	}
	users := make([]casb.SaaSUser, 0, len(result.Records))
	for _, u := range result.Records {
		isAdmin := u.Profile.Name == "System Administrator"
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       u.Email,
			DisplayName: u.Name,
			Active:      u.Active,
			Admin:       isAdmin,
		})
	}
	return users, nil
}

func (sf *Salesforce) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, instanceURL, err := sf.getToken(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	soql := "SELECT Id, CreatedBy.Name, Action, CreatedDate, Display FROM SetupAuditTrail ORDER BY CreatedDate DESC LIMIT 100"
	if since != "" {
		soql = fmt.Sprintf("SELECT Id, CreatedBy.Name, Action, CreatedDate, Display FROM SetupAuditTrail WHERE CreatedDate >= %s ORDER BY CreatedDate DESC LIMIT 100", since)
	}
	endpoint := fmt.Sprintf("%s/services/data/v60.0/query?q=%s", instanceURL, url.QueryEscape(soql))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", sf.userAgent)
	resp, err := sf.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("salesforce: list activity failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("salesforce: list activity returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Records []struct {
			ID        string `json:"Id"`
			CreatedBy struct {
				Name string `json:"Name"`
			} `json:"CreatedBy"`
			Action      string `json:"Action"`
			CreatedDate string `json:"CreatedDate"`
			Display     string `json:"Display"`
		} `json:"records"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("salesforce: decode activity: %w", err)
	}
	events := make([]casb.ActivityEvent, 0, len(result.Records))
	for _, r := range result.Records {
		ts, _ := time.Parse(time.RFC3339, r.CreatedDate)
		events = append(events, casb.ActivityEvent{
			ID:        r.ID,
			Actor:     r.CreatedBy.Name,
			Action:    r.Action,
			Details: r.Display,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (sf *Salesforce) AssessPosture(_ context.Context, _ json.RawMessage, _ []byte) (casb.PostureReport, error) {
	now := time.Now().UTC()
	var checks []casb.PostureCheck

	checks = append(checks, casb.PostureCheck{
		Name:     "mfa_enforcement",
		Status:   casb.CheckStatusWarn,
		Evidence: "MFA enforcement requires Salesforce org settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "session_settings",
		Status:   casb.CheckStatusWarn,
		Evidence: "session timeout and IP restrictions require org settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "password_policy",
		Status:   casb.CheckStatusWarn,
		Evidence: "password complexity policy requires org settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "api_access_control",
		Status:   casb.CheckStatusWarn,
		Evidence: "API access control requires connected app and profile inspection",
	})

	score := computePostureScore(checks)
	return casb.PostureReport{
		Checks:     checks,
		RiskScore:  score,
		AssessedAt: now,
	}, nil
}

func (sf *Salesforce) getToken(ctx context.Context, config json.RawMessage, secret []byte) (string, string, error) {
	var cfg SalesforceConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", "", fmt.Errorf("salesforce: invalid config: %w", err)
	}
	var sec SalesforceSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", "", fmt.Errorf("salesforce: invalid secret: %w", err)
	}
	if cfg.InstanceURL == "" || cfg.ClientID == "" {
		return "", "", fmt.Errorf("salesforce: instance_url and client_id are required")
	}
	if sec.ClientSecret == "" {
		return "", "", fmt.Errorf("salesforce: client_secret is required")
	}

	tokenURL := cfg.InstanceURL + "/services/oauth2/token"
	data := url.Values{
		"grant_type":    {"password"},
		"client_id":     {cfg.ClientID},
		"client_secret": {sec.ClientSecret},
		"username":      {sec.Username},
		"password":      {sec.Password + sec.SecurityToken},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", sf.userAgent)
	resp, err := sf.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("salesforce: token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", "", fmt.Errorf("salesforce: token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", "", fmt.Errorf("salesforce: decode token: %w", err)
	}
	instanceURL := tokenResp.InstanceURL
	if instanceURL == "" {
		instanceURL = cfg.InstanceURL
	}
	return tokenResp.AccessToken, instanceURL, nil
}

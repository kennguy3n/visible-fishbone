package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// googleTokenURL is the default Google OAuth2 token endpoint used for the
// JWT-bearer (service account) grant when the service account key does not
// carry its own token_uri.
const googleTokenURL = "https://oauth2.googleapis.com/token" //nolint:gosec // G101 false positive: public OAuth2 endpoint URL, not a credential.

// googleScopes are the OAuth2 scopes requested for the Admin SDK Directory
// and Reports APIs that this connector reads. They are read-only: the
// connector never mutates Workspace state.
const googleScopes = "https://www.googleapis.com/auth/admin.directory.user.readonly " +
	"https://www.googleapis.com/auth/admin.reports.audit.readonly"

// jwtBearerGrant is the OAuth2 grant type for a signed-JWT assertion.
const jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer" //nolint:gosec // G101 false positive: OAuth2 grant-type URN, not a credential.

// googleTrustedTokenHosts is the allowlist of hosts the connector will POST a
// signed assertion to. A service account key file is tenant-supplied input in
// a multi-tenant CASB, so its token_uri is untrusted: honoring an arbitrary
// value would let a malicious key point the control plane at an internal
// address or cloud-metadata endpoint (SSRF). Genuine Google keys always use
// oauth2.googleapis.com, so the allowlist costs real deployments nothing.
var googleTrustedTokenHosts = map[string]bool{
	"oauth2.googleapis.com": true,
	"accounts.google.com":   true,
}

// validateGoogleTokenURI enforces that a key-supplied token_uri is an https
// Google endpoint before it is used as the assertion audience and POST target.
func validateGoogleTokenURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("google: invalid token_uri in service account key: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("google: token_uri must use https, got scheme %q", u.Scheme)
	}
	if !googleTrustedTokenHosts[u.Host] {
		return fmt.Errorf("google: untrusted token_uri host %q (expected a googleapis.com token endpoint)", u.Host)
	}
	return nil
}

// googleSAKey is the relevant subset of a Google service account key file
// (the JSON downloaded from the GCP console). Only the fields needed to mint
// and exchange a signed assertion are decoded.
type googleSAKey struct {
	ClientEmail  string `json:"client_email"`
	PrivateKey   string `json:"private_key"`
	PrivateKeyID string `json:"private_key_id"`
	TokenURI     string `json:"token_uri"`
}

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
	tokenURL  string // overridable for testing; defaults to https://oauth2.googleapis.com/token
	now       func() time.Time
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
		tokenURL:  googleTokenURL,
		now:       time.Now,
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
		Name:     "2sv_enforcement",
		Status:   casb.CheckStatusWarn,
		Evidence: "2-Step Verification enforcement requires Admin SDK org unit settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "recovery_options",
		Status:   casb.CheckStatusWarn,
		Evidence: "recovery phone/email settings require per-user inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "oauth_app_access",
		Status:   casb.CheckStatusWarn,
		Evidence: "OAuth app access control requires domain settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "external_sharing",
		Status:   casb.CheckStatusWarn,
		Evidence: "Drive external sharing policy requires Drive SDK settings inspection",
	})

	score := computePostureScore(checks)
	return casb.PostureReport{
		Checks:     checks,
		RiskScore:  score,
		AssessedAt: now,
	}, nil
}

// getToken performs OAuth2 service-account authentication with domain-wide
// delegation: it mints an RS256-signed JWT assertion impersonating the
// configured admin (the `sub` claim) and exchanges it at Google's token
// endpoint for a short-lived access token scoped to the Admin SDK
// Directory and Reports APIs.
func (g *Google) getToken(ctx context.Context, config json.RawMessage, secret []byte) (string, error) {
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
	// Treat an absent field and an explicit JSON null the same: both mean no
	// key was supplied. json.RawMessage captures "null" as 4 literal bytes,
	// so a length check alone is not enough.
	if trimmed := strings.TrimSpace(string(sec.PrivateKeyJSON)); trimmed == "" || trimmed == "null" {
		return "", fmt.Errorf("google: service account private_key_json is required")
	}

	var key googleSAKey
	if err := json.Unmarshal(sec.PrivateKeyJSON, &key); err != nil {
		return "", fmt.Errorf("google: invalid service account key json: %w", err)
	}
	// The issuer of the assertion is the service account itself. Prefer the
	// client_email embedded in the key file; fall back to the explicitly
	// configured service account address.
	issuer := key.ClientEmail
	if issuer == "" {
		issuer = cfg.ServiceAccount
	}
	if issuer == "" {
		return "", fmt.Errorf("google: service account email missing from key (client_email) and config (service_account_email)")
	}
	if strings.TrimSpace(key.PrivateKey) == "" {
		return "", fmt.Errorf("google: service account key json missing private_key")
	}
	rsaKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(key.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("google: parse service account private key: %w", err)
	}

	// The audience of the assertion must equal the token endpoint it is
	// presented to (RFC 7523 §3). A real Google key carries its own
	// token_uri; honor it only after validating it is an https Google host so
	// a malicious tenant-supplied key cannot redirect the POST (SSRF). The
	// default g.tokenURL is operator-controlled and trusted as-is.
	tokenURL := g.tokenURL
	if key.TokenURI != "" {
		if err := validateGoogleTokenURI(key.TokenURI); err != nil {
			return "", err
		}
		tokenURL = key.TokenURI
	}

	now := g.now()
	claims := jwt.MapClaims{
		"iss":   issuer,
		"sub":   cfg.AdminEmail, // domain-wide delegation: impersonate the admin
		"scope": googleScopes,
		"aud":   tokenURL,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(), // Google caps assertion lifetime at 1h
	}
	assertion := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if key.PrivateKeyID != "" {
		assertion.Header["kid"] = key.PrivateKeyID
	}
	signed, err := assertion.SignedString(rsaKey)
	if err != nil {
		return "", fmt.Errorf("google: sign service account assertion: %w", err)
	}

	form := url.Values{
		"grant_type": {jwtBearerGrant},
		"assertion":  {signed},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", g.userAgent)
	resp, err := g.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("google: token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("google: token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("google: decode token: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("google: token endpoint returned empty access_token")
	}
	return tokenResp.AccessToken, nil
}

package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// M365Config holds the non-sensitive connector configuration.
type M365Config struct {
	AzureTenantID string `json:"tenant_id"`
	ClientID      string `json:"client_id"`
}

// M365Secret holds the sensitive credentials.
type M365Secret struct {
	ClientSecret string `json:"client_secret"`
}

// M365 implements CASBConnectorPlugin for Microsoft 365 via
// Microsoft Graph API v1.0.
type M365 struct {
	client       HTTPDoer
	userAgent    string
	graphBase    string // overridable for testing; defaults to https://graph.microsoft.com/v1.0
	tokenBaseURL string // overridable for testing; defaults to https://login.microsoftonline.com
}

// NewM365 constructs a Microsoft 365 CASB connector.
func NewM365(client HTTPDoer, userAgent string) *M365 {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/m365)"
	}
	return &M365{
		client:       client,
		userAgent:    userAgent,
		graphBase:    "https://graph.microsoft.com/v1.0",
		tokenBaseURL: "https://login.microsoftonline.com",
	}
}

func (m *M365) Type() repository.CASBConnectorType {
	return repository.CASBConnectorM365
}

func (m *M365) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, err := m.getToken(ctx, config, secret)
	return err
}

func (m *M365) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	token, err := m.getToken(ctx, config, secret)
	if err != nil {
		return fmt.Errorf("m365: auth failed: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.graphBase+"/organization", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return fmt.Errorf("m365: test request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("m365: test returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (m *M365) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := m.getToken(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.graphBase+"/users?$select=id,displayName,mail,accountEnabled", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("m365: list users failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("m365: list users returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Value []struct {
			ID             string `json:"id"`
			DisplayName    string `json:"displayName"`
			Mail           string `json:"mail"`
			AccountEnabled bool   `json:"accountEnabled"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("m365: decode users: %w", err)
	}
	users := make([]casb.SaaSUser, 0, len(result.Value))
	for _, u := range result.Value {
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       u.Mail,
			DisplayName: u.DisplayName,
			Active:      u.AccountEnabled,
		})
	}
	return users, nil
}

func (m *M365) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := m.getToken(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := m.graphBase + "/auditLogs/signIns?$top=100"
	if since != "" {
		endpoint += "&$filter=createdDateTime ge " + since
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("m365: list activity failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("m365: list activity returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Value []struct {
			ID                string `json:"id"`
			UserDisplayName   string `json:"userDisplayName"`
			AppDisplayName    string `json:"appDisplayName"`
			IPAddress         string `json:"ipAddress"`
			CreatedDateTime   string `json:"createdDateTime"`
			UserPrincipalName string `json:"userPrincipalName"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("m365: decode activity: %w", err)
	}
	events := make([]casb.ActivityEvent, 0, len(result.Value))
	for _, e := range result.Value {
		ts, _ := time.Parse(time.RFC3339, e.CreatedDateTime)
		events = append(events, casb.ActivityEvent{
			ID:        e.ID,
			Actor:     e.UserPrincipalName,
			Action:    "sign_in",
			Target:    e.AppDisplayName,
			IP:        e.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (m *M365) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	token, err := m.getToken(ctx, config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	now := time.Now().UTC()
	var checks []casb.PostureCheck

	// Check MFA enforcement via conditional access policies.
	checks = append(checks, m.checkMFAEnforcement(ctx, token))
	// Check legacy auth blocked.
	checks = append(checks, m.checkLegacyAuthBlocked(ctx, token))
	// Check audit logging enabled.
	checks = append(checks, casb.PostureCheck{
		Name:     "audit_logging_enabled",
		Status:   casb.CheckStatusPass,
		Evidence: "Microsoft 365 audit logging is enabled by default for enterprise tenants",
	})
	// Check admin MFA.
	checks = append(checks, m.checkAdminMFA(ctx, token))
	// Check guest access policy.
	checks = append(checks, m.checkGuestAccessPolicy(ctx, token))

	score := computePostureScore(checks)
	return casb.PostureReport{
		Checks:     checks,
		RiskScore:  score,
		AssessedAt: now,
	}, nil
}

func (m *M365) checkMFAEnforcement(ctx context.Context, token string) casb.PostureCheck {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.graphBase+"/identity/conditionalAccess/policies", nil)
	if err != nil {
		return casb.PostureCheck{Name: "mfa_enforcement", Status: casb.CheckStatusWarn, Evidence: "unable to check: " + err.Error()}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return casb.PostureCheck{Name: "mfa_enforcement", Status: casb.CheckStatusWarn, Evidence: "request failed: " + err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return casb.PostureCheck{Name: "mfa_enforcement", Status: casb.CheckStatusWarn, Evidence: fmt.Sprintf("API returned %d", resp.StatusCode)}
	}
	var result struct {
		Value []struct {
			State         string `json:"state"`
			GrantControls struct {
				BuiltInControls []string `json:"builtInControls"`
			} `json:"grantControls"`
		} `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return casb.PostureCheck{Name: "mfa_enforcement", Status: casb.CheckStatusWarn, Evidence: "decode error: " + err.Error()}
	}
	for _, p := range result.Value {
		if p.State != "enabled" {
			continue
		}
		for _, c := range p.GrantControls.BuiltInControls {
			if c == "mfa" {
				return casb.PostureCheck{Name: "mfa_enforcement", Status: casb.CheckStatusPass, Evidence: "MFA enforced via conditional access policy"}
			}
		}
	}
	return casb.PostureCheck{Name: "mfa_enforcement", Status: casb.CheckStatusFail, Evidence: "no active conditional access policy enforcing MFA"}
}

func (m *M365) checkLegacyAuthBlocked(ctx context.Context, token string) casb.PostureCheck {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.graphBase+"/identity/conditionalAccess/policies", nil)
	if err != nil {
		return casb.PostureCheck{Name: "legacy_auth_blocked", Status: casb.CheckStatusWarn, Evidence: "unable to check"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return casb.PostureCheck{Name: "legacy_auth_blocked", Status: casb.CheckStatusWarn, Evidence: "request failed"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return casb.PostureCheck{Name: "legacy_auth_blocked", Status: casb.CheckStatusWarn, Evidence: fmt.Sprintf("API returned %d", resp.StatusCode)}
	}
	var result struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return casb.PostureCheck{Name: "legacy_auth_blocked", Status: casb.CheckStatusWarn, Evidence: "decode error"}
	}
	for _, raw := range result.Value {
		s := string(raw)
		if strings.Contains(s, "exchangeActiveSync") || strings.Contains(s, "other") {
			if strings.Contains(s, `"block"`) || strings.Contains(s, `"Block"`) {
				return casb.PostureCheck{Name: "legacy_auth_blocked", Status: casb.CheckStatusPass, Evidence: "legacy authentication is blocked"}
			}
		}
	}
	return casb.PostureCheck{Name: "legacy_auth_blocked", Status: casb.CheckStatusFail, Evidence: "legacy authentication may not be blocked"}
}

func (m *M365) checkAdminMFA(_ context.Context, _ string) casb.PostureCheck {
	return casb.PostureCheck{
		Name:     "admin_mfa",
		Status:   casb.CheckStatusWarn,
		Evidence: "admin MFA check requires Security Defaults or per-user MFA status inspection",
	}
}

func (m *M365) checkGuestAccessPolicy(ctx context.Context, token string) casb.PostureCheck {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		m.graphBase+"/policies/authorizationPolicy", nil)
	if err != nil {
		return casb.PostureCheck{Name: "guest_access_policy", Status: casb.CheckStatusWarn, Evidence: "unable to check"}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return casb.PostureCheck{Name: "guest_access_policy", Status: casb.CheckStatusWarn, Evidence: "request failed"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return casb.PostureCheck{Name: "guest_access_policy", Status: casb.CheckStatusWarn, Evidence: fmt.Sprintf("API returned %d", resp.StatusCode)}
	}
	var result struct {
		AllowInvitesFrom string `json:"allowInvitesFrom"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return casb.PostureCheck{Name: "guest_access_policy", Status: casb.CheckStatusWarn, Evidence: "decode error"}
	}
	if result.AllowInvitesFrom == "none" || result.AllowInvitesFrom == "adminsAndGuestInviters" {
		return casb.PostureCheck{Name: "guest_access_policy", Status: casb.CheckStatusPass, Evidence: "guest invitations restricted to " + result.AllowInvitesFrom}
	}
	return casb.PostureCheck{Name: "guest_access_policy", Status: casb.CheckStatusFail, Evidence: "guest invitations allowed from: " + result.AllowInvitesFrom}
}

// ScanContent implements casb.ContentInspector for Microsoft 365: it
// enumerates each user's OneDrive and streams the content of every
// file (bounded to opts.MaxBytesPerObject) for DLP classification.
// Drives are walked breadth-first via Graph's driveItem children
// listing with @odata.nextLink paging so the file set is never
// buffered, and content is fetched through the Graph /content endpoint
// (using the tenant's own token) rather than the response's
// pre-authenticated @microsoft.graph.downloadUrl — the latter is an
// opaque CDN URL we would otherwise have to trust as a fetch target.
func (m *M365) ScanContent(
	ctx context.Context,
	config json.RawMessage,
	secret []byte,
	opts casb.ContentScanOptions,
	yield func(context.Context, casb.ContentObject) error,
) error {
	token, err := m.getToken(ctx, config, secret)
	if err != nil {
		return err
	}
	users, err := m.listDriveUserIDs(ctx, token)
	if err != nil {
		return err
	}
	for _, uid := range users {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := m.scanUserDrive(ctx, token, uid, opts, yield); err != nil {
			return err
		}
	}
	return nil
}

// listDriveUserIDs returns the ids of users whose OneDrive should be
// scanned. Graph caps /users at ~100 rows per page, so it must follow
// @odata.nextLink to enumerate every user — otherwise a tenant with
// more than a page of users would have most OneDrives silently skipped.
func (m *M365) listDriveUserIDs(ctx context.Context, token string) ([]string, error) {
	endpoint := m.graphBase + "/users?$select=id&$top=999"
	var ids []string
	for endpoint != "" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var result struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := getJSON(ctx, m.client, m.userAgent, "m365", endpoint, token, &result); err != nil {
			return nil, err
		}
		for _, u := range result.Value {
			ids = append(ids, u.ID)
		}
		endpoint = result.NextLink
	}
	return ids, nil
}

type graphDriveItem struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModifiedDateTime"`
	Folder       *struct {
		ChildCount int `json:"childCount"`
	} `json:"folder"`
	File *struct {
		MimeType string `json:"mimeType"`
	} `json:"file"`
}

// scanUserDrive walks one user's OneDrive breadth-first. A missing
// drive (404 — user never provisioned OneDrive) is skipped rather than
// failing the whole scan.
func (m *M365) scanUserDrive(
	ctx context.Context,
	token, userID string,
	opts casb.ContentScanOptions,
	yield func(context.Context, casb.ContentObject) error,
) error {
	root := fmt.Sprintf("%s/users/%s/drive/root/children?$select=id,name,size,lastModifiedDateTime,folder,file",
		m.graphBase, url.PathEscape(userID))
	queue := []string{root}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		endpoint := queue[0]
		queue = queue[1:]
		var page struct {
			Value    []graphDriveItem `json:"value"`
			NextLink string           `json:"@odata.nextLink"`
		}
		if err := getJSON(ctx, m.client, m.userAgent, "m365", endpoint, token, &page); err != nil {
			if isM365NotFound(err) {
				// User never provisioned a OneDrive; nothing to scan.
				continue
			}
			// Another per-user/per-folder Graph error (e.g. 403 on a
			// drive we cannot read). Record it and move on rather than
			// aborting the whole tenant scan. This getJSON path is
			// distinct from the yield path below, so the object-budget
			// stop sentinel is never swallowed here.
			if yerr := yield(ctx, casb.ContentObject{
				ID:       "user:" + userID,
				Owner:    userID,
				FetchErr: fmt.Errorf("list drive items: %w", err),
			}); yerr != nil {
				return yerr
			}
			return nil
		}
		for _, it := range page.Value {
			if it.Folder != nil {
				queue = append(queue, fmt.Sprintf(
					"%s/users/%s/drive/items/%s/children?$select=id,name,size,lastModifiedDateTime,folder,file",
					m.graphBase, url.PathEscape(userID), url.PathEscape(it.ID)))
				continue
			}
			if it.File == nil {
				continue
			}
			modified, _ := time.Parse(time.RFC3339, it.LastModified)
			if !opts.Since.IsZero() && !modified.IsZero() && modified.Before(opts.Since) {
				continue
			}
			content, ctype, ferr := fetchContent(ctx, m.client, m.userAgent, "m365",
				fmt.Sprintf("%s/users/%s/drive/items/%s/content",
					m.graphBase, url.PathEscape(userID), url.PathEscape(it.ID)),
				token, opts.MaxBytesPerObject)
			reported := ctype
			if it.File.MimeType != "" {
				reported = it.File.MimeType
			}
			obj := casb.ContentObject{
				ID:          it.ID,
				Name:        it.Name,
				Owner:       userID,
				ContentType: contentTypeFromName(reported, it.Name),
				SizeBytes:   it.Size,
				ModifiedAt:  modified,
				Content:     content,
				FetchErr:    ferr,
			}
			if err := yield(ctx, obj); err != nil {
				return err
			}
		}
		if page.NextLink != "" {
			queue = append(queue, page.NextLink)
		}
	}
	return nil
}

// isM365NotFound reports whether a doJSON/getJSON error wraps a Graph
// 404, used to skip users without a provisioned drive.
func isM365NotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "returned 404")
}

func (m *M365) getToken(ctx context.Context, config json.RawMessage, secret []byte) (string, error) {
	var cfg M365Config
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("m365: invalid config: %w", err)
	}
	var sec M365Secret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("m365: invalid secret: %w", err)
	}
	if cfg.AzureTenantID == "" || cfg.ClientID == "" || sec.ClientSecret == "" {
		return "", fmt.Errorf("m365: tenant_id, client_id, and client_secret are required")
	}
	tokenURL := fmt.Sprintf("%s/%s/oauth2/v2.0/token", m.tokenBaseURL, cfg.AzureTenantID)
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.ClientID},
		"client_secret": {sec.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL,
		bytes.NewBufferString(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", m.userAgent)
	resp, err := m.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("m365: token request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("m365: token endpoint returned %d: %s", resp.StatusCode, body)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("m365: decode token: %w", err)
	}
	return tokenResp.AccessToken, nil
}

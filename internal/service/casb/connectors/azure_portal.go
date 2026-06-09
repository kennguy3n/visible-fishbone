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

// AzurePortalConfig holds the non-sensitive connector configuration.
// SubscriptionID scopes the ARM role-assignment inventory.
type AzurePortalConfig struct {
	AzureTenantID  string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	SubscriptionID string `json:"subscription_id"`
}

// AzurePortalSecret holds the app-registration client secret.
type AzurePortalSecret struct {
	ClientSecret string `json:"client_secret"`
}

// AzurePortal implements CASBConnectorPlugin for the Azure control
// plane: users/roles from Microsoft Graph and subscription RBAC from
// Azure Resource Manager (ARM).
type AzurePortal struct {
	client       HTTPDoer
	userAgent    string
	graphBase    string
	armBase      string
	tokenBaseURL string
}

// NewAzurePortal constructs an Azure Portal CASB connector.
func NewAzurePortal(client HTTPDoer, userAgent string) *AzurePortal {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/azure_portal)"
	}
	return &AzurePortal{
		client:       client,
		userAgent:    userAgent,
		graphBase:    "https://graph.microsoft.com/v1.0",
		armBase:      "https://management.azure.com",
		tokenBaseURL: "https://login.microsoftonline.com",
	}
}

func (a *AzurePortal) Type() repository.CASBConnectorType { return repository.CASBConnectorAzurePortal }

func (a *AzurePortal) parse(config json.RawMessage, secret []byte) (AzurePortalConfig, string, error) {
	var cfg AzurePortalConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return AzurePortalConfig{}, "", fmt.Errorf("azure_portal: invalid config: %w", err)
	}
	var sec AzurePortalSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return AzurePortalConfig{}, "", fmt.Errorf("azure_portal: invalid secret: %w", err)
	}
	if cfg.AzureTenantID == "" || cfg.ClientID == "" || sec.ClientSecret == "" {
		return AzurePortalConfig{}, "", fmt.Errorf("azure_portal: tenant_id, client_id, and client_secret are required")
	}
	return cfg, sec.ClientSecret, nil
}

func (a *AzurePortal) graphToken(ctx context.Context, cfg AzurePortalConfig, clientSecret string) (string, error) {
	return azureADToken(ctx, a.client, a.userAgent, "azure_portal", a.tokenBaseURL,
		cfg.AzureTenantID, cfg.ClientID, clientSecret, "https://graph.microsoft.com/.default")
}

func (a *AzurePortal) armToken(ctx context.Context, cfg AzurePortalConfig, clientSecret string) (string, error) {
	return azureADToken(ctx, a.client, a.userAgent, "azure_portal", a.tokenBaseURL,
		cfg.AzureTenantID, cfg.ClientID, clientSecret, "https://management.azure.com/.default")
}

func (a *AzurePortal) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	cfg, cs, err := a.parse(config, secret)
	if err != nil {
		return err
	}
	_, err = a.graphToken(ctx, cfg, cs)
	return err
}

func (a *AzurePortal) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	cfg, cs, err := a.parse(config, secret)
	if err != nil {
		return err
	}
	token, err := a.graphToken(ctx, cfg, cs)
	if err != nil {
		return err
	}
	var out struct {
		Value []json.RawMessage `json:"value"`
	}
	if err := getJSON(ctx, a.client, a.userAgent, "azure_portal",
		a.graphBase+"/organization", token, &out); err != nil {
		return fmt.Errorf("azure_portal: test failed: %w", err)
	}
	return nil
}

func (a *AzurePortal) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	cfg, cs, err := a.parse(config, secret)
	if err != nil {
		return nil, err
	}
	token, err := a.graphToken(ctx, cfg, cs)
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
	if err := getJSON(ctx, a.client, a.userAgent, "azure_portal",
		a.graphBase+"/users?$select=id,displayName,mail,userPrincipalName,accountEnabled&$top=999", token, &out); err != nil {
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

func (a *AzurePortal) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	cfg, cs, err := a.parse(config, secret)
	if err != nil {
		return nil, err
	}
	token, err := a.graphToken(ctx, cfg, cs)
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
	endpoint := a.graphBase + "/auditLogs/directoryAudits?" + q.Encode()
	var out struct {
		Value []struct {
			ID                  string `json:"id"`
			ActivityDisplayName string `json:"activityDisplayName"`
			ActivityDateTime    string `json:"activityDateTime"`
			Result              string `json:"result"`
			InitiatedBy         struct {
				User struct {
					UPN string `json:"userPrincipalName"`
				} `json:"user"`
			} `json:"initiatedBy"`
		} `json:"value"`
	}
	if err := getJSON(ctx, a.client, a.userAgent, "azure_portal", endpoint, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Value))
	for _, e := range out.Value {
		ts, _ := time.Parse(time.RFC3339, e.ActivityDateTime)
		events = append(events, casb.ActivityEvent{
			ID:        e.ID,
			Actor:     e.InitiatedBy.User.UPN,
			Action:    e.ActivityDisplayName,
			Details:   e.Result,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (a *AzurePortal) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	cfg, cs, err := a.parse(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	checks := make([]casb.PostureCheck, 0, 2)

	graphTok, err := a.graphToken(ctx, cfg, cs)
	if err != nil {
		return casb.PostureReport{}, err
	}
	// Count privileged directory-role members (Global Administrator)
	// as the directory-level over-privilege signal.
	var ga struct {
		Value []struct {
			Members []json.RawMessage `json:"members"`
		} `json:"value"`
	}
	gaQuery := url.Values{
		"$filter": {"displayName eq 'Global Administrator'"},
		"$expand": {"members"},
	}
	if err := getJSON(ctx, a.client, a.userAgent, "azure_portal",
		a.graphBase+"/directoryRoles?"+gaQuery.Encode(), graphTok, &ga); err == nil {
		globalAdmins := 0
		for _, r := range ga.Value {
			globalAdmins += len(r.Members)
		}
		switch {
		case globalAdmins == 0:
			checks = append(checks, casb.PostureCheck{Name: "global_admin_count", Category: "access_control",
				Status: casb.CheckStatusWarn, Evidence: "no Global Administrators enumerated (insufficient directory read scope?)"})
		case globalAdmins <= 5:
			checks = append(checks, casb.PostureCheck{Name: "global_admin_count", Category: "access_control",
				Status: casb.CheckStatusPass, Evidence: fmt.Sprintf("%d Global Administrators (within recommended <=5)", globalAdmins)})
		default:
			checks = append(checks, casb.PostureCheck{Name: "global_admin_count", Category: "access_control",
				Status: casb.CheckStatusFail, Evidence: fmt.Sprintf("%d Global Administrators exceeds recommended maximum of 5", globalAdmins)})
		}
	}

	// Subscription RBAC: flag classic/owner role assignments at the
	// subscription scope when a subscription is configured.
	if cfg.SubscriptionID != "" {
		armTok, err := a.armToken(ctx, cfg, cs)
		if err != nil {
			return casb.PostureReport{}, err
		}
		endpoint := fmt.Sprintf("%s/subscriptions/%s/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01",
			a.armBase, cfg.SubscriptionID)
		var ra struct {
			Value []struct {
				Properties struct {
					RoleDefinitionID string `json:"roleDefinitionId"`
				} `json:"properties"`
			} `json:"value"`
		}
		if err := getJSON(ctx, a.client, a.userAgent, "azure_portal", endpoint, armTok, &ra); err == nil {
			owners := 0
			for _, r := range ra.Value {
				// The built-in Owner role definition id always ends in
				// this well-known GUID.
				if strings.HasSuffix(strings.ToLower(r.Properties.RoleDefinitionID),
					"8e3af657-a8ff-443c-a75c-2fe8c4bcb635") {
					owners++
				}
			}
			checks = append(checks, casb.PostureCheck{Name: "subscription_owner_assignments", Category: "access_control",
				Status: ownerStatus(owners), Evidence: fmt.Sprintf("%d Owner role assignments at subscription scope", owners)})
		}
	}

	if len(checks) == 0 {
		checks = append(checks, casb.PostureCheck{Name: "azure_posture", Category: "access_control",
			Status: casb.CheckStatusWarn, Evidence: "no posture signals available with the granted scopes"})
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

// ownerStatus rates the number of subscription Owner assignments.
func ownerStatus(owners int) casb.CheckStatus {
	switch {
	case owners <= 3:
		return casb.CheckStatusPass
	case owners <= 6:
		return casb.CheckStatusWarn
	default:
		return casb.CheckStatusFail
	}
}

package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// HubSpotConfig holds the non-sensitive connector configuration.
type HubSpotConfig struct {
	PortalID string `json:"portal_id,omitempty"`
}

// HubSpotSecret holds the private-app access token.
type HubSpotSecret struct {
	Token string `json:"token"`
}

// HubSpot implements CASBConnectorPlugin for a HubSpot account via
// the HubSpot CRM/Settings API v3.
type HubSpot struct {
	client    HTTPDoer
	userAgent string
	baseURL   string
}

// NewHubSpot constructs a HubSpot CASB connector.
func NewHubSpot(client HTTPDoer, userAgent string) *HubSpot {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/hubspot)"
	}
	return &HubSpot{client: client, userAgent: userAgent, baseURL: "https://api.hubapi.com"}
}

func (h *HubSpot) Type() repository.CASBConnectorType { return repository.CASBConnectorHubSpot }

func parseHubSpotToken(secret []byte) (string, error) {
	var sec HubSpotSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("hubspot: invalid secret: %w", err)
	}
	if sec.Token == "" {
		return "", fmt.Errorf("hubspot: token is required")
	}
	return sec.Token, nil
}

func (h *HubSpot) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return h.Test(ctx, config, secret)
}

func (h *HubSpot) Test(ctx context.Context, _ json.RawMessage, secret []byte) error {
	token, err := parseHubSpotToken(secret)
	if err != nil {
		return err
	}
	var out struct {
		Results []json.RawMessage `json:"results"`
	}
	if err := getJSON(ctx, h.client, h.userAgent, "hubspot",
		h.baseURL+"/settings/v3/users?limit=1", token, &out); err != nil {
		return fmt.Errorf("hubspot: test failed: %w", err)
	}
	return nil
}

func (h *HubSpot) ListUsers(ctx context.Context, _ json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := parseHubSpotToken(secret)
	if err != nil {
		return nil, err
	}
	var out struct {
		Results []struct {
			ID            string `json:"id"`
			Email         string `json:"email"`
			FirstName     string `json:"firstName"`
			LastName      string `json:"lastName"`
			SuperAdmin    bool   `json:"superAdmin"`
			PrimaryTeamID string `json:"primaryTeamId"`
		} `json:"results"`
	}
	if err := getJSON(ctx, h.client, h.userAgent, "hubspot",
		h.baseURL+"/settings/v3/users?limit=100", token, &out); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(out.Results))
	for _, u := range out.Results {
		name := strings.TrimSpace(u.FirstName + " " + u.LastName)
		if name == "" {
			name = u.Email
		}
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       u.Email,
			DisplayName: name,
			Active:      true,
			Admin:       u.SuperAdmin,
		})
	}
	return users, nil
}

func (h *HubSpot) ListActivity(ctx context.Context, _ json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := parseHubSpotToken(secret)
	if err != nil {
		return nil, err
	}
	endpoint := h.baseURL + "/account-info/v3/activity/login?limit=100"
	if since != "" {
		endpoint += "&occurredAfter=" + since
	}
	var out struct {
		Results []struct {
			Timestamp string `json:"occurredAt"`
			Actor     string `json:"actorId"`
			Type      string `json:"activityType"`
			IPAddress string `json:"ipAddress"`
		} `json:"results"`
	}
	if err := getJSON(ctx, h.client, h.userAgent, "hubspot", endpoint, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Results))
	for i, e := range out.Results {
		ts, _ := time.Parse(time.RFC3339, e.Timestamp)
		action := e.Type
		if action == "" {
			action = "login"
		}
		events = append(events, casb.ActivityEvent{
			ID:        fmt.Sprintf("%s-%d", e.Timestamp, i),
			Actor:     e.Actor,
			Action:    action,
			IP:        e.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (h *HubSpot) AssessPosture(ctx context.Context, _ json.RawMessage, secret []byte) (casb.PostureReport, error) {
	token, err := parseHubSpotToken(secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	var users struct {
		Results []struct {
			SuperAdmin bool `json:"superAdmin"`
		} `json:"results"`
	}
	if err := getJSON(ctx, h.client, h.userAgent, "hubspot",
		h.baseURL+"/settings/v3/users?limit=100", token, &users); err != nil {
		return casb.PostureReport{}, err
	}
	total := len(users.Results)
	admins := 0
	for _, u := range users.Results {
		if u.SuperAdmin {
			admins++
		}
	}
	checks := []casb.PostureCheck{leastPrivilegeAdminCheck("hubspot", total, admins)}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

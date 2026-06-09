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

// ZoomConfig holds the non-sensitive connector configuration for a
// Zoom Server-to-Server OAuth app.
type ZoomConfig struct {
	AccountID string `json:"account_id"`
	ClientID  string `json:"client_id"`
}

// ZoomSecret holds the Server-to-Server OAuth client secret.
type ZoomSecret struct {
	ClientSecret string `json:"client_secret"`
}

// Zoom implements CASBConnectorPlugin for a Zoom account via the
// Zoom API v2 with Server-to-Server OAuth (account_credentials).
type Zoom struct {
	client    HTTPDoer
	userAgent string
	baseURL   string
	tokenURL  string
}

// NewZoom constructs a Zoom CASB connector.
func NewZoom(client HTTPDoer, userAgent string) *Zoom {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/zoom)"
	}
	return &Zoom{
		client:    client,
		userAgent: userAgent,
		baseURL:   "https://api.zoom.us",
		tokenURL:  "https://zoom.us/oauth/token",
	}
}

func (z *Zoom) Type() repository.CASBConnectorType { return repository.CASBConnectorZoom }

func (z *Zoom) token(ctx context.Context, config json.RawMessage, secret []byte) (string, error) {
	var cfg ZoomConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return "", fmt.Errorf("zoom: invalid config: %w", err)
	}
	var sec ZoomSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("zoom: invalid secret: %w", err)
	}
	if cfg.AccountID == "" || cfg.ClientID == "" {
		return "", fmt.Errorf("zoom: account_id and client_id are required")
	}
	if sec.ClientSecret == "" {
		return "", fmt.Errorf("zoom: client_secret is required")
	}
	form := url.Values{
		"grant_type": {"account_credentials"},
		"account_id": {cfg.AccountID},
	}
	return clientCredentialsToken(ctx, z.client, z.userAgent, "zoom", z.tokenURL, form, cfg.ClientID, sec.ClientSecret)
}

func (z *Zoom) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, err := z.token(ctx, config, secret)
	return err
}

func (z *Zoom) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	token, err := z.token(ctx, config, secret)
	if err != nil {
		return err
	}
	var out struct {
		TotalRecords int `json:"total_records"`
	}
	if err := getJSON(ctx, z.client, z.userAgent, "zoom",
		z.baseURL+"/v2/users?page_size=1", token, &out); err != nil {
		return fmt.Errorf("zoom: test failed: %w", err)
	}
	return nil
}

func (z *Zoom) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := z.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	var out struct {
		Users []struct {
			ID        string `json:"id"`
			Email     string `json:"email"`
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Status    string `json:"status"`
			RoleName  string `json:"role_name"`
		} `json:"users"`
	}
	if err := getJSON(ctx, z.client, z.userAgent, "zoom",
		z.baseURL+"/v2/users?page_size=300&status=active", token, &out); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(out.Users))
	for _, u := range out.Users {
		name := strings.TrimSpace(u.FirstName + " " + u.LastName)
		if name == "" {
			name = u.Email
		}
		role := strings.ToLower(u.RoleName)
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       u.Email,
			DisplayName: name,
			Active:      u.Status == "active",
			Admin:       role == "owner" || role == "admin",
		})
	}
	return users, nil
}

func (z *Zoom) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := z.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := z.baseURL + "/v2/report/activities?page_size=300"
	if since != "" {
		endpoint += "&from=" + url.QueryEscape(since)
	}
	var out struct {
		ActivityLogs []struct {
			Email     string `json:"email"`
			Time      string `json:"time"`
			Type      string `json:"type"`
			IPAddress string `json:"ip_address"`
		} `json:"activity_logs"`
	}
	if err := getJSON(ctx, z.client, z.userAgent, "zoom", endpoint, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.ActivityLogs))
	for i, e := range out.ActivityLogs {
		ts, _ := time.Parse(time.RFC3339, e.Time)
		action := strings.ToLower(e.Type)
		if action == "" {
			action = "sign_in"
		}
		events = append(events, casb.ActivityEvent{
			ID:        fmt.Sprintf("%s-%d", e.Time, i),
			Actor:     e.Email,
			Action:    action,
			IP:        e.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (z *Zoom) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	token, err := z.token(ctx, config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	var s struct {
		InMeeting struct {
			WaitingRoom        bool `json:"waiting_room"`
			E2EEncryption      bool `json:"e2e_encryption"`
			MeetingPasswordReq bool `json:"meeting_password_requirement"`
		} `json:"in_meeting"`
		ScheduleMeeting struct {
			RequirePasswordForAll bool `json:"require_password_for_all_meetings"`
		} `json:"schedule_meeting"`
	}
	if err := getJSON(ctx, z.client, z.userAgent, "zoom",
		z.baseURL+"/v2/accounts/me/settings", token, &s); err != nil {
		return casb.PostureReport{}, err
	}
	checks := []casb.PostureCheck{
		boolCheck("waiting_room_enabled", "access_control", s.InMeeting.WaitingRoom,
			"waiting room is enabled (prevents unauthorized meeting access)",
			"waiting room is disabled"),
		boolCheck("meeting_password_required", "access_control", s.ScheduleMeeting.RequirePasswordForAll,
			"a passcode is required for all meetings",
			"meetings may be created without a passcode"),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

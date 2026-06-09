package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// DropboxConfig holds the non-sensitive connector configuration.
// TeamID is informational; the access token scopes the team.
type DropboxConfig struct {
	TeamID string `json:"team_id,omitempty"`
}

// DropboxSecret holds the Dropbox Business team access token.
type DropboxSecret struct {
	Token string `json:"token"`
}

// Dropbox implements CASBConnectorPlugin for Dropbox Business via
// the Dropbox Team API (RPC endpoints: HTTPS POST with a JSON body).
type Dropbox struct {
	client    HTTPDoer
	userAgent string
	baseURL   string
}

// NewDropbox constructs a Dropbox CASB connector.
func NewDropbox(client HTTPDoer, userAgent string) *Dropbox {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/dropbox)"
	}
	return &Dropbox{client: client, userAgent: userAgent, baseURL: "https://api.dropboxapi.com"}
}

func (d *Dropbox) Type() repository.CASBConnectorType { return repository.CASBConnectorDropbox }

func parseDropboxToken(secret []byte) (string, error) {
	var sec DropboxSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("dropbox: invalid secret: %w", err)
	}
	if sec.Token == "" {
		return "", fmt.Errorf("dropbox: token is required")
	}
	return sec.Token, nil
}

// rpc posts a JSON arg to a Dropbox RPC endpoint. Dropbox requires a
// body on every RPC call; null is the documented "no args" value.
func (d *Dropbox) rpc(ctx context.Context, token, path string, arg any, out any) error {
	var body []byte
	if arg != nil {
		b, err := json.Marshal(arg)
		if err != nil {
			return fmt.Errorf("dropbox: marshal arg: %w", err)
		}
		body = b
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("dropbox: %w", err)
	}
	bearer(req, token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	return doJSON(d.client, d.userAgent, "dropbox", req, out)
}

func (d *Dropbox) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return d.Test(ctx, config, secret)
}

func (d *Dropbox) Test(ctx context.Context, _ json.RawMessage, secret []byte) error {
	token, err := parseDropboxToken(secret)
	if err != nil {
		return err
	}
	var info struct {
		Name struct {
			DisplayName string `json:"display_name"`
		} `json:"name"`
	}
	if err := d.rpc(ctx, token, "/2/team/get_info", nil, &info); err != nil {
		return fmt.Errorf("dropbox: test failed: %w", err)
	}
	return nil
}

func (d *Dropbox) ListUsers(ctx context.Context, _ json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := parseDropboxToken(secret)
	if err != nil {
		return nil, err
	}
	var result struct {
		Members []struct {
			Profile struct {
				TeamMemberID string `json:"team_member_id"`
				Email        string `json:"email"`
				Status       struct {
					Tag string `json:".tag"`
				} `json:"status"`
				Name struct {
					DisplayName string `json:"display_name"`
				} `json:"name"`
			} `json:"profile"`
			Role struct {
				Tag string `json:".tag"`
			} `json:"role"`
		} `json:"members"`
	}
	if err := d.rpc(ctx, token, "/2/team/members/list_v2",
		map[string]any{"limit": 1000}, &result); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(result.Members))
	for _, m := range result.Members {
		users = append(users, casb.SaaSUser{
			ID:          m.Profile.TeamMemberID,
			Email:       m.Profile.Email,
			DisplayName: m.Profile.Name.DisplayName,
			Active:      m.Profile.Status.Tag == "active",
			Admin:       m.Role.Tag == "team_admin",
		})
	}
	return users, nil
}

func (d *Dropbox) ListActivity(ctx context.Context, _ json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := parseDropboxToken(secret)
	if err != nil {
		return nil, err
	}
	arg := map[string]any{"limit": 100}
	if since != "" {
		arg["time"] = map[string]any{"start_time": since}
	}
	var result struct {
		Events []struct {
			Timestamp string `json:"timestamp"`
			EventType struct {
				Tag string `json:".tag"`
			} `json:"event_type"`
			Actor struct {
				User struct {
					Email string `json:"email"`
				} `json:"user"`
			} `json:"actor"`
		} `json:"events"`
	}
	if err := d.rpc(ctx, token, "/2/team_log/get_events", arg, &result); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(result.Events))
	for i, e := range result.Events {
		ts, _ := time.Parse(time.RFC3339, e.Timestamp)
		events = append(events, casb.ActivityEvent{
			ID:        fmt.Sprintf("%s-%d", e.Timestamp, i),
			Actor:     e.Actor.User.Email,
			Action:    e.EventType.Tag,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (d *Dropbox) AssessPosture(ctx context.Context, _ json.RawMessage, secret []byte) (casb.PostureReport, error) {
	token, err := parseDropboxToken(secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	var info struct {
		Policies struct {
			SharedFolderMemberPolicy struct {
				Tag string `json:".tag"`
			} `json:"shared_folder_member_policy"`
			SharedLinkCreatePolicy struct {
				Tag string `json:".tag"`
			} `json:"shared_link_create_policy"`
			EMMState struct {
				Tag string `json:".tag"`
			} `json:"emm_state"`
		} `json:"policies"`
	}
	if err := d.rpc(ctx, token, "/2/team/get_info", nil, &info); err != nil {
		return casb.PostureReport{}, err
	}
	// "team_only" sharing policies keep data inside the org; the
	// "anyone" variants are the external-exposure risk.
	memberTeamOnly := info.Policies.SharedFolderMemberPolicy.Tag == "team"
	linkTeamOnly := info.Policies.SharedLinkCreatePolicy.Tag == "team_only"
	emmOn := info.Policies.EMMState.Tag == "required" || info.Policies.EMMState.Tag == "optional"
	checks := []casb.PostureCheck{
		boolCheck("shared_folder_members_team_only", "data_protection", memberTeamOnly,
			"shared-folder membership restricted to team",
			"shared folders may include external members"),
		boolCheck("shared_links_team_only", "data_protection", linkTeamOnly,
			"shared-link creation restricted to team",
			"shared links may be created for anyone (public exposure risk)"),
		boolCheck("enterprise_mobility_management", "device", emmOn,
			"enterprise mobility management is configured",
			"enterprise mobility management is disabled"),
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

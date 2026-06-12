package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// SlackConfig holds the non-sensitive connector configuration.
type SlackConfig struct {
	WorkspaceID string `json:"workspace_id"`
}

// SlackSecret holds the OAuth token.
type SlackSecret struct {
	Token string `json:"token"`
}

// Slack implements CASBConnectorPlugin for Slack via SCIM API +
// Audit Logs API.
type Slack struct {
	client    HTTPDoer
	userAgent string
	baseURL   string
	// webBaseURL hosts the Slack Web API methods (conversations.*),
	// which live under slack.com/api rather than the api.slack.com host
	// the SCIM/audit endpoints use. Overridable for testing.
	webBaseURL string
}

// NewSlack constructs a Slack CASB connector.
func NewSlack(client HTTPDoer, userAgent string) *Slack {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/slack)"
	}
	return &Slack{
		client:     client,
		userAgent:  userAgent,
		baseURL:    "https://api.slack.com",
		webBaseURL: "https://slack.com",
	}
}

func (s *Slack) Type() repository.CASBConnectorType {
	return repository.CASBConnectorSlack
}

func (s *Slack) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return s.Test(ctx, config, secret)
}

func (s *Slack) Test(ctx context.Context, _ json.RawMessage, secret []byte) error {
	token, err := parseSlackToken(secret)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.baseURL+"/scim/v1/Users?count=1", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("slack: test request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("slack: test returned %d: %s", resp.StatusCode, body)
	}
	return nil
}

func (s *Slack) ListUsers(ctx context.Context, _ json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	token, err := parseSlackToken(secret)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		s.baseURL+"/scim/v1/Users?count=1000", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: list users failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("slack: list users returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Resources []struct {
			ID          string `json:"id"`
			UserName    string `json:"userName"`
			DisplayName string `json:"displayName"`
			Active      bool   `json:"active"`
			Emails      []struct {
				Value   string `json:"value"`
				Primary bool   `json:"primary"`
			} `json:"emails"`
		} `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("slack: decode users: %w", err)
	}
	users := make([]casb.SaaSUser, 0, len(result.Resources))
	for _, u := range result.Resources {
		email := u.UserName
		for _, e := range u.Emails {
			if e.Primary {
				email = e.Value
				break
			}
		}
		users = append(users, casb.SaaSUser{
			ID:          u.ID,
			Email:       email,
			DisplayName: u.DisplayName,
			Active:      u.Active,
		})
	}
	return users, nil
}

func (s *Slack) ListActivity(ctx context.Context, _ json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	token, err := parseSlackToken(secret)
	if err != nil {
		return nil, err
	}
	endpoint := s.baseURL + "/audit/v1/logs?limit=100"
	if since != "" {
		endpoint += "&oldest=" + since
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", s.userAgent)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("slack: list activity failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("slack: list activity returned %d: %s", resp.StatusCode, body)
	}
	var result struct {
		Entries []struct {
			ID     string `json:"id"`
			Action string `json:"action"`
			Actor  struct {
				User struct {
					Email string `json:"email"`
				} `json:"user"`
			} `json:"actor"`
			Context struct {
				IPAddress string `json:"ip_address"`
			} `json:"context"`
			DateCreate int64 `json:"date_create"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("slack: decode activity: %w", err)
	}
	events := make([]casb.ActivityEvent, 0, len(result.Entries))
	for _, e := range result.Entries {
		events = append(events, casb.ActivityEvent{
			ID:        e.ID,
			Actor:     e.Actor.User.Email,
			Action:    e.Action,
			IP:        e.Context.IPAddress,
			Timestamp: time.Unix(e.DateCreate, 0).UTC(),
		})
	}
	return events, nil
}

func (s *Slack) AssessPosture(_ context.Context, _ json.RawMessage, _ []byte) (casb.PostureReport, error) {
	now := time.Now().UTC()
	var checks []casb.PostureCheck

	checks = append(checks, casb.PostureCheck{
		Name:     "sso_enforcement",
		Status:   casb.CheckStatusWarn,
		Evidence: "SSO enforcement status requires Slack admin settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "two_factor_auth",
		Status:   casb.CheckStatusWarn,
		Evidence: "2FA enforcement status requires workspace settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "external_sharing",
		Status:   casb.CheckStatusWarn,
		Evidence: "external sharing policy requires workspace settings inspection",
	})
	checks = append(checks, casb.PostureCheck{
		Name:     "app_install_permissions",
		Status:   casb.CheckStatusWarn,
		Evidence: "app installation permissions require workspace admin settings inspection",
	})

	score := computePostureScore(checks)
	return casb.PostureReport{
		Checks:     checks,
		RiskScore:  score,
		AssessedAt: now,
	}, nil
}

// slackPageLimit bounds Slack Web API page sizes for the
// conversations.* listings the content scan walks.
const slackPageLimit = 200

// ScanContent implements casb.ContentInspector for Slack: it walks
// every channel the token can see and streams each message's text as a
// ContentObject for DLP classification. Slack message *text* is the
// natural inspection target — it is already present in the
// conversations.history payload, so no second per-object fetch (and no
// url_private SSRF surface) is involved. Channels and history are both
// cursor-paged so no workspace is buffered whole, and the per-object
// byte cap trims any pathologically large message.
func (s *Slack) ScanContent(
	ctx context.Context,
	_ json.RawMessage,
	secret []byte,
	opts casb.ContentScanOptions,
	yield func(context.Context, casb.ContentObject) error,
) error {
	token, err := parseSlackToken(secret)
	if err != nil {
		return err
	}
	channels, err := s.listChannels(ctx, token)
	if err != nil {
		return err
	}
	for _, ch := range channels {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.scanChannelHistory(ctx, token, ch.ID, ch.Name, opts, yield); err != nil {
			return err
		}
	}
	return nil
}

type slackChannel struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (s *Slack) listChannels(ctx context.Context, token string) ([]slackChannel, error) {
	var channels []slackChannel
	cursor := ""
	for {
		endpoint := fmt.Sprintf(
			"%s/api/conversations.list?types=public_channel,private_channel&limit=%d",
			s.webBaseURL, slackPageLimit)
		if cursor != "" {
			endpoint += "&cursor=" + url.QueryEscape(cursor)
		}
		var out struct {
			OK               bool           `json:"ok"`
			Error            string         `json:"error"`
			Channels         []slackChannel `json:"channels"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := getJSON(ctx, s.client, s.userAgent, "slack", endpoint, token, &out); err != nil {
			return nil, err
		}
		if !out.OK {
			return nil, fmt.Errorf("slack: conversations.list: %s", out.Error)
		}
		channels = append(channels, out.Channels...)
		if out.ResponseMetadata.NextCursor == "" {
			break
		}
		cursor = out.ResponseMetadata.NextCursor
	}
	return channels, nil
}

func (s *Slack) scanChannelHistory(
	ctx context.Context,
	token, channelID, channelName string,
	opts casb.ContentScanOptions,
	yield func(context.Context, casb.ContentObject) error,
) error {
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		endpoint := fmt.Sprintf("%s/api/conversations.history?channel=%s&limit=%d",
			s.webBaseURL, url.QueryEscape(channelID), slackPageLimit)
		if !opts.Since.IsZero() {
			endpoint += fmt.Sprintf("&oldest=%d", opts.Since.Unix())
		}
		if cursor != "" {
			endpoint += "&cursor=" + url.QueryEscape(cursor)
		}
		var out struct {
			OK       bool   `json:"ok"`
			Error    string `json:"error"`
			Messages []struct {
				Type    string `json:"type"`
				Subtype string `json:"subtype"`
				TS      string `json:"ts"`
				User    string `json:"user"`
				Text    string `json:"text"`
			} `json:"messages"`
			HasMore          bool `json:"has_more"`
			ResponseMetadata struct {
				NextCursor string `json:"next_cursor"`
			} `json:"response_metadata"`
		}
		if err := getJSON(ctx, s.client, s.userAgent, "slack", endpoint, token, &out); err != nil {
			return err
		}
		if !out.OK {
			// Channel-level error (commonly not_in_channel when the
			// token's app was never invited, or channel_not_found).
			// Skip this channel rather than aborting the whole
			// workspace scan; record it as a per-object fetch failure.
			return yield(ctx, casb.ContentObject{
				ID:       "channel:" + channelID,
				Name:     "#" + channelName,
				FetchErr: fmt.Errorf("conversations.history: %s", out.Error),
			})
		}
		for _, msg := range out.Messages {
			if msg.Text == "" {
				continue
			}
			content := []byte(msg.Text)
			if limit := opts.MaxBytesPerObject; limit > 0 && int64(len(content)) > limit {
				content = content[:limit]
			}
			obj := casb.ContentObject{
				ID:          channelID + ":" + msg.TS,
				Name:        fmt.Sprintf("#%s @%s", channelName, msg.TS),
				Owner:       msg.User,
				ContentType: "text/plain",
				SizeBytes:   int64(len(msg.Text)),
				ModifiedAt:  slackTSToTime(msg.TS),
				Content:     content,
			}
			if err := yield(ctx, obj); err != nil {
				return err
			}
		}
		// Stop when Slack signals no further pages OR omits the cursor.
		// Checking both guards against an infinite loop if a future API
		// response ever returned has_more=true with an empty cursor.
		if !out.HasMore || out.ResponseMetadata.NextCursor == "" {
			break
		}
		cursor = out.ResponseMetadata.NextCursor
	}
	return nil
}

// slackTSToTime converts a Slack message timestamp ("1234567890.000200")
// to a time.Time. A malformed ts yields the zero time.
func slackTSToTime(ts string) time.Time {
	sec := ts
	if i := strings.IndexByte(ts, '.'); i >= 0 {
		sec = ts[:i]
	}
	n, err := strconv.ParseInt(sec, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(n, 0).UTC()
}

func parseSlackToken(secret []byte) (string, error) {
	var sec SlackSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return "", fmt.Errorf("slack: invalid secret: %w", err)
	}
	if sec.Token == "" {
		return "", fmt.Errorf("slack: token is required")
	}
	return sec.Token, nil
}

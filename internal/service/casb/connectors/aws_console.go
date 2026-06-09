package connectors

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// AWSConsoleConfig holds the non-sensitive connector configuration.
// Region is used for the regional CloudTrail endpoint; IAM is global
// and always signed against us-east-1.
type AWSConsoleConfig struct {
	Region string `json:"region"`
}

// AWSConsoleSecret holds the IAM access key used to sign requests.
// SessionToken is optional (set for STS/temporary credentials).
type AWSConsoleSecret struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token,omitempty"`
}

// AWSConsole implements CASBConnectorPlugin for an AWS account:
// principals from IAM (Query/XML protocol) and console/API activity
// from CloudTrail (JSON 1.1 protocol). Requests are signed with AWS
// Signature Version 4.
type AWSConsole struct {
	client     HTTPDoer
	userAgent  string
	signer     *v4.Signer
	iamBase    string
	trailBase  string // host template; %s is replaced with the region
	now        func() time.Time
	signingNow func() time.Time
}

// NewAWSConsole constructs an AWS Console CASB connector.
func NewAWSConsole(client HTTPDoer, userAgent string) *AWSConsole {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/aws_console)"
	}
	return &AWSConsole{
		client:     client,
		userAgent:  userAgent,
		signer:     v4.NewSigner(),
		iamBase:    "https://iam.amazonaws.com",
		trailBase:  "https://cloudtrail.%s.amazonaws.com",
		now:        time.Now,
		signingNow: time.Now,
	}
}

func (a *AWSConsole) Type() repository.CASBConnectorType { return repository.CASBConnectorAWSConsole }

func (a *AWSConsole) creds(config json.RawMessage, secret []byte) (region string, c aws.Credentials, err error) {
	var cfg AWSConsoleConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", aws.Credentials{}, fmt.Errorf("aws_console: invalid config: %w", err)
	}
	var sec AWSConsoleSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", aws.Credentials{}, fmt.Errorf("aws_console: invalid secret: %w", err)
	}
	if sec.AccessKeyID == "" || sec.SecretAccessKey == "" {
		return "", aws.Credentials{}, fmt.Errorf("aws_console: access_key_id and secret_access_key are required")
	}
	region = cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	return region, aws.Credentials{
		AccessKeyID:     sec.AccessKeyID,
		SecretAccessKey: sec.SecretAccessKey,
		SessionToken:    sec.SessionToken,
	}, nil
}

// signAndDo signs req with SigV4 for the given service/region and
// executes it, returning the response body bytes on a 2xx.
func (a *AWSConsole) signAndDo(ctx context.Context, c aws.Credentials, req *http.Request, body []byte, service, region string) ([]byte, error) {
	sum := sha256.Sum256(body)
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", a.userAgent)
	}
	if err := a.signer.SignHTTP(ctx, c, req, hex.EncodeToString(sum[:]), service, region, a.signingNow().UTC()); err != nil {
		return nil, fmt.Errorf("aws_console: sign %s request: %w", service, err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("aws_console: %s request failed: %w", service, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		snippet := respBody
		if len(snippet) > maxErrorBody {
			snippet = snippet[:maxErrorBody]
		}
		return nil, fmt.Errorf("aws_console: %s returned %d: %s", service, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return respBody, nil
}

// iamQuery performs a signed IAM Query-protocol GET and unmarshals
// the XML response into out.
func (a *AWSConsole) iamQuery(ctx context.Context, c aws.Credentials, action string, params url.Values, out any) error {
	if params == nil {
		params = url.Values{}
	}
	params.Set("Action", action)
	params.Set("Version", "2010-05-08")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.iamBase+"/?"+params.Encode(), nil)
	if err != nil {
		return fmt.Errorf("aws_console: %w", err)
	}
	// IAM is a global service signed against us-east-1.
	body, err := a.signAndDo(ctx, c, req, nil, "iam", "us-east-1")
	if err != nil {
		return err
	}
	if out != nil {
		if err := xml.Unmarshal(body, out); err != nil {
			return fmt.Errorf("aws_console: decode iam %s response: %w", action, err)
		}
	}
	return nil
}

func (a *AWSConsole) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return a.Test(ctx, config, secret)
}

func (a *AWSConsole) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, c, err := a.creds(config, secret)
	if err != nil {
		return err
	}
	// GetAccountSummary is a cheap, always-available IAM call that
	// proves the credentials sign and authorize correctly.
	if err := a.iamQuery(ctx, c, "GetAccountSummary", nil, nil); err != nil {
		return fmt.Errorf("aws_console: test failed: %w", err)
	}
	return nil
}

func (a *AWSConsole) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	_, c, err := a.creds(config, secret)
	if err != nil {
		return nil, err
	}
	var resp struct {
		XMLName xml.Name `xml:"ListUsersResponse"`
		Result  struct {
			Users []struct {
				UserName string `xml:"UserName"`
				UserID   string `xml:"UserId"`
				Arn      string `xml:"Arn"`
			} `xml:"Users>member"`
		} `xml:"ListUsersResult"`
	}
	if err := a.iamQuery(ctx, c, "ListUsers", url.Values{"MaxItems": {"1000"}}, &resp); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(resp.Result.Users))
	for _, u := range resp.Result.Users {
		users = append(users, casb.SaaSUser{
			ID:          u.UserID,
			DisplayName: u.UserName,
			Active:      true,
			// AWS admin attribution requires per-principal policy
			// evaluation (ListAttachedUserPolicies / policy
			// simulation), which is intentionally not performed here
			// to keep ListUsers a single, cheap call. Privilege is
			// surfaced via AssessPosture instead.
		})
	}
	return users, nil
}

func (a *AWSConsole) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	region, c, err := a.creds(config, secret)
	if err != nil {
		return nil, err
	}
	payload := map[string]any{"MaxResults": 50}
	if since != "" {
		if ts, perr := time.Parse(time.RFC3339, since); perr == nil {
			payload["StartTime"] = ts.Unix()
		}
	}
	body, _ := json.Marshal(payload)
	endpoint := fmt.Sprintf(a.trailBase, region) + "/"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("aws_console: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "CloudTrail_20131101.LookupEvents")
	respBody, err := a.signAndDo(ctx, c, req, body, "cloudtrail", region)
	if err != nil {
		return nil, err
	}
	var out struct {
		Events []struct {
			EventID   string  `json:"EventId"`
			EventName string  `json:"EventName"`
			Username  string  `json:"Username"`
			EventTime float64 `json:"EventTime"`
			Resources []struct {
				ResourceName string `json:"ResourceName"`
			} `json:"Resources"`
		} `json:"Events"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("aws_console: decode cloudtrail response: %w", err)
	}
	events := make([]casb.ActivityEvent, 0, len(out.Events))
	for _, e := range out.Events {
		var target string
		if len(e.Resources) > 0 {
			target = e.Resources[0].ResourceName
		}
		events = append(events, casb.ActivityEvent{
			ID:        e.EventID,
			Actor:     e.Username,
			Action:    e.EventName,
			Target:    target,
			Timestamp: time.Unix(int64(e.EventTime), 0).UTC(),
		})
	}
	return events, nil
}

func (a *AWSConsole) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	_, c, err := a.creds(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	checks := make([]casb.PostureCheck, 0, 4)

	// Account summary carries the root-account risk signals.
	var summary struct {
		Entries []struct {
			Key   string `xml:"key"`
			Value int    `xml:"value"`
		} `xml:"GetAccountSummaryResult>SummaryMap>entry"`
	}
	if err := a.iamQuery(ctx, c, "GetAccountSummary", nil, &summary); err != nil {
		return casb.PostureReport{}, err
	}
	sm := map[string]int{}
	for _, e := range summary.Entries {
		sm[e.Key] = e.Value
	}
	checks = append(checks,
		boolCheck("root_mfa_enabled", "authentication", sm["AccountMFAEnabled"] == 1,
			"root account has MFA enabled",
			"root account does not have MFA enabled"),
		boolCheck("no_root_access_keys", "access_control", sm["AccountAccessKeysPresent"] == 0,
			"root account has no access keys",
			"root account has active access keys (high-risk long-lived credential)"),
	)

	// Password policy strength.
	var pp struct {
		MinLen         int  `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>MinimumPasswordLength"`
		RequireSymbols bool `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>RequireSymbols"`
		RequireNumbers bool `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>RequireNumbers"`
		RequireUpper   bool `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>RequireUppercaseCharacters"`
		RequireLower   bool `xml:"GetAccountPasswordPolicyResult>PasswordPolicy>RequireLowercaseCharacters"`
	}
	if err := a.iamQuery(ctx, c, "GetAccountPasswordPolicy", nil, &pp); err == nil {
		strong := pp.MinLen >= 14 && pp.RequireSymbols && pp.RequireNumbers && pp.RequireUpper && pp.RequireLower
		checks = append(checks, boolCheck("strong_password_policy", "authentication", strong,
			"account password policy meets CIS strength requirements (>=14 chars, mixed classes)",
			"account password policy is weaker than CIS recommendations (len="+strconv.Itoa(pp.MinLen)+")"))
	} else {
		// A missing policy is itself a finding (no policy at all).
		checks = append(checks, casb.PostureCheck{Name: "strong_password_policy", Category: "authentication",
			Status: casb.CheckStatusFail, Evidence: "no account password policy is configured"})
	}

	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: a.now().UTC()}, nil
}

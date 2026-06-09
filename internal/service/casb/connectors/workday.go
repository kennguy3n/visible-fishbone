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

// WorkdayConfig holds the non-sensitive connector configuration.
// BaseURL is the Workday API host (https://wd2-impl-services1.workday.com)
// and Tenant is the Workday tenant id embedded in every API path.
type WorkdayConfig struct {
	BaseURL string `json:"base_url"`
	Tenant  string `json:"tenant"`
}

// WorkdaySecret holds the OAuth2 client + refresh token for a Workday
// Integration System User (ISU) registered as an API client.
type WorkdaySecret struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

// Workday implements CASBConnectorPlugin for a Workday tenant:
// workers from the Staffing REST API and admin activity from the
// Workday User Activity Logging API (the SIEM/CASB feed).
type Workday struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string // test seam; empty in production (base_url is tenant-supplied)
	now         func() time.Time
}

// NewWorkday constructs a Workday CASB connector.
func NewWorkday(client HTTPDoer, userAgent string) *Workday {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/workday)"
	}
	return &Workday{client: client, userAgent: userAgent, now: time.Now}
}

func (w *Workday) Type() repository.CASBConnectorType { return repository.CASBConnectorWorkday }

func (w *Workday) resolve(config json.RawMessage, secret []byte) (cfg WorkdayConfig, base string, sec WorkdaySecret, err error) {
	if err = json.Unmarshal(config, &cfg); err != nil {
		return cfg, "", sec, fmt.Errorf("workday: invalid config: %w", err)
	}
	if err = json.Unmarshal(secret, &sec); err != nil {
		return cfg, "", sec, fmt.Errorf("workday: invalid secret: %w", err)
	}
	if strings.TrimSpace(cfg.Tenant) == "" {
		return cfg, "", sec, fmt.Errorf("workday: tenant is required")
	}
	if sec.ClientID == "" || sec.ClientSecret == "" || sec.RefreshToken == "" {
		return cfg, "", sec, fmt.Errorf("workday: client_id, client_secret, and refresh_token are required")
	}
	if base, err = resolveTenantBase("workday", cfg.BaseURL, w.defaultBase); err != nil {
		return cfg, "", sec, err
	}
	return cfg, base, sec, nil
}

func (w *Workday) token(ctx context.Context, base, tenant string, sec WorkdaySecret) (string, error) {
	tokenURL := fmt.Sprintf("%s/ccx/oauth2/%s/token", base, url.PathEscape(tenant))
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {sec.RefreshToken},
	}
	return clientCredentialsToken(ctx, w.client, w.userAgent, "workday", tokenURL, form, sec.ClientID, sec.ClientSecret)
}

func (w *Workday) auth(ctx context.Context, config json.RawMessage, secret []byte) (cfg WorkdayConfig, base, token string, err error) {
	cfg, base, sec, err := w.resolve(config, secret)
	if err != nil {
		return cfg, "", "", err
	}
	token, err = w.token(ctx, base, cfg.Tenant, sec)
	if err != nil {
		return cfg, "", "", err
	}
	return cfg, base, token, nil
}

func (w *Workday) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	_, _, _, err := w.auth(ctx, config, secret)
	return err
}

func (w *Workday) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	cfg, base, token, err := w.auth(ctx, config, secret)
	if err != nil {
		return err
	}
	var out struct {
		Total int `json:"total"`
	}
	endpoint := fmt.Sprintf("%s/ccx/api/v1/%s/workers?limit=1", base, url.PathEscape(cfg.Tenant))
	if err := getJSON(ctx, w.client, w.userAgent, "workday", endpoint, token, &out); err != nil {
		return fmt.Errorf("workday: test failed: %w", err)
	}
	return nil
}

type workdayWorker struct {
	ID         string `json:"id"`
	Descriptor string `json:"descriptor"`
	Primary    struct {
		Email string `json:"primaryWorkEmail"`
	} `json:"primaryWorkContactInformation"`
	IsActive bool `json:"isActive"`
}

func (w *Workday) fetchWorkers(ctx context.Context, base, tenant, token string) ([]workdayWorker, error) {
	endpoint := fmt.Sprintf("%s/ccx/api/v1/%s/workers?limit=100", base, url.PathEscape(tenant))
	var out struct {
		Data []workdayWorker `json:"data"`
	}
	if err := getJSON(ctx, w.client, w.userAgent, "workday", endpoint, token, &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

func (w *Workday) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	cfg, base, token, err := w.auth(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	workers, err := w.fetchWorkers(ctx, base, cfg.Tenant, token)
	if err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(workers))
	for _, wk := range workers {
		users = append(users, casb.SaaSUser{
			ID:          wk.ID,
			Email:       wk.Primary.Email,
			DisplayName: wk.Descriptor,
			Active:      wk.IsActive,
		})
	}
	return users, nil
}

func (w *Workday) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	cfg, base, token, err := w.auth(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	// The Workday User Activity Logging API requires an explicit
	// [from,to] window; default to the last 24h when no cursor is
	// supplied so the feed is always bounded.
	to := w.now().UTC()
	from := to.Add(-24 * time.Hour)
	if since != "" {
		if ts, perr := time.Parse(time.RFC3339, since); perr == nil {
			from = ts.UTC()
		}
	}
	endpoint := fmt.Sprintf("%s/ccx/api/privacy/v1/%s/activityLogging?from=%s&to=%s&instancesReturned=100",
		base, url.PathEscape(cfg.Tenant),
		url.QueryEscape(from.Format(time.RFC3339)),
		url.QueryEscape(to.Format(time.RFC3339)))
	var out struct {
		Data []struct {
			TaskDisplayName string `json:"taskDisplayName"`
			RequestTime     string `json:"requestTime"`
			SystemAccount   string `json:"systemAccount"`
			IPAddress       string `json:"ipAddress"`
			Target          struct {
				Descriptor string `json:"descriptor"`
			} `json:"target"`
		} `json:"data"`
	}
	if err := getJSON(ctx, w.client, w.userAgent, "workday", endpoint, token, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Data))
	for i, e := range out.Data {
		ts, _ := time.Parse(time.RFC3339, e.RequestTime)
		events = append(events, casb.ActivityEvent{
			ID:        fmt.Sprintf("%s-%d", e.RequestTime, i),
			Actor:     e.SystemAccount,
			Action:    e.TaskDisplayName,
			Target:    e.Target.Descriptor,
			IP:        e.IPAddress,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (w *Workday) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	cfg, base, token, err := w.auth(ctx, config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	workers, err := w.fetchWorkers(ctx, base, cfg.Tenant, token)
	if err != nil {
		return casb.PostureReport{}, err
	}
	inactive := 0
	for _, wk := range workers {
		if !wk.IsActive {
			inactive++
		}
	}
	status := casb.CheckStatusPass
	evidence := fmt.Sprintf("workday: %d inactive workers still provisioned of %d", inactive, len(workers))
	if inactive > 0 {
		status = casb.CheckStatusWarn
		evidence += " (verify offboarding revokes downstream access)"
	}
	checks := []casb.PostureCheck{
		{Name: "offboarding_hygiene", Category: "access_control", Status: status, Evidence: evidence},
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: w.now().UTC()}, nil
}

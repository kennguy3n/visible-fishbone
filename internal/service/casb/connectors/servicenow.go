package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// ServiceNowConfig holds the non-sensitive connector configuration.
// BaseURL is the instance root (https://acme.service-now.com).
type ServiceNowConfig struct {
	BaseURL string `json:"base_url"`
}

// ServiceNowSecret holds the integration-user Basic-auth credentials.
type ServiceNowSecret struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ServiceNow implements CASBConnectorPlugin for a ServiceNow instance
// via the Table API.
type ServiceNow struct {
	client      HTTPDoer
	userAgent   string
	defaultBase string // test seam; empty in production (base_url is tenant-supplied)
}

// NewServiceNow constructs a ServiceNow CASB connector.
func NewServiceNow(client HTTPDoer, userAgent string) *ServiceNow {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/servicenow)"
	}
	return &ServiceNow{client: client, userAgent: userAgent}
}

func (s *ServiceNow) Type() repository.CASBConnectorType { return repository.CASBConnectorServiceNow }

func (s *ServiceNow) resolve(config json.RawMessage, secret []byte) (base, user, pass string, err error) {
	var cfg ServiceNowConfig
	if err = json.Unmarshal(config, &cfg); err != nil {
		return "", "", "", fmt.Errorf("servicenow: invalid config: %w", err)
	}
	var sec ServiceNowSecret
	if err = json.Unmarshal(secret, &sec); err != nil {
		return "", "", "", fmt.Errorf("servicenow: invalid secret: %w", err)
	}
	if sec.Username == "" || sec.Password == "" {
		return "", "", "", fmt.Errorf("servicenow: username and password are required")
	}
	if base, err = resolveTenantBase("servicenow", cfg.BaseURL, s.defaultBase); err != nil {
		return "", "", "", err
	}
	return base, sec.Username, sec.Password, nil
}

func (s *ServiceNow) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return s.Test(ctx, config, secret)
}

func (s *ServiceNow) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	base, user, pass, err := s.resolve(config, secret)
	if err != nil {
		return err
	}
	var out struct {
		Result []json.RawMessage `json:"result"`
	}
	if err := getJSONBasic(ctx, s.client, s.userAgent, "servicenow",
		base+"/api/now/table/sys_user?sysparm_limit=1", user, pass, &out); err != nil {
		return fmt.Errorf("servicenow: test failed: %w", err)
	}
	return nil
}

func (s *ServiceNow) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	base, user, pass, err := s.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	endpoint := base + "/api/now/table/sys_user?sysparm_limit=1000" +
		"&sysparm_fields=sys_id,user_name,name,email,active" +
		"&sysparm_query=" + url.QueryEscape("active=true")
	var out struct {
		Result []struct {
			SysID    string `json:"sys_id"`
			UserName string `json:"user_name"`
			Name     string `json:"name"`
			Email    string `json:"email"`
			Active   string `json:"active"`
		} `json:"result"`
	}
	if err := getJSONBasic(ctx, s.client, s.userAgent, "servicenow", endpoint, user, pass, &out); err != nil {
		return nil, err
	}
	users := make([]casb.SaaSUser, 0, len(out.Result))
	for _, u := range out.Result {
		name := u.Name
		if name == "" {
			name = u.UserName
		}
		users = append(users, casb.SaaSUser{
			ID:          u.SysID,
			Email:       u.Email,
			DisplayName: name,
			Active:      u.Active == "true",
		})
	}
	return users, nil
}

func (s *ServiceNow) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	base, user, pass, err := s.resolve(config, secret)
	if err != nil {
		return nil, err
	}
	query := "ORDERBYDESCsys_created_on"
	if since != "" {
		query = "sys_created_on>=" + since + "^" + query
	}
	endpoint := base + "/api/now/table/sys_audit?sysparm_limit=100" +
		"&sysparm_fields=sys_id,user,fieldname,tablename,sys_created_on,newvalue" +
		"&sysparm_query=" + url.QueryEscape(query)
	var out struct {
		Result []struct {
			SysID     string `json:"sys_id"`
			User      string `json:"user"`
			FieldName string `json:"fieldname"`
			TableName string `json:"tablename"`
			Created   string `json:"sys_created_on"`
		} `json:"result"`
	}
	if err := getJSONBasic(ctx, s.client, s.userAgent, "servicenow", endpoint, user, pass, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Result))
	for _, r := range out.Result {
		// ServiceNow timestamps are UTC "2006-01-02 15:04:05".
		ts, _ := time.Parse("2006-01-02 15:04:05", r.Created)
		action := r.FieldName
		if action == "" {
			action = "record_change"
		}
		events = append(events, casb.ActivityEvent{
			ID:        r.SysID,
			Actor:     r.User,
			Action:    action,
			Target:    r.TableName,
			Timestamp: ts.UTC(),
		})
	}
	return events, nil
}

func (s *ServiceNow) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	base, user, pass, err := s.resolve(config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	// admin role grants (sys_user_has_role for role "admin") are the
	// over-privilege signal; ServiceNow's "admin" is a superuser.
	endpoint := base + "/api/now/table/sys_user_has_role?sysparm_limit=1000" +
		"&sysparm_fields=user,role.name&sysparm_exclude_reference_link=true" +
		"&sysparm_query=" + url.QueryEscape("role.name=admin")
	var out struct {
		Result []struct {
			User string `json:"user"`
			Role string `json:"role.name"`
		} `json:"result"`
	}
	if err := getJSONBasic(ctx, s.client, s.userAgent, "servicenow", endpoint, user, pass, &out); err != nil {
		return casb.PostureReport{}, err
	}
	admins := len(out.Result)
	checks := []casb.PostureCheck{
		{Name: "admin_role_grants", Category: "access_control", Status: ownerStatus(admins),
			Evidence: fmt.Sprintf("servicenow: %d users hold the superuser 'admin' role", admins)},
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: time.Now().UTC()}, nil
}

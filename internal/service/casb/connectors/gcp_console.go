package connectors

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// gcpScope is the read-only scope used to inventory IAM and read
// Cloud Audit Logs.
const gcpScope = "https://www.googleapis.com/auth/cloud-platform.read-only"

// GCPConsoleConfig holds the non-sensitive connector configuration.
// ProjectID is the project whose IAM policy and audit logs are read.
type GCPConsoleConfig struct {
	ProjectID string `json:"project_id"`
}

// GCPConsoleSecret holds the service-account key JSON used to mint a
// signed assertion.
type GCPConsoleSecret struct {
	ServiceAccountKey json.RawMessage `json:"service_account_key"`
}

// GCPConsole implements CASBConnectorPlugin for the GCP control
// plane: IAM membership from Cloud Resource Manager and admin
// activity from Cloud Audit Logs (Cloud Logging).
type GCPConsole struct {
	client      HTTPDoer
	userAgent   string
	crmBase     string
	loggingBase string
	tokenURL    string
	now         func() time.Time
}

// NewGCPConsole constructs a GCP Console CASB connector.
func NewGCPConsole(client HTTPDoer, userAgent string) *GCPConsole {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if userAgent == "" {
		userAgent = "sng-control/0.1 (+casb/gcp_console)"
	}
	return &GCPConsole{
		client:      client,
		userAgent:   userAgent,
		crmBase:     "https://cloudresourcemanager.googleapis.com",
		loggingBase: "https://logging.googleapis.com",
		tokenURL:    "https://oauth2.googleapis.com/token",
		now:         time.Now,
	}
}

func (g *GCPConsole) Type() repository.CASBConnectorType { return repository.CASBConnectorGCPConsole }

func (g *GCPConsole) token(ctx context.Context, config json.RawMessage, secret []byte) (GCPConsoleConfig, string, error) {
	var cfg GCPConsoleConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return GCPConsoleConfig{}, "", fmt.Errorf("gcp_console: invalid config: %w", err)
	}
	var sec GCPConsoleSecret
	if err := json.Unmarshal(secret, &sec); err != nil {
		return GCPConsoleConfig{}, "", fmt.Errorf("gcp_console: invalid secret: %w", err)
	}
	if strings.TrimSpace(cfg.ProjectID) == "" {
		return GCPConsoleConfig{}, "", fmt.Errorf("gcp_console: project_id is required")
	}
	tok, err := googleSAToken(ctx, g.client, g.userAgent, "gcp_console",
		sec.ServiceAccountKey, gcpScope, "", g.now().UTC(), g.tokenURL)
	if err != nil {
		return GCPConsoleConfig{}, "", err
	}
	return cfg, tok, nil
}

// getIamPolicy returns the project IAM bindings.
func (g *GCPConsole) getIamPolicy(ctx context.Context, projectID, token string) ([]iamBinding, error) {
	endpoint := fmt.Sprintf("%s/v1/projects/%s:getIamPolicy", g.crmBase, projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("gcp_console: %w", err)
	}
	bearer(req, token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	var out struct {
		Bindings []iamBinding `json:"bindings"`
	}
	if err := doJSON(g.client, g.userAgent, "gcp_console", req, &out); err != nil {
		return nil, err
	}
	return out.Bindings, nil
}

type iamBinding struct {
	Role    string   `json:"role"`
	Members []string `json:"members"`
}

func (g *GCPConsole) Connect(ctx context.Context, config json.RawMessage, secret []byte) error {
	return g.Test(ctx, config, secret)
}

func (g *GCPConsole) Test(ctx context.Context, config json.RawMessage, secret []byte) error {
	cfg, token, err := g.token(ctx, config, secret)
	if err != nil {
		return err
	}
	if _, err := g.getIamPolicy(ctx, cfg.ProjectID, token); err != nil {
		return fmt.Errorf("gcp_console: test failed: %w", err)
	}
	return nil
}

// privilegedRole reports whether a role grants broad project control.
func privilegedRole(role string) bool {
	switch role {
	case "roles/owner", "roles/editor", "roles/resourcemanager.projectIamAdmin",
		"roles/iam.securityAdmin", "roles/iam.organizationRoleAdmin":
		return true
	}
	return false
}

func (g *GCPConsole) ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]casb.SaaSUser, error) {
	cfg, token, err := g.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	bindings, err := g.getIamPolicy(ctx, cfg.ProjectID, token)
	if err != nil {
		return nil, err
	}
	// Aggregate per human user (member prefix "user:"); a user is
	// admin if any of their bindings is a privileged role.
	admin := map[string]bool{}
	seen := map[string]bool{}
	order := make([]string, 0)
	for _, b := range bindings {
		for _, m := range b.Members {
			email, ok := strings.CutPrefix(m, "user:")
			if !ok {
				continue
			}
			if !seen[email] {
				seen[email] = true
				order = append(order, email)
			}
			if privilegedRole(b.Role) {
				admin[email] = true
			}
		}
	}
	users := make([]casb.SaaSUser, 0, len(order))
	for _, email := range order {
		users = append(users, casb.SaaSUser{
			ID:          email,
			Email:       email,
			DisplayName: email,
			Active:      true,
			Admin:       admin[email],
		})
	}
	return users, nil
}

func (g *GCPConsole) ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]casb.ActivityEvent, error) {
	cfg, token, err := g.token(ctx, config, secret)
	if err != nil {
		return nil, err
	}
	filter := fmt.Sprintf(`logName="projects/%s/logs/cloudaudit.googleapis.com%%2Factivity"`, cfg.ProjectID)
	if since != "" {
		filter += fmt.Sprintf(` AND timestamp>=%q`, since)
	}
	body, _ := json.Marshal(map[string]any{
		"resourceNames": []string{"projects/" + cfg.ProjectID},
		"filter":        filter,
		"orderBy":       "timestamp desc",
		"pageSize":      100,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		g.loggingBase+"/v2/entries:list", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("gcp_console: %w", err)
	}
	bearer(req, token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	var out struct {
		Entries []struct {
			InsertID     string `json:"insertId"`
			Timestamp    string `json:"timestamp"`
			ProtoPayload struct {
				MethodName         string `json:"methodName"`
				ResourceName       string `json:"resourceName"`
				AuthenticationInfo struct {
					PrincipalEmail string `json:"principalEmail"`
				} `json:"authenticationInfo"`
				RequestMetadata struct {
					CallerIP string `json:"callerIp"`
				} `json:"requestMetadata"`
			} `json:"protoPayload"`
		} `json:"entries"`
	}
	if err := doJSON(g.client, g.userAgent, "gcp_console", req, &out); err != nil {
		return nil, err
	}
	events := make([]casb.ActivityEvent, 0, len(out.Entries))
	for _, e := range out.Entries {
		ts, _ := time.Parse(time.RFC3339, e.Timestamp)
		events = append(events, casb.ActivityEvent{
			ID:        e.InsertID,
			Actor:     e.ProtoPayload.AuthenticationInfo.PrincipalEmail,
			Action:    e.ProtoPayload.MethodName,
			Target:    e.ProtoPayload.ResourceName,
			IP:        e.ProtoPayload.RequestMetadata.CallerIP,
			Timestamp: ts,
		})
	}
	return events, nil
}

func (g *GCPConsole) AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (casb.PostureReport, error) {
	cfg, token, err := g.token(ctx, config, secret)
	if err != nil {
		return casb.PostureReport{}, err
	}
	bindings, err := g.getIamPolicy(ctx, cfg.ProjectID, token)
	if err != nil {
		return casb.PostureReport{}, err
	}
	owners := 0
	publicBinding := false
	for _, b := range bindings {
		for _, m := range b.Members {
			if m == "allUsers" || m == "allAuthenticatedUsers" {
				publicBinding = true
			}
		}
		if b.Role == "roles/owner" {
			for _, m := range b.Members {
				if strings.HasPrefix(m, "user:") {
					owners++
				}
			}
		}
	}
	checks := []casb.PostureCheck{
		boolCheck("no_public_iam_bindings", "data_protection", !publicBinding,
			"no allUsers/allAuthenticatedUsers IAM bindings on the project",
			"project IAM grants a role to allUsers/allAuthenticatedUsers (public exposure)"),
		{Name: "project_owner_count", Category: "access_control", Status: ownerStatus(owners),
			Evidence: fmt.Sprintf("%d user-principal Owner bindings on the project", owners)},
	}
	return casb.PostureReport{Checks: checks, RiskScore: computePostureScore(checks), AssessedAt: g.now().UTC()}, nil
}

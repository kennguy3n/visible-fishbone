// Package connectors provides CASB connector plugin implementations
// for the supported SaaS and cloud-console applications (Microsoft
// 365, Google Workspace, Slack, Salesforce, Box, Dropbox, GitHub,
// GitLab, Jira, Confluence, ServiceNow, Zendesk, HubSpot, Zoom,
// Teams, AWS Console, GCP Console, Azure Portal, Okta, and Workday).
//
// Each connector implements the casb.CASBConnectorPlugin interface
// and lives in an eponymous file (m365.go, github.go, ...). The
// shared HTTP/auth plumbing (request execution, error shaping,
// tenant base-URL SSRF validation, OAuth/JWT token minting, and the
// common posture-check builders) lives in helpers.go; the
// posture-scoring helper and the HTTPDoer test seam live here.
package connectors

import (
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// HTTPDoer is the seam tests use to inject a mock HTTP client.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// computePostureScore calculates a risk score from posture checks.
// Higher values mean higher risk: fail=100, warn=50, pass=0.
func computePostureScore(checks []casb.PostureCheck) int {
	if len(checks) == 0 {
		return 0
	}
	healthTotal := 0
	for _, c := range checks {
		switch c.Status {
		case casb.CheckStatusPass:
			healthTotal += 100
		case casb.CheckStatusWarn:
			healthTotal += 50
		}
	}
	return 100 - healthTotal/len(checks)
}

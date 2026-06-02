// Package connectors provides CASB connector plugin implementations
// for Microsoft 365, Google Workspace, Slack, and Salesforce.
//
// Each connector implements the casb.CASBConnectorPlugin interface.
// Shared HTTP plumbing is in this file; per-connector logic lives
// in the eponymous files (m365.go, google.go, slack.go,
// salesforce.go).
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

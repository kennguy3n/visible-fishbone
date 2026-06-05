// Package rbi implements Remote Browser Isolation session management
// (Gap #8). When the SWG data plane determines that a URL should be
// rendered in an isolated container rather than the endpoint's local
// browser, the control plane creates an RBI session here and the
// RBI proxy streams the rendering. The policy engine decides which
// URLs trigger isolation based on URL category, risk score, and
// whether the URL is uncategorised.
package rbi

import (
	"strings"
)

// TriggerReason explains why a URL was routed to RBI, recorded on
// the session for audit/reporting.
type TriggerReason string

const (
	TriggerCategoryMatch  TriggerReason = "category_match"
	TriggerRiskScore      TriggerReason = "risk_score"
	TriggerUncategorised  TriggerReason = "uncategorised"
	TriggerExplicitPolicy TriggerReason = "explicit_policy"
)

// PolicyConfig captures the operator-configurable trigger rules for
// RBI. A URL triggers isolation when any enabled condition matches.
type PolicyConfig struct {
	// Categories lists the URL categories that trigger RBI (e.g.
	// "gambling", "phishing", "uncategorised"). An empty list
	// disables category-based triggering.
	Categories []string
	// RiskScoreThreshold, when >0, triggers RBI for URLs whose risk
	// score (as evaluated by the SWG categoriser) meets or exceeds
	// this value. Range [0,100]; 0 disables risk-score triggering.
	RiskScoreThreshold int
	// IsolateUncategorised, when true, triggers RBI for any URL the
	// categoriser cannot classify. This is a conservative posture
	// for high-security tenants.
	IsolateUncategorised bool
}

// Evaluate checks whether a URL matches the RBI trigger policy and
// returns the trigger reason if so. A zero-value PolicyConfig
// matches nothing (RBI is effectively disabled).
func (pc PolicyConfig) Evaluate(category string, riskScore int) (bool, TriggerReason) {
	if pc.IsolateUncategorised && isUncategorised(category) {
		return true, TriggerUncategorised
	}
	if pc.RiskScoreThreshold > 0 && riskScore >= pc.RiskScoreThreshold {
		return true, TriggerRiskScore
	}
	if len(pc.Categories) > 0 {
		cat := strings.ToLower(strings.TrimSpace(category))
		for _, c := range pc.Categories {
			if strings.ToLower(strings.TrimSpace(c)) == cat {
				return true, TriggerCategoryMatch
			}
		}
	}
	return false, ""
}

func isUncategorised(cat string) bool {
	c := strings.ToLower(strings.TrimSpace(cat))
	return c == "" || c == "uncategorised" || c == "uncategorized" || c == "unknown"
}

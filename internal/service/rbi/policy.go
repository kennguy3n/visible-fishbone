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
// RBI. A URL triggers isolation when the highest-precedence enabled
// condition matches (see [PolicyConfig.EvaluateRequest] for the
// precedence ordering).
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
	// ExplicitIsolate lists host patterns that ALWAYS route to RBI,
	// regardless of category or risk score. A pattern matches the
	// destination host exactly or as a parent domain (so
	// "example.com" matches "app.example.com"). This is the
	// highest-precedence rule: an operator can force isolation for a
	// known-risky destination even when the categoriser would clear
	// it.
	ExplicitIsolate []string
	// ExplicitBypass lists host patterns that are NEVER isolated even
	// when a category/risk/uncategorised rule would otherwise match —
	// the allow-list for trusted destinations (e.g. an internal SaaS
	// app that must run in the local browser). Matching follows the
	// same exact-or-parent-domain rule as ExplicitIsolate.
	//
	// Precedence is deny-wins: a host present in BOTH lists is
	// isolated, so an explicit bypass can never re-open a destination
	// the operator has explicitly pinned to isolation.
	ExplicitBypass []string
}

// Request is the input to RBI policy evaluation: the destination host
// (when known) plus the SWG categoriser's verdict for the URL.
type Request struct {
	// Host is the destination hostname (no scheme/port/path). Empty
	// when the data plane could not extract it; the explicit
	// allow/deny lists then never match and evaluation falls through
	// to the category/risk rules.
	Host string
	// Category is the URL category the SWG categoriser assigned.
	Category string
	// RiskScore is the categoriser's risk score in [0,100].
	RiskScore int
}

// Evaluate checks whether a URL matches the RBI trigger policy and
// returns the trigger reason if so. A zero-value PolicyConfig
// matches nothing (RBI is effectively disabled).
//
// This is the host-agnostic entry point retained for callers that
// only have the categoriser verdict; it cannot match the explicit
// host allow/deny lists. Prefer [PolicyConfig.EvaluateRequest] when
// the destination host is available.
func (pc PolicyConfig) Evaluate(category string, riskScore int) (bool, TriggerReason) {
	return pc.EvaluateRequest(Request{Category: category, RiskScore: riskScore})
}

// EvaluateRequest applies the full policy with precedence:
//
//  1. ExplicitIsolate — an explicitly pinned host is always isolated
//     (TriggerExplicitPolicy), regardless of category/risk. Deny-wins.
//  2. ExplicitBypass — an explicitly trusted host is never isolated,
//     short-circuiting the category/risk/uncategorised rules below.
//  3. IsolateUncategorised — isolate any URL the categoriser could
//     not classify.
//  4. RiskScoreThreshold — isolate when the risk score meets/exceeds
//     the threshold.
//  5. Categories — isolate when the category is on the trigger list.
//
// The ordering is deliberate: the explicit operator lists override
// the heuristic category/risk rules, and within the heuristics the
// fail-conservative uncategorised check runs first.
func (pc PolicyConfig) EvaluateRequest(req Request) (bool, TriggerReason) {
	if hostMatches(pc.ExplicitIsolate, req.Host) {
		return true, TriggerExplicitPolicy
	}
	if hostMatches(pc.ExplicitBypass, req.Host) {
		return false, ""
	}
	if pc.IsolateUncategorised && isUncategorised(req.Category) {
		return true, TriggerUncategorised
	}
	if pc.RiskScoreThreshold > 0 && req.RiskScore >= pc.RiskScoreThreshold {
		return true, TriggerRiskScore
	}
	if len(pc.Categories) > 0 {
		cat := strings.ToLower(strings.TrimSpace(req.Category))
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

// hostMatches reports whether host matches any pattern in list. A
// pattern matches when it equals the host, or when it is a parent
// domain of the host (a leading "." is tolerated, so both
// "example.com" and ".example.com" match "app.example.com"). Matching
// is case-insensitive and a trailing dot (the FQDN root) is ignored.
// An empty host or empty list never matches.
func hostMatches(list []string, host string) bool {
	h := normalizeHost(host)
	if h == "" {
		return false
	}
	for _, p := range list {
		pat := normalizeHost(p)
		if pat == "" {
			continue
		}
		if h == pat || strings.HasSuffix(h, "."+pat) {
			return true
		}
	}
	return false
}

// normalizeHost lowercases, trims surrounding whitespace, and strips a
// leading "." and trailing "." so host/pattern comparison is on a
// single canonical form.
func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimPrefix(h, ".")
	h = strings.TrimSuffix(h, ".")
	return h
}

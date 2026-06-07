package rbi

import "testing"

func TestPolicyEvaluateRequest_Precedence(t *testing.T) {
	pc := PolicyConfig{
		Categories:           []string{"gambling"},
		RiskScoreThreshold:   70,
		IsolateUncategorised: true,
		ExplicitIsolate:      []string{"evil.example.com"},
		ExplicitBypass:       []string{"trusted.example.com", "intranet.corp"},
	}

	tests := []struct {
		name       string
		req        Request
		wantIso    bool
		wantReason TriggerReason
	}{
		{
			name:       "explicit isolate beats everything",
			req:        Request{Host: "evil.example.com", Category: "news", RiskScore: 0},
			wantIso:    true,
			wantReason: TriggerExplicitPolicy,
		},
		{
			name:       "explicit isolate matches subdomain",
			req:        Request{Host: "login.evil.example.com", Category: "business", RiskScore: 0},
			wantIso:    true,
			wantReason: TriggerExplicitPolicy,
		},
		{
			name:    "explicit bypass overrides category match",
			req:     Request{Host: "trusted.example.com", Category: "gambling", RiskScore: 99},
			wantIso: false,
		},
		{
			name:    "explicit bypass overrides uncategorised",
			req:     Request{Host: "app.intranet.corp", Category: "", RiskScore: 0},
			wantIso: false,
		},
		{
			name:       "uncategorised triggers when no explicit match",
			req:        Request{Host: "unknown.test", Category: "", RiskScore: 0},
			wantIso:    true,
			wantReason: TriggerUncategorised,
		},
		{
			name:       "risk score triggers",
			req:        Request{Host: "news.test", Category: "news", RiskScore: 80},
			wantIso:    true,
			wantReason: TriggerRiskScore,
		},
		{
			name:       "category triggers",
			req:        Request{Host: "casino.test", Category: "gambling", RiskScore: 10},
			wantIso:    true,
			wantReason: TriggerCategoryMatch,
		},
		{
			name:    "no rule matches",
			req:     Request{Host: "news.test", Category: "news", RiskScore: 10},
			wantIso: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			iso, reason := pc.EvaluateRequest(tc.req)
			if iso != tc.wantIso {
				t.Fatalf("isolate = %v, want %v", iso, tc.wantIso)
			}
			if iso && reason != tc.wantReason {
				t.Fatalf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

func TestPolicyDenyWins(t *testing.T) {
	// A host present in BOTH lists must be isolated (deny-wins).
	pc := PolicyConfig{
		ExplicitIsolate: []string{"both.example.com"},
		ExplicitBypass:  []string{"both.example.com"},
	}
	iso, reason := pc.EvaluateRequest(Request{Host: "both.example.com"})
	if !iso || reason != TriggerExplicitPolicy {
		t.Fatalf("deny-wins failed: iso=%v reason=%q", iso, reason)
	}
}

func TestPolicyEvaluateBackCompat(t *testing.T) {
	// The host-agnostic Evaluate cannot match explicit host lists, so
	// a category rule still drives the decision.
	pc := PolicyConfig{
		Categories:      []string{"phishing"},
		ExplicitIsolate: []string{"evil.example.com"},
	}
	if iso, reason := pc.Evaluate("phishing", 0); !iso || reason != TriggerCategoryMatch {
		t.Fatalf("category eval failed: iso=%v reason=%q", iso, reason)
	}
	if iso, _ := pc.Evaluate("news", 0); iso {
		t.Fatalf("expected no isolation for unmatched category")
	}
}

func TestHostMatches(t *testing.T) {
	list := []string{"Example.COM", ".trailing.test.", "exact.host"}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"app.example.com", true},
		{"notexample.com", false},
		{"badexample.com", false},
		{"x.trailing.test", true},
		{"trailing.test", true},
		{"exact.host", true},
		{"sub.exact.host", true},
		{"", false},
	}
	for _, c := range cases {
		if got := hostMatches(list, c.host); got != c.want {
			t.Errorf("hostMatches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

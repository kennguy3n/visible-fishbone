package dlp_test

import (
	"context"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TestService_SecretsCredentialsTemplate verifies the WS7
// secrets-credentials template is in the catalog and applies to a real
// enabled blocking policy carrying exactly the eight secret detectors.
func TestService_SecretsCredentialsTemplate(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	const id = "secrets-credentials"

	var found bool
	for _, tmpl := range svc.ListTemplates() {
		if tmpl.ID == id {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("template %q missing from catalog", id)
	}

	p, err := svc.ApplyTemplate(ctx, tid, id)
	if err != nil {
		t.Fatalf("apply %q: %v", id, err)
	}
	if !p.Enabled {
		t.Errorf("template %q produced a disabled policy", id)
	}
	// Secrets are high-value exfil; the validators are near-zero-FP, so
	// the template hard-blocks rather than coaches.
	if p.Action != repository.DLPActionBlock {
		t.Errorf("action = %v, want block", p.Action)
	}

	want := map[string]bool{
		"private_key_block": false,
		"aws_access_key_id": false,
		"google_api_key":    false,
		"github_token":      false,
		"github_pat":        false,
		"slack_token":       false,
		"stripe_secret_key": false,
		"jwt":               false,
	}
	for _, r := range p.Rules {
		if r.Type != repository.DLPRuleTypeRegex {
			t.Errorf("rule %q is %v, want regex", r.Pattern, r.Type)
		}
		if _, ok := want[r.Pattern]; !ok {
			t.Errorf("unexpected pattern %q in secrets template", r.Pattern)
			continue
		}
		want[r.Pattern] = true
	}
	for pat, seen := range want {
		if !seen {
			t.Errorf("secrets template missing pattern %q", pat)
		}
	}
}

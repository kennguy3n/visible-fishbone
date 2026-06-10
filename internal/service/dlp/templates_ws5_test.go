package dlp_test

import (
	"context"
	"testing"
)

// TestService_WS5Templates verifies the jurisdiction compliance
// templates added for WS5 are present, have unique IDs, and apply to a
// real enabled policy with non-empty rules.
func TestService_WS5Templates(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	templates := svc.ListTemplates()
	byID := make(map[string]int, len(templates))
	for _, tmpl := range templates {
		byID[tmpl.ID]++
		if byID[tmpl.ID] > 1 {
			t.Fatalf("duplicate template ID %q", tmpl.ID)
		}
	}

	wantNew := []string{
		"australia-privacy-act",
		"uk-dpa-2018",
		"japan-appi",
		"brazil-lgpd",
		"gcc-pdpl",
		"sea-pdpa",
	}
	for _, id := range wantNew {
		if byID[id] == 0 {
			t.Fatalf("template %q missing from catalog", id)
		}
		p, err := svc.ApplyTemplate(ctx, tid, id)
		if err != nil {
			t.Fatalf("apply %q: %v", id, err)
		}
		if !p.Enabled {
			t.Errorf("template %q produced a disabled policy", id)
		}
		if len(p.Rules) == 0 {
			t.Errorf("template %q produced no rules", id)
		}
		for _, r := range p.Rules {
			if r.Pattern == "" {
				t.Errorf("template %q has a rule with an empty pattern", id)
			}
		}
	}
}

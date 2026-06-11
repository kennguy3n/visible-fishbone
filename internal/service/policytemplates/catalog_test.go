package policytemplates

import (
	"testing"
)

func TestBuildCatalog_Shape(t *testing.T) {
	cat := buildCatalog()

	wantLen := 1 + len(industryProfiles) + len(complianceProfiles)
	if len(cat) != wantLen {
		t.Fatalf("catalog size = %d, want %d", len(cat), wantLen)
	}

	var baseline, industry, compliance int
	seen := map[string]struct{}{}
	for i, tmpl := range cat {
		if tmpl.ID == "" {
			t.Errorf("template[%d] has empty id", i)
		}
		if _, dup := seen[tmpl.ID]; dup {
			t.Errorf("duplicate template id %q", tmpl.ID)
		}
		seen[tmpl.ID] = struct{}{}
		if i > 0 && cat[i-1].ID > tmpl.ID {
			t.Errorf("catalog not sorted by id: %q before %q", cat[i-1].ID, tmpl.ID)
		}
		if tmpl.Name == "" {
			t.Errorf("template %q has empty name", tmpl.ID)
		}
		if tmpl.Description == "" {
			t.Errorf("template %q has empty description", tmpl.ID)
		}

		switch tmpl.Kind {
		case KindBaseline:
			baseline++
			if tmpl.Industry != "" || tmpl.Regime != "" {
				t.Errorf("baseline %q must not set industry/regime", tmpl.ID)
			}
		case KindIndustry:
			industry++
			if tmpl.Industry == "" || tmpl.Regime != "" {
				t.Errorf("industry %q must set industry and not regime", tmpl.ID)
			}
		case KindCompliance:
			compliance++
			if tmpl.Regime == "" || tmpl.Industry != "" {
				t.Errorf("compliance %q must set regime and not industry", tmpl.ID)
			}
		default:
			t.Errorf("template %q has unknown kind %q", tmpl.ID, tmpl.Kind)
		}
	}
	if baseline != 1 {
		t.Errorf("baseline count = %d, want 1", baseline)
	}
	if industry != len(industryProfiles) {
		t.Errorf("industry count = %d, want %d", industry, len(industryProfiles))
	}
	if compliance != len(complianceProfiles) {
		t.Errorf("compliance count = %d, want %d", compliance, len(complianceProfiles))
	}
}

// TestCatalogVocabularyParity asserts every category / detector /
// action / sensitivity / posture authored in any profile is a member
// of the package's closed vocabulary. A profile referencing a token
// the data plane cannot enforce would ship a baseline that silently
// never matches, so this guards against that at test time.
func TestCatalogVocabularyParity(t *testing.T) {
	checkSpec := func(name string, s Spec) {
		for _, c := range s.Categories {
			if _, ok := knownCategories[c.Category]; !ok {
				t.Errorf("%s: unknown category %q", name, c.Category)
			}
			if c.Action != CategoryBlock && c.Action != CategoryMonitor {
				t.Errorf("%s: unknown action %q on %q", name, c.Action, c.Category)
			}
		}
		for _, d := range s.Detectors {
			if _, ok := knownDetectors[d.Detector]; !ok {
				t.Errorf("%s: unknown detector %q", name, d.Detector)
			}
			if sensitivityRank(d.Sensitivity) == 0 {
				t.Errorf("%s: unknown sensitivity %q on %q", name, d.Sensitivity, d.Detector)
			}
		}
		if s.Firewall != "" && s.Firewall != PostureStandard && s.Firewall != PostureStrict {
			t.Errorf("%s: unknown firewall posture %q", name, s.Firewall)
		}
	}

	checkSpec("baseline", baselineProfile)
	for i, s := range industryProfiles {
		checkSpec("industry/"+string(i), s)
		if s.Firewall == "" {
			t.Errorf("industry %q must set a firewall posture", i)
		}
	}
	for r, s := range complianceProfiles {
		checkSpec("compliance/"+string(r), s)
		if len(s.Detectors) == 0 {
			t.Errorf("compliance %q must declare at least one detector", r)
		}
	}
}

func TestRegimeForCountry(t *testing.T) {
	cases := []struct {
		in   Country
		want ComplianceRegime
		ok   bool
	}{
		{"GB", RegimeUKDPA, true},
		{"gb", RegimeUKDPA, true}, // case-insensitive
		{"DE", RegimeEUGDPR, true},
		{"fr", RegimeEUGDPR, true},
		{"US", RegimeUSBaseline, true},
		{"AU", RegimeAUPrivacy, true},
		{"CA", RegimeCAPIPEDA, true},
		{"ZZ", "", false}, // unmodelled
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := RegimeForCountry(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("RegimeForCountry(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestBaselineBlocksSecurityCategories(t *testing.T) {
	blocked := map[URLCategory]bool{}
	for _, c := range baselineProfile.Categories {
		if c.Action == CategoryBlock {
			blocked[c.Category] = true
		}
	}
	for _, want := range []URLCategory{CategorySecurityThreat, CategorySecurityHacking, CategoryAnonymizer} {
		if !blocked[want] {
			t.Errorf("baseline must block %q", want)
		}
	}
}

package casb

import (
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestClassifyApp_Deterministic(t *testing.T) {
	tid := uuid.New()
	v := DiscoveredAppView{Name: "OpenAI ChatGPT", Category: "generative_ai", ActiveDevices: 7}
	a := classifyApp(tid, v)
	b := classifyApp(tid, v)
	if a.RiskScore != b.RiskScore || a.Confidence != b.Confidence || a.Sanction != b.Sanction {
		t.Fatalf("classification not deterministic: %+v vs %+v", a, b)
	}
	if a.Source != ClassificationSourceHeuristic {
		t.Fatalf("source = %q, want heuristic", a.Source)
	}
}

func TestClassifyApp_Sanction(t *testing.T) {
	tid := uuid.New()
	cases := []struct {
		name     string
		view     DiscoveredAppView
		sanction SanctionState
	}{
		{"connector wins", DiscoveredAppView{Name: "GitHub", Category: "code_repository", HasConnector: true}, SanctionSanctioned},
		{"exfil no connector", DiscoveredAppView{Name: "WeTransfer", Category: "file_transfer"}, SanctionUnsanctioned},
		{"genai no connector", DiscoveredAppView{Name: "ChatGPT", Category: "generative_ai"}, SanctionUnsanctioned},
		{"benign known", DiscoveredAppView{Name: "Zoom", Category: "conferencing"}, SanctionTolerated},
		{"unknown category", DiscoveredAppView{Name: "Mystery", Category: "weird"}, SanctionTolerated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyApp(tid, tc.view).Sanction
			if got != tc.sanction {
				t.Fatalf("sanction = %q, want %q", got, tc.sanction)
			}
		})
	}
}

func TestClassifyApp_RiskNeverBelowBaseline(t *testing.T) {
	tid := uuid.New()
	// Grammarly: productivity (weight 45) but catalog baseline 55.
	v := DiscoveredAppView{Name: "Grammarly", Category: "productivity", BaselineRisk: 55}
	got := classifyApp(tid, v).RiskScore
	if got < 55 {
		t.Fatalf("risk %d softened below baseline 55", got)
	}
}

func TestClassifyApp_UnknownCategoryLowersConfidence(t *testing.T) {
	tid := uuid.New()
	known := classifyApp(tid, DiscoveredAppView{Name: "A", Category: "crm"}).Confidence
	unknown := classifyApp(tid, DiscoveredAppView{Name: "B", Category: "nonsense"}).Confidence
	if !(unknown < known) {
		t.Fatalf("unknown-category confidence %d should be < known %d", unknown, known)
	}
}

func TestActionEnforcement_TrafficClass(t *testing.T) {
	cases := map[ActionEnforcement]repository.TrafficClass{
		ActionThrottle: repository.TrafficClassInspectLite,
		ActionProtect:  repository.TrafficClassInspectFull,
		ActionRoute:    repository.TrafficClassTunnelPrivate,
		ActionEnforce:  repository.TrafficClassBlock,
		ActionNone:     "",
	}
	for verb, want := range cases {
		if got := verb.TrafficClass(); got != want {
			t.Fatalf("%s.TrafficClass() = %q, want %q", verb, got, want)
		}
	}
}

func TestDecideAction_Bands(t *testing.T) {
	pol := DefaultActionPolicy(uuid.New())
	cases := []struct {
		name string
		c    AppClassification
		verb ActionEnforcement
		mode ActionMode
	}{
		{
			name: "below floor => none",
			c:    AppClassification{Category: "design", RiskScore: 20, Confidence: 90, Sanction: SanctionTolerated},
			verb: ActionNone, mode: ActionModeRecommend,
		},
		{
			name: "throttle band recommend",
			c:    AppClassification{Category: "design", RiskScore: 35, Confidence: 90, Sanction: SanctionUnsanctioned},
			verb: ActionThrottle, mode: ActionModeRecommend,
		},
		{
			name: "protect band, unsanctioned, high conf => auto",
			c:    AppClassification{Category: "file_transfer", RiskScore: 65, Confidence: 90, Sanction: SanctionUnsanctioned},
			verb: ActionProtect, mode: ActionModeAuto,
		},
		{
			name: "protect band but tolerated => recommend",
			c:    AppClassification{Category: "crm", RiskScore: 65, Confidence: 90, Sanction: SanctionTolerated},
			verb: ActionProtect, mode: ActionModeRecommend,
		},
		{
			name: "protect band, low confidence => recommend",
			c:    AppClassification{Category: "file_transfer", RiskScore: 65, Confidence: 50, Sanction: SanctionUnsanctioned},
			verb: ActionProtect, mode: ActionModeRecommend,
		},
		{
			name: "enforce band never auto",
			c:    AppClassification{Category: "cloud_iaas", RiskScore: 80, Confidence: 99, Sanction: SanctionUnsanctioned},
			verb: ActionEnforce, mode: ActionModeRecommend,
		},
		{
			name: "sanctioned sensitive => route recommend",
			c:    AppClassification{Category: "identity", RiskScore: 65, Confidence: 90, Sanction: SanctionSanctioned},
			verb: ActionRoute, mode: ActionModeRecommend,
		},
		{
			name: "sanctioned benign => none",
			c:    AppClassification{Category: "crm", RiskScore: 65, Confidence: 90, Sanction: SanctionSanctioned},
			verb: ActionNone, mode: ActionModeRecommend,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			verb, mode, _ := decideAction(tc.c, pol)
			if verb != tc.verb || mode != tc.mode {
				t.Fatalf("decideAction = (%s,%s), want (%s,%s)", verb, mode, tc.verb, tc.mode)
			}
		})
	}
}

func TestDecideAction_PolicyDisablesAuto(t *testing.T) {
	pol := DefaultActionPolicy(uuid.New())
	pol.AutoEnforceEnabled = false
	c := AppClassification{Category: "file_transfer", RiskScore: 65, Confidence: 95, Sanction: SanctionUnsanctioned}
	_, mode, _ := decideAction(c, pol)
	if mode != ActionModeRecommend {
		t.Fatalf("mode = %s, want recommend when auto disabled", mode)
	}
}

func TestWildcardDomains(t *testing.T) {
	got := wildcardDomains([]string{"slack.com", "", "slack.com", "console.aws.amazon.com"})
	want := []string{"*.slack.com", "*.console.aws.amazon.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

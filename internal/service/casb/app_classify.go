package casb

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// DiscoveredAppView is the read-only input to classification: the
// app's stable identity plus the signals the heuristic weighs. It is
// assembled from the shadow catalog (for catalog-matched apps) and/or
// the persisted casb_discovered_apps row, so classification works for
// both shadow-discovered apps and connector-synced ones.
type DiscoveredAppView struct {
	Name     string
	Vendor   string
	Category string
	// BaselineRisk is the catalog/posture risk score (0-100) when
	// known, else 0.
	BaselineRisk int
	// ActiveDevices is the windowed distinct-device count (shadow-IT
	// signal); 0 when unknown.
	ActiveDevices int
	// HasConnector is true when the tenant has a first-class CASB
	// connector for the app — a strong signal the app is sanctioned.
	HasConnector bool
	// Domains are the registrable host suffixes the app is known by
	// (e.g. "slack.com", "console.aws.amazon.com"). Used by the action
	// engine to scope enforcement; not weighed by the classifier.
	Domains []string
}

// categoryWeight maps an app category to a baseline risk weight (0-100)
// reflecting how much unsanctioned use of that category moves regulated
// data off-network and bypasses tenant DLP/posture controls. An unknown
// category is treated as medium-high (we cannot vouch for it).
//
// This is the deterministic core of classification: the same category
// always yields the same weight, so a tenant's verdict is reproducible
// and auditable without any model or network call.
var categoryWeight = map[string]int{
	"cloud_iaas":         75,
	"generative_ai":      70,
	"file_transfer":      70,
	"messaging":          60,
	"code_repository":    60,
	"cloud_storage":      55,
	"identity":           55,
	"database":           50,
	"hcm":                45,
	"crm":                45,
	"itsm":               45,
	"productivity":       45,
	"marketing":          40,
	"support":            35,
	"design":             35,
	"project_management": 35,
	"collaboration":      35,
	"conferencing":       30,
}

const unknownCategoryWeight = 50

// classifyApp computes the deterministic classification for an app
// within a tenant. The result is fully determined by the inputs (no
// wall clock beyond the supplied `now`, no randomness), so it is safe
// to recompute every reconcile and to assert on in tests.
func classifyApp(tenantID uuid.UUID, v DiscoveredAppView) AppClassification {
	cat := strings.TrimSpace(strings.ToLower(v.Category))
	weight, known := categoryWeight[cat]
	if !known {
		weight = unknownCategoryWeight
	}

	// Risk: blend the category weight with any catalog/posture baseline
	// so a category's inherent risk dominates while an app-specific
	// baseline (e.g. Grammarly scoring above its category) still pulls
	// the score. Integer math, rounded, clamped to [0,100].
	risk := weight
	if v.BaselineRisk > 0 {
		risk = (3*v.BaselineRisk + 2*weight) / 5
		if v.BaselineRisk > risk {
			// Never classify below the explicit baseline: a known-bad
			// app must not be softened by a benign category.
			risk = v.BaselineRisk
		}
	}
	risk = clampScore(risk)

	sanction := sanctionFor(cat, v.HasConnector)

	// Confidence: how much we trust the verdict. A catalog/connector
	// match and observed adoption raise it; an unknown category lowers
	// it (we are guessing the risk).
	conf := 50
	if known {
		conf += 25
	} else {
		conf -= 25
	}
	if v.HasConnector {
		conf += 20 // we KNOW it is connected
	}
	switch {
	case v.ActiveDevices >= 5:
		conf += 10
	case v.ActiveDevices >= 1:
		conf += 5
	}
	conf = clampScore(conf)

	return AppClassification{
		TenantID:   tenantID,
		AppName:    v.Name,
		Category:   v.Category,
		RiskScore:  risk,
		Sanction:   sanction,
		Confidence: conf,
		Source:     ClassificationSourceHeuristic,
		Rationale:  classificationRationale(cat, known, sanction, risk, conf, v),
	}
}

// sanctionFor derives the sanction recommendation deterministically.
//
//   - A connector means the tenant deliberately adopted the app ->
//     sanctioned.
//   - The classic shadow-IT exfiltration categories with no connector
//     -> unsanctioned (eligible for auto-protect).
//   - Anything else known -> tolerated (recommend-only).
func sanctionFor(category string, hasConnector bool) SanctionState {
	if hasConnector {
		return SanctionSanctioned
	}
	switch category {
	case "generative_ai", "file_transfer", "messaging", "cloud_iaas", "cloud_storage", "code_repository":
		return SanctionUnsanctioned
	default:
		return SanctionTolerated
	}
}

func classificationRationale(category string, knownCategory bool, sanction SanctionState, risk, conf int, v DiscoveredAppView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "category=%s", category)
	if !knownCategory {
		b.WriteString(" (unrecognised; treated as medium-high)")
	}
	fmt.Fprintf(&b, "; risk=%d; confidence=%d; sanction=%s", risk, conf, sanction)
	if v.HasConnector {
		b.WriteString("; connector present")
	}
	if v.ActiveDevices > 0 {
		fmt.Fprintf(&b, "; active_devices=%d", v.ActiveDevices)
	}
	return b.String()
}

func clampScore(n int) int {
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

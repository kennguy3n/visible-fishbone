package compliance

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

var regionalFrameworks = []ComplianceFramework{
	FrameworkPDPA,
	FrameworkNESA,
	FrameworkNDSG,
	FrameworkBDSG,
	FrameworkCSACE,
}

// TestRegionalMappingsReferenceRealControls guards against typos: every
// control id named in a policy→control mapping must exist in that
// framework's catalog, otherwise enforcing the policy would silently
// fail to credit any control.
func TestRegionalMappingsReferenceRealControls(t *testing.T) {
	for _, fw := range regionalFrameworks {
		catalog := frameworkControlMap[fw]
		if len(catalog) == 0 {
			t.Errorf("framework %s has no controls", fw)
			continue
		}
		known := map[string]bool{}
		for _, c := range catalog {
			known[c.ControlID] = true
		}
		for policyType, byFramework := range policyControlMapping {
			for _, id := range byFramework[fw] {
				if !known[id] {
					t.Errorf("policy %q maps %s to unknown control %q", policyType, fw, id)
				}
			}
		}
	}
}

// TestRegionalFrameworksScoreFully verifies regional frameworks flow
// through the shared Generate pipeline and that every catalog control
// is reachable: with all policies enforced the score equals max.
func TestRegionalFrameworksScoreFully(t *testing.T) {
	store := memory.NewStore()
	repo := memory.NewComplianceReportRepository(store)
	svc := NewReportService(repo, nil)
	ctx := context.Background()

	for _, fw := range regionalFrameworks {
		if !ValidFrameworks[fw] {
			t.Errorf("%s missing from ValidFrameworks", fw)
		}
		report, err := svc.Generate(ctx, uuid.New(), fw, EnforcedPolicies{
			DLP:           true,
			Browser:       true,
			CASB:          true,
			Policy:        true,
			AccessControl: true,
		})
		if err != nil {
			t.Fatalf("Generate(%s): %v", fw, err)
		}
		if report.MaxScore != float64(len(frameworkControlMap[fw])) {
			t.Errorf("%s max score %v != catalog size %d", fw, report.MaxScore, len(frameworkControlMap[fw]))
		}
		if report.Score != report.MaxScore {
			t.Errorf("%s: every control should be covered by some policy; score %v of %v", fw, report.Score, report.MaxScore)
		}
	}
}

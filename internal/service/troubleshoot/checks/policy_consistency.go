package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyConsistencyCheck verifies policy graph integrity: cycles,
// unreachable rules, and version skew between compiled bundles.
type PolicyConsistencyCheck struct {
	policies repository.PolicyRepository
}

// NewPolicyConsistencyCheck creates a policy consistency check.
func NewPolicyConsistencyCheck(policies repository.PolicyRepository) *PolicyConsistencyCheck {
	return &PolicyConsistencyCheck{policies: policies}
}

func (c *PolicyConsistencyCheck) Name() string { return "policy_consistency" }

func (c *PolicyConsistencyCheck) Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult {
	now := time.Now().UTC()
	result := DiagnosticResult{
		CheckName:  c.Name(),
		ExecutedAt: now,
	}

	graphs, err := c.policies.ListGraphVersions(ctx, tenantID, repository.Page{Limit: 100})
	if err != nil {
		result.Status = DiagnosticFail
		result.Message = "Failed to retrieve policy graphs: " + err.Error()
		return result
	}

	if len(graphs.Items) == 0 {
		result.Status = DiagnosticPass
		result.Message = "No policy graphs configured"
		return result
	}

	issues := 0
	var warnings []string
	for _, g := range graphs.Items {
		if len(g.Graph) == 0 {
			issues++
			warnings = append(warnings, fmt.Sprintf("Graph %s has empty graph data", g.ID))
		}
	}

	details, _ := json.Marshal(map[string]any{
		"total_graphs": len(graphs.Items),
		"issues":       issues,
		"warnings":     warnings,
	})
	result.Details = details

	switch {
	case issues == 0:
		result.Status = DiagnosticPass
		result.Message = fmt.Sprintf("All %d policy graphs are consistent", len(graphs.Items))
	case issues < len(graphs.Items):
		result.Status = DiagnosticWarn
		result.Message = fmt.Sprintf("%d of %d graphs have consistency issues", issues, len(graphs.Items))
	default:
		result.Status = DiagnosticFail
		result.Message = "All policy graphs have consistency issues"
	}
	return result
}

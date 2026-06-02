// Package terraform — drift.go implements config-as-code drift
// detection (Phase 4, Task 48).
//
// DetectDrift compares a declared (desired) config against the
// actual state exported from the live tenant and reports
// added/modified/removed resources.
package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// DriftType enumerates the kinds of drift a resource can exhibit.
type DriftType string

const (
	DriftTypeAdded    DriftType = "added"
	DriftTypeModified DriftType = "modified"
	DriftTypeRemoved  DriftType = "removed"
)

// DriftEntry is a single resource-level drift finding.
type DriftEntry struct {
	ResourceType string    `json:"resource_type"`
	ResourceName string    `json:"resource_name"`
	DriftType    DriftType `json:"drift_type"`
	Details      string    `json:"details,omitempty"`
}

// DriftReport is the aggregate result of a drift detection run.
type DriftReport struct {
	TenantID   uuid.UUID    `json:"tenant_id"`
	DetectedAt time.Time    `json:"detected_at"`
	Entries    []DriftEntry `json:"entries"`
	HasDrift   bool         `json:"has_drift"`
}

// DetectDrift compares the declared config against the current
// tenant state and returns a DriftReport.
func (p *Provider) DetectDrift(ctx context.Context, tenantID uuid.UUID, declaredConfig json.RawMessage) (DriftReport, error) {
	var declared ExportedConfig
	if err := json.Unmarshal(declaredConfig, &declared); err != nil {
		return DriftReport{}, fmt.Errorf("unmarshal declared config: %w", err)
	}

	actualBytes, err := p.ExportTenantConfig(ctx, tenantID)
	if err != nil {
		return DriftReport{}, fmt.Errorf("export actual config: %w", err)
	}
	var actual ExportedConfig
	if err := json.Unmarshal(actualBytes, &actual); err != nil {
		return DriftReport{}, fmt.Errorf("unmarshal actual config: %w", err)
	}

	report := DriftReport{
		TenantID:   tenantID,
		DetectedAt: time.Now().UTC(),
	}

	// Compare sites.
	report.Entries = append(report.Entries, diffNamedResources("site",
		exportedSiteNames(declared.Sites),
		exportedSiteNames(actual.Sites),
	)...)

	// Compare browser policies.
	report.Entries = append(report.Entries, diffNamedResources("browser_policy",
		exportedBrowserPolicyNames(declared.BrowserPolicies),
		exportedBrowserPolicyNames(actual.BrowserPolicies),
	)...)

	// Compare data classifications.
	report.Entries = append(report.Entries, diffNamedResources("data_classification",
		exportedDataClassificationLabels(declared.DataClassifications),
		exportedDataClassificationLabels(actual.DataClassifications),
	)...)

	// Compare integrations.
	report.Entries = append(report.Entries, diffNamedResources("integration",
		exportedIntegrationNames(declared.Integrations),
		exportedIntegrationNames(actual.Integrations),
	)...)

	report.HasDrift = len(report.Entries) > 0
	return report, nil
}

func diffNamedResources(resourceType string, declared, actual map[string]bool) []DriftEntry {
	var entries []DriftEntry

	for name := range declared {
		if !actual[name] {
			entries = append(entries, DriftEntry{
				ResourceType: resourceType,
				ResourceName: name,
				DriftType:    DriftTypeRemoved,
				Details:      "declared but not present in actual state",
			})
		}
	}
	for name := range actual {
		if !declared[name] {
			entries = append(entries, DriftEntry{
				ResourceType: resourceType,
				ResourceName: name,
				DriftType:    DriftTypeAdded,
				Details:      "present in actual state but not declared",
			})
		}
	}
	return entries
}

func exportedSiteNames(sites []ExportedSite) map[string]bool {
	m := make(map[string]bool, len(sites))
	for _, s := range sites {
		m[s.Name] = true
	}
	return m
}

func exportedBrowserPolicyNames(policies []ExportedBrowserPolicy) map[string]bool {
	m := make(map[string]bool, len(policies))
	for _, p := range policies {
		m[p.Name] = true
	}
	return m
}

func exportedDataClassificationLabels(dcs []ExportedDataClassification) map[string]bool {
	m := make(map[string]bool, len(dcs))
	for _, dc := range dcs {
		m[dc.Label] = true
	}
	return m
}

func exportedIntegrationNames(ics []ExportedIntegration) map[string]bool {
	m := make(map[string]bool, len(ics))
	for _, ic := range ics {
		m[ic.Name] = true
	}
	return m
}

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

	"github.com/kennguy3n/visible-fishbone/internal/repository"
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
// tenant state and returns a DriftReport. Drift is detected for
// sites, browser policies, data classifications, and integrations.
// Policy graphs are excluded because they follow a separate
// versioning/signing workflow and are not round-tripped by import.
func (p *Provider) DetectDrift(ctx context.Context, tenantID uuid.UUID, declaredConfig json.RawMessage) (DriftReport, error) {
	var declared ExportedConfig
	if err := json.Unmarshal(declaredConfig, &declared); err != nil {
		return DriftReport{}, fmt.Errorf("unmarshal declared config: %w: %w", repository.ErrInvalidArgument, err)
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
		Entries:    []DriftEntry{},
	}

	// Compare sites.
	report.Entries = append(report.Entries, diffResources("site",
		indexSites(declared.Sites), indexSites(actual.Sites))...)

	// Compare browser policies.
	report.Entries = append(report.Entries, diffResources("browser_policy",
		indexBrowserPolicies(declared.BrowserPolicies), indexBrowserPolicies(actual.BrowserPolicies))...)

	// Compare data classifications.
	report.Entries = append(report.Entries, diffResources("data_classification",
		indexDataClassifications(declared.DataClassifications), indexDataClassifications(actual.DataClassifications))...)

	// Compare integrations.
	report.Entries = append(report.Entries, diffResources("integration",
		indexIntegrations(declared.Integrations), indexIntegrations(actual.Integrations))...)

	report.HasDrift = len(report.Entries) > 0
	return report, nil
}

func diffResources(resourceType string, declared, actual map[string]string) []DriftEntry {
	var entries []DriftEntry

	for name, declHash := range declared {
		actHash, exists := actual[name]
		if !exists {
			entries = append(entries, DriftEntry{
				ResourceType: resourceType,
				ResourceName: name,
				DriftType:    DriftTypeRemoved,
				Details:      "declared but not present in actual state",
			})
		} else if declHash != actHash {
			entries = append(entries, DriftEntry{
				ResourceType: resourceType,
				ResourceName: name,
				DriftType:    DriftTypeModified,
				Details:      "configuration differs between declared and actual state",
			})
		}
	}
	for name := range actual {
		if _, exists := declared[name]; !exists {
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

// marshalCanonical serializes v into a canonical JSON string for
// comparison. json.RawMessage fields (e.g. Config, HandlingRules)
// are normalized via json.Compact so semantically equivalent JSON
// with different whitespace/key-ordering produces identical output.
func marshalCanonical(v any) string {
	b, _ := json.Marshal(v)
	// Round-trip through interface{} to normalize json.RawMessage
	// fields: json.Unmarshal parses them into map[string]any with
	// deterministic key ordering on re-marshal.
	var normalized any
	if err := json.Unmarshal(b, &normalized); err != nil {
		return string(b)
	}
	out, err := json.Marshal(normalized)
	if err != nil {
		return string(b)
	}
	return string(out)
}

func indexSites(sites []ExportedSite) map[string]string {
	m := make(map[string]string, len(sites))
	for _, s := range sites {
		m[s.Slug] = marshalCanonical(s)
	}
	return m
}

func indexBrowserPolicies(policies []ExportedBrowserPolicy) map[string]string {
	m := make(map[string]string, len(policies))
	for _, p := range policies {
		if p.Rules == nil {
			p.Rules = []repository.BrowserRule{}
		}
		m[p.Name] = marshalCanonical(p)
	}
	return m
}

func indexDataClassifications(dcs []ExportedDataClassification) map[string]string {
	m := make(map[string]string, len(dcs))
	for _, dc := range dcs {
		m[dc.Level] = marshalCanonical(dc)
	}
	return m
}

func indexIntegrations(ics []ExportedIntegration) map[string]string {
	m := make(map[string]string, len(ics))
	for _, ic := range ics {
		if ic.EventTypes == nil {
			ic.EventTypes = []string{}
		}
		// Status is runtime state (e.g. "active"/"disabled"), not
		// declared configuration. Zero it so drift detection only
		// compares config-level fields.
		ic.Status = ""
		m[ic.Name] = marshalCanonical(ic)
	}
	return m
}

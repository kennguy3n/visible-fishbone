package ai

import (
	"fmt"
	"strings"
)

// TemplateData is the structured evidence the template summarizer
// renders into a deterministic narrative. Populated from ClickHouse
// query results.
type TemplateData struct {
	TenantID       string
	AlertCount     int
	TopAlertKinds  []string
	BaselineCount  int
	TopDimensions  []string
	VerdictCount   int
	DenyCount      int
	AllowCount     int
	TimeRangeLabel string
}

// RenderTemplate produces a deterministic summary from structured
// data. Always succeeds — this IS the fallback. No LLM dependency.
func RenderTemplate(data TemplateData) Summary {
	var b strings.Builder

	// Opener.
	fmt.Fprintf(&b, "Summary for tenant %s over %s.\n",
		data.TenantID, data.TimeRangeLabel)

	// Findings.
	findings := buildTemplateFindings(data)
	if len(findings) > 0 {
		b.WriteString("\nKey findings:\n")
		for _, f := range findings {
			fmt.Fprintf(&b, "- %s\n", f)
		}
	}

	// Actions.
	actions := buildTemplateActions(data)
	if len(actions) > 0 {
		b.WriteString("\nRecommended actions:\n")
		for _, a := range actions {
			fmt.Fprintf(&b, "- %s\n", a)
		}
	}

	return Summary{
		Text:               strings.TrimRight(b.String(), "\n"),
		KeyFindings:        findings,
		RecommendedActions: actions,
		EvidenceRefs:       []string{},
		AIGenerated:        false,
	}
}

func buildTemplateFindings(data TemplateData) []string {
	out := []string{}
	if data.AlertCount > 0 {
		s := fmt.Sprintf("%d alert(s) detected", data.AlertCount)
		if len(data.TopAlertKinds) > 0 {
			s += fmt.Sprintf("; top kind(s): %s", strings.Join(data.TopAlertKinds, ", "))
		}
		out = append(out, s)
	}
	if data.BaselineCount > 0 {
		s := fmt.Sprintf("%d baseline deviation(s)", data.BaselineCount)
		if len(data.TopDimensions) > 0 {
			s += fmt.Sprintf("; top dimension(s): %s", strings.Join(data.TopDimensions, ", "))
		}
		out = append(out, s)
	}
	if data.VerdictCount > 0 {
		out = append(out, fmt.Sprintf("%d policy verdict(s): %d deny, %d allow",
			data.VerdictCount, data.DenyCount, data.AllowCount))
	}
	if len(out) == 0 {
		out = append(out, "No significant events in the requested time range.")
	}
	return out
}

func buildTemplateActions(data TemplateData) []string {
	out := []string{}
	if data.AlertCount > 0 {
		out = append(out, "Review and triage open alerts.")
	}
	if data.DenyCount > 0 {
		out = append(out, "Investigate denied policy verdicts for potential misconfigurations.")
	}
	if data.BaselineCount > 0 {
		out = append(out, "Review baseline deviations and update thresholds if needed.")
	}
	if len(out) == 0 {
		out = append(out, "No immediate action required.")
	}
	return out
}

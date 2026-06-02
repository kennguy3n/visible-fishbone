package ai

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// PostureReport is a security posture summary for a tenant over a
// reporting period.
type PostureReport struct {
	TenantID        uuid.UUID            `json:"tenant_id"`
	Period          ReportPeriod         `json:"period"`
	Overview        PostureOverview      `json:"overview"`
	Threats         PostureThreatSection `json:"threats"`
	PolicyHealth    PosturePolicyHealth  `json:"policy_health"`
	Recommendations []string             `json:"recommendations"`
	Summary         string               `json:"summary,omitempty"`
	GeneratedAt     time.Time            `json:"generated_at"`
	AIGenerated     bool                 `json:"ai_generated"`
	ModelID         string               `json:"model_id,omitempty"`
}

// ReportPeriod defines the reporting window.
type ReportPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Label string    `json:"label"` // e.g. "weekly", "monthly"
}

// PostureOverview is the top-level overview section.
type PostureOverview struct {
	TotalAlerts      int            `json:"total_alerts"`
	AlertsBySeverity map[string]int `json:"alerts_by_severity"`
	Trend            string         `json:"trend"` // improving, degrading, stable
}

// PostureThreatSection summarises top threats.
type PostureThreatSection struct {
	TopKinds       []string `json:"top_kinds"`
	NewThreatTypes int      `json:"new_threat_types"`
}

// ThreatEntry is a single top-threat line item (internal use).
type ThreatEntry struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// PosturePolicyHealth is the policy health section.
type PosturePolicyHealth struct {
	TotalPolicies  int     `json:"total_policies"`
	ActivePolicies int     `json:"active_policies"`
	CoveragePct    float64 `json:"coverage_pct"`
}

// PostureInput is the structured data fed into the report engine.
// Callers aggregate this from their data stores.
type PostureInput struct {
	TenantID uuid.UUID
	Period   ReportPeriod

	AlertsBySeverity map[string]int
	ResolvedAlerts   int
	PrevPeriodAlerts int
	TopThreats       []ThreatEntry
	TotalPolicies    int
	ActivePolicies   int
	TotalVerdicts    int
	DenyVerdicts     int
}

// ReportEngine generates security posture reports.
type ReportEngine struct {
	llm LLMProvider
}

// NewReportEngine constructs a ReportEngine. llm may be nil
// (template-only mode).
func NewReportEngine(llm LLMProvider) *ReportEngine {
	return &ReportEngine{llm: llm}
}

// Generate produces a posture report from structured input.
func (e *ReportEngine) Generate(ctx context.Context, input PostureInput) (PostureReport, error) {
	totalAlerts := 0
	for _, v := range input.AlertsBySeverity {
		totalAlerts += v
	}

	trendDir, _ := computeTrend(totalAlerts, input.PrevPeriodAlerts)

	var coveragePct float64
	if input.TotalPolicies > 0 {
		coveragePct = float64(input.ActivePolicies) / float64(input.TotalPolicies) * 100
	}
	var denyRate float64
	if input.TotalVerdicts > 0 {
		denyRate = float64(input.DenyVerdicts) / float64(input.TotalVerdicts) * 100
	}

	overview := PostureOverview{
		TotalAlerts:      totalAlerts,
		AlertsBySeverity: input.AlertsBySeverity,
		Trend:            trendDir,
	}

	topKinds := make([]string, 0, len(input.TopThreats))
	for _, t := range input.TopThreats {
		topKinds = append(topKinds, t.Kind)
	}

	recs := e.buildRecommendations(overview, input, coveragePct, denyRate)

	report := PostureReport{
		TenantID: input.TenantID,
		Period:   input.Period,
		Overview: overview,
		Threats: PostureThreatSection{
			TopKinds:       topKinds,
			NewThreatTypes: 0,
		},
		PolicyHealth: PosturePolicyHealth{
			TotalPolicies:  input.TotalPolicies,
			ActivePolicies: input.ActivePolicies,
			CoveragePct:    coveragePct,
		},
		Recommendations: recs,
		GeneratedAt:     time.Now().UTC(),
	}

	if e.llm != nil {
		text, modelID, err := e.polishWithLLM(ctx, report)
		if err == nil {
			report.Summary = text
			report.AIGenerated = true
			report.ModelID = modelID
		}
	}

	return report, nil
}

func (e *ReportEngine) buildRecommendations(o PostureOverview, input PostureInput, coverage, denyRate float64) []string {
	var recs []string
	if o.AlertsBySeverity["critical"] > 0 {
		recs = append(recs, fmt.Sprintf("Investigate %d critical alert(s) immediately.", o.AlertsBySeverity["critical"]))
	}
	if o.Trend == "degrading" {
		recs = append(recs, "Alert volume is increasing; review detection thresholds.")
	}
	if coverage < 80 {
		recs = append(recs, fmt.Sprintf("Policy coverage is %.0f%%; consider activating dormant policies.", coverage))
	}
	if denyRate > 50 {
		recs = append(recs, "High deny rate detected; review policy rules for over-restriction.")
	}
	if o.TotalAlerts-input.ResolvedAlerts > 0 {
		recs = append(recs, fmt.Sprintf("%d alert(s) remain open; prioritise triage.", o.TotalAlerts-input.ResolvedAlerts))
	}
	if len(recs) == 0 {
		recs = append(recs, "Security posture is healthy. No immediate action required.")
	}
	return recs
}

func (e *ReportEngine) polishWithLLM(ctx context.Context, report PostureReport) (string, string, error) {
	prompt := fmt.Sprintf(
		"You are a ShieldNet Gateway security analyst. "+
			"Polish the following security posture data into a professional executive briefing. "+
			"Do not invent data — only rephrase the evidence provided.\n\n"+
			"Total alerts: %d, Trend: %s, Period: %s",
		report.Overview.TotalAlerts, report.Overview.Trend, report.Period.Label)

	resp, err := e.llm.Complete(ctx, LLMRequest{
		Prompt:         prompt,
		TemperatureX10: 3,
		MaxTokens:      500,
	})
	if err != nil {
		return "", "", err
	}
	return resp.Text, resp.ModelID, nil
}

func computeTrend(current, previous int) (direction string, pctChange float64) {
	if previous == 0 {
		if current == 0 {
			return "stable", 0
		}
		return "degrading", 100
	}
	change := float64(current-previous) / float64(previous) * 100
	switch {
	case change > 10:
		return "degrading", change
	case change < -10:
		return "improving", change
	default:
		return "stable", change
	}
}

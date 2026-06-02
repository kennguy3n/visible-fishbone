package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// PostureReport is a security posture summary for a tenant over a
// reporting period.
type PostureReport struct {
	TenantID        uuid.UUID             `json:"tenant_id"`
	Period          ReportPeriod          `json:"period"`
	Overview        PostureOverview       `json:"overview"`
	Threats         PostureThreatSection  `json:"threats"`
	PolicyHealth    PosturePolicyHealth   `json:"policy_health"`
	Recommendations []string             `json:"recommendations"`
	GeneratedAt     time.Time             `json:"generated_at"`
	AIGenerated     bool                  `json:"ai_generated"`
	ModelID         string                `json:"model_id,omitempty"`
}

// ReportPeriod defines the reporting window.
type ReportPeriod struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
	Label string    `json:"label"` // e.g. "weekly", "monthly"
}

// PostureOverview is the top-level overview section.
type PostureOverview struct {
	TotalAlerts     int     `json:"total_alerts"`
	CriticalAlerts  int     `json:"critical_alerts"`
	HighAlerts      int     `json:"high_alerts"`
	MediumAlerts    int     `json:"medium_alerts"`
	LowAlerts       int     `json:"low_alerts"`
	ResolvedAlerts  int     `json:"resolved_alerts"`
	TrendDirection  string  `json:"trend_direction"` // improving, degrading, stable
	TrendPctChange  float64 `json:"trend_pct_change"`
	SummaryText     string  `json:"summary_text"`
}

// PostureThreatSection summarises top threats.
type PostureThreatSection struct {
	TopThreats []ThreatEntry `json:"top_threats"`
}

// ThreatEntry is a single top-threat line item.
type ThreatEntry struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

// PosturePolicyHealth is the policy health section.
type PosturePolicyHealth struct {
	TotalPolicies   int     `json:"total_policies"`
	ActivePolicies  int     `json:"active_policies"`
	CoveragePercent float64 `json:"coverage_percent"`
	DenyRate        float64 `json:"deny_rate"`
}

// PostureInput is the structured data fed into the report engine.
// Callers aggregate this from their data stores.
type PostureInput struct {
	TenantID uuid.UUID
	Period   ReportPeriod

	AlertsBySeverity  map[string]int
	ResolvedAlerts    int
	PrevPeriodAlerts  int
	TopThreats        []ThreatEntry
	TotalPolicies     int
	ActivePolicies    int
	TotalVerdicts     int
	DenyVerdicts      int
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

	trendDir, trendPct := computeTrend(totalAlerts, input.PrevPeriodAlerts)

	var coveragePct float64
	if input.TotalPolicies > 0 {
		coveragePct = float64(input.ActivePolicies) / float64(input.TotalPolicies) * 100
	}
	var denyRate float64
	if input.TotalVerdicts > 0 {
		denyRate = float64(input.DenyVerdicts) / float64(input.TotalVerdicts) * 100
	}

	overview := PostureOverview{
		TotalAlerts:    totalAlerts,
		CriticalAlerts: input.AlertsBySeverity["critical"],
		HighAlerts:     input.AlertsBySeverity["high"],
		MediumAlerts:   input.AlertsBySeverity["medium"],
		LowAlerts:      input.AlertsBySeverity["low"],
		ResolvedAlerts: input.ResolvedAlerts,
		TrendDirection: trendDir,
		TrendPctChange: trendPct,
	}

	overview.SummaryText = e.buildTemplateSummary(overview, input.Period)

	recs := e.buildRecommendations(overview, coveragePct, denyRate)

	report := PostureReport{
		TenantID: input.TenantID,
		Period:   input.Period,
		Overview: overview,
		Threats: PostureThreatSection{
			TopThreats: input.TopThreats,
		},
		PolicyHealth: PosturePolicyHealth{
			TotalPolicies:   input.TotalPolicies,
			ActivePolicies:  input.ActivePolicies,
			CoveragePercent: coveragePct,
			DenyRate:        denyRate,
		},
		Recommendations: recs,
		GeneratedAt:     time.Now().UTC(),
	}

	if e.llm != nil {
		polished, modelID, err := e.polishWithLLM(ctx, report)
		if err == nil {
			report.Overview.SummaryText = polished
			report.AIGenerated = true
			report.ModelID = modelID
		}
	}

	return report, nil
}

func (e *ReportEngine) buildTemplateSummary(o PostureOverview, period ReportPeriod) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Security posture report for %s.\n", period.Label)
	fmt.Fprintf(&b, "Total alerts: %d (critical: %d, high: %d, medium: %d, low: %d). ",
		o.TotalAlerts, o.CriticalAlerts, o.HighAlerts, o.MediumAlerts, o.LowAlerts)
	fmt.Fprintf(&b, "Resolved: %d. ", o.ResolvedAlerts)
	fmt.Fprintf(&b, "Trend: %s (%.1f%% change).", o.TrendDirection, o.TrendPctChange)
	return b.String()
}

func (e *ReportEngine) buildRecommendations(o PostureOverview, coverage, denyRate float64) []string {
	var recs []string
	if o.CriticalAlerts > 0 {
		recs = append(recs, fmt.Sprintf("Investigate %d critical alert(s) immediately.", o.CriticalAlerts))
	}
	if o.TrendDirection == "degrading" {
		recs = append(recs, "Alert volume is increasing; review detection thresholds.")
	}
	if coverage < 80 {
		recs = append(recs, fmt.Sprintf("Policy coverage is %.0f%%; consider activating dormant policies.", coverage))
	}
	if denyRate > 50 {
		recs = append(recs, "High deny rate detected; review policy rules for over-restriction.")
	}
	if o.TotalAlerts-o.ResolvedAlerts > 0 {
		recs = append(recs, fmt.Sprintf("%d alert(s) remain open; prioritise triage.", o.TotalAlerts-o.ResolvedAlerts))
	}
	if len(recs) == 0 {
		recs = append(recs, "Security posture is healthy. No immediate action required.")
	}
	return recs
}

func (e *ReportEngine) polishWithLLM(ctx context.Context, report PostureReport) (string, string, error) {
	prompt := fmt.Sprintf(
		"You are a ShieldNet Gateway security analyst. "+
			"Polish the following security posture summary into a professional executive briefing. "+
			"Do not invent data — only rephrase the evidence provided.\n\n%s",
		report.Overview.SummaryText)

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

package ai

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// CorrelationEngine groups related alerts into incident clusters.
// It uses the configured LLMProvider for cluster summaries (falling
// back to template summaries when nil).
type CorrelationEngine struct {
	llm    LLMProvider
	config CorrelationConfig
}

// NewCorrelationEngine constructs a CorrelationEngine. llm may be
// nil (template-only summaries).
func NewCorrelationEngine(llm LLMProvider, cfg CorrelationConfig) *CorrelationEngine {
	return &CorrelationEngine{
		llm:    llm,
		config: cfg.normalize(),
	}
}

// Analyze correlates a batch of alerts and returns incident clusters.
func (e *CorrelationEngine) Analyze(ctx context.Context, alerts []AlertInput) (CorrelationResult, error) {
	if len(alerts) == 0 {
		return CorrelationResult{}, nil
	}

	sorted := make([]AlertInput, len(alerts))
	copy(sorted, alerts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
	})

	// Deduplicate by position in the sorted slice rather than by alert
	// ID. The id field is optional in the API contract, so callers may
	// omit it (uuid.Nil) on some or all alerts; keying the dedup set on
	// the index keeps every alert distinct without (a) collapsing all
	// nil-ID alerts onto a single key and silently dropping them, or
	// (b) fabricating synthetic IDs that would later be persisted into
	// ai_alert_correlations.alert_ids as dangling references.
	assigned := make([]bool, len(sorted))
	var clusters []CorrelationCluster
	correlated := 0

	for i := range sorted {
		if assigned[i] {
			continue
		}
		anchor := sorted[i]
		group := []AlertInput{anchor}
		assigned[i] = true
		dims := map[CorrelationDimension]bool{}

		for j := i + 1; j < len(sorted); j++ {
			if assigned[j] {
				continue
			}
			candidate := sorted[j]
			if candidate.TenantID != anchor.TenantID {
				continue
			}

			// Temporal proximity is a necessary precondition, not a
			// sufficient one. The slice is sorted ascending by
			// CreatedAt, so once a candidate falls outside the anchor's
			// window every later candidate does too and we can stop.
			// Crucially, closeness in time alone must NOT correlate two
			// otherwise-unrelated alerts: a real correlation also
			// requires a shared entity (device/user/IP) or a shared
			// pattern (same kind). Without this, any pair of alerts
			// within TimeWindow would be clustered, producing very
			// broad, low-signal incidents.
			if candidate.CreatedAt.Sub(anchor.CreatedAt) > e.config.TimeWindow {
				break
			}

			// Entity dimension: shared device, user, or IP.
			sharedEntity := (anchor.DeviceID != "" && anchor.DeviceID == candidate.DeviceID) ||
				(anchor.UserID != "" && anchor.UserID == candidate.UserID) ||
				(anchor.IPAddress != "" && anchor.IPAddress == candidate.IPAddress)

			// Pattern dimension: same alert kind suggests attack chain.
			samePattern := anchor.Kind != "" && anchor.Kind == candidate.Kind

			if !sharedEntity && !samePattern {
				continue
			}

			// Record only the dimensions that actually contributed.
			dims[CorrelationDimensionTemporal] = true
			if sharedEntity {
				dims[CorrelationDimensionEntity] = true
			}
			if samePattern {
				dims[CorrelationDimensionPattern] = true
			}
			group = append(group, candidate)
			assigned[j] = true
		}

		if len(group) < e.config.MinClusterSize {
			continue
		}
		correlated += len(group)

		// Persist only real alert references. Alerts submitted without
		// an ID (uuid.Nil) still count toward the cluster (group size,
		// summary, correlated total) but are not written as dangling
		// UUIDs into alert_ids.
		alertIDs := make([]uuid.UUID, 0, len(group))
		for _, a := range group {
			if a.ID != uuid.Nil {
				alertIDs = append(alertIDs, a.ID)
			}
		}

		dimSlice := make([]CorrelationDimension, 0, len(dims))
		for d := range dims {
			dimSlice = append(dimSlice, d)
		}
		sort.Slice(dimSlice, func(a, b int) bool { return dimSlice[a] < dimSlice[b] })

		severity := escalateSeverity(group)
		summary := e.buildTemplateSummary(group, dimSlice)

		// ID is intentionally left nil: the engine result is ephemeral
		// until a caller persists it, at which point the persisted
		// (retrievable) ID is written back onto the cluster. Assigning
		// an ID here would produce a plausible-looking UUID that a later
		// GET could not resolve.
		cluster := CorrelationCluster{
			TenantID:   anchor.TenantID,
			AlertIDs:   alertIDs,
			Summary:    summary,
			Severity:   severity,
			Status:     "open",
			Dimensions: dimSlice,
			CreatedAt:  anchor.CreatedAt,
		}
		clusters = append(clusters, cluster)
	}

	// AI-polish summaries when LLM is available.
	aiGenerated := false
	if e.llm != nil {
		for i := range clusters {
			polished, err := e.llmSummarize(ctx, clusters[i])
			if err == nil {
				clusters[i].Summary = polished
				aiGenerated = true
			}
		}
	}

	return CorrelationResult{
		Clusters:         clusters,
		TotalAlerts:      len(alerts),
		CorrelatedAlerts: correlated,
		AIGenerated:      aiGenerated,
	}, nil
}

func (e *CorrelationEngine) buildTemplateSummary(group []AlertInput, dims []CorrelationDimension) string {
	kinds := map[string]int{}
	for _, a := range group {
		kinds[a.Kind]++
	}
	var kindStrs []string
	for k, n := range kinds {
		kindStrs = append(kindStrs, fmt.Sprintf("%s(%d)", k, n))
	}
	sort.Strings(kindStrs)

	dimStrs := make([]string, len(dims))
	for i, d := range dims {
		dimStrs[i] = string(d)
	}

	return fmt.Sprintf("Correlated cluster of %d alerts [%s] across dimensions: %s",
		len(group), strings.Join(kindStrs, ", "), strings.Join(dimStrs, ", "))
}

func (e *CorrelationEngine) llmSummarize(ctx context.Context, cluster CorrelationCluster) (string, error) {
	prompt := fmt.Sprintf(
		"You are a ShieldNet Gateway security analyst. "+
			"Summarize the following alert cluster into a concise incident narrative. "+
			"Do not invent data.\n\n"+
			"Cluster: %d alerts, severity=%s, dimensions=%v\n"+
			"Template summary: %s",
		len(cluster.AlertIDs), cluster.Severity, cluster.Dimensions, cluster.Summary)

	resp, err := e.llm.Complete(ctx, LLMRequest{
		Prompt:         prompt,
		TemperatureX10: 3,
		MaxTokens:      300,
	})
	if err != nil {
		return "", err
	}
	return resp.Text, nil
}

// escalateSeverity returns the highest severity in the group, or
// "critical" if the group shows multi-stage attack patterns
// (multiple distinct alert kinds). The returned value is always one of
// the canonical lowercase levels (low/medium/high/critical) so it
// satisfies the AICorrelation severity enum / CHECK constraint
// regardless of the casing callers used on the input alerts.
func escalateSeverity(group []AlertInput) string {
	kinds := map[string]bool{}
	maxSev := "low"
	for _, a := range group {
		kinds[a.Kind] = true
		// severityRank lowercases internally for comparison; store the
		// normalized form so a "High"/"CRITICAL" input doesn't leak its
		// original casing into the persisted (enum-validated) value.
		if severityRank(a.Severity) > severityRank(maxSev) {
			maxSev = strings.ToLower(a.Severity)
		}
	}
	// Multi-stage attack: multiple distinct kinds → escalate.
	if len(kinds) >= 3 {
		return "critical"
	}
	if len(kinds) >= 2 && severityRank(maxSev) < severityRank("high") {
		return "high"
	}
	return maxSev
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

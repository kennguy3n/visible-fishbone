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

	assigned := map[uuid.UUID]bool{}
	var clusters []CorrelationCluster

	for i, anchor := range sorted {
		if assigned[anchor.ID] {
			continue
		}
		group := []AlertInput{anchor}
		assigned[anchor.ID] = true
		dims := map[CorrelationDimension]bool{}

		for j := i + 1; j < len(sorted); j++ {
			candidate := sorted[j]
			if assigned[candidate.ID] {
				continue
			}
			if candidate.TenantID != anchor.TenantID {
				continue
			}

			matched := false

			// Temporal dimension.
			if candidate.CreatedAt.Sub(anchor.CreatedAt) <= e.config.TimeWindow {
				dims[CorrelationDimensionTemporal] = true
				matched = true
			}

			// Entity dimension: shared device, user, or IP.
			if (anchor.DeviceID != "" && anchor.DeviceID == candidate.DeviceID) ||
				(anchor.UserID != "" && anchor.UserID == candidate.UserID) ||
				(anchor.IPAddress != "" && anchor.IPAddress == candidate.IPAddress) {
				dims[CorrelationDimensionEntity] = true
				matched = true
			}

			// Pattern dimension: same alert kind suggests attack chain.
			if anchor.Kind == candidate.Kind && anchor.Kind != "" {
				dims[CorrelationDimensionPattern] = true
				matched = true
			}

			if matched {
				group = append(group, candidate)
				assigned[candidate.ID] = true
			}
		}

		if len(group) < e.config.MinClusterSize {
			continue
		}

		alertIDs := make([]uuid.UUID, len(group))
		for k, a := range group {
			alertIDs[k] = a.ID
		}

		dimSlice := make([]CorrelationDimension, 0, len(dims))
		for d := range dims {
			dimSlice = append(dimSlice, d)
		}
		sort.Slice(dimSlice, func(a, b int) bool { return dimSlice[a] < dimSlice[b] })

		severity := escalateSeverity(group)
		summary := e.buildTemplateSummary(group, dimSlice)

		cluster := CorrelationCluster{
			ID:         uuid.New(),
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
		Clusters:    clusters,
		TotalAlerts: len(alerts),
		AIGenerated: aiGenerated,
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
// (multiple distinct alert kinds).
func escalateSeverity(group []AlertInput) string {
	kinds := map[string]bool{}
	maxSev := "info"
	for _, a := range group {
		kinds[a.Kind] = true
		if severityRank(a.Severity) > severityRank(maxSev) {
			maxSev = a.Severity
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

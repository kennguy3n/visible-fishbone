package ai

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ThreatFeedProvider is the pluggable threat feed interface.
// Production wires up an HTTP-based feed; tests wire up a mock.
type ThreatFeedProvider interface {
	QueryIOCs(ctx context.Context, indicators []string) ([]IOCMatch, error)
}

// IOCMatch represents a single IOC match from a threat feed.
type IOCMatch struct {
	Indicator   string    `json:"indicator"`
	FeedName    string    `json:"feed_name,omitempty"`
	ThreatType  string    `json:"threat_type"` // ip, domain, hash, url
	ThreatActor string    `json:"threat_actor,omitempty"`
	Campaign    string    `json:"campaign,omitempty"`
	Confidence  float64   `json:"confidence"` // 0.0–1.0
	LastSeen    time.Time `json:"last_seen,omitempty"`
}

// ThreatContext is the enrichment result for an alert.
type ThreatContext struct {
	AlertID           uuid.UUID  `json:"alert_id"`
	IOCMatches        []IOCMatch `json:"ioc_matches"`
	ThreatActors      []string   `json:"threat_actors"`
	Campaigns         []string   `json:"campaigns"`
	Confidence        float64    `json:"confidence"`
	EscalatedSeverity string     `json:"escalated_severity"`
}

// EnrichRequest is the input for threat intelligence enrichment.
type EnrichRequest struct {
	AlertID    uuid.UUID `json:"alert_id"`
	TenantID   uuid.UUID `json:"tenant_id"`
	Indicators []string  `json:"indicators"` // IPs, domains, hashes
	Severity   string    `json:"severity"`
}

// ThreatIntelEngine enriches alerts with external threat intelligence.
type ThreatIntelEngine struct {
	feed ThreatFeedProvider
}

// NewThreatIntelEngine constructs a ThreatIntelEngine. feed may be
// nil (enrichment returns empty context).
func NewThreatIntelEngine(feed ThreatFeedProvider) *ThreatIntelEngine {
	return &ThreatIntelEngine{feed: feed}
}

// Enrich processes an enrichment request against the configured
// threat feed.
func (e *ThreatIntelEngine) Enrich(ctx context.Context, req EnrichRequest) (ThreatContext, error) {
	if len(req.Indicators) == 0 {
		return ThreatContext{
			AlertID:           req.AlertID,
			Confidence:        0,
			EscalatedSeverity: req.Severity,
		}, nil
	}

	if e.feed == nil {
		return ThreatContext{
			AlertID:           req.AlertID,
			Confidence:        0,
			EscalatedSeverity: req.Severity,
		}, nil
	}

	matches, err := e.feed.QueryIOCs(ctx, req.Indicators)
	if err != nil {
		return ThreatContext{}, fmt.Errorf("ai/threat_intel: query feed: %w", err)
	}

	actorSet := map[string]bool{}
	campaignSet := map[string]bool{}
	var maxConfidence float64
	for _, m := range matches {
		if m.ThreatActor != "" {
			actorSet[m.ThreatActor] = true
		}
		if m.Campaign != "" {
			campaignSet[m.Campaign] = true
		}
		if m.Confidence > maxConfidence {
			maxConfidence = m.Confidence
		}
	}

	actors := mapKeys(actorSet)
	campaigns := mapKeys(campaignSet)

	escalatedSev := req.Severity
	if maxConfidence >= 0.8 && len(matches) > 0 {
		escalatedSev = escalateThreatSeverity(req.Severity)
	}

	return ThreatContext{
		AlertID:           req.AlertID,
		IOCMatches:        matches,
		ThreatActors:      actors,
		Campaigns:         campaigns,
		Confidence:        maxConfidence,
		EscalatedSeverity: escalatedSev,
	}, nil
}

func escalateThreatSeverity(current string) string {
	switch strings.ToLower(current) {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high":
		return "critical"
	default:
		return current
	}
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

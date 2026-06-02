package ai

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestThreatIntelEngine_NoIndicators(t *testing.T) {
	t.Parallel()
	engine := NewThreatIntelEngine(nil)
	tc, err := engine.Enrich(context.Background(), EnrichRequest{
		AlertID:  uuid.New(),
		TenantID: uuid.New(),
		Severity: "medium",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.EscalatedSeverity != "medium" {
		t.Fatalf("expected medium (unchanged), got %s", tc.EscalatedSeverity)
	}
}

func TestThreatIntelEngine_NoFeed(t *testing.T) {
	t.Parallel()
	engine := NewThreatIntelEngine(nil)
	tc, err := engine.Enrich(context.Background(), EnrichRequest{
		AlertID:    uuid.New(),
		TenantID:   uuid.New(),
		Indicators: []string{"1.2.3.4"},
		Severity:   "medium",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.EscalatedSeverity != "medium" {
		t.Fatalf("expected medium (unchanged) without feed, got %s", tc.EscalatedSeverity)
	}
}

func TestThreatIntelEngine_HighConfidenceEscalation(t *testing.T) {
	t.Parallel()
	feed := &stubThreatFeed{
		matches: []IOCMatch{
			{
				Indicator:   "1.2.3.4",
				ThreatType:  "ip",
				ThreatActor: "APT29",
				Campaign:    "SolarWinds",
				Confidence:  0.95,
				LastSeen:    time.Now(),
			},
		},
	}
	engine := NewThreatIntelEngine(feed)
	tc, err := engine.Enrich(context.Background(), EnrichRequest{
		AlertID:    uuid.New(),
		TenantID:   uuid.New(),
		Indicators: []string{"1.2.3.4"},
		Severity:   "medium",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.EscalatedSeverity != "high" {
		t.Fatalf("expected high severity after escalation, got %s", tc.EscalatedSeverity)
	}
	if len(tc.ThreatActors) != 1 || tc.ThreatActors[0] != "APT29" {
		t.Fatalf("expected threat actor APT29, got %v", tc.ThreatActors)
	}
	if len(tc.Campaigns) != 1 || tc.Campaigns[0] != "SolarWinds" {
		t.Fatalf("expected campaign SolarWinds, got %v", tc.Campaigns)
	}
}

func TestThreatIntelEngine_LowConfidenceNoEscalation(t *testing.T) {
	t.Parallel()
	feed := &stubThreatFeed{
		matches: []IOCMatch{
			{
				Indicator:  "suspicious.com",
				ThreatType: "domain",
				Confidence: 0.3,
				LastSeen:   time.Now(),
			},
		},
	}
	engine := NewThreatIntelEngine(feed)
	tc, err := engine.Enrich(context.Background(), EnrichRequest{
		AlertID:    uuid.New(),
		TenantID:   uuid.New(),
		Indicators: []string{"suspicious.com"},
		Severity:   "low",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.EscalatedSeverity != "low" {
		t.Fatalf("expected low (unchanged) for low confidence, got %s", tc.EscalatedSeverity)
	}
}

func TestThreatIntelEngine_FeedError(t *testing.T) {
	t.Parallel()
	feed := &stubThreatFeed{
		err: errors.New("feed unavailable"),
	}
	engine := NewThreatIntelEngine(feed)
	_, err := engine.Enrich(context.Background(), EnrichRequest{
		AlertID:    uuid.New(),
		TenantID:   uuid.New(),
		Indicators: []string{"1.2.3.4"},
		Severity:   "medium",
	})
	if err == nil {
		t.Fatal("expected error on feed failure")
	}
}

func TestEscalateThreatSeverity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  string
	}{
		{"low", "medium"},
		{"medium", "high"},
		{"high", "critical"},
		{"critical", "critical"},
		{"info", "info"},
	}
	for _, tc := range cases {
		if got := escalateThreatSeverity(tc.input); got != tc.want {
			t.Errorf("escalateThreatSeverity(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- test stubs ---

type stubThreatFeed struct {
	matches []IOCMatch
	err     error
}

func (s *stubThreatFeed) QueryIOCs(_ context.Context, _ []string) ([]IOCMatch, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.matches, nil
}

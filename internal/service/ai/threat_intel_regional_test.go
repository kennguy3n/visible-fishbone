package ai

import (
	"context"
	"errors"
	"testing"
)

func TestRegionalFeed_MatchesSeededIndicator(t *testing.T) {
	feed := NewRegionalFeed(ThreatRegionGCC)
	// Query with surrounding whitespace + mixed case to prove
	// normalization on both the seed and the query side.
	matches, err := feed.QueryIOCs(context.Background(), []string{"  VPN.OilRig.Example.Test  "})
	if err != nil {
		t.Fatalf("QueryIOCs: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	m := matches[0]
	if m.Indicator != "vpn.oilrig.example.test" {
		t.Fatalf("indicator not normalized: %q", m.Indicator)
	}
	if m.FeedName != "regional:GCC" {
		t.Fatalf("feed name = %q, want regional:GCC", m.FeedName)
	}
	if m.ThreatActor == "" || m.Campaign == "" || m.Confidence == 0 {
		t.Fatalf("attribution missing: %+v", m)
	}
	if m.LastSeen.IsZero() {
		t.Fatal("LastSeen should be stamped")
	}
}

func TestRegionalFeed_NoMatchAndEmptyInput(t *testing.T) {
	feed := NewRegionalFeed(ThreatRegionSEA)
	matches, err := feed.QueryIOCs(context.Background(), []string{"8.8.8.8"})
	if err != nil || len(matches) != 0 {
		t.Fatalf("unknown indicator should not match: matches=%d err=%v", len(matches), err)
	}
	matches, err = feed.QueryIOCs(context.Background(), nil)
	if err != nil || matches != nil {
		t.Fatalf("empty input should return nil,nil: matches=%v err=%v", matches, err)
	}
}

func TestRegionalFeed_DeduplicatesQueryIndicators(t *testing.T) {
	feed := NewRegionalFeed(ThreatRegionDACH)
	matches, err := feed.QueryIOCs(context.Background(), []string{"203.0.113.9", "203.0.113.9"})
	if err != nil {
		t.Fatalf("QueryIOCs: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("duplicate query indicators should collapse to 1 match, got %d", len(matches))
	}
}

func TestRegionalFeed_UnknownRegionNeverMatches(t *testing.T) {
	feed := NewRegionalFeed(ThreatRegion("ANTARCTICA"))
	matches, err := feed.QueryIOCs(context.Background(), []string{"198.51.100.21"})
	if err != nil || len(matches) != 0 {
		t.Fatalf("unknown region should have empty catalog: matches=%d err=%v", len(matches), err)
	}
}

func TestMultiFeed_MergesAcrossRegionsSortedByConfidence(t *testing.T) {
	feed := NewRegionalFeeds()
	// One indicator from each region; results must include all three,
	// ordered by descending confidence.
	matches, err := feed.QueryIOCs(context.Background(), []string{
		"198.51.100.21", // SEA APT32, 0.9
		"203.0.113.140", // GCC APT35, 0.72
		"203.0.113.23",  // DACH APT41, 0.86
	})
	if err != nil {
		t.Fatalf("QueryIOCs: %v", err)
	}
	if len(matches) != 3 {
		t.Fatalf("expected 3 matches across regions, got %d", len(matches))
	}
	for i := 1; i < len(matches); i++ {
		if matches[i-1].Confidence < matches[i].Confidence {
			t.Fatalf("matches not sorted by descending confidence: %+v", matches)
		}
	}
}

type errFeed struct{ err error }

func (e errFeed) QueryIOCs(context.Context, []string) ([]IOCMatch, error) { return nil, e.err }

func TestMultiFeed_DegradesOpenWhenSomeFeedsFail(t *testing.T) {
	good := NewRegionalFeed(ThreatRegionSEA)
	bad := errFeed{err: errors.New("feed down")}
	feed := NewMultiFeed(bad, good)

	matches, err := feed.QueryIOCs(context.Background(), []string{"198.51.100.21"})
	if err != nil {
		t.Fatalf("a single failing feed must not fail the query: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("healthy feed result should survive, got %d", len(matches))
	}
}

func TestMultiFeed_FailsClosedWhenAllFeedsFail(t *testing.T) {
	feed := NewMultiFeed(errFeed{err: errors.New("a down")}, errFeed{err: errors.New("b down")})
	if _, err := feed.QueryIOCs(context.Background(), []string{"198.51.100.21"}); err == nil {
		t.Fatal("expected error when every feed fails")
	}
}

func TestMultiFeed_EndToEndEscalationThroughEngine(t *testing.T) {
	engine := NewThreatIntelEngine(NewRegionalFeeds())
	ctx, err := engine.Enrich(context.Background(), EnrichRequest{
		Indicators: []string{"203.0.113.9"}, // DACH Turla, confidence 0.9
		Severity:   "medium",
	})
	if err != nil {
		t.Fatalf("Enrich: %v", err)
	}
	if ctx.EscalatedSeverity != "high" {
		t.Fatalf("high-confidence match should escalate medium->high, got %q", ctx.EscalatedSeverity)
	}
	if len(ctx.ThreatActors) == 0 {
		t.Fatal("expected threat actor attribution in enrichment")
	}
}

package threatfeed

import (
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

func constWeight(w float64) func(string) float64 {
	return func(string) float64 { return w }
}

// weightByName resolves per-source weights, falling back to a low
// default for an unregistered source name.
func weightByName(m map[string]float64, def float64) func(string) float64 {
	return func(s string) float64 {
		if w, ok := m[s]; ok {
			return w
		}
		return def
	}
}

func findIndicator(t *testing.T, in []Indicator, typ, value string) Indicator {
	t.Helper()
	for _, ind := range in {
		if ind.Type == typ && ind.Value == value {
			return ind
		}
	}
	t.Fatalf("indicator %s/%s not found in %+v", typ, value, in)
	return Indicator{}
}

func TestAggregate_SameSourceNotDoubleCounted(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now},
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now},
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	if len(out) != 1 {
		t.Fatalf("got %d indicators, want 1", len(out))
	}
	ind := out[0]
	if len(ind.Sources) != 1 || ind.Sources[0] != "feedA" {
		t.Fatalf("sources = %v, want [feedA]", ind.Sources)
	}
	if !approx(ind.Score, 0.8) {
		t.Fatalf("score = %v, want 0.8 (a feed listing a value twice is not corroboration)", ind.Score)
	}
}

func TestAggregate_DistinctSourcesCorroborate(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now},
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedB", LastSeen: now},
	}
	out := aggregate(iocs, weightByName(map[string]float64{"feedA": 0.8, "feedB": 0.6}, 0.3), now, DefaultHalfLife)
	if len(out) != 1 {
		t.Fatalf("got %d indicators, want 1", len(out))
	}
	ind := out[0]
	if len(ind.Sources) != 2 {
		t.Fatalf("sources = %v, want 2 distinct", ind.Sources)
	}
	want := 1 - (1-0.8)*(1-0.6) // 0.92
	if !approx(ind.Score, want) {
		t.Fatalf("corroborated score = %v, want %v", ind.Score, want)
	}
}

func TestAggregate_RecencyDecay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now.Add(-DefaultHalfLife)},
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	ind := out[0]
	if !approx(ind.Score, 0.8*0.5) {
		t.Fatalf("decayed score = %v, want %v", ind.Score, 0.8*0.5)
	}
}

func TestAggregate_ConfidenceScalesContribution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeURL, Value: "http://evil.example/x", Source: "feedA", Confidence: 0.5, LastSeen: now},
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	ind := out[0]
	if !approx(ind.Score, 0.8*0.5) {
		t.Fatalf("confidence-scaled score = %v, want %v", ind.Score, 0.8*0.5)
	}
}

func TestAggregate_DropsExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now.Add(-48 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{Type: ai.IOCTypeIP, Value: "198.51.100.5", Source: "feedA", LastSeen: now, ExpiresAt: now.Add(time.Hour)},
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	if len(out) != 1 {
		t.Fatalf("got %d indicators, want 1 (expired dropped)", len(out))
	}
	if out[0].Value != "198.51.100.5" {
		t.Fatalf("kept %q, want the unexpired one", out[0].Value)
	}
}

func TestAggregate_NeverExpireWins(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now, ExpiresAt: now.Add(time.Hour)},
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedB", LastSeen: now}, // zero ExpiresAt = never
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	ind := out[0]
	if !ind.ExpiresAt.IsZero() {
		t.Fatalf("ExpiresAt = %v, want zero (any never-expire contributor keeps it alive)", ind.ExpiresAt)
	}
}

func TestAggregate_WidensObservationWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	early := now.Add(-72 * time.Hour)
	late := now.Add(-time.Hour)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", FirstSeen: late, LastSeen: late},
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", FirstSeen: early, LastSeen: early},
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	ind := out[0]
	if !ind.FirstSeen.Equal(early) {
		t.Fatalf("FirstSeen = %v, want earliest %v", ind.FirstSeen, early)
	}
	if !ind.LastSeen.Equal(late) {
		t.Fatalf("LastSeen = %v, want latest %v", ind.LastSeen, late)
	}
}

func TestAggregate_SkipsInvalid(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCType("bogus"), Value: "x", Source: "feedA", LastSeen: now},
		{Type: ai.IOCTypeIP, Value: "", Source: "feedA", LastSeen: now},
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "feedA", LastSeen: now},
	}
	out := aggregate(iocs, constWeight(0.8), now, DefaultHalfLife)
	if len(out) != 1 {
		t.Fatalf("got %d, want 1 (invalid rows skipped)", len(out))
	}
}

func TestAggregate_UnknownSourceFallbackWeight(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	iocs := []ai.IOC{
		{Type: ai.IOCTypeIP, Value: "203.0.113.10", Source: "mystery", LastSeen: now},
	}
	out := aggregate(iocs, weightByName(map[string]float64{"feedA": 0.8}, 0.3), now, DefaultHalfLife)
	ind := findIndicator(t, out, "ip", "203.0.113.10")
	if !approx(ind.Score, 0.3) {
		t.Fatalf("unknown-source score = %v, want fallback 0.3", ind.Score)
	}
}

func TestCapIndicators(t *testing.T) {
	t.Parallel()
	in := []Indicator{
		{Type: "ip", Value: "b", Score: 0.5},
		{Type: "ip", Value: "a", Score: 0.5},
		{Type: "domain", Value: "z", Score: 0.9},
		{Type: "url", Value: "u", Score: 0.1},
	}
	out := capIndicators(in, 2)
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2", len(out))
	}
	if out[0].Score != 0.9 {
		t.Fatalf("top = %+v, want highest score first", out[0])
	}
	// Tie at 0.5: type "ip" both, value "a" < "b".
	if out[1].Value != "a" {
		t.Fatalf("tie-break second = %+v, want value a", out[1])
	}
}

func TestCapIndicators_Unbounded(t *testing.T) {
	t.Parallel()
	in := []Indicator{{Type: "ip", Value: "a", Score: 0.5}}
	if out := capIndicators(in, 0); len(out) != 1 {
		t.Fatalf("max<=0 should be unbounded, got %d", len(out))
	}
	if out := capIndicators(in, 5); len(out) != 1 {
		t.Fatalf("len<=max should be unchanged, got %d", len(out))
	}
}

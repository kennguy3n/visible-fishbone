package ai

import (
	"context"
	"math"
	"testing"
	"time"
)

func mkIOC(t IOCType, v string, conf float64, opts ...func(*IOC)) IOC {
	ioc, ok := NewIOC(t, v, IOCMeta{Source: "test", Confidence: conf})
	if !ok {
		panic("mkIOC: invalid indicator " + v)
	}
	for _, o := range opts {
		o(&ioc)
	}
	return ioc
}

func TestIOCStore_DedupMergesHigherConfidenceAndLaterLastSeen(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	t0 := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Hour)

	res := store.Upsert(
		mkIOC(IOCTypeDomain, "evil.example.com", 0.6, func(i *IOC) {
			i.LastSeen = t0
			i.ThreatActor = "APT29"
		}),
	)
	if res.Added != 1 {
		t.Fatalf("first upsert: %#v", res)
	}
	// Same indicator, higher confidence + later LastSeen, but no
	// actor — the merge must keep the existing actor.
	res = store.Upsert(
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9, func(i *IOC) { i.LastSeen = t1 }),
	)
	if res.Updated != 1 || res.Added != 0 {
		t.Fatalf("merge upsert: %#v", res)
	}
	if store.Len() != 1 {
		t.Fatalf("dedup failed: len=%d", store.Len())
	}
	snap := store.Snapshot()
	got := snap.Domains[0]
	if got.Confidence != 0.9 {
		t.Errorf("confidence not merged up: %v", got.Confidence)
	}
	if !got.LastSeen.Equal(t1) {
		t.Errorf("LastSeen not advanced: %v", got.LastSeen)
	}
	if got.ThreatActor != "APT29" {
		t.Errorf("attribution lost on merge: %q", got.ThreatActor)
	}
}

func TestIOCStore_MinConfidenceFloorDropsNoise(t *testing.T) {
	t.Parallel()
	store := NewIOCStore(WithMinConfidence(0.5))
	res := store.Upsert(
		mkIOC(IOCTypeIP, "203.0.113.1", 0.4), // below floor
		mkIOC(IOCTypeIP, "203.0.113.2", 0.6), // admitted
	)
	if res.Added != 1 || res.Skipped != 1 {
		t.Fatalf("floor tally: %#v", res)
	}
}

// TestConfidenceNaNInfNormalized guards the clampConfidence hardening:
// a NaN confidence (or a NaN floor from a misconfigured
// THREATINTEL_MIN_CONFIDENCE) must collapse to a well-ordered number
// rather than poisoning every `confidence < floor` comparison (all
// comparisons against NaN are false in IEEE 754). NaN -> 0, +Inf -> 1.
func TestConfidenceNaNInfNormalized(t *testing.T) {
	t.Parallel()
	nan := math.NaN()
	if got := clampConfidence(nan); got != 0 {
		t.Errorf("clampConfidence(NaN) = %v, want 0", got)
	}
	if got := clampConfidence(math.Inf(1)); got != 1 {
		t.Errorf("clampConfidence(+Inf) = %v, want 1", got)
	}
	if got := clampConfidence(math.Inf(-1)); got != 0 {
		t.Errorf("clampConfidence(-Inf) = %v, want 0", got)
	}

	// A NaN store floor must not silently admit everything: it
	// degrades to 0 (the documented default), so an indicator with
	// real confidence is still admitted and a NaN-confidence
	// indicator is normalized to 0 (and dropped by any positive
	// floor).
	store := NewIOCStore(WithMinConfidence(nan))
	res := store.Upsert(mkIOC(IOCTypeIP, "203.0.113.9", 0.7))
	if res.Added != 1 {
		t.Fatalf("NaN floor should degrade to 0 and admit real IOCs: %#v", res)
	}
	ioc := mkIOC(IOCTypeIP, "203.0.113.10", nan)
	if ioc.Confidence != 0 {
		t.Errorf("NaN confidence not normalized: %v", ioc.Confidence)
	}
}

func TestIOCStore_ExpiryAndSweep(t *testing.T) {
	t.Parallel()
	now := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	cur := now
	store := NewIOCStore(withStoreClock(func() time.Time { return cur }))
	store.Upsert(
		mkIOC(IOCTypeIP, "203.0.113.3", 0.9, func(i *IOC) { i.ExpiresAt = now.Add(time.Hour) }),
		mkIOC(IOCTypeIP, "203.0.113.4", 0.9), // permanent (zero ExpiresAt)
	)
	if store.Len() != 2 {
		t.Fatalf("pre-expiry len=%d", store.Len())
	}
	// Advance past the first IOC's TTL: it must drop out of active
	// views but only Sweep physically deletes it.
	cur = now.Add(2 * time.Hour)
	if store.Len() != 1 {
		t.Fatalf("expired IOC still active: len=%d", store.Len())
	}
	if removed := store.Sweep(); removed != 1 {
		t.Fatalf("sweep removed=%d want 1", removed)
	}
	if store.Len() != 1 {
		t.Fatalf("post-sweep len=%d", store.Len())
	}
}

func TestIOCStore_QueryIOCsMatchesNormalizedLiveTraffic(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(
		mkIOC(IOCTypeDomain, "evil.example.com", 0.9),
		mkIOC(IOCTypeIP, "203.0.113.10", 0.8),
	)
	// A raw, un-pre-classified query (mixed case domain) must match.
	matches, err := store.QueryIOCs(context.Background(), []string{"EVIL.example.com", "203.0.113.10", "clean.example.org"})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches, got %d (%#v)", len(matches), matches)
	}
	// Highest confidence sorts first.
	if matches[0].Indicator != "evil.example.com" || matches[0].Confidence != 0.9 {
		t.Errorf("match order/content: %#v", matches[0])
	}
}

func TestIOCStore_ImplementsThreatFeedProvider(t *testing.T) {
	t.Parallel()
	var _ ThreatFeedProvider = NewIOCStore()
}

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

// TestNormalizeDomainRejectsIPLiterals guards that an IP literal is
// not canonicalized as a domain (which would add a phantom domain
// key in candidateKeys and let NewIOC mis-store an IP under a domain
// key), while real hostnames and wildcard/trailing-dot forms still
// normalize.
func TestNormalizeDomainRejectsIPLiterals(t *testing.T) {
	t.Parallel()
	rejects := []string{
		"203.0.113.10",        // IPv4 dotted-quad
		"::ffff:203.0.113.10", // IPv6 (also has ':')
		"2001:db8::1",         // IPv6
		"255.255.255.255",     // IPv4 broadcast
	}
	for _, in := range rejects {
		if got, ok := normalizeDomain(in); ok {
			t.Errorf("normalizeDomain(%q) = (%q, true), want rejected", in, got)
		}
	}
	accepts := map[string]string{
		"EVIL.com":      "evil.com",
		"*.evil.com.":   "evil.com",
		"a.b.example":   "a.b.example",
		"1.2.3.example": "1.2.3.example", // numeric labels but not an IP
	}
	for in, want := range accepts {
		got, ok := normalizeDomain(in)
		if !ok || got != want {
			t.Errorf("normalizeDomain(%q) = (%q, %v), want (%q, true)", in, got, ok, want)
		}
	}

	// candidateKeys for an IP must yield the IP key only, no domain key.
	for _, k := range candidateKeys("203.0.113.10") {
		if k == string(IOCTypeDomain)+"\x00203.0.113.10" {
			t.Errorf("candidateKeys produced a phantom domain key for an IP: %q", k)
		}
	}
}

// TestNormalizeCIDR guards the CIDR canonicalizer: it must mask off
// host bits, lowercase IPv6, and reject anything that is not a
// prefix-bearing range — in particular a bare address (which is a
// single IP and belongs under IOCTypeIP), so the two types stay
// disjoint.
func TestNormalizeCIDR(t *testing.T) {
	t.Parallel()
	accepts := map[string]string{
		"203.0.113.10/24": "203.0.113.0/24",  // host bits masked off
		"198.51.100.0/24": "198.51.100.0/24", // already canonical
		"10.0.0.0/8":      "10.0.0.0/8",
		"2001:DB8::1/32":  "2001:db8::/32", // IPv6 lowercased + masked
		"203.0.113.10/32": "203.0.113.10/32",
	}
	for in, want := range accepts {
		got, ok := normalizeCIDR(in)
		if !ok || got != want {
			t.Errorf("normalizeCIDR(%q) = (%q, %v), want (%q, true)", in, got, ok, want)
		}
	}
	rejects := []string{
		"203.0.113.10", // bare IPv4 -> belongs to IOCTypeIP
		"2001:db8::1",  // bare IPv6 -> belongs to IOCTypeIP
		"not-a-cidr",   // garbage
		"203.0.113.0/", // malformed prefix
		"",             // empty
	}
	for _, in := range rejects {
		if got, ok := normalizeCIDR(in); ok {
			t.Errorf("normalizeCIDR(%q) = (%q, true), want rejected", in, got)
		}
	}

	// A range must classify as IOCTypeCIDR (not domain or IP), and a
	// bare IP must NOT classify as a CIDR.
	if typ, ok := classifyIndicator("10.0.0.0/8"); !ok || typ != IOCTypeCIDR {
		t.Errorf("classifyIndicator(CIDR) = (%v, %v), want (cidr, true)", typ, ok)
	}
	if typ, _ := classifyIndicator("203.0.113.10"); typ == IOCTypeCIDR {
		t.Errorf("bare IP must not classify as CIDR")
	}

	// NewIOC stores a range under the CIDR type with the canonical
	// masked value; a bare IP is rejected for the CIDR type.
	if ioc, ok := NewIOC(IOCTypeCIDR, "203.0.113.10/24", IOCMeta{Confidence: 0.9}); !ok || ioc.Value != "203.0.113.0/24" {
		t.Errorf("NewIOC(CIDR) = (%#v, %v), want masked 203.0.113.0/24", ioc, ok)
	}
	if _, ok := NewIOC(IOCTypeCIDR, "203.0.113.10", IOCMeta{Confidence: 0.9}); ok {
		t.Errorf("NewIOC(CIDR, bare IP) must be rejected")
	}
}

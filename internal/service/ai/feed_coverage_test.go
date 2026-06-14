package ai

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestSizeBySourceReconcilesWithSizeByType verifies the per-source
// breakdown sums (across sources, per type and in total) back to the
// aggregate SizeByType so the two views can never disagree.
func TestSizeBySourceReconcilesWithSizeByType(t *testing.T) {
	t.Parallel()
	store := NewIOCStore()
	store.Upsert(
		IOC{Type: IOCTypeDomain, Value: "a.example.com", Source: "feedA", Confidence: 0.9},
		IOC{Type: IOCTypeDomain, Value: "b.example.com", Source: "feedA", Confidence: 0.9},
		IOC{Type: IOCTypeIP, Value: "203.0.113.5", Source: "feedB", Confidence: 0.9},
		IOC{Type: IOCTypeHash, Value: "0123456789abcdef0123456789abcdef", Source: "feedB", Confidence: 0.9},
	)

	bySource := store.SizeBySource()
	if got := bySource["feedA"].Domains; got != 2 {
		t.Errorf("feedA domains = %d, want 2", got)
	}
	if got := bySource["feedA"].Total; got != 2 {
		t.Errorf("feedA total = %d, want 2", got)
	}
	if got := bySource["feedB"].IPs; got != 1 {
		t.Errorf("feedB ips = %d, want 1", got)
	}
	if got := bySource["feedB"].Hashes; got != 1 {
		t.Errorf("feedB hashes = %d, want 1", got)
	}

	// Sum across sources must equal the aggregate view exactly.
	var sum IOCCounts
	for _, c := range bySource {
		sum.Domains += c.Domains
		sum.IPs += c.IPs
		sum.CIDRs += c.CIDRs
		sum.URLs += c.URLs
		sum.Hashes += c.Hashes
		sum.JA3s += c.JA3s
		sum.Total += c.Total
	}
	if want := store.SizeByType(); sum != want {
		t.Errorf("per-source sum = %+v, want SizeByType %+v", sum, want)
	}
}

// TestSizeBySourceExcludesExpired verifies an expired indicator drops
// out of the per-source view (matching SizeByType / Snapshot).
func TestSizeBySourceExcludesExpired(t *testing.T) {
	t.Parallel()
	start := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	cur := start
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}
	store := NewIOCStore(withStoreClock(clock))
	store.Upsert(IOC{
		Type:       IOCTypeDomain,
		Value:      "ephemeral.example.com",
		Source:     "feedA",
		Confidence: 0.9,
		ExpiresAt:  start.Add(time.Hour),
	})
	if got := store.SizeBySource()["feedA"].Total; got != 1 {
		t.Fatalf("pre-expiry total = %d, want 1", got)
	}

	mu.Lock()
	cur = start.Add(2 * time.Hour)
	mu.Unlock()
	if got := store.SizeBySource()["feedA"].Total; got != 0 {
		t.Errorf("post-expiry total = %d, want 0", got)
	}
}

// TestFeedManagerCoverageComposesHealthAndStore verifies Coverage
// stitches per-feed health together with the live store cardinality
// (aggregate and per-source) at the requested instant.
func TestFeedManagerCoverageComposesHealthAndStore(t *testing.T) {
	t.Parallel()
	start := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	cur := start
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}
	store := NewIOCStore(withStoreClock(clock))
	feeds := []Feed{{
		Name:     "alpha",
		Interval: time.Hour,
		Parser:   CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.9},
		Fetcher:  StaticFetcher{Data: []byte("bad.example.com\n203.0.113.5\n")},
	}}
	mgr := NewFeedManager(store, feeds,
		withManagerClock(clock),
		WithStaleFactor(3.0),
	)
	if _, err := mgr.RunFeedOnce(context.Background(), feeds[0]); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	cov := mgr.Coverage(clock())
	if !cov.GeneratedAt.Equal(start) {
		t.Errorf("GeneratedAt = %v, want %v", cov.GeneratedAt, start)
	}
	if len(cov.Feeds) != 1 || cov.Feeds[0].Name != "alpha" {
		t.Fatalf("Feeds = %+v, want one feed 'alpha'", cov.Feeds)
	}
	if cov.Feeds[0].Stale {
		t.Errorf("alpha should not be stale immediately after a success")
	}
	if cov.Store.Domains != 1 || cov.Store.IPs != 1 || cov.Store.Total != 2 {
		t.Errorf("Store = %+v, want Domains=1 IPs=1 Total=2", cov.Store)
	}
	// The CSVParser stamps its own source label ("csv") on every
	// indicator it emits, so the per-source view is keyed under that.
	if got := cov.BySource["csv"].Total; got != 2 {
		t.Errorf("BySource[csv].Total = %d, want 2 (keys: %v)", got, cov.BySource)
	}

	// Past the staleness window the same view reports the feed stale
	// without touching the store cardinality.
	mu.Lock()
	cur = start.Add(4 * time.Hour)
	mu.Unlock()
	cov = mgr.Coverage(clock())
	if !cov.Feeds[0].Stale {
		t.Errorf("alpha should be stale 4h after its only success (3h window)")
	}
	if cov.Store.Total != 2 {
		t.Errorf("Store.Total = %d, want 2 (staleness must not change cardinality)", cov.Store.Total)
	}
}

// TestFeedManagerDomainIndicators verifies the DNS-bundle bridge:
// DomainIndicators returns only domain IOC values, applies the
// enforcement-confidence gate on top of the store, and excludes IPs /
// other types and expired indicators.
func TestFeedManagerDomainIndicators(t *testing.T) {
	t.Parallel()
	start := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	cur := start
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}
	store := NewIOCStore(withStoreClock(clock))
	store.Upsert(
		IOC{Type: IOCTypeDomain, Value: "evil.example.com", Source: "misp", Confidence: 0.9},
		IOC{Type: IOCTypeDomain, Value: "low.example.com", Source: "misp", Confidence: 0.2},
		IOC{Type: IOCTypeIP, Value: "203.0.113.5", Source: "misp", Confidence: 0.9},
		IOC{Type: IOCTypeDomain, Value: "gone.example.com", Source: "misp", Confidence: 0.9, ExpiresAt: start.Add(time.Hour)},
	)
	mgr := NewFeedManager(store, nil, withManagerClock(clock))

	// Gate at 0.5 keeps the high-confidence domain, drops the
	// low-confidence one, and never includes the IP.
	got := mgr.DomainIndicators(0.5)
	if len(got) != 2 {
		t.Fatalf("DomainIndicators(0.5) = %v, want 2 (evil + gone)", got)
	}
	for _, d := range got {
		if d == "203.0.113.5" {
			t.Fatalf("DomainIndicators must not return IPs: %v", got)
		}
		if d == "low.example.com" {
			t.Fatalf("DomainIndicators(0.5) must drop sub-threshold domain: %v", got)
		}
	}

	// Past expiry, the expired domain drops out.
	mu.Lock()
	cur = start.Add(2 * time.Hour)
	mu.Unlock()
	got = mgr.DomainIndicators(0.5)
	if len(got) != 1 || got[0] != "evil.example.com" {
		t.Fatalf("post-expiry DomainIndicators(0.5) = %v, want [evil.example.com]", got)
	}
}

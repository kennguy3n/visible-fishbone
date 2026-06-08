package ai

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recordingObserver captures FeedObserver callbacks for assertions.
type recordingObserver struct {
	mu        sync.Mutex
	refreshes []refreshCall
	stale     map[string]bool
	sizes     []IOCCounts
}

type refreshCall struct {
	feed string
	res  UpsertResult
	err  error
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{stale: map[string]bool{}}
}

func (o *recordingObserver) ObserveRefresh(feed string, res UpsertResult, err error, _ time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.refreshes = append(o.refreshes, refreshCall{feed: feed, res: res, err: err})
}

func (o *recordingObserver) ObserveStale(feed string, stale bool, _ time.Time, _ time.Time) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.stale[feed] = stale
}

func (o *recordingObserver) ObserveStoreSize(c IOCCounts) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.sizes = append(o.sizes, c)
}

func (o *recordingObserver) staleOf(feed string) (bool, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	v, ok := o.stale[feed]
	return v, ok
}

func (o *recordingObserver) lastSize() (IOCCounts, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.sizes) == 0 {
		return IOCCounts{}, false
	}
	return o.sizes[len(o.sizes)-1], true
}

// TestFeedHealthStalenessThreshold verifies the staleFactor x interval
// staleness window for both a freshly-refreshed feed and one that has
// never succeeded (measured from the manager's construction time).
func TestFeedHealthStalenessThreshold(t *testing.T) {
	t.Parallel()
	start := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	cur := start
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return cur
	}
	store := NewIOCStore(withStoreClock(clock))
	interval := time.Hour
	feeds := []Feed{
		{
			Name:     "fresh",
			Interval: interval,
			Parser:   CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.9},
			Fetcher:  StaticFetcher{Data: []byte("evil.example.com\n")},
		},
		{
			Name:     "never",
			Interval: interval,
			Parser:   CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.9},
			Fetcher:  StaticFetcher{Err: context.DeadlineExceeded},
		},
	}
	mgr := NewFeedManager(store, feeds,
		withManagerClock(clock),
		WithStaleFactor(3.0),
	)

	// fresh feed succeeds at t=start, so LastSuccessAt = start.
	if _, err := mgr.RunFeedOnce(context.Background(), feeds[0]); err != nil {
		t.Fatalf("fresh refresh: %v", err)
	}

	healthAt := func(d time.Duration) map[string]FeedHealth {
		nowMu.Lock()
		cur = start.Add(d)
		nowMu.Unlock()
		out := map[string]FeedHealth{}
		for _, h := range mgr.Health(clock()) {
			out[h.Name] = h
		}
		return out
	}

	// Just inside the 3h window: neither feed is stale.
	h := healthAt(2 * time.Hour)
	if h["fresh"].Stale {
		t.Errorf("fresh feed stale at 2h (< 3h threshold)")
	}
	if h["never"].Stale {
		t.Errorf("never feed stale at 2h from start (< 3h threshold)")
	}
	if want := 3 * time.Hour; h["fresh"].Threshold != want {
		t.Errorf("threshold = %v, want %v", h["fresh"].Threshold, want)
	}

	// Past the 3h window: both go stale (fresh from its success,
	// never from manager construction time).
	h = healthAt(4 * time.Hour)
	if !h["fresh"].Stale {
		t.Errorf("fresh feed should be stale at 4h (> 3h threshold)")
	}
	if !h["never"].Stale {
		t.Errorf("never-succeeded feed should be stale at 4h from start")
	}
	if !h["never"].LastSuccessAt.IsZero() {
		t.Errorf("never feed LastSuccessAt should be zero, got %v", h["never"].LastSuccessAt)
	}
}

// TestReportHealthDrivesObserver verifies reportHealth publishes
// per-feed staleness and store-size telemetry to the observer.
func TestReportHealthDrivesObserver(t *testing.T) {
	t.Parallel()
	start := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	var nowMu sync.Mutex
	cur := start
	clock := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return cur
	}
	store := NewIOCStore(withStoreClock(clock))
	obs := newRecordingObserver()
	feeds := []Feed{
		{
			Name:     "alpha",
			Interval: time.Hour,
			Parser:   CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.9},
			Fetcher:  StaticFetcher{Data: []byte("bad.example.com\n203.0.113.5\n")},
		},
	}
	mgr := NewFeedManager(store, feeds,
		withManagerClock(clock),
		WithFeedObserver(obs),
		WithStaleFactor(3.0),
	)

	// Ingest so the store is non-empty and the feed has a success.
	if _, err := mgr.RunFeedOnce(context.Background(), feeds[0]); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got := len(obs.refreshes); got != 1 {
		t.Fatalf("ObserveRefresh calls = %d, want 1", got)
	}

	// Health tick within the window: not stale, store size reported.
	mgr.reportHealth(context.Background())
	if stale, ok := obs.staleOf("alpha"); !ok || stale {
		t.Errorf("alpha stale=%v ok=%v, want false/true", stale, ok)
	}
	sz, ok := obs.lastSize()
	if !ok {
		t.Fatal("ObserveStoreSize never called")
	}
	if sz.Domains != 1 || sz.IPs != 1 || sz.Total != 2 {
		t.Errorf("store size = %+v, want Domains=1 IPs=1 Total=2", sz)
	}

	// Advance past the staleness window and re-evaluate.
	nowMu.Lock()
	cur = start.Add(4 * time.Hour)
	nowMu.Unlock()
	mgr.reportHealth(context.Background())
	if stale, _ := obs.staleOf("alpha"); !stale {
		t.Errorf("alpha should be stale after 4h")
	}
}

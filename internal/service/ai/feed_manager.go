package ai

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// FeedManager runs the configured threat feeds on their schedules,
// folding every ingest into a single shared IOCStore. It is the
// aggregator the workstream calls for: each Feed refreshes on its
// own cadence (default hourly), parsed IOCs are normalized,
// confidence-filtered, TTL-stamped, de-duplicated into the store,
// and — after every successful refresh — an optional OnUpdate hook
// fires so the enforcement layer can recompile the policy bundle
// and malware list from the new snapshot.
//
// Lifecycle mirrors the existing ai.Scheduler: Start launches one
// goroutine per feed plus a sweeper; Stop is idempotent and waits
// for them to drain. RunFeedOnce / RunOnce expose a single
// synchronous refresh for tests and for an initial warm-up before
// the tickers take over.
type FeedManager struct {
	feeds    []Feed
	store    *IOCStore
	logger   *slog.Logger
	now      func() time.Time
	onUpdate func(context.Context, IOCSnapshot)

	// sweepInterval controls how often expired IOCs are reaped.
	// Zero applies defaultSweepInterval.
	sweepInterval time.Duration

	metrics   feedMetrics
	stopCh    chan struct{}
	doneCh    chan struct{}
	wg        sync.WaitGroup
	stopOnce  sync.Once
	startOnce sync.Once
	started   atomic.Bool
}

const defaultSweepInterval = 10 * time.Minute

// FeedManagerOption configures a FeedManager.
type FeedManagerOption func(*FeedManager)

// WithFeedLogger sets the logger. Defaults to slog.Default().
func WithFeedLogger(logger *slog.Logger) FeedManagerOption {
	return func(m *FeedManager) {
		if logger != nil {
			m.logger = logger
		}
	}
}

// WithOnUpdate registers a hook invoked with a fresh store
// Snapshot after every successful feed refresh. This is the seam
// the IOC->enforcement pipeline attaches to (recompile policy
// bundle, install malware hashes, emit demotion events).
func WithOnUpdate(fn func(context.Context, IOCSnapshot)) FeedManagerOption {
	return func(m *FeedManager) { m.onUpdate = fn }
}

// WithSweepInterval overrides the expired-IOC reap cadence.
func WithSweepInterval(d time.Duration) FeedManagerOption {
	return func(m *FeedManager) {
		if d > 0 {
			m.sweepInterval = d
		}
	}
}

// withManagerClock overrides the clock (tests).
func withManagerClock(now func() time.Time) FeedManagerOption {
	return func(m *FeedManager) {
		if now != nil {
			m.now = now
		}
	}
}

// NewFeedManager constructs a manager over the given store and
// feeds.
func NewFeedManager(store *IOCStore, feeds []Feed, opts ...FeedManagerOption) *FeedManager {
	m := &FeedManager{
		feeds:         feeds,
		store:         store,
		logger:        slog.Default(),
		now:           time.Now,
		sweepInterval: defaultSweepInterval,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// feedMetrics tracks per-manager ingest telemetry.
type feedMetrics struct {
	mu            sync.Mutex
	totalRuns     int64
	totalErrors   int64
	totalIngested int64
	lastRunAt     time.Time
	perFeed       map[string]*FeedStat
}

// FeedStat is the public per-feed telemetry snapshot.
type FeedStat struct {
	Runs      int64
	Errors    int64
	Added     int64
	Updated   int64
	Skipped   int64
	LastRunAt time.Time
	LastErr   string
}

func (fm *feedMetrics) record(feed string, res UpsertResult, err error, at time.Time) {
	fm.mu.Lock()
	defer fm.mu.Unlock()
	if fm.perFeed == nil {
		fm.perFeed = map[string]*FeedStat{}
	}
	st := fm.perFeed[feed]
	if st == nil {
		st = &FeedStat{}
		fm.perFeed[feed] = st
	}
	fm.totalRuns++
	st.Runs++
	st.LastRunAt = at
	fm.lastRunAt = at
	if err != nil {
		fm.totalErrors++
		st.Errors++
		st.LastErr = err.Error()
		return
	}
	st.LastErr = ""
	st.Added += int64(res.Added)
	st.Updated += int64(res.Updated)
	st.Skipped += int64(res.Skipped)
	fm.totalIngested += int64(res.Added + res.Updated)
}

// Stats returns a per-feed telemetry snapshot.
func (m *FeedManager) Stats() map[string]FeedStat {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()
	out := make(map[string]FeedStat, len(m.metrics.perFeed))
	for k, v := range m.metrics.perFeed {
		out[k] = *v
	}
	return out
}

// RunFeedOnce performs a single synchronous refresh of one feed:
// fetch -> parse -> normalize TTL/confidence -> upsert. It returns
// the upsert tally and any fetch/parse error. A parse that yields
// some IOCs and skips malformed rows is not an error. This method
// does NOT fire the OnUpdate hook (callers that need the hook use
// RunOnce, which fires it once after refreshing all feeds).
func (m *FeedManager) RunFeedOnce(ctx context.Context, feed Feed) (UpsertResult, error) {
	at := m.now().UTC()
	raw, err := feed.Fetcher.Fetch(ctx)
	if err != nil {
		wrapped := fmt.Errorf("feed %q fetch: %w", feed.Name, err)
		m.metrics.record(feed.Name, UpsertResult{}, wrapped, at)
		return UpsertResult{}, wrapped
	}
	iocs, err := feed.Parser.Parse(raw)
	if err != nil {
		wrapped := fmt.Errorf("feed %q parse: %w", feed.Name, err)
		m.metrics.record(feed.Name, UpsertResult{}, wrapped, at)
		return UpsertResult{}, wrapped
	}
	m.applyFeedDefaults(feed, iocs, at)
	res := m.store.Upsert(iocs...)
	m.metrics.record(feed.Name, res, nil, at)
	return res, nil
}

// applyFeedDefaults stamps per-feed Source / TTL defaults and
// drops IOCs below the feed's MinConfidence. Mutates iocs in
// place. The Source default lets a feed override the parser's
// label; the TTL default turns a feed-level retention window into
// a concrete ExpiresAt for indicators the upstream did not date.
func (m *FeedManager) applyFeedDefaults(feed Feed, iocs []IOC, at time.Time) {
	for i := range iocs {
		if iocs[i].Source == "" {
			iocs[i].Source = feed.Name
		}
		if iocs[i].LastSeen.IsZero() {
			iocs[i].LastSeen = at
		}
		if feed.DefaultTTL > 0 && iocs[i].ExpiresAt.IsZero() {
			iocs[i].ExpiresAt = at.Add(feed.DefaultTTL)
		}
		if feed.MinConfidence > 0 && iocs[i].Confidence < feed.MinConfidence {
			// Mark for skip by zeroing the value; Upsert drops
			// empty-value IOCs. Done in-place to avoid a second
			// allocation.
			iocs[i].Value = ""
		}
	}
}

// RunOnce refreshes every feed once (sequentially, so one slow or
// failing feed cannot starve the others of the store lock) and
// fires the OnUpdate hook a single time afterwards if any feed
// succeeded. It returns the joined error of all feed failures;
// a partial failure still updates the store and fires the hook
// (degrade-open), matching the MultiFeed contract.
func (m *FeedManager) RunOnce(ctx context.Context) error {
	var (
		errs  []error
		anyOK bool
	)
	for _, feed := range m.feeds {
		if _, err := m.RunFeedOnce(ctx, feed); err != nil {
			errs = append(errs, err)
			if m.logger != nil {
				m.logger.WarnContext(ctx, "threat-intel: feed refresh failed; degrading open",
					"feed", feed.Name, "error", err)
			}
			continue
		}
		anyOK = true
	}
	if anyOK {
		m.fireUpdate(ctx)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (m *FeedManager) fireUpdate(ctx context.Context) {
	if m.onUpdate == nil {
		return
	}
	m.onUpdate(ctx, m.store.Snapshot())
}

// Start launches one ticker goroutine per feed plus a sweeper.
// Non-blocking and idempotent. Each feed refreshes immediately on
// start (warm-up) and then on its configured interval.
func (m *FeedManager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		m.started.Store(true)
		for _, feed := range m.feeds {
			m.wg.Add(1)
			go m.runFeedLoop(ctx, feed)
		}
		m.wg.Add(1)
		go m.runSweepLoop(ctx)
		go func() {
			m.wg.Wait()
			close(m.doneCh)
		}()
	})
}

func (m *FeedManager) runFeedLoop(ctx context.Context, feed Feed) {
	defer m.wg.Done()
	// Warm-up refresh so the store is populated before the first
	// tick; fire the hook after it so enforcement reflects the
	// initial load promptly.
	if _, err := m.RunFeedOnce(ctx, feed); err == nil {
		m.fireUpdate(ctx)
	} else if m.logger != nil {
		m.logger.WarnContext(ctx, "threat-intel: initial feed refresh failed",
			"feed", feed.Name, "error", err)
	}
	ticker := time.NewTicker(feed.effectiveInterval())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			if _, err := m.RunFeedOnce(ctx, feed); err != nil {
				if m.logger != nil {
					m.logger.WarnContext(ctx, "threat-intel: scheduled feed refresh failed",
						"feed", feed.Name, "error", err)
				}
				continue
			}
			m.fireUpdate(ctx)
		}
	}
}

func (m *FeedManager) runSweepLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			if removed := m.store.Sweep(); removed > 0 {
				if m.logger != nil {
					m.logger.DebugContext(ctx, "threat-intel: swept expired IOCs", "removed", removed)
				}
				// An expiry changes the active set; refresh
				// enforcement so dropped IOCs stop being enforced.
				m.fireUpdate(ctx)
			}
		}
	}
}

// Stop signals all loops to exit and waits for them. Idempotent;
// safe to call before Start (no-op wait).
func (m *FeedManager) Stop() {
	m.stopOnce.Do(func() { close(m.stopCh) })
	if m.started.Load() {
		<-m.doneCh
	}
}

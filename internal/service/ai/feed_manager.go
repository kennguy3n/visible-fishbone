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
	observer FeedObserver

	// sweepInterval controls how often expired IOCs are reaped.
	// Zero applies defaultSweepInterval.
	sweepInterval time.Duration
	// healthInterval controls how often per-feed staleness/health
	// is evaluated and published. Zero applies defaultHealthInterval.
	healthInterval time.Duration
	// staleFactor multiplies a feed's refresh interval to derive the
	// staleness threshold (a feed is stale if it has not refreshed
	// successfully within staleFactor x its interval). Zero applies
	// defaultStaleFactor.
	staleFactor float64
	// startedAt is the manager's construction time, used as the
	// staleness baseline for feeds that have never refreshed yet so a
	// feed that never comes up is eventually reported stale.
	startedAt time.Time

	// persister, when set, durably snapshots the active IOC set so
	// a restart does not start from an empty store. persistInterval
	// is the flush cadence; a final flush also runs on shutdown.
	persister       IOCPersister
	persistInterval time.Duration
	// isLeader, when set, gates the PERIODIC persist write so only
	// the elected leader flushes the shared snapshot table in a
	// multi-replica deployment. Nil means persist from every
	// replica. Restore (a read) and the shutdown flush are never
	// gated.
	isLeader func() bool

	metrics   feedMetrics
	stopCh    chan struct{}
	doneCh    chan struct{}
	wg        sync.WaitGroup
	stopOnce  sync.Once
	startOnce sync.Once
	started   atomic.Bool
}

const (
	defaultSweepInterval  = 10 * time.Minute
	defaultHealthInterval = time.Minute
	// defaultStaleFactor flags a feed stale once it has gone three
	// refresh intervals without a successful refresh — long enough to
	// ride out a single transient fetch failure (feeds degrade open),
	// short enough that a feed wedged by an auth expiry or endpoint
	// change surfaces within a few intervals rather than silently.
	defaultStaleFactor = 3.0
	// defaultPersistInterval is the IOC-store flush cadence when a
	// persister is configured without an explicit interval.
	defaultPersistInterval = 5 * time.Minute
	// persistFlushTimeout bounds the final shutdown flush, which
	// runs on a fresh context because the parent is already
	// cancelled by the time the loops drain.
	persistFlushTimeout = 10 * time.Second
)

// FeedObserver receives feed-ingest and feed-health telemetry so a
// metrics backend (or a test) can observe the manager without the
// ai package importing it. Implementations must be safe for
// concurrent use: ObserveRefresh fires from each feed goroutine,
// while ObserveStale / ObserveStoreSize fire from the single health
// loop.
type FeedObserver interface {
	// ObserveRefresh is called after every feed refresh attempt with
	// the upsert tally (zero on failure) and the refresh error (nil
	// on success).
	ObserveRefresh(feed string, res UpsertResult, err error, at time.Time)
	// ObserveStale is called once per feed on each health tick with
	// the feed's current staleness and the time of its last
	// successful refresh (zero if it has never succeeded).
	ObserveStale(feed string, stale bool, lastSuccess time.Time, at time.Time)
	// ObserveStoreSize is called once per health tick with the active
	// indicator cardinality of the shared store.
	ObserveStoreSize(counts IOCCounts)
}

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

// WithPersister enables IOC-store durability: the active set is
// flushed to the persister every interval (defaulting to
// defaultPersistInterval when interval <= 0) and once more on
// graceful shutdown. A nil persister disables persistence, leaving
// the manager's behaviour unchanged. Restore-on-boot is driven by
// the caller (before Start) so the store is warm before the first
// feed tick — see IOCStore.Restore.
func WithPersister(p IOCPersister, interval time.Duration) FeedManagerOption {
	return func(m *FeedManager) {
		if p == nil {
			return
		}
		m.persister = p
		if interval > 0 {
			m.persistInterval = interval
		} else {
			m.persistInterval = defaultPersistInterval
		}
	}
}

// WithLeaderCheck gates the persist *write* behind a leadership
// predicate so that, in a multi-replica deployment, only the elected
// leader flushes the shared threat_intel_iocs snapshot table —
// matching the singleton-workload pattern used for the other periodic
// DB writers (app-registry sync, pop rebalance, compliance evidence).
// Only the periodic flush is gated: Restore (a read, every replica
// hydrates its own store on boot) and the final shutdown flush are
// always allowed — the shutdown flush must not be lost to the
// elector-relinquish race (see flushPersist). A nil predicate (the
// default) persists from every replica, which is safe (each
// ReplaceAll is an atomic last-writer-wins swap) but multiplies
// periodic write traffic by replica count. Has no effect unless a
// persister is also configured.
func WithLeaderCheck(isLeader func() bool) FeedManagerOption {
	return func(m *FeedManager) { m.isLeader = isLeader }
}

// WithFeedObserver registers a telemetry observer for feed ingest
// and health. When nil (the default) the manager keeps its internal
// counters only.
func WithFeedObserver(obs FeedObserver) FeedManagerOption {
	return func(m *FeedManager) { m.observer = obs }
}

// WithHealthInterval overrides how often per-feed staleness/health
// is evaluated and published.
func WithHealthInterval(d time.Duration) FeedManagerOption {
	return func(m *FeedManager) {
		if d > 0 {
			m.healthInterval = d
		}
	}
}

// WithStaleFactor overrides the multiple of a feed's refresh
// interval after which it is reported stale.
func WithStaleFactor(factor float64) FeedManagerOption {
	return func(m *FeedManager) {
		if factor > 0 {
			m.staleFactor = factor
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
		feeds:          feeds,
		store:          store,
		logger:         slog.Default(),
		now:            time.Now,
		sweepInterval:  defaultSweepInterval,
		healthInterval: defaultHealthInterval,
		staleFactor:    defaultStaleFactor,
		stopCh:         make(chan struct{}),
		doneCh:         make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	m.startedAt = m.now().UTC()
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
	Runs          int64
	Errors        int64
	Added         int64
	Updated       int64
	Skipped       int64
	LastRunAt     time.Time
	LastSuccessAt time.Time
	LastErr       string
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
	st.LastSuccessAt = at
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

// FeedHealth is a per-feed staleness/health view as of a given
// instant.
type FeedHealth struct {
	Name          string
	Stale         bool
	LastSuccessAt time.Time
	LastRunAt     time.Time
	Threshold     time.Duration
	Runs          int64
	Errors        int64
}

// Health evaluates each configured feed's staleness as of now. A
// feed is stale when it has not refreshed successfully within
// staleFactor x its refresh interval. A feed that has never
// succeeded is measured from the manager's construction time, so a
// feed that never comes up is reported stale once the threshold
// elapses rather than staying silently "healthy" forever.
func (m *FeedManager) Health(now time.Time) []FeedHealth {
	now = now.UTC()
	stats := m.Stats()
	out := make([]FeedHealth, 0, len(m.feeds))
	for _, feed := range m.feeds {
		threshold := m.stalenessThreshold(feed)
		st := stats[feed.Name]
		baseline := st.LastSuccessAt
		if baseline.IsZero() {
			baseline = m.startedAt
		}
		out = append(out, FeedHealth{
			Name:          feed.Name,
			Stale:         now.Sub(baseline) > threshold,
			LastSuccessAt: st.LastSuccessAt,
			LastRunAt:     st.LastRunAt,
			Threshold:     threshold,
			Runs:          st.Runs,
			Errors:        st.Errors,
		})
	}
	return out
}

// FeedCoverage is the operator-facing "what threat intel is live"
// view: each feed's health alongside the active indicator
// cardinality currently in the shared store, both in aggregate and
// attributed to the source feed that contributed it. It composes
// Health (staleness) with the store's SizeByType / SizeBySource so
// an operator can answer "is every feed fresh, and what is each one
// actually contributing right now?" in a single read.
type FeedCoverage struct {
	// GeneratedAt is the instant the view was computed (UTC).
	GeneratedAt time.Time
	// Feeds is the per-feed staleness/health view.
	Feeds []FeedHealth
	// Store is the active indicator cardinality across all feeds.
	Store IOCCounts
	// BySource attributes the active cardinality to the source feed
	// that contributed it. Keyed on IOC.Source; an indicator with no
	// source is keyed under "".
	BySource map[string]IOCCounts
}

// Coverage computes the operator-facing feed-coverage view as of
// now: per-feed health plus the live indicator cardinality of the
// shared store (aggregate and per-source). It is a read-only
// composition of Health and the store size accessors, safe to call
// concurrently with feed refreshes.
func (m *FeedManager) Coverage(now time.Time) FeedCoverage {
	return FeedCoverage{
		GeneratedAt: now.UTC(),
		Feeds:       m.Health(now),
		Store:       m.store.SizeByType(),
		BySource:    m.store.SizeBySource(),
	}
}

// stalenessThreshold is staleFactor x the feed's effective refresh
// interval.
func (m *FeedManager) stalenessThreshold(feed Feed) time.Duration {
	factor := m.staleFactor
	if factor <= 0 {
		factor = defaultStaleFactor
	}
	return time.Duration(float64(feed.effectiveInterval()) * factor)
}

// RunFeedOnce performs a single synchronous refresh of one feed:
// fetch -> parse -> normalize TTL/confidence -> upsert. It returns
// the upsert tally and any fetch/parse error. A parse that yields
// some IOCs and skips malformed rows is not an error. This method
// does NOT fire the OnUpdate hook (callers that need the hook use
// RunOnce, which fires it once after refreshing all feeds).
func (m *FeedManager) RunFeedOnce(ctx context.Context, feed Feed) (UpsertResult, error) {
	at := m.now().UTC()
	res, err := m.refreshOnce(ctx, feed, at)
	// Record + observe at exactly one point so every refresh outcome
	// (fetch error, parse error, success) updates the internal
	// counters and any external observer identically.
	m.metrics.record(feed.Name, res, err, at)
	if m.observer != nil {
		m.observer.ObserveRefresh(feed.Name, res, err, at)
	}
	return res, err
}

// refreshOnce performs the fetch -> parse -> normalize -> upsert
// pipeline for one feed, returning the upsert tally and any
// fetch/parse error. It does no telemetry; RunFeedOnce owns the
// single record/observe call so the two error paths and the success
// path can't drift.
func (m *FeedManager) refreshOnce(ctx context.Context, feed Feed, at time.Time) (UpsertResult, error) {
	raw, err := feed.Fetcher.Fetch(ctx)
	if err != nil {
		return UpsertResult{}, fmt.Errorf("feed %q fetch: %w", feed.Name, err)
	}
	iocs, err := feed.Parser.Parse(raw)
	if err != nil {
		return UpsertResult{}, fmt.Errorf("feed %q parse: %w", feed.Name, err)
	}
	m.applyFeedDefaults(feed, iocs, at)
	return m.store.Upsert(iocs...), nil
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

// Restore re-warms the IOC store from the configured persister
// before the feeds start. It is a no-op (zero result, nil error)
// when no persister is set, so callers can invoke it
// unconditionally. Run it before Start so enforcement reflects the
// last persisted snapshot immediately, rather than being empty
// until the first feed warm-up completes.
//
// A successful restore fires the OnUpdate hook (same as a feed
// refresh), so demotion-driven enforcement is re-synced from the
// restored snapshot at once instead of waiting for the first feed
// warm-up — which is exactly the window that can be slow when an
// upstream is unreachable, the scenario this snapshot guards.
func (m *FeedManager) Restore(ctx context.Context) (UpsertResult, error) {
	if m.persister == nil {
		return UpsertResult{}, nil
	}
	res, err := m.store.Restore(ctx, m.persister)
	if res.Added > 0 {
		m.fireUpdate(ctx)
	}
	return res, err
}

// Start launches one ticker goroutine per feed plus a sweeper.
// Non-blocking and idempotent. Each feed refreshes immediately on
// start (warm-up) and then on its configured interval.
func (m *FeedManager) Start(ctx context.Context) {
	m.startOnce.Do(func() {
		m.started.Store(true)
		// Derive a feed context cancelled when EITHER the parent ctx
		// is done OR Stop closes stopCh. The loops fetch with this
		// context, so Stop aborts an in-flight warm-up/scheduled HTTP
		// fetch promptly instead of blocking on <-doneCh until the
		// 30s HTTP client timeout. (On the normal shutdown path the
		// parent ctx is already cancelled; this also covers the
		// early-return path where the deferred Stop runs while the
		// parent ctx is still live — see cmd/sng-control/main.go.)
		runCtx, cancel := context.WithCancel(ctx)
		go func() {
			select {
			case <-ctx.Done():
			case <-m.stopCh:
			}
			cancel()
		}()
		for _, feed := range m.feeds {
			m.wg.Add(1)
			go m.runFeedLoop(runCtx, feed)
		}
		m.wg.Add(1)
		go m.runSweepLoop(runCtx)
		if m.persister != nil {
			m.wg.Add(1)
			go m.runPersistLoop(runCtx)
		}
		// Only run the health loop when there is something to observe
		// it (a logger to warn through or an observer to publish to)
		// and at least one feed to evaluate.
		if len(m.feeds) > 0 && (m.observer != nil || m.logger != nil) {
			m.wg.Add(1)
			go m.runHealthLoop(runCtx)
		}
		go func() {
			m.wg.Wait()
			cancel()
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

// runPersistLoop periodically flushes the active IOC set to the
// configured persister and performs one final flush when the loop
// is told to stop, so the freshest snapshot survives a restart.
//
// The shutdown flush runs on a fresh, time-bounded context because
// the loop's parent ctx is already cancelled by the time Stop
// fires (the cancel bridge in Start cancels runCtx on stopCh); a
// cancelled context would otherwise abort the very flush meant to
// capture the latest state.
func (m *FeedManager) runPersistLoop(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(m.persistInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.flushPersist(context.Background(), "shutdown")
			return
		case <-m.stopCh:
			m.flushPersist(context.Background(), "shutdown")
			return
		case <-ticker.C:
			m.flushPersist(ctx, "interval")
		}
	}
}

// flushPersist writes the active set once. On the shutdown path the
// supplied ctx is the still-live background context, so the flush
// is wrapped in a bounded timeout to avoid hanging shutdown on a
// slow database.
func (m *FeedManager) flushPersist(ctx context.Context, reason string) {
	if m.persister == nil {
		return
	}
	// Leader-only PERIODIC write: the snapshot table is fleet-wide, so
	// in a multi-replica deployment only the leader flushes on the
	// interval. Followers still run the loop (and restore on boot);
	// they just skip the redundant periodic write. Re-checked on every
	// tick so leadership changes are honoured without restarting the
	// loop.
	//
	// The shutdown flush is deliberately EXEMPT from this gate. On
	// graceful shutdown the elector relinquishes leadership off the
	// same rootCtx cancellation that stops this loop (electorCtx is a
	// child of rootCtx), so by the time the shutdown flush runs the
	// leader may have already stepped down — gating it would silently
	// drop the very flush meant to capture the freshest pre-restart
	// state. A shutdown flush happens at most once per replica, so the
	// worst case (every replica flushing on a rolling restart) is a
	// handful of bounded, atomic last-writer-wins swaps — negligible
	// versus losing the final snapshot.
	if reason != "shutdown" && m.isLeader != nil && !m.isLeader() {
		if m.logger != nil {
			m.logger.DebugContext(ctx, "threat-intel: skipping periodic IOC store persist (not leader)",
				"reason", reason)
		}
		return
	}
	if reason == "shutdown" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, persistFlushTimeout)
		defer cancel()
	}
	n, err := m.store.Persist(ctx, m.persister)
	if err != nil {
		if m.logger != nil {
			m.logger.WarnContext(ctx, "threat-intel: IOC store persist failed",
				"reason", reason, "error", err)
		}
		return
	}
	if m.logger != nil {
		m.logger.DebugContext(ctx, "threat-intel: persisted IOC store snapshot",
			"reason", reason, "count", n)
	}
}

func (m *FeedManager) runHealthLoop(ctx context.Context) {
	defer m.wg.Done()
	interval := m.healthInterval
	if interval <= 0 {
		interval = defaultHealthInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	// Publish an initial reading so a feed that fails its warm-up is
	// reflected promptly rather than only after the first tick.
	m.reportHealth(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.reportHealth(ctx)
		}
	}
}

// reportHealth evaluates per-feed staleness and the store size and
// publishes both to the logger (stale feeds warn) and the observer.
func (m *FeedManager) reportHealth(ctx context.Context) {
	now := m.now().UTC()
	for _, h := range m.Health(now) {
		if h.Stale && m.logger != nil {
			m.logger.WarnContext(ctx, "threat-intel: feed is stale",
				"feed", h.Name,
				"last_success", h.LastSuccessAt,
				"threshold", h.Threshold,
				"errors", h.Errors)
		}
		if m.observer != nil {
			m.observer.ObserveStale(h.Name, h.Stale, h.LastSuccessAt, now)
		}
	}
	if m.observer != nil {
		m.observer.ObserveStoreSize(m.store.SizeByType())
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

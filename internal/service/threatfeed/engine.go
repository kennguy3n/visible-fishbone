package threatfeed

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// unknownSourceWeight is the trust applied to an indicator whose source
// is not in the registry (should not happen for built-ins, but keeps an
// unexpected label contributing weakly rather than at full weight).
const unknownSourceWeight = 0.3

// BundlePublisher distributes a signed bundle over a message transport
// (NATS in production). It mirrors the existing threatintel publisher
// contract so the same control-plane adapter satisfies both. Publishing
// is best-effort: the durable persisted bundle is the source of truth,
// and any replica can serve the latest from the repository.
type BundlePublisher interface {
	PublishBundle(ctx context.Context, subject string, data []byte) error
}

// SourceStat is the per-feed outcome of one refresh, surfaced for logs
// and the manual-refresh response.
type SourceStat struct {
	Source      string `json:"source"`
	Indicators  int    `json:"indicators"`
	NotModified bool   `json:"not_modified,omitempty"`
	UsedCache   bool   `json:"used_cache,omitempty"`
	// Disabled is true when an operator has switched the source off in
	// the registry (enabled=false): the feed was not fetched or parsed
	// this cycle and contributes no indicators.
	Disabled bool   `json:"disabled,omitempty"`
	Err      string `json:"error,omitempty"`
}

// RefreshResult summarizes one ingestion cycle.
type RefreshResult struct {
	// Skipped is true when the kill switch is off (no work done).
	Skipped bool `json:"skipped"`
	// Unchanged is true when the produced content matched the last
	// bundle, so no new version was minted or published.
	Unchanged bool `json:"unchanged"`
	// Degraded is true when this cycle could not produce a complete
	// fresh result and the engine deliberately kept serving the last
	// good bundle instead (the fail-safe that refuses to overwrite
	// non-empty content with an empty set when every upstream is down).
	// It is reported alongside Unchanged precisely so monitoring can
	// tell a healthy no-change refresh (Unchanged && !Degraded) apart
	// from one that is silently serving stale content; the per-source
	// stats carry the underlying failures.
	Degraded bool `json:"degraded"`
	// Serial is the current bundle version (the existing one when
	// Unchanged, the new one otherwise).
	Serial int64 `json:"serial"`
	// Indicators is the deduplicated indicator count in the bundle.
	Indicators int `json:"indicators"`
	// Published is true when the bundle was distributed over the
	// transport this cycle.
	Published bool `json:"published"`
	// Sources is the per-feed breakdown.
	Sources []SourceStat `json:"sources"`
}

// Engine is the managed threat-content producer: it ingests the curated
// feeds, scores and deduplicates indicators, and persists + distributes
// a signed versioned bundle. One Engine runs on the elected leader; the
// produced bundle is consumed by every tenant.
type Engine struct {
	feeds         []Feed
	weights       map[string]float64
	unknownWeight float64
	signer        *Signer
	keyID         string
	repo          repository.ThreatFeedRepository
	publisher     BundlePublisher
	subject       string
	publish       bool
	maxIndicators int
	historyKeep   int
	halfLife      time.Duration
	logger        *slog.Logger
	now           func() time.Time

	// enabled is the kill switch, read without locking.
	enabled atomic.Bool
	// degraded reflects the most recent completed refresh: true when the
	// engine kept serving the last good bundle because the cycle produced
	// no indicators (every upstream down), false on a healthy cycle or
	// while the kill switch is off. It is an atomic so the
	// sng_threatcontent_degraded gauge can read it at scrape time without
	// taking refreshMu.
	degraded atomic.Bool
	// lastSerial is the highest minted/seen serial (monotonic).
	lastSerial atomic.Int64

	// refreshMu serializes refreshes so a manual trigger and a
	// scheduled tick never interleave; it also guards the fields below,
	// which are only touched inside a refresh.
	refreshMu         sync.Mutex
	seeded            bool
	lastGood          map[string][]ai.IOC
	lastContentDigest string
	// lastIndicators is the indicator count of the last bundle in
	// effect (seeded from the persisted bundle on first refresh). It
	// powers the fail-safe that refuses to overwrite non-empty content
	// with an empty set.
	lastIndicators int
}

// Option customizes an Engine at construction.
type Option func(*Engine)

// WithLogger sets the structured logger (default slog.Default()).
func WithLogger(l *slog.Logger) Option {
	return func(e *Engine) {
		if l != nil {
			e.logger = l
		}
	}
}

// WithClock overrides the time source (tests inject a deterministic
// clock).
func WithClock(fn func() time.Time) Option {
	return func(e *Engine) {
		if fn != nil {
			e.now = fn
		}
	}
}

// WithPublisher wires bundle distribution over the given transport and
// subject. Without it the engine still persists bundles durably.
func WithPublisher(p BundlePublisher, subject string) Option {
	return func(e *Engine) {
		e.publisher = p
		if subject != "" {
			e.subject = subject
		}
	}
}

// NewEngine constructs the managed threat-content engine.
func NewEngine(cfg Config, feeds []Feed, signer *Signer, repo repository.ThreatFeedRepository, opts ...Option) (*Engine, error) {
	if signer == nil {
		return nil, errors.New("threatfeed: nil signer")
	}
	if repo == nil {
		return nil, errors.New("threatfeed: nil repository")
	}
	if len(feeds) == 0 {
		return nil, errors.New("threatfeed: no feeds configured")
	}
	e := &Engine{
		feeds:         feeds,
		weights:       weightMap(feeds),
		unknownWeight: unknownSourceWeight,
		signer:        signer,
		keyID:         cfg.KeyID,
		repo:          repo,
		subject:       cfg.Subject,
		publish:       cfg.Publish,
		maxIndicators: cfg.MaxIndicators,
		historyKeep:   cfg.HistoryKeep,
		halfLife:      cfg.HalfLife,
		logger:        slog.Default(),
		now:           time.Now,
		lastGood:      make(map[string][]ai.IOC, len(feeds)),
	}
	e.enabled.Store(cfg.Enabled)
	for _, opt := range opts {
		opt(e)
	}
	if e.keyID == "" {
		e.keyID = DefaultKeyID
	}
	if e.subject == "" {
		e.subject = DefaultSubject
	}
	if e.halfLife <= 0 {
		e.halfLife = DefaultHalfLife
	}
	return e, nil
}

// Enabled reports whether the kill switch permits ingestion.
func (e *Engine) Enabled() bool { return e.enabled.Load() }

// SetEnabled toggles the kill switch at runtime.
func (e *Engine) SetEnabled(v bool) { e.enabled.Store(v) }

// Degraded reports whether the most recent refresh kept serving the
// last good bundle because it could not produce a complete fresh result
// (every upstream down). It feeds the sng_threatcontent_degraded gauge
// so operators are alerted when the fleet is silently serving stale
// content. It is false on a healthy cycle and while the kill switch is
// off, and is only meaningful on the elected leader (the sole replica
// that runs ingestion).
func (e *Engine) Degraded() bool { return e.degraded.Load() }

// SeedRegistry idempotently upserts the built-in feed set into the
// source registry so the operator-visible posture reflects the curated
// sources even before the first refresh and on every replica.
func (e *Engine) SeedRegistry(ctx context.Context) error {
	return e.repo.UpsertSources(ctx, SourcesFromFeeds(e.feeds))
}

// Run drives the bounded refresh schedule: an immediate warm-up
// followed by a refresh every interval until ctx is cancelled. The
// caller leader-gates this (elector.RunIfLeader) so ingestion runs once
// centrally, never per replica or per tenant.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	e.refreshLogged(ctx)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			e.refreshLogged(ctx)
		}
	}
}

func (e *Engine) refreshLogged(ctx context.Context) {
	res, err := e.RefreshOnce(ctx)
	if err != nil {
		e.logger.Error("threatfeed: refresh failed", "error", err)
		return
	}
	if res.Skipped {
		e.logger.Debug("threatfeed: disabled, skipping refresh")
		return
	}
	e.logger.Info("threatfeed: refresh complete",
		"serial", res.Serial,
		"indicators", res.Indicators,
		"unchanged", res.Unchanged,
		"published", res.Published,
	)
}

// RefreshOnce runs one full ingestion cycle: fetch (conditionally) and
// parse every enabled feed, degrade to the last good set on failure,
// aggregate + score + expire, and — only when the content changed —
// mint, sign, persist and publish a new bundle version. It is safe to
// call from the scheduler and the manual-trigger handler concurrently;
// calls are serialized.
func (e *Engine) RefreshOnce(ctx context.Context) (RefreshResult, error) {
	if !e.enabled.Load() {
		e.degraded.Store(false)
		return RefreshResult{Skipped: true}, nil
	}

	e.refreshMu.Lock()
	defer e.refreshMu.Unlock()

	now := e.now().UTC()
	e.seedFromRepo(ctx)

	prevStates := e.loadIngestStates(ctx)
	disabled := e.disabledSources(ctx)

	var (
		all   []ai.IOC
		stats = make([]SourceStat, 0, len(e.feeds))
	)
	for _, feed := range e.feeds {
		if disabled[feed.Name] {
			// Operator has switched this feed off in the registry. Skip
			// the fetch/parse entirely and drop any cached payload so
			// the disable takes effect immediately (its indicators fall
			// out of the aggregated set this cycle) and a later re-enable
			// forces a fresh full fetch rather than serving stale cache.
			delete(e.lastGood, feed.Name)
			stats = append(stats, SourceStat{Source: feed.Name, Disabled: true})
			continue
		}
		iocs, stat := e.ingestFeed(ctx, feed, prevStates[feed.Name], now)
		all = append(all, iocs...)
		stats = append(stats, stat)
	}

	indicators := aggregate(all, e.weightOf, now, e.halfLife)
	indicators = capIndicators(indicators, e.maxIndicators)

	bundle := newBundle(0, now)
	bundle.Indicators = indicators
	contentDigest := bundle.ContentDigest()
	total, byType := bundle.Counts()

	result := RefreshResult{Serial: e.lastSerial.Load(), Indicators: total, Sources: stats}

	// Identical content -> keep the existing version, no re-publish.
	if e.lastContentDigest != "" && e.lastContentDigest == contentDigest {
		result.Unchanged = true
		e.degraded.Store(false)
		return result, nil
	}

	// Fail-safe: never replace a non-empty published bundle with an
	// empty one. An empty indicator set almost always means a transient
	// ingestion failure (every upstream down, or a cold leader whose
	// warm-up fetches all failed) rather than a genuinely empty threat
	// landscape. Overwriting good content with nothing would disable
	// protection for the whole fleet, so we keep serving the last good
	// bundle and report the cycle as unchanged/degraded. The per-source
	// health surface still shows the underlying failures.
	if total == 0 && e.lastIndicators > 0 {
		e.logger.Warn("threatfeed: refresh produced no indicators; keeping last good bundle",
			"last_indicators", e.lastIndicators)
		result.Unchanged = true
		result.Degraded = true
		result.Indicators = e.lastIndicators
		e.degraded.Store(true)
		return result, nil
	}

	serial := e.nextSerial(now)
	bundle.Serial = serial
	result.Serial = serial

	signed, err := bundle.Sign(e.signer, e.keyID)
	if err != nil {
		return result, err
	}
	envelope, err := signed.Marshal()
	if err != nil {
		return result, err
	}

	row := repository.ThreatFeedBundle{
		Serial:         serial,
		SchemaVersion:  SchemaVersion,
		GeneratedAt:    now,
		KeyID:          e.keyID,
		Algorithm:      Algorithm,
		IndicatorCount: int64(total),
		SizeBytes:      int64(len(envelope)),
		Digest:         contentDigest,
		CountsByType:   byType,
		Envelope:       envelope,
	}
	if err := e.repo.SaveBundle(ctx, row); err != nil {
		return result, err
	}
	if err := e.repo.PruneBundles(ctx, e.historyKeep); err != nil {
		e.logger.Warn("threatfeed: prune bundles failed", "error", err)
	}

	if e.publish && e.publisher != nil {
		if err := e.publisher.PublishBundle(ctx, e.subject, envelope); err != nil {
			e.logger.Warn("threatfeed: publish bundle failed", "subject", e.subject, "error", err)
		} else {
			result.Published = true
		}
	}

	e.lastContentDigest = contentDigest
	e.lastIndicators = total
	e.degraded.Store(false)
	return result, nil
}

// ingestFeed fetches and parses a single feed, applying the
// conditional-GET fast path and degrading to the last good parse on any
// failure. It persists the per-source ingest state and returns the
// indicators this feed contributes plus a stat for telemetry. Must be
// called with refreshMu held (it reads/writes lastGood).
func (e *Engine) ingestFeed(ctx context.Context, feed Feed, prev repository.ThreatFeedIngestState, now time.Time) ([]ai.IOC, SourceStat) {
	stat := SourceStat{Source: feed.Name}
	state := prev
	state.SourceName = feed.Name
	state.LastAttemptAt = now

	// Only present cache validators when we actually hold the cached
	// payload they let us reuse. After a process restart the in-memory
	// last-good set is empty, so honoring a 304 would yield NOTHING to
	// serve for this feed; sending no validators forces a full fetch
	// that repopulates the cache. This ties the conditional-GET fast
	// path to the data it depends on and prevents an empty bundle after
	// a leader restart.
	var condETag, condLastModified string
	if _, warm := e.lastGood[feed.Name]; warm {
		condETag, condLastModified = prev.ETag, prev.LastModified
	}

	res, err := feed.Fetcher.Fetch(ctx, condETag, condLastModified)
	switch {
	case err != nil:
		stat.Err = err.Error()
		state.LastError = err.Error()
		state.ConsecutiveFailures = prev.ConsecutiveFailures + 1
		iocs := e.useCached(feed.Name, &stat)
		e.saveState(ctx, state)
		return iocs, stat

	case res.NotModified:
		stat.NotModified = true
		state.ETag = res.ETag
		state.LastModified = res.LastModified
		state.LastError = ""
		state.ConsecutiveFailures = 0
		state.LastSuccessAt = now
		state.IndicatorCount = prev.IndicatorCount
		iocs := e.useCached(feed.Name, &stat)
		e.saveState(ctx, state)
		return iocs, stat

	default:
		parsed, perr := feed.Parser.Parse(res.Body)
		if perr != nil {
			stat.Err = perr.Error()
			state.LastError = perr.Error()
			state.ConsecutiveFailures = prev.ConsecutiveFailures + 1
			iocs := e.useCached(feed.Name, &stat)
			e.saveState(ctx, state)
			return iocs, stat
		}
		stamped := e.stampIOCs(parsed, feed, now)
		e.lastGood[feed.Name] = stamped
		stat.Indicators = len(stamped)
		state.ETag = res.ETag
		state.LastModified = res.LastModified
		state.LastError = ""
		state.ConsecutiveFailures = 0
		state.LastSuccessAt = now
		state.IndicatorCount = int64(len(stamped))
		e.saveState(ctx, state)
		return stamped, stat
	}
}

// useCached returns the last good indicator set for a source (after a
// fetch/parse failure or a 304), updating the stat. Must hold refreshMu.
func (e *Engine) useCached(source string, stat *SourceStat) []ai.IOC {
	cached, ok := e.lastGood[source]
	if !ok {
		return nil
	}
	stat.Indicators = len(cached)
	stat.UsedCache = true
	return cached
}

func (e *Engine) saveState(ctx context.Context, state repository.ThreatFeedIngestState) {
	if err := e.repo.SaveIngestState(ctx, state); err != nil {
		e.logger.Warn("threatfeed: save ingest state failed", "source", state.SourceName, "error", err)
	}
}

// stampIOCs fills observation timestamps the parser left zero: the
// fetch instant for first/last seen and the feed's TTL for expiry. This
// keeps parsers pure and the TTL policy in one place.
func (e *Engine) stampIOCs(iocs []ai.IOC, feed Feed, now time.Time) []ai.IOC {
	out := make([]ai.IOC, 0, len(iocs))
	for _, ioc := range iocs {
		if ioc.Source == "" {
			ioc.Source = feed.Name
		}
		if ioc.FirstSeen.IsZero() {
			ioc.FirstSeen = now
		}
		if ioc.LastSeen.IsZero() {
			ioc.LastSeen = now
		}
		if ioc.ExpiresAt.IsZero() && feed.DefaultTTL > 0 {
			ioc.ExpiresAt = now.Add(feed.DefaultTTL)
		}
		out = append(out, ioc)
	}
	return out
}

// weightOf resolves a source name to its registry trust weight.
func (e *Engine) weightOf(source string) float64 {
	if w, ok := e.weights[source]; ok {
		return w
	}
	return e.unknownWeight
}

// loadIngestStates snapshots the persisted per-source cursors so each
// feed's conditional GET can present its last ETag / Last-Modified.
func (e *Engine) loadIngestStates(ctx context.Context) map[string]repository.ThreatFeedIngestState {
	states, err := e.repo.ListIngestState(ctx)
	if err != nil {
		e.logger.Warn("threatfeed: load ingest state failed", "error", err)
		return nil
	}
	m := make(map[string]repository.ThreatFeedIngestState, len(states))
	for _, s := range states {
		m[s.SourceName] = s
	}
	return m
}

// disabledSources returns the set of registry source names an operator
// has switched off (enabled=false). Honoring it lets an operator quench
// a single misbehaving curated feed by flipping one registry row — no
// redeploy, no effect on the rest of the managed set.
//
// On a registry read error it returns nil (fail-OPEN to the curated
// all-on default): the per-feed switch is an operator refinement, not
// the engine's master kill switch (that is the env-backed flag checked
// at the top of RefreshOnce), so a transient DB blip must never silently
// blank the fleet's threat content. An empty/unseeded registry likewise
// disables nothing.
func (e *Engine) disabledSources(ctx context.Context) map[string]bool {
	sources, err := e.repo.ListSources(ctx)
	if err != nil {
		e.logger.Warn("threatfeed: list sources for enable-filter failed; treating all feeds as enabled",
			"error", err)
		return nil
	}
	var disabled map[string]bool
	for _, s := range sources {
		if !s.Enabled {
			if disabled == nil {
				disabled = make(map[string]bool, len(sources))
			}
			disabled[s.Name] = true
		}
	}
	return disabled
}

// seedFromRepo lazily restores the monotonic serial and last content
// digest from the latest persisted bundle, so a freshly-started leader
// continues the version line instead of restarting it and does not
// re-publish identical content. Must hold refreshMu.
func (e *Engine) seedFromRepo(ctx context.Context) {
	if e.seeded {
		return
	}
	latest, err := e.repo.LatestBundle(ctx)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			e.seeded = true // nothing persisted yet
			return
		}
		e.logger.Warn("threatfeed: seed from repository failed", "error", err)
		return // retry on next refresh
	}
	if latest.Serial > e.lastSerial.Load() {
		e.lastSerial.Store(latest.Serial)
	}
	if e.lastContentDigest == "" {
		e.lastContentDigest = latest.Digest
	}
	if latest.IndicatorCount > 0 {
		e.lastIndicators = int(latest.IndicatorCount)
	}
	e.seeded = true
}

// nextSerial returns a strictly increasing version: the current unix
// second, or one past the last serial if the clock has not advanced
// (or two replicas mint within the same second). Monotonicity is what
// lets a consumer pin-and-ignore-lower without ever rolling back.
func (e *Engine) nextSerial(now time.Time) int64 {
	for {
		prev := e.lastSerial.Load()
		next := now.Unix()
		if next <= prev {
			next = prev + 1
		}
		if e.lastSerial.CompareAndSwap(prev, next) {
			return next
		}
	}
}

package ai

import (
	"context"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"
)

// RetroTenantLister enumerates the tenants a retro-hunt fans out
// over. repository.TenantRepository's activity projection satisfies
// it through a thin adapter in the binary; kept as a local
// interface so the ai package does not import the repository layer.
type RetroTenantLister interface {
	ListRetroHuntTenants(ctx context.Context) ([]uuid.UUID, error)
}

// RetroHitSink consumes the findings of a tenant sweep. The default
// wiring logs + counts them; routing them to the alert / NATS
// pipeline is a deferred follow-up (the same transport seam left
// open by the DNS and IPS bundle producers).
type RetroHitSink interface {
	EmitRetroReport(ctx context.Context, report RetroReport)
}

// RetroHitSinkFunc adapts a func to a RetroHitSink.
type RetroHitSinkFunc func(ctx context.Context, report RetroReport)

// EmitRetroReport calls f.
func (f RetroHitSinkFunc) EmitRetroReport(ctx context.Context, report RetroReport) {
	f(ctx, report)
}

// RetroHuntCoordinator turns the store's growing indicator set into
// "on new IOC" retro-hunts. Each tick it snapshots the store,
// diffs the active indicators against the set already swept, and —
// when new domain/IP/CIDR indicators have appeared — sweeps every
// active tenant's recent telemetry for prior exposure to ONLY those
// new indicators, reporting non-empty findings to the sink.
//
// Diffing against a seen-set is what makes this an "on new IOC"
// sweep rather than a full re-scan: a known indicator is hunted
// exactly once (when it first lands), so steady-state ticks with no
// new intel touch the event source not at all.
type RetroHuntCoordinator struct {
	hunter        *RetroHunter
	snapshot      func() IOCSnapshot
	tenants       RetroTenantLister
	sink          RetroHitSink
	lookback      time.Duration
	minConfidence float64
	now           func() time.Time
	logger        *slog.Logger

	// seen holds the IOC store keys already swept, so each new
	// indicator is hunted exactly once. Coordinator runs on a
	// single leader goroutine, so no lock is needed.
	seen map[string]struct{}
	// primed is false until the first tick establishes the
	// baseline. The first tick records the existing indicator set
	// as already-seen WITHOUT hunting it, so enabling the feature
	// does not trigger a sweep of the entire backlog against every
	// tenant; only indicators that arrive AFTER enablement are
	// hunted. Operators wanting a full backfill can clear the
	// seen-set out of band (not yet wired).
	primed bool
}

// RetroHuntConfig configures a RetroHuntCoordinator.
type RetroHuntConfig struct {
	// Hunter performs the per-tenant sweep. Required.
	Hunter *RetroHunter
	// Snapshot returns the current active indicator set. Required
	// (typically IOCStore.Snapshot).
	Snapshot func() IOCSnapshot
	// Tenants enumerates the tenants to sweep. Required.
	Tenants RetroTenantLister
	// Sink consumes findings. Required.
	Sink RetroHitSink
	// Lookback is how far back each sweep reaches. Zero falls back
	// to DefaultRetroLookback.
	Lookback time.Duration
	// MinConfidence is the floor an indicator must clear to be
	// hunted. Mirrors the enforcement / IPS confidence floors.
	MinConfidence float64
	// Now overrides the clock (tests). Zero uses time.Now.
	Now func() time.Time
	// Logger is the structured logger. Zero uses slog.Default.
	Logger *slog.Logger
}

// DefaultRetroLookback is the default sweep window: a week of
// recent telemetry, which comfortably fits inside the 30–90 day
// per-tenant retention floor while bounding the scan.
const DefaultRetroLookback = 7 * 24 * time.Hour

// DefaultRetroHuntInterval is the default cadence at which the
// coordinator checks for newly-arrived indicators to hunt. It is the
// poll/tick fallback — distinct from DefaultRetroLookback, which is
// the telemetry *window* a sweep reaches back over. Mirrors the
// THREAT_INTEL_REFRESH_INTERVAL default so a new indicator is swept
// about as soon as the feed loop ingests it.
const DefaultRetroHuntInterval = time.Hour

// NewRetroHuntCoordinator builds a coordinator. Returns nil when a
// required dependency is missing, so the caller can treat a
// misconfigured retro-hunt as "disabled" rather than crash.
func NewRetroHuntCoordinator(cfg RetroHuntConfig) *RetroHuntCoordinator {
	if cfg.Hunter == nil || cfg.Snapshot == nil || cfg.Tenants == nil || cfg.Sink == nil {
		return nil
	}
	lookback := cfg.Lookback
	if lookback <= 0 {
		lookback = DefaultRetroLookback
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &RetroHuntCoordinator{
		hunter:        cfg.Hunter,
		snapshot:      cfg.Snapshot,
		tenants:       cfg.Tenants,
		sink:          cfg.Sink,
		lookback:      lookback,
		minConfidence: cfg.MinConfidence,
		now:           now,
		logger:        logger,
		seen:          map[string]struct{}{},
	}
}

// Run drives the coordinator on a ticker until ctx is cancelled.
// The first tick fires immediately (priming the baseline), then
// every interval.
func (c *RetroHuntCoordinator) Run(ctx context.Context, interval time.Duration) {
	if c == nil {
		return
	}
	if interval <= 0 {
		interval = DefaultRetroHuntInterval
	}
	if err := c.Tick(ctx); err != nil && ctx.Err() == nil {
		c.logger.Warn("ai/retrohunt: tick failed", slog.String("error", err.Error()))
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.Tick(ctx); err != nil && ctx.Err() == nil {
				c.logger.Warn("ai/retrohunt: tick failed", slog.String("error", err.Error()))
			}
		}
	}
}

// Tick performs one diff-and-sweep cycle. It is safe to call
// directly in tests. The first call primes the baseline (records
// the current indicators as seen without hunting) so enabling the
// feature never floods the event source with a backlog sweep.
func (c *RetroHuntCoordinator) Tick(ctx context.Context) error {
	if c == nil {
		return nil
	}
	snap := c.snapshot()

	if !c.primed {
		for _, ioc := range huntableIOCs(snap) {
			// Gate the baseline by the same confidence floor as the
			// hunt: a sub-threshold indicator is left un-seen so a
			// later confidence upgrade above the floor still triggers
			// a hunt rather than being permanently suppressed.
			if !c.meetsFloor(ioc) {
				continue
			}
			c.seen[ioc.Key()] = struct{}{}
		}
		c.primed = true
		c.logger.Info("ai/retrohunt: primed baseline; future new indicators will be hunted",
			slog.Int("baseline_indicators", len(c.seen)))
		return nil
	}

	newSnap, newCount := c.diffNew(snap)
	if newCount == 0 {
		return nil
	}
	set := NewRetroIndicatorSet(newSnap, c.minConfidence)
	if set.empty() {
		return nil
	}

	tenants, err := c.tenants.ListRetroHuntTenants(ctx)
	if err != nil {
		return err
	}
	until := c.now().UTC()
	since := until.Add(-c.lookback)

	var totalHits, sweptTenants int
	for _, tid := range tenants {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		report, hErr := c.hunter.Hunt(ctx, tid, set, since, until)
		if hErr != nil {
			c.logger.Warn("ai/retrohunt: tenant sweep failed",
				slog.String("tenant_id", tid.String()),
				slog.String("error", hErr.Error()))
			continue
		}
		sweptTenants++
		if len(report.Hits) == 0 {
			continue
		}
		totalHits += len(report.Hits)
		c.sink.EmitRetroReport(ctx, report)
	}

	c.logger.Info("ai/retrohunt: swept new indicators across tenants",
		slog.Int("new_indicators", set.Len()),
		slog.Int("tenants", sweptTenants),
		slog.Int("hits", totalHits),
		slog.Duration("lookback", c.lookback))
	return nil
}

// diffNew returns the subset of snap's huntable indicators not yet
// seen, marking them seen so each is hunted exactly once. The
// returned snapshot carries only the new indicators.
//
// Indicators below the confidence floor are skipped WITHOUT being
// marked seen: they are neither hunted now nor recorded, so if a
// later feed re-ingest upgrades one above the floor it is treated as
// newly-huntable and swept then. (NewRetroIndicatorSet applies the
// same floor downstream; gating here is what keeps the seen-set from
// permanently suppressing a low-confidence indicator that is later
// upgraded.)
func (c *RetroHuntCoordinator) diffNew(snap IOCSnapshot) (IOCSnapshot, int) {
	var out IOCSnapshot
	count := 0
	add := func(ioc IOC, dst *[]IOC) {
		if !c.meetsFloor(ioc) {
			return
		}
		key := ioc.Key()
		if _, ok := c.seen[key]; ok {
			return
		}
		c.seen[key] = struct{}{}
		*dst = append(*dst, ioc)
		count++
	}
	for _, ioc := range snap.Domains {
		add(ioc, &out.Domains)
	}
	for _, ioc := range snap.IPs {
		add(ioc, &out.IPs)
	}
	for _, ioc := range snap.CIDRs {
		add(ioc, &out.CIDRs)
	}
	return out, count
}

// meetsFloor reports whether an indicator clears the coordinator's
// confidence floor. It is the single gate shared by baseline priming
// and the new-indicator diff, matching the floor NewRetroIndicatorSet
// applies when it builds the lookup set.
func (c *RetroHuntCoordinator) meetsFloor(ioc IOC) bool {
	return ioc.Confidence >= c.minConfidence
}

// huntableIOCs flattens the domain/IP/CIDR indicators a hunt can
// match, in deterministic order. JA3/URL/hash are excluded for the
// same reason NewRetroIndicatorSet ignores them.
func huntableIOCs(snap IOCSnapshot) []IOC {
	out := make([]IOC, 0, len(snap.Domains)+len(snap.IPs)+len(snap.CIDRs))
	out = append(out, snap.Domains...)
	out = append(out, snap.IPs...)
	out = append(out, snap.CIDRs...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out
}

// scheduler.go drives automated SOC2 evidence collection. The Scheduler
// performs three periodic jobs:
//
//   - weekly collection: run the SOC2 collector and archive a signed
//     'weekly' evidence bundle;
//   - monthly aggregation: roll the trailing window of weekly bundles
//     into a single audit-ready 'monthly' package;
//   - gap detection: alert when expected evidence is missing or stale.
//
// All three are singleton workloads: in a multi-replica deployment they
// must run on exactly one replica. The Scheduler itself is leadership-
// agnostic — Run is meant to be wrapped by the leader elector's
// RunIfLeader so the loop only turns while this replica holds
// leadership (see cmd/sng-control wiring). This keeps the Scheduler
// unit-testable without a Postgres advisory lock.
package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Scheduling cadences. Evidence is collected weekly; aggregated
// monthly; and gaps are checked daily so a missed weekly run is caught
// well before an audit.
const (
	DefaultWeeklyInterval   = 7 * 24 * time.Hour
	DefaultMonthlyInterval  = 30 * 24 * time.Hour
	DefaultGapCheckInterval = 24 * time.Hour
	// DefaultWeeklyMaxAge is how stale the most recent weekly bundle
	// may be before gap detection flags it. One week of cadence plus a
	// one-day grace window.
	DefaultWeeklyMaxAge = 8 * 24 * time.Hour
	// DefaultAggregationWindow is the trailing span of weekly bundles a
	// monthly package rolls up.
	DefaultAggregationWindow = 31 * 24 * time.Hour
)

// Scheduler runs the periodic evidence-collection workloads.
type Scheduler struct {
	collector *SOC2EvidenceCollector
	evidence  *EvidenceService
	logger    *slog.Logger
	now       func() time.Time

	weeklyInterval    time.Duration
	monthlyInterval   time.Duration
	gapCheckInterval  time.Duration
	weeklyMaxAge      time.Duration
	aggregationWindow time.Duration
}

// SchedulerOption customises a Scheduler.
type SchedulerOption func(*Scheduler)

// WithSchedulerClock overrides the wall-clock (tests).
func WithSchedulerClock(now func() time.Time) SchedulerOption {
	return func(s *Scheduler) {
		if now != nil {
			s.now = now
		}
	}
}

// WithIntervals overrides the weekly / monthly / gap-check cadences.
// Non-positive values keep the default for that field.
func WithIntervals(weekly, monthly, gapCheck time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if weekly > 0 {
			s.weeklyInterval = weekly
		}
		if monthly > 0 {
			s.monthlyInterval = monthly
		}
		if gapCheck > 0 {
			s.gapCheckInterval = gapCheck
		}
	}
}

// WithWeeklyMaxAge overrides the staleness threshold gap detection uses.
func WithWeeklyMaxAge(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.weeklyMaxAge = d
		}
	}
}

// NewScheduler constructs a Scheduler. collector and evidence are
// required.
func NewScheduler(collector *SOC2EvidenceCollector, evidence *EvidenceService, logger *slog.Logger, opts ...SchedulerOption) (*Scheduler, error) {
	if collector == nil || evidence == nil {
		return nil, errors.New("compliance: NewScheduler requires a collector and evidence service")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Scheduler{
		collector:         collector,
		evidence:          evidence,
		logger:            logger,
		now:               func() time.Time { return time.Now().UTC() },
		weeklyInterval:    DefaultWeeklyInterval,
		monthlyInterval:   DefaultMonthlyInterval,
		gapCheckInterval:  DefaultGapCheckInterval,
		weeklyMaxAge:      DefaultWeeklyMaxAge,
		aggregationWindow: DefaultAggregationWindow,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// CollectWeekly runs the SOC2 collector and archives a signed weekly
// evidence bundle. Returns the persisted index row.
func (s *Scheduler) CollectWeekly(ctx context.Context) (repository.ComplianceEvidence, error) {
	return s.collect(ctx, CollectionWeekly)
}

// CollectManual runs an on-demand collection (the admin "collect now"
// endpoint). Identical to the weekly path but tagged 'manual' so it is
// distinguishable in the audit index.
func (s *Scheduler) CollectManual(ctx context.Context) (repository.ComplianceEvidence, error) {
	return s.collect(ctx, CollectionManual)
}

func (s *Scheduler) collect(ctx context.Context, collectionType string) (repository.ComplianceEvidence, error) {
	result, err := s.collector.Collect(ctx, collectionType)
	if err != nil {
		return repository.ComplianceEvidence{}, fmt.Errorf("collect %s evidence: %w", collectionType, err)
	}
	row, err := s.evidence.Store(ctx, result.Bundle)
	if err != nil {
		return repository.ComplianceEvidence{}, err
	}
	if len(result.FailedControl) > 0 {
		s.logger.Warn("compliance: evidence stored with control failures",
			slog.String("id", row.ID.String()),
			slog.String("collection_type", collectionType),
			slog.Int("failed_controls", len(result.FailedControl)))
	}
	return row, nil
}

// AggregateMonthly rolls the trailing aggregation window of weekly
// bundles into a single 'monthly' audit-ready package. The monthly
// bundle's artifacts are a manifest of the constituent weekly bundles
// (id, collected_at, s3_key, signature) plus a coverage summary, so an
// auditor can pull a month of evidence from one signed object. The
// constituent weekly rows are transitioned to 'aggregated'.
func (s *Scheduler) AggregateMonthly(ctx context.Context) (repository.ComplianceEvidence, error) {
	cutoff := s.now().Add(-s.aggregationWindow)
	// Only roll up successfully-collected weeklies. Including 'failed'
	// or 'collecting' rows would (a) put incomplete evidence into an
	// audit-ready package and (b) let the status transition below mask
	// those failures as 'aggregated'. Restricting to 'collected' also
	// makes monthly partitions non-overlapping: once a weekly is
	// aggregated it is no longer 'collected', so a later monthly run
	// over the same window will not pick it up again.
	weeklies, err := s.listSince(ctx, CollectionWeekly, StatusCollected, cutoff)
	if err != nil {
		return repository.ComplianceEvidence{}, err
	}
	if len(weeklies) == 0 {
		return repository.ComplianceEvidence{}, fmt.Errorf("aggregate monthly: %w", ErrNoEvidence)
	}

	manifest := s.newMonthlyManifest(ctx, s.now(), cutoff, weeklies)
	bundle := NewBundle(CollectionMonthly, s.now())
	data, err := jsonRaw(manifest)
	if err != nil {
		return repository.ComplianceEvidence{}, fmt.Errorf("aggregate monthly: %w", err)
	}
	bundle.Add(EvidenceArtifact{
		Control: "", // platform-wide manifest, not a single control
		Name:    "monthly_manifest",
		Kind:    ArtifactJSONExport,
		Data:    data,
	})

	row, err := s.evidence.Store(ctx, bundle)
	if err != nil {
		return repository.ComplianceEvidence{}, err
	}

	// Mark constituents aggregated. A failure here is non-fatal: the
	// monthly package already exists; log and continue.
	for _, w := range weeklies {
		if _, err := s.evidence.repo.UpdateStatus(ctx, w.ID, StatusAggregated); err != nil {
			s.logger.Error("compliance: mark weekly aggregated",
				slog.String("id", w.ID.String()), slog.Any("error", err))
		}
	}
	s.logger.Info("compliance: monthly evidence aggregated",
		slog.String("id", row.ID.String()),
		slog.Int("weekly_bundles", len(weeklies)))
	return row, nil
}

// GapReport is the result of a gap-detection run.
type GapReport struct {
	// LatestWeeklyAt is the timestamp of the most recent weekly bundle
	// (zero if none exists).
	LatestWeeklyAt time.Time
	// MissingWeekly is true when no weekly bundle exists at all.
	MissingWeekly bool
	// StaleWeekly is true when the most recent weekly bundle is older
	// than the configured max age.
	StaleWeekly bool
}

// HasGap reports whether the report indicates any evidence gap.
func (r GapReport) HasGap() bool { return r.MissingWeekly || r.StaleWeekly }

// DetectGaps checks that recent expected evidence exists and is fresh.
// It does not mutate state; callers decide how to alert.
func (s *Scheduler) DetectGaps(ctx context.Context) (GapReport, error) {
	latest, err := s.evidence.LatestByType(ctx, CollectionWeekly)
	if errors.Is(err, repository.ErrNotFound) {
		s.logger.Warn("compliance: evidence gap — no weekly bundle on record")
		return GapReport{MissingWeekly: true}, nil
	}
	if err != nil {
		return GapReport{}, fmt.Errorf("detect gaps: %w", err)
	}
	report := GapReport{LatestWeeklyAt: latest.CollectedAt}
	if s.now().Sub(latest.CollectedAt) > s.weeklyMaxAge {
		report.StaleWeekly = true
		s.logger.Warn("compliance: evidence gap — latest weekly bundle is stale",
			slog.Time("collected_at", latest.CollectedAt),
			slog.Duration("max_age", s.weeklyMaxAge))
	}
	return report, nil
}

// Run drives the three periodic jobs until ctx is cancelled. It is
// leadership-agnostic; wrap it with the leader elector's RunIfLeader so
// it only runs on the leader replica:
//
//	go elector.RunIfLeader(ctx, "compliance-evidence", scheduler.Run)
//
// Run does NOT collect immediately on start: a freshly elected leader
// should not duplicate a bundle the previous leader just produced. The
// first weekly collection fires one weeklyInterval after start; gap
// detection fires first (after gapCheckInterval) to catch a backlog.
func (s *Scheduler) Run(ctx context.Context) {
	weekly := time.NewTicker(s.weeklyInterval)
	monthly := time.NewTicker(s.monthlyInterval)
	gap := time.NewTicker(s.gapCheckInterval)
	defer weekly.Stop()
	defer monthly.Stop()
	defer gap.Stop()

	s.logger.Info("compliance: evidence scheduler started",
		slog.Duration("weekly", s.weeklyInterval),
		slog.Duration("monthly", s.monthlyInterval),
		slog.Duration("gap_check", s.gapCheckInterval))

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("compliance: evidence scheduler stopped")
			return
		case <-weekly.C:
			if _, err := s.CollectWeekly(ctx); err != nil {
				s.logger.Error("compliance: scheduled weekly collection failed", slog.Any("error", err))
			}
		case <-monthly.C:
			if _, err := s.AggregateMonthly(ctx); err != nil && !errors.Is(err, ErrNoEvidence) {
				s.logger.Error("compliance: scheduled monthly aggregation failed", slog.Any("error", err))
			}
		case <-gap.C:
			if _, err := s.DetectGaps(ctx); err != nil {
				s.logger.Error("compliance: scheduled gap detection failed", slog.Any("error", err))
			}
		}
	}
}

// listSince pages through evidence of a type (optionally narrowed to a
// status; empty status means any) collected at or after cutoff,
// oldest-bounded by the List ordering (most-recent first). It stops as
// soon as it crosses the cutoff to bound work.
func (s *Scheduler) listSince(ctx context.Context, collectionType, status string, cutoff time.Time) ([]repository.ComplianceEvidence, error) {
	var out []repository.ComplianceEvidence
	page := repository.Page{Limit: 100}
	for {
		res, err := s.evidence.List(ctx, repository.ComplianceEvidenceFilter{CollectionType: collectionType, Status: status}, page)
		if err != nil {
			return nil, fmt.Errorf("list %s evidence: %w", collectionType, err)
		}
		for _, e := range res.Items {
			if e.CollectedAt.Before(cutoff) {
				return out, nil
			}
			out = append(out, e)
		}
		if res.NextCursor == "" {
			return out, nil
		}
		page.After = res.NextCursor
	}
}

// ErrNoEvidence indicates an aggregation run found no constituent
// bundles in the window.
var ErrNoEvidence = errors.New("compliance: no evidence in window")

// monthlyManifestEntry references one constituent weekly bundle.
type monthlyManifestEntry struct {
	ID          string    `json:"id"`
	CollectedAt time.Time `json:"collected_at"`
	S3Key       string    `json:"s3_key"`
	Signature   string    `json:"signature"`
	Status      string    `json:"status"`
	// Controls is the set of SOC2 controls this weekly bundle actually
	// carries evidence for, read back from the signed bundle body.
	Controls []string `json:"controls"`
}

// monthlyManifest is the audit-ready summary embedded in a monthly
// aggregation bundle.
type monthlyManifest struct {
	GeneratedAt   time.Time              `json:"generated_at"`
	WindowStart   time.Time              `json:"window_start"`
	WindowEnd     time.Time              `json:"window_end"`
	WeeklyCount   int                    `json:"weekly_count"`
	WeeklyBundles []monthlyManifestEntry `json:"weekly_bundles"`
	// ControlsCovered is the actual union of controls present across the
	// constituent weekly bundles — computed from their signed contents,
	// not assumed. ControlsExpected is the canonical SOC2 set, and
	// ControlsMissing is the difference, so an auditor can see at a
	// glance whether the month's coverage is complete.
	ControlsCovered  []string `json:"controls_covered"`
	ControlsExpected []string `json:"controls_expected"`
	ControlsMissing  []string `json:"controls_missing"`
}

// newMonthlyManifest builds the audit summary. It downloads each
// constituent weekly bundle and reads back the controls it actually
// carries, so ControlsCovered reflects real coverage rather than the
// expected set. A weekly whose bundle can't be fetched/verified is
// still listed (with empty controls) and logged — its absence from the
// covered union surfaces as a missing control instead of being masked.
func (s *Scheduler) newMonthlyManifest(ctx context.Context, now, windowStart time.Time, weeklies []repository.ComplianceEvidence) monthlyManifest {
	entries := make([]monthlyManifestEntry, 0, len(weeklies))
	coveredSet := make(map[string]struct{})
	for _, w := range weeklies {
		controls := s.bundleControls(ctx, w)
		for _, c := range controls {
			coveredSet[c] = struct{}{}
		}
		entries = append(entries, monthlyManifestEntry{
			ID:          w.ID.String(),
			CollectedAt: w.CollectedAt,
			S3Key:       w.S3Key,
			Signature:   w.Signature,
			Status:      w.Status,
			Controls:    controls,
		})
	}

	covered := make([]string, 0, len(coveredSet))
	for c := range coveredSet {
		covered = append(covered, c)
	}
	sort.Strings(covered)

	missing := make([]string, 0)
	for _, c := range ExpectedControls {
		if _, ok := coveredSet[c]; !ok {
			missing = append(missing, c)
		}
	}

	return monthlyManifest{
		GeneratedAt:      now.UTC(),
		WindowStart:      windowStart.UTC(),
		WindowEnd:        now.UTC(),
		WeeklyCount:      len(entries),
		WeeklyBundles:    entries,
		ControlsCovered:  covered,
		ControlsExpected: append([]string(nil), ExpectedControls...),
		ControlsMissing:  missing,
	}
}

// bundleControls fetches a weekly bundle and returns the controls it
// actually carries evidence for. On any download/parse failure it logs
// and returns nil rather than failing aggregation: the weekly is still
// listed in the manifest, and the controls it would have covered show
// up in ControlsMissing instead of being silently assumed present.
func (s *Scheduler) bundleControls(ctx context.Context, w repository.ComplianceEvidence) []string {
	_, body, err := s.evidence.Download(ctx, w.ID)
	if err != nil {
		s.logger.Warn("compliance: could not read weekly bundle for coverage",
			slog.String("id", w.ID.String()), slog.Any("error", err))
		return nil
	}
	var bundle EvidenceBundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		s.logger.Warn("compliance: could not parse weekly bundle for coverage",
			slog.String("id", w.ID.String()), slog.Any("error", err))
		return nil
	}
	return bundle.Controls()
}

// jsonRaw marshals v into a json.RawMessage.
func jsonRaw(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return json.RawMessage(b), nil
}

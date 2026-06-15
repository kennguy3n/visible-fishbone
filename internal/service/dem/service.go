// Package dem implements the control-plane half of Lightweight DEM
// (Digital Experience Monitoring), a Zscaler ZDX-style end-to-end
// user-experience signal for ShieldNet Gateway.
//
// The edge sng-dem crate runs cheap, bounded synthetic probes
// (DNS/TCP/HTTP(S)) against a small set of critical SaaS targets and
// uploads structured results. This service ingests those results,
// rolls them into a per-tenant, per-target experience score over a
// short rolling window, maintains a cheap O(1) EWMA baseline per
// target, and raises a degradation alert (reusing the existing alert
// router) when experience drops below an absolute floor or
// significantly below its own baseline.
//
// Everything here is bounded for a 5,000-tenant no-ops SaaS: ingest
// batches are size-capped, scoring is a single windowed aggregate per
// distinct target, the baseline is constant-memory, and retention is
// swept by a leader-only scheduler (see scheduler.go).
package dem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ExperienceDegradedKind is the alert Kind raised when a target's
// experience score degrades. It scopes the ListAlerts query and lets
// operators filter DEM alerts apart from baseline/anomaly alerts.
const ExperienceDegradedKind = "dem.experience_degraded"

// AlertGateway is the slice of the alert router this service needs:
// emit a degradation alert and list prior DEM alerts. *alert.Router
// satisfies it; tests use a stub.
type AlertGateway interface {
	Emit(ctx context.Context, tenantID uuid.UUID, a repository.Alert) (repository.Alert, error)
	List(ctx context.Context, tenantID uuid.UUID, filter repository.AlertListFilter, page repository.Page) (repository.PageResult[repository.Alert], error)
}

// Config tunes scoring, degradation detection, and retention. The zero
// value is invalid; pass DefaultConfig() or rely on withDefaults
// (applied by NewService) to backfill non-positive fields.
type Config struct {
	// WindowSeconds is the rolling window each score aggregates over.
	WindowSeconds int
	// EWMAAlpha is the smoothing factor (0,1] for the baseline.
	EWMAAlpha float64
	// AvailabilityWeight / LatencyWeight compose the score; they are
	// normalized to sum to 1.
	AvailabilityWeight float64
	LatencyWeight      float64
	// GoodLatencyMs / BadLatencyMs bound the latency sub-score: p50 at
	// or below Good scores 1.0, at or above Bad scores 0.0.
	GoodLatencyMs float64
	BadLatencyMs  float64
	// DegradeScoreFloor is the absolute score below which a target is
	// degraded regardless of baseline.
	DegradeScoreFloor float64
	// DegradeZScore is how many standard deviations below the EWMA mean
	// a score must fall to be degraded by the relative trigger.
	DegradeZScore float64
	// MinSamplesForZ is the baseline maturity (sample count) required
	// before the relative z-score trigger arms.
	MinSamplesForZ int64
	// AlertCooldown is the minimum spacing between alerts for the same
	// target, to avoid alert storms while a target stays degraded.
	AlertCooldown time.Duration
	// RawRetention / ScoreRetention bound how long raw results and
	// score samples are kept.
	RawRetention   time.Duration
	ScoreRetention time.Duration
	// MaxIngestBatch caps how many results one ingest call may carry.
	MaxIngestBatch int
}

// DefaultConfig returns the documented production defaults.
func DefaultConfig() Config {
	return Config{
		WindowSeconds:      300,
		EWMAAlpha:          0.2,
		AvailabilityWeight: 0.6,
		LatencyWeight:      0.4,
		GoodLatencyMs:      100,
		BadLatencyMs:       2000,
		DegradeScoreFloor:  70,
		DegradeZScore:      2.0,
		MinSamplesForZ:     10,
		AlertCooldown:      15 * time.Minute,
		RawRetention:       7 * 24 * time.Hour,
		ScoreRetention:     30 * 24 * time.Hour,
		MaxIngestBatch:     1000,
	}
}

// withDefaults backfills any non-positive / out-of-range field from
// DefaultConfig so a partially-specified Config is always usable.
func (c Config) withDefaults() Config {
	d := DefaultConfig()
	out := c
	if out.WindowSeconds <= 0 {
		out.WindowSeconds = d.WindowSeconds
	}
	if out.EWMAAlpha <= 0 || out.EWMAAlpha > 1 {
		out.EWMAAlpha = d.EWMAAlpha
	}
	if out.AvailabilityWeight < 0 {
		out.AvailabilityWeight = d.AvailabilityWeight
	}
	if out.LatencyWeight < 0 {
		out.LatencyWeight = d.LatencyWeight
	}
	if out.AvailabilityWeight == 0 && out.LatencyWeight == 0 {
		out.AvailabilityWeight = d.AvailabilityWeight
		out.LatencyWeight = d.LatencyWeight
	}
	if out.GoodLatencyMs <= 0 {
		out.GoodLatencyMs = d.GoodLatencyMs
	}
	if out.BadLatencyMs <= out.GoodLatencyMs {
		out.GoodLatencyMs = d.GoodLatencyMs
		out.BadLatencyMs = d.BadLatencyMs
	}
	if out.DegradeScoreFloor <= 0 || out.DegradeScoreFloor > 100 {
		out.DegradeScoreFloor = d.DegradeScoreFloor
	}
	if out.DegradeZScore <= 0 {
		out.DegradeZScore = d.DegradeZScore
	}
	if out.MinSamplesForZ <= 0 {
		out.MinSamplesForZ = d.MinSamplesForZ
	}
	if out.AlertCooldown <= 0 {
		out.AlertCooldown = d.AlertCooldown
	}
	if out.RawRetention <= 0 {
		out.RawRetention = d.RawRetention
	}
	if out.ScoreRetention <= 0 {
		out.ScoreRetention = d.ScoreRetention
	}
	if out.MaxIngestBatch <= 0 {
		out.MaxIngestBatch = d.MaxIngestBatch
	}
	return out
}

// Service is the DEM control-plane service.
type Service struct {
	repo   repository.DEMRepository
	alerts AlertGateway
	cfg    Config
	logger *slog.Logger
	now    func() time.Time
}

// Option customises a Service.
type Option func(*Service)

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClock overrides the wall clock (tests).
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// NewService constructs a Service. repo and alerts are required.
func NewService(repo repository.DEMRepository, alerts AlertGateway, cfg Config, opts ...Option) (*Service, error) {
	if repo == nil {
		return nil, errors.New("dem: NewService requires a repository")
	}
	if alerts == nil {
		return nil, errors.New("dem: NewService requires an alert gateway")
	}
	s := &Service{
		repo:   repo,
		alerts: alerts,
		cfg:    cfg.withDefaults(),
		logger: slog.Default(),
		now:    func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Config returns the effective (defaulted) configuration.
func (s *Service) Config() Config { return s.cfg }

// -----------------------------------------------------------------------
// Targets
// -----------------------------------------------------------------------

// ListEffectiveTargets returns the managed defaults overlaid with the
// tenant's custom targets — the exact set an agent should probe.
func (s *Service) ListEffectiveTargets(ctx context.Context, tenantID uuid.UUID) ([]repository.DEMTarget, error) {
	custom, err := s.allCustomTargets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return mergeEffectiveTargets(ManagedDefaultTargets(), custom), nil
}

// ListCustomTargets returns only the tenant's persisted custom targets.
func (s *Service) ListCustomTargets(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DEMTarget], error) {
	return s.repo.ListTargets(ctx, tenantID, page)
}

func (s *Service) allCustomTargets(ctx context.Context, tenantID uuid.UUID) ([]repository.DEMTarget, error) {
	var out []repository.DEMTarget
	page := repository.Page{Limit: repository.MaxPageLimit}
	for {
		res, err := s.repo.ListTargets(ctx, tenantID, page)
		if err != nil {
			return nil, fmt.Errorf("dem: list targets: %w", err)
		}
		out = append(out, res.Items...)
		if res.NextCursor == "" {
			return out, nil
		}
		page.After = res.NextCursor
	}
}

// CreateTarget validates and persists a custom target, applying
// default cadence/timeout when omitted.
func (s *Service) CreateTarget(ctx context.Context, tenantID uuid.UUID, t repository.DEMTarget) (repository.DEMTarget, error) {
	t = applyTargetDefaults(t)
	if err := validateTarget(t, true); err != nil {
		return repository.DEMTarget{}, err
	}
	return s.repo.CreateTarget(ctx, tenantID, t)
}

// GetTarget returns one custom target by id.
func (s *Service) GetTarget(ctx context.Context, tenantID, id uuid.UUID) (repository.DEMTarget, error) {
	return s.repo.GetTarget(ctx, tenantID, id)
}

// UpdateTarget validates and updates a custom target.
func (s *Service) UpdateTarget(ctx context.Context, tenantID uuid.UUID, t repository.DEMTarget) (repository.DEMTarget, error) {
	t = applyTargetDefaults(t)
	if err := validateTarget(t, false); err != nil {
		return repository.DEMTarget{}, err
	}
	return s.repo.UpdateTarget(ctx, tenantID, t)
}

// DeleteTarget removes a custom target by id.
func (s *Service) DeleteTarget(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.repo.DeleteTarget(ctx, tenantID, id)
}

func applyTargetDefaults(t repository.DEMTarget) repository.DEMTarget {
	if t.IntervalSeconds == 0 {
		t.IntervalSeconds = DefaultProbeIntervalSeconds
	}
	if t.TimeoutMs == 0 {
		t.TimeoutMs = DefaultProbeTimeoutMs
	}
	return t
}

func validateTarget(t repository.DEMTarget, requireKey bool) error {
	if requireKey && t.TargetKey == "" {
		return fmt.Errorf("%w: target_key required", repository.ErrInvalidArgument)
	}
	if t.Name == "" {
		return fmt.Errorf("%w: name required", repository.ErrInvalidArgument)
	}
	if !validProbeKind(t.ProbeKind) {
		return fmt.Errorf("%w: invalid probe_kind %q", repository.ErrInvalidArgument, t.ProbeKind)
	}
	if t.Address == "" {
		return fmt.Errorf("%w: address required", repository.ErrInvalidArgument)
	}
	if t.Port != nil && (*t.Port < 1 || *t.Port > 65535) {
		return fmt.Errorf("%w: port out of range", repository.ErrInvalidArgument)
	}
	if t.IntervalSeconds < 10 || t.IntervalSeconds > 3600 {
		return fmt.Errorf("%w: interval_seconds out of range [10,3600]", repository.ErrInvalidArgument)
	}
	if t.TimeoutMs < 100 || t.TimeoutMs > 30000 {
		return fmt.Errorf("%w: timeout_ms out of range [100,30000]", repository.ErrInvalidArgument)
	}
	return nil
}

// -----------------------------------------------------------------------
// Ingest + scoring
// -----------------------------------------------------------------------

// IngestResult summarises one ingest call.
type IngestResult struct {
	// Accepted is how many raw results were stored.
	Accepted int
	// Scores holds the freshly computed score per distinct target.
	Scores []repository.DEMExperienceScore
}

// Ingest stores a batch of probe results for one tenant and recomputes
// the experience score for each distinct target touched by the batch.
// Storage is all-or-nothing; per-target scoring is best-effort (a
// scoring failure for one target is logged and does not fail the
// ingest, since the raw results are already durably stored).
func (s *Service) Ingest(ctx context.Context, tenantID uuid.UUID, results []repository.DEMProbeResult) (IngestResult, error) {
	if tenantID == uuid.Nil {
		return IngestResult{}, repository.ErrInvalidArgument
	}
	if len(results) == 0 {
		return IngestResult{}, nil
	}
	if len(results) > s.cfg.MaxIngestBatch {
		return IngestResult{}, fmt.Errorf("%w: batch size %d exceeds max %d", repository.ErrInvalidArgument, len(results), s.cfg.MaxIngestBatch)
	}

	targetNames := make(map[string]string, len(results))
	for i := range results {
		if err := normalizeResult(&results[i]); err != nil {
			return IngestResult{}, fmt.Errorf("result %d: %w", i, err)
		}
		targetNames[results[i].TargetKey] = results[i].TargetName
	}

	if err := s.repo.InsertProbeResults(ctx, tenantID, results); err != nil {
		return IngestResult{}, fmt.Errorf("dem: insert probe results: %w", err)
	}

	keys := make([]string, 0, len(targetNames))
	for k := range targetNames {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := IngestResult{Accepted: len(results)}
	for _, key := range keys {
		score, scored, err := s.recomputeTarget(ctx, tenantID, key, targetNames[key])
		if err != nil {
			s.logger.ErrorContext(ctx, "dem: score recompute failed",
				slog.String("tenant_id", tenantID.String()),
				slog.String("target_key", key),
				slog.Any("error", err))
			continue
		}
		if scored {
			out.Scores = append(out.Scores, score)
		}
	}
	return out, nil
}

// normalizeResult validates and canonicalises one raw result in place.
func normalizeResult(r *repository.DEMProbeResult) error {
	if r.TargetKey == "" || r.TargetName == "" {
		return fmt.Errorf("%w: target_key and target_name required", repository.ErrInvalidArgument)
	}
	if !validProbeKind(r.ProbeKind) {
		return fmt.Errorf("%w: invalid probe_kind %q", repository.ErrInvalidArgument, r.ProbeKind)
	}
	if r.ObservedAt.IsZero() {
		return fmt.Errorf("%w: observed_at required", repository.ErrInvalidArgument)
	}
	if r.Success {
		// A successful probe carries no failure bucket.
		r.ErrorKind = ""
		return nil
	}
	if r.ErrorKind == "" {
		r.ErrorKind = ErrorKindInternal
	} else if !validErrorKind(r.ErrorKind) {
		return fmt.Errorf("%w: invalid error_kind %q", repository.ErrInvalidArgument, r.ErrorKind)
	}
	return nil
}

// recomputeTarget aggregates one target's rolling window, persists a
// score sample, and updates the baseline (raising an alert on
// degradation). scored is false when the window held no samples (e.g.
// only stale buffered results were ingested), in which case no score
// row is written.
func (s *Service) recomputeTarget(ctx context.Context, tenantID uuid.UUID, key, name string) (repository.DEMExperienceScore, bool, error) {
	since := s.now().Add(-time.Duration(s.cfg.WindowSeconds) * time.Second)
	agg, err := s.repo.WindowAggregate(ctx, tenantID, key, since)
	if err != nil {
		return repository.DEMExperienceScore{}, false, fmt.Errorf("window aggregate: %w", err)
	}
	if agg.SampleCount == 0 {
		return repository.DEMExperienceScore{}, false, nil
	}
	availability := float64(agg.SuccessCount) / float64(agg.SampleCount)
	score := repository.DEMExperienceScore{
		TargetKey:     key,
		TargetName:    name,
		Score:         s.cfg.experienceScore(availability, agg.LatencyP50Ms),
		Availability:  availability,
		LatencyP50Ms:  agg.LatencyP50Ms,
		LatencyP95Ms:  agg.LatencyP95Ms,
		SampleCount:   agg.SampleCount,
		WindowSeconds: s.cfg.WindowSeconds,
		WindowStart:   agg.WindowStart,
		WindowEnd:     agg.WindowEnd,
	}
	saved, err := s.repo.InsertScore(ctx, tenantID, score)
	if err != nil {
		return repository.DEMExperienceScore{}, false, fmt.Errorf("insert score: %w", err)
	}
	if err := s.updateBaseline(ctx, tenantID, saved, availability); err != nil {
		return saved, true, fmt.Errorf("update baseline: %w", err)
	}
	return saved, true, nil
}

// updateBaseline folds the new score into the per-target EWMA baseline
// and raises a degradation alert (respecting the cooldown) when the
// score is degraded relative to the pre-update baseline.
//
// The read-compute-write is done atomically through
// MutateTargetState, which holds a row-level lock for the whole cycle.
// This prevents concurrent ingests for the same (tenant, target_key)
// from each reading the same baseline and clobbering one another's
// EWMA contribution. The lock also serializes the cooldown gate so a
// burst of degraded samples raises at most one alert per cooldown.
//
// mutate runs under the lock and must stay pure, so the actual alert
// emission (a separate aggregate write) is deferred until after the
// transaction commits. We optimistically stamp last_alert_at inside
// the lock; on the rare emit failure the stamp is rolled back so the
// next window retries rather than being suppressed for a full
// cooldown.
func (s *Service) updateBaseline(ctx context.Context, tenantID uuid.UUID, score repository.DEMExperienceScore, availability float64) error {
	var (
		emit         bool
		decision     degradeDecision
		baselineMean float64
		baselineN    int64
	)

	saved, err := s.repo.MutateTargetState(ctx, tenantID, score.TargetKey, score.TargetName,
		func(prev repository.DEMTargetState) (repository.DEMTargetState, error) {
			n := prev.SampleCount
			var prevMean, prevVar float64
			if prev.EWMAScore != nil {
				prevMean = *prev.EWMAScore
			}
			if prev.EWMAVariance != nil {
				prevVar = *prev.EWMAVariance
			}

			decision = s.cfg.assessDegradation(n, prevMean, prevVar, score.Score)
			newMean, newVar := s.cfg.ewmaUpdate(n, prevMean, prevVar, score.Score)
			now := s.now()
			lastScore := score.Score

			next := repository.DEMTargetState{
				EWMAScore:      &newMean,
				EWMAVariance:   &newVar,
				LastScore:      &lastScore,
				SampleCount:    n + 1,
				Degraded:       decision.degraded,
				LastAlertAt:    prev.LastAlertAt,
				LastObservedAt: &now,
			}

			if decision.degraded {
				cooldownOK := prev.LastAlertAt == nil || now.Sub(*prev.LastAlertAt) >= s.cfg.AlertCooldown
				if cooldownOK {
					alertAt := now
					next.LastAlertAt = &alertAt
					emit = true
					baselineMean = prevMean
					baselineN = n
				}
			}
			return next, nil
		})
	if err != nil {
		return fmt.Errorf("mutate target state: %w", err)
	}

	if !emit {
		return nil
	}
	if err := s.emitDegradation(ctx, tenantID, score, availability, decision, baselineMean, baselineN); err != nil {
		// The cooldown stamp committed above but no alert went out;
		// clear it best-effort so the next window can retry instead of
		// staying silent for the full cooldown.
		s.clearAlertStamp(ctx, tenantID, saved)
		return fmt.Errorf("emit degradation alert: %w", err)
	}
	return nil
}

// clearAlertStamp rolls back an optimistic last_alert_at stamp after a
// failed alert emission so the degradation can re-alert on the next
// window rather than being suppressed for the whole cooldown. It is
// best-effort: a failure here only delays the retry, so it is logged
// and swallowed.
func (s *Service) clearAlertStamp(ctx context.Context, tenantID uuid.UUID, st repository.DEMTargetState) {
	_, err := s.repo.MutateTargetState(ctx, tenantID, st.TargetKey, st.TargetName,
		func(cur repository.DEMTargetState) (repository.DEMTargetState, error) {
			// Only clear the stamp we set; if another ingest already
			// advanced it, leave it alone.
			if cur.LastAlertAt != nil && st.LastAlertAt != nil && cur.LastAlertAt.Equal(*st.LastAlertAt) {
				cur.LastAlertAt = nil
			}
			return cur, nil
		})
	if err != nil {
		s.logger.WarnContext(ctx, "dem: failed to roll back alert cooldown stamp",
			slog.String("target_key", st.TargetKey), slog.Any("error", err))
	}
}

// emitDegradation raises a degradation alert via the alert router. The
// alert carries the score, availability, and the baseline context so
// it remains self-explaining after the baseline drifts.
func (s *Service) emitDegradation(
	ctx context.Context,
	tenantID uuid.UUID,
	score repository.DEMExperienceScore,
	availability float64,
	decision degradeDecision,
	baselineMean float64,
	baselineSamples int64,
) error {
	severity := repository.AlertSeverityWarning
	if availability <= 0 || score.Score < s.cfg.DegradeScoreFloor/2 {
		severity = repository.AlertSeverityCritical
	}

	evidence := map[string]any{
		"score":            score.Score,
		"availability":     availability,
		"sample_count":     score.SampleCount,
		"below_floor":      decision.belowFloor,
		"z_exceeded":       decision.zExceeded,
		"baseline_samples": baselineSamples,
	}
	if score.LatencyP50Ms != nil {
		evidence["latency_p50_ms"] = *score.LatencyP50Ms
	}
	if score.LatencyP95Ms != nil {
		evidence["latency_p95_ms"] = *score.LatencyP95Ms
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return fmt.Errorf("marshal evidence: %w", err)
	}

	alert := repository.Alert{
		Kind:           ExperienceDegradedKind,
		Severity:       severity,
		Dimension:      score.TargetKey,
		ObservedValue:  score.Score,
		BaselineMean:   baselineMean,
		BaselineStdDev: decision.stdDev,
		ZScore:         decision.zScore,
		WindowStart:    score.WindowStart,
		WindowEnd:      score.WindowEnd,
		WindowSeconds:  score.WindowSeconds,
		Summary: fmt.Sprintf("Experience degraded for %s: score %.0f, availability %.0f%%",
			score.TargetName, score.Score, availability*100),
		Evidence: raw,
		State:    repository.AlertStateOpen,
	}
	if _, err := s.alerts.Emit(ctx, tenantID, alert); err != nil {
		return err
	}
	return nil
}

// -----------------------------------------------------------------------
// Scores + alerts (read paths)
// -----------------------------------------------------------------------

// LatestScores returns the newest score per target for a tenant — the
// "current experience" dashboard view.
func (s *Service) LatestScores(ctx context.Context, tenantID uuid.UUID) ([]repository.DEMExperienceScore, error) {
	return s.repo.LatestScores(ctx, tenantID)
}

// ListScores returns the score timeseries matching the filter.
func (s *Service) ListScores(ctx context.Context, tenantID uuid.UUID, filter repository.DEMScoreFilter, page repository.Page) (repository.PageResult[repository.DEMExperienceScore], error) {
	return s.repo.ListScores(ctx, tenantID, filter, page)
}

// ListAlerts returns DEM degradation alerts for a tenant, optionally
// narrowed by state.
func (s *Service) ListAlerts(ctx context.Context, tenantID uuid.UUID, states []repository.AlertState, page repository.Page) (repository.PageResult[repository.Alert], error) {
	filter := repository.AlertListFilter{
		Kinds:  []string{ExperienceDegradedKind},
		States: states,
	}
	return s.alerts.List(ctx, tenantID, filter, page)
}

// -----------------------------------------------------------------------
// Retention
// -----------------------------------------------------------------------

// PruneRetention deletes raw results and score samples older than
// their configured retention horizons. Cross-tenant; intended to run
// on the leader replica only (see scheduler.go).
func (s *Service) PruneRetention(ctx context.Context) (rawPruned, scoresPruned int64, err error) {
	now := s.now()
	rawPruned, err = s.repo.PruneProbeResults(ctx, now.Add(-s.cfg.RawRetention))
	if err != nil {
		return 0, 0, fmt.Errorf("dem: prune probe results: %w", err)
	}
	scoresPruned, err = s.repo.PruneScores(ctx, now.Add(-s.cfg.ScoreRetention))
	if err != nil {
		return rawPruned, 0, fmt.Errorf("dem: prune scores: %w", err)
	}
	s.logger.InfoContext(ctx, "dem: retention sweep complete",
		slog.Int64("raw_pruned", rawPruned),
		slog.Int64("scores_pruned", scoresPruned))
	return rawPruned, scoresPruned, nil
}

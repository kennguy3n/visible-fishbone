// Package baseline — anomaly.go implements the
// AnomalyDetector. It sits BETWEEN the baseline service and the
// alert.Router: an Observation arrives, the Detector loads the
// current Baseline, scores the Observation against it, and
// emits an alert if the score crosses the model's threshold AND
// the estimator has seen enough warmup samples.
//
// The Observation is folded into the Baseline AFTER scoring so
// the alert reflects "how surprising was this observation given
// what we have learned SO FAR" — folding first would dilute
// the deviation by the new sample's own contribution to the
// mean, masking obvious spikes.
package baseline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AlertEmitter is the slice of the alert.Router API the
// Detector uses. Defining the interface here lets tests stub
// the Router without dragging in NATS / the alert package.
type AlertEmitter interface {
	// Emit persists the alert and routes it. Returns the
	// persisted Alert (with assigned ID / CreatedAt) or
	// ErrConflict / ErrInvalidArgument from the repository.
	Emit(ctx context.Context, tenantID uuid.UUID, a repository.Alert) (repository.Alert, error)
}

// DetectorOptions configures the Detector's emit-gating
// thresholds. Zero values fall back to the package defaults.
type DetectorOptions struct {
	// MinWarmupSamples is the minimum sample count required
	// before the Detector will emit alerts on a dimension.
	// Below this the estimator is too unstable. Defaults to
	// the package's MinWarmupSamples constant.
	MinWarmupSamples int64
	// WarningZScore is the **cold-start default** ZThreshold
	// stamped onto a freshly materialised BaselineModel when
	// no row exists yet for (tenant, dim, window). Once a row
	// is persisted the BaselineModel's own ZThreshold takes
	// over — the Detector emits at maxAbsZ >= model.ZThreshold
	// (warning) or maxAbsZ >= 1.5 * model.ZThreshold (critical),
	// regardless of WarningZScore.
	//
	// In particular the Detector does **not** floor the
	// effective threshold at WarningZScore: that would silently
	// override an operator's lower threshold (e.g. a 2.5σ
	// override on a noisy dimension) or the feedback tuning
	// loop's downward nudges (alert.FeedbackTuningOptions
	// MinZThreshold defaults to 2.0σ), which would make the
	// REST baseline.z_threshold field a lie. See PR #40 round-7
	// BUG_0001.
	WarningZScore float64
}

func (o DetectorOptions) fillDefaults() DetectorOptions {
	if o.MinWarmupSamples <= 0 {
		o.MinWarmupSamples = MinWarmupSamples
	}
	if o.WarningZScore <= 0 {
		o.WarningZScore = DefaultZThreshold
	}
	return o
}

// Detector wires the baseline.Service to an AlertEmitter and
// applies the deviation-score policy. One Detector per process;
// per-(tenant, dim) tuning lives on the Baseline itself.
type Detector struct {
	svc  *Service
	emit AlertEmitter
	opts DetectorOptions
	now  func() time.Time
}

// NewDetector constructs a Detector. emit may be nil — the
// Detector will skip emission in that case (useful for tests
// that only want to exercise the scoring path). now defaults to
// time.Now.UTC if nil.
func NewDetector(svc *Service, emit AlertEmitter, opts DetectorOptions) *Detector {
	return &Detector{
		svc:  svc,
		emit: emit,
		opts: opts.fillDefaults(),
		now:  func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall-clock source. Used by tests to
// pin CreatedAt / WindowStart on emitted alerts.
func (d *Detector) SetClock(fn func() time.Time) {
	if fn != nil {
		d.now = fn
	}
}

// ObserveAndScore is the main entry point. It performs the
// score-then-fold sequence:
//
//  1. Load the current Baseline.
//  2. Score the observation against the loaded Baseline.
//  3. Fold the observation into the Baseline and persist.
//  4. If max(|zW|, |zE|) >= model.ZThreshold AND samples >=
//     MinWarmupSamples, emit an alert. The threshold honoured
//     here is the BaselineModel's persisted ZThreshold — any
//     operator override (PUT /baselines/.../threshold) or
//     feedback tuning nudge is respected verbatim. The
//     DetectorOptions.WarningZScore field is **only** the
//     cold-start default applied when no row exists yet.
//
// Returns (foldedBaseline, alert?, error). alert is non-nil
// only when an alert was emitted; err is non-nil only when
// either the baseline persist OR the alert emit failed (i.e.
// "we did not score" vs "we scored but couldn't persist").
//
// Cold-start (no row exists) inserts a fresh Baseline (stamped
// with DetectorOptions.WarningZScore as the initial ZThreshold);
// no alert is emitted on the first observation regardless of
// score because the estimator has nothing to compare against.
func (d *Detector) ObserveAndScore(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
	obs Observation,
	kind string,
) (repository.BaselineModel, *repository.Alert, error) {
	if tenantID == uuid.Nil || dimension == "" || windowSeconds <= 0 {
		return repository.BaselineModel{}, nil, repository.ErrInvalidArgument
	}
	if kind == "" {
		kind = "baseline.zscore_exceeded"
	}
	// The load-score-fold-upsert sequence runs inside an
	// optimistic-lock retry loop matching Service.Observe.
	// Without the retry, a concurrent Observe / ObserveAndScore
	// that bumps the baseline's Version between our Get and
	// Upsert would surface ErrConflict to the caller and the
	// observation would be lost — silently dropping data is
	// worse than scoring against a slightly more recent state
	// (the rescored value reflects the latest mean/EWMA, which
	// is what we want anyway).
	//
	// Each retry re-loads the baseline so the score is computed
	// against the pre-update state that we are about to fold
	// into; this preserves the "score against what we have
	// learned SO FAR" semantics documented at the package head.
	//
	// See Service.Observe (engine.go) for the canonical pattern;
	// the only difference here is we also stash zW / zE / maxZ
	// across the loop so the alert emit at the bottom uses the
	// values that match the successfully-persisted baseline.
	var (
		cur     repository.BaselineModel
		saved   repository.BaselineModel
		zW      float64
		zE      float64
		maxZ    float64
		lastErr error
	)
	loaded := false
	for attempt := 0; attempt < d.svc.maxRetry; attempt++ {
		// 1. Load (or materialise cold-start) the current Baseline.
		got, err := d.svc.repo.GetForDimension(ctx, tenantID, dimension, windowSeconds)
		if errors.Is(err, repository.ErrNotFound) {
			got = repository.BaselineModel{
				TenantID:      tenantID,
				Dimension:     dimension,
				WindowSeconds: windowSeconds,
				Alpha:         DefaultAlpha,
				// Cold-start default — once persisted, the
				// operator + feedback tuning loop own this
				// value via UpdateThreshold. See
				// DetectorOptions.WarningZScore doc.
				ZThreshold: d.opts.WarningZScore,
			}
		} else if err != nil {
			return repository.BaselineModel{}, nil, fmt.Errorf("anomaly load baseline: %w", err)
		}
		cur = got
		loaded = true

		// 2. Score the observation against the PRE-update state.
		zW, zE = d.svc.engine.Score(cur, obs)
		maxZ = MaxAbsZ(zW, zE)

		// 3. Fold into the Baseline + persist.
		folded := d.svc.engine.Fold(cur, obs)
		var err2 error
		saved, err2 = d.svc.repo.Upsert(ctx, tenantID, folded)
		if err2 == nil {
			lastErr = nil
			break
		}
		if errors.Is(err2, repository.ErrConflict) {
			// Another writer raced us; re-load and re-score.
			lastErr = err2
			continue
		}
		return repository.BaselineModel{}, nil, fmt.Errorf("anomaly upsert baseline: %w", err2)
	}
	if !loaded {
		// d.svc.maxRetry <= 0 should be unreachable (NewService
		// fills the default), but guard anyway so callers don't
		// observe a zero BaselineModel paired with nil err.
		return repository.BaselineModel{}, nil, fmt.Errorf("anomaly: invalid maxRetry configuration")
	}
	if lastErr != nil {
		return repository.BaselineModel{}, nil, fmt.Errorf("anomaly upsert baseline: %w", lastErr)
	}

	// 4. Emit gate. Warmup AND score-above-threshold both required.
	//
	// We honour cur.ZThreshold verbatim. Pre-round-7 this took
	// max(cur.ZThreshold, d.opts.WarningZScore) which silently
	// overrode operator + feedback-tuned thresholds below the
	// default 3.0σ. WarningZScore is now only the cold-start
	// default applied above when no row exists. See PR #40
	// round-7 BUG_0001 and the BaselineModel.ZThreshold doc.
	threshold := cur.ZThreshold
	if cur.Samples < d.opts.MinWarmupSamples || maxZ < threshold {
		return saved, nil, nil
	}
	if d.emit == nil {
		// Useful for tests that only want to exercise the
		// scoring path without an emit stub.
		return saved, nil, nil
	}

	severity := repository.AlertSeverityWarning
	// 1.5x threshold escalates to critical — a 4.5σ event
	// on the default 3.0σ threshold is single-tenant
	// outage territory.
	if maxZ >= threshold*1.5 {
		severity = repository.AlertSeverityCritical
	}

	now := d.now()
	evidence, _ := json.Marshal(map[string]any{
		"z_welford":          zW,
		"z_ewma":             zE,
		"max_abs_z":          maxZ,
		"alpha":              cur.Alpha,
		"window_seconds":     windowSeconds,
		"baseline_samples":   cur.Samples,
		"baseline_ewma":      cur.EWMA,
		"baseline_ewma_var":  cur.EWMAVar,
		"observed_value":     obs.Value,
		"threshold_z":        threshold,
		"min_warmup_samples": d.opts.MinWarmupSamples,
	})

	summary := fmt.Sprintf(
		"%s on %s: observed=%.3f mean=%.3f stddev=%.3f z=%.2fσ (warning ≥ %.2fσ)",
		kind, dimension, obs.Value, cur.Mean, cur.StdDev(), maxZ, threshold,
	)

	stddev := cur.StdDev()
	if stddev == 0 || math.IsNaN(stddev) {
		stddev = cur.EWMAStdDev()
	}

	a := repository.Alert{
		TenantID:       tenantID,
		Kind:           kind,
		Severity:       severity,
		Dimension:      dimension,
		ObservedValue:  obs.Value,
		BaselineMean:   cur.Mean,
		BaselineStdDev: stddev,
		ZScore:         maxZ,
		WindowStart:    now.Add(-time.Duration(windowSeconds) * time.Second),
		WindowEnd:      now,
		WindowSeconds:  windowSeconds,
		Summary:        summary,
		Evidence:       evidence,
		State:          repository.AlertStateOpen,
	}
	emitted, err := d.emit.Emit(ctx, tenantID, a)
	if err != nil {
		return saved, nil, fmt.Errorf("anomaly emit: %w", err)
	}
	return saved, &emitted, nil
}

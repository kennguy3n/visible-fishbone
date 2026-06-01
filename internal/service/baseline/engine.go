// Package baseline implements the statistical baseline + anomaly
// detection layer documented in PROPOSAL §3 (Self-Explaining
// Behaviour Models) and migration 012_baseline_models.sql.
//
// The package decomposes into three layers:
//
//	Engine        — pure online arithmetic (Welford + EWMA).
//	                Given a Baseline + an Observation, returns the
//	                Baseline folded with that sample. Stateless;
//	                no clocks, no I/O.
//
//	Service       — load-modify-store loop over Engine on top of
//	                a BaselineModelRepository. Handles the
//	                optimistic-lock retry on Upsert conflict.
//
//	AnomalyDetector — score a fresh observation against the
//	                stored baseline; emit an alert via the
//	                alert.Router when |max(z_welford, z_ewma)|
//	                exceeds the model's ZThreshold and the
//	                Engine has seen enough warmup samples to
//	                make the score meaningful.
//
// The split keeps the arithmetic deterministic + trivially
// testable. Engine has no dependency on the repository at all;
// AnomalyDetector consumes the repository through interfaces so
// the alert.Router stub can be swapped in for tests.
package baseline

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Defaults applied when a Baseline is materialised cold-start.
const (
	// DefaultAlpha is the EWMA decay used when no per-tenant
	// override is configured. 0.1 captures recent regime shifts
	// across roughly the last 10 observations under the typical
	// 1-minute bucket — fast enough to trip on a malware-outbreak
	// DNS surge in single-digit minutes but slow enough to ignore
	// minute-scale jitter on otherwise-steady traffic.
	DefaultAlpha = 0.1

	// DefaultZThreshold is the per-tenant operator-tunable
	// z-score that wakes an operator. 3.0 captures ~0.27% of
	// normal observations under a Gaussian assumption; the
	// feedback loop in alert.Feedback raises this on a noisy
	// dimension and lowers it on a quiet one.
	DefaultZThreshold = 3.0

	// MinWarmupSamples is the minimum sample count Engine must
	// have folded before AnomalyDetector will emit alerts on
	// the dimension. Below this, the estimator is too unstable
	// to score deviation. 30 mirrors the convention used by
	// most "n>30 => normal-ish" online estimators.
	MinWarmupSamples int64 = 30
)

// Observation is a single sample fed into the baseline. It is
// the unit of the Engine's online update — one observation per
// (tenant, dimension, window_seconds) per fold call.
type Observation struct {
	// Value is the metric value for this bucket, e.g. count of
	// failed-auth events, total bytes_in, count of NXDOMAIN
	// responses.
	Value float64
	// At is the wall-clock time of the observation (typically
	// the bucket's right edge). Used to stamp LastObservedAt
	// on the persisted model.
	At time.Time
}

// Engine is the pure online estimator. It owns no state; every
// method takes the current Baseline + an Observation and
// returns the folded Baseline. The Service layer is responsible
// for round-tripping the value through the repository.
//
// The split keeps the arithmetic stateless + race-free: two
// concurrent goroutines can call Fold on the same Baseline
// without coordinating, and the only contention is on the
// repository UPSERT (which is gated by an optimistic-lock
// retry).
type Engine struct{}

// NewEngine returns a stateless Engine. There is no
// configuration — the only knobs (Alpha, ZThreshold) travel
// with the Baseline itself so per-(tenant, dim) tuning works.
func NewEngine() *Engine { return &Engine{} }

// Fold applies one Observation to a Baseline and returns the
// updated state. The folding is order-stable (commutative
// across the Welford branch, NOT commutative across the EWMA
// branch — the latter is inherent to "exponentially-weighted
// MOVING average").
//
// The arithmetic is:
//
//	n      = baseline.Samples + 1
//	delta  = obs.Value - baseline.Mean
//	mean'  = baseline.Mean + delta / n
//	delta2 = obs.Value - mean'           // intentionally
//	                                     // uses the NEW mean
//	m2'    = baseline.M2 + delta * delta2
//
//	ewma'  = alpha*obs + (1-alpha)*baseline.EWMA   (cold:
//	         baseline.EWMA = obs.Value on the first sample)
//	dev    = obs.Value - baseline.EWMA   (deviation from PRE-
//	                                      update EWMA so the
//	                                      variance update sees
//	                                      the same residual the
//	                                      EWMA itself absorbed)
//	ewmaVar' = alpha*dev*dev + (1-alpha)*baseline.EWMAVar
//
// Defaults: Alpha defaults to DefaultAlpha if the supplied
// Baseline has Alpha == 0; ZThreshold defaults to
// DefaultZThreshold when zero. The defaults are applied to the
// RETURNED Baseline so the caller can persist the resolved
// values.
func (e *Engine) Fold(b repository.BaselineModel, obs Observation) repository.BaselineModel {
	out := b

	alpha := out.Alpha
	if alpha <= 0 || alpha > 1 {
		alpha = DefaultAlpha
	}
	out.Alpha = alpha

	if out.ZThreshold <= 0 {
		out.ZThreshold = DefaultZThreshold
	}

	// --- Welford running mean / M2 (sample variance) ---
	n := out.Samples + 1
	delta := obs.Value - out.Mean
	out.Mean += delta / float64(n)
	delta2 := obs.Value - out.Mean
	out.M2 += delta * delta2
	out.Samples = n

	// --- EWMA ---
	if n == 1 {
		// Cold start: the EWMA starts at the first
		// observation so the estimator does not have to
		// climb from zero. The EWMAVar starts at 0 — we
		// have no residual to feed in.
		out.EWMA = obs.Value
		out.EWMAVar = 0
	} else {
		dev := obs.Value - out.EWMA
		out.EWMA = alpha*obs.Value + (1-alpha)*out.EWMA
		out.EWMAVar = alpha*dev*dev + (1-alpha)*out.EWMAVar
	}

	if !obs.At.IsZero() {
		out.LastObservedAt = obs.At.UTC()
	}
	return out
}

// Score returns the two z-scores (Welford-based and EWMA-based)
// for the supplied observation against the supplied baseline.
// The score is computed against the PRE-update state — the
// AnomalyDetector calls Score on the loaded Baseline before
// calling Fold on the new sample so the alert reflects "how
// surprising was this observation given what we have learned so
// far". When samples < 2 the standard deviation is undefined
// and both scores return 0 (the AnomalyDetector additionally
// gates on MinWarmupSamples before emitting).
//
// The deviation score the AnomalyDetector ultimately uses is
// max(|z_welford|, |z_ewma|) — see anomaly.go.
func (e *Engine) Score(b repository.BaselineModel, obs Observation) (zWelford, zEWMA float64) {
	if b.Samples < 2 {
		return 0, 0
	}
	stdw := b.StdDev()
	if stdw > 0 {
		zWelford = (obs.Value - b.Mean) / stdw
	}
	stde := b.EWMAStdDev()
	if stde > 0 {
		zEWMA = (obs.Value - b.EWMA) / stde
	}
	return zWelford, zEWMA
}

// MaxAbsZ returns max(|zWelford|, |zEWMA|) — the score the
// AnomalyDetector compares against the model's ZThreshold.
func MaxAbsZ(zWelford, zEWMA float64) float64 {
	a := math.Abs(zWelford)
	b := math.Abs(zEWMA)
	if a > b {
		return a
	}
	return b
}

// Service is the load-modify-store loop over Engine. Observe is
// the only meaningful entry point; it loads the current
// Baseline for (tenant, dim, window), folds the observation,
// and writes the result back through the optimistic-lock retry.
type Service struct {
	repo     repository.BaselineModelRepository
	engine   *Engine
	maxRetry int
}

// NewService returns a baseline.Service bound to the supplied
// repository. The Engine is owned internally (no per-tenant
// state lives in Engine, so one instance is shared across the
// process).
func NewService(repo repository.BaselineModelRepository) *Service {
	return &Service{repo: repo, engine: NewEngine(), maxRetry: 5}
}

// Engine returns the internal estimator. Tests + the
// AnomalyDetector reuse the same Engine to score observations
// before they are folded.
func (s *Service) Engine() *Engine { return s.engine }

// Observe folds a single observation into the baseline for
// (tenant, dimension, windowSeconds). Cold-start baselines are
// materialised with DefaultAlpha + DefaultZThreshold; subsequent
// observations round-trip through the optimistic-lock retry
// loop.
//
// Returns the folded Baseline. ErrConflict is retried up to
// s.maxRetry times before being surfaced to the caller.
func (s *Service) Observe(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
	obs Observation,
) (repository.BaselineModel, error) {
	if tenantID == uuid.Nil || dimension == "" || windowSeconds <= 0 {
		return repository.BaselineModel{}, repository.ErrInvalidArgument
	}
	var lastErr error
	for attempt := 0; attempt < s.maxRetry; attempt++ {
		cur, err := s.repo.GetForDimension(ctx, tenantID, dimension, windowSeconds)
		if errors.Is(err, repository.ErrNotFound) {
			cur = repository.BaselineModel{
				TenantID:      tenantID,
				Dimension:     dimension,
				WindowSeconds: windowSeconds,
				Alpha:         DefaultAlpha,
				ZThreshold:    DefaultZThreshold,
			}
		} else if err != nil {
			return repository.BaselineModel{}, fmt.Errorf("baseline get: %w", err)
		}
		folded := s.engine.Fold(cur, obs)
		saved, err := s.repo.Upsert(ctx, tenantID, folded)
		if err == nil {
			return saved, nil
		}
		if errors.Is(err, repository.ErrConflict) {
			lastErr = err
			continue
		}
		return repository.BaselineModel{}, fmt.Errorf("baseline upsert: %w", err)
	}
	if lastErr == nil {
		lastErr = repository.ErrConflict
	}
	return repository.BaselineModel{}, fmt.Errorf("baseline observe: %w", lastErr)
}

// Package alert — feedback.go implements the operator feedback
// loop documented in Task 15. Operators mark alerts as
// true_positive / false_positive / noise; the Feedback service
// (1) persists the feedback in alert_feedback, and (2) runs a
// per-dimension tuning loop that adjusts the baseline's
// ZThreshold based on the accumulated false-positive rate.
//
// Tuning policy:
//
//   - false_positive rate >= 0.5 in the last LookbackWindow
//     → raise ZThreshold by 0.5σ (capped at MaxZThreshold).
//   - false_positive rate <= 0.05 and noise rate <= 0.05
//     → lower ZThreshold by 0.25σ (floored at MinZThreshold).
//   - otherwise: no change.
//
// The loop is conservative: it only nudges; never overshoots.
// The MinSampleCount gate ensures we don't tune off a single
// feedback datum.
package alert

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// TenantActivitySource yields the cheap (id, last_active_at) projection
// the dormancy sweep buckets tenants by. It mirrors the identity package's
// source of the same name (both are satisfied by the tenant repository),
// letting the tuning loop reuse the shared tenancy.TieredSweep instead of
// re-tuning every tenant's baselines every cycle.
type TenantActivitySource interface {
	ListTenantActivity(ctx context.Context) ([]repository.TenantActivity, error)
}

// defaultRunConcurrency caps the number of tenants the Run
// background loop processes in parallel per tick. The choice
// of 16 trades total tick latency for predictable database
// load: a single tick at this concurrency caps the open
// repository connections at roughly 16 (one List per tenant
// plus a handful of TuneDimension lookups) regardless of the
// total tenant count. Operators with thousands of tenants no
// longer see one goroutine — and one set of connection
// acquisitions — per tenant.
const defaultRunConcurrency = 16

// FeedbackTuningOptions configure the Feedback tuning loop.
type FeedbackTuningOptions struct {
	// LookbackWindow bounds how far back the tuning loop
	// looks when computing the FP rate. Defaults to 14 days.
	LookbackWindow time.Duration
	// MinSampleCount is the minimum feedback row count
	// required before the loop will adjust the threshold.
	// Defaults to 5.
	MinSampleCount int
	// MaxZThreshold caps how high the loop will raise the
	// threshold. Defaults to 6.0σ — beyond this the metric is
	// effectively muted anyway and the operator should add a
	// suppression instead.
	MaxZThreshold float64
	// MinZThreshold floors how low the loop will lower the
	// threshold. Defaults to 2.0σ.
	MinZThreshold float64
	// RaiseStep is the additive nudge applied when the FP
	// rate is high. Defaults to 0.5σ.
	RaiseStep float64
	// LowerStep is the (positive) additive nudge subtracted
	// when both FP and noise rates are low. Defaults to 0.25σ.
	LowerStep float64
	// RunConcurrency bounds how many tenants Run processes in
	// parallel per tick. Zero / negative → defaultRunConcurrency.
	// A value greater than the tenant count is harmless — the
	// limiter caps actually-spawned goroutines.
	RunConcurrency int
}

func (o FeedbackTuningOptions) fillDefaults() FeedbackTuningOptions {
	if o.LookbackWindow <= 0 {
		o.LookbackWindow = 14 * 24 * time.Hour
	}
	if o.MinSampleCount <= 0 {
		o.MinSampleCount = 5
	}
	if o.MaxZThreshold <= 0 {
		o.MaxZThreshold = 6.0
	}
	if o.MinZThreshold <= 0 {
		o.MinZThreshold = 2.0
	}
	if o.RaiseStep <= 0 {
		o.RaiseStep = 0.5
	}
	if o.LowerStep <= 0 {
		o.LowerStep = 0.25
	}
	if o.RunConcurrency <= 0 {
		o.RunConcurrency = defaultRunConcurrency
	}
	return o
}

// Feedback wires the alert.Feedback service together with the
// baseline repository for threshold tuning. The tuning loop is
// triggered on-demand via TuneDimension and (optionally) on a
// fixed cadence via Run.
type Feedback struct {
	feedback repository.AlertFeedbackRepository
	alerts   repository.AlertRepository
	baseline repository.BaselineModelRepository
	opts     FeedbackTuningOptions
	now      func() time.Time
	// logger receives operational events from the Run
	// background loop. It is also used by TuneDimension /
	// tickOnce to surface per-dimension failures without
	// aborting the tick. Defaults to slog.Default() when
	// NewFeedback is called without an explicit logger via
	// SetLogger — the Run docstring promises a logger is
	// always present, so the field is never nil at use time.
	logger *slog.Logger

	// sweep + activity, when both set (via WithDormancySweep), make the
	// Run tuning loop activity-tiered through the shared
	// tenancy.TieredSweep helper: active tenants are re-tuned every
	// cycle, idle/dormant ones at a reduced cadence, instead of walking
	// every tenant's baselines every tick. nil keeps the legacy
	// every-tenant fan-out via the tenantsFn passed to Run.
	sweep    *tenancy.TieredSweep
	activity TenantActivitySource
}

// NewFeedback constructs a Feedback service. The tuning loop
// logs operational events through slog.Default(); callers that
// want a scoped logger should call SetLogger immediately after
// construction.
func NewFeedback(
	feedback repository.AlertFeedbackRepository,
	alerts repository.AlertRepository,
	baseline repository.BaselineModelRepository,
	opts FeedbackTuningOptions,
) *Feedback {
	return &Feedback{
		feedback: feedback,
		alerts:   alerts,
		baseline: baseline,
		opts:     opts.fillDefaults(),
		now:      func() time.Time { return time.Now().UTC() },
		logger:   slog.Default(),
	}
}

// SetLogger overrides the logger used by the Run / tickOnce
// background loop. Passing nil resets to slog.Default(). Wiring
// a scoped logger here gives operators a single attribute key
// (e.g. component=alert-feedback) to filter the tuning loop's
// diagnostics in production.
func (f *Feedback) SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}
	f.logger = l
}

// SetClock overrides the wall-clock source; used by tests.
func (f *Feedback) SetClock(fn func() time.Time) {
	if fn != nil {
		f.now = fn
	}
}

// WithDormancySweep makes the Run tuning loop activity-tiered using the
// shared tenancy.TieredSweep helper. Once set, each tick loads the cheap
// (id, last_active_at) projection from `activity` and lets the sweep
// decide which tenants to re-tune this cycle: active tenants every tick,
// idle/dormant ones at a reduced cadence. Cycle 0 (the first tick) tunes
// every tenant, so enabling this never delays a tenant's first tuning.
// Passing a nil sweep or activity source is a no-op (legacy every-tenant
// fan-out via the tenantsFn given to Run is retained), so wiring is
// fail-safe. Returns the receiver for chaining at construction.
func (f *Feedback) WithDormancySweep(sweep *tenancy.TieredSweep, activity TenantActivitySource) *Feedback {
	if sweep != nil && activity != nil {
		f.sweep = sweep
		f.activity = activity
	}
	return f
}

// Submit persists feedback on an alert. The caller passes the
// alert ID, the decision, optional notes, and the operator ID.
// Returns ErrConflict when feedback already exists for the
// alert (one feedback row per alert, by design).
func (f *Feedback) Submit(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
	decision repository.AlertFeedbackDecision,
	notes string,
	by *uuid.UUID,
) (repository.AlertFeedback, error) {
	if tenantID == uuid.Nil || alertID == uuid.Nil {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	if !decision.IsValid() {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	return f.feedback.Create(ctx, tenantID, repository.AlertFeedback{
		AlertID:   alertID,
		Decision:  decision,
		Notes:     notes,
		CreatedBy: by,
	})
}

// GetForAlert returns the feedback row for one alert (if any).
func (f *Feedback) GetForAlert(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
) (repository.AlertFeedback, error) {
	return f.feedback.GetForAlert(ctx, tenantID, alertID)
}

// Delete removes feedback for an alert.
func (f *Feedback) Delete(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
) error {
	return f.feedback.Delete(ctx, tenantID, alertID)
}

// TuningResult summarises one tuning decision so the caller can
// log / surface what the loop did. Action is one of "raised",
// "lowered", or "no_change".
type TuningResult struct {
	TenantID       uuid.UUID
	Dimension      string
	WindowSeconds  int
	OldZThreshold  float64
	NewZThreshold  float64
	FalsePositive  int
	TruePositive   int
	Noise          int
	TotalFeedback  int
	FalsePositiveR float64
	NoiseR         float64
	Action         string
	SkippedReason  string
}

// TuneDimension inspects the recent feedback for (tenant, dim)
// and applies the tuning policy. Returns a TuningResult that
// describes the action taken. The caller can ignore the result
// for fire-and-forget tuning, or surface it for an operator
// audit log.
func (f *Feedback) TuneDimension(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
) (TuningResult, error) {
	if tenantID == uuid.Nil || dimension == "" || windowSeconds <= 0 {
		return TuningResult{}, repository.ErrInvalidArgument
	}
	since := f.now().Add(-f.opts.LookbackWindow)
	// Scope by windowSeconds so a noisy 60s window's FP rate
	// does not silently push the 3600s window's threshold up
	// (or vice versa) for the same dimension. The Alert struct
	// carries window_seconds as a first-class field for exactly
	// this filter — see PR #40 round-9 ANALYSIS_0002.
	rows, err := f.feedback.ListByDimension(ctx, tenantID, dimension, windowSeconds, since)
	if err != nil {
		return TuningResult{}, fmt.Errorf("feedback list: %w", err)
	}
	res := TuningResult{
		TenantID:      tenantID,
		Dimension:     dimension,
		WindowSeconds: windowSeconds,
		TotalFeedback: len(rows),
		Action:        "no_change",
	}
	if len(rows) < f.opts.MinSampleCount {
		res.SkippedReason = "below MinSampleCount"
		return res, nil
	}
	for _, r := range rows {
		switch r.Decision {
		case repository.AlertFeedbackTruePositive:
			res.TruePositive++
		case repository.AlertFeedbackFalsePositive:
			res.FalsePositive++
		case repository.AlertFeedbackNoise:
			res.Noise++
		}
	}
	total := float64(len(rows))
	res.FalsePositiveR = float64(res.FalsePositive) / total
	res.NoiseR = float64(res.Noise) / total

	current, err := f.baseline.GetForDimension(ctx, tenantID, dimension, windowSeconds)
	if errors.Is(err, repository.ErrNotFound) {
		res.SkippedReason = "no baseline"
		return res, nil
	}
	if err != nil {
		return TuningResult{}, fmt.Errorf("baseline get: %w", err)
	}
	res.OldZThreshold = current.ZThreshold

	switch {
	case res.FalsePositiveR >= 0.5:
		next := math.Min(current.ZThreshold+f.opts.RaiseStep, f.opts.MaxZThreshold)
		if next > current.ZThreshold {
			res.Action = "raised"
			res.NewZThreshold = next
		} else {
			res.Action = "no_change"
			res.NewZThreshold = current.ZThreshold
			res.SkippedReason = "already at MaxZThreshold"
		}
	case res.FalsePositiveR <= 0.05 && res.NoiseR <= 0.05:
		next := math.Max(current.ZThreshold-f.opts.LowerStep, f.opts.MinZThreshold)
		if next < current.ZThreshold {
			res.Action = "lowered"
			res.NewZThreshold = next
		} else {
			res.Action = "no_change"
			res.NewZThreshold = current.ZThreshold
			res.SkippedReason = "already at MinZThreshold"
		}
	default:
		res.NewZThreshold = current.ZThreshold
	}
	if res.Action == "raised" || res.Action == "lowered" {
		if _, err := f.baseline.UpdateThreshold(ctx, tenantID, dimension, windowSeconds, res.NewZThreshold); err != nil {
			return TuningResult{}, fmt.Errorf("baseline update threshold: %w", err)
		}
	}
	return res, nil
}

// Run starts a goroutine that calls TuneDimension once per
// `interval` across every (tenant, dimension, window_seconds)
// the repository knows about. Cancellation through ctx stops
// the loop.
//
// Each tick processes every baseline for every tenant. Tenant
// fan-out is bounded by opts.RunConcurrency (default 16) so
// the tick produces at most that many in-flight per-tenant
// goroutines regardless of the operator's tenant count. Per-
// tenant baseline iteration remains sequential within each
// goroutine, capping concurrent repository connections at
// RunConcurrency. The loop is resilient: any per-dimension
// failure is logged via the supplied logger (or slog.Default())
// and does NOT abort the tick.
func (f *Feedback) Run(
	ctx context.Context,
	interval time.Duration,
	tenantsFn func(ctx context.Context) ([]uuid.UUID, error),
) {
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.tickOnce(ctx, tenantsFn)
		}
	}
}

func (f *Feedback) tickOnce(ctx context.Context, tenantsFn func(ctx context.Context) ([]uuid.UUID, error)) {
	tenants, err := f.dueTenants(ctx, tenantsFn)
	if err != nil {
		f.logger.Warn("feedback tuning tick: tenants enumeration failed",
			slog.Any("error", err))
		return
	}
	// errgroup.WithContext + SetLimit caps the per-tick goroutine
	// count and connection-pool pressure at RunConcurrency.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(f.opts.RunConcurrency)
	for _, tid := range tenants {
		tenantID := tid
		g.Go(func() error {
			// Cursor-loop through every baseline for this
			// tenant. The previous implementation passed
			// `Limit: 1000`, which the repository clamps to
			// `MaxPageLimit = 200` — so high-cardinality
			// tenants with more than 200 (dimension,
			// window_seconds) tuples silently dropped the
			// tail and their thresholds were NEVER tuned. The
			// page-by-page walk uses the cursor returned by
			// the repo (DefaultPageLimit per page) and stops
			// when NextCursor is empty.
			//
			// Per-tenant List failure on the FIRST page is
			// logged and the tenant skipped — a transient repo
			// error (pool exhaustion, single tenant's RLS row
			// missing) must not silently disable threshold
			// tuning for every other tenant on the same tick.
			// Mid-walk List errors are also logged but break
			// the walk for THIS tenant (preserving completed
			// pages' tuning work).
			cursor := ""
			for {
				pg, err := f.baseline.List(gctx, tenantID, repository.Page{After: cursor})
				if err != nil {
					f.logger.Warn("feedback tuning tick: baseline list failed",
						slog.String("tenant_id", tenantID.String()),
						slog.String("cursor", cursor),
						slog.Any("error", err))
					return nil
				}
				for _, m := range pg.Items {
					if _, err := f.TuneDimension(gctx, tenantID, m.Dimension, m.WindowSeconds); err != nil {
						f.logger.Warn("feedback tuning tick: TuneDimension failed",
							slog.String("tenant_id", tenantID.String()),
							slog.String("dimension", m.Dimension),
							slog.Int("window_seconds", m.WindowSeconds),
							slog.Any("error", err))
						// Continue iterating: a noisy dimension's
						// failure must not block other dimensions on
						// the same tenant.
					}
				}
				if pg.NextCursor == "" {
					return nil
				}
				cursor = pg.NextCursor
				// Honour ctx cancellation between pages so a
				// long-running per-tenant walk does not pin a
				// goroutine past the parent context's deadline.
				if gctx.Err() != nil {
					return nil
				}
			}
		})
	}
	_ = g.Wait()
}

// dueTenants returns the tenants to tune this tick. With a dormancy
// sweep configured it loads the cheap (id, last_active_at) projection
// and lets the shared TieredSweep gate by activity tier — advancing the
// cycle counter, exporting the per-tier metric, and logging the skip
// count so the saving is observable. Without a sweep it falls back to
// the tenantsFn passed to Run (legacy every-tenant fan-out).
func (f *Feedback) dueTenants(ctx context.Context, tenantsFn func(ctx context.Context) ([]uuid.UUID, error)) ([]uuid.UUID, error) {
	if f.sweep == nil || f.activity == nil {
		return tenantsFn(ctx)
	}
	acts, err := f.activity.ListTenantActivity(ctx)
	if err != nil {
		return nil, err
	}
	cyc := f.sweep.Begin(f.now())
	due := cyc.Due(acts)
	cyc.Finish()
	if summary := cyc.Summary(); summary.Skipped > 0 {
		f.logger.Debug("feedback tuning tick: activity-tiered sweep",
			slog.Int64("cycle", summary.Cycle),
			slog.Int("total", summary.Total),
			slog.Int("visited", summary.Visited),
			slog.Int("skipped", summary.Skipped),
			slog.Int("active", summary.Active),
			slog.Int("idle", summary.Idle),
			slog.Int("dormant", summary.Dormant),
		)
	}
	return due, nil
}

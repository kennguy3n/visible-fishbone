// Package telemetry — autotune.go implements closed-loop tuning of
// the ClickHouse writer's batch size so the hot path holds a healthy
// INSERT frequency as fleet-wide telemetry volume changes.
//
// Why this exists. ClickHouse ingests millions of rows/sec per node
// without trouble; its dominant write-side failure mode is "too many
// parts" — every INSERT creates a part, and a high part-creation rate
// starves the background merge scheduler (docs/scaling.md §3.2). The
// healthy target is therefore a *low insert frequency*, not a row
// ceiling. The per-shard insert frequency is:
//
//	inserts_per_sec = rows_per_sec / batch_size
//
// so the lever is batch size: more rows per part ⇒ fewer inserts/sec.
// A static CLICKHOUSE_BATCH_SIZE cannot satisfy this across the tier
// range — the docs show the default 1024 producing 2.6 inserts/s at
// 1K tenants and 12.9 at 5K — and hand-tuning it per deployment is
// exactly the operational burden the platform is built to avoid. The
// autotuner closes the loop: it measures the live insert rate and
// moves batch size to hold inserts/sec at a target (~2/sec by
// default), so a deployment self-tunes from 1K to 5K tenants without
// an operator touching the knob.
//
// Control model. Each tick the tuner differences the writer's
// cumulative row and insert counters over the elapsed interval to get
// the live rows/sec, then computes the batch size that *would* land
// the insert rate exactly on target at that row rate:
//
//	desired_batch = rows_per_sec / target_inserts_per_sec
//
// (Little's-law batching: a batch holds 1/target seconds of arrivals.)
// The effective batch size is moved toward desired_batch by an
// exponential-moving-average step (Smoothing) so a transient burst
// nudges rather than slams the knob, and the result is clamped to
// [MinBatchSize, MaxBatchSize]. At the converged set-point the
// size trigger always fires before the writer's FlushInterval, so the
// realised insert rate equals the target; below that volume the
// interval trigger binds and the insert rate sits *under* target
// (strictly healthy — fewer parts). The controller is therefore a
// one-sided guarantee: it never drives the insert rate *above* target.
//
// Scope & cost. One tuner manages one or more writers (one per
// ClickHouse shard — "too many parts" is a per-shard failure mode), so
// it runs a single background goroutine for the whole fleet regardless
// of tenant count: there is no per-tenant state and no per-tenant
// goroutine, which is the design constraint at 5000 tenants.
package telemetry

import (
	"context"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"
)

// DefaultAutoTuneTargetInsertsPerSec is the insert-frequency set-point
// the tuner holds. docs/scaling.md §3.2 calls ≤ ~1 insert/s/shard the
// healthy band; 2/sec is a deliberately conservative ceiling that
// keeps part-creation comfortably clear of the merge-scheduler
// pressure point while leaving headroom for the FlushInterval-bound
// regime at low volume (which sits well below it).
const DefaultAutoTuneTargetInsertsPerSec = 2.0

// DefaultAutoTuneInterval is the sampling/adjustment cadence. It
// matches the sampler's window (DefaultSamplingWindow) so the two
// cost-control loops observe the same volume epoch, and it is long
// enough that a single flush-rate blip cannot swing the knob (the
// tuner differences cumulative counters over the whole interval).
const DefaultAutoTuneInterval = 10 * time.Second

// DefaultAutoTuneMinBatchSize floors the tuned batch. The floor exists
// only to stop the controller from driving the size trigger so low
// that it competes with the FlushInterval trigger at trivial volume;
// it is not a latency knob (FlushInterval bounds staleness regardless).
const DefaultAutoTuneMinBatchSize = 256

// DefaultAutoTuneMaxBatchSize caps the tuned batch. It mirrors the
// capacity model's ceiling (docs/scaling.md §3.3): beyond ~65,536 rows
// per part the right answer is another shard (CLICKHOUSE_SHARDING),
// not a still-larger batch (insert latency and writer memory grow with
// the batch). When the controller wants to exceed this and the insert
// rate is still over target, the tuner logs a shard recommendation.
const DefaultAutoTuneMaxBatchSize = 65536

// DefaultAutoTuneSmoothing is the EMA step applied to each adjustment:
// new = cur + α·(desired − cur). 0.5 halves the gap to the set-point
// each interval — fast enough to track a tier-scale volume change
// within a minute, damped enough that a one-window burst cannot slam
// the batch to an extreme.
const DefaultAutoTuneSmoothing = 0.5

// BatchTunable is the control surface the autotuner drives on a
// ClickHouse writer. *clickhouse.Writer satisfies it; it is declared
// here (rather than importing the clickhouse package for a concrete
// type) so the tuner depends only on the narrow capability it needs
// and stays unit-testable against an in-memory fake. A sharded writer
// exposes one BatchTunable per shard (clickhouse.ShardedWriter.Shards)
// so each shard is tuned against its own insert rate.
type BatchTunable interface {
	// BatchSize returns the effective max-rows-per-insert flush
	// trigger currently in force.
	BatchSize() int
	// SetBatchSize updates the effective flush trigger. Implementations
	// must treat values < 1 as a no-op.
	SetBatchSize(int)
	// RowsWritten returns the cumulative count of rows successfully
	// sent to ClickHouse. Monotonic non-decreasing within a process.
	RowsWritten() uint64
	// InsertCount returns the cumulative count of successful inserts
	// (flushes that sent ≥1 row). Monotonic non-decreasing within a
	// process.
	InsertCount() uint64
}

// AutoTuneConfig configures a BatchAutoTuner. The zero value is valid
// and yields the package defaults for every field.
type AutoTuneConfig struct {
	// TargetInsertsPerSec is the per-writer insert-frequency set-point.
	// Defaults to DefaultAutoTuneTargetInsertsPerSec. Must be > 0.
	TargetInsertsPerSec float64
	// MinBatchSize / MaxBatchSize clamp the tuned batch size. Default
	// to DefaultAutoTuneMinBatchSize / DefaultAutoTuneMaxBatchSize.
	MinBatchSize int
	MaxBatchSize int
	// Interval is the sampling/adjustment cadence. Defaults to
	// DefaultAutoTuneInterval.
	Interval time.Duration
	// Smoothing is the EMA step in (0,1]. Defaults to
	// DefaultAutoTuneSmoothing. Out-of-range values are clamped.
	Smoothing float64
	// NowFunc returns the current time; injected so tests can pin the
	// clock. Defaults to time.Now.
	NowFunc func() time.Time
	// Logger receives the periodic tuning decisions (at Debug) and the
	// shard-recommendation warning. Defaults to slog.Default().
	Logger *slog.Logger
}

func (c AutoTuneConfig) withDefaults() AutoTuneConfig {
	if c.TargetInsertsPerSec <= 0 {
		c.TargetInsertsPerSec = DefaultAutoTuneTargetInsertsPerSec
	}
	if c.MinBatchSize <= 0 {
		c.MinBatchSize = DefaultAutoTuneMinBatchSize
	}
	if c.MaxBatchSize <= 0 {
		c.MaxBatchSize = DefaultAutoTuneMaxBatchSize
	}
	// A min above max is a misconfiguration; collapse the band to the
	// min so the writer is never clamped to an empty range.
	if c.MaxBatchSize < c.MinBatchSize {
		c.MaxBatchSize = c.MinBatchSize
	}
	if c.Interval <= 0 {
		c.Interval = DefaultAutoTuneInterval
	}
	if c.Smoothing <= 0 || c.Smoothing > 1 {
		c.Smoothing = DefaultAutoTuneSmoothing
	}
	if c.NowFunc == nil {
		c.NowFunc = time.Now
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return c
}

// tunerTarget is the per-writer control state: the writer itself plus
// the last-observed counter baseline and the controller's float
// set-point (kept separately from the integer batch size so rounding
// does not accumulate across intervals).
type tunerTarget struct {
	w BatchTunable

	// name distinguishes shards in log lines.
	name string

	// primed is false until the first observe() call records a
	// baseline; the first call cannot compute a rate (no prior
	// sample) so it only seeds lastRows/lastInserts/lastAt.
	primed      bool
	lastRows    uint64
	lastInserts uint64
	lastAt      time.Time

	// setpoint is the controller's continuous batch-size estimate,
	// seeded from the writer's current batch size and moved by the EMA
	// each interval. The integer SetBatchSize value is round(setpoint)
	// clamped to the band.
	setpoint float64
}

// BatchAutoTuner holds closed-loop control over one or more ClickHouse
// writers' batch sizes. Construct with NewBatchAutoTuner; call Start to
// launch the background loop and Stop to terminate it. Safe for
// concurrent use. A nil *BatchAutoTuner is a valid no-op so wiring is
// optional.
type BatchAutoTuner struct {
	cfg     AutoTuneConfig
	targets []*tunerTarget

	startOnce sync.Once
	stopOnce  sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewBatchAutoTuner builds a tuner that holds each writer's insert
// frequency near cfg.TargetInsertsPerSec. Pass one writer for a
// single-node deployment or one per shard (ShardedWriter.Shards) so
// each shard is tuned against its own row rate. Nil writers are
// skipped. Returns nil when no non-nil writer is supplied, so a
// deployment with no ClickHouse hot tier carries no tuner and no
// goroutine.
func NewBatchAutoTuner(cfg AutoTuneConfig, writers ...BatchTunable) *BatchAutoTuner {
	cfg = cfg.withDefaults()
	targets := make([]*tunerTarget, 0, len(writers))
	for i, w := range writers {
		if w == nil {
			continue
		}
		name := "writer"
		if len(writers) > 1 {
			name = "shard-" + strconv.Itoa(i)
		}
		targets = append(targets, &tunerTarget{
			w:        w,
			name:     name,
			setpoint: float64(clampBatch(w.BatchSize(), cfg.MinBatchSize, cfg.MaxBatchSize)),
		})
	}
	if len(targets) == 0 {
		return nil
	}
	return &BatchAutoTuner{
		cfg:     cfg,
		targets: targets,
		done:    make(chan struct{}),
	}
}

// Start launches the background control loop. Idempotent: the second
// and later calls are no-ops. A nil tuner is a no-op. The loop runs
// until ctx is cancelled or Stop is called.
func (t *BatchAutoTuner) Start(ctx context.Context) {
	if t == nil {
		return
	}
	t.startOnce.Do(func() {
		runCtx, cancel := context.WithCancel(ctx)
		t.cancel = cancel
		go t.loop(runCtx)
	})
}

// Stop terminates the control loop and waits for it to exit. Idempotent
// and safe on a nil tuner, and safe to call without a prior Start (in
// which case there is no loop to join, so it returns immediately). The
// batch sizes the tuner last set remain in force on the writers (Stop
// does not reset them).
func (t *BatchAutoTuner) Stop() {
	if t == nil {
		return
	}
	t.stopOnce.Do(func() {
		// t.cancel is set only by Start. When Stop runs without a
		// prior Start the loop goroutine was never launched, so
		// nothing will ever close t.done — join on it only when we
		// actually cancelled a running loop, otherwise this blocks
		// forever.
		if t.cancel != nil {
			t.cancel()
			<-t.done
		}
	})
}

func (t *BatchAutoTuner) loop(ctx context.Context) {
	defer close(t.done)
	ticker := time.NewTicker(t.cfg.Interval)
	defer ticker.Stop()
	// Prime baselines immediately so the first ticker tick computes a
	// rate over one whole interval rather than from process start.
	now := t.cfg.NowFunc()
	for _, tt := range t.targets {
		t.observe(tt, now)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.tuneOnce()
		}
	}
}

// tuneOnce runs one adjustment pass over every target. Exposed
// (unexported) as a single method so tests can drive the controller
// deterministically with a pinned clock instead of waiting on the
// ticker.
func (t *BatchAutoTuner) tuneOnce() {
	now := t.cfg.NowFunc()
	for _, tt := range t.targets {
		t.adjust(tt, now)
	}
}

// observe records a counter baseline for tt at time now without
// adjusting the batch size. Used to prime the first sample.
func (t *BatchAutoTuner) observe(tt *tunerTarget, now time.Time) {
	tt.lastRows = tt.w.RowsWritten()
	tt.lastInserts = tt.w.InsertCount()
	tt.lastAt = now
	tt.primed = true
}

// adjust performs one closed-loop step for tt: measure the row/insert
// rate over the interval since the last sample, compute the batch size
// that lands the insert rate on target, move the set-point toward it
// by the EMA step, clamp, and push it to the writer.
func (t *BatchAutoTuner) adjust(tt *tunerTarget, now time.Time) {
	rows := tt.w.RowsWritten()
	inserts := tt.w.InsertCount()

	if !tt.primed {
		tt.lastRows, tt.lastInserts, tt.lastAt, tt.primed = rows, inserts, now, true
		return
	}

	elapsed := now.Sub(tt.lastAt)
	// Counters are cumulative and monotonic within a process. A
	// backwards step means the writer was reset/reconstructed (or the
	// clock did not advance); re-baseline and skip this tick rather
	// than compute a nonsensical negative rate.
	if elapsed <= 0 || rows < tt.lastRows || inserts < tt.lastInserts {
		t.observe(tt, now)
		return
	}

	dRows := rows - tt.lastRows
	dInserts := inserts - tt.lastInserts
	secs := elapsed.Seconds()
	// Always advance the baseline so the next interval measures a fresh
	// delta regardless of which branch we take below.
	tt.lastRows, tt.lastInserts, tt.lastAt = rows, inserts, now

	// No rows flushed this interval ⇒ the writer is idle (or wedged on
	// a downstream outage, which is the requeue path's concern, not the
	// tuner's). Leave the batch where it is: there is no row-rate
	// signal to size against, and thrashing the knob on idle would only
	// guarantee a burst of tiny inserts when traffic resumes.
	if dRows == 0 {
		return
	}

	rowsPerSec := float64(dRows) / secs
	insertsPerSec := float64(dInserts) / secs

	// The batch size that lands the insert rate exactly on target at
	// the observed row rate. desiredBatch ≥ 1 since rowsPerSec > 0.
	desired := rowsPerSec / t.cfg.TargetInsertsPerSec
	clampedDesired := clampBatchF(desired, t.cfg.MinBatchSize, t.cfg.MaxBatchSize)

	// EMA toward the (clamped) desired set-point.
	tt.setpoint += t.cfg.Smoothing * (clampedDesired - tt.setpoint)
	newBatch := clampBatch(int(math.Round(tt.setpoint)), t.cfg.MinBatchSize, t.cfg.MaxBatchSize)

	prev := tt.w.BatchSize()
	tt.w.SetBatchSize(newBatch)

	// Sharding recommendation: the controller wants a batch above the
	// cap and the insert rate is still over target, so a larger batch
	// is no longer the right lever — the deployment needs another
	// shard (docs/scaling.md §3.3). Logged at WARN so it surfaces on
	// the operator dashboard; this is advisory, the tuner keeps the
	// batch pinned at MaxBatchSize meanwhile.
	if desired > float64(t.cfg.MaxBatchSize) && insertsPerSec > t.cfg.TargetInsertsPerSec {
		t.cfg.Logger.Warn("telemetry: clickhouse batch autotune capped — consider CLICKHOUSE_SHARDING",
			slog.String("target", tt.name),
			slog.Float64("rows_per_sec", rowsPerSec),
			slog.Float64("inserts_per_sec", insertsPerSec),
			slog.Float64("desired_batch", desired),
			slog.Int("max_batch", t.cfg.MaxBatchSize))
		return
	}

	if newBatch != prev {
		t.cfg.Logger.Debug("telemetry: clickhouse batch autotuned",
			slog.String("target", tt.name),
			slog.Float64("rows_per_sec", rowsPerSec),
			slog.Float64("inserts_per_sec", insertsPerSec),
			slog.Int("prev_batch", prev),
			slog.Int("new_batch", newBatch))
	}
}

// clampBatch bounds n to [lo,hi].
func clampBatch(n, lo, hi int) int {
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}

// clampBatchF bounds f to [lo,hi] in float space (used before the
// EMA so the set-point itself never wanders outside the band).
func clampBatchF(f float64, lo, hi int) float64 {
	if f < float64(lo) {
		return float64(lo)
	}
	if f > float64(hi) {
		return float64(hi)
	}
	return f
}

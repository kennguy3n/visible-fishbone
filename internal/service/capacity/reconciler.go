// Package capacity implements the WS6 capacity autopilot: a
// leader-only reconciler that closes the NoOps loop on infrastructure
// sizing.
//
// docs/scaling.md and the offline `bench/controlplane capacity-plan`
// model produce excellent sizing recommendations (Postgres pool,
// CLICKHOUSE_BATCH_SIZE, NATS_PARTITIONS, replica counts) — but they
// are an OFFLINE planning aid: an operator runs the bench by hand,
// reads the numbers, and edits env knobs. This package turns that into
// a LIVE control loop. It periodically reads the real fleet size, runs
// the exact same analytical model (internal/capacityplan — the bench
// and this reconciler share one implementation, so the runtime numbers
// match the documented planning numbers to the row), compares the
// recommendation against the knobs the process actually booted with,
// and surfaces the gap as Prometheus metrics + structured log lines.
//
// Posture — recommend, never mutate. The reconciler deliberately does
// NOT apply changes itself. Every capacity axis the model sizes
// (Postgres pool size / replica count / max_connections, ClickHouse
// shard count, NATS partition count) requires a config change + process
// restart or redeploy to take effect — none is safely mutable in place
// at runtime, and the task's ground rules forbid auto-restarting
// services or any destructive action. The one knob that IS runtime-
// tunable, the ClickHouse batch size, is already owned by the closed-
// loop autotuner (WS12, internal/service/telemetry/autotune.go);
// having a second controller fight it for the same knob would be a
// regression, not a feature. So the autopilot is a recommend-and-surface
// controller: it gives operators a live, fleet-driven "here is what to
// set, and where you currently sit" per axis — a one-glance, one-action
// decision — instead of re-running an offline tool. The latest
// recommendation is also exposed via Latest() so an operator-facing
// endpoint can render or action it.
//
// Fail-safe. A reconcile that cannot read the fleet size logs and
// records an error outcome but never publishes a stale or fabricated
// recommendation, and never blocks the rest of the control plane. The
// loop is leader-only (one replica emits) and gated default-OFF.
package capacity

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/capacityplan"
)

// DefaultInterval is the reconcile cadence when none is configured.
// Capacity sizing tracks tenant growth, not request rate, so a slow
// cadence keeps the once-per-cycle fleet-count query negligible.
const DefaultInterval = 5 * time.Minute

// Axis names used as the `axis` metric label and in log lines.
const (
	AxisPostgres   = "postgres"
	AxisClickHouse = "clickhouse"
	AxisNATS       = "nats"
)

// FleetObservation is the live fleet state one reconcile reads before
// running the model.
type FleetObservation struct {
	// TenantCount is the number of live (non-deleted) tenants — the
	// model's primary scaling input.
	TenantCount int
	// ActiveTenantCount is how many of those were active within the
	// recent window. Reported for operator context; the sizing model
	// uses TenantCount (subjects/pools exist per tenant regardless of
	// activity).
	ActiveTenantCount int
	// EventsPerSec is an optional live, fleet-wide telemetry publish
	// rate. When > 0 it refines the ClickHouse/NATS throughput
	// projection to what the fleet is actually emitting; when 0 the
	// model falls back to its per-class synthetic rates (so the
	// recommendation matches the offline bench exactly).
	EventsPerSec float64
	// ObservedAt is when the observation was taken.
	ObservedAt time.Time
}

// FleetObserver reads the live fleet state. RepoFleetObserver is the
// production implementation (see observer.go); tests supply a fake.
type FleetObserver interface {
	Observe(ctx context.Context) (FleetObservation, error)
}

// RuntimeKnobs is a snapshot of the capacity-relevant settings the
// process is currently running with. The reconciler reads these live
// each cycle (some, like the ClickHouse shard count, can change at
// runtime) and grades them against the model.
type RuntimeKnobs struct {
	ControlPlaneReplicas int
	PGMaxOpenConns       int
	PGMaxConnections     int
	PGBouncerMode        bool
	// ClickHouseEnabled is true when a ClickHouse hot tier is actually
	// configured. When false the deployment ingests telemetry without
	// the hot analytics tier, so the ClickHouse sizing is hypothetical
	// ("what to set IF you enable it") — the reconciler still surfaces
	// the numbers for context but never flags the axis pending, else an
	// operator who deliberately runs cold-only gets a permanent false
	// "ClickHouse under-provisioned" alert.
	ClickHouseEnabled bool
	ClickHouseShards  int
	// ClickHouseBatchSize is the *effective* batch size in force, not
	// the boot-time config: when the WS12 autotuner owns this knob the
	// caller passes the live retuned value so the gauge stays truthful.
	ClickHouseBatchSize int
	// ClickHouseBatchAutotuned is true when the WS12 closed-loop
	// autotuner (internal/service/telemetry/autotune.go) is driving the
	// batch size at runtime. When set, the reconciler still reports the
	// current-vs-recommended batch as context but never flags the knob
	// as pending — the autotuner already holds it at the right value, so
	// flagging it would raise a permanent false "under-provisioned"
	// alert on an operator dashboard.
	ClickHouseBatchAutotuned bool
	NATSPartitions           int
}

// MetricSink is the narrow metrics surface the reconciler writes to.
// *metrics.Metrics satisfies it; the interface keeps this package from
// importing the metrics/prometheus types directly and avoids an import
// cycle (metrics must not import this service). A nil sink is fine —
// the reconciler nil-checks before every call.
type MetricSink interface {
	SetCapacitySetting(axis, knob string, current, recommended float64)
	ClearCapacitySettings()
	SetCapacityRecommendationPending(axis string, pending bool)
	SetCapacityFleetTenants(n int)
	IncCapacityReconcile(outcome string)
}

// KnobDelta is one tunable's current-vs-recommended comparison.
type KnobDelta struct {
	Axis        string
	Knob        string
	Current     float64
	Recommended float64
	// Pending is true when the current setting is below the model's
	// recommendation — i.e. the deployment is under-provisioned on this
	// axis and an operator has an action to take. Being ABOVE the
	// recommendation is safe headroom and never flagged (fail-safe
	// toward more capacity, never less).
	Pending bool
}

// AxisStatus aggregates the deltas for one scaling axis.
type AxisStatus struct {
	Axis    string
	Deltas  []KnobDelta
	Pending bool
}

// Recommendation is the full result of one reconcile: the model
// section plus the per-axis current-vs-recommended grading.
type Recommendation struct {
	Observation FleetObservation
	Plan        *capacityplan.Section
	Axes        []AxisStatus
	// Pending is true when any axis is under-provisioned.
	Pending bool
	// At is when the recommendation was computed.
	At time.Time
}

// Reconciler is the leader-only capacity autopilot loop.
type Reconciler struct {
	observer FleetObserver
	knobs    func() RuntimeKnobs
	metrics  MetricSink
	interval time.Duration
	logger   *slog.Logger
	now      func() time.Time

	mu     sync.RWMutex
	latest Recommendation
	hasRec bool
}

// Config wires a Reconciler. Observer and Knobs are required; the rest
// have safe defaults.
type Config struct {
	// Observer reads the live fleet state each cycle.
	Observer FleetObserver
	// Knobs returns the current runtime settings to grade. Read each
	// cycle so a runtime-changed value (e.g. shard count) is reflected.
	Knobs func() RuntimeKnobs
	// Metrics is the gauge/counter sink. Optional (nil is fine).
	Metrics MetricSink
	// Interval is the reconcile cadence. <= 0 uses DefaultInterval.
	Interval time.Duration
	// Logger is the structured logger. nil uses slog.Default().
	Logger *slog.Logger
	// NowFunc overrides the clock (tests). nil uses time.Now.
	NowFunc func() time.Time
}

// New constructs a Reconciler. It panics if Observer or Knobs is nil —
// a wiring bug the boot path should surface immediately.
func New(cfg Config) *Reconciler {
	if cfg.Observer == nil {
		panic("capacity: New requires a non-nil Observer")
	}
	if cfg.Knobs == nil {
		panic("capacity: New requires a non-nil Knobs func")
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.NowFunc
	if now == nil {
		now = time.Now
	}
	return &Reconciler{
		observer: cfg.Observer,
		knobs:    cfg.Knobs,
		metrics:  cfg.Metrics,
		interval: interval,
		logger:   logger,
		now:      now,
	}
}

// Run drives the reconcile loop until ctx is cancelled. It reconciles
// once immediately, then every interval. It blocks, so callers launch
// it in its own goroutine — typically via the leader elector's
// RunIfLeader so only one replica emits. Run is leader-only by
// convention; it does no leadership check itself.
func (r *Reconciler) Run(ctx context.Context) {
	r.logger.Info("capacity: reconciler started",
		slog.Duration("interval", r.interval))
	// Reconcile once up front so the gauges populate without waiting a
	// full interval.
	if _, err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
		r.logger.Warn("capacity: initial reconcile failed", slog.Any("error", err))
	}

	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("capacity: reconciler stopped")
			return
		case <-t.C:
			if _, err := r.Reconcile(ctx); err != nil && ctx.Err() == nil {
				r.logger.Warn("capacity: reconcile failed", slog.Any("error", err))
			}
		}
	}
}

// Reconcile performs one pass: observe the fleet, run the model, grade
// the live knobs, emit metrics + logs, and cache the result. It returns
// the recommendation (also retrievable via Latest) and any error. On
// error it records the "error" outcome and does NOT overwrite the last
// good recommendation with a partial one.
func (r *Reconciler) Reconcile(ctx context.Context) (Recommendation, error) {
	obs, err := r.observer.Observe(ctx)
	if err != nil {
		r.metricsIncReconcile("error")
		return Recommendation{}, err
	}
	r.metricsSetFleet(obs.TenantCount)

	if obs.TenantCount < 1 {
		// A brand-new install with no tenants: nothing to size yet.
		// Record a clean pass (the fleet gauge is already 0) but do not
		// run the model — passing 0 would make the model substitute its
		// default tier and publish a fabricated recommendation. Clear the
		// per-axis pending gauges so a recommendation left over from a
		// prior non-empty cycle does not keep an operator alert firing
		// against an empty fleet, and drop the current-vs-recommended
		// setting series so a dashboard does not show stale sizing (e.g.
		// recommended batch_size=13250 from the last 5K cycle) next to
		// fleet_tenants=0.
		for _, axis := range []string{AxisPostgres, AxisClickHouse, AxisNATS} {
			r.metricsSetPending(axis, false)
		}
		r.metricsClearSettings()
		r.logger.Info("capacity: no live tenants yet; skipping sizing")
		r.metricsIncReconcile("ok")
		return Recommendation{Observation: obs, At: r.now()}, nil
	}

	knobs := r.knobs()
	plan := capacityplan.Run(r.buildConfig(knobs, obs))
	rec := Recommendation{
		Observation: obs,
		Plan:        plan,
		Axes:        gradeAxes(knobs, plan),
		At:          r.now(),
	}
	for _, a := range rec.Axes {
		if a.Pending {
			rec.Pending = true
			break
		}
	}

	r.publish(rec)
	r.store(rec)
	r.metricsIncReconcile("ok")
	return rec, nil
}

// buildConfig maps the live knobs + observation onto the shared model
// config. A zero observed event rate leaves MeasuredEventsPerSec unset,
// so the model uses its per-class synthetic rates and the recommendation
// matches the offline bench exactly.
func (r *Reconciler) buildConfig(k RuntimeKnobs, obs FleetObservation) capacityplan.Config {
	return capacityplan.Config{
		TenantCount:          obs.TenantCount,
		ControlPlaneReplicas: k.ControlPlaneReplicas,
		PGMaxOpenConns:       k.PGMaxOpenConns,
		PGBouncerMode:        capacityplan.BoolPtr(k.PGBouncerMode),
		PGMaxConnections:     k.PGMaxConnections,
		ClickHouseShards:     k.ClickHouseShards,
		ClickHouseBatchSize:  k.ClickHouseBatchSize,
		NATSPartitions:       k.NATSPartitions,
		MeasuredEventsPerSec: obs.EventsPerSec,
	}
}

// gradeAxes builds the per-axis current-vs-recommended comparison from
// the live knobs and the model plan.
func gradeAxes(k RuntimeKnobs, plan *capacityplan.Section) []AxisStatus {
	pg := plan.Postgres
	ch := plan.ClickHouse
	n := plan.NATS

	postgres := AxisStatus{
		Axis: AxisPostgres,
		Deltas: []KnobDelta{
			knobDelta(AxisPostgres, "pool_size_per_replica", k.PGMaxOpenConns, pg.RecommendedPoolSize),
			// Backend connections required vs the server's max_connections
			// ceiling. "Recommended" here is the ceiling; pending means the
			// projected backend demand has crossed it (enable PgBouncer or
			// raise max_connections).
			ceilingDelta(AxisPostgres, "backend_conns", pg.BackendConnsRequired, pg.MaxConnections, !pg.WithinMaxConnections),
		},
	}
	batch := knobDelta(AxisClickHouse, "batch_size", k.ClickHouseBatchSize, ch.RecommendedBatchSize)
	shards := knobDelta(AxisClickHouse, "shards", k.ClickHouseShards, ch.RecommendedShards)
	switch {
	case !k.ClickHouseEnabled:
		// No hot tier configured: the ClickHouse sizing is hypothetical.
		// Surface the numbers for context but never flag the axis pending
		// (else a cold-only deployment alerts forever on a subsystem it
		// does not run).
		batch.Pending = false
		shards.Pending = false
	case k.ClickHouseBatchAutotuned:
		// The WS12 autotuner owns the batch size and holds it at the
		// right value at runtime; surface the comparison but never flag
		// it pending (else an operator dashboard alerts forever even
		// while the autotuner is doing its job). Shard count is still a
		// real, operator-set knob and is graded normally.
		batch.Pending = false
	}
	clickhouse := AxisStatus{
		Axis: AxisClickHouse,
		Deltas: []KnobDelta{
			batch,
			shards,
		},
	}
	nats := AxisStatus{
		Axis: AxisNATS,
		Deltas: []KnobDelta{
			knobDelta(AxisNATS, "partitions", k.NATSPartitions, n.RecommendedPartitions),
		},
	}
	out := []AxisStatus{postgres, clickhouse, nats}
	for i := range out {
		for _, d := range out[i].Deltas {
			if d.Pending {
				out[i].Pending = true
				break
			}
		}
	}
	return out
}

// knobDelta builds a delta whose Pending flag fires when the current
// value is below the recommendation (under-provisioned).
func knobDelta(axis, knob string, current, recommended int) KnobDelta {
	return KnobDelta{
		Axis:        axis,
		Knob:        knob,
		Current:     float64(current),
		Recommended: float64(recommended),
		Pending:     recommended > current,
	}
}

// ceilingDelta builds a delta against a hard ceiling (e.g.
// max_connections) where Pending is supplied explicitly rather than
// derived from a "more is better" comparison.
func ceilingDelta(axis, knob string, current, ceiling int, pending bool) KnobDelta {
	return KnobDelta{
		Axis:        axis,
		Knob:        knob,
		Current:     float64(current),
		Recommended: float64(ceiling),
		Pending:     pending,
	}
}

// publish mirrors the recommendation onto metrics and logs the per-axis
// state — INFO when an axis is under-provisioned (operator action
// available), DEBUG when it is healthy. The fleet gauge is already set by
// Reconcile before the model runs, so it is not re-set here.
func (r *Reconciler) publish(rec Recommendation) {
	for _, a := range rec.Axes {
		for _, d := range a.Deltas {
			r.metricsSetSetting(d.Axis, d.Knob, d.Current, d.Recommended)
		}
		r.metricsSetPending(a.Axis, a.Pending)
		if a.Pending {
			r.logger.Info("capacity: axis under-provisioned",
				slog.String("axis", a.Axis),
				slog.Int("tenants", rec.Observation.TenantCount),
				slog.Any("recommendation", logDeltas(a.Deltas)))
		} else {
			r.logger.Debug("capacity: axis within recommendation",
				slog.String("axis", a.Axis),
				slog.Int("tenants", rec.Observation.TenantCount))
		}
	}
}

// logDeltas renders the pending deltas of an axis for a log line.
func logDeltas(deltas []KnobDelta) []string {
	var out []string
	for _, d := range deltas {
		if d.Pending {
			out = append(out, knobLine(d))
		}
	}
	return out
}

func knobLine(d KnobDelta) string {
	return d.Knob + ": current=" + ftoa(d.Current) + " recommended=" + ftoa(d.Recommended)
}

// ftoa renders an integer-valued float knob without a trailing ".0".
func ftoa(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// store caches the latest recommendation under the write lock.
func (r *Reconciler) store(rec Recommendation) {
	r.mu.Lock()
	r.latest = rec
	r.hasRec = true
	r.mu.Unlock()
}

// Latest returns the most recent recommendation and whether one has
// been computed yet. Safe for concurrent use — an operator endpoint can
// read it while the loop writes.
func (r *Reconciler) Latest() (Recommendation, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.latest, r.hasRec
}

func (r *Reconciler) metricsSetFleet(n int) {
	if r.metrics != nil {
		r.metrics.SetCapacityFleetTenants(n)
	}
}

func (r *Reconciler) metricsSetSetting(axis, knob string, current, recommended float64) {
	if r.metrics != nil {
		r.metrics.SetCapacitySetting(axis, knob, current, recommended)
	}
}

func (r *Reconciler) metricsClearSettings() {
	if r.metrics != nil {
		r.metrics.ClearCapacitySettings()
	}
}

func (r *Reconciler) metricsSetPending(axis string, pending bool) {
	if r.metrics != nil {
		r.metrics.SetCapacityRecommendationPending(axis, pending)
	}
}

func (r *Reconciler) metricsIncReconcile(outcome string) {
	if r.metrics != nil {
		r.metrics.IncCapacityReconcile(outcome)
	}
}

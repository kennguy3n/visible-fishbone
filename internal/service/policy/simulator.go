// Package policy — simulator.go implements deterministic policy
// change simulation (Phase 3 Block 2, Task 7).
//
// Operators propose a new policy graph; the simulator replays
// recent telemetry events through both the current and the
// proposed graph and produces an ImpactReport summarising which
// flows would change verdict, which devices/sites would be
// affected, and a per-(prev,next) transition matrix. The output
// is the foundation for the dry-run + canary rollout machinery
// (dryrun.go / canary.go) and for the operator-facing approval
// API (handler/policy_simulation.go).
//
// Determinism is a contract, not an accident:
//
//   - Telemetry events are pulled in a fixed ORDER BY clause from
//     the TelemetrySource (timestamp, event_id) so the input
//     stream is reproducible across runs.
//   - The evaluator never reads wall-clock time, RNG, or
//     environment — Evaluate(env) -> Verdict is a pure function
//     of (graph, env).
//   - ImpactReport.Transitions / AffectedDevices / AffectedSites
//     are materialised in canonical sort order so two runs
//     against the same fixture produce byte-identical JSON.
//
// The simulator is side-effect free: it must NOT publish bundles
// to NATS, persist to Postgres, mutate the live policy bundle
// store, or otherwise touch production state. It is invoked from
// an HTTP handler (PR B Task 10) and from the canary controller
// (canary.go) — both expect read-only semantics.
//
// The simulator is conceptually a sibling of internal/service/
// telemetry/replay/Service. The replay service replays cold-tier
// (S3-sealed) envelopes against a pair of PolicyEvaluators; the
// simulator replays hot-tier (ClickHouse) envelopes against two
// compiled policy graphs. We deliberately do NOT collapse them
// into one type because the two pipelines have different
// failure modes (sealed-batch decode errors vs ClickHouse query
// timeouts), different latency budgets, and different memory
// footprints — sharing the type would force one set of options
// onto a workload it doesn't fit.

package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Errors returned by Simulator.
var (
	// ErrSimulatorBusy is returned when a Simulate call comes in
	// while another run is in flight. The simulator serialises
	// runs to bound memory; callers should retry after the
	// in-flight run finishes.
	ErrSimulatorBusy = errors.New("policy: simulator busy")

	// ErrNoEvaluator is returned when neither the prev nor next
	// graph could be compiled to an Evaluator (e.g. both fail
	// schema validation). A simulation with no evaluator can't
	// produce meaningful output.
	ErrNoEvaluator = errors.New("policy: simulator has no evaluator")

	// ErrSimulationWindow is returned when the [Since, Until]
	// window is empty or reversed.
	ErrSimulationWindow = errors.New("policy: simulation window invalid")

	// ErrSimulationTenant is returned when the tenant ID is
	// zero.
	ErrSimulationTenant = errors.New("policy: simulation tenant id required")
)

// TelemetrySource is the read-only telemetry side of the
// simulator. The production implementation is backed by the
// ClickHouse hot tier (see internal/service/telemetry/
// clickhouse). Tests inject a deterministic in-memory source.
//
// Implementations MUST return envelopes in a stable order
// (timestamp ascending, event_id tie-breaker) so the simulator
// can guarantee determinism — the simulator does NOT re-sort.
// The maxEvents argument is an upper bound; a source that has
// fewer matching events returns the smaller slice rather than
// padding.
//
// ListEvents is the canonical method; classes selects which
// schema.EventClass values the simulator pulls. Pass a single
// EventClassFlow to replicate the pre-DNS/HTTP/ZTNA contract.
//
// ListFlowEvents is retained for callers that still want the
// flow-only path; implementations may forward to ListEvents.
type TelemetrySource interface {
	ListFlowEvents(
		ctx context.Context,
		tenantID uuid.UUID,
		since, until time.Time,
		maxEvents int,
	) ([]schema.Envelope, error)

	ListEvents(
		ctx context.Context,
		tenantID uuid.UUID,
		classes []schema.EventClass,
		since, until time.Time,
		maxEvents int,
	) ([]schema.Envelope, error)
}

// DefaultSimulatedEventClasses is the set of schema.EventClass
// values the simulator pulls when SimulationOptions.EventClasses
// is unset. Chosen to align with the evaluator's
// domainMatchesEventClass dispatch (every event class the
// evaluator can dispatch rules for):
//
//   - flow: NGFW / SD-WAN / SWG / ZTNA flow events
//   - dns:  DNS-domain rules
//   - http: SWG HTTP-shaped rules
//   - ztna: dedicated ZTNA verdict events
//
// Excluded by default (no rules currently dispatch against
// them): ips, sdwan (handled via flow), agent, posture.
// Operators can override by setting SimulationOptions.EventClasses.
var DefaultSimulatedEventClasses = []schema.EventClass{
	schema.EventClassFlow,
	schema.EventClassDNS,
	schema.EventClassHTTP,
	schema.EventClassZTNA,
}

// Evaluator is a pure (graph, envelope) -> verdict function. The
// simulator compiles each graph (prev / next) once via the
// injected EvaluatorFactory and reuses the resulting Evaluator
// across every envelope in the run.
//
// Implementations MUST be:
//
//   - Deterministic: same (graph, envelope) always yields the
//     same verdict. No wall-clock, no RNG.
//   - Side-effect free: must not mutate the envelope, write to
//     any store, or publish to NATS.
//   - Concurrency-safe: a future fan-out parallelisation may
//     call Evaluate from multiple goroutines.
type Evaluator interface {
	Evaluate(ctx context.Context, env schema.Envelope) (schema.Verdict, error)
}

// EvaluatorFactory builds an Evaluator from a stored policy
// graph. The default factory is GraphEvaluatorFactory; tests
// inject a stub factory that returns a constant verdict.
type EvaluatorFactory interface {
	Build(ctx context.Context, graph repository.PolicyGraph) (Evaluator, error)
}

// VerdictTransition is one cell of the impact report's
// transition matrix: PrevVerdict -> NextVerdict counted Count
// times. Records with PrevVerdict == NextVerdict are included so
// the matrix doubles as a coverage view (total = sum of counts).
type VerdictTransition struct {
	PrevVerdict schema.Verdict
	NextVerdict schema.Verdict
	Count       int
}

// ImpactReport summarises one simulation run. All slice fields
// are deterministically ordered so two runs against the same
// inputs produce byte-identical JSON.
type ImpactReport struct {
	// SimulationID identifies this specific run. Set by the
	// simulator from a UUIDv4 so the operator-facing API can
	// reference the run by ID.
	SimulationID uuid.UUID

	// TenantID scopes the report.
	TenantID uuid.UUID

	// Window is the closed [Since, Until] interval the
	// simulation covers. Pinned by the caller (typically "the
	// last 24 hours" or "the last 7 days").
	Since time.Time
	Until time.Time

	// PrevGraphID / NextGraphID are the graphs evaluated. NextGraphID
	// is zero when the simulator is asked to "evaluate against the
	// proposed graph only" (e.g. a fresh tenant with no prior
	// policy). PrevGraphID is zero when there is no current
	// graph.
	PrevGraphID  uuid.UUID
	NextGraphID  uuid.UUID
	PrevGraphVer int
	NextGraphVer int

	// Total is the number of envelopes processed.
	Total int

	// Changed is the count of envelopes whose verdict differed
	// between PrevEvaluator and NextEvaluator.
	Changed int

	// Transitions is the per-(prev, next) verdict count matrix
	// in canonical sort order (PrevVerdict, then NextVerdict).
	Transitions []VerdictTransition

	// AffectedDevices is the sorted set of device IDs that saw
	// at least one verdict change between prev and next. Sites
	// (below) is the same shape at the site rollup level.
	AffectedDevices []uuid.UUID

	// AffectedSites is the sorted set of site IDs (per
	// envelope.SiteID, nil entries skipped) where any device
	// saw a verdict change.
	AffectedSites []uuid.UUID

	// PrevErrors / NextErrors count evaluator failures on each
	// side. A non-zero count means the corresponding policy
	// rejected at least one envelope (e.g. a malformed rule
	// reference) — the affected envelopes are excluded from
	// Transitions but included in Total.
	PrevErrors int
	NextErrors int

	// StartedAt / FinishedAt bound the wall-clock duration of
	// the run for operator-facing observability. Sourced via
	// Simulator.nowFunc so tests can fix the clock.
	StartedAt  time.Time
	FinishedAt time.Time
}

// SimulationOptions tunes one Simulate call. All fields are
// optional.
type SimulationOptions struct {
	// MaxEvents caps the number of envelopes pulled from the
	// telemetry source. Zero -> DefaultSimulationMaxEvents.
	MaxEvents int

	// EventClasses overrides the set of schema.EventClass values
	// pulled from the telemetry source. Nil/empty ->
	// DefaultSimulatedEventClasses (flow + dns + http + ztna).
	// Pass a singleton EventClassFlow to restrict to flow-only.
	EventClasses []schema.EventClass

	// Logger overrides the simulator's default logger for this
	// call. Useful when operator-driven runs want a per-run
	// log stream.
	Logger *slog.Logger
}

// DefaultSimulationMaxEvents is the per-run cap on envelopes
// pulled from the telemetry source. Picked to bound memory at
// a few MB per simulation (~250B per envelope * 100k events).
const DefaultSimulationMaxEvents = 100_000

// Simulator is the policy-change simulation engine. Construct
// with NewSimulator. Safe for concurrent construction; Simulate
// itself serialises runs via the running flag (see
// ErrSimulatorBusy).
type Simulator struct {
	src     TelemetrySource
	factory EvaluatorFactory
	logger  *slog.Logger
	nowFunc func() time.Time

	mu      sync.Mutex
	running bool
}

// NewSimulator constructs a Simulator. src + factory are
// required; logger / nowFunc default to slog.Default and
// time.Now.
func NewSimulator(src TelemetrySource, factory EvaluatorFactory, opts ...SimulatorOption) (*Simulator, error) {
	if src == nil {
		return nil, errors.New("policy: simulator requires a non-nil TelemetrySource")
	}
	if factory == nil {
		return nil, errors.New("policy: simulator requires a non-nil EvaluatorFactory")
	}
	s := &Simulator{
		src:     src,
		factory: factory,
		logger:  slog.Default(),
		nowFunc: time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// SimulatorOption tweaks a freshly-constructed Simulator.
type SimulatorOption func(*Simulator)

// WithSimulatorLogger overrides the default logger.
func WithSimulatorLogger(l *slog.Logger) SimulatorOption {
	return func(s *Simulator) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithSimulatorClock overrides the default time source. Tests
// pin this to a deterministic clock so StartedAt / FinishedAt
// are reproducible.
func WithSimulatorClock(now func() time.Time) SimulatorOption {
	return func(s *Simulator) {
		if now != nil {
			s.nowFunc = now
		}
	}
}

// IsRunning reports whether a simulation is currently in
// flight. Useful for an admin endpoint to surface "another run
// is in progress" before calling Simulate.
func (s *Simulator) IsRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Simulate runs the policy-change comparison and returns an
// ImpactReport. Concurrent Simulate calls fail with
// ErrSimulatorBusy — the caller is expected to back off and
// retry.
//
// Either prev or next may be a zero-value PolicyGraph; the
// simulator treats a zero graph as "no policy" which is
// equivalent to default-deny for every envelope. A run with
// both sides zero is an error (ErrNoEvaluator).
func (s *Simulator) Simulate(
	ctx context.Context,
	tenantID uuid.UUID,
	prev, next repository.PolicyGraph,
	since, until time.Time,
	opts SimulationOptions,
) (ImpactReport, error) {
	if tenantID == uuid.Nil {
		return ImpactReport{}, ErrSimulationTenant
	}
	if until.IsZero() || since.IsZero() || !until.After(since) {
		return ImpactReport{}, ErrSimulationWindow
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return ImpactReport{}, ErrSimulatorBusy
	}
	s.running = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
	}()

	logger := s.logger
	if opts.Logger != nil {
		logger = opts.Logger
	}

	maxEvents := opts.MaxEvents
	if maxEvents <= 0 {
		maxEvents = DefaultSimulationMaxEvents
	}

	// Pick the event-class set. Defaulting to flow+dns+http+ztna
	// matches what the evaluator dispatches against; a caller
	// (e.g. an automated bake-off) can narrow it via opts.
	classes := opts.EventClasses
	if len(classes) == 0 {
		classes = DefaultSimulatedEventClasses
	}

	prevEval, prevErr := s.buildEvaluator(ctx, prev)
	nextEval, nextErr := s.buildEvaluator(ctx, next)
	if prevEval == nil && nextEval == nil {
		// Both sides failed to compile; can't produce a
		// meaningful report. Surface the more specific of
		// the two errors if available.
		if nextErr != nil {
			return ImpactReport{}, fmt.Errorf("%w: next: %w", ErrNoEvaluator, nextErr)
		}
		if prevErr != nil {
			return ImpactReport{}, fmt.Errorf("%w: prev: %w", ErrNoEvaluator, prevErr)
		}
		return ImpactReport{}, ErrNoEvaluator
	}
	// A single-sided compile failure is recoverable: we treat
	// the failed side as "default deny" so the report still
	// describes the change the operator is about to make.
	// Logged at warn so operators see the degraded comparison.
	if prevEval == nil {
		logger.Warn("policy.simulate: prev graph compile failed; defaulting to deny",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", prevErr),
		)
		prevEval = denyAllEvaluator{}
	}
	if nextEval == nil {
		logger.Warn("policy.simulate: next graph compile failed; defaulting to deny",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", nextErr),
		)
		nextEval = denyAllEvaluator{}
	}

	started := s.nowFunc().UTC()
	envelopes, err := s.src.ListEvents(ctx, tenantID, classes, since, until, maxEvents)
	if err != nil {
		return ImpactReport{}, fmt.Errorf("policy.simulate: list events: %w", err)
	}

	report := ImpactReport{
		SimulationID: uuid.New(),
		TenantID:     tenantID,
		Since:        since.UTC(),
		Until:        until.UTC(),
		PrevGraphID:  prev.ID,
		NextGraphID:  next.ID,
		PrevGraphVer: prev.Version,
		NextGraphVer: next.Version,
		Total:        len(envelopes),
		StartedAt:    started,
	}

	transitions := make(map[verdictPair]int, 8)
	affectedDevices := make(map[uuid.UUID]struct{})
	affectedSites := make(map[uuid.UUID]struct{})

	for i := range envelopes {
		env := envelopes[i]
		prevVerdict, prevErr := prevEval.Evaluate(ctx, env)
		if prevErr != nil {
			report.PrevErrors++
			continue
		}
		nextVerdict, nextErr := nextEval.Evaluate(ctx, env)
		if nextErr != nil {
			report.NextErrors++
			continue
		}
		transitions[verdictPair{prevVerdict, nextVerdict}]++
		if prevVerdict != nextVerdict {
			report.Changed++
			affectedDevices[env.DeviceID] = struct{}{}
			if env.SiteID != nil {
				affectedSites[*env.SiteID] = struct{}{}
			}
		}
	}

	report.Transitions = sortedTransitions(transitions)
	report.AffectedDevices = sortedUUIDs(affectedDevices)
	report.AffectedSites = sortedUUIDs(affectedSites)
	report.FinishedAt = s.nowFunc().UTC()

	logger.Info("policy.simulate: completed",
		slog.String("tenant_id", tenantID.String()),
		slog.String("simulation_id", report.SimulationID.String()),
		slog.Int("total", report.Total),
		slog.Int("changed", report.Changed),
		slog.Int("prev_errors", report.PrevErrors),
		slog.Int("next_errors", report.NextErrors),
		slog.Duration("duration", report.FinishedAt.Sub(report.StartedAt)),
	)

	return report, nil
}

// buildEvaluator compiles a single graph to an Evaluator. A
// zero-value PolicyGraph (Graph == nil) returns
// (denyAllEvaluator{}, nil) — the "no policy" semantics — so the
// caller can pass an empty graph for a brand-new tenant.
func (s *Simulator) buildEvaluator(ctx context.Context, g repository.PolicyGraph) (Evaluator, error) {
	if len(g.Graph) == 0 {
		return denyAllEvaluator{}, nil
	}
	return s.factory.Build(ctx, g)
}

// verdictPair keys the transition map. Plain struct so it can
// be used as a map key (slices of (prev, next) tuples would
// not work).
type verdictPair struct {
	prev schema.Verdict
	next schema.Verdict
}

// sortedTransitions materialises the transition map in canonical
// order (PrevVerdict ascending, then NextVerdict ascending) so
// the report is byte-identical across runs.
func sortedTransitions(m map[verdictPair]int) []VerdictTransition {
	if len(m) == 0 {
		return nil
	}
	out := make([]VerdictTransition, 0, len(m))
	for k, v := range m {
		out = append(out, VerdictTransition{
			PrevVerdict: k.prev,
			NextVerdict: k.next,
			Count:       v,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].PrevVerdict != out[j].PrevVerdict {
			return out[i].PrevVerdict < out[j].PrevVerdict
		}
		return out[i].NextVerdict < out[j].NextVerdict
	})
	return out
}

// sortedUUIDs materialises a set of UUIDs into a sorted slice.
// Sort key is the 16-byte UUID value treated as big-endian — the
// uuid package's String() method already produces a canonical
// representation, and bytes.Compare on the canonical wire form
// matches the lexicographic order of the string form.
func sortedUUIDs(m map[uuid.UUID]struct{}) []uuid.UUID {
	if len(m) == 0 {
		return nil
	}
	out := make([]uuid.UUID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return uuidLess(out[i], out[j])
	})
	return out
}

func uuidLess(a, b uuid.UUID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// denyAllEvaluator is the fallback evaluator used when one side
// of the simulation has no policy (or fails to compile). Every
// envelope receives VerdictDeny — the safe default the
// architecture mandates.
type denyAllEvaluator struct{}

func (denyAllEvaluator) Evaluate(_ context.Context, _ schema.Envelope) (schema.Verdict, error) {
	return schema.VerdictDeny, nil
}

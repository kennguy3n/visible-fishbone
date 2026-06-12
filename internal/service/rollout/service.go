package rollout

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Repository is the persistence contract the rollout framework depends
// on. It is declared here (not in internal/repository) so the
// dependency points inward: the concrete repos implement this interface.
//
// Every method is tenant-scoped: implementations MUST constrain all
// reads and writes to tenantID (Postgres via the `sng.tenant_id` RLS
// GUC, memory via explicit filtering) and MUST NOT trust an id argument
// to belong to the tenant without checking.
type Repository interface {
	// Get returns the stored record for (tenant, capability), or
	// repository.ErrNotFound when the tenant has never transitioned that
	// capability (the caller treats that as the default off state).
	Get(ctx context.Context, tenantID uuid.UUID, c Capability) (Record, error)

	// List returns every stored record for the tenant. Capabilities the
	// tenant has never transitioned are simply absent (the service fills
	// them in as off); the slice is empty (non-nil) when none exist.
	List(ctx context.Context, tenantID uuid.UUID) ([]Record, error)

	// Upsert writes rec (its State/Reason/UpdatedBy already validated and
	// set by the service) for (tenant, capability) and returns the stored
	// row with timestamps populated.
	Upsert(ctx context.Context, tenantID uuid.UUID, rec Record) (Record, error)
}

// TransitionSink records an immutable audit trail of rollout
// transitions. It is optional; the default is a no-op. A transition is
// reported only AFTER it has been durably persisted, so a sink failure
// can never roll back or fail the operator's request.
type TransitionSink interface {
	// OnTransition is called after a transition (manual or automatic) has
	// committed. from is the state before the transition.
	OnTransition(ctx context.Context, rec Record, from State)
}

// NoopTransitionSink is the default sink: it records nothing.
type NoopTransitionSink struct{}

// OnTransition does nothing.
func (NoopTransitionSink) OnTransition(context.Context, Record, State) {}

// Threshold is the monitor-phase auto-rollback policy: when a
// capability in [StateMonitor] accumulates metrics that breach it, the
// framework rolls the capability back to [StateOff] and records why.
//
// A breach requires at least MinSamples observations so a single early
// error cannot trip the rollback on a statistically meaningless sample.
// The zero value disables auto-rollback (see [MonitorMetrics.Breach]).
type Threshold struct {
	// MaxErrorRate is the highest tolerated fraction of observations that
	// errored (0..1). 0 disables the error-rate check.
	MaxErrorRate float64
	// MaxDenyRate is the highest tolerated fraction of observations that
	// would have been denied/blocked (0..1). 0 disables the deny-rate
	// check. The deny rate matters in monitor because a high "would-have
	// blocked" rate signals that promoting to enforce would deny a large
	// share of real traffic.
	MaxDenyRate float64
	// MinSamples is the minimum number of observations before either rate
	// is considered. 0 is treated as 1 (any single observation counts).
	MinSamples int
}

// MonitorMetrics is a snapshot of what a capability observed during its
// monitor (dry-run) phase, fed to [Service.EvaluateAutoRollback].
type MonitorMetrics struct {
	// Samples is the total number of observations.
	Samples int
	// Errors is how many observations errored (the capability could not
	// evaluate).
	Errors int
	// Denies is how many observations would have been denied/blocked had
	// the capability been enforcing.
	Denies int
}

// ErrorRate returns Errors/Samples, or 0 when there are no samples.
func (m MonitorMetrics) ErrorRate() float64 {
	if m.Samples <= 0 {
		return 0
	}
	return float64(m.Errors) / float64(m.Samples)
}

// DenyRate returns Denies/Samples, or 0 when there are no samples.
func (m MonitorMetrics) DenyRate() float64 {
	if m.Samples <= 0 {
		return 0
	}
	return float64(m.Denies) / float64(m.Samples)
}

// Breach reports whether m breaches t and, if so, a human-readable
// reason. It returns false when t is the zero value (auto-rollback
// disabled), when there are fewer than t.MinSamples observations, or
// when neither configured rate is exceeded.
func (m MonitorMetrics) Breach(t Threshold) (string, bool) {
	if t.MaxErrorRate <= 0 && t.MaxDenyRate <= 0 {
		return "", false // auto-rollback disabled
	}
	minSamples := t.MinSamples
	if minSamples < 1 {
		minSamples = 1
	}
	if m.Samples < minSamples {
		return "", false
	}
	if t.MaxErrorRate > 0 {
		if r := m.ErrorRate(); r > t.MaxErrorRate {
			return fmt.Sprintf("error_rate %.3f exceeded threshold %.3f over %d samples",
				r, t.MaxErrorRate, m.Samples), true
		}
	}
	if t.MaxDenyRate > 0 {
		if r := m.DenyRate(); r > t.MaxDenyRate {
			return fmt.Sprintf("deny_rate %.3f exceeded threshold %.3f over %d samples",
				r, t.MaxDenyRate, m.Samples), true
		}
	}
	return "", false
}

// Service is the rollout state machine. It is safe for concurrent use as
// long as the injected [Repository] is (the bundled implementations
// are).
type Service struct {
	repo      Repository
	sink      TransitionSink
	threshold Threshold
	logger    *slog.Logger
	now       func() time.Time
}

// Option configures a [Service].
type Option func(*Service)

// WithTransitionSink injects the audit sink. Defaults to
// [NoopTransitionSink].
func WithTransitionSink(sink TransitionSink) Option {
	return func(s *Service) {
		if sink != nil {
			s.sink = sink
		}
	}
}

// WithThreshold sets the monitor-phase auto-rollback policy. The zero
// Threshold (the default) disables auto-rollback.
func WithThreshold(t Threshold) Option {
	return func(s *Service) { s.threshold = t }
}

// WithLogger injects a structured logger. Defaults to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClock injects the time source, for deterministic tests. Defaults
// to time.Now (UTC-normalised).
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New builds a Service over repo. repo must be non-nil.
func New(repo Repository, opts ...Option) (*Service, error) {
	if repo == nil {
		return nil, fmt.Errorf("rollout: %w: nil repository", repository.ErrInvalidArgument)
	}
	s := &Service{
		repo:   repo,
		sink:   NoopTransitionSink{},
		logger: slog.Default(),
		now:    func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// Threshold returns the configured auto-rollback policy.
func (s *Service) Threshold() Threshold { return s.threshold }

// Get returns the current record for (tenant, capability). A tenant that
// has never transitioned the capability reads back as the default off
// record (not an error), so callers always get a concrete state.
func (s *Service) Get(ctx context.Context, tenantID uuid.UUID, c Capability) (Record, error) {
	if tenantID == uuid.Nil {
		return Record{}, fmt.Errorf("rollout: %w: nil tenant", repository.ErrInvalidArgument)
	}
	if !c.Valid() {
		return Record{}, ErrInvalidCapability
	}
	rec, err := s.repo.Get(ctx, tenantID, c)
	if err != nil {
		if isNotFound(err) {
			return defaultRecord(tenantID, c), nil
		}
		return Record{}, err
	}
	return rec, nil
}

// List returns the rollout state of every governed capability for the
// tenant, in [AllCapabilities] order. Capabilities the tenant has never
// transitioned are returned as their default off record, so the result
// is always complete (one entry per known capability).
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]Record, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("rollout: %w: nil tenant", repository.ErrInvalidArgument)
	}
	stored, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	byCap := make(map[Capability]Record, len(stored))
	for _, r := range stored {
		byCap[r.Capability] = r
	}
	out := make([]Record, 0, len(AllCapabilities()))
	for _, c := range AllCapabilities() {
		if r, ok := byCap[c]; ok {
			out = append(out, r)
			continue
		}
		out = append(out, defaultRecord(tenantID, c))
	}
	return out, nil
}

// TransitionInput describes an operator-initiated transition.
type TransitionInput struct {
	// To is the target state.
	To State
	// AllowSkip permits an advance that skips the monitor phase
	// (off -> enforce). Ignored for rollbacks and single-step advances.
	AllowSkip bool
	// Reason is the operator's note recorded with the transition. May be
	// empty.
	Reason string
	// Actor is the id/subject of the operator driving the transition. It
	// is recorded as updated_by and must be non-empty.
	Actor string
}

// Transition moves (tenant, capability) to in.To, validating the move
// against the state machine. It is the single write path for both
// advances and rollbacks; the only difference is the target state. The
// stored record is returned.
//
// Errors: ErrInvalidCapability / ErrInvalidState for bad inputs,
// ErrNoOpTransition when To equals the current state, ErrSkipNotAllowed
// when an advance would skip the monitor phase without AllowSkip — all
// wrapping repository.ErrInvalidArgument.
func (s *Service) Transition(ctx context.Context, tenantID uuid.UUID, c Capability, in TransitionInput) (Record, error) {
	if tenantID == uuid.Nil {
		return Record{}, fmt.Errorf("rollout: %w: nil tenant", repository.ErrInvalidArgument)
	}
	if !c.Valid() {
		return Record{}, ErrInvalidCapability
	}
	if !in.To.Valid() {
		return Record{}, ErrInvalidState
	}
	if in.Actor == "" {
		return Record{}, fmt.Errorf("rollout: %w: a transition requires an actor", repository.ErrInvalidArgument)
	}

	current, err := s.Get(ctx, tenantID, c)
	if err != nil {
		return Record{}, err
	}
	if err := validateTransition(current.State, in.To, in.AllowSkip); err != nil {
		return Record{}, err
	}
	return s.persist(ctx, tenantID, c, current.State, in.To, in.Reason, in.Actor)
}

// EvaluateAutoRollback inspects monitor-phase metrics for (tenant,
// capability) and, if they breach the configured [Threshold] while the
// capability is in [StateMonitor], rolls it back to [StateOff] recording
// the breach reason. It returns the (possibly unchanged) record and
// whether a rollback was performed.
//
// It is a no-op (returning rolled=false) when auto-rollback is disabled,
// when the capability is not currently monitoring, or when the metrics
// do not breach the threshold — so it is safe to call unconditionally on
// every metrics flush.
func (s *Service) EvaluateAutoRollback(ctx context.Context, tenantID uuid.UUID, c Capability, m MonitorMetrics) (Record, bool, error) {
	current, err := s.Get(ctx, tenantID, c)
	if err != nil {
		return Record{}, false, err
	}
	// Auto-rollback only acts on a capability that is actively
	// dry-running; off has nothing to roll back, and enforce is past the
	// monitor-phase guardrail (a deliberate operator decision).
	if current.State != StateMonitor {
		return current, false, nil
	}
	reason, breached := m.Breach(s.threshold)
	if !breached {
		return current, false, nil
	}
	rolled, err := s.persist(ctx, tenantID, c, current.State, StateOff,
		"auto-rollback: "+reason, SystemActor)
	if err != nil {
		return Record{}, false, err
	}
	s.logger.WarnContext(ctx, "rollout: auto-rolled capability back to off",
		slog.String("tenant_id", tenantID.String()),
		slog.String("capability", string(c)),
		slog.String("reason", reason))
	return rolled, true, nil
}

// GateState is the read path for a capability GATE. It returns the
// tenant's current state for the capability AND whether the tenant is
// explicitly MANAGED by the framework for it (an operator has recorded a
// transition row):
//
//   - managed == false: no row exists. The framework is not (yet)
//     governing this tenant's capability, so the caller MUST fall back to
//     its legacy pre-framework behavior. This is what makes deploying the
//     framework a no-op until an operator opts a tenant in with its first
//     transition — wiring the gate never silently disables a capability
//     that was already enabled by the legacy config flag.
//   - managed == true: the returned State is authoritative for the gate.
//
// It FAILS CLOSED on a genuine read error or a corrupt stored state,
// returning ([StateOff], managed=true) so an unreadable state DISABLES the
// capability rather than reverting to legacy-enabled — a gate must never
// enforce, nor silently fall back to legacy-on, on a state it could not
// read. It never returns an error for that reason. An invalid argument
// (nil tenant / unknown capability) is a programmer error on the gate
// path and likewise fails closed as managed-off.
func (s *Service) GateState(ctx context.Context, tenantID uuid.UUID, c Capability) (State, bool) {
	if tenantID == uuid.Nil || !c.Valid() {
		return StateOff, true
	}
	rec, err := s.repo.Get(ctx, tenantID, c)
	if err != nil {
		if isNotFound(err) {
			// No row: the tenant has not been opted into staged rollout
			// for this capability. The caller uses its legacy behavior.
			return StateOff, false
		}
		// A genuine read failure: log and fail closed (managed-off) so the
		// gate disables the capability rather than reverting to legacy-on.
		s.logger.WarnContext(ctx, "rollout: state unreadable; failing closed to off",
			slog.String("tenant_id", tenantID.String()),
			slog.String("capability", string(c)),
			slog.Any("error", err))
		return StateOff, true
	}
	if !rec.State.Valid() {
		return StateOff, true
	}
	return rec.State, true
}

// EffectiveState is the read path for callers that only need the
// fail-closed state and not the managed/unmanaged distinction (telemetry,
// projections). It returns the tenant's current state for the capability,
// FAILING CLOSED TO [StateOff] on any error (unreadable state, bad
// capability, store outage) and treating a never-transitioned tenant as
// off. It never returns an error. Gates that must preserve legacy
// behavior for unmanaged tenants use [Service.GateState] instead.
func (s *Service) EffectiveState(ctx context.Context, tenantID uuid.UUID, c Capability) State {
	state, _ := s.GateState(ctx, tenantID, c)
	return state
}

// persist writes the post-transition record and notifies the audit sink
// after it commits.
func (s *Service) persist(ctx context.Context, tenantID uuid.UUID, c Capability, from, to State, reason, actor string) (Record, error) {
	rec := Record{
		TenantID:   tenantID,
		Capability: c,
		State:      to,
		Reason:     reason,
		UpdatedBy:  actor,
	}
	saved, err := s.repo.Upsert(ctx, tenantID, rec)
	if err != nil {
		return Record{}, err
	}
	s.sink.OnTransition(ctx, saved, from)
	return saved, nil
}

// isNotFound reports whether err is the repository "no row" sentinel.
func isNotFound(err error) bool {
	return err != nil && errors.Is(err, repository.ErrNotFound)
}

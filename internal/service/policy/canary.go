// Package policy — canary.go implements progressive policy
// rollout (Phase 3 Block 2, Task 9).
//
// The lifecycle of a rollout is a five-state machine:
//
//   dry_run -> canary -> full -> completed
//                    \      \
//                     '------'--> rolled_back
//
//   - dry_run: shadow bundle distributed via CompileDryRun.
//     Agents log proposed verdicts but enforce the live bundle.
//   - canary: a deterministic subset of devices (CanaryPercent %
//     of the fleet, picked by hash) enforces the proposed graph;
//     the remainder stays on the live bundle.
//   - full: every device enforces the proposed graph. The
//     previous graph remains as the "rollback target" until
//     the operator marks the rollout completed.
//   - completed: the proposed graph is now the canonical graph;
//     no rollback is possible without a fresh proposal.
//   - rolled_back: terminal failure path. The proposed graph is
//     discarded fleet-wide; the previous graph is restored.
//
// Transitions are enforced both in the in-memory state machine
// (validRolloutTransition in repository/memory/policy_rollout.go)
// AND by a database trigger
// (policy_rollouts_check_transition in migration 010). Belt-and-
// suspenders — a buggy service caller cannot leave the table in
// an impossible state.
//
// Canary cohort assignment is deterministic: a device is in the
// canary iff fnv1a64(canary_salt || device_id_bytes) % 100 <
// canary_percent. The salt is the rollout's UUID, so two
// rollouts at the same percent select disjoint-ish cohorts (each
// device is independently sampled) and a re-eval at restart
// reproduces the exact same cohort. This matters because a
// device must NOT flap between "canary" and "non-canary" on a
// poller restart — flapping would force the agent to re-pull
// bundles every minute and would scramble the operator-facing
// per-cohort error-rate dashboards.
//
// The CanaryService does NOT push bundles itself — it returns
// the compiled bundle bytes plus a target subject, and the
// caller is responsible for the NATS push. This keeps the
// service unit-testable without a NATS testcontainer.

package policy

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Errors surfaced by the canary controller.
var (
	// ErrCanaryRolloutActive is returned by StartDryRun when an
	// active (non-terminal) rollout already exists for the
	// tenant. The operator must roll the existing rollout back
	// or promote it to completed before starting a fresh one.
	ErrCanaryRolloutActive = errors.New("policy: active rollout already exists for tenant")

	// ErrCanaryPercent is returned when an invalid
	// canary_percent (outside 0..100) is supplied.
	ErrCanaryPercent = errors.New("policy: canary percent must be in [0, 100]")
)

// CanaryService orchestrates progressive policy rollouts on top
// of the policy Service (which owns compile + dry-run) and the
// repository.PolicyRolloutRepository (which owns state).
type CanaryService struct {
	policy   *Service
	rollouts repository.PolicyRolloutRepository
	logger   *slog.Logger
	nowFunc  func() time.Time
}

// CanaryOption tweaks a freshly-constructed CanaryService.
type CanaryOption func(*CanaryService)

// WithCanaryLogger overrides the default logger.
func WithCanaryLogger(l *slog.Logger) CanaryOption {
	return func(s *CanaryService) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithCanaryClock overrides the default time source. Tests pin
// this for deterministic CreatedAt / UpdatedAt timestamps.
func WithCanaryClock(now func() time.Time) CanaryOption {
	return func(s *CanaryService) {
		if now != nil {
			s.nowFunc = now
		}
	}
}

// NewCanaryService constructs a CanaryService. Both `policy` and
// `rollouts` are required.
func NewCanaryService(p *Service, rollouts repository.PolicyRolloutRepository, opts ...CanaryOption) (*CanaryService, error) {
	if p == nil {
		return nil, errors.New("policy: canary service requires policy service")
	}
	if rollouts == nil {
		return nil, errors.New("policy: canary service requires rollout repository")
	}
	s := &CanaryService{
		policy:   p,
		rollouts: rollouts,
		logger:   slog.Default(),
		nowFunc:  time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// StartDryRunInput parameterises a call to StartDryRun.
type StartDryRunInput struct {
	// Proposed is the candidate graph operators want to evaluate.
	Proposed repository.PolicyGraph

	// PreviousGraphID is the graph the proposal is intended to
	// replace. Optional; zero if the tenant has no current
	// graph (first-ever rollout).
	PreviousGraphID uuid.UUID

	// SimulationID binds the rollout to a prior simulator run.
	// Optional; the simulator emits one of these and stamps it
	// into the operator-facing report.
	SimulationID uuid.UUID

	// ActorID is the operator (user) initiating the rollout.
	// Optional; nil for automation-initiated rollouts.
	ActorID *uuid.UUID

	// Notes is an operator-supplied freeform note (e.g. "rolling
	// out new DLP rule for finance team"). Optional.
	Notes string
}

// StartDryRun creates a new rollout in dry_run stage and
// produces the shadow bundle bytes via the underlying policy
// service. The returned DryRunResult is what the caller pushes
// onto the dry-run NATS subject.
//
// Refuses if the tenant already has an active rollout — see
// ErrCanaryRolloutActive. The caller can resolve by either
// promoting or rolling back the existing rollout first; this
// guard prevents two overlapping rollouts from confusing the
// operator-facing UI.
func (s *CanaryService) StartDryRun(
	ctx context.Context,
	tenantID uuid.UUID,
	in StartDryRunInput,
) (repository.PolicyRollout, DryRunResult, error) {
	if tenantID == uuid.Nil {
		return repository.PolicyRollout{}, DryRunResult{}, errors.New("policy: tenant id required")
	}
	if in.Proposed.ID == uuid.Nil || len(in.Proposed.Graph) == 0 {
		return repository.PolicyRollout{}, DryRunResult{}, errors.New("policy: proposed graph required")
	}

	if _, err := s.rollouts.GetActive(ctx, tenantID); err == nil {
		return repository.PolicyRollout{}, DryRunResult{}, ErrCanaryRolloutActive
	} else if !errors.Is(err, repository.ErrNotFound) {
		return repository.PolicyRollout{}, DryRunResult{}, fmt.Errorf("policy: check active rollout: %w", err)
	}

	// Compile the shadow bundle BEFORE persisting the rollout so
	// a compile failure does not leak a half-baked rollout row.
	dryRun, err := s.policy.CompileDryRun(ctx, tenantID, in.Proposed, DryRunOptions{
		SimulationID: in.SimulationID,
	})
	if err != nil {
		return repository.PolicyRollout{}, DryRunResult{}, fmt.Errorf("policy: compile dryrun: %w", err)
	}

	now := s.nowFunc().UTC()
	rollout := repository.PolicyRollout{
		ID:              uuid.New(),
		TenantID:        tenantID,
		GraphID:         in.Proposed.ID,
		PreviousGraphID: in.PreviousGraphID,
		Stage:           repository.PolicyRolloutStageDryRun,
		CanaryPercent:   0,
		SimulationID:    dryRun.SimulationID,
		CreatedBy:       in.ActorID,
		CreatedAt:       now,
		UpdatedAt:       now,
		Notes:           in.Notes,
	}
	saved, err := s.rollouts.Create(ctx, tenantID, rollout)
	if err != nil {
		return repository.PolicyRollout{}, DryRunResult{}, fmt.Errorf("policy: persist rollout: %w", err)
	}

	s.logger.Info("policy.canary: dry-run started",
		slog.String("tenant_id", tenantID.String()),
		slog.String("rollout_id", saved.ID.String()),
		slog.String("graph_id", in.Proposed.ID.String()),
		slog.String("simulation_id", dryRun.SimulationID.String()),
		slog.String("subject", dryRun.Subject),
	)
	return saved, dryRun, nil
}

// AdvanceInput parameterises a call to Advance.
type AdvanceInput struct {
	// NextStage is the target stage. Must be a legal
	// transition from the current stage — see the package
	// header for the state machine.
	NextStage repository.PolicyRolloutStage

	// CanaryPercent is meaningful only when NextStage =
	// PolicyRolloutStageCanary; ignored otherwise. Must be in
	// [0, 100] when supplied.
	CanaryPercent int

	// ActorID is the operator advancing the rollout. Optional.
	ActorID *uuid.UUID

	// Notes is an operator-supplied freeform note (e.g.
	// "promoting to 25% after 4h dry-run, no anomalies"). The
	// repository appends to the per-rollout notes audit trail
	// rather than overwriting.
	Notes string
}

// Advance moves the rollout to the next stage. Legal targets:
//
//   dry_run -> canary (with CanaryPercent in (0, 100))
//   dry_run -> full
//   canary  -> full
//   full    -> completed
//
// Any other transition fails with ErrInvalidArgument from the
// repository (validRolloutTransition; mirrored in the DB
// trigger). Terminal stages reject every further Advance.
func (s *CanaryService) Advance(
	ctx context.Context,
	tenantID, rolloutID uuid.UUID,
	in AdvanceInput,
) (repository.PolicyRollout, error) {
	if tenantID == uuid.Nil || rolloutID == uuid.Nil {
		return repository.PolicyRollout{}, errors.New("policy: tenant_id and rollout_id required")
	}
	if in.NextStage == repository.PolicyRolloutStageCanary {
		if in.CanaryPercent <= 0 || in.CanaryPercent > 100 {
			return repository.PolicyRollout{}, ErrCanaryPercent
		}
	}

	// Look up the rollout BEFORE mutating state so we know
	// which graph to promote on a draft -> live transition,
	// and so we can validate that the requested transition is
	// legal at this point in the lifecycle (UpdateStage is the
	// authoritative validator; this fetch is just for the
	// promotion side-effect below).
	current, err := s.rollouts.Get(ctx, tenantID, rolloutID)
	if err != nil {
		return repository.PolicyRollout{}, err
	}

	// Promotion side-effect: the proposed graph was stored as
	// a draft by StartDryRun so that /policy/compile would
	// keep serving the previously-live bundle during dry-run.
	// On the first transition that lets real fleet traffic
	// reach the new policy — dry_run -> canary (any percent),
	// dry_run -> full, or canary -> full — we flip is_draft
	// back to false so any future /policy/compile (or the
	// implicit compile that happens at canary stage) picks up
	// the new graph as "current". Subsequent transitions
	// (canary -> full, full -> completed) are no-ops on the
	// graph table because PromoteGraph is idempotent.
	if shouldPromote(current.Stage, in.NextStage) {
		if _, err := s.policy.PromoteGraph(
			ctx, tenantID, in.ActorID, current.GraphID,
		); err != nil {
			return repository.PolicyRollout{}, fmt.Errorf("policy: promote graph: %w", err)
		}
	}

	now := s.nowFunc().UTC()
	updated, err := s.rollouts.UpdateStage(
		ctx, tenantID, rolloutID,
		in.NextStage, in.CanaryPercent, in.Notes, in.ActorID, now,
	)
	if err != nil {
		return repository.PolicyRollout{}, err
	}
	s.logger.Info("policy.canary: advanced",
		slog.String("tenant_id", tenantID.String()),
		slog.String("rollout_id", rolloutID.String()),
		slog.String("stage", string(updated.Stage)),
		slog.Int("canary_percent", updated.CanaryPercent),
	)
	return updated, nil
}

// shouldPromote returns true when the transition from prev to
// next is the boundary at which the proposed (draft) graph
// becomes the live policy. Today that is any transition out of
// dry_run into a stage that actually enforces (canary or full),
// or canary -> full. Rollback / completed never trigger a
// promotion — rollback leaves the draft as-is (so it remains
// queryable for audit but does not become current), and
// "completed" is the terminal stage that follows a canary in
// which the graph was already promoted.
func shouldPromote(prev, next repository.PolicyRolloutStage) bool {
	switch prev {
	case repository.PolicyRolloutStageDryRun:
		return next == repository.PolicyRolloutStageCanary ||
			next == repository.PolicyRolloutStageFull
	default:
		return false
	}
}

// Rollback is the dedicated escape hatch from any non-terminal
// stage. It is functionally Advance(NextStage:
// PolicyRolloutStageRolledBack) — distinct method for
// operator-facing clarity (rollback is a different button in the
// UI than "next stage").
func (s *CanaryService) Rollback(
	ctx context.Context,
	tenantID, rolloutID uuid.UUID,
	actorID *uuid.UUID,
	notes string,
) (repository.PolicyRollout, error) {
	return s.Advance(ctx, tenantID, rolloutID, AdvanceInput{
		NextStage: repository.PolicyRolloutStageRolledBack,
		ActorID:   actorID,
		Notes:     notes,
	})
}

// Get returns a single rollout. RLS-scoped to tenant.
func (s *CanaryService) Get(ctx context.Context, tenantID, rolloutID uuid.UUID) (repository.PolicyRollout, error) {
	return s.rollouts.Get(ctx, tenantID, rolloutID)
}

// GetActive returns the most recent non-terminal rollout for
// the tenant, or repository.ErrNotFound if none exists.
func (s *CanaryService) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicyRollout, error) {
	return s.rollouts.GetActive(ctx, tenantID)
}

// List returns rollouts in created_at-descending order, paged
// per the supplied Page.
func (s *CanaryService) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PolicyRollout], error) {
	return s.rollouts.List(ctx, tenantID, page)
}

// IsCanaryDevice returns true iff the given device is in the
// canary cohort for the given rollout. Deterministic: same
// (rollout_id, device_id) always returns the same answer, so a
// device cannot flap between cohorts across polls.
//
// Algorithm: fnv1a64(rolloutID_bytes || deviceID_bytes) % 100 <
// canaryPercent. fnv1a was chosen for its uniform distribution
// at small sample sizes and zero-allocation hot path; we don't
// need cryptographic strength here — the cohort assignment is
// an operator-visible administrative selection, not a security
// boundary.
//
// canaryPercent == 0 returns false for every device (the dry-
// run stage's canary cohort is empty). canaryPercent >= 100
// returns true for every device. Values outside [0, 100] are
// clamped.
func IsCanaryDevice(rolloutID, deviceID uuid.UUID, canaryPercent int) bool {
	if canaryPercent <= 0 {
		return false
	}
	if canaryPercent >= 100 {
		return true
	}
	h := fnv.New64a()
	// rolloutID acts as a per-rollout salt so two rollouts at
	// the same percent over the same fleet do NOT pick the
	// same cohort — each device is independently sampled
	// across rollouts, matching operator expectations.
	_, _ = h.Write(rolloutID[:])
	_, _ = h.Write(deviceID[:])
	bucket := h.Sum64() % 100
	return bucket < uint64(canaryPercent)
}



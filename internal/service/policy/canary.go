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
	"encoding/json"
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
	// canary_percent is supplied. The valid range is the
	// half-open interval (0, 100] — 0 is rejected because a 0%
	// canary is indistinguishable from "no canary" (the old
	// graph keeps serving 100% of traffic), and Advance is the
	// wrong primitive for that state. StartDryRun already covers
	// "policy is staged but not yet live"; an explicit 0% canary
	// stage would let an operator silently revert progress
	// without surfacing the intent. The message uses [1, 100]
	// so clients are not told 0 is acceptable and then rejected.
	ErrCanaryPercent = errors.New("policy: canary percent must be in [1, 100]")
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
	// ProposedGraph is the candidate graph JSON the operator
	// wants to evaluate. StartDryRun owns the persistence of
	// this payload as a *draft* (is_draft=true) so the
	// active-rollout pre-check runs BEFORE any DB row is
	// written: this prevents accumulating orphaned draft
	// graphs whenever an operator retries past a 409 conflict
	// (see PR #39 Devin Review ANALYSIS_0004).
	ProposedGraph json.RawMessage

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
// operator-facing UI. The active-rollout check fires BEFORE
// the draft graph is persisted so a 409 retry doesn't leak
// orphaned draft rows into policy_graphs.
func (s *CanaryService) StartDryRun(
	ctx context.Context,
	tenantID uuid.UUID,
	in StartDryRunInput,
) (repository.PolicyRollout, DryRunResult, error) {
	if tenantID == uuid.Nil {
		return repository.PolicyRollout{}, DryRunResult{}, errors.New("policy: tenant id required")
	}
	if len(in.ProposedGraph) == 0 {
		return repository.PolicyRollout{}, DryRunResult{}, errors.New("policy: proposed graph required")
	}

	// Fail fast on already-active rollout BEFORE persisting
	// any candidate state. If we persisted the draft first
	// and then hit this branch, every retry would leak an
	// orphaned draft row (invisible to GetCurrentGraph but
	// still incrementing the version counter).
	if _, err := s.rollouts.GetActive(ctx, tenantID); err == nil {
		return repository.PolicyRollout{}, DryRunResult{}, ErrCanaryRolloutActive
	} else if !errors.Is(err, repository.ErrNotFound) {
		return repository.PolicyRollout{}, DryRunResult{}, fmt.Errorf("policy: check active rollout: %w", err)
	}

	// Persist the proposed graph as a draft so the rollout
	// row can FK to it. PutDraftGraph allocates a fresh ID,
	// the next sequential version, and sets is_draft=true
	// so GetCurrentGraph (and therefore /policy/compile)
	// keeps returning the previously-live graph until the
	// rollout state machine promotes the draft.
	proposed, err := s.policy.PutDraftGraph(ctx, tenantID, in.ActorID, in.ProposedGraph)
	if err != nil {
		return repository.PolicyRollout{}, DryRunResult{}, fmt.Errorf("policy: persist draft graph: %w", err)
	}

	// Compile the shadow bundle BEFORE persisting the rollout so
	// a compile failure does not leak a half-baked rollout row.
	// (A draft graph may have already landed at this point; that
	// is acceptable — the graph is invisible to GetCurrentGraph
	// and the next StartDryRun on the same operator-supplied
	// payload will simply mint a new draft. The only state we
	// must avoid leaking is the rollout row itself, because the
	// "one active rollout per tenant" invariant gates further
	// progress on it.)
	dryRun, err := s.policy.CompileDryRun(ctx, tenantID, proposed, DryRunOptions{
		SimulationID: in.SimulationID,
	})
	if err != nil {
		return repository.PolicyRollout{}, DryRunResult{}, fmt.Errorf("policy: compile dryrun: %w", err)
	}

	now := s.nowFunc().UTC()
	rollout := repository.PolicyRollout{
		ID:              uuid.New(),
		TenantID:        tenantID,
		GraphID:         proposed.ID,
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
		slog.String("graph_id", proposed.ID.String()),
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
//	dry_run -> canary (with CanaryPercent in (0, 100))
//	dry_run -> full
//	canary  -> full
//	full    -> completed
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
	// which graph to promote on a draft -> live transition.
	// UpdateStage is still the authoritative validator for
	// the transition itself; this fetch only feeds the
	// promotion gate below.
	current, err := s.rollouts.Get(ctx, tenantID, rolloutID)
	if err != nil {
		return repository.PolicyRollout{}, err
	}

	// Decide whether the candidate (draft) graph should flip
	// to live as part of this stage advance. The proposed
	// graph was stored as is_draft=true by StartDryRun so
	// /policy/compile keeps serving the previously-live
	// bundle during dry-run. On the first transition that
	// lets real fleet traffic reach the new policy —
	// dry_run -> canary (any percent) or dry_run -> full —
	// is_draft must flip to false so any subsequent
	// /policy/compile picks the new graph up as "current".
	//
	// We deliberately fold the promotion into UpdateStage
	// rather than calling s.policy.PromoteGraph separately:
	// two repository calls would leave a failure window in
	// which the rollout state + graph live-state can
	// disagree (see PR #39 Devin Review ANALYSIS_0001).
	// The postgres impl runs the rollout UPDATE and the
	// graph UPDATE in the same withTenant transaction; the
	// memory impl holds s.mu across both writes for the
	// equivalent atomicity guarantee.
	//
	// Subsequent transitions (canary -> full, full ->
	// completed) do not pass a promote id: by that point
	// the graph is already live and the advance is a
	// state-machine move on the rollout row.
	//
	// Rollback (* -> rolled_back) instead passes a DEMOTE
	// id when the rollout had already reached canary or
	// full — by that point the proposed graph is live, and
	// failing to flip it back to is_draft = true would
	// leave the just-rolled-back proposal as the result
	// of GetCurrentGraph until a new graph is published
	// (see PR #39 Devin Review BUG_0001 round 3). When
	// rolling back from dry_run the graph never went live,
	// so no demotion is needed.
	var promoteID *uuid.UUID
	var demoteID *uuid.UUID
	if shouldPromote(current.Stage, in.NextStage) {
		gid := current.GraphID
		promoteID = &gid
	} else if shouldDemote(current.Stage, in.NextStage) {
		gid := current.GraphID
		demoteID = &gid
	}

	now := s.nowFunc().UTC()
	updated, err := s.rollouts.UpdateStage(
		ctx, tenantID, rolloutID,
		in.NextStage, in.CanaryPercent, in.Notes, in.ActorID, now,
		promoteID, demoteID,
	)
	if err != nil {
		return repository.PolicyRollout{}, err
	}
	s.logger.Info("policy.canary: advanced",
		slog.String("tenant_id", tenantID.String()),
		slog.String("rollout_id", rolloutID.String()),
		slog.String("stage", string(updated.Stage)),
		slog.Int("canary_percent", updated.CanaryPercent),
		slog.Bool("promoted", promoteID != nil),
		slog.Bool("demoted", demoteID != nil),
	)
	return updated, nil
}

// shouldPromote returns true when the transition from prev to
// next is the boundary at which the proposed (draft) graph
// becomes the live policy. Today that means dry_run -> canary
// (at any percentage) or dry_run -> full: those are the only
// stages where agents start fetching bundles compiled off the
// candidate graph, so is_draft must flip exactly then.
//
// Later forward transitions (canary -> full, full -> completed)
// do NOT re-promote: by the time the rollout reaches canary the
// graph is already is_draft = false, and the subsequent advance
// is just a state-machine move on the rollout row.
//
// Rollback (* -> rolled_back) is handled by shouldDemote below
// — it never re-promotes, and from dry_run there is no live
// graph to either promote or demote, so shouldPromote and
// shouldDemote both return false in that case.
func shouldPromote(prev, next repository.PolicyRolloutStage) bool {
	if prev != repository.PolicyRolloutStageDryRun {
		return false
	}
	return next == repository.PolicyRolloutStageCanary ||
		next == repository.PolicyRolloutStageFull
}

// shouldDemote returns true when the transition from prev to
// next requires the proposed graph to be flipped back to
// is_draft = true. That happens exactly when a rollout that
// already reached canary or full is rolled back: the
// dry_run -> canary | full edge promoted the proposed graph
// to live (shouldPromote above), so the reverse edge has to
// undo that promotion or GetCurrentGraph would keep returning
// the rolled-back proposal as the live bundle (see PR #39
// Devin Review BUG_0001 round 3).
//
// Rolling back from dry_run is a no-op for the graph: the
// proposal never went live, it stays is_draft = true, and
// audit history retains the row without polluting
// GetCurrentGraph. Forward transitions never demote.
func shouldDemote(prev, next repository.PolicyRolloutStage) bool {
	if next != repository.PolicyRolloutStageRolledBack {
		return false
	}
	return prev == repository.PolicyRolloutStageCanary ||
		prev == repository.PolicyRolloutStageFull
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
// Algorithm: hash the device id and the rollout id with fnv1a64
// independently, then combine them through the splitmix64 mixing
// finalizer before taking the bucket mod 100; a device is in the
// canary iff bucket < canaryPercent.
//
// The two-hash-then-mix construction is what makes the *rollout*
// act as a true independent salt. An earlier version fed
// fnv1a64(rolloutID || deviceID) directly to % 100, but FNV-1a's
// weak avalanche means two different rollout salts leave the
// internal state highly correlated, so for unlucky rollout pairs
// the two cohorts were not independent (sometimes strongly
// overlapping, sometimes strongly disjoint). That both violated
// the documented "each device is independently sampled across
// rollouts" invariant and produced heavy distribution tails.
// Mixing the rollout hash with the splitmix64 finalizer
// (multiply + xorshift rounds) gives full avalanche, so two
// rollouts at the same percent over the same fleet overlap at
// the expected Binomial(fleet, p²) rate. fnv1a + splitmix64 are
// non-cryptographic and zero-allocation; cohort assignment is an
// operator-visible administrative selection, not a security
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
	hd := fnv.New64a()
	_, _ = hd.Write(deviceID[:])
	hr := fnv.New64a()
	_, _ = hr.Write(rolloutID[:])
	bucket := mixCanary(hd.Sum64(), hr.Sum64()) % 100
	return bucket < uint64(canaryPercent)
}

// mixCanary combines an independent device hash and rollout hash
// into a well-distributed bucket source. The rollout hash is run
// through a splitmix64 increment/multiply step and xor-folded
// into the device hash, then the whole word is passed through the
// splitmix64 finalizer so every input bit avalanches across the
// output. This decorrelates cohorts of distinct rollouts (see
// IsCanaryDevice) where a plain salted FNV-1a does not.
func mixCanary(device, rollout uint64) uint64 {
	const (
		gamma = 0x9E3779B97F4A7C15
		m1    = 0xBF58476D1CE4E5B9
		m2    = 0x94D049BB133111EB
	)
	x := device ^ (rollout*gamma + gamma)
	x ^= x >> 30
	x *= m1
	x ^= x >> 27
	x *= m2
	x ^= x >> 31
	return x
}

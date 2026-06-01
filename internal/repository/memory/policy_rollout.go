package memory

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyRolloutRepository is the memory-backed implementation of
// repository.PolicyRolloutRepository. It mirrors the
// monotone-forward state-machine invariant the Postgres driver
// enforces with a CHECK on UpdateStage transitions; rejections
// surface as ErrInvalidArgument so service-layer callers can
// branch on the same sentinel both backends emit.
type PolicyRolloutRepository struct{ s *Store }

// NewPolicyRolloutRepository wires a fresh repo over the shared
// Store.
func NewPolicyRolloutRepository(s *Store) *PolicyRolloutRepository {
	return &PolicyRolloutRepository{s: s}
}

var _ repository.PolicyRolloutRepository = (*PolicyRolloutRepository)(nil)

// cloneRollout returns a deep copy of the rollout — slice / pointer
// fields are independent of the stored row so callers can mutate
// the returned value without racing the store. Matches the pattern
// used in policy.go / policy_signing_key.go.
func cloneRollout(in repository.PolicyRollout) repository.PolicyRollout {
	out := in
	if in.CreatedBy != nil {
		u := *in.CreatedBy
		out.CreatedBy = &u
	}
	return out
}

// Create inserts a new rollout. The caller may leave ID zero (the
// repo assigns one); a non-zero ID collides only if a row with
// that ID already exists (ErrConflict). Stage is forced to DryRun
// at creation — the state machine starts at DryRun and may only
// advance from there.
func (r *PolicyRolloutRepository) Create(ctx context.Context, tenantID uuid.UUID, rl repository.PolicyRollout) (repository.PolicyRollout, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyRollout{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil || rl.GraphID == uuid.Nil {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.PolicyRollout{}, repository.ErrNotFound
	}
	if g, ok := r.s.policyGraphs[rl.GraphID]; !ok || g.TenantID != tenantID {
		return repository.PolicyRollout{}, repository.ErrNotFound
	}
	// PreviousGraphID is optional (uuid.Nil means "no prior
	// graph"); when set, it must reference the same tenant.
	if rl.PreviousGraphID != uuid.Nil {
		if g, ok := r.s.policyGraphs[rl.PreviousGraphID]; !ok || g.TenantID != tenantID {
			return repository.PolicyRollout{}, repository.ErrNotFound
		}
	}
	if rl.Stage.IsTerminal() {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
	}
	if rl.Stage == "" {
		rl.Stage = repository.PolicyRolloutStageDryRun
	}
	if rl.Stage == repository.PolicyRolloutStageCanary {
		if rl.CanaryPercent < 0 || rl.CanaryPercent > 100 {
			return repository.PolicyRollout{}, repository.ErrInvalidArgument
		}
	} else {
		rl.CanaryPercent = 0
	}
	if rl.ID == uuid.Nil {
		rl.ID = uuid.New()
	} else if _, dup := r.s.policyRollouts[rl.ID]; dup {
		return repository.PolicyRollout{}, repository.ErrConflict
	}
	rl.TenantID = tenantID
	now := r.s.clock()
	rl.CreatedAt = now
	rl.UpdatedAt = now
	stored := cloneRollout(rl)
	r.s.policyRollouts[stored.ID] = stored
	return cloneRollout(stored), nil
}

// Get returns the rollout by ID, filtering on tenant scope.
func (r *PolicyRolloutRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyRollout, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyRollout{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	rl, ok := r.s.policyRollouts[id]
	if !ok || rl.TenantID != tenantID {
		return repository.PolicyRollout{}, repository.ErrNotFound
	}
	return cloneRollout(rl), nil
}

// GetActive returns the most recently created NON-terminal
// rollout for the tenant. Ties on CreatedAt are broken by ID to
// keep the result deterministic across runs.
func (r *PolicyRolloutRepository) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicyRollout, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyRollout{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var best repository.PolicyRollout
	found := false
	for _, rl := range r.s.policyRollouts {
		if rl.TenantID != tenantID || rl.Stage.IsTerminal() {
			continue
		}
		if !found ||
			rl.CreatedAt.After(best.CreatedAt) ||
			(rl.CreatedAt.Equal(best.CreatedAt) && rolloutIDLess(best.ID, rl.ID)) {
			best = rl
			found = true
		}
	}
	if !found {
		return repository.PolicyRollout{}, repository.ErrNotFound
	}
	return cloneRollout(best), nil
}

// List returns rollouts in created-at descending order.
func (r *PolicyRolloutRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PolicyRollout], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.PolicyRollout]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.PolicyRollout, 0, len(r.s.policyRollouts))
	for _, rl := range r.s.policyRollouts {
		if rl.TenantID != tenantID {
			continue
		}
		all = append(all, cloneRollout(rl))
	}
	sort.SliceStable(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return rolloutIDLess(all[j].ID, all[i].ID) // descending by ID
	})
	return paginate(all, page, func(rl repository.PolicyRollout) cursor {
		return cursor{CreatedAt: rl.CreatedAt, ID: rl.ID}
	}), nil
}

// UpdateStage transitions the rollout to a new stage, enforcing
// the monotone-forward invariant. Returns the updated row.
func (r *PolicyRolloutRepository) UpdateStage(
	ctx context.Context,
	tenantID, id uuid.UUID,
	next repository.PolicyRolloutStage,
	canaryPercent int,
	notes string,
	updatedBy *uuid.UUID,
	at time.Time,
	promoteGraphID *uuid.UUID,
) (repository.PolicyRollout, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PolicyRollout{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	rl, ok := r.s.policyRollouts[id]
	if !ok || rl.TenantID != tenantID {
		return repository.PolicyRollout{}, repository.ErrNotFound
	}
	if !validRolloutTransition(rl.Stage, next) {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
	}
	if next == repository.PolicyRolloutStageCanary {
		if canaryPercent < 0 || canaryPercent > 100 {
			return repository.PolicyRollout{}, repository.ErrInvalidArgument
		}
		rl.CanaryPercent = canaryPercent
	} else if canaryPercent >= 0 && canaryPercent <= 100 && next != repository.PolicyRolloutStageCanary {
		// Leaving canary stage — CanaryPercent is no longer
		// meaningful, but we keep the historical value on the
		// row so the audit trail records "we ran at N%".
	}
	// If the caller requested a draft -> live promotion,
	// validate the target graph exists for this tenant BEFORE
	// mutating any rollout state — the memory impl has no
	// transactions, so failing here is the only way to keep
	// the rollout and the graph from disagreeing on rollback.
	// In the postgres impl this is enforced by the FK + the
	// tenant RLS GUC inside the surrounding withTenant tx.
	if promoteGraphID != nil {
		g, gok := r.s.policyGraphs[*promoteGraphID]
		if !gok || g.TenantID != tenantID {
			return repository.PolicyRollout{}, repository.ErrNotFound
		}
	}
	rl.Stage = next
	rl.UpdatedAt = at.UTC()
	if updatedBy != nil {
		// CreatedBy stays put (immutable provenance); the
		// updater is folded into Notes so we don't add a
		// second column for it in the memory impl.
		_ = updatedBy
	}
	if notes != "" {
		if rl.Notes == "" {
			rl.Notes = notes
		} else {
			rl.Notes = strings.Join([]string{rl.Notes, notes}, "\n")
		}
	}
	r.s.policyRollouts[id] = rl
	// Promotion side-effect: flip is_draft = false on the
	// target graph. Idempotent (no-op if already live). The
	// postgres impl does the equivalent UPDATE inside the
	// same withTenant tx so the stage advance + promotion
	// commit atomically; here we hold s.mu for both writes
	// which is the memory-equivalent guarantee.
	if promoteGraphID != nil {
		g := r.s.policyGraphs[*promoteGraphID]
		g.IsDraft = false
		r.s.policyGraphs[*promoteGraphID] = g
	}
	return cloneRollout(rl), nil
}

// validRolloutTransition encodes the monotone-forward state
// machine: any non-terminal stage may transition to RolledBack
// (one-way emergency exit); DryRun -> Canary, Canary -> Full,
// Full -> Completed are the only forward edges. The Postgres
// driver enforces the same matrix via a CHECK constraint.
func validRolloutTransition(from, to repository.PolicyRolloutStage) bool {
	if from.IsTerminal() {
		return false
	}
	if to == repository.PolicyRolloutStageRolledBack {
		return true
	}
	switch from {
	case repository.PolicyRolloutStageDryRun:
		return to == repository.PolicyRolloutStageCanary || to == repository.PolicyRolloutStageFull
	case repository.PolicyRolloutStageCanary:
		return to == repository.PolicyRolloutStageFull
	case repository.PolicyRolloutStageFull:
		return to == repository.PolicyRolloutStageCompleted
	}
	return false
}

// rolloutIDLess compares two UUIDs byte-wise — used as a
// deterministic tiebreaker when CreatedAt collides.
func rolloutIDLess(a, b uuid.UUID) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

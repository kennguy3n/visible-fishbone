package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PolicyRolloutRepository owns the policy_rollouts table — the
// state machine that tracks a proposed PolicyGraph through
// dry-run, canary, and full-fleet enforcement. RLS gates every
// statement via the sng.tenant_id GUC set by withTenant /
// withTenantRO so a tenant cannot see rollouts that belong to
// another tenant even on direct primary-key lookup.
type PolicyRolloutRepository struct{ s *Store }

const policyRolloutSelectColumns = `
id, tenant_id, graph_id, previous_graph_id, stage, canary_percent,
simulation_id, created_by, created_at, updated_at, COALESCE(notes, '')
`

// scanPolicyRollout walks one row out of a pgx.Row into the typed
// struct. previous_graph_id, simulation_id, and created_by are
// nullable in the schema; we materialise them via uuidScan /
// deletedAtScan-style helpers so a NULL surfaces as the zero
// value the service layer expects.
func scanPolicyRollout(row pgx.Row) (repository.PolicyRollout, error) {
	var (
		r           repository.PolicyRollout
		prevGraphID nullableUUID
		simID       nullableUUID
		createdBy   nullableUUID
	)
	if err := row.Scan(
		&r.ID, &r.TenantID, &r.GraphID, &prevGraphID,
		&r.Stage, &r.CanaryPercent, &simID, &createdBy,
		&r.CreatedAt, &r.UpdatedAt, &r.Notes,
	); err != nil {
		return repository.PolicyRollout{}, err
	}
	if prevGraphID.Valid {
		r.PreviousGraphID = prevGraphID.ID
	}
	if simID.Valid {
		r.SimulationID = simID.ID
	}
	if createdBy.Valid {
		u := createdBy.ID
		r.CreatedBy = &u
	}
	return r, nil
}

// Create inserts a new rollout. The CHECK constraint on the
// stage column enforces the valid-stage-set; this method
// additionally rejects terminal-stage creations at the Go layer
// for a clear ErrInvalidArgument rather than the bare CHECK
// violation surface.
func (r *PolicyRolloutRepository) Create(ctx context.Context, tenantID uuid.UUID, rl repository.PolicyRollout) (repository.PolicyRollout, error) {
	if tenantID == uuid.Nil || rl.GraphID == uuid.Nil {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
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
	}
	var out repository.PolicyRollout
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Coerce optional UUIDs to typed nullable args so a
		// zero-value uuid becomes SQL NULL rather than
		// '00000000-...' (which would violate the FK on
		// graph_id and silently confuse rollback resolution).
		var prevGraph, simID any
		if rl.PreviousGraphID != uuid.Nil {
			prevGraph = rl.PreviousGraphID
		}
		if rl.SimulationID != uuid.Nil {
			simID = rl.SimulationID
		}
		var createdBy any
		if rl.CreatedBy != nil {
			createdBy = *rl.CreatedBy
		}
		row := tx.QueryRow(ctx, `
INSERT INTO policy_rollouts (
    id, tenant_id, graph_id, previous_graph_id, stage,
    canary_percent, simulation_id, created_by, notes
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''))
RETURNING `+policyRolloutSelectColumns,
			rl.ID, tenantID, rl.GraphID, prevGraph, string(rl.Stage),
			rl.CanaryPercent, simID, createdBy, rl.Notes,
		)
		scanned, err := scanPolicyRollout(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("insert rollout: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// Get returns one rollout by ID, RLS-scoped to the tenant.
func (r *PolicyRolloutRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyRollout, error) {
	var out repository.PolicyRollout
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
SELECT `+policyRolloutSelectColumns+`
FROM policy_rollouts
WHERE id = $1
`, id)
		scanned, err := scanPolicyRollout(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select rollout: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// GetActive returns the most recent non-terminal rollout for the
// tenant.
func (r *PolicyRolloutRepository) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicyRollout, error) {
	var out repository.PolicyRollout
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
SELECT `+policyRolloutSelectColumns+`
FROM policy_rollouts
WHERE stage NOT IN ('completed', 'rolled_back')
ORDER BY created_at DESC, id DESC
LIMIT 1
`)
		scanned, err := scanPolicyRollout(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select active rollout: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// List enumerates rollouts in created-at DESC order, paginated.
func (r *PolicyRolloutRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PolicyRollout], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.PolicyRollout]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.PolicyRollout]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("policy_rollouts", policyRolloutSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list rollouts: %w", err)
		}
		defer rows.Close()
		items := make([]repository.PolicyRollout, 0, page.Limit)
		for rows.Next() {
			rl, err := scanPolicyRollout(rows)
			if err != nil {
				return fmt.Errorf("scan rollout: %w", err)
			}
			items = append(items, rl)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate rollouts: %w", err)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

// UpdateStage advances the rollout to a new stage. The Postgres
// CHECK on (stage, canary_percent) and the trigger that
// enforces monotone-forward transitions surface as
// ErrInvalidArgument; an unknown id surfaces as ErrNotFound.
//
// updatedBy is recorded into the notes column alongside the
// transition reason so the per-transition audit trail captures
// "who advanced this rollout, why" without adding a separate
// audit_log entry per stage change.
func (r *PolicyRolloutRepository) UpdateStage(
	ctx context.Context,
	tenantID, id uuid.UUID,
	next repository.PolicyRolloutStage,
	canaryPercent int,
	notes string,
	updatedBy *uuid.UUID,
	at time.Time,
	promoteGraphID *uuid.UUID,
	demoteGraphID *uuid.UUID,
) (repository.PolicyRollout, error) {
	if next == "" {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
	}
	if next == repository.PolicyRolloutStageCanary && (canaryPercent < 0 || canaryPercent > 100) {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
	}
	// Promote + demote are mutually exclusive: a single stage
	// transition cannot both make a draft live and unmake it.
	// Mirror the memory impl's rejection.
	if promoteGraphID != nil && demoteGraphID != nil {
		return repository.PolicyRollout{}, repository.ErrInvalidArgument
	}
	var out repository.PolicyRollout
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// updatedBy is folded into notes so the per-transition
		// audit row includes the actor without a schema
		// extension; the column itself is set on Create only.
		var enrichedNotes string
		switch {
		case notes != "" && updatedBy != nil:
			enrichedNotes = fmt.Sprintf("[by %s] %s", updatedBy.String(), notes)
		case notes != "":
			enrichedNotes = notes
		case updatedBy != nil:
			enrichedNotes = fmt.Sprintf("[by %s]", updatedBy.String())
		}
		// canary_percent_arg is only applied on transitions
		// INTO Canary; other transitions preserve the
		// existing column value so the historical "ran at N%"
		// figure survives in audit.
		updateCanary := next == repository.PolicyRolloutStageCanary
		row := tx.QueryRow(ctx, `
UPDATE policy_rollouts
SET stage = $1,
    canary_percent = CASE WHEN $2 THEN $3 ELSE canary_percent END,
    notes = CASE
        WHEN COALESCE(NULLIF($4, ''), '') = '' THEN notes
        WHEN notes IS NULL OR notes = '' THEN $4
        ELSE notes || E'\n' || $4
    END,
    updated_at = $5
WHERE id = $6
RETURNING `+policyRolloutSelectColumns,
			string(next), updateCanary, canaryPercent, enrichedNotes, at.UTC(), id,
		)
		scanned, err := scanPolicyRollout(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("update rollout stage: %w", err)
		}
		// Promotion side-effect, inside the same tx so the
		// stage advance and the graph going-live commit
		// atomically. The CanaryService passes the rollout's
		// graph_id here when the transition is the boundary
		// at which the candidate becomes the live policy
		// (dry_run -> canary / dry_run -> full). The UPDATE
		// is intentionally idempotent (no-op if is_draft is
		// already false), matching PromoteGraph's contract,
		// so re-running this transaction on retry stays
		// safe. We don't ErrNotFound here: the rollout's FK
		// to policy_graphs already guarantees the row exists.
		if promoteGraphID != nil {
			if _, err := tx.Exec(ctx, `
				UPDATE policy_graphs
				SET is_draft = false
				WHERE id = $1::uuid
				  AND tenant_id = $2::uuid
			`, *promoteGraphID, tenantID); err != nil {
				return fmt.Errorf("promote draft graph: %w", err)
			}
		}
		// Demotion side-effect, also inside the same tx so
		// the stage advance to rolled_back and the graph
		// going back to draft commit atomically. The
		// CanaryService passes the rollout's graph_id here
		// when rolling back FROM canary or full: the
		// proposed graph was promoted to live on the
		// dry_run -> canary | full edge, and rollback must
		// flip it back so the previous live graph again
		// wins GetCurrentGraph. The UPDATE is intentionally
		// idempotent (no-op if is_draft is already true),
		// so re-running this transaction on retry stays
		// safe. RLS via the tenant GUC scopes the row.
		if demoteGraphID != nil {
			if _, err := tx.Exec(ctx, `
				UPDATE policy_graphs
				SET is_draft = true
				WHERE id = $1::uuid
				  AND tenant_id = $2::uuid
			`, *demoteGraphID, tenantID); err != nil {
				return fmt.Errorf("demote graph back to draft: %w", err)
			}
		}
		out = scanned
		return nil
	})
	return out, err
}

var _ repository.PolicyRolloutRepository = (*PolicyRolloutRepository)(nil)

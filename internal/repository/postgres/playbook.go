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

// --- PlaybookRepository ---------------------------------------------------

// PlaybookRepository is the Postgres-backed PlaybookRepository.
type PlaybookRepository struct{ s *Store }

func scanPlaybook(row pgx.Row) (repository.Playbook, error) {
	var p repository.Playbook
	if err := row.Scan(
		&p.ID,
		&p.TenantID,
		&p.Name,
		&p.Description,
		&p.TriggerCondition,
		&p.Steps,
		&p.Enabled,
		&p.CreatedAt,
		&p.UpdatedAt,
	); err != nil {
		return repository.Playbook{}, err
	}
	return p, nil
}

const playbookCols = `id, tenant_id, name, description, trigger_condition, steps, enabled, created_at, updated_at`

func (r *PlaybookRepository) Create(ctx context.Context, tenantID uuid.UUID, p repository.Playbook) (repository.Playbook, error) {
	var out repository.Playbook
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `INSERT INTO playbooks (tenant_id, name, description, trigger_condition, steps, enabled)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING ` + playbookCols
		scanned, err := scanPlaybook(tx.QueryRow(ctx, q,
			tenantID, p.Name, p.Description, p.TriggerCondition, p.Steps, p.Enabled,
		))
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			return fmt.Errorf("insert playbooks: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Playbook, error) {
	var out repository.Playbook
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `SELECT ` + playbookCols + ` FROM playbooks WHERE id = $1`
		scanned, err := scanPlaybook(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get playbooks: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.Playbook], error) {
	var out repository.PageResult[repository.Playbook]
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		page = page.Normalize()
		cur, err := decodeCursor(page.After)
		if err != nil {
			return repository.ErrInvalidArgument
		}

		q := `SELECT ` + playbookCols + ` FROM playbooks`
		args := []any{}
		argN := 0

		if !cur.T.IsZero() {
			argN++
			tArg := argN
			argN++
			iArg := argN
			q += fmt.Sprintf(` WHERE (created_at, id) < ($%d, $%d)`, tArg, iArg)
			args = append(args, cur.T, cur.I)
		}
		argN++
		q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, argN)
		args = append(args, page.Limit)

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		var items []repository.Playbook
		for rows.Next() {
			item, err := scanPlaybook(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		next := ""
		if len(items) == page.Limit {
			last := items[len(items)-1]
			next = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		out = repository.PageResult[repository.Playbook]{Items: items, NextCursor: next}
		return nil
	})
	return out, err
}

func (r *PlaybookRepository) Update(ctx context.Context, tenantID, id uuid.UUID, patch repository.PlaybookPatch) (repository.Playbook, error) {
	var out repository.Playbook
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// fetch current with row lock to prevent lost updates
		q := `SELECT ` + playbookCols + ` FROM playbooks WHERE id = $1 FOR UPDATE`
		p, err := scanPlaybook(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get playbooks for update: %w", err)
		}

		if patch.Name != nil {
			p.Name = *patch.Name
		}
		if patch.Description != nil {
			p.Description = *patch.Description
		}
		if patch.TriggerCondition != nil {
			p.TriggerCondition = *patch.TriggerCondition
		}
		if patch.Steps != nil {
			p.Steps = *patch.Steps
		}
		if patch.Enabled != nil {
			p.Enabled = *patch.Enabled
		}

		uq := `UPDATE playbooks SET name=$1, description=$2, trigger_condition=$3, steps=$4, enabled=$5, updated_at=NOW()
WHERE id=$6
RETURNING ` + playbookCols
		scanned, err := scanPlaybook(tx.QueryRow(ctx, uq,
			p.Name, p.Description, p.TriggerCondition, p.Steps, p.Enabled, id,
		))
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			return fmt.Errorf("update playbooks: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookRepository) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `DELETE FROM playbooks WHERE id = $1`
		tag, err := tx.Exec(ctx, q, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *PlaybookRepository) ListByTrigger(ctx context.Context, tenantID uuid.UUID, triggerType string) ([]repository.Playbook, error) {
	var out []repository.Playbook
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `SELECT ` + playbookCols + ` FROM playbooks WHERE trigger_condition = $1 AND enabled = true`
		rows, err := tx.Query(ctx, q, triggerType)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanPlaybook(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// --- PlaybookExecutionRepository ------------------------------------------

// PlaybookExecutionRepository is the Postgres-backed PlaybookExecutionRepository.
type PlaybookExecutionRepository struct{ s *Store }

const execCols = `id, tenant_id, playbook_id, status, trigger_event, started_at, completed_at, created_at`

func scanExecution(row pgx.Row) (repository.PlaybookExecution, error) {
	var e repository.PlaybookExecution
	var completedAt deletedAtScan
	if err := row.Scan(
		&e.ID,
		&e.TenantID,
		&e.PlaybookID,
		&e.Status,
		&e.TriggerEvent,
		&e.StartedAt,
		&completedAt,
		&e.CreatedAt,
	); err != nil {
		return repository.PlaybookExecution{}, err
	}
	if completedAt.Valid {
		e.CompletedAt = &completedAt.Time
	}
	return e, nil
}

func (r *PlaybookExecutionRepository) Create(ctx context.Context, tenantID uuid.UUID, e repository.PlaybookExecution) (repository.PlaybookExecution, error) {
	var out repository.PlaybookExecution
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `INSERT INTO playbook_executions (tenant_id, playbook_id, status, trigger_event, started_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING ` + execCols
		scanned, err := scanExecution(tx.QueryRow(ctx, q,
			tenantID, e.PlaybookID, e.Status, e.TriggerEvent, e.StartedAt,
		))
		if err != nil {
			return fmt.Errorf("insert playbook_executions: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookExecutionRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PlaybookExecution, error) {
	var out repository.PlaybookExecution
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `SELECT ` + execCols + ` FROM playbook_executions WHERE id = $1`
		scanned, err := scanExecution(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get playbook_executions: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookExecutionRepository) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PlaybookExecution], error) {
	var out repository.PageResult[repository.PlaybookExecution]
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		page = page.Normalize()
		cur, err := decodeCursor(page.After)
		if err != nil {
			return repository.ErrInvalidArgument
		}

		q := `SELECT ` + execCols + ` FROM playbook_executions`
		args := []any{}
		argN := 0

		if !cur.T.IsZero() {
			argN++
			tArg := argN
			argN++
			iArg := argN
			q += fmt.Sprintf(` WHERE (created_at, id) < ($%d, $%d)`, tArg, iArg)
			args = append(args, cur.T, cur.I)
		}
		argN++
		q += fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, argN)
		args = append(args, page.Limit)

		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		var items []repository.PlaybookExecution
		for rows.Next() {
			item, err := scanExecution(rows)
			if err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		next := ""
		if len(items) == page.Limit {
			last := items[len(items)-1]
			next = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		out = repository.PageResult[repository.PlaybookExecution]{Items: items, NextCursor: next}
		return nil
	})
	return out, err
}

func (r *PlaybookExecutionRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `UPDATE playbook_executions SET status = $1`
		if status == "completed" || status == "failed" || status == "rolled_back" {
			q += `, completed_at = NOW()`
		}
		q += ` WHERE id = $2`
		tag, err := tx.Exec(ctx, q, status, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *PlaybookExecutionRepository) AddStepResult(ctx context.Context, tenantID, executionID uuid.UUID, sr repository.StepResult) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `INSERT INTO playbook_step_results (execution_id, tenant_id, step_order, status, output, error, started_at, completed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err := tx.Exec(ctx, q,
			executionID, tenantID, sr.StepOrder, sr.Status, sr.Output, sr.Error,
			optionalTime(sr.StartedAt), optionalTime(sr.CompletedAt),
		)
		return err
	})
}

// --- PlaybookApprovalRepository -------------------------------------------

// PlaybookApprovalRepository is the Postgres-backed PlaybookApprovalRepository.
type PlaybookApprovalRepository struct{ s *Store }

const approvalCols = `id, tenant_id, execution_id, approver_id, status, expires_at, decided_at, created_at`

func scanApproval(row pgx.Row) (repository.PlaybookApproval, error) {
	var a repository.PlaybookApproval
	var approverID nullableUUID
	var decidedAt deletedAtScan
	if err := row.Scan(
		&a.ID,
		&a.TenantID,
		&a.ExecutionID,
		&approverID,
		&a.Status,
		&a.ExpiresAt,
		&decidedAt,
		&a.CreatedAt,
	); err != nil {
		return repository.PlaybookApproval{}, err
	}
	if approverID.Valid {
		a.ApproverID = &approverID.ID
	}
	if decidedAt.Valid {
		a.DecidedAt = &decidedAt.Time
	}
	return a, nil
}

func (r *PlaybookApprovalRepository) Create(ctx context.Context, tenantID uuid.UUID, a repository.PlaybookApproval) (repository.PlaybookApproval, error) {
	var out repository.PlaybookApproval
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `INSERT INTO playbook_approvals (tenant_id, execution_id, status, expires_at)
VALUES ($1, $2, $3, $4)
RETURNING ` + approvalCols
		scanned, err := scanApproval(tx.QueryRow(ctx, q,
			tenantID, a.ExecutionID, a.Status, a.ExpiresAt,
		))
		if err != nil {
			return fmt.Errorf("insert playbook_approvals: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookApprovalRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PlaybookApproval, error) {
	var out repository.PlaybookApproval
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `SELECT ` + approvalCols + ` FROM playbook_approvals WHERE id = $1`
		scanned, err := scanApproval(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get playbook_approvals: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *PlaybookApprovalRepository) ListPending(ctx context.Context, tenantID uuid.UUID) ([]repository.PlaybookApproval, error) {
	var out []repository.PlaybookApproval
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := `SELECT ` + approvalCols + ` FROM playbook_approvals WHERE status = 'pending' ORDER BY created_at ASC`
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanApproval(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

func (r *PlaybookApprovalRepository) UpdateStatus(ctx context.Context, tenantID, id uuid.UUID, status string, approverID *uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `UPDATE playbook_approvals SET status = $1, approver_id = $2, decided_at = NOW()
WHERE id = $3`
		tag, err := tx.Exec(ctx, q, status, optionalUUID(approverID), id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *PlaybookApprovalRepository) ExpireOld(ctx context.Context, before time.Time) (int, error) {
	var count int
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `UPDATE playbook_approvals SET status = 'expired', decided_at = NOW()
WHERE status = 'pending' AND expires_at < $1`
		tag, err := tx.Exec(ctx, q, before)
		if err != nil {
			return err
		}
		count = int(tag.RowsAffected())
		return nil
	})
	return count, err
}
